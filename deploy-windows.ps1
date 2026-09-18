# Windows PowerShell deployment script for account system

$ErrorActionPreference = "Stop"

Write-Host "=========================================="
Write-Host "   ACCOUNT SYSTEM - WINDOWS DEPLOYMENT"
Write-Host "=========================================="
Write-Host ""

$REPO = "C:\Users\Alex\Self-Host"
cd $REPO

# Database
Write-Host "[1/5] Setting up database..." -ForegroundColor Cyan
$DATA_DIR = "$env:USERPROFILE\.selfhost\data"
if (!(Test-Path $DATA_DIR)) { New-Item -ItemType Directory -Path $DATA_DIR | Out-Null }

$DB_PATH = "$DATA_DIR\accounts.db"
if (Test-Path $DB_PATH) { Remove-Item $DB_PATH }

$SCHEMA = @"
CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, status TEXT DEFAULT 'active');
CREATE TABLE passkeys (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), credential_id BLOB NOT NULL UNIQUE, public_key BLOB NOT NULL);
CREATE TABLE roles (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE permissions (id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id), resource_type TEXT, resource_id TEXT, action TEXT);
CREATE TABLE vpn_locations (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, region TEXT);
CREATE TABLE sessions (id TEXT PRIMARY KEY, user_id TEXT REFERENCES users(id), token_hash TEXT NOT NULL UNIQUE, expires_at TIMESTAMP);
CREATE TABLE audit_log (id TEXT PRIMARY KEY, action TEXT, resource_type TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
INSERT INTO roles VALUES ('admin', 'Administrator'), ('operator', 'Operator'), ('viewer', 'Viewer');
INSERT INTO vpn_locations VALUES ('us-east-1', 'US East', 'US'), ('eu-west-1', 'EU West', 'Ireland'), ('ap-southeast-1', 'Asia Pacific', 'Singapore');
"@

$SCHEMA | sqlite3.exe $DB_PATH
Write-Host "✓ Database ready at $DB_PATH" -ForegroundColor Green
Write-Host ""

# Build backend
Write-Host "[2/5] Building backend..." -ForegroundColor Cyan
cd "$REPO\crates\services\account-manager"
cargo build --release 2>&1 | Select-String "Finished|error" | Select-Object -Last 1
Write-Host "✓ Backend built" -ForegroundColor Green
Write-Host ""

# Frontend
Write-Host "[3/5] Installing frontend dependencies..." -ForegroundColor Cyan
cd "$REPO\crates\ui\account-console"
npm install --silent 2>&1 | Select-String "added|up to date" | Select-Object -Last 1
Write-Host "✓ Frontend ready" -ForegroundColor Green
Write-Host ""

Write-Host "[4/5] Summary" -ForegroundColor Cyan
Write-Host "Backend: $REPO\crates\services\account-manager" -ForegroundColor Yellow
Write-Host "Frontend: $REPO\crates\ui\account-console" -ForegroundColor Yellow
Write-Host "Database: $DB_PATH" -ForegroundColor Yellow
Write-Host ""

Write-Host "[5/5] Ready to Start Services" -ForegroundColor Cyan
Write-Host ""
Write-Host "Terminal 1 (Backend):" -ForegroundColor Green
Write-Host "  cd C:\Users\Alex\Self-Host\crates\services\account-manager"
Write-Host "  cargo run --release --bin account-manager"
Write-Host ""
Write-Host "Terminal 2 (Frontend):" -ForegroundColor Green
Write-Host "  cd C:\Users\Alex\Self-Host\crates\ui\account-console"
Write-Host "  npm run dev"
Write-Host ""
Write-Host "Browser:" -ForegroundColor Green
Write-Host "  http://localhost:3000"
Write-Host ""
