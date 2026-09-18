#!/bin/bash
# Quick command reference for account system deployment and testing

REPO="/Users/alexwaldmann/Desktop/Self-Host"
SCRATCHPAD="/private/tmp/claude-501/-Users-alexwaldmann-Desktop-Self-Host/cad2fc70-35a8-4078-9284-76332ce840d3/scratchpad"

# ============================================================
# DEPLOYMENT
# ============================================================

# Deploy everything (run this first)
deploy_all() {
    echo "🚀 Running full deployment..."
    bash "$SCRATCHPAD/DEPLOY_ALL.sh"
}

# ============================================================
# START SERVICES
# ============================================================

# Start backend (Terminal 1)
start_backend() {
    echo "🔧 Starting backend service..."
    cd "$REPO/crates/services/account-manager"
    DATABASE_URL="sqlite:///Users/alexwaldmann/.selfhost/data/accounts.db" \
    BIND_ADDR="127.0.0.1:9000" \
    cargo run --release
}

# Start frontend (Terminal 2)
start_frontend() {
    echo "🎨 Starting frontend UI..."
    cd "$REPO/crates/ui/account-console"
    npm run dev
}

# Start both in background (Terminal 3 for testing)
start_both() {
    echo "Starting backend and frontend in background..."
    start_backend &
    sleep 3
    start_frontend &
    echo "Both services started. Open http://localhost:3000"
}

# ============================================================
# DATABASE OPERATIONS
# ============================================================

# Open database shell
db_shell() {
    sqlite3 ~/.selfhost/data/accounts.db
}

# Show all users
db_users() {
    sqlite3 ~/.selfhost/data/accounts.db "SELECT id, email, status, created_at FROM users;"
}

# Show all permissions
db_permissions() {
    sqlite3 ~/.selfhost/data/accounts.db "SELECT user_id, resource_type, resource_id, action FROM permissions;"
}

# Show audit log
db_audit() {
    sqlite3 ~/.selfhost/data/accounts.db "SELECT timestamp, action, resource_type, status FROM audit_log ORDER BY timestamp DESC LIMIT 20;"
}

# Show VPN access log
db_vpn_log() {
    sqlite3 ~/.selfhost/data/accounts.db "SELECT timestamp, event_type, status FROM vpn_access_log ORDER BY timestamp DESC LIMIT 20;"
}

# Show database tables
db_tables() {
    sqlite3 ~/.selfhost/data/accounts.db ".tables"
}

# Backup database
db_backup() {
    BACKUP_PATH="$REPO/backups/accounts.db.$(date +%s).bak"
    mkdir -p "$REPO/backups"
    cp ~/.selfhost/data/accounts.db "$BACKUP_PATH"
    echo "Database backed up to: $BACKUP_PATH"
}

# Reset database (DANGER!)
db_reset() {
    echo "WARNING: This will DELETE all data!"
    read -p "Continue? (yes/no) " confirm
    if [ "$confirm" = "yes" ]; then
        rm ~/.selfhost/data/accounts.db
        sqlite3 ~/.selfhost/data/accounts.db < "$REPO/crates/services/account-manager/schema.sql"
        echo "Database reset."
    fi
}

# ============================================================
# API TESTING
# ============================================================

# Test backend health
test_health() {
    echo "Testing backend health..."
    curl -s http://localhost:9000/health | jq .
}

# Register test user
test_register() {
    echo "Registering test user..."
    curl -X POST http://localhost:9000/api/auth/register \
        -H "Content-Type: application/json" \
        -d '{
            "email": "test@example.com",
            "username": "test",
            "passkey_credential_id": "base64_encoded_credential"
        }' | jq .
}

# List all users
test_list_users() {
    echo "Listing users..."
    curl -s http://localhost:9000/api/users \
        -H "Authorization: Bearer admin-token" | jq .
}

# Get specific user
test_get_user() {
    USER_ID=${1:-$(sqlite3 ~/.selfhost/data/accounts.db "SELECT id FROM users LIMIT 1;")}
    echo "Getting user: $USER_ID"
    curl -s http://localhost:9000/api/users/$USER_ID | jq .
}

# Approve user
test_approve_user() {
    USER_ID=${1:-$(sqlite3 ~/.selfhost/data/accounts.db "SELECT id FROM users WHERE status='pending' LIMIT 1;")}
    echo "Approving user: $USER_ID"
    curl -X POST http://localhost:9000/api/users/$USER_ID/approve \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer admin-token" \
        -d '{}' | jq .
}

# Grant permission
test_grant_permission() {
    USER_ID=${1:-$(sqlite3 ~/.selfhost/data/accounts.db "SELECT id FROM users LIMIT 1;")}
    LOCATION_ID=${2:-"us-east-1"}
    echo "Granting permission to user $USER_ID for location $LOCATION_ID..."
    curl -X POST http://localhost:9000/api/users/$USER_ID/permissions \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer admin-token" \
        -d "{
            \"resource_type\": \"vpn_location\",
            \"resource_id\": \"$LOCATION_ID\",
            \"action\": \"read\"
        }" | jq .
}

# Check VPN access (allowed)
test_vpn_access_allowed() {
    USER_ID=$(sqlite3 ~/.selfhost/data/accounts.db "SELECT user_id FROM permissions LIMIT 1;")
    LOCATION_ID=$(sqlite3 ~/.selfhost/data/accounts.db "SELECT resource_id FROM permissions WHERE user_id='$USER_ID' LIMIT 1;")
    echo "Testing VPN access (should be allowed)..."
    curl -X POST http://localhost:9000/api/vpn/check-access \
        -H "Content-Type: application/json" \
        -d "{
            \"user_id\": \"$USER_ID\",
            \"location_id\": \"$LOCATION_ID\"
        }" | jq .
}

# Check VPN access (denied)
test_vpn_access_denied() {
    USER_ID=$(sqlite3 ~/.selfhost/data/accounts.db "SELECT id FROM users LIMIT 1;")
    echo "Testing VPN access (should be denied)..."
    curl -X POST http://localhost:9000/api/vpn/check-access \
        -H "Content-Type: application/json" \
        -d "{
            \"user_id\": \"$USER_ID\",
            \"location_id\": \"nonexistent-location\"
        }" | jq .
}

# ============================================================
# BUILD & DEVELOPMENT
# ============================================================

# Build backend
build_backend() {
    echo "Building backend..."
    cd "$REPO/crates/services/account-manager"
    cargo build --release
}

# Build frontend
build_frontend() {
    echo "Building frontend..."
    cd "$REPO/crates/ui/account-console"
    npm run build
}

# Run backend tests
test_backend() {
    echo "Running backend tests..."
    cd "$REPO/crates/services/account-manager"
    cargo test
}

# Run backend linting
lint_backend() {
    echo "Linting backend..."
    cd "$REPO/crates/services/account-manager"
    cargo clippy
}

# ============================================================
# LOGS & MONITORING
# ============================================================

# Watch backend logs (if running in background)
logs_backend() {
    tail -f ~/.selfhost/logs/account-manager.log 2>/dev/null || echo "Log file not found"
}

# Check running processes
ps_check() {
    echo "Checking for running services..."
    ps aux | grep -E "(account-manager|account-console|node|npm)" | grep -v grep
}

# ============================================================
# CLEANUP
# ============================================================

# Kill all services
kill_services() {
    echo "Killing services..."
    pkill -f "account-manager"
    pkill -f "account-console"
    pkill -f "vite"
    echo "Services stopped."
}

# Clean build artifacts
clean_build() {
    echo "Cleaning build artifacts..."
    rm -rf "$REPO/target"
    rm -rf "$REPO/crates/ui/account-console/node_modules"
    rm -rf "$REPO/crates/ui/account-console/dist"
    echo "Cleaned."
}

# ============================================================
# DOCUMENTATION
# ============================================================

# Show deployment summary
show_summary() {
    cat "$SCRATCHPAD/DEPLOYMENT_SUMMARY.md"
}

# Show testing guide
show_testing() {
    cat "$SCRATCHPAD/TESTING_GUIDE.md"
}

# Show implementation guide
show_implementation() {
    cat "$SCRATCHPAD/IMPLEMENTATION_GUIDE.md"
}

# ============================================================
# COMMAND HELP
# ============================================================

help() {
    cat << 'EOF'
Account System Quick Commands
============================

DEPLOYMENT:
  deploy_all                    - Deploy everything (run this first!)

SERVICES:
  start_backend                 - Start backend service (port 9000)
  start_frontend                - Start frontend UI (port 3000)
  start_both                    - Start both services
  kill_services                 - Stop all services

DATABASE:
  db_shell                      - Open SQLite shell
  db_users                      - List all users
  db_permissions                - List all permissions
  db_audit                      - Show audit log (latest 20)
  db_vpn_log                    - Show VPN access log
  db_tables                     - List all tables
  db_backup                     - Backup database
  db_reset                      - Reset database (DANGER!)

API TESTS:
  test_health                   - Check backend health
  test_register                 - Register test user
  test_list_users               - List all users
  test_get_user [ID]            - Get user details
  test_approve_user [ID]        - Approve pending user
  test_grant_permission [ID] [LOC] - Grant VPN location access
  test_vpn_access_allowed       - Test VPN access (allowed)
  test_vpn_access_denied        - Test VPN access (denied)

BUILD:
  build_backend                 - Build Rust backend
  build_frontend                - Build React frontend
  test_backend                  - Run backend tests
  lint_backend                  - Run Clippy linting

MONITORING:
  logs_backend                  - Watch backend logs
  ps_check                      - Check running processes

CLEANUP:
  clean_build                   - Remove build artifacts

DOCS:
  show_summary                  - Show deployment summary
  show_testing                  - Show testing guide
  show_implementation           - Show implementation guide
  help                          - Show this help

EXAMPLE WORKFLOW:
  1. deploy_all
  2. start_backend (Terminal 1)
  3. start_frontend (Terminal 2)
  4. test_health
  5. test_register
  6. test_list_users
  7. Open http://localhost:3000

EOF
}

# If no command provided, show help
if [ $# -eq 0 ]; then
    help
else
    # Run the provided command with arguments
    "$@"
fi
