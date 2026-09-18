# Quick Start: Account System Setup

## 5-Minute Setup

### 1. Copy Files to Project

```bash
cd /Users/alexwaldmann/Desktop/Self-Host

# Create account-manager crate structure
mkdir -p crates/services/account-manager/src

# Copy database schema
cp 01-database-schema.sql crates/services/account-manager/schema.sql

# Copy source files
cp 02-lib.rs crates/services/account-manager/src/lib.rs
cp 03-models.rs crates/services/account-manager/src/models.rs
cp 04-permissions.rs crates/services/account-manager/src/permissions.rs
cp 05-auth.rs crates/services/account-manager/src/auth.rs
cp 06-handlers.rs crates/services/account-manager/src/handlers.rs
cp 08-main.rs crates/services/account-manager/src/main.rs
cp 07-Cargo.toml crates/services/account-manager/Cargo.toml
```

### 2. Update Workspace Cargo.toml

Add to root `Cargo.toml`:

```toml
[workspace]
members = [
    # ... existing members ...
    "crates/services/account-manager",
]
```

### 3. Initialize Database

```bash
# Create database directory if needed
mkdir -p /var/lib/selfhost

# Initialize with schema
sqlite3 /var/lib/selfhost/accounts.db < crates/services/account-manager/schema.sql

# Verify tables exist
sqlite3 /var/lib/selfhost/accounts.db ".tables"
```

### 4. Build Service

```bash
cd crates/services/account-manager
cargo build --release
```

### 5. Run Service

```bash
# Terminal 1: Run account manager
DATABASE_URL=sqlite:///var/lib/selfhost/accounts.db \
BIND_ADDR=127.0.0.1:9000 \
RUST_LOG=info \
cargo run --release

# Terminal 2: Test the API
curl http://localhost:9000/health
```

## Quick Test Flow

### Register a User

```bash
curl -X POST http://localhost:9000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "email": "alice@example.com",
    "passkey_credential_id": "dGVzdF9jcmVkZW50aWFsX2lk"
  }' | jq .
```

Expected response:
```json
{
  "user_id": "12345678-1234-1234-1234-123456789012",
  "username": "alice",
  "email": "alice@example.com",
  "status": "pending",
  "created_at": "2025-09-18T12:34:56Z"
}
```

Copy the `user_id` for next step.

### Approve the User

```bash
USER_ID="12345678-1234-1234-1234-123456789012"

curl -X POST http://localhost:9000/api/users/$USER_ID/approve \
  -H "Content-Type: application/json" \
  -d '{"approve": true}' | jq .
```

Expected response:
```json
{
  "success": true,
  "user": {
    "id": "12345678-1234-1234-1234-123456789012",
    "username": "alice",
    "status": "active"
  }
}
```

### Create a VPN Location

```bash
curl -X POST http://localhost:9000/api/vpn-locations \
  -H "Content-Type: application/json" \
  -d '{
    "name": "home",
    "description": "Home VPN Location",
    "region": "local"
  }' | jq .
```

Expected response:
```json
{
  "id": "87654321-4321-4321-4321-210987654321",
  "name": "home",
  "description": "Home VPN Location",
  "region": "local",
  "created_at": "2025-09-18T12:34:56Z",
  "user_count": 0
}
```

Copy the `id` for next step.

### Grant Location Access

```bash
USER_ID="12345678-1234-1234-1234-123456789012"
LOCATION_ID="87654321-4321-4321-4321-210987654321"

curl -X POST http://localhost:9000/api/users/$USER_ID/permissions \
  -H "Content-Type: application/json" \
  -d "{\"location_id\": \"$LOCATION_ID\"}" | jq .
```

Expected response:
```json
{
  "success": true,
  "message": "Permission granted"
}
```

### Check VPN Access

```bash
USER_ID="12345678-1234-1234-1234-123456789012"
LOCATION_ID="87654321-4321-4321-4321-210987654321"

curl -X POST http://localhost:9000/api/vpn/check-access \
  -H "Content-Type: application/json" \
  -d "{
    \"user_id\": \"$USER_ID\",
    \"location_id\": \"$LOCATION_ID\",
    \"ip_address\": \"192.168.1.100\"
  }" | jq .
```

Expected response:
```json
{
  "allowed": true,
  "reason": "Access granted",
  "user_name": null,
  "session_timeout": 86400
}
```

## Using the Admin CLI

### With MCP Tools

```bash
# Create a user via CLI
selfhost-account-manager create-user \
  --username bob \
  --email bob@example.com

# List all users
selfhost-account-manager list-users

# Approve a user
selfhost-account-manager approve-user <user_id>

# Grant location access
selfhost-account-manager grant-location <user_id> <location_id>

# Revoke access
selfhost-account-manager revoke-location <user_id> <location_id>
```

## Database Inspection

### View Users

```bash
sqlite3 /var/lib/selfhost/accounts.db \
  "SELECT id, username, email, status, approved_at FROM users;"
```

### View Permissions

```bash
sqlite3 /var/lib/selfhost/accounts.db \
  "SELECT u.username, l.name, lp.granted_at FROM location_permissions lp
   JOIN users u ON lp.user_id = u.id
   JOIN vpn_locations l ON lp.location_id = l.id;"
```

### View Audit Log

```bash
sqlite3 /var/lib/selfhost/accounts.db \
  "SELECT actor_user_id, action, resource_type, resource_id, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT 20;"
```

## Common Issues & Solutions

### Issue: "Connection refused" when starting service

**Solution**: Make sure port 9000 is available
```bash
# Check if port is in use
lsof -i :9000

# Use different port
BIND_ADDR=127.0.0.1:9001 cargo run --release
```

### Issue: "Database locked" errors

**Solution**: SQLite issues with concurrent access
```bash
# Check if other connections exist
ps aux | grep account-manager

# Reset database if needed
rm /var/lib/selfhost/accounts.db
sqlite3 /var/lib/selfhost/accounts.db < schema.sql
```

### Issue: "Unknown column" SQL errors

**Solution**: Schema not initialized
```bash
# Check tables exist
sqlite3 /var/lib/selfhost/accounts.db ".schema users"

# Re-initialize if missing
sqlite3 /var/lib/selfhost/accounts.db < crates/services/account-manager/schema.sql
```

### Issue: User can't log in after approval

**Solution**: Check session creation
```bash
# Verify user is actually approved
sqlite3 /var/lib/selfhost/accounts.db \
  "SELECT username, status, approved_at FROM users WHERE username='alice';"

# Check if status is 'active'
```

## Next Steps

1. **Create Web UI**:
   - Use React/Vue for registration and login pages
   - Add admin console for user management

2. **Integrate with VPN**:
   - Update VPN server to call `/api/vpn/check-access`
   - See `10-vpn-integration-example.rs` for details

3. **Add WebAuthn Support**:
   - Replace stub verification with real passkey validation
   - Use `webauthn-rs` crate

4. **Configure Email Notifications**:
   - Set up SMTP for approval notifications
   - Email templates for registration steps

5. **Production Deployment**:
   - Test on Windows ALEX-DESKTOP box
   - Set up database backups
   - Configure monitoring and alerting

## Architecture Summary

```
┌─────────────────┐
│   VPN Client    │
└────────┬────────┘
         │
         │ TLS Connection
         ▼
┌─────────────────────────────┐
│   VPN Server (Secure-VPN)   │
│  - Extract user_id          │
│  - Call check-access API    │
└────────┬────────────────────┘
         │
         │ POST /api/vpn/check-access
         ▼
┌──────────────────────────────────┐
│    Account Manager Service       │
│  - Check user status (active)    │
│  - Check location permissions    │
│  - Return allow/deny decision    │
│  - Log access attempt            │
└──────────────────────────────────┘
         │
         │ Uses
         ▼
┌──────────────────────────────────┐
│    SQLite Database               │
│  - users table (registration)    │
│  - location_permissions          │
│  - audit_log (compliance)        │
└──────────────────────────────────┘
```

## Testing Checklist

- [ ] Service starts without errors
- [ ] Health check endpoint responds (GET /health)
- [ ] Can register a new user
- [ ] Can approve pending user
- [ ] Can create VPN location
- [ ] Can grant location permission
- [ ] VPN access check returns "allowed": true
- [ ] Database contains correct data
- [ ] Audit log records actions
- [ ] Session tokens are created and validated
- [ ] User can't access without approval
- [ ] User can't access revoked locations

## Performance Notes

- SQLite is fine for single-server setups (up to ~100 users)
- For larger deployments, migrate to PostgreSQL
- Connection pooling enabled in sqlx (10 connections by default)
- Indexes created for common queries

## Security Notes

- All passwords replaced with WebAuthn passkeys
- Session tokens expire after 24 hours
- Failed attempts logged to audit trail
- Database access restricted to service account
- HTTPS recommended for production
