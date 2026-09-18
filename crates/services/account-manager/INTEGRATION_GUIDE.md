# Account System Integration Guide

## Overview

This guide explains how to integrate the new account management system with the existing VPN infrastructure in the selfhost project.

## Files to Create

### 1. Create the Account Manager Crate

```bash
mkdir -p crates/services/account-manager/src
```

Copy the following files to the new crate:
- `01-database-schema.sql` → `crates/services/account-manager/schema.sql`
- `02-lib.rs` → `crates/services/account-manager/src/lib.rs`
- `03-models.rs` → `crates/services/account-manager/src/models.rs`
- `04-permissions.rs` → `crates/services/account-manager/src/permissions.rs`
- `05-auth.rs` → `crates/services/account-manager/src/auth.rs`
- `06-handlers.rs` → `crates/services/account-manager/src/handlers.rs`
- `08-main.rs` → `crates/services/account-manager/src/main.rs`
- `07-Cargo.toml` → `crates/services/account-manager/Cargo.toml`

### 2. Update Workspace Cargo.toml

Add to the root `Cargo.toml`:

```toml
[workspace]
members = [
    # ... existing members ...
    "crates/services/account-manager",
]
```

### 3. Create Database

Initialize the database with the schema:

```bash
sqlite3 /var/lib/selfhost/accounts.db < crates/services/account-manager/schema.sql
```

Or for PostgreSQL:

```bash
psql -d selfhost_accounts < crates/services/account-manager/schema.sql
```

## Configuration

### Environment Variables

Set these in your `.env` or `selfhost.config.toml`:

```
DATABASE_URL=sqlite:///var/lib/selfhost/accounts.db
BIND_ADDR=127.0.0.1:9000
```

### Service Configuration (selfhost.config.toml)

Add the account-manager service:

```toml
[[services]]
name = "account-manager"
port = 9000
build_command = "cd crates/services/account-manager && cargo build --release"
run_command = "crates/services/account-manager/target/release/account-manager"
environment = [
  "DATABASE_URL=sqlite:///var/lib/selfhost/accounts.db",
  "BIND_ADDR=127.0.0.1:9000",
  "RUST_LOG=info"
]
health_check = "/health"
```

## Integration Points

### 1. VPN Server Integration

In your VPN server (e.g., `server.py` or VPN service), add a permission check:

```python
async def validate_vpn_connection(client_id, location_id):
    """Check if user has access to VPN location"""
    
    # Call the account manager API
    response = await httpx.post(
        "http://127.0.0.1:9000/api/vpn/check-access",
        json={
            "user_id": client_id,
            "location_id": location_id,
            "ip_address": client_ip,
        }
    )
    
    result = response.json()
    return result["allowed"], result["reason"]
```

### 2. Web UI Integration

For the admin console, integrate these endpoints:

**Registration Page** (`/register`):
- POST `/api/auth/register` to create new user account
- Includes WebAuthn passkey setup

**Login Page** (`/login`):
- POST `/api/auth/login` to authenticate
- Returns session token

**Admin Console** (`/admin/users`):
- GET `/api/users` - List all users
- GET `/api/users/{user_id}` - Get user details
- POST `/api/users/{user_id}/approve` - Approve pending registration
- POST `/api/users/{user_id}/permissions` - Grant location access
- POST `/api/vpn-locations` - Create new VPN location

## API Endpoints

### Authentication

```bash
# Register new user
curl -X POST http://localhost:9000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "email": "alice@example.com",
    "passkey_credential_id": "base64_encoded_credential"
  }'

# Login
curl -X POST http://localhost:9000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "passkey_assertion": "base64_encoded_assertion"
  }'

# Get current user info
curl -X GET http://localhost:9000/api/auth/whoami \
  -H "Authorization: Bearer <session_token>"
```

### User Management (Admin Only)

```bash
# List all users
curl -X GET http://localhost:9000/api/users

# Approve pending user
curl -X POST http://localhost:9000/api/users/{user_id}/approve \
  -H "Content-Type: application/json" \
  -d '{"approve": true}'

# Grant location access
curl -X POST http://localhost:9000/api/users/{user_id}/permissions \
  -H "Content-Type: application/json" \
  -d '{"location_id": "us-east-1"}'
```

### VPN Permission Check

```bash
# Check if user can access a location (called by VPN server)
curl -X POST http://localhost:9000/api/vpn/check-access \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "alice",
    "location_id": "us-east-1",
    "ip_address": "192.168.1.100"
  }'
```

Response:
```json
{
  "allowed": true,
  "reason": "Access granted",
  "user_name": "alice",
  "session_timeout": 86400
}
```

## Workflow: Register → Approve → Access VPN

### Step 1: User Registration

User visits `/register` and:
1. Enters username and email
2. Creates WebAuthn passkey
3. System creates "pending" user in database

```
POST /api/auth/register
→ User inserted with status='pending'
→ Admin notified of pending registration
```

### Step 2: Admin Approval

Admin visits `/admin/users` and:
1. Sees pending registration
2. Clicks "Approve"
3. User status changes to "active"

```
POST /api/users/{user_id}/approve
→ User status='active'
→ Email sent to user confirming approval
```

### Step 3: Grant Location Access

Admin clicks "Grant Access" for specific location:

```
POST /api/users/{user_id}/permissions
→ location_permissions entry created
→ User can now access that VPN location
```

### Step 4: User Connects to VPN

User logs in and selects VPN location:

```
VPN Client → Server
Server calls: POST /api/vpn/check-access
Account Manager checks:
  - User status = 'active' ✓
  - User approved_at IS NOT NULL ✓
  - User has location_permissions entry ✓
  → Returns "allowed": true
Server → Opens VPN tunnel
```

## Database Schema Overview

### Core Tables

- **users**: User accounts with registration status and approval state
- **roles**: Role definitions (Admin, Operator, Viewer)
- **permissions**: Permission definitions (create_site, edit_vpn, etc.)
- **user_roles**: Maps users to roles (many-to-many)
- **role_permissions**: Maps roles to permissions (many-to-many)

### VPN-Specific Tables

- **vpn_locations**: Available VPN locations/endpoints
- **location_permissions**: User access to specific locations
- **vpn_access_log**: Records of VPN connection attempts and results

### Audit & Security

- **sessions**: Active login sessions with expiration
- **audit_log**: Record of all administrative actions
- **image_auth**: Image-based authentication data
- **action_approvals**: Time-limited action approvals

## Permission Model

### Role-Based Access Control

Three default roles:
- **Admin**: Full access - create users, approve registrations, manage locations
- **Operator**: Operational access - create locations, grant permissions
- **Viewer**: Read-only - view logs and status

### Location-Based Access

Each user can be granted access to specific VPN locations:
- User Alice → Access to "home" and "work" locations
- User Bob → Access to only "office" location

### Action Approval

Temporary approvals for specific actions:
- Action: "create_peer"
- Location: "server-1"
- Expires: 30 days

## Security Considerations

### Password-less Authentication
- Uses WebAuthn passkeys instead of passwords
- More secure against phishing
- Hardware-backed on modern devices

### Time-locked Access
- VPN access tied to image-based time-locked keys
- Keys valid for 30 seconds only
- Requires real-time image source (orchid-images service)

### Audit Trail
- All actions logged with timestamps
- Tracks who approved what and when
- Full compliance audit available

### Session Management
- Sessions expire after 24 hours
- Can be revoked immediately
- Tracks IP and user agent for security

## Troubleshooting

### User can't register
Check:
- `/api/auth/register` endpoint is accessible
- DATABASE_URL is set correctly
- Database has been initialized with schema

### Registration pending forever
Check:
- Admin hasn't visited `/admin/users`
- Approval endpoint is working
- Check audit_log for any errors

### VPN access denied
Check:
- User is "active" (approved)
- User has location_permissions entry
- VPN server is calling `/api/vpn/check-access` correctly

### Database errors
Check:
- SQLite database file exists and is writable
- Or PostgreSQL connection string is correct
- Migrations have been run

## Testing

### Quick Test Script

```bash
#!/bin/bash

BASE_URL="http://localhost:9000"

# 1. Register user
USER_RESP=$(curl -s -X POST $BASE_URL/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "passkey_credential_id": "dGVzdF9jcmVkZW50aWFsX2lk"
  }')

USER_ID=$(echo $USER_RESP | jq -r '.user_id')
echo "Created user: $USER_ID"

# 2. Approve user
curl -s -X POST $BASE_URL/api/users/$USER_ID/approve \
  -H "Content-Type: application/json" \
  -d '{"approve": true}'
echo "Approved user"

# 3. Create location
LOC_RESP=$(curl -s -X POST $BASE_URL/api/vpn-locations \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-location",
    "description": "Test VPN Location",
    "region": "us-east-1"
  }')

LOCATION_ID=$(echo $LOC_RESP | jq -r '.id')
echo "Created location: $LOCATION_ID"

# 4. Grant permission
curl -s -X POST $BASE_URL/api/users/$USER_ID/permissions \
  -H "Content-Type: application/json" \
  -d "{\"location_id\": \"$LOCATION_ID\"}"
echo "Granted permission"

# 5. Check VPN access
curl -s -X POST $BASE_URL/api/vpn/check-access \
  -H "Content-Type: application/json" \
  -d "{
    \"user_id\": \"$USER_ID\",
    \"location_id\": \"$LOCATION_ID\"
  }" | jq .
```

## Next Steps

1. **Create UI Pages**:
   - Registration form
   - Login form
   - Admin console for user management

2. **Integrate with VPN Server**:
   - Update VPN authentication to call account manager
   - Log VPN access attempts

3. **Set up Email Notifications**:
   - Notify on registration
   - Notify on approval
   - Notify on suspension

4. **Implement WebAuthn**:
   - Use `webauthn-rs` crate for proper WebAuthn support
   - Currently passkey verification is stubbed

5. **Production Deployment**:
   - Test on Windows/Linux production box
   - Set up database backups
   - Monitor performance and audit logs
