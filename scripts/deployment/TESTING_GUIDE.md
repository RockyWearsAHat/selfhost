# Account System Testing & Validation Guide

## Quick Start (5 minutes)

### Terminal 1: Start Backend
```bash
cd /Users/alexwaldmann/Desktop/Self-Host/crates/services/account-manager
DATABASE_URL="sqlite:///Users/alexwaldmann/.selfhost/data/accounts.db" \
BIND_ADDR="127.0.0.1:9000" \
cargo run --release
```

You should see:
```
Server running on 127.0.0.1:9000
Health check: GET /health
```

### Terminal 2: Start Frontend
```bash
cd /Users/alexwaldmann/Desktop/Self-Host/crates/ui/account-console
npm run dev
```

You should see:
```
  ➜  Local:   http://localhost:3000
```

### Terminal 3: Test & Explore
Open browser to `http://localhost:3000`

---

## Test Flow 1: User Registration

### Step 1: Register New User
1. Click "Sign Up" or go to `/register`
2. Enter email: `test@example.com`
3. Click "Set Up Passkey"
4. Browser will prompt for biometric (Touch ID/Face ID) or security key
5. Complete passkey registration
6. Click "Create Account"
7. Should redirect to login screen

### Verify Backend
```bash
# Check database for new user
sqlite3 ~/.selfhost/data/accounts.db << 'SQL'
SELECT id, username, email, status FROM users WHERE email='test@example.com';
SQL
```

Expected output:
```
<uuid>|test|test@example.com|pending
```

---

## Test Flow 2: User Approval (Admin Flow)

### Step 1: Approve User Registration
```bash
# Get user ID from database
USER_ID=$(sqlite3 ~/.selfhost/data/accounts.db "SELECT id FROM users WHERE email='test@example.com' LIMIT 1;")
echo "User ID: $USER_ID"

# Approve user
curl -X POST http://localhost:9000/api/users/$USER_ID/approve \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-token" \
  -d '{}'
```

### Step 2: Verify Approval
```bash
# Check user status changed to 'active'
sqlite3 ~/.selfhost/data/accounts.db << SQL
SELECT id, email, status FROM users WHERE id='$USER_ID';
SQL
```

Expected output:
```
<uuid>|test@example.com|active
```

---

## Test Flow 3: VPN Location Access

### Step 1: Create VPN Location
```bash
sqlite3 ~/.selfhost/data/accounts.db << 'SQL'
INSERT INTO vpn_locations (id, name, subdomain, description, region, country)
VALUES ('us-east-1', 'US East 1', 'us-east-1.vpn', 'New York server', 'US East', 'USA');
SQL
```

### Step 2: Grant User Access to Location
```bash
USER_ID=$(sqlite3 ~/.selfhost/data/accounts.db "SELECT id FROM users WHERE email='test@example.com' LIMIT 1;")

curl -X POST http://localhost:9000/api/users/$USER_ID/permissions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer admin-token" \
  -d '{
    "resource_type": "vpn_location",
    "resource_id": "us-east-1",
    "action": "read"
  }'
```

### Step 3: Verify Permission
```bash
# Check permission in database
sqlite3 ~/.selfhost/data/accounts.db << SQL
SELECT user_id, resource_type, resource_id, action FROM permissions WHERE user_id='$USER_ID';
SQL
```

Expected output:
```
<uuid>|vpn_location|us-east-1|read
```

---

## Test Flow 4: VPN Permission Enforcement

### Step 1: Test Access Check - ALLOWED
```bash
USER_ID=$(sqlite3 ~/.selfhost/data/accounts.db "SELECT id FROM users WHERE email='test@example.com' LIMIT 1;")

curl -X POST http://localhost:9000/api/vpn/check-access \
  -H "Content-Type: application/json" \
  -d "{
    \"user_id\": \"$USER_ID\",
    \"location_id\": \"us-east-1\",
    \"ip_address\": \"192.168.1.100\"
  }"
```

Expected response:
```json
{
  "allowed": true,
  "reason": "Access granted",
  "user_name": "test@example.com",
  "session_timeout": 86400
}
```

### Step 2: Test Access Check - DENIED (Different Location)
```bash
curl -X POST http://localhost:9000/api/vpn/check-access \
  -H "Content-Type: application/json" \
  -d "{
    \"user_id\": \"$USER_ID\",
    \"location_id\": \"eu-west-1\",
    \"ip_address\": \"192.168.1.100\"
  }"
```

Expected response:
```json
{
  "allowed": false,
  "reason": "User does not have access to location eu-west-1",
  "user_name": "test@example.com",
  "session_timeout": null
}
```

---

## Test Flow 5: Login with Passkey

### Step 1: Login via UI
1. Go to `http://localhost:3000/login`
2. Enter email: `test@example.com`
3. Click "Login with Passkey"
4. Browser prompts for biometric
5. Complete authentication
6. Redirected to dashboard

### Step 2: Verify Session Token
```bash
# Browser console should show token (F12 → Console)
console.log(localStorage.getItem('auth_token'))
```

### Step 3: Verify Session in Database
```bash
USER_ID=$(sqlite3 ~/.selfhost/data/accounts.db "SELECT id FROM users WHERE email='test@example.com' LIMIT 1;")

sqlite3 ~/.selfhost/data/accounts.db << SQL
SELECT id, user_id, expires_at FROM sessions WHERE user_id='$USER_ID' LIMIT 1;
SQL
```

---

## Test Flow 6: Permission Revocation

### Step 1: Revoke Access
```bash
USER_ID=$(sqlite3 ~/.selfhost/data/accounts.db "SELECT id FROM users WHERE email='test@example.com' LIMIT 1;")
PERM_ID=$(sqlite3 ~/.selfhost/data/accounts.db "SELECT id FROM permissions WHERE user_id='$USER_ID' LIMIT 1;")

curl -X DELETE http://localhost:9000/api/users/$USER_ID/permissions/$PERM_ID \
  -H "Authorization: Bearer admin-token"
```

### Step 2: Verify Revocation
```bash
# Try to access location again
curl -X POST http://localhost:9000/api/vpn/check-access \
  -H "Content-Type: application/json" \
  -d "{
    \"user_id\": \"$USER_ID\",
    \"location_id\": \"us-east-1\"
  }"
```

Expected response (denied):
```json
{
  "allowed": false,
  "reason": "User does not have access to location us-east-1"
}
```

---

## Test Flow 7: Audit Logging

### Step 1: Check Audit Log
```bash
sqlite3 ~/.selfhost/data/accounts.db << 'SQL'
SELECT timestamp, action, resource_type, status FROM audit_log LIMIT 10;
SQL
```

Expected rows:
- User registration
- User approval
- Permission grant
- Permission revocation

### Step 2: Verify VPN Access Log
```bash
sqlite3 ~/.selfhost/data/accounts.db << 'SQL'
SELECT timestamp, event_type, status FROM vpn_access_log LIMIT 10;
SQL
```

Expected rows:
- connect (status: success)
- connect (status: denied)

---

## Troubleshooting

### Backend Won't Start
```bash
# Check database exists
ls -la ~/.selfhost/data/accounts.db

# Check port 9000 is available
lsof -i :9000

# Check environment variables
echo $DATABASE_URL
echo $BIND_ADDR
```

### Frontend Won't Connect to Backend
1. Check backend is running on 9000
2. Check proxy in vite.config.ts points to `http://localhost:9000`
3. Open browser DevTools (F12) → Network tab
4. Try to make a request, check CORS errors

### Passkey Registration Fails
1. Must be HTTPS in production or localhost for dev
2. Browser must support WebAuthn (Chrome, Firefox, Safari 13+)
3. Check browser console for errors (F12 → Console)

### Database Errors
1. Check database file path is correct
2. Verify schema was applied: `sqlite3 ~/.selfhost/data/accounts.db ".tables"`
3. Should show: `audit_log`, `passkeys`, `permissions`, `roles`, `sessions`, `users`, etc.

---

## Success Criteria

- [x] Backend service starts without errors
- [x] Frontend loads and connects to backend
- [x] User can register with email and passkey
- [x] User registration creates database entry with status=pending
- [x] Admin can approve user (status→active)
- [x] Admin can grant VPN location permission
- [x] Permission check returns allowed=true when user has permission
- [x] Permission check returns allowed=false when user lacks permission
- [x] User can login with passkey
- [x] Audit log records all actions
- [x] VPN access log records permission checks

When all criteria are met, the account system is fully operational and ready for VPN integration.

---

## Next: VPN Server Integration

Once all tests pass, update the VPN server (Secure-VPN/server.py) to call:

```python
POST /api/vpn/check-access HTTP/1.1
Host: localhost:9000
Content-Type: application/json

{
  "user_id": "...",
  "location_id": "...",
  "ip_address": "..."
}
```

Before allowing a VPN connection.

See IMPLEMENTATION_GUIDE.md for full details.
