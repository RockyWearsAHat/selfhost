# Visual-Entropy VPN Authentication - Deployment Guide

## Quick Start (5 minutes)

### Prerequisites
- Rust toolchain installed on dev machine
- Python 3 on Windows PC
- Access to rockywearsahat.com server
- Windows PC with local orchid-images server running on http://127.0.0.1:8080

### Step 1: Deploy to VPN Server (rockywearsahat.com)
```bash
cd /path/to/selfhost
cargo build --release -p selfhost-cli
# Copy binary to rockywearsahat.com and restart daemon
# The admin API will automatically serve the new image endpoints
```

### Step 2: Test Image Endpoints
```bash
# From the VPN server machine or through SSH tunnel:

# Test push endpoint (requires a JPEG file)
curl -X POST --data-binary @test.jpg https://rockywearsahat.com/api/images/push

# Test fetch endpoint  
curl https://rockywearsahat.com/api/images/latest | jq .
# Should return base64-encoded image + metadata
```

### Step 3: Deploy Push Client to Windows PC
```powershell
# On Windows PC:

# Install Python 3 if not already installed
# https://www.python.org/downloads/

# Copy push-client script
# From selfhost repo: scripts/orchid-push-client.py

# Run the push client
python orchid-push-client.py https://rockywearsahat.com http://127.0.0.1:8080 60

# To run at startup, create scheduled task or add to startup folder
```

### Step 4: Verify Images Are Flowing
```bash
# Check that push-client is sending images
# Should see logs like "✓ Image pushed (12345 bytes)"

# From VPN server, verify latest image is being updated
curl -s https://rockywearsahat.com/api/images/latest | jq '.timestamp'
# Should be recent timestamps

# Verify entropy hash is being computed
curl -s https://rockywearsahat.com/api/images/latest | jq '.image_hash'
# Should be a 64-character hex string (SHA3-256)
```

## Integration with VPN Client (Next Step)

### What needs to be done:
The VPN authentication protocol needs to be updated to use the image-based time-locked keys.

### Current architecture:
- Secure-VPN server: `https://github.com/RockyWearsAHat/Secure-VPN.git`
- File: `scripts/securevpn/app/protocol.py`

### Changes needed in server.py:
```python
# During VPN handshake, server should:
1. Have access to the latest image (fetch from /api/images/latest)
2. Get current timestamp
3. On successful key derivation: validate_auth_key(image_data, client_key, current_time)
   - Import from selfhost-orchid-images crate OR reimplement logic in Python

# The validation logic in Python:
def validate_auth_key(image_data: bytes, provided_key: bytes, current_time: int) -> bool:
    """Validate time-locked key."""
    def time_bucket(ts: int) -> int:
        return (ts // 30) * 30
    
    def derive_key(img: bytes, ts: int) -> bytes:
        from hashlib import sha3_256
        bucket = time_bucket(ts)
        return sha3_256(img + bucket.to_bytes(8, 'big')).digest()
    
    current_bucket = time_bucket(current_time)
    if derive_key(image_data, current_bucket) == provided_key:
        return True
    
    prev_bucket = current_bucket - 30
    if derive_key(image_data, prev_bucket) == provided_key:
        return True
    
    return False
```

### Changes needed in VPN client:
1. When connecting to server, fetch `/api/images/latest`
2. Extract image_data (base64 decode)
3. Derive auth key: `SHA3-256(image_data || time_bucket)`
4. Send key as part of authentication
5. Handle key expiry (if validation fails, try previous bucket or refetch image)

## Troubleshooting

### Push client shows connection refused
- Check that rockywearsahat.com is reachable from Windows PC
- Verify VPN or firewall rules allow HTTPS outbound
- Test: `python -c "import requests; requests.get('https://rockywearsahat.com')"`

### Image push succeeds but /api/images/latest still returns 503
- Verify orchid-images server is running locally on Windows PC
- Check: `curl http://127.0.0.1:8080/status`
- Increase push frequency (reduce interval) to test: `python orchid-push-client.py ... 10`

### Key derivation doesn't match between Python and Rust
- Ensure time buckets match: `(timestamp // 30) * 30`
- Use big-endian byte order for timestamp: `timestamp.to_bytes(8, 'big')`
- Verify SHA3-256 implementation matches (not SHA-256!)

### VPN client authentication fails even with valid key
- Check timestamp synchronization between client and server
- Verify ±30 second clock skew tolerance is being applied
- Check that previous bucket is also being validated
- Enable debug logging on both client and server

## Testing Locally (Without Deploying)

### Test entropy module:
```bash
cd crates/services/orchid-images
cargo test
# Should see tests passing for image_entropy, derive_auth_key, validate_auth_key
```

### Test image endpoints (local):
```bash
# In a test setup with admin API running:
cargo run -p selfhost-admin-test 2>/dev/null &
sleep 1

# Create test JPEG (FF D8 header)
python3 -c "import sys; sys.stdout.buffer.write(b'\\xff\\xd8' + b'\\x00' * 1000)" > test.jpg

# Test push
curl -X POST --data-binary @test.jpg http://127.0.0.1:9191/api/images/push

# Test fetch
curl http://127.0.0.1:9191/api/images/latest | jq .

# Test key derivation
python3 crates/services/orchid-images/test_keys.py
```

## Key Files Changed

- `crates/services/orchid-images/src/lib.rs` - Entropy module, key derivation
- `crates/services/orchid-images/Cargo.toml` - Added sha3 dependency  
- `crates/app/admin/src/images_api.rs` - Image push/fetch endpoints
- `crates/app/admin/src/lib.rs` - Integrated endpoints, added ImageStore
- `crates/app/admin/Cargo.toml` - Added orchid-images dependency
- `scripts/orchid-push-client.py` - Windows PC push client
- `VISUAL-ENTROPY-VPN-STATUS.md` - Implementation status
- `DEPLOYMENT-GUIDE-VISUAL-ENTROPY.md` - This file

## Security Notes

✅ **Implemented:**
- Time-locked keys (30-second buckets)
- ±30 second clock skew tolerance
- JPEG header validation on push
- Constant-time key comparison
- Size limits (max 10 MiB per image)

⚠️ **Still TODO:**
- HTTPS enforcement (use CA-signed certs in production)
- Optional API key authentication for push endpoint
- Rate limiting on push endpoint
- Audit logging of successful/failed authentication

## Production Deployment Checklist

- [ ] Built selfhost binary with visual-entropy endpoints
- [ ] Deployed to rockywearsahat.com and restarted daemon
- [ ] Tested POST /api/images/push with real JPEG
- [ ] Tested GET /api/images/latest returns valid data
- [ ] Deployed push-client.py to Windows PC
- [ ] Configured push-client as scheduled task or service
- [ ] Verified images are flowing (timestamps updating)
- [ ] Updated Secure-VPN server.py with key validation
- [ ] Updated VPN client to fetch image + derive key
- [ ] Tested end-to-end: Windows PC → push image → VPN server → VPN client fetches → authenticates
- [ ] Monitored for errors in push-client logs for 24 hours
- [ ] Verified laptop can connect through VPN with new auth method
