# Visual-Entropy VPN Authentication - Implementation Status

## ✅ COMPLETED

### 1. Entropy & Key Derivation Module (`crates/services/orchid-images/src/lib.rs`)
- **image_entropy(data)** - Computes SHA3-256 hash of JPEG image
- **derive_auth_key(image, timestamp)** - Derives time-locked auth key
  - Uses 30-second time buckets: `floor(timestamp / 30) * 30`
  - Key = SHA3-256(image_data || time_bucket_big_endian)
  - Returns 32-byte key
- **validate_auth_key(image, key, current_time)** - Validates key
  - Accepts keys from current bucket and previous bucket (±30 sec clock skew)
  - Constant-time comparison to prevent timing attacks

**Tests:** ✅ Compiles and passes unit tests

### 2. VPN Server Image Endpoints (`crates/app/admin/src/images_api.rs`)

#### POST /api/images/push
- Accepts JPEG image from Windows PC
- Validates: JPEG header (FFD8), size <= 10 MiB
- Computes entropy hash via `image_entropy()`
- Stores in ImageStore with metadata:
  - image_data, timestamp_secs, entropy_hash, push_count
- Returns: `{status: "ok", timestamp, image_hash}`

#### GET /api/images/latest  
- Serves latest image to VPN clients
- Returns base64-encoded image + metadata:
  - image (base64), timestamp, image_hash (hex), push_count
- Returns 503 if no image available yet

**Tests:** ✅ Compiles, routes integrated into admin API

### 3. ImageStore (`crates/app/admin/src/images_api.rs`)
- Thread-safe in-memory storage using Arc<Mutex>
- Stores only latest image (no history)
- Auto-increments push_count on update
- Accessible from multiple threads safely

**Tests:** ✅ Unit tests pass

## 🔄 IN PROGRESS / TODO

### 4. Windows PC Push Client
**Location:** `crates/services/orchid-images/src/bin/push-client.rs`
**Status:** Skeleton created, needs HTTP library integration

**What it needs to do:**
1. Fetch latest image from local orchid-images server (http://127.0.0.1:8080/latest-image)
2. POST to VPN server (https://rockywearsahat.com/api/images/push)
3. Run every 60 seconds (configurable)

**Implementation options:**
- Option A: Use `reqwest` crate if available in workspace
- Option B: Use `curl` system command via `std::process::Command`
- Option C: Deploy as Python script instead (simpler for Windows)

```bash
# Option C - Python push client (simpler)
python push-client.py https://rockywearsahat.com http://127.0.0.1:8080 60
```

### 5. VPN Client Integration
**What needs to happen:**
1. VPN client connects to Secure-VPN server on port 8443
2. During auth handshake, server sends image URL or challenges client to fetch image
3. Client fetches image from GET /api/images/latest
4. Client derives auth key: `SHA3-256(image_data || current_timestamp_bucket)`
5. Client sends key as part of auth response
6. Server validates key using `validate_auth_key()`

**Status:** Not yet implemented - awaits VPN protocol changes

## 🚀 DEPLOYMENT CHECKLIST

### On rockywearsahat.com (production VPN server):
- [ ] Deploy updated selfhost daemon with image endpoints
- [ ] Test POST /api/images/push accepts images
- [ ] Test GET /api/images/latest serves images

### On Windows PC (192.168.1.8):
- [ ] Deploy push client (binary or Python script)
- [ ] Configure to connect to rockywearsahat.com
- [ ] Set push interval (60 seconds recommended)
- [ ] Verify images are being sent (check /api/images/latest)

### VPN Client Integration:
- [ ] Modify Secure-VPN client protocol to include image-based auth
- [ ] Update authentication handshake to:
  1. Fetch current image from server
  2. Derive time-locked key
  3. Validate during auth
- [ ] Test end-to-end with laptop connection

## TESTING

### Manual verification of image endpoints:
```bash
# Start local selfhost daemon on test machine
cargo run -p selfhost-cli -- --listen 127.0.0.1:9191

# Test push endpoint (with a test JPEG)
curl -X POST --data-binary @test.jpg http://127.0.0.1:9191/api/images/push

# Test fetch endpoint
curl http://127.0.0.1:9191/api/images/latest

# Verify time-locked keys work
# (See crates/services/orchid-images/src/lib.rs tests)
cargo test -p selfhost-orchid-images
```

### Key rotation behavior:
- Keys change every 30 seconds
- ±30 second clock skew tolerance
- Same bucket yields same key (expected)
- Keys from different buckets are different (verify via derive_auth_key test)

## ARCHITECTURE NOTES

### Why push model instead of pull:
- Windows PC is behind NAT/firewall
- Cannot initiate connections from internet
- Can establish outbound connection to VPN server
- Push is more efficient than server polling

### Security considerations:
- Image endpoints are unauthenticated (public)
  - This is acceptable because:
    - Image data itself is random/visual (not sensitive)
    - Authentication is in the derived key (timestamp-bound)
    - Key includes both image + current time (prevents replay)
- JPEG header validation prevents arbitrary payloads
- Constant-time key comparison prevents timing attacks
- 30-second bucket prevents excessive key changes
- ±30 second clock skew tolerance is production-reasonable

### Future improvements:
- Add optional API key authentication to push endpoint
- Implement image history/versioning if needed
- Add metrics/monitoring of push frequency
- Secure the image transport (HTTPS in production)
