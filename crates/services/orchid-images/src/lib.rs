use std::sync::Arc;
use parking_lot::RwLock;
use std::time::SystemTime;
use sha3::{Sha3_256, Digest};

#[derive(Clone)]
pub struct Frame {
    pub data: Vec<u8>,
    pub timestamp: f64,
    pub size: usize,
}

impl Frame {
    pub fn id(&self) -> String {
        format!("{:x}", self.timestamp.to_bits())
    }
}

pub struct FrameStore {
    current: Arc<RwLock<Option<Frame>>>,
}

impl FrameStore {
    pub fn new() -> Self {
        Self {
            current: Arc::new(RwLock::new(None)),
        }
    }

    pub fn update(&self, data: Vec<u8>) {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let size = data.len();
        let frame = Frame {
            data,
            timestamp,
            size,
        };

        *self.current.write() = Some(frame);
    }

    pub fn get(&self) -> Option<Frame> {
        self.current.read().clone()
    }
}

impl Clone for FrameStore {
    fn clone(&self) -> Self {
        Self {
            current: Arc::clone(&self.current),
        }
    }
}

// Entropy extraction and time-locked key derivation for visual-entropy VPN auth

/// Time bucket duration in seconds. Keys derived from the same time bucket are identical,
/// forcing key rotation every TIME_BUCKET_SECS seconds.
pub const TIME_BUCKET_SECS: u64 = 30;

/// Computes the SHA3-256 entropy hash of image data.
/// Used to validate image integrity during VPN authentication.
pub fn image_entropy(image_data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(image_data);
    hasher.finalize().to_vec()
}

/// Computes the time bucket for a given Unix timestamp.
/// All timestamps in the same bucket produce the same derived key.
fn time_bucket(timestamp_secs: u64) -> u64 {
    (timestamp_secs / TIME_BUCKET_SECS) * TIME_BUCKET_SECS
}

/// Derives a time-locked authentication key from image data and current timestamp.
/// The key is valid only for the time bucket it was derived in, forcing periodic rotation.
///
/// Key derivation: SHA3-256(image_data || time_bucket_big_endian)
/// Time bucket: floor(unix_timestamp / 30) * 30
///
/// # Arguments
/// * `image_data` - The raw JPEG image bytes
/// * `timestamp_secs` - Current Unix timestamp in seconds (from the server)
///
/// # Returns
/// 32-byte derived key
pub fn derive_auth_key(image_data: &[u8], timestamp_secs: u64) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    // Time bucket-based derivation: same bucket → same key
    let bucket = time_bucket(timestamp_secs);
    hasher.update(image_data);
    hasher.update(bucket.to_be_bytes());

    let hash = hasher.finalize();
    hash.to_vec()
}

/// Validates an authentication key against current image data and timestamp.
/// Accepts keys from the current time bucket and the previous bucket (to allow clock skew).
///
/// # Arguments
/// * `image_data` - The stored JPEG image bytes on the server
/// * `provided_key` - The 32-byte key provided by the VPN client
/// * `current_time_secs` - Current Unix timestamp on the server
///
/// # Returns
/// true if key is valid and current, false if expired or mismatched
pub fn validate_auth_key(
    image_data: &[u8],
    provided_key: &[u8],
    current_time_secs: u64,
) -> bool {
    if provided_key.len() != 32 {
        return false;
    }

    // Accept keys from current bucket and previous bucket
    let current_bucket = time_bucket(current_time_secs);
    let prev_bucket = current_bucket.saturating_sub(TIME_BUCKET_SECS);

    // Check current bucket
    let current_key = derive_auth_key(image_data, current_bucket);
    if constant_time_compare(&current_key, provided_key) {
        return true;
    }

    // Check previous bucket (to allow clock skew)
    let prev_key = derive_auth_key(image_data, prev_bucket);
    if constant_time_compare(&prev_key, provided_key) {
        return true;
    }

    false
}

/// Constant-time byte slice comparison to prevent timing attacks.
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
