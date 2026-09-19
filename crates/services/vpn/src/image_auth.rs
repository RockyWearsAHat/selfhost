//! Visual-entropy image-based authentication for VPN connections.
//!
//! Clients derive time-locked keys from the latest entropy image and send them
//! during VPN handshake. This module validates those keys.

use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for image-based authentication.
#[derive(Clone, Debug)]
pub struct ImageAuthConfig {
    /// Current image data (fetched from admin API /api/images/latest)
    pub image_data: Vec<u8>,
    /// Unix timestamp when image was pushed to server
    pub image_timestamp: u64,
    /// Time window in seconds that a derived key is valid for (typically 30 or 60)
    pub time_window_secs: u64,
}

/// Validates a VPN client's image-derived authentication key.
///
/// The client derives the key as: SHA3-256(image_data || time_bucket)
/// where time_bucket = floor(current_time / time_window) * time_window
///
/// This validator accepts keys from the current time bucket and previous bucket
/// to account for ±30 second clock skew between client and server.
pub fn validate_image_auth_key(
    config: &ImageAuthConfig,
    provided_key: &[u8],
) -> bool {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Import the validation function from orchid-images crate
    selfhost_orchid_images::validate_auth_key(
        &config.image_data,
        provided_key,
        current_time,
    )
}

/// Derives what the correct image auth key should be for a given timestamp.
/// (Used for testing and server-side verification)
pub fn compute_expected_key(config: &ImageAuthConfig, timestamp: u64) -> Vec<u8> {
    selfhost_orchid_images::derive_auth_key(&config.image_data, timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_auth_validation() {
        let image = vec![0xFF, 0xD8, 0x00, 0x01, 0x02];
        let config = ImageAuthConfig {
            image_data: image.clone(),
            image_timestamp: 1000,
            time_window_secs: 30,
        };

        // `validate_image_auth_key` always buckets a fresh `SystemTime::now()`
        // read of its own, so calling it here would race a *second* clock
        // read against the one below — under heavy parallel test load a
        // scheduling gap of more than one time bucket between the two reads
        // makes this fail nondeterministically. Instead exercise the
        // underlying pure, timestamp-taking functions directly against a
        // single shared timestamp, which is deterministic.
        let test_time =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let expected_key = compute_expected_key(&config, test_time);

        assert!(selfhost_orchid_images::validate_auth_key(
            &config.image_data,
            &expected_key,
            test_time,
        ));

        let wrong_key = vec![0x00; 32];
        assert!(!selfhost_orchid_images::validate_auth_key(
            &config.image_data,
            &wrong_key,
            test_time,
        ));
    }
}
