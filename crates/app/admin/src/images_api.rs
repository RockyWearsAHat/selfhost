//! Visual-entropy image storage and VPN authentication.
//!
//! # Overview
//!
//! The orchid-images service provides visual entropy for VPN authentication.
//! This API manages the latest image and serves it to VPN clients, which derive
//! time-locked authentication keys from the image + timestamp.
//!
//! # Endpoints
//!
//! - `POST /api/images/push` — Accept image from Windows PC (unauthenticated)
//! - `GET /api/images/latest` — Serve latest image to VPN clients (public)

use selfhost_http::{Response, Status};
use selfhost_json::Json;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::BTreeMap;

/// Metadata stored with each image.
#[derive(Clone, Debug)]
pub struct ImageEntry {
    /// Raw JPEG image bytes.
    pub data: Vec<u8>,
    /// Unix timestamp when image was pushed to the server.
    pub timestamp_secs: u64,
    /// SHA3-256 entropy hash of the image data.
    pub entropy_hash: Vec<u8>,
    /// Number of times this image slot has been updated.
    pub push_count: u64,
}

/// Thread-safe image storage.
pub struct ImageStore {
    entry: Arc<Mutex<Option<ImageEntry>>>,
}

impl ImageStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self {
            entry: Arc::new(Mutex::new(None)),
        }
    }

    /// Update the stored image.
    pub fn update(&self, data: Vec<u8>, entropy_hash: Vec<u8>) {
        let timestamp_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut store = self.entry.lock().unwrap();
        let push_count = store.as_ref().map(|e| e.push_count).unwrap_or(0) + 1;

        *store = Some(ImageEntry {
            data,
            timestamp_secs,
            entropy_hash,
            push_count,
        });
    }

    /// Get the current stored image.
    pub fn get(&self) -> Option<ImageEntry> {
        self.entry.lock().unwrap().clone()
    }
}

impl Clone for ImageStore {
    fn clone(&self) -> Self {
        Self {
            entry: Arc::clone(&self.entry),
        }
    }
}

impl Default for ImageStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to construct JSON responses
fn json(status: Status, value: Json) -> Response {
    Response::bytes(
        status,
        "application/json; charset=utf-8",
        value.to_text().into_bytes(),
    )
    .unwrap_or_else(|_| Response::empty(Status(500)))
}

/// Helper to construct error responses
fn problem(status: Status, message: &str) -> Response {
    json(status, Json::object([("error", Json::string(message))]))
}

/// Handle `POST /api/images/push` — accept image from Windows PC.
pub fn push_image(
    store: &ImageStore,
    body: &[u8],
) -> Response {
    // Validate image payload
    if body.is_empty() {
        return problem(Status(400), "image cannot be empty");
    }

    if body.len() > 10 * 1024 * 1024 {
        return problem(Status(413), "image too large (max 10 MiB)");
    }

    // Verify it looks like a JPEG (starts with FFD8FFE0 or FFD8FFE1)
    if body.len() < 2 || body[0] != 0xFF || body[1] != 0xD8 {
        return problem(Status(400), "not a valid JPEG image");
    }

    // Compute entropy hash
    let entropy_hash = selfhost_orchid_images::image_entropy(body);

    // Store it
    store.update(body.to_vec(), entropy_hash.clone());

    // Return success
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut obj = BTreeMap::new();
    obj.insert("status".to_string(), Json::string("ok"));
    obj.insert("timestamp".to_string(), Json::Number(timestamp as f64));
    obj.insert("image_hash".to_string(), Json::string(&hex_encode(&entropy_hash)));

    json(Status(200), Json::Object(obj))
}

/// Handle `GET /api/images/latest` — serve latest image to VPN clients.
pub fn get_latest_image(store: &ImageStore) -> Response {
    match store.get() {
        Some(entry) => {
            // Encode image as base64 for JSON transport
            let image_b64 = base64_encode(&entry.data);

            let mut obj = BTreeMap::new();
            obj.insert("status".to_string(), Json::string("ok"));
            obj.insert("image".to_string(), Json::string(&image_b64));
            obj.insert("timestamp".to_string(), Json::Number(entry.timestamp_secs as f64));
            obj.insert("image_hash".to_string(), Json::string(&hex_encode(&entry.entropy_hash)));
            obj.insert("push_count".to_string(), Json::Number(entry.push_count as f64));

            json(Status(200), Json::Object(obj))
        }
        None => problem(Status(503), "no image available yet"),
    }
}

/// Encode bytes as hex string.
fn hex_encode(data: &[u8]) -> String {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    let mut result = String::with_capacity(data.len() * 2);
    for byte in data {
        result.push(HEX_CHARS[(byte >> 4) as usize] as char);
        result.push(HEX_CHARS[(byte & 0xf) as usize] as char);
    }
    result
}

/// Encode bytes as base64.
fn base64_encode(data: &[u8]) -> String {
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b1 = data[i];
        let b2 = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let b3 = if i + 2 < data.len() { data[i + 2] } else { 0 };

        let n = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);

        result.push(BASE64_CHARS[((n >> 18) & 63) as usize] as char);
        result.push(BASE64_CHARS[((n >> 12) & 63) as usize] as char);

        if i + 1 < data.len() {
            result.push(BASE64_CHARS[((n >> 6) & 63) as usize] as char);
        } else {
            result.push('=');
        }

        if i + 2 < data.len() {
            result.push(BASE64_CHARS[(n & 63) as usize] as char);
        } else {
            result.push('=');
        }

        i += 3;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(base64_encode(b"world"), "d29ybGQ=");
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(b"\x00\xFF"), "00ff");
    }

    #[test]
    fn test_image_store() {
        let store = ImageStore::new();
        assert!(store.get().is_none());

        let image = vec![0xFF, 0xD8, 0x00, 0x01, 0x02];
        let hash = selfhost_orchid_images::image_entropy(&image);
        store.update(image.clone(), hash);

        let entry = store.get().unwrap();
        assert_eq!(entry.data, image);
        assert_eq!(entry.push_count, 1);
    }
}
