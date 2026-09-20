//! Percent-encoding for one path segment of a request target.
//!
//! A request line is split on spaces and a path on `/`, so a value placed in a
//! path — a Person's name, a file name — must be encoded by whoever builds the
//! request and decoded, once, by whoever reads the segment. Both halves live
//! here so they cannot disagree.

/// Encodes one path segment or query value.
///
/// Deliberately conservative — everything outside `[A-Za-z0-9._~-]` is
/// escaped — because over-escaping costs a longer request line and
/// under-escaping costs a byte that changes which route the request reaches.
pub fn encode_segment(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'~' | b'-' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Decodes one path segment, once. `None` for a malformed escape, an encoded
/// NUL, or bytes that are not UTF-8 — a segment that does not decode names
/// nothing, and the caller refuses it rather than guessing.
pub fn decode_segment(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'%' {
            let high = char::from(*bytes.get(index + 1)?).to_digit(16)?;
            let low = char::from(*bytes.get(index + 2)?).to_digit(16)?;
            let decoded = (high * 16 + low) as u8;
            if decoded == 0 {
                return None;
            }
            out.push(decoded);
            index += 3;
        } else {
            out.push(byte);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_segment_survives_the_round_trip() {
        for text in ["Jane Doe", "J. Alex", "plain-name", "a/b?c#d%e", "Zoë"] {
            let encoded = encode_segment(text);
            assert!(!encoded.contains(' ') && !encoded.contains('/'), "{encoded}");
            assert_eq!(decode_segment(&encoded).as_deref(), Some(text));
        }
        assert_eq!(encode_segment("Jane Doe"), "Jane%20Doe");
    }

    #[test]
    fn a_malformed_segment_names_nothing() {
        assert_eq!(decode_segment("a%2"), None);
        assert_eq!(decode_segment("a%zz"), None);
        assert_eq!(decode_segment("a%00b"), None);
        assert_eq!(decode_segment("%FF"), None);
    }
}
