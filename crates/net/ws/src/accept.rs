//! The handshake accept key, and the one base64 alphabet the rest of the
//! repository does not already speak.
//!
//! RFC 6455 §4.2.2 asks the server to prove it understood the handshake rather
//! than merely echoed it: take the client's `Sec-WebSocket-Key` exactly as it
//! arrived, concatenate the fixed GUID, SHA-1 the result, and return that digest
//! in base64 as `Sec-WebSocket-Accept`. The value is not a secret and it is not
//! authentication — a man in the middle can compute it as easily as we can. It
//! exists so that a *cache*, a *proxy*, or an HTTP server that has never heard of
//! WebSockets cannot accidentally complete a handshake by replaying a stored 101
//! response, because the digest is different for every key. That is the whole
//! job, and it is why SHA-1 is not a weakness here: no property of SHA-1 that has
//! been broken is a property this use depends on. `ring` names the constant
//! [`SHA1_FOR_LEGACY_USE_ONLY`](ring::digest::SHA1_FOR_LEGACY_USE_ONLY) precisely
//! so that a reader stops at this paragraph and asks; the answer is that the
//! specification names the algorithm and this is the specification.
//!
//! # Why a fourth base64 in this tree
//!
//! There are already two hand-written base64 implementations in the workspace,
//! and neither one can be used here. `crates/admin/src/webauthn.rs` has
//! `b64url_encode`, and `crates/acme/src/jose.rs` has `base64url`: both emit the
//! **URL-safe** alphabet (`-` and `_`) and both are **unpadded**, because that is
//! the only encoding JOSE, ACME and WebAuthn use. RFC 6455 wants the opposite on
//! both counts — the **standard** alphabet (`+` and `/`) with `=` padding — so an
//! accept key produced by either of them would be wrong in two ways at once and
//! would be rejected by every browser. They are also both `pub(crate)` in crates
//! that sit *above* this one in the dependency graph, so even a compatible
//! encoder would not have been reachable without inverting the layering.
//!
//! The encoder here is therefore private, twenty lines, and does one thing. The
//! decoder beside it exists only to answer a validation question — *is this key
//! sixteen bytes?* — and never hands its output to anything.

use ring::digest;

/// The GUID RFC 6455 §1.3 fixes for the accept-key derivation.
///
/// It is a constant of the protocol, not a parameter: it is written out in the
/// specification, every implementation uses this exact string, and changing a
/// character of it makes this server unable to talk to any browser.
const HANDSHAKE_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The standard base64 alphabet (RFC 4648 §4), which is the one this protocol uses.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The number of raw bytes a well-formed `Sec-WebSocket-Key` decodes to.
///
/// RFC 6455 §4.1 requires the client to send sixteen random bytes. Checking it
/// costs nothing and turns a whole class of confused non-WebSocket client — a
/// probe, a scanner, a misconfigured reverse proxy replaying a header it found —
/// into a clean refusal at the handshake instead of a stream that opens and then
/// fails to make sense.
const KEY_BYTES: usize = 16;

/// The exact length of the base64 text that encodes sixteen bytes with padding.
const KEY_TEXT_LEN: usize = 24;

/// Computes the `Sec-WebSocket-Accept` value for a client's `Sec-WebSocket-Key`.
///
/// `client_key` is passed through byte for byte, exactly as it arrived in the
/// header — the specification concatenates the *text* of the key, not its decoded
/// bytes, so trimming, re-encoding or normalising it here would produce a digest
/// the client does not expect. Validation of the key's shape is a separate
/// question, asked by [`client_key_is_well_formed`] before this is called; this
/// function is total and will happily hash a malformed key, because its job is
/// arithmetic and not judgement.
pub fn accept_key(client_key: &str) -> String {
    let mut input = String::with_capacity(client_key.len() + HANDSHAKE_GUID.len());
    input.push_str(client_key);
    input.push_str(HANDSHAKE_GUID);
    encode_standard(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, input.as_bytes()).as_ref())
}

/// Whether `key` is a `Sec-WebSocket-Key` that could have come from a real client.
///
/// True exactly when the text is padded standard base64 of sixteen bytes: the
/// length the specification fixes, in the alphabet it fixes. This is a shape
/// check and deliberately not a randomness check — we cannot tell sixteen random
/// bytes from sixteen zeroes, and nothing in the protocol depends on the key
/// being unpredictable. What it buys is that a client which sends a key of the
/// wrong length is told so at the handshake rather than at the first frame.
pub fn client_key_is_well_formed(key: &str) -> bool {
    key.len() == KEY_TEXT_LEN && decode_standard(key).is_some_and(|bytes| bytes.len() == KEY_BYTES)
}

/// Encodes bytes as padded standard base64 (RFC 4648 §4).
///
/// Padded and standard-alphabet, which is what RFC 6455 requires and what
/// neither existing encoder in this workspace produces. Total: it indexes the
/// alphabet only with values masked to six bits, and reads beyond the end of a
/// short final chunk through `get`, so no input length can panic.
fn encode_standard(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let bits = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(bits >> 18 & 0x3f) as usize] as char);
        out.push(ALPHABET[(bits >> 12 & 0x3f) as usize] as char);
        match chunk.len() {
            1 => out.push_str("=="),
            2 => {
                out.push(ALPHABET[(bits >> 6 & 0x3f) as usize] as char);
                out.push('=');
            }
            _ => {
                out.push(ALPHABET[(bits >> 6 & 0x3f) as usize] as char);
                out.push(ALPHABET[(bits & 0x3f) as usize] as char);
            }
        }
    }
    out
}

/// Decodes padded standard base64, or `None` if the text is not exactly that.
///
/// Strict on purpose, because its only caller is a validity check and a lenient
/// decoder would make that check meaningless: the length must be a multiple of
/// four, padding may only appear as the last one or two characters, and no
/// character outside the standard alphabet is tolerated. The decoded bytes are
/// never interpreted by anything — they are counted and dropped — so this is the
/// one place in the crate where being wrong costs a refused handshake rather
/// than anything worse.
fn decode_standard(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return None;
    }
    let padding = bytes.iter().rev().take_while(|&&byte| byte == b'=').count();
    if padding > 2 {
        return None;
    }
    let body = &bytes[..bytes.len() - padding];
    if body.contains(&b'=') {
        return None; // padding in the middle is not padding, it is corruption
    }

    let mut out = Vec::with_capacity(body.len() / 4 * 3);
    let mut accumulator: u32 = 0;
    let mut have: u32 = 0;
    for &byte in body {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(value);
        have += 6;
        if have >= 8 {
            have -= 8;
            out.push((accumulator >> have) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rfc_6455_vector_reproduces() {
        // RFC 6455 §1.3, the worked example every implementation is checked against.
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn the_accept_value_is_padded_standard_base64() {
        let accept = accept_key("dGhlIHNhbXBsZSBub25jZQ==");
        assert!(accept.ends_with('='), "a 20-byte digest always pads");
        assert!(!accept.contains('-') && !accept.contains('_'), "not the url alphabet");
        assert_eq!(accept.len(), 28, "20 bytes of SHA-1 encode to 28 characters");
    }

    #[test]
    fn the_key_text_is_hashed_verbatim_not_its_decoded_bytes() {
        // Two keys that decode to the same bytes but differ in text must give
        // different accepts — proof we are not normalising the input.
        let a = accept_key("dGhlIHNhbXBsZSBub25jZQ==");
        let b = accept_key("dGhlIHNhbXBsZSBub25jZQ");
        assert_ne!(a, b);
    }

    #[test]
    fn empty_text_decodes_to_nothing_rather_than_to_an_empty_key() {
        // Zero bytes is a legal base64 encoding of nothing, and a legal key it
        // is not. The decoder refuses it so `client_key_is_well_formed` cannot be
        // talked into agreeing with an absent header.
        assert!(decode_standard("").is_none());
        assert!(!client_key_is_well_formed(""));
    }

    #[test]
    fn base64_round_trips_over_every_short_length() {
        for length in 1..64usize {
            let data: Vec<u8> = (0..length).map(|index| (index * 7 + 3) as u8).collect();
            let encoded = encode_standard(&data);
            assert_eq!(encoded.len() % 4, 0, "padded output is a multiple of four");
            assert_eq!(decode_standard(&encoded).as_deref(), Some(data.as_slice()), "length {length}");
        }
    }

    #[test]
    fn the_high_alphabet_characters_are_the_standard_ones() {
        assert_eq!(encode_standard(&[0xfb, 0xff]), "+/8=");
    }

    #[test]
    fn a_well_formed_key_is_accepted() {
        assert!(client_key_is_well_formed("dGhlIHNhbXBsZSBub25jZQ=="));
        assert!(client_key_is_well_formed(&encode_standard(&[0u8; 16])));
    }

    #[test]
    fn keys_of_the_wrong_shape_are_refused() {
        assert!(!client_key_is_well_formed(""), "empty");
        assert!(!client_key_is_well_formed("dGhlIHNhbXBsZSBub25jZQ"), "unpadded");
        assert!(!client_key_is_well_formed(&"dGhlIHNhbXBsZSBub25jZQ=="[..23]), "truncated");
        assert!(!client_key_is_well_formed("AAAAAAAAAAAAAAAAAAAAAAAA=="), "too many bytes");
        assert!(!client_key_is_well_formed("dGhlIHNhbXBsZSBub25j!!=="), "outside the alphabet");
        assert!(!client_key_is_well_formed("-GhlIHNhbXBsZSBub25jZQ=="), "url alphabet");
        assert!(!client_key_is_well_formed(&encode_standard(&[0u8; 15])), "fifteen bytes");
    }

    #[test]
    fn the_decoder_refuses_misplaced_padding() {
        assert!(decode_standard("AA=A").is_none());
        assert!(decode_standard("A===").is_none());
        assert!(decode_standard("AAA").is_none(), "not a multiple of four");
    }

    #[test]
    fn neither_encoder_nor_decoder_panics_on_arbitrary_text() {
        // Totality matters more here than correctness of the result: this runs
        // on a header value a stranger chose.
        for length in 0..40usize {
            for seed in 0..64u8 {
                let text: String = (0..length)
                    .map(|index| char::from(seed.wrapping_add((index as u8).wrapping_mul(13))))
                    .collect();
                let _ = client_key_is_well_formed(&text);
                let _ = accept_key(&text);
            }
        }
    }
}
