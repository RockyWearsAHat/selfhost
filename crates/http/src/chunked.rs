//! Decoding the chunked transfer-coding (RFC 9112 §7.1).
//!
//! Kept here, beside the response parser, because it belongs to the same pure
//! charter: it turns a framed byte sequence into the bytes it framed, with no
//! socket and no I/O, so the smuggling-relevant edge cases (a chunk
//! size that is not hexadecimal, data that is not CRLF-terminated, a size that
//! overflows) can be unit-tested exhaustively.
//!
//! The async read loop that feeds this lives in the caller (the ACME transport);
//! only the *decoding* lives here. That split is deliberate — [`ParseError::Incomplete`]
//! is how this module tells a streaming caller "read more and call me again".

use crate::request::ParseError;

/// The largest chunk-size line accepted, in hexadecimal digits.
///
/// Sixteen hex digits is a full 64-bit length; anything longer is a broken or
/// hostile peer, and rejecting it early keeps [`chunk_size`] from having to reason
/// about arbitrarily long inputs.
const MAX_SIZE_DIGITS: usize = 16;

/// Decodes a chunked message body into the bytes it carried.
///
/// `input` is the raw body that followed the response head: a run of size-prefixed
/// chunks terminated by a zero-size chunk and its (possibly empty) trailer section.
/// Returns the concatenated chunk data with all framing removed.
///
/// Returns [`ParseError::Incomplete`] when the terminating zero chunk has not yet
/// arrived — a streaming caller should read more bytes and retry. Every other error
/// means the body is malformed and must not be retried.
pub fn dechunk(input: &[u8]) -> Result<Vec<u8>, ParseError> {
    let mut decoded = Vec::new();
    let mut rest = input;

    loop {
        let (size_line, after_size) = split_line(rest).ok_or(ParseError::Incomplete)?;
        let size = chunk_size(size_line)?;

        if size == 0 {
            // The last chunk is followed by a trailer section: zero or more header
            // lines, then a blank line that ends the message.
            let mut trailer = after_size;
            loop {
                let (line, next) = split_line(trailer).ok_or(ParseError::Incomplete)?;
                if line.is_empty() {
                    return Ok(decoded);
                }
                trailer = next;
            }
        }

        // The chunk data is exactly `size` bytes, terminated by its own CRLF.
        let needed = size.checked_add(2).ok_or(ParseError::AmbiguousFraming("chunk size out of range"))?;
        if after_size.len() < needed {
            return Err(ParseError::Incomplete);
        }
        let (data, tail) = after_size.split_at(size);
        if &tail[..2] != b"\r\n" {
            return Err(ParseError::AmbiguousFraming("chunk data not terminated by CRLF"));
        }
        decoded.extend_from_slice(data);
        rest = &tail[2..];
    }
}

/// Splits off one CRLF-terminated line, returning it and the bytes after the CRLF.
///
/// `None` means the CRLF has not arrived yet, which a caller reads as "incomplete".
fn split_line(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let crlf = input.windows(2).position(|pair| pair == b"\r\n")?;
    Some((&input[..crlf], &input[crlf + 2..]))
}

/// Parses a chunk-size line: hexadecimal digits, then optional chunk extensions.
///
/// Extensions (everything from the first `;`) are ignored, as are surrounding
/// spaces and tabs some servers append. The size must be non-empty hexadecimal.
fn chunk_size(line: &[u8]) -> Result<usize, ParseError> {
    let hex = match line.iter().position(|&byte| byte == b';') {
        Some(semicolon) => &line[..semicolon],
        None => line,
    };
    let hex = trim_spaces(hex);

    if hex.is_empty() || hex.len() > MAX_SIZE_DIGITS {
        return Err(ParseError::AmbiguousFraming("chunk size is empty or too long"));
    }

    let mut size: usize = 0;
    for &byte in hex {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(ParseError::AmbiguousFraming("chunk size is not hexadecimal")),
        };
        size = size
            .checked_mul(16)
            .and_then(|shifted| shifted.checked_add(digit as usize))
            .ok_or(ParseError::AmbiguousFraming("chunk size out of range"))?;
    }
    Ok(size)
}

/// Trims leading and trailing spaces and tabs.
fn trim_spaces(mut bytes: &[u8]) -> &[u8] {
    while let [first, tail @ ..] = bytes {
        if *first == b' ' || *first == b'\t' {
            bytes = tail;
        } else {
            break;
        }
    }
    while let [head @ .., last] = bytes {
        if *last == b' ' || *last == b'\t' {
            bytes = head;
        } else {
            break;
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_a_single_chunk() {
        let decoded = dechunk(b"5\r\nhello\r\n0\r\n\r\n").expect("decode");
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn decodes_several_chunks_in_order() {
        let decoded = dechunk(b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n").expect("decode");
        assert_eq!(decoded, b"abcde");
    }

    #[test]
    fn an_empty_body_is_the_zero_chunk_only() {
        let decoded = dechunk(b"0\r\n\r\n").expect("decode");
        assert!(decoded.is_empty());
    }

    #[test]
    fn hexadecimal_sizes_are_read_as_hex() {
        // 0x1a == 26 bytes.
        let data = "x".repeat(26);
        let raw = format!("1a\r\n{data}\r\n0\r\n\r\n");
        assert_eq!(dechunk(raw.as_bytes()).expect("decode"), data.as_bytes());
    }

    #[test]
    fn chunk_extensions_are_ignored() {
        let decoded = dechunk(b"5;name=value\r\nhello\r\n0\r\n\r\n").expect("decode");
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn a_trailer_section_is_consumed() {
        let decoded = dechunk(b"5\r\nhello\r\n0\r\nX-Trailer: v\r\n\r\n").expect("decode");
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn a_body_missing_its_zero_chunk_is_incomplete() {
        assert!(matches!(dechunk(b"5\r\nhello\r\n"), Err(ParseError::Incomplete)));
    }

    #[test]
    fn a_chunk_whose_data_has_not_all_arrived_is_incomplete() {
        assert!(matches!(dechunk(b"5\r\nhel"), Err(ParseError::Incomplete)));
    }

    #[test]
    fn a_trailer_without_its_blank_line_is_incomplete() {
        assert!(matches!(dechunk(b"0\r\nX-Trailer: v\r\n"), Err(ParseError::Incomplete)));
    }

    #[test]
    fn a_non_hexadecimal_size_is_refused() {
        assert!(matches!(
            dechunk(b"zz\r\nhello\r\n0\r\n\r\n"),
            Err(ParseError::AmbiguousFraming(_))
        ));
    }

    #[test]
    fn data_not_terminated_by_crlf_is_refused() {
        // The declared size says 5, but the bytes after are not "hello\r\n".
        assert!(matches!(
            dechunk(b"5\r\nhelloXX0\r\n\r\n"),
            Err(ParseError::AmbiguousFraming(_))
        ));
    }

    #[test]
    fn an_oversized_size_field_is_refused_rather_than_overflowing() {
        assert!(matches!(
            dechunk(b"fffffffffffffffff\r\n"),
            Err(ParseError::AmbiguousFraming(_))
        ));
    }
}
