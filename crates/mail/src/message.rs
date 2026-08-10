//! One parsed RFC 5322 message — the unit every mail server moves.
//!
//! The store writes it, IMAP `FETCH` reads it, and DKIM signs over it, so it is
//! parsed exactly once, here, into a header block plus a raw body. Nothing in
//! this type rewrites the bytes it was given: `raw` is preserved verbatim so a
//! signature computed over the received message still verifies after storage.

use std::fmt;

/// A parsed message: the full received bytes plus where the body begins.
///
/// `raw` is the message exactly as received or stored, CRLF line endings and
/// all. `header_end` is the byte offset of the body — the index just past the
/// blank line that separates headers from body (RFC 5322 §2.1). Keeping the
/// original bytes untouched is what lets a DKIM signature survive a round trip
/// through the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    raw: Vec<u8>,
    header_end: usize,
}

/// Why a byte sequence could not be accepted as a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageError {
    /// The input was empty; a message must carry at least one header.
    Empty,
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "message is empty"),
        }
    }
}

impl std::error::Error for MessageError {}

impl Message {
    /// Parses received bytes into headers and body.
    ///
    /// The split is the first blank line (`\r\n\r\n`). A message with no blank
    /// line is treated as all headers and an empty body rather than rejected —
    /// some minimal messages arrive that way, and refusing them would drop mail
    /// a stricter parser would have delivered.
    pub fn parse(raw: Vec<u8>) -> Result<Self, MessageError> {
        if raw.is_empty() {
            return Err(MessageError::Empty);
        }
        let header_end = find_body_start(&raw).unwrap_or(raw.len());
        Ok(Self { raw, header_end })
    }

    /// The first value of a header, case-insensitively, with continuation lines
    /// unfolded and surrounding whitespace trimmed. `None` if absent.
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers(name).into_iter().next()
    }

    /// Every value of a repeated header (e.g. `Received`), first to last.
    pub fn headers(&self, name: &str) -> Vec<String> {
        let block = &self.raw[..self.header_end];
        let mut values = Vec::new();
        let mut current: Option<String> = None;

        for line in split_crlf(block) {
            let is_continuation = line.first().is_some_and(|b| *b == b' ' || *b == b'\t');
            if is_continuation {
                if let Some(value) = current.as_mut() {
                    value.push(' ');
                    value.push_str(String::from_utf8_lossy(line).trim());
                }
                continue;
            }
            // A fresh header line closes the previous field.
            if let Some((field, rest)) = split_field(line) {
                if let Some(done) = current.take() {
                    values.push(done);
                }
                if field.eq_ignore_ascii_case(name) {
                    current = Some(String::from_utf8_lossy(rest).trim().to_owned());
                }
            }
        }
        if let Some(done) = current.take() {
            values.push(done);
        }
        values
    }

    /// The body bytes, after the header/body separator.
    pub fn body(&self) -> &[u8] {
        &self.raw[self.header_end..]
    }

    /// The full message bytes as received or stored.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// A copy with one header inserted at the top.
    ///
    /// Used for the `Received:` trace the receiver stamps and, later, the
    /// `DKIM-Signature` the sender adds. Prepending keeps the newest trace
    /// header first, the order every mail tool expects to read them in.
    pub fn with_prepended_header(&self, name: &str, value: &str) -> Message {
        let mut raw = Vec::with_capacity(self.raw.len() + name.len() + value.len() + 4);
        raw.extend_from_slice(name.as_bytes());
        raw.extend_from_slice(b": ");
        raw.extend_from_slice(value.as_bytes());
        raw.extend_from_slice(b"\r\n");
        raw.extend_from_slice(&self.raw);
        let header_end = self.header_end + (raw.len() - self.raw.len());
        Message { raw, header_end }
    }

    /// The size of the message in bytes, as declared in `SIZE` and Maildir names.
    pub fn size(&self) -> u64 {
        self.raw.len() as u64
    }
}

/// Finds the offset of the body: just past the first `\r\n\r\n`.
fn find_body_start(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// Splits a header line into `(field-name, value-bytes)` at the first colon.
fn split_field(line: &[u8]) -> Option<(&str, &[u8])> {
    let colon = line.iter().position(|b| *b == b':')?;
    let name = std::str::from_utf8(&line[..colon]).ok()?.trim();
    Some((name, &line[colon + 1..]))
}

/// Iterates the CRLF-separated lines of a byte block, without the terminators.
fn split_crlf(block: &[u8]) -> impl Iterator<Item = &[u8]> {
    block.split(|b| *b == b'\n').map(|line| {
        match line.split_last() {
            Some((b'\r', rest)) => rest,
            _ => line,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(raw: &str) -> Message {
        Message::parse(raw.as_bytes().to_vec()).unwrap()
    }

    #[test]
    fn separates_headers_from_body() {
        let m = message("Subject: hi\r\nFrom: a@b.com\r\n\r\nbody text");
        assert_eq!(m.header("subject").as_deref(), Some("hi"));
        assert_eq!(m.header("FROM").as_deref(), Some("a@b.com"));
        assert_eq!(m.body(), b"body text");
    }

    #[test]
    fn header_lookup_is_case_insensitive_and_trims() {
        let m = message("Subject:   spaced   \r\n\r\n");
        assert_eq!(m.header("subject").as_deref(), Some("spaced"));
    }

    #[test]
    fn folded_headers_are_unfolded() {
        // A value continued on an indented line is one logical value.
        let m = message("Subject: first\r\n  second\r\n\r\nbody");
        assert_eq!(m.header("subject").as_deref(), Some("first second"));
    }

    #[test]
    fn repeated_headers_are_all_returned_in_order() {
        let m = message("Received: from a\r\nReceived: from b\r\n\r\n");
        assert_eq!(m.headers("received"), vec!["from a", "from b"]);
    }

    #[test]
    fn prepending_a_header_keeps_the_original_bytes_below_it() {
        let original = message("Subject: hi\r\n\r\nbody");
        let stamped = original.with_prepended_header("Received", "from mx");
        assert_eq!(stamped.header("received").as_deref(), Some("from mx"));
        assert_eq!(stamped.header("subject").as_deref(), Some("hi"));
        assert_eq!(stamped.body(), b"body");
        // The exact original bytes are still present, unrewritten.
        assert!(stamped.as_bytes().ends_with(original.as_bytes()));
    }

    #[test]
    fn size_is_the_byte_length() {
        let m = message("A: b\r\n\r\nxyz");
        assert_eq!(m.size(), m.as_bytes().len() as u64);
    }

    #[test]
    fn an_empty_input_is_rejected() {
        assert_eq!(Message::parse(Vec::new()).unwrap_err(), MessageError::Empty);
    }

    #[test]
    fn a_message_with_no_blank_line_is_all_headers() {
        let m = message("Subject: hi\r\n");
        assert_eq!(m.header("subject").as_deref(), Some("hi"));
        assert_eq!(m.body(), b"");
    }
}
