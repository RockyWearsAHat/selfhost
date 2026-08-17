//! HTTP header fields.
//!
//! Field names are compared case-insensitively (RFC 9110 §5.1) but stored with
//! the casing they arrived in, so a proxied response looks to the origin exactly
//! as it did on the wire.
//!
//! Values are stored as raw bytes rather than `String`. Header values are not
//! required to be UTF-8, and lossily converting them would corrupt filenames in
//! `Content-Disposition` and break signature headers that are compared verbatim.

use std::fmt;

/// The maximum number of header fields accepted in one message.
///
/// A message with thousands of small headers is a memory-amplification attack
/// rather than a legitimate request.
pub const MAX_HEADER_COUNT: usize = 128;

/// The maximum total size of a message head, in bytes.
pub const MAX_HEAD_BYTES: usize = 64 * 1024;

/// A single header field.
#[derive(Clone, PartialEq, Eq)]
pub struct Header {
    name: String,
    value: Vec<u8>,
}

impl Header {
    /// Creates a header, rejecting names and values that could inject a new line
    /// into the serialised message.
    ///
    /// This is the single choke point for response splitting: a value carrying a
    /// bare CR or LF would end the field early and let an attacker append
    /// arbitrary headers or a whole second response.
    pub fn new(name: impl Into<String>, value: impl Into<Vec<u8>>) -> Result<Self, HeaderError> {
        let name = name.into();
        let value = value.into();

        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(HeaderError::InvalidName);
        }
        if value.iter().any(|&b| b == b'\r' || b == b'\n' || b == 0) {
            return Err(HeaderError::InvalidValue);
        }
        Ok(Self { name, value })
    }

    /// The field name, in the casing it was created with.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The raw field value.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// The field value as UTF-8, or `None` when it is not valid UTF-8.
    pub fn value_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.value).ok()
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, String::from_utf8_lossy(&self.value))
    }
}

/// Why a header could not be constructed or parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderError {
    /// The field name was empty or contained a byte outside the token set.
    InvalidName,
    /// The field value contained CR, LF, or NUL.
    InvalidValue,
    /// The message carried more header fields than [`MAX_HEADER_COUNT`].
    TooMany,
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => write!(f, "invalid header name"),
            Self::InvalidValue => write!(f, "header value contains CR, LF, or NUL"),
            Self::TooMany => write!(f, "too many header fields"),
        }
    }
}

impl std::error::Error for HeaderError {}

/// Whether a byte is legal in a header field name (RFC 9110 token).
fn is_token_byte(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'^' | b'_' | b'`' | b'|' | b'~'
        | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

/// An ordered collection of header fields.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Headers {
    fields: Vec<Header>,
}

impl Headers {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of fields present, counting repeats separately.
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// Whether no fields are present.
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Appends a field, keeping any existing field of the same name.
    ///
    /// Repetition is meaningful for `Set-Cookie` and for list-valued fields, so
    /// this never silently replaces.
    pub fn append(&mut self, header: Header) -> Result<(), HeaderError> {
        if self.fields.len() >= MAX_HEADER_COUNT {
            return Err(HeaderError::TooMany);
        }
        self.fields.push(header);
        Ok(())
    }

    /// Appends a field built from a name and value.
    pub fn push(&mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Result<(), HeaderError> {
        self.append(Header::new(name, value)?)
    }

    /// Removes every field with this name, then appends the new value.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Result<(), HeaderError> {
        let name = name.into();
        self.remove(&name);
        self.append(Header::new(name, value)?)
    }

    /// Removes every field with this name, returning how many were removed.
    pub fn remove(&mut self, name: &str) -> usize {
        let before = self.fields.len();
        self.fields.retain(|f| !f.name.eq_ignore_ascii_case(name));
        before - self.fields.len()
    }

    /// The value of the first field with this name.
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
            .map(Header::value)
    }

    /// The value of the first field with this name, as UTF-8.
    pub fn get_str(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
            .and_then(Header::value_str)
    }

    /// How many fields carry this name.
    pub fn count(&self, name: &str) -> usize {
        self.fields
            .iter()
            .filter(|f| f.name.eq_ignore_ascii_case(name))
            .count()
    }

    /// Whether any field carries this name.
    pub fn contains(&self, name: &str) -> bool {
        self.count(name) > 0
    }

    /// Iterates the fields in order.
    pub fn iter(&self) -> impl Iterator<Item = &Header> {
        self.fields.iter()
    }

    /// Writes the fields in wire format, each terminated by CRLF.
    ///
    /// The terminating blank line is *not* written, so callers can append
    /// trailers or a body framing decision afterwards.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        for field in &self.fields {
            out.extend_from_slice(field.name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(&field.value);
            out.extend_from_slice(b"\r\n");
        }
    }
}

impl<'a> IntoIterator for &'a Headers {
    type Item = &'a Header;
    type IntoIter = std::slice::Iter<'a, Header>;

    fn into_iter(self) -> Self::IntoIter {
        self.fields.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_ignores_case() {
        let mut headers = Headers::new();
        headers.push("Content-Type", "text/html").unwrap();
        assert_eq!(headers.get_str("content-type"), Some("text/html"));
        assert_eq!(headers.get_str("CONTENT-TYPE"), Some("text/html"));
    }

    #[test]
    fn casing_is_preserved_on_the_wire() {
        let mut headers = Headers::new();
        headers.push("X-Custom-Header", "v").unwrap();
        let mut out = Vec::new();
        headers.write_to(&mut out);
        assert_eq!(out, b"X-Custom-Header: v\r\n");
    }

    #[test]
    fn crlf_in_a_value_is_rejected() {
        // Response splitting: without this, a value could terminate the field
        // and inject headers or an entire second response.
        assert_eq!(
            Header::new("X-Test", "a\r\nInjected: yes").unwrap_err(),
            HeaderError::InvalidValue
        );
        assert_eq!(Header::new("X-Test", "a\nb").unwrap_err(), HeaderError::InvalidValue);
        assert_eq!(Header::new("X-Test", "a\rb").unwrap_err(), HeaderError::InvalidValue);
    }

    #[test]
    fn nul_in_a_value_is_rejected() {
        assert_eq!(Header::new("X-Test", vec![b'a', 0, b'b']).unwrap_err(), HeaderError::InvalidValue);
    }

    #[test]
    fn invalid_names_are_rejected() {
        assert_eq!(Header::new("Bad Name", "v").unwrap_err(), HeaderError::InvalidName);
        assert_eq!(Header::new("", "v").unwrap_err(), HeaderError::InvalidName);
        assert_eq!(Header::new("Bad:Name", "v").unwrap_err(), HeaderError::InvalidName);
    }

    #[test]
    fn set_replaces_every_existing_field() {
        let mut headers = Headers::new();
        headers.push("Accept", "a").unwrap();
        headers.push("accept", "b").unwrap();
        headers.set("Accept", "c").unwrap();
        assert_eq!(headers.count("accept"), 1);
        assert_eq!(headers.get_str("accept"), Some("c"));
    }

    #[test]
    fn append_keeps_repeats() {
        let mut headers = Headers::new();
        headers.push("Set-Cookie", "a=1").unwrap();
        headers.push("Set-Cookie", "b=2").unwrap();
        assert_eq!(headers.count("set-cookie"), 2);
    }

    #[test]
    fn header_count_is_capped() {
        let mut headers = Headers::new();
        for i in 0..MAX_HEADER_COUNT {
            headers.push(format!("X-{i}"), "v").unwrap();
        }
        assert_eq!(headers.push("X-Overflow", "v").unwrap_err(), HeaderError::TooMany);
    }

    #[test]
    fn non_utf8_values_survive_as_bytes() {
        let header = Header::new("X-Raw", vec![0xff, 0xfe]).unwrap();
        assert_eq!(header.value(), &[0xff, 0xfe]);
        assert_eq!(header.value_str(), None);
    }
}
