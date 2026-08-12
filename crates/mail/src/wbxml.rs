//! WBXML — the binary XML encoding [MS-ASWBXML] wraps every ActiveSync
//! request and response in.
//!
//! This module is the wire format only: a generic token writer/reader with
//! no opinion about which tag numbers mean what — that mapping (each
//! protocol's "code page") lives in [`crate::eas`], which is the only
//! caller. The format itself is fully specified and small enough to
//! hand-roll exactly like this crate hand-rolls WebDAV's XML
//! (`crates/storage/src/dav`) and its own base64 (`crate::dkim`) — no crate
//! for it exists in this workspace, and WBXML's binary framing (unlike
//! ActiveSync's tag tables — see [`crate::eas`]'s own caveat) is unambiguous
//! from the spec alone, so this half needs no device to verify.
//!
//! # Framing
//!
//! A document is a header followed by a token stream:
//!
//! ```text
//! version(1) publicid(mb_uint32) charset(mb_uint32) string_table_len(mb_uint32) tokens...
//! ```
//!
//! This module always writes `string_table_len = 0` — every string ActiveSync
//! carries is written inline (`STR_I`), so there is never a string table to
//! reference, matching how real devices' own requests are shaped.
//!
//! A token is one of:
//! - `SWITCH_PAGE (0x00) page` — every following tag code is read against a
//!   different one of ActiveSync's ~25 code pages until the next switch.
//! - a **tag code** byte: bits 0–5 are the code page's tag number, bit 6
//!   (`0x80`) marks "has attributes" (unused by ActiveSync — never set),
//!   bit 7 (`0x40`) marks "has content" — children or text follow, terminated
//!   by `END`.
//! - `END (0x01)` — closes the innermost open tag that had content.
//! - `STR_I (0x03) bytes... NUL` — an inline, null-terminated UTF-8 string.
//! - `OPAQUE (0xC3) len(mb_uint32) bytes...` — raw binary content, used here
//!   for a message's MIME bytes (`AirSyncBase:Data`, `ComposeMail:Mime`).

/// WBXML version byte this module writes and expects — 1.3, per [MS-ASWBXML]
/// §2.1.1.
const VERSION: u8 = 0x03;
/// "Unknown or missing public identifier" — ActiveSync sets no real one.
const PUBLIC_ID: u8 = 0x01;
/// MIBenum 106 — UTF-8, the only charset this module ever writes or expects.
const CHARSET_UTF8: u8 = 0x6A;

const TOK_SWITCH_PAGE: u8 = 0x00;
const TOK_END: u8 = 0x01;
const TOK_STR_I: u8 = 0x03;
const TOK_OPAQUE: u8 = 0xC3;
/// Set on a tag byte when the element has content (children/text) that must
/// be closed with [`TOK_END`].
const FLAG_CONTENT: u8 = 0x40;

/// Builds one WBXML document token by token.
#[derive(Default)]
pub struct Writer {
    body: Vec<u8>,
    current_page: u8,
}

impl Writer {
    /// A writer starting on code page 0, the state every WBXML document
    /// begins in.
    pub fn new() -> Self {
        Self::default()
    }

    /// Switches the active code page for tags written after this call.
    pub fn switch_page(&mut self, page: u8) {
        if page != self.current_page {
            self.body.push(TOK_SWITCH_PAGE);
            self.body.push(page);
            self.current_page = page;
        }
    }

    /// Opens a tag with no content — self-closing, no matching `end_tag`.
    ///
    /// `code` must be `0x05..=0x3f`: codes `0x00..=0x04` collide with the
    /// reserved global tokens (`SWITCH_PAGE`, `END`, `ENTITY`, `STR_I`,
    /// `LITERAL`) at the byte level, which is why every real ActiveSync code
    /// page's own tag numbering starts at `0x05` — this is a wire-format
    /// constraint, not a convention [`crate::eas`] chose.
    pub fn empty_tag(&mut self, code: u8) {
        debug_assert!((0x05..=0x3f).contains(&code), "tag code {code:#x} collides with a reserved global token");
        self.body.push(code & 0x3f);
    }

    /// Opens a tag whose children/text follow; must be paired with
    /// [`Writer::end_tag`]. See [`Writer::empty_tag`] for `code`'s valid range.
    pub fn start_tag(&mut self, code: u8) {
        debug_assert!((0x05..=0x3f).contains(&code), "tag code {code:#x} collides with a reserved global token");
        self.body.push((code & 0x3f) | FLAG_CONTENT);
    }

    /// Closes the innermost tag opened by [`Writer::start_tag`].
    pub fn end_tag(&mut self) {
        self.body.push(TOK_END);
    }

    /// Writes an inline string, e.g. as a tag's entire content:
    /// `w.start_tag(CODE); w.text(value); w.end_tag();`.
    pub fn text(&mut self, value: &str) {
        self.body.push(TOK_STR_I);
        self.body.extend_from_slice(value.as_bytes());
        self.body.push(0);
    }

    /// A convenience for the extremely common `<Tag>text</Tag>` shape.
    pub fn text_tag(&mut self, code: u8, value: &str) {
        self.start_tag(code);
        self.text(value);
        self.end_tag();
    }

    /// Writes raw binary content (a message's MIME bytes).
    pub fn opaque(&mut self, bytes: &[u8]) {
        self.body.push(TOK_OPAQUE);
        write_mb_u32(&mut self.body, bytes.len() as u32);
        self.body.extend_from_slice(bytes);
    }

    /// Finishes the document: header, then the accumulated token stream.
    pub fn finish(self) -> Vec<u8> {
        let mut out = vec![VERSION, PUBLIC_ID, CHARSET_UTF8, 0];
        out.extend(self.body);
        out
    }
}

/// One token read back from a WBXML document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// The code page every following tag code is read against, until the
    /// next `SwitchPage`.
    SwitchPage(u8),
    /// A tag's code (the low 6 bits only — the "has attributes" bit is
    /// never set by ActiveSync and is asserted absent by [`Reader::next`])
    /// and whether it has content to read until a matching [`Token::End`].
    Tag {
        /// The tag's code within the currently active page.
        code: u8,
        /// Whether children/text follow, to be closed by [`Token::End`].
        has_content: bool,
    },
    /// Closes the innermost open [`Token::Tag`] that had content.
    End,
    /// Inline text content.
    Text(String),
    /// Raw binary content.
    Opaque(Vec<u8>),
}

/// Reads a WBXML document's token stream, after validating and skipping its
/// header.
pub struct Reader<'a> {
    body: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Opens `data` for reading, validating the header this module itself
    /// always writes. `None` for anything else — a version this module does
    /// not speak, a non-UTF-8 charset, or a truncated header — the same
    /// "cannot parse well enough to answer, so answer nothing" posture
    /// [`crate::xml`] documents for its own scanner.
    pub fn new(data: &'a [u8]) -> Option<Self> {
        let mut pos = 0;
        let version = *data.get(pos)?;
        pos += 1;
        if version != VERSION {
            return None;
        }
        let (_public_id, len) = read_mb_u32(data, pos)?;
        pos += len;
        let (charset, len) = read_mb_u32(data, pos)?;
        pos += len;
        if charset != CHARSET_UTF8 as u32 {
            return None;
        }
        let (string_table_len, len) = read_mb_u32(data, pos)?;
        pos += len;
        pos += string_table_len as usize; // skip a string table this reader never indexes into
        Some(Self { body: data, pos })
    }

    /// The next token, or `None` at end of document (or on a malformed
    /// tail, which this reader treats identically — a truncated ActiveSync
    /// request has nothing left worth extracting). Also reachable as
    /// [`Iterator::next`] — `Reader` implements `Iterator<Item = Token>`.
    fn read(&mut self) -> Option<Token> {
        let byte = *self.body.get(self.pos)?;
        self.pos += 1;
        match byte {
            TOK_SWITCH_PAGE => {
                let page = *self.body.get(self.pos)?;
                self.pos += 1;
                Some(Token::SwitchPage(page))
            }
            TOK_END => Some(Token::End),
            TOK_STR_I => {
                let start = self.pos;
                let end = self.body[start..].iter().position(|b| *b == 0)? + start;
                self.pos = end + 1;
                Some(Token::Text(String::from_utf8_lossy(&self.body[start..end]).into_owned()))
            }
            TOK_OPAQUE => {
                let (len, consumed) = read_mb_u32(self.body, self.pos)?;
                self.pos += consumed;
                let start = self.pos;
                let end = start.checked_add(len as usize)?;
                let bytes = self.body.get(start..end)?.to_vec();
                self.pos = end;
                Some(Token::Opaque(bytes))
            }
            // Every other single byte is a tag code — the low 6 bits are the
            // code, bit 6 says whether content follows. ActiveSync never
            // sets bit 7 (attributes), so a set bit 7 here is a document
            // this reader does not understand.
            other if other & 0x80 == 0 => {
                Some(Token::Tag { code: other & 0x3f, has_content: other & FLAG_CONTENT != 0 })
            }
            _ => None,
        }
    }
}

impl<'a> Iterator for Reader<'a> {
    type Item = Token;

    fn next(&mut self) -> Option<Token> {
        self.read()
    }
}

/// Writes `value` as WBXML's multi-byte unsigned integer: 7 bits per byte,
/// most-significant chunk first, every byte but the last carrying a
/// continuation bit (`0x80`).
fn write_mb_u32(out: &mut Vec<u8>, value: u32) {
    let mut chunks = [0u8; 5];
    let mut n = 0;
    let mut v = value;
    loop {
        chunks[n] = (v & 0x7f) as u8;
        v >>= 7;
        n += 1;
        if v == 0 {
            break;
        }
    }
    for (i, chunk) in chunks[..n].iter().enumerate().rev() {
        out.push(if i > 0 { chunk | 0x80 } else { *chunk });
    }
}

/// Reads a `write_mb_u32`-encoded integer starting at `pos`, returning the
/// value and how many bytes it occupied.
fn read_mb_u32(data: &[u8], pos: usize) -> Option<(u32, usize)> {
    let mut value: u32 = 0;
    let mut consumed = 0;
    loop {
        let byte = *data.get(pos + consumed)?;
        value = (value << 7) | (byte & 0x7f) as u32;
        consumed += 1;
        if byte & 0x80 == 0 {
            return Some((value, consumed));
        }
        if consumed > 5 {
            return None; // longer than any value this protocol ever sends
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mb_u32_round_trips_across_the_single_and_multi_byte_boundary() {
        for value in [0u32, 1, 127, 128, 300, 16384, 1_000_000] {
            let mut buf = Vec::new();
            write_mb_u32(&mut buf, value);
            let (decoded, consumed) = read_mb_u32(&buf, 0).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(consumed, buf.len());
        }
    }

    #[test]
    fn a_document_with_one_text_tag_round_trips() {
        let mut w = Writer::new();
        w.switch_page(7);
        w.text_tag(0x0F, "Inbox");
        let bytes = w.finish();

        let mut r = Reader::new(&bytes).unwrap();
        assert_eq!(r.next(), Some(Token::SwitchPage(7)));
        assert_eq!(r.next(), Some(Token::Tag { code: 0x0F, has_content: true }));
        assert_eq!(r.next(), Some(Token::Text("Inbox".to_owned())));
        assert_eq!(r.next(), Some(Token::End));
        assert_eq!(r.next(), None);
    }

    #[test]
    fn nested_tags_and_opaque_content_round_trip() {
        let mut w = Writer::new();
        w.start_tag(0x05);
        w.empty_tag(0x06);
        w.opaque(b"raw mime bytes");
        w.end_tag();
        let bytes = w.finish();

        let mut r = Reader::new(&bytes).unwrap();
        assert_eq!(r.next(), Some(Token::Tag { code: 0x05, has_content: true }));
        assert_eq!(r.next(), Some(Token::Tag { code: 0x06, has_content: false }));
        assert_eq!(r.next(), Some(Token::Opaque(b"raw mime bytes".to_vec())));
        assert_eq!(r.next(), Some(Token::End));
        assert_eq!(r.next(), None);
    }

    #[test]
    fn a_document_with_the_wrong_version_byte_is_rejected() {
        assert!(Reader::new(&[0x02, PUBLIC_ID, CHARSET_UTF8, 0]).is_none());
    }

    #[test]
    fn switch_page_is_a_no_op_when_already_on_that_page() {
        let mut w = Writer::new();
        w.switch_page(0);
        w.empty_tag(0x05);
        let bytes = w.finish();
        // No SWITCH_PAGE token should have been written for the default page.
        assert_eq!(bytes.len(), 4 + 1, "header plus the one tag byte only");
    }

    #[test]
    fn a_tag_code_that_would_collide_with_a_reserved_token_panics_in_debug() {
        let result = std::panic::catch_unwind(|| {
            let mut w = Writer::new();
            w.empty_tag(0x01); // collides with TOK_END
        });
        assert!(result.is_err());
    }
}
