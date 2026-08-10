//! MIME structure parsing — the part tree behind `BODYSTRUCTURE` and numeric
//! `BODY[n.m]` sections.
//!
//! A stored message is a tree: multiparts hold children, `message/rfc822`
//! wraps a nested message, everything else is a leaf. IMAP needs two things
//! from that tree: a description of it (`BODYSTRUCTURE`) and the bytes of one
//! node (`BODY[1.2]`). This module builds the tree as byte ranges into the
//! original message, so extracting a part is a slice, never a copy.

use std::ops::Range;

/// One node of a message's MIME tree. Ranges index the raw message bytes the
/// tree was parsed from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// Media type, lower-cased (e.g. `text`).
    pub kind: String,
    /// Media subtype, lower-cased (e.g. `plain`).
    pub subtype: String,
    /// `Content-Type` parameters in header order, attribute lower-cased.
    pub params: Vec<(String, String)>,
    /// `Content-ID`, verbatim.
    pub content_id: Option<String>,
    /// `Content-Description`, verbatim.
    pub description: Option<String>,
    /// `Content-Transfer-Encoding`, lower-cased; `7bit` when absent.
    pub encoding: String,
    /// This part's header block, including the blank separator line.
    pub header: Range<usize>,
    /// This part's body octets (content after the header block).
    pub body: Range<usize>,
    /// Child parts: the pieces of a multipart, or the single embedded message
    /// of a `message/rfc822`. Empty for other leaves.
    pub children: Vec<Part>,
}

impl Part {
    /// True for `multipart/*`.
    pub fn is_multipart(&self) -> bool {
        self.kind == "multipart"
    }

    /// True for `message/rfc822`.
    pub fn is_message(&self) -> bool {
        self.kind == "message" && self.subtype == "rfc822"
    }

    /// Line count of the body, as `BODYSTRUCTURE` reports for text parts: the
    /// number of newline-terminated lines, counting a ragged final line.
    pub fn line_count(&self, raw: &[u8]) -> usize {
        let body = &raw[self.body.clone()];
        let newlines = body.iter().filter(|b| **b == b'\n').count();
        if body.last().is_some_and(|b| *b != b'\n') { newlines + 1 } else { newlines }
    }
}

/// What a numeric section path asks for once the part is found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// `[1.2]` — the part's body octets.
    Content,
    /// `[1.2.MIME]` — the part's own MIME header block.
    Mime,
    /// `[1.HEADER]` — header of the message embedded in a `message/rfc822`.
    Header,
    /// `[1.TEXT]` — body of the message embedded in a `message/rfc822`.
    Text,
}

/// Parses `raw` (a full RFC822 message) into its MIME tree.
pub fn parse(raw: &[u8]) -> Part {
    parse_range(raw, 0..raw.len())
}

/// Resolves a numeric section path (`[1.2]`, 1-based per level) against the
/// tree, returning the requested byte range of `raw`. `None` when the path
/// names no existing part or the target does not apply to it.
pub fn section(root: &Part, path: &[u32], target: Target) -> Option<Range<usize>> {
    let mut part = root;
    for (i, index) in path.iter().enumerate() {
        let index = *index as usize;
        if part.is_multipart() {
            part = part.children.get(index.checked_sub(1)?)?;
        } else if part.is_message() && !part.children.is_empty() {
            // Descend through the embedded message: its parts are addressed as
            // if the wrapper were the message itself.
            let inner = &part.children[0];
            if inner.is_multipart() {
                part = inner.children.get(index.checked_sub(1)?)?;
            } else if index == 1 {
                part = inner;
            } else {
                return None;
            }
        } else if index == 1 && i == 0 {
            // Part 1 of a non-multipart message is the message body itself.
        } else {
            return None;
        }
    }
    match target {
        Target::Content => Some(part.body.clone()),
        Target::Mime => Some(part.header.clone()),
        Target::Header if part.is_message() && !part.children.is_empty() => {
            Some(part.children[0].header.clone())
        }
        Target::Text if part.is_message() && !part.children.is_empty() => {
            Some(part.children[0].body.clone())
        }
        Target::Header | Target::Text => None,
    }
}

/// Parses the message-or-part occupying `range` of `raw` into a tree node.
fn parse_range(raw: &[u8], range: Range<usize>) -> Part {
    let slice = &raw[range.clone()];
    let header_len = header_length(slice);
    let header = range.start..range.start + header_len;
    let body = range.start + header_len..range.end;

    let content_type = header_value(&raw[header.clone()], "Content-Type");
    let (kind, subtype, params) = split_content_type(content_type.as_deref());
    let encoding = header_value(&raw[header.clone()], "Content-Transfer-Encoding")
        .map(|e| e.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "7bit".into());
    let content_id = header_value(&raw[header.clone()], "Content-ID");
    let description = header_value(&raw[header.clone()], "Content-Description");

    let children = if kind == "multipart" {
        boundary_param(&params)
            .map(|b| child_ranges(raw, body.clone(), &b))
            .unwrap_or_default()
            .into_iter()
            .map(|r| parse_range(raw, r))
            .collect()
    } else if kind == "message" && subtype == "rfc822" && body.start < body.end {
        vec![parse_range(raw, body.clone())]
    } else {
        Vec::new()
    };

    Part { kind, subtype, params, content_id, description, encoding, header, body, children }
}

/// Byte length of the header block including the blank separator line, or the
/// whole slice when no separator exists.
fn header_length(slice: &[u8]) -> usize {
    if let Some(pos) = find(slice, b"\r\n\r\n") {
        return pos + 4;
    }
    if let Some(pos) = find(slice, b"\n\n") {
        return pos + 2;
    }
    slice.len()
}

/// Splits a `Content-Type` value into lower-cased type, subtype, and its
/// parameter list. Absent or malformed values default to `text/plain` with
/// `us-ascii`, as MIME directs.
fn split_content_type(value: Option<&str>) -> (String, String, Vec<(String, String)>) {
    let Some(value) = value else {
        return ("text".into(), "plain".into(), vec![("charset".into(), "us-ascii".into())]);
    };
    let mut segments = split_unquoted(value, ';');
    let media = segments.next().unwrap_or_default();
    let (kind, subtype) = match media.trim().split_once('/') {
        Some((k, s)) => (k.trim().to_ascii_lowercase(), s.trim().to_ascii_lowercase()),
        None => ("text".into(), "plain".into()),
    };
    let mut params = Vec::new();
    for segment in segments {
        if let Some((attr, val)) = segment.split_once('=') {
            params.push((
                attr.trim().to_ascii_lowercase(),
                val.trim().trim_matches('"').to_string(),
            ));
        }
    }
    (kind, subtype, params)
}

/// Splits on `separator` outside double quotes.
fn split_unquoted(value: &str, separator: char) -> impl Iterator<Item = String> + '_ {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for ch in value.chars() {
        match ch {
            '"' => {
                quoted = !quoted;
                current.push(ch);
            }
            c if c == separator && !quoted => out.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    out.push(current);
    out.into_iter()
}

/// The `boundary` parameter of a multipart, if declared.
fn boundary_param(params: &[(String, String)]) -> Option<String> {
    params.iter().find(|(attr, _)| attr == "boundary").map(|(_, val)| val.clone())
}

/// Locates each child part of a multipart body: the ranges between boundary
/// delimiter lines, per RFC 2046 (delimiters start a line with `--boundary`;
/// `--boundary--` closes the multipart).
fn child_ranges(raw: &[u8], body: Range<usize>, boundary: &str) -> Vec<Range<usize>> {
    let delimiter = format!("--{boundary}");
    let mut children = Vec::new();
    let mut current_start: Option<usize> = None;
    let mut pos = body.start;
    while pos < body.end {
        let line_end = find(&raw[pos..body.end], b"\n").map(|i| pos + i + 1).unwrap_or(body.end);
        let line = &raw[pos..line_end];
        let text = trim_line(line);
        if text.starts_with(delimiter.as_bytes()) {
            if let Some(start) = current_start.take() {
                // The delimiter's leading CRLF belongs to it, not the part.
                children.push(start..line_start_before_crlf(raw, pos));
            }
            let rest = &text[delimiter.len()..];
            if rest.starts_with(b"--") {
                break;
            }
            current_start = Some(line_end);
        }
        pos = line_end;
    }
    if let Some(start) = current_start {
        children.push(start..body.end);
    }
    children
}

/// The end of the content preceding the delimiter line at `line_start`: backs
/// up over the CRLF (or LF) that terminates the previous line.
fn line_start_before_crlf(raw: &[u8], line_start: usize) -> usize {
    if line_start >= 2 && &raw[line_start - 2..line_start] == b"\r\n" {
        line_start - 2
    } else if line_start >= 1 && raw[line_start - 1] == b'\n' {
        line_start - 1
    } else {
        line_start
    }
}

/// A line with its trailing CR/LF and surrounding whitespace removed.
fn trim_line(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\n' || line[end - 1] == b'\r' || line[end - 1] == b' ') {
        end -= 1;
    }
    &line[..end]
}

/// Reads one header field's unfolded value by name, case-insensitively, from a
/// header block. First match wins.
fn header_value(header: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(header);
    let mut lines: Vec<String> = Vec::new();
    for raw_line in text.split("\r\n").flat_map(|l| l.split('\n')) {
        if raw_line.is_empty() {
            continue;
        }
        if raw_line.starts_with(' ') || raw_line.starts_with('\t') {
            if let Some(last) = lines.last_mut() {
                last.push(' ');
                last.push_str(raw_line.trim_start());
                continue;
            }
        }
        lines.push(raw_line.to_string());
    }
    for line in lines {
        if let Some((field, value)) = line.split_once(':') {
            if field.trim().eq_ignore_ascii_case(name) {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// Finds the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE: &[u8] = b"From: a@b.c\r\n\
        Content-Type: text/plain; charset=us-ascii\r\n\
        \r\n\
        Hello there!\r\n";

    fn multipart() -> Vec<u8> {
        b"From: a@b.c\r\n\
          Content-Type: multipart/alternative; boundary=\"XYZ\"\r\n\
          \r\n\
          preamble\r\n\
          --XYZ\r\n\
          Content-Type: text/plain\r\n\
          \r\n\
          plain body\r\n\
          --XYZ\r\n\
          Content-Type: text/html\r\n\
          \r\n\
          <b>html body</b>\r\n\
          --XYZ--\r\n"
            .to_vec()
    }

    #[test]
    fn simple_message_is_a_text_leaf() {
        let part = parse(SIMPLE);
        assert_eq!(part.kind, "text");
        assert_eq!(part.subtype, "plain");
        assert_eq!(&SIMPLE[part.body.clone()], b"Hello there!\r\n");
        assert_eq!(part.line_count(SIMPLE), 1);
        assert!(part.children.is_empty());
    }

    #[test]
    fn multipart_splits_on_the_boundary() {
        let raw = multipart();
        let part = parse(&raw);
        assert!(part.is_multipart());
        assert_eq!(part.subtype, "alternative");
        assert_eq!(part.children.len(), 2);
        assert_eq!(&raw[part.children[0].body.clone()], b"plain body");
        assert_eq!(part.children[1].subtype, "html");
        assert_eq!(&raw[part.children[1].body.clone()], b"<b>html body</b>");
    }

    #[test]
    fn section_part_one_of_a_simple_message_is_its_body() {
        let part = parse(SIMPLE);
        let range = section(&part, &[1], Target::Content).unwrap();
        assert_eq!(&SIMPLE[range], b"Hello there!\r\n");
    }

    #[test]
    fn section_resolves_multipart_children_and_mime_headers() {
        let raw = multipart();
        let part = parse(&raw);
        let two = section(&part, &[2], Target::Content).unwrap();
        assert_eq!(&raw[two], b"<b>html body</b>");
        let mime = section(&part, &[2], Target::Mime).unwrap();
        assert_eq!(&raw[mime], b"Content-Type: text/html\r\n\r\n");
        assert!(section(&part, &[3], Target::Content).is_none());
    }

    #[test]
    fn message_rfc822_wraps_the_embedded_message() {
        let raw: Vec<u8> = b"Content-Type: message/rfc822\r\n\
            \r\n\
            Subject: inner\r\n\
            \r\n\
            inner body\r\n"
            .to_vec();
        let part = parse(&raw);
        assert!(part.is_message());
        let header = section(&part, &[], Target::Header).unwrap();
        assert_eq!(&raw[header], b"Subject: inner\r\n\r\n");
        let text = section(&part, &[], Target::Text).unwrap();
        assert_eq!(&raw[text], b"inner body\r\n");
    }
}
