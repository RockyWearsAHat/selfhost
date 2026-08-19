//! Just enough XML to read what a UPnP device says, and nothing more.
//!
//! Every protocol this crate speaks that carries structure carries it as XML:
//! the SOAP envelopes Sonos answers with, the DIDL-Lite describing what is
//! playing, and the `ZoneGroupState` document naming every speaker in the
//! house. None of it is XML in the general sense — it is machine-generated,
//! namespaced flatly, and shaped the same way every time — so a general parser
//! would be a dependency bought to solve a problem this crate does not have.
//!
//! What it *is* asked to survive is escaping, twice. A Sonos GENA event is a
//! `<LastChange>` element whose text is an escaped `<Event>` document, inside
//! which a `val` attribute holds a **second** escaped document. Reading that
//! means unescaping, parsing, unescaping again, and parsing again — so the
//! extraction functions here all take a `&str` and never a stream, because the
//! input to the second pass is a `String` the first pass produced.
//!
//! The parser is deliberately naive in one way that matters and is safe here:
//! it finds elements by scanning for `<name` and does not track nesting, so
//! [`element`] returns the *first* match at any depth. Every document this
//! crate reads names each field once, and the alternative — a real tree — buys
//! nothing a UPnP payload will ever exercise. Where nesting does matter, as in
//! `ZoneGroupState`, the caller slices the outer element with [`elements`]
//! first and reads within one member's bounds.

/// The five XML entities, expanded.
///
/// Written as a scan rather than five `replace` passes because chained
/// replacement is wrong on this input: expanding `&amp;` first turns
/// `&amp;lt;` into `&lt;`, and the next pass would expand that into `<` — one
/// unescape doing the work of two, which is exactly the bug that makes a
/// doubly-escaped Sonos event decode into nonsense. One left-to-right pass
/// consumes each entity once and cannot cascade.
#[must_use]
pub fn unescape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&' {
            // The longest entity here is "&quot;" at six bytes; look no further.
            let rest = &input[i..];
            if let Some((entity, expanded)) = ENTITIES.iter().find(|(e, _)| rest.starts_with(e)) {
                out.push(*expanded);
                i += entity.len();
                continue;
            }
            // A numeric reference, &#60; or &#x3c;. Sonos does not emit these,
            // but a track title carrying one would otherwise reach the page as
            // literal text, so they are expanded rather than passed through.
            if let Some(end) = rest.find(';').filter(|end| *end <= 10) {
                if let Some(ch) = numeric_reference(&rest[..end]) {
                    out.push(ch);
                    i += end + 1;
                    continue;
                }
            }
        }
        // Not an entity: copy the whole UTF-8 character, not the byte, or a
        // multi-byte title would be cut in half.
        let ch = input[i..].chars().next().unwrap_or('\u{fffd}');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

const ENTITIES: [(&str, char); 5] = [
    ("&lt;", '<'),
    ("&gt;", '>'),
    ("&quot;", '"'),
    ("&apos;", '\''),
    ("&amp;", '&'),
];

/// `&#60;` or `&#x3c;` (without the trailing semicolon) as a character.
fn numeric_reference(reference: &str) -> Option<char> {
    let digits = reference.strip_prefix("&#")?;
    let value = match digits.strip_prefix('x').or_else(|| digits.strip_prefix('X')) {
        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
        None => digits.parse::<u32>().ok()?,
    };
    char::from_u32(value)
}

/// The five XML entities, escaped, for a value being sent to a device.
///
/// `&` is handled by the same single pass for the same reason [`unescape`] is:
/// replacing it afterwards would re-escape the ampersands the other four just
/// introduced.
#[must_use]
pub fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '&' => out.push_str("&amp;"),
            other => out.push(other),
        }
    }
    out
}

/// One element's attribute text and inner content, borrowed from the document.
///
/// Borrowed rather than owned because the caller is usually slicing a large
/// document into many members and reading two fields from each; copying every
/// member's full text to read its `UUID` would be the bulk of the work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Element<'a> {
    /// The raw text between the element name and the closing `>` of its open
    /// tag — read it with [`attr`].
    pub attrs: &'a str,
    /// The raw text between the open and close tags, still escaped. Empty for
    /// a self-closing element.
    pub inner: &'a str,
}

/// The text of the first `<name>` element at any depth, unescaped.
///
/// Returns `None` when the element is absent, and `Some("")` when it is
/// present and empty — a distinction that matters, because Sonos answers an
/// idle player with `<TrackURI></TrackURI>` and an unsupported field by
/// omitting it, and those are different facts.
#[must_use]
pub fn element(document: &str, name: &str) -> Option<String> {
    first(document, name).map(|found| unescape(found.inner))
}

/// Every `<name>` element in the document, in order.
///
/// The scan does not recurse, so a `<ZoneGroup>` containing `<ZoneGroup>`
/// would be reported flat. No document this crate reads nests a repeated
/// element inside itself.
#[must_use]
pub fn elements<'a>(document: &'a str, name: &str) -> Vec<Element<'a>> {
    let mut found = Vec::new();
    let mut rest = document;
    while let Some((element, tail)) = next(rest, name) {
        found.push(element);
        rest = tail;
    }
    found
}

/// The value of `name=` in an open tag's attribute text, unescaped.
///
/// Matches the attribute name only when it stands alone, so asking for `UUID`
/// never matches `GroupUUID` and asking for `val` never matches `oldval`.
#[must_use]
pub fn attr(attrs: &str, name: &str) -> Option<String> {
    let mut rest = attrs;
    while let Some(at) = rest.find(name) {
        let before_is_boundary = at == 0
            || rest[..at].ends_with(|c: char| c.is_whitespace());
        let after = &rest[at + name.len()..];
        let after = after.trim_start();
        if before_is_boundary && after.starts_with('=') {
            let after = after[1..].trim_start();
            let quote = after.chars().next()?;
            if quote == '"' || quote == '\'' {
                let value = &after[1..];
                let end = value.find(quote)?;
                return Some(unescape(&value[..end]));
            }
        }
        // Not this occurrence — step past it and keep looking, so a document
        // mentioning the name inside another attribute's value cannot hide a
        // real one that follows.
        rest = &rest[at + name.len()..];
    }
    None
}

/// The first `<name …>` element, if any.
fn first<'a>(document: &'a str, name: &str) -> Option<Element<'a>> {
    next(document, name).map(|(element, _)| element)
}

/// The first `<name …>` element and the document text following it.
fn next<'a>(document: &'a str, name: &str) -> Option<(Element<'a>, &'a str)> {
    let mut search = document;
    let mut consumed = 0;
    loop {
        let at = search.find('<')?;
        let after_bracket = &search[at + 1..];
        // A namespace prefix is part of the tag as written on the wire
        // (`<r:streamContent>`), and callers ask by the local name, so a tag
        // matches when it ends with the name at a prefix boundary.
        let tag_end = after_bracket
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .unwrap_or(after_bracket.len());
        let tag = &after_bracket[..tag_end];
        let matches = tag == name || tag.rsplit(':').next() == Some(name);
        if !matches {
            let step = at + 1;
            consumed += step;
            search = &search[step..];
            continue;
        }

        let open_start = consumed + at;
        let rest = &after_bracket[tag_end..];
        let close = rest.find('>')?;
        let attrs = &rest[..close];
        let self_closing = attrs.trim_end().ends_with('/');
        let attrs = attrs.trim_end().trim_end_matches('/');
        let body_start = open_start + 1 + tag_end + close + 1;

        if self_closing {
            return Some((Element { attrs, inner: "" }, &document[body_start..]));
        }

        // Find the matching close tag, counting nested opens of the same name
        // so an outer element is not closed by an inner one's tag.
        let mut depth = 1usize;
        let mut cursor = body_start;
        while depth > 0 {
            let tail = document.get(cursor..)?;
            let at = tail.find('<')?;
            let after = &tail[at + 1..];
            if let Some(after_close) = after.strip_prefix('/') {
                let end = after_close.find('>')?;
                let closing = after_close[..end].trim();
                if closing == name || closing.rsplit(':').next() == Some(name) {
                    depth -= 1;
                    if depth == 0 {
                        let inner = &document[body_start..cursor + at];
                        let tail_start = cursor + at + 1 + end + 1;
                        return Some((
                            Element { attrs, inner },
                            document.get(tail_start..).unwrap_or(""),
                        ));
                    }
                }
                cursor += at + 1 + end + 1;
                continue;
            }
            let tag_end = after
                .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
                .unwrap_or(after.len());
            let tag = &after[..tag_end];
            if tag == name || tag.rsplit(':').next() == Some(name) {
                let close = after[tag_end..].find('>')?;
                let attrs = &after[tag_end..tag_end + close];
                if !attrs.trim_end().ends_with('/') {
                    depth += 1;
                }
                cursor += at + 1 + tag_end + close + 1;
                continue;
            }
            cursor += at + 1;
        }
        return None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_five_entities_expand() {
        assert_eq!(unescape("&lt;a&gt; &amp; &quot;b&quot; &apos;c&apos;"), "<a> & \"b\" 'c'");
    }

    /// The whole reason this is a scan and not five `replace` calls: one pass
    /// over a doubly-escaped document must leave the inner escaping intact.
    #[test]
    fn one_unescape_does_not_do_the_work_of_two() {
        let doubly = "&amp;lt;DIDL-Lite&amp;gt;";
        let once = unescape(doubly);
        assert_eq!(once, "&lt;DIDL-Lite&gt;");
        assert_eq!(unescape(&once), "<DIDL-Lite>");
    }

    #[test]
    fn a_numeric_reference_expands_in_either_base() {
        assert_eq!(unescape("&#60;&#x3e;"), "<>");
    }

    #[test]
    fn a_lone_ampersand_survives_unescaping() {
        assert_eq!(unescape("Simon & Garfunkel"), "Simon & Garfunkel");
    }

    #[test]
    fn a_multibyte_title_is_not_cut_in_half() {
        assert_eq!(unescape("Sigur Rós — Hoppípolla"), "Sigur Rós — Hoppípolla");
    }

    #[test]
    fn escaping_then_unescaping_is_the_identity() {
        let original = "a<b>c&d\"e'f — ø";
        assert_eq!(unescape(&escape(original)), original);
    }

    #[test]
    fn an_element_yields_its_unescaped_text() {
        let document = "<a><CurrentVolume>9</CurrentVolume></a>";
        assert_eq!(element(document, "CurrentVolume").as_deref(), Some("9"));
    }

    /// An absent field and an empty one are different facts, and Sonos emits
    /// both — an idle player has an empty `TrackURI`, not a missing one.
    #[test]
    fn an_empty_element_is_not_a_missing_one() {
        assert_eq!(element("<TrackURI></TrackURI>", "TrackURI").as_deref(), Some(""));
        assert_eq!(element("<Other/>", "TrackURI"), None);
    }

    #[test]
    fn a_self_closing_element_has_empty_inner_text() {
        assert_eq!(element("<TransportState val=\"PLAYING\"/>", "TransportState").as_deref(), Some(""));
    }

    #[test]
    fn a_namespaced_tag_is_found_by_its_local_name() {
        let document = "<r:streamContent>Nacho Sotomayor - Reject</r:streamContent>";
        assert_eq!(
            element(document, "streamContent").as_deref(),
            Some("Nacho Sotomayor - Reject")
        );
    }

    #[test]
    fn an_attribute_is_read_by_name() {
        let found = elements("<TransportState val=\"PLAYING\"/>", "TransportState");
        assert_eq!(attr(found[0].attrs, "val").as_deref(), Some("PLAYING"));
    }

    /// `UUID` must not be answered by `GroupUUID`, or a topology parse would
    /// attribute a member to the wrong speaker.
    #[test]
    fn an_attribute_name_must_stand_alone() {
        let attrs = r#"GroupUUID="wrong" UUID="right""#;
        assert_eq!(attr(attrs, "UUID").as_deref(), Some("right"));
    }

    #[test]
    fn an_absent_attribute_is_none() {
        assert_eq!(attr(r#"val="1""#, "channel"), None);
    }

    #[test]
    fn an_attribute_value_is_unescaped() {
        let attrs = r#"val="&amp;lt;DIDL-Lite&amp;gt;""#;
        assert_eq!(attr(attrs, "val").as_deref(), Some("&lt;DIDL-Lite&gt;"));
    }

    #[test]
    fn every_repeated_element_is_returned_in_order() {
        let document = "<z><M UUID=\"a\"/><M UUID=\"b\"/><M UUID=\"c\"/></z>";
        let members = elements(document, "M");
        let uuids: Vec<_> = members.iter().filter_map(|m| attr(m.attrs, "UUID")).collect();
        assert_eq!(uuids, ["a", "b", "c"]);
    }

    /// The outer element must not be closed by an inner one of the same name,
    /// or a group's membership would be truncated at its first nested tag.
    #[test]
    fn a_nested_element_of_the_same_name_does_not_close_the_outer_one() {
        let document = "<g><g>inner</g>tail</g>";
        let found = elements(document, "g");
        assert_eq!(found[0].inner, "<g>inner</g>tail");
    }

    #[test]
    fn a_missing_element_is_none_rather_than_a_panic() {
        assert_eq!(element("<a>text", "b"), None);
        assert_eq!(element("", "b"), None);
        assert_eq!(element("<<<>>", "b"), None);
    }

    /// The real shape: a SOAP response, read the way the driver reads it.
    #[test]
    fn a_soap_response_yields_its_out_arguments() {
        let body = concat!(
            r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>"#,
            r#"<u:GetTransportInfoResponse xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">"#,
            r#"<CurrentTransportState>PLAYING</CurrentTransportState>"#,
            r#"<CurrentTransportStatus>OK</CurrentTransportStatus>"#,
            r#"<CurrentSpeed>1</CurrentSpeed>"#,
            r#"</u:GetTransportInfoResponse></s:Body></s:Envelope>"#,
        );
        assert_eq!(element(body, "CurrentTransportState").as_deref(), Some("PLAYING"));
        assert_eq!(element(body, "CurrentSpeed").as_deref(), Some("1"));
    }

    /// The real shape of a fault, which the driver must tell apart from a
    /// success by reading `errorCode` rather than by the HTTP status alone.
    #[test]
    fn a_soap_fault_yields_its_error_code() {
        let body = concat!(
            r#"<s:Envelope><s:Body><s:Fault><faultcode>s:Client</faultcode>"#,
            r#"<faultstring>UPnPError</faultstring><detail>"#,
            r#"<UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>701</errorCode></UPnPError>"#,
            r#"</detail></s:Fault></s:Body></s:Envelope>"#,
        );
        assert_eq!(element(body, "errorCode").as_deref(), Some("701"));
    }
}
