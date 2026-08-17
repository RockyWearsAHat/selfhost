//! A narrow, hand-rolled XML scanner shared by [`crate::autodiscover`],
//! [`crate::ews`], and [`crate::eas`]'s WBXML-to-XML request path.
//!
//! No XML crate exists anywhere in this workspace (`crates/storage/src/dav`
//! hand-rolls WebDAV's XML the same way) and none is added here. What every
//! caller of this module needs is narrower still than DAV's property
//! matching: find the text of a named element wherever it appears, find an
//! attribute's value wherever it appears, or find every occurrence of one of
//! those. None of it resolves namespaces or validates well-formedness — a
//! request this server cannot parse well enough to find what it needs is
//! answered with an empty result, not a parse error, exactly as
//! [`crate::autodiscover::respond`] documents for its own use of this module.

/// The text content of the first `<name>...</name>` (or namespaced
/// `<prefix:name>...</prefix:name>`) element in `body`.
///
/// A prefix is matched by accepting either `<` or `:` immediately before the
/// name, so `<t:Foo>` and `<Foo>` both match a request for `"Foo"` — callers
/// never need to know or care which prefix a client chose. `None` for a
/// self-closing tag (`<Foo/>`, no content to bound) as well as an absent or
/// empty element.
pub fn element_text(body: &str, name: &str) -> Option<String> {
    let (_, gt, self_closing, tag_name) = find_tag(body, name)?;
    if self_closing {
        return None;
    }
    let open_end = gt + 1;
    // The closing tag must carry the same prefix (or lack of one) the
    // opening tag did — `<t:Foo>...</Foo>` is not well-formed XML, so a
    // client never sends it, but matching only the exact pair found avoids
    // ever pairing this open tag with an unrelated same-named element under
    // a different prefix later in the body.
    let close = format!("</{tag_name}>");
    let end = open_end + body[open_end..].find(&close)?;
    let value = body[open_end..end].trim();
    if value.is_empty() { None } else { Some(value.to_owned()) }
}

/// Every value of an attribute named `attr` anywhere in `body`, in the order
/// they appear — e.g. `attr_values(body, "Id")` over a `<m:FolderIds>` block
/// containing several `<t:FolderId Id="…"/>` entries returns every id.
///
/// Deliberately whole-document rather than scoped to one element: every
/// caller in this crate uses this only where the attribute name is unique
/// enough within the operation's request shape that scoping would not change
/// the result (`Id`, `MessageDisposition`) — see each call site's own doc for
/// why that holds there.
pub fn attr_values(body: &str, attr: &str) -> Vec<String> {
    let mut values = Vec::new();
    let needle = format!("{attr}=\"");
    let mut search_from = 0;
    while let Some(relative) = body[search_from..].find(&needle) {
        let start = search_from + relative + needle.len();
        let Some(relative_end) = body[start..].find('"') else { break };
        values.push(body[start..start + relative_end].to_owned());
        search_from = start + relative_end;
    }
    values
}

/// The value of the first occurrence of `attr` in `body`.
pub fn attr_value(body: &str, attr: &str) -> Option<String> {
    attr_values(body, attr).into_iter().next()
}

/// Whether `body` contains an opening tag for `name` — used to tell which
/// operation a SOAP body carries, since the operation is always exactly one
/// of a known, disjoint set of element names and no two ever appear in the
/// same request. `true` regardless of whether the tag is self-closing.
pub fn has_element(body: &str, name: &str) -> bool {
    find_tag(body, name).is_some()
}

/// Finds the first opening tag matching `name` (honouring an optional
/// namespace prefix), returning `(tag_start, index_of_'>', is_self_closing,
/// full_tag_name)` — `full_tag_name` includes the prefix when the match had
/// one (`"t:Foo"`, not just `"Foo"`), since the matching closing tag carries
/// the same prefix and a caller bounding an element's text needs to search
/// for the *same* pair, not any same-named element anywhere else in the body.
///
/// The boundary check — the character immediately before `name` must open a
/// tag (`<` or a prefix's `:`), and the character immediately after must end
/// the name (`>`, a space before attributes, or `/` for a self-closing tag)
/// — is what keeps a search for `"Item"` from matching inside `"ItemId"` or a
/// search for `"GetFolder"` from matching inside a longer name that merely
/// contains it.
fn find_tag(body: &str, name: &str) -> Option<(usize, usize, bool, String)> {
    let mut search_from = 0;
    loop {
        let relative = body[search_from..].find(name)?;
        let at = search_from + relative;
        let before = body[..at].chars().next_back();
        let after = body[at + name.len()..].chars().next();
        let preceded_by_tag_start = matches!(before, Some('<') | Some(':'));
        let followed_by_tag_end = matches!(after, Some('>') | Some(' ') | Some('/'));
        if preceded_by_tag_start && followed_by_tag_end {
            let gt = at + body[at..].find('>')?;
            let self_closing = body.as_bytes().get(gt.wrapping_sub(1)) == Some(&b'/');
            let tag_name = if before == Some(':') {
                let lt = body[..at].rfind('<')?;
                body[lt + 1..at + name.len()].to_owned()
            } else {
                name.to_owned()
            };
            return Some((at, gt, self_closing, tag_name));
        }
        search_from = at + name.len();
    }
}

/// Escapes the five characters XML text content and quoted attribute values
/// cannot carry literally.
///
/// Applied unconditionally rather than only where a `<`/`&` happens to
/// occur, so correctness never depends on the caller remembering which
/// context a value lands in — the same policy
/// `crates/storage/src/dav/multistatus.rs`'s `escape` documents for itself.
pub fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn element_text_matches_a_namespaced_tag_by_local_name() {
        assert_eq!(element_text("<t:EMailAddress>dave@example.com</t:EMailAddress>", "EMailAddress").as_deref(), Some("dave@example.com"));
    }

    #[test]
    fn element_text_matches_an_unprefixed_tag() {
        assert_eq!(element_text("<EMailAddress>dave@example.com</EMailAddress>", "EMailAddress").as_deref(), Some("dave@example.com"));
    }

    #[test]
    fn element_text_is_none_for_an_absent_element() {
        assert_eq!(element_text("<Other>x</Other>", "EMailAddress"), None);
    }

    #[test]
    fn element_text_is_none_for_empty_content() {
        assert_eq!(element_text("<EMailAddress></EMailAddress>", "EMailAddress"), None);
    }

    #[test]
    fn attr_values_collects_every_occurrence_in_order() {
        let body = r#"<t:FolderId Id="inbox"/><t:FolderId Id="drafts"/>"#;
        assert_eq!(attr_values(body, "Id"), vec!["inbox".to_owned(), "drafts".to_owned()]);
    }

    #[test]
    fn attr_value_is_none_when_absent() {
        assert_eq!(attr_value("<t:FolderId/>", "Id"), None);
    }

    #[test]
    fn has_element_does_not_false_positive_on_a_longer_tag_name() {
        // "Item" must not be reported present just because "ItemId" contains
        // it as a literal substring — the boundary check requires the match
        // to actually end the tag name, not just start it.
        assert!(!has_element("<t:ItemId Id=\"x\"/>", "Item"));
        assert!(has_element("<m:FindItem Traversal=\"Shallow\">", "FindItem"));
    }

    #[test]
    fn has_element_matches_a_self_closing_tag() {
        assert!(has_element("<m:GetFolder/>", "GetFolder"));
    }
}
