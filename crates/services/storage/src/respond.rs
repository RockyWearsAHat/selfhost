//! The response head for one file out of a share.
//!
//! Pure: `(request, name, total, modified)` in, a head and a byte window out.
//! No file is opened here, exactly as `proxy/src/files.rs::build_response`
//! (`:191`) takes `total` and `modified` as arguments for the same reason — it
//! is the only way to test 206, 304 and 416 without a filesystem.
//!
//! # What is reused, precisely
//!
//! Range and validator handling are **not reimplemented**. This module calls, unchanged:
//!
//! - [`selfhost_http::range::evaluate`] — the whole `Range` grammar, including
//!   the suffix form, the open-ended form, the "ignore a malformed range rather
//!   than reject it" rule the specification requires, and the multi-range case
//!   collapsing to the full representation.
//! - [`selfhost_http::ByteRange::content_range`] — the `Content-Range` field
//!   value, so a 206 and a 416 cannot disagree about how to spell one.
//! - [`selfhost_http::date::entity_tag`] — the `ETag`, derived from size and
//!   mtime.
//! - [`selfhost_http::date::if_none_match_matches`] — including the weak-tag and
//!   `*` cases.
//! - [`selfhost_http::date::parse`] / [`selfhost_http::date::format`] — HTTP-date
//!   handling for `If-Modified-Since` and `Last-Modified`.
//! - [`selfhost_http::Body::Streamed`] — so the head declares a length the
//!   sending loop is then obliged to match.
//!
//! What is *not* reused is `files::build_response` itself, and there are two
//! reasons rather than one. The structural reason: `proxy` is a sibling crate
//! that `storage` does not depend on and must not (the edge runs
//! `config → storage → http`; a NAS pulling in the reverse proxy would make the
//! daemon's dependency graph a cycle waiting to happen). The substantive reason
//! is the next section, and it would keep the two functions apart even if the
//! dependency edge allowed it.
//!
//! # A share is not a published site, and the `Content-Type` is where that bites
//!
//! `proxy/src/mime.rs` guesses a type from the extension and serves it, which is
//! right for a static root: an operator published those files deliberately, and
//! a site that cannot serve its own `index.html` as HTML is not a site.
//!
//! A share is the opposite. Its contents were *uploaded*, possibly by somebody
//! who is not the operator, and the URL they are served from is on the console's
//! own origin — the origin that holds the session cookie for the thing that can
//! restart services, drive a keyboard and read the filesystem. Serving an
//! uploaded `evil.html` as `text/html` from that origin is stored
//! cross-site scripting straight into the admin console, and it needs no bug
//! anywhere else to work.
//!
//! So the rule here is an **allow-list, inverted from the static server's
//! best-effort guess**:
//!
//! 1. Every response is `Content-Disposition: attachment` unless the caller
//!    explicitly asked for a preview *and* the type is one of the few that
//!    cannot carry script.
//! 2. Everything not on that list is `application/octet-stream`, which browsers
//!    treat as an opaque download.
//! 3. `X-Content-Type-Options: nosniff` is always sent, so a browser cannot
//!    sniff its way back to a type we refused to name.
//! 4. `Content-Security-Policy: sandbox` is always sent, so even a type that
//!    slipped through executes with no origin, no scripts and no forms.
//!
//! `image/svg+xml` and `application/pdf` are deliberately **absent** from the
//! preview list. Both are documents that execute script in the embedding origin,
//! and both are the exact files a person most wants to preview — which is why
//! the omission is written down here rather than left to be noticed as missing.

use selfhost_http::date;
use selfhost_http::range::{self, RangeOutcome};
use selfhost_http::{Body, HeaderError, Headers, Request, Response, Status};
use std::time::{SystemTime, UNIX_EPOCH};

/// The type served when nothing safer applies.
///
/// Also the type served for everything a caller did not explicitly ask to
/// preview, which is the common case.
pub const OPAQUE_TYPE: &str = "application/octet-stream";

/// Types a share will serve inline, when a caller asks for a preview.
///
/// Every entry is a format whose renderer does not execute author-supplied
/// script in the embedding origin. Notably absent, and absent on purpose:
/// `text/html` (obviously), `image/svg+xml` (an SVG is a document that can carry
/// `<script>`), `application/pdf` (the built-in viewers run embedded
/// JavaScript), and `application/xml` (an XML file with a stylesheet is HTML in
/// a hat). Adding an entry to this list is a security decision, not a
/// convenience one.
const PREVIEWABLE: [(&str, &str); 12] = [
    ("png", "image/png"),
    ("jpg", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("gif", "image/gif"),
    ("webp", "image/webp"),
    ("avif", "image/avif"),
    ("mp4", "video/mp4"),
    ("m4v", "video/mp4"),
    ("webm", "video/webm"),
    ("mp3", "audio/mpeg"),
    ("wav", "audio/wav"),
    ("txt", "text/plain; charset=utf-8"),
];

/// Whether the caller asked to look at the file or to save it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Always a download. The default, and what every WebDAV client wants.
    Attachment,
    /// Show it in the page if — and only if — the type is one that cannot carry
    /// script. Anything else falls back to a download; the caller does not get
    /// to override that, which is why the variant is named for a request rather
    /// than for an outcome.
    InlineIfSafe,
}

/// A response head plus the byte window the caller must send from the file.
///
/// The same shape as `proxy::files::FileResponse`, because the sending loop is
/// the same loop (`proxy/src/server.rs:896-913`: seek, take, `tokio::io::copy`)
/// and a second shape would mean a second loop.
#[derive(Debug)]
pub struct BlobResponse {
    /// The head to write.
    pub response: Response,
    /// Offset of the first byte to send.
    pub offset: u64,
    /// Number of bytes to send. Zero for `HEAD`, for a 304, and for a 416.
    pub length: u64,
}

/// Builds the response head for a file in a share.
///
/// `total` and `modified` come from the caller's already-open handle rather than
/// from a fresh `stat`, so the head describes the same bytes the body will
/// carry. Reading metadata here and opening the file afterwards is a race: the
/// file can change size in between, and the `Content-Length` would then be a
/// lie the connection cannot recover from.
pub fn blob(
    request: &Request,
    name: &str,
    total: u64,
    modified: Option<SystemTime>,
    disposition: Disposition,
) -> BlobResponse {
    match build(request, name, total, modified, disposition) {
        Ok(built) => built,
        // A header value is refused only if it contains CR, LF or NUL, which
        // nothing built below can (the filename is percent-encoded to ASCII
        // first). Answering 500 rather than unwrapping keeps that reasoning
        // from becoming a panic if it is ever wrong — and under
        // `panic = "abort"` a panic in this process is the whole box.
        Err(_) => BlobResponse {
            response: Response::error_page(Status::INTERNAL_SERVER_ERROR),
            offset: 0,
            length: 0,
        },
    }
}

/// The body of [`blob`], with header failures surfaced rather than ignored.
fn build(
    request: &Request,
    name: &str,
    total: u64,
    modified: Option<SystemTime>,
    disposition: Disposition,
) -> Result<BlobResponse, HeaderError> {
    let tag = date::entity_tag(total, modified);

    // A cache validator that still matches means the client already holds these
    // bytes. This is what makes a second `PROPFIND`-then-`GET` from Finder cost
    // nothing, and it must be decided before `Range`: answering a range request
    // for a representation the client already has is a transfer nobody needed.
    if is_unchanged(request, &tag, modified) {
        let mut not_modified = Response::empty(Status::NOT_MODIFIED);
        validators(&mut not_modified.headers, &tag, modified)?;
        guards(&mut not_modified.headers)?;
        return Ok(BlobResponse { response: not_modified, offset: 0, length: 0 });
    }

    let mut response = Response::empty(Status::OK);
    let (content_type, inline) = presentation(name, disposition);
    response.headers.set("Content-Type", content_type)?;
    response.headers.set("Content-Disposition", content_disposition(name, inline))?;
    validators(&mut response.headers, &tag, modified)?;
    guards(&mut response.headers)?;

    // A `HEAD` gets every header a `GET` would, including the range headers, and
    // no bytes: that is how a client learns a file's size before deciding to
    // fetch it.
    let send_body = request.method.allows_response_body();

    Ok(match range::evaluate(request.headers.get_str("range"), total) {
        RangeOutcome::Full => {
            response.body = Body::Streamed(total);
            BlobResponse { response, offset: 0, length: if send_body { total } else { 0 } }
        }
        RangeOutcome::Partial(window) => {
            response.status = Status::PARTIAL_CONTENT;
            response.headers.set("Content-Range", window.content_range(total))?;
            response.body = Body::Streamed(window.len());
            BlobResponse {
                response,
                offset: window.start,
                length: if send_body { window.len() } else { 0 },
            }
        }
        RangeOutcome::Unsatisfiable => {
            let mut refused = Response::empty(Status::RANGE_NOT_SATISFIABLE);
            // Telling the client the real size lets it retry with a range that
            // works instead of guessing a second time.
            refused.headers.set("Content-Range", format!("bytes */{total}"))?;
            guards(&mut refused.headers)?;
            BlobResponse { response: refused, offset: 0, length: 0 }
        }
    })
}

/// The cache validators, which every one of these responses carries.
///
/// A 304 carries them too, so the client can refresh its freshness bookkeeping
/// without a second request.
fn validators(
    headers: &mut Headers,
    tag: &str,
    modified: Option<SystemTime>,
) -> Result<(), HeaderError> {
    headers.set("ETag", tag)?;
    headers.set("Accept-Ranges", "bytes")?;
    if let Some(time) = modified {
        headers.set("Last-Modified", date::format(time))?;
    }
    Ok(())
}

/// The headers that hold whatever the `Content-Type` decision got wrong.
///
/// `nosniff` stops a browser recovering a type we deliberately refused to name,
/// and the sandbox policy strips origin, scripts and forms from anything that
/// renders anyway — so a file that somehow reaches a renderer reaches it with no
/// access to the console it is being served from. `private` keeps a share's
/// contents out of any shared cache while leaving revalidation working, which is
/// what makes the 304 path above worth having.
fn guards(headers: &mut Headers) -> Result<(), HeaderError> {
    headers.set("X-Content-Type-Options", "nosniff")?;
    headers.set("Content-Security-Policy", "sandbox")?;
    headers.set("Cache-Control", "private, max-age=0, must-revalidate")?;
    Ok(())
}

/// The content type to send, and whether it may be shown inline.
///
/// Returns `(type, inline)` together because the two decisions are one decision:
/// a type is served inline exactly when it is on the preview list *and* the
/// caller asked, and anything else is an opaque download. Splitting them into
/// two functions would let a caller pair "inline" with a type that was never
/// cleared for it.
pub fn presentation(name: &str, disposition: Disposition) -> (&'static str, bool) {
    if disposition == Disposition::Attachment {
        return (OPAQUE_TYPE, false);
    }
    let extension = name.rsplit('.').next().unwrap_or_default().to_ascii_lowercase();
    // A name with no dot at all yields the whole name here, which cannot match
    // an extension in the table and so falls through to the opaque type — the
    // safe direction.
    match PREVIEWABLE.iter().find(|(ext, _)| *ext == extension) {
        Some((_, content_type)) => (content_type, true),
        None => (OPAQUE_TYPE, false),
    }
}

/// The `Content-Disposition` field value, carrying the filename twice.
///
/// RFC 6266 wants both spellings: a quoted ASCII `filename` that every client
/// understands, and an RFC 5987 `filename*` that carries the real UTF-8 name.
/// Sending only the first loses every non-ASCII name; sending only the second
/// loses older clients. The ASCII fallback is stripped rather than transliterated
/// — a name reduced to `_` still downloads, whereas a guessed transliteration
/// downloads under a name the person did not choose and cannot search for.
fn content_disposition(name: &str, inline: bool) -> String {
    let kind = if inline { "inline" } else { "attachment" };
    // A plain space survives — it is legal inside the quoted form and it is in
    // half the filenames a person has. A quote or a backslash would end the
    // quoted string early, and anything non-ASCII has no meaning in this
    // parameter at all, so both become `_`.
    let fallback: String = name
        .chars()
        .map(|c| if (c.is_ascii_graphic() || c == ' ') && c != '"' && c != '\\' { c } else { '_' })
        .collect();
    let encoded = encode_rfc5987(name_only(name));
    format!("{kind}; filename=\"{fallback}\"; filename*=UTF-8''{encoded}")
}

/// The last path segment of a name, so a `Content-Disposition` never leaks the
/// directories above it.
///
/// The resolver has already refused a separator inside a segment, so this is a
/// belt on top of braces — and it is cheap enough that leaving it out to prove
/// a point about layering would be the wrong trade.
fn name_only(name: &str) -> &str {
    name.rsplit(['/', '\\']).next().unwrap_or(name)
}

/// Percent-encodes a filename for an RFC 5987 `filename*` parameter.
///
/// Only the unreserved set survives unescaped; everything else, including every
/// byte of a multi-byte character, becomes `%XX`. That is stricter than the
/// grammar demands, and being stricter costs nothing here while removing any
/// argument about whether a particular byte needed escaping.
///
/// Written locally on purpose: the other percent-encoder in this repository
/// ([`crate::path::encode_segment`]) escapes a different set for a different
/// grammar. When `crates/http/src/uri.rs` lands with a shared encoder, this
/// function should be deleted in favour of it — see the crate's follow-ups.
fn encode_rfc5987(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for byte in name.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Whether the client's cached copy is still current.
///
/// `If-None-Match` wins outright when present: an entity tag is an exact
/// identity check, while a modification date has one-second resolution and
/// cannot tell two edits in the same second apart. Consulting the date as well
/// when a tag was supplied would let the weaker validator override the stronger
/// one. This mirrors `proxy/src/files.rs::is_unchanged` (`:271`) deliberately —
/// two file servers on one box answering `If-None-Match` differently would be a
/// bug nobody could reproduce.
fn is_unchanged(request: &Request, tag: &str, modified: Option<SystemTime>) -> bool {
    if let Some(header) = request.headers.get_str("if-none-match") {
        return date::if_none_match_matches(header, tag);
    }

    let (Some(header), Some(time)) = (request.headers.get_str("if-modified-since"), modified) else {
        return false;
    };
    let (Some(since), Ok(file_time)) = (date::parse(header), time.duration_since(UNIX_EPOCH)) else {
        return false;
    };

    // Truncate to whole seconds before comparing: the header has no sub-second
    // precision, so a file written mid-second would otherwise always look newer
    // than a date derived from it.
    (file_time.as_secs() as i64) <= since
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_http::Method;
    use std::time::Duration;

    fn request(method: Method, headers: &[(&str, &str)]) -> Request {
        let mut request = Request {
            method,
            target: "/api/storage/blob/vault/notes.txt".to_string(),
            minor_version: 1,
            headers: Headers::new(),
        };
        for (name, value) in headers {
            request.headers.set(*name, *value).expect("test header must be legal");
        }
        request
    }

    fn modified() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_770_000_000)
    }

    fn header(response: &Response, name: &str) -> String {
        response.headers.get_str(name).unwrap_or_default().to_string()
    }

    #[test]
    fn a_whole_file_is_a_streamed_two_hundred() {
        let built = blob(
            &request(Method::Get, &[]),
            "notes.txt",
            1000,
            Some(modified()),
            Disposition::Attachment,
        );
        assert_eq!(built.response.status, Status::OK);
        assert_eq!(built.offset, 0);
        assert_eq!(built.length, 1000);
        assert_eq!(built.response.body.len(), 1000);
        assert_eq!(header(&built.response, "accept-ranges"), "bytes");
        assert!(!header(&built.response, "etag").is_empty());
        assert!(!header(&built.response, "last-modified").is_empty());
    }

    #[test]
    fn a_range_is_evaluated_by_the_http_crate_and_answered_206() {
        let built = blob(
            &request(Method::Get, &[("Range", "bytes=100-199")]),
            "video.mp4",
            1000,
            None,
            Disposition::Attachment,
        );
        assert_eq!(built.response.status, Status::PARTIAL_CONTENT);
        assert_eq!(built.offset, 100);
        assert_eq!(built.length, 100);
        assert_eq!(header(&built.response, "content-range"), "bytes 100-199/1000");
        assert_eq!(built.response.body.len(), 100);
    }

    #[test]
    fn a_suffix_range_and_an_open_range_come_straight_from_http_range() {
        let suffix = blob(
            &request(Method::Get, &[("Range", "bytes=-100")]),
            "f",
            1000,
            None,
            Disposition::Attachment,
        );
        assert_eq!(suffix.offset, 900);
        assert_eq!(suffix.length, 100);

        let open = blob(
            &request(Method::Get, &[("Range", "bytes=900-")]),
            "f",
            1000,
            None,
            Disposition::Attachment,
        );
        assert_eq!(open.offset, 900);
        assert_eq!(open.length, 100);
    }

    #[test]
    fn an_impossible_range_is_416_with_the_real_size() {
        let built = blob(
            &request(Method::Get, &[("Range", "bytes=5000-6000")]),
            "f",
            1000,
            None,
            Disposition::Attachment,
        );
        assert_eq!(built.response.status, Status::RANGE_NOT_SATISFIABLE);
        assert_eq!(header(&built.response, "content-range"), "bytes */1000");
        assert_eq!(built.length, 0);
    }

    #[test]
    fn a_matching_entity_tag_is_304_with_no_bytes() {
        let tag = date::entity_tag(1000, Some(modified()));
        let built = blob(
            &request(Method::Get, &[("If-None-Match", &tag)]),
            "f",
            1000,
            Some(modified()),
            Disposition::Attachment,
        );
        assert_eq!(built.response.status, Status::NOT_MODIFIED);
        assert_eq!(built.length, 0);
        assert_eq!(header(&built.response, "etag"), tag);

        // A tag for different bytes is not a match.
        let stale = date::entity_tag(999, Some(modified()));
        let refetch = blob(
            &request(Method::Get, &[("If-None-Match", &stale)]),
            "f",
            1000,
            Some(modified()),
            Disposition::Attachment,
        );
        assert_eq!(refetch.response.status, Status::OK);
    }

    #[test]
    fn a_validator_is_checked_before_a_range() {
        // Otherwise a client that already holds the bytes is sent a partial
        // transfer it did not need.
        let tag = date::entity_tag(1000, Some(modified()));
        let built = blob(
            &request(Method::Get, &[("If-None-Match", &tag), ("Range", "bytes=0-9")]),
            "f",
            1000,
            Some(modified()),
            Disposition::Attachment,
        );
        assert_eq!(built.response.status, Status::NOT_MODIFIED);
    }

    #[test]
    fn a_head_carries_every_header_and_no_bytes() {
        let built = blob(
            &request(Method::Head, &[("Range", "bytes=100-199")]),
            "f",
            1000,
            None,
            Disposition::Attachment,
        );
        assert_eq!(built.response.status, Status::PARTIAL_CONTENT);
        assert_eq!(header(&built.response, "content-range"), "bytes 100-199/1000");
        assert_eq!(built.length, 0, "a HEAD sends no body");
    }

    #[test]
    fn uploaded_content_is_never_served_as_something_a_browser_will_run() {
        // The whole point: these are served from the console's own origin.
        let dangerous = ["evil.html", "evil.svg", "report.pdf", "app.js", "sheet.xml", "x.htm"];
        for name in dangerous {
            for disposition in [Disposition::Attachment, Disposition::InlineIfSafe] {
                let (content_type, inline) = presentation(name, disposition);
                assert_eq!(content_type, OPAQUE_TYPE, "{name} must stay opaque");
                assert!(!inline, "{name} must never render inline");
            }
        }
    }

    #[test]
    fn a_preview_is_granted_only_for_types_that_cannot_carry_script() {
        for (extension, expected) in PREVIEWABLE {
            let name = format!("file.{extension}");
            let (content_type, inline) = presentation(&name, Disposition::InlineIfSafe);
            assert_eq!(content_type, expected);
            assert!(inline);
            // ...and never without being asked.
            assert_eq!(presentation(&name, Disposition::Attachment), (OPAQUE_TYPE, false));
        }
        // Case is not part of the decision: Windows preserves it without
        // honouring it, so `Photo.PNG` must preview like `photo.png`.
        assert_eq!(presentation("Photo.PNG", Disposition::InlineIfSafe), ("image/png", true));
        // A name with no extension has nothing to match.
        assert_eq!(presentation("README", Disposition::InlineIfSafe), (OPAQUE_TYPE, false));
    }

    #[test]
    fn every_response_carries_the_guards() {
        for (name, disposition) in
            [("evil.html", Disposition::Attachment), ("photo.png", Disposition::InlineIfSafe)]
        {
            let built = blob(&request(Method::Get, &[]), name, 1, None, disposition);
            assert_eq!(header(&built.response, "x-content-type-options"), "nosniff");
            assert_eq!(header(&built.response, "content-security-policy"), "sandbox");
            assert_eq!(
                header(&built.response, "cache-control"),
                "private, max-age=0, must-revalidate"
            );
        }
    }

    #[test]
    fn the_filename_survives_in_both_spellings() {
        let built = blob(
            &request(Method::Get, &[]),
            "café ☕.txt",
            1,
            None,
            Disposition::Attachment,
        );
        let disposition = header(&built.response, "content-disposition");
        assert!(disposition.starts_with("attachment; "), "{disposition}");
        // The ASCII fallback keeps the shape of the name and loses the rest,
        // rather than guessing a transliteration.
        assert!(disposition.contains(r#"filename="caf_ _.txt""#), "{disposition}");
        assert!(disposition.contains("filename*=UTF-8''caf%C3%A9%20%E2%98%95.txt"), "{disposition}");
        // Whatever the name was, the header value stayed a single line.
        assert!(!disposition.contains('\n') && !disposition.contains('\r'));
    }

    #[test]
    fn a_preview_says_inline_and_a_download_says_attachment() {
        let inline = blob(
            &request(Method::Get, &[]),
            "photo.png",
            1,
            None,
            Disposition::InlineIfSafe,
        );
        assert!(header(&inline.response, "content-disposition").starts_with("inline; "));

        let download =
            blob(&request(Method::Get, &[]), "photo.png", 1, None, Disposition::Attachment);
        assert!(header(&download.response, "content-disposition").starts_with("attachment; "));
    }

    #[test]
    fn a_directory_prefix_never_reaches_the_header() {
        assert_eq!(name_only("a/b/c.txt"), "c.txt");
        assert_eq!(name_only("a\\b\\c.txt"), "c.txt");
        assert_eq!(name_only("c.txt"), "c.txt");
    }

    #[test]
    fn if_modified_since_is_consulted_only_without_a_tag() {
        let since = date::format(modified());
        let built = blob(
            &request(Method::Get, &[("If-Modified-Since", &since)]),
            "f",
            1000,
            Some(modified()),
            Disposition::Attachment,
        );
        assert_eq!(built.response.status, Status::NOT_MODIFIED);

        // A tag that does not match wins over a date that would have said
        // "unchanged" — the stronger validator decides.
        let built = blob(
            &request(
                Method::Get,
                &[("If-None-Match", "\"nonsense\""), ("If-Modified-Since", &since)],
            ),
            "f",
            1000,
            Some(modified()),
            Disposition::Attachment,
        );
        assert_eq!(built.response.status, Status::OK);
    }

    #[test]
    fn an_empty_file_is_answered_without_arithmetic_going_wrong() {
        let built =
            blob(&request(Method::Get, &[]), "empty", 0, None, Disposition::Attachment);
        assert_eq!(built.response.status, Status::OK);
        assert_eq!(built.length, 0);
        assert_eq!(built.response.body.len(), 0);

        // Any range at all against zero bytes is unsatisfiable.
        let ranged = blob(
            &request(Method::Get, &[("Range", "bytes=0-0")]),
            "empty",
            0,
            None,
            Disposition::Attachment,
        );
        assert_eq!(ranged.response.status, Status::RANGE_NOT_SATISFIABLE);
    }
}
