//! Static file serving.
//!
//! Two things here have to be correct or the server is either insecure or
//! useless for video:
//!
//! 1. **Path resolution must not escape the site root.** The request target is
//!    attacker-controlled, so `..`, percent-encoded `..`, absolute paths,
//!    Windows drive letters and backslashes, NUL bytes, and symlinks pointing
//!    outside the root all have to be refused. Decoding happens *before* the
//!    traversal check, because checking first and decoding second is exactly how
//!    `%2e%2e%2f` gets through.
//! 2. **Byte ranges must work.** The site this platform was built for serves an
//!    adaptive HLS ladder, and every seek is a `Range` request.

use crate::mime;
use selfhost_http::range::{self, RangeOutcome};
use selfhost_http::date;
use selfhost_http::{Method, Request, Response, Status};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// What a request resolved to inside a site root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// A file to serve.
    File(PathBuf),
    /// The path escaped the root, or was otherwise refused.
    Rejected,
    /// Nothing matched, and the site does not fall back to an app shell.
    NotFound,
}

/// Percent-decodes a path, refusing encodings that hide a NUL or a separator.
///
/// Returns `None` for malformed escapes rather than passing them through, since
/// a half-decoded path is precisely the kind of ambiguity that lets two layers
/// disagree about what was requested.
fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;

    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes.get(i + 1..i + 3)?;
                let text = std::str::from_utf8(hex).ok()?;
                let byte = u8::from_str_radix(text, 16).ok()?;
                // A decoded NUL would truncate the path for any C-based syscall
                // layer underneath us.
                if byte == 0 {
                    return None;
                }
                out.push(byte);
                i += 3;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }

    String::from_utf8(out).ok()
}

/// Maps a request path to a file beneath `root`.
///
/// `spa` makes an unmatched path fall back to `index.html`, which is what lets
/// a client-side route survive a page reload.
pub fn resolve(root: &Path, request_path: &str, spa: bool) -> Resolution {
    let Some(decoded) = percent_decode(request_path) else {
        return Resolution::Rejected;
    };

    if decoded.contains('\0') {
        return Resolution::Rejected;
    }

    // Backslash is a separator on Windows, so treating it as an ordinary
    // character would let `..\..\` walk out of the root on that platform.
    let normalised = decoded.replace('\\', "/");

    let mut safe = PathBuf::new();
    for segment in normalised.split('/') {
        match segment {
            "" | "." => continue,
            ".." => {
                // Refuse rather than pop. Popping silently serves a *different*
                // file than was asked for, which hides the attempt.
                return Resolution::Rejected;
            }
            segment => {
                let component = Path::new(segment);
                // A segment must be one plain name. Anything the OS would read
                // as a root, prefix, or drive letter is refused.
                let mut components = component.components();
                match (components.next(), components.next()) {
                    (Some(Component::Normal(name)), None) => safe.push(name),
                    _ => return Resolution::Rejected,
                }
            }
        }
    }

    let candidate = root.join(&safe);
    let candidate = if candidate.is_dir() { candidate.join("index.html") } else { candidate };

    if candidate.is_file() {
        return match confine(root, &candidate) {
            Some(path) => Resolution::File(path),
            None => Resolution::Rejected,
        };
    }

    if spa {
        let shell = root.join("index.html");
        if shell.is_file() {
            return match confine(root, &shell) {
                Some(path) => Resolution::File(path),
                None => Resolution::Rejected,
            };
        }
    }

    Resolution::NotFound
}

/// Confirms a resolved path really sits inside the root once symlinks are
/// followed.
///
/// The textual checks above stop `..`; this stops a symlink inside the root that
/// points outside it, which no amount of string handling can catch.
fn confine(root: &Path, candidate: &Path) -> Option<PathBuf> {
    let real_root = root.canonicalize().ok()?;
    let real_candidate = candidate.canonicalize().ok()?;
    real_candidate.starts_with(&real_root).then_some(real_candidate)
}

/// A response head plus the byte window to send from a file.
#[derive(Debug)]
pub struct FileResponse {
    /// The head to write.
    pub response: Response,
    /// Offset of the first byte to send.
    pub offset: u64,
    /// Number of bytes to send. Zero for a `HEAD` request or an error page.
    pub length: u64,
}

/// Builds the response for a resolved file, honouring `Range` and cache
/// validators.
///
/// `total` and `modified` are passed in rather than read here, so this stays a
/// pure function testable without touching a filesystem.
pub fn build_response(
    request: &Request,
    path: &Path,
    total: u64,
    modified: Option<SystemTime>,
) -> FileResponse {
    let name = path.to_string_lossy();
    let content_type = mime::for_path(&name);
    let tag = date::entity_tag(total, modified);

    let mut response = Response::empty(Status::OK);
    let _ = response.headers.set("Content-Type", content_type);
    // Advertising range support is what makes a player attempt a seek at all.
    let _ = response.headers.set("Accept-Ranges", "bytes");
    let _ = response.headers.set("ETag", tag.clone());
    if let Some(time) = modified {
        let _ = response.headers.set("Last-Modified", date::format(time));
    }

    // A cache validator that still matches means the client already has this
    // representation. Answering 304 skips the transfer entirely — on a repeat
    // visit to a video-heavy site that is most of the bytes.
    if is_unchanged(request, &tag, modified) {
        let mut not_modified = Response::empty(Status::NOT_MODIFIED);
        // A 304 carries the validators so the client can refresh its freshness
        // bookkeeping, but never a body.
        let _ = not_modified.headers.set("ETag", tag);
        if let Some(time) = modified {
            let _ = not_modified.headers.set("Last-Modified", date::format(time));
        }
        let _ = not_modified.headers.set("Accept-Ranges", "bytes");
        return FileResponse { response: not_modified, offset: 0, length: 0 };
    }

    let range_header = request.headers.get_str("range");

    // A range request against a HEAD is answered with the range's headers but no
    // body, so the player learns the size without downloading anything.
    let send_body = request.method.allows_response_body();

    match range::evaluate(range_header, total) {
        RangeOutcome::Full => {
            response.body = selfhost_http::Body::Streamed(total);
            FileResponse { response, offset: 0, length: if send_body { total } else { 0 } }
        }
        RangeOutcome::Partial(window) => {
            response.status = Status::PARTIAL_CONTENT;
            let _ = response.headers.set("Content-Range", window.content_range(total));
            response.body = selfhost_http::Body::Streamed(window.len());
            FileResponse {
                response,
                offset: window.start,
                length: if send_body { window.len() } else { 0 },
            }
        }
        RangeOutcome::Unsatisfiable => {
            let mut refused = Response::empty(Status::RANGE_NOT_SATISFIABLE);
            // Telling the client the real size lets it retry with a valid range
            // instead of guessing again.
            let _ = refused.headers.set("Content-Range", format!("bytes */{total}"));
            let _ = refused.headers.set("Accept-Ranges", "bytes");
            FileResponse { response: refused, offset: 0, length: 0 }
        }
    }
}

/// Whether the client's cached copy is still current.
///
/// `If-None-Match` wins outright when present: an entity tag is an exact
/// identity check, while a modification date has one-second resolution and
/// cannot distinguish two edits within the same second. Consulting the date as
/// well when a tag was supplied would let the weaker validator override the
/// stronger one.
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

/// Whether a method may be served from static files.
pub fn method_allowed(method: &Method) -> bool {
    matches!(method, Method::Get | Method::Head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("selfhost-files-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("assets")).unwrap();
        fs::write(root.join("index.html"), b"<h1>home</h1>").unwrap();
        fs::write(root.join("assets/app.js"), b"console.log(1)").unwrap();
        root
    }

    #[test]
    fn serves_a_plain_file() {
        let root = temp_root("plain");
        assert!(matches!(resolve(&root, "/assets/app.js", false), Resolution::File(_)));
    }

    #[test]
    fn a_directory_serves_its_index() {
        let root = temp_root("dir");
        let Resolution::File(path) = resolve(&root, "/", false) else {
            panic!("expected the directory index");
        };
        assert!(path.ends_with("index.html"));
    }

    #[test]
    fn dot_dot_is_refused_not_normalised() {
        let root = temp_root("traversal");
        // Refusing rather than popping means the attempt cannot silently return
        // some other file instead.
        assert_eq!(resolve(&root, "/../../etc/passwd", false), Resolution::Rejected);
        assert_eq!(resolve(&root, "/assets/../../etc/passwd", false), Resolution::Rejected);
        assert_eq!(resolve(&root, "/..", false), Resolution::Rejected);
    }

    #[test]
    fn percent_encoded_traversal_is_refused() {
        let root = temp_root("encoded");
        // Decoding after the traversal check is exactly how this gets through,
        // so decoding happens first.
        assert_eq!(resolve(&root, "/%2e%2e/%2e%2e/etc/passwd", false), Resolution::Rejected);
        assert_eq!(resolve(&root, "/%2E%2E/secret", false), Resolution::Rejected);
        assert_eq!(resolve(&root, "/assets/%2e%2e%2f%2e%2e%2fetc", false), Resolution::Rejected);
    }

    #[test]
    fn double_encoded_traversal_stays_a_literal_name() {
        let root = temp_root("double");
        // %252e decodes once to %2e, not to a dot — decoding must not recurse.
        assert!(matches!(resolve(&root, "/%252e%252e/x", false), Resolution::NotFound));
    }

    #[test]
    fn backslash_traversal_is_refused() {
        let root = temp_root("backslash");
        assert_eq!(resolve(&root, "/..\\..\\windows\\system32", false), Resolution::Rejected);
        assert_eq!(resolve(&root, "/%5c..%5c..", false), Resolution::Rejected);
    }

    #[test]
    fn nul_bytes_are_refused() {
        let root = temp_root("nul");
        assert_eq!(resolve(&root, "/index.html%00.txt", false), Resolution::Rejected);
    }

    #[test]
    fn malformed_escapes_are_refused() {
        let root = temp_root("malformed");
        assert_eq!(resolve(&root, "/%zz", false), Resolution::Rejected);
        assert_eq!(resolve(&root, "/%2", false), Resolution::Rejected);
    }

    #[test]
    fn spa_falls_back_to_the_shell_but_still_refuses_traversal() {
        let root = temp_root("spa");
        // A deep link must survive a reload...
        assert!(matches!(resolve(&root, "/videos/2024", true), Resolution::File(_)));
        // ...without the fallback becoming a way to bypass the root check.
        assert_eq!(resolve(&root, "/../etc/passwd", true), Resolution::Rejected);
    }

    #[test]
    fn missing_files_are_not_found_when_spa_is_off() {
        let root = temp_root("missing");
        assert_eq!(resolve(&root, "/nope.txt", false), Resolution::NotFound);
    }

    fn request_with_range(range: Option<&str>) -> Request {
        let raw = match range {
            Some(value) => format!("GET /clip.mp4 HTTP/1.1\r\nHost: a.com\r\nRange: {value}\r\n\r\n"),
            None => "GET /clip.mp4 HTTP/1.1\r\nHost: a.com\r\n\r\n".to_owned(),
        };
        Request::parse(raw.as_bytes()).unwrap().request
    }

    #[test]
    fn a_whole_file_is_sent_without_a_range() {
        let built = build_response(&request_with_range(None), Path::new("clip.mp4"), 1000, None);
        assert_eq!(built.response.status, Status::OK);
        assert_eq!(built.offset, 0);
        assert_eq!(built.length, 1000);
        assert_eq!(built.response.headers.get_str("accept-ranges"), Some("bytes"));
        assert_eq!(built.response.headers.get_str("content-type"), Some("video/mp4"));
    }

    #[test]
    fn a_seek_produces_206_with_the_right_window() {
        let built = build_response(&request_with_range(Some("bytes=500-")), Path::new("clip.mp4"), 1000, None);
        assert_eq!(built.response.status, Status::PARTIAL_CONTENT);
        assert_eq!(built.offset, 500);
        assert_eq!(built.length, 500);
        assert_eq!(built.response.headers.get_str("content-range"), Some("bytes 500-999/1000"));
    }

    #[test]
    fn an_impossible_range_reports_the_real_size() {
        let built = build_response(&request_with_range(Some("bytes=5000-")), Path::new("clip.mp4"), 1000, None);
        assert_eq!(built.response.status, Status::RANGE_NOT_SATISFIABLE);
        assert_eq!(built.response.headers.get_str("content-range"), Some("bytes */1000"));
        assert_eq!(built.length, 0);
    }

    #[test]
    fn head_reports_the_size_without_sending_bytes() {
        let raw = "HEAD /clip.mp4 HTTP/1.1\r\nHost: a.com\r\n\r\n";
        let request = Request::parse(raw.as_bytes()).unwrap().request;
        let built = build_response(&request, Path::new("clip.mp4"), 1000, None);
        assert_eq!(built.length, 0);
        // The declared length still describes what a GET would return.
        assert_eq!(built.response.body.len(), 1000);
    }

    fn request_with(headers: &[(&str, &str)]) -> Request {
        let mut raw = String::from("GET /clip.mp4 HTTP/1.1\r\nHost: a.com\r\n");
        for (name, value) in headers {
            raw.push_str(&format!("{name}: {value}\r\n"));
        }
        raw.push_str("\r\n");
        Request::parse(raw.as_bytes()).unwrap().request
    }

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(seconds)
    }

    #[test]
    fn a_fresh_response_carries_both_validators() {
        let built = build_response(&request_with(&[]), Path::new("clip.mp4"), 1000, Some(at(1_785_089_368)));
        assert_eq!(built.response.status, Status::OK);
        assert_eq!(
            built.response.headers.get_str("last-modified"),
            Some("Sun, 26 Jul 2026 18:09:28 GMT")
        );
        assert!(built.response.headers.get_str("etag").is_some());
    }

    #[test]
    fn a_matching_etag_answers_304_with_no_body() {
        let modified = Some(at(1_785_089_368));
        let first = build_response(&request_with(&[]), Path::new("clip.mp4"), 1000, modified);
        let tag = first.response.headers.get_str("etag").unwrap().to_owned();

        let second =
            build_response(&request_with(&[("If-None-Match", &tag)]), Path::new("clip.mp4"), 1000, modified);
        assert_eq!(second.response.status, Status::NOT_MODIFIED);
        assert_eq!(second.length, 0);
        // 304 keeps the validators so the client can refresh its bookkeeping.
        assert_eq!(second.response.headers.get_str("etag"), Some(tag.as_str()));
    }

    #[test]
    fn a_stale_etag_sends_the_file() {
        let built = build_response(
            &request_with(&[("If-None-Match", "W/\"deadbeef-1\"")]),
            Path::new("clip.mp4"),
            1000,
            Some(at(1_785_089_368)),
        );
        assert_eq!(built.response.status, Status::OK);
        assert_eq!(built.length, 1000);
    }

    #[test]
    fn if_modified_since_answers_304_when_unchanged() {
        let built = build_response(
            &request_with(&[("If-Modified-Since", "Sun, 26 Jul 2026 18:09:28 GMT")]),
            Path::new("clip.mp4"),
            1000,
            Some(at(1_785_089_368)),
        );
        assert_eq!(built.response.status, Status::NOT_MODIFIED);
    }

    #[test]
    fn if_modified_since_sends_the_file_when_it_changed() {
        let built = build_response(
            &request_with(&[("If-Modified-Since", "Sun, 26 Jul 2026 18:09:28 GMT")]),
            Path::new("clip.mp4"),
            1000,
            // One second newer than the client's copy.
            Some(at(1_785_089_369)),
        );
        assert_eq!(built.response.status, Status::OK);
    }

    #[test]
    fn an_etag_outranks_a_modification_date() {
        // A date has one-second resolution and cannot distinguish two edits in
        // the same second. Letting it override an exact tag match would serve a
        // stale body.
        let built = build_response(
            &request_with(&[
                ("If-None-Match", "W/\"deadbeef-1\""),
                ("If-Modified-Since", "Sun, 26 Jul 2026 18:09:28 GMT"),
            ]),
            Path::new("clip.mp4"),
            1000,
            Some(at(1_785_089_368)),
        );
        assert_eq!(built.response.status, Status::OK, "stale tag should force a transfer");
    }

    #[test]
    fn an_unparseable_date_falls_back_to_sending_the_file() {
        // Failing open is always correct; failing closed would serve a stale page.
        let built = build_response(
            &request_with(&[("If-Modified-Since", "Sunday, 26-Jul-26 18:09:28 GMT")]),
            Path::new("clip.mp4"),
            1000,
            Some(at(1_785_089_368)),
        );
        assert_eq!(built.response.status, Status::OK);
    }

    #[test]
    fn only_get_and_head_may_read_static_files() {
        assert!(method_allowed(&Method::Get));
        assert!(method_allowed(&Method::Head));
        assert!(!method_allowed(&Method::Post));
        assert!(!method_allowed(&Method::Delete));
    }
}
