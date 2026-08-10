//! The verb table: which WebDAV methods exist, which this build answers, and
//! what `OPTIONS` is therefore allowed to claim.
//!
//! Pure. Every function here is a value in and a value out.
//!
//! # The table is a closed allow-list, matched first
//!
//! `http/src/request.rs:349` accepts any token as a method, so `PROPFIND`
//! already parses and arrives as [`Method::Other`]. That is convenient and it is
//! also the trap: an unrecognised token must be `405`, decided **before**
//! anything else looks at the request, never a fallthrough into a handler that
//! happened to be reachable. [`Verb::classify`] is that decision and it returns
//! `None` for everything it does not name.
//!
//! # What this build claims is what this build does
//!
//! [`IMPLEMENTED`] is the single list, and the `Allow` and `DAV` headers are
//! **derived** from it rather than written out beside it. That is the whole
//! design of this module, and it exists because the alternative has a specific
//! failure: a server that advertises `DAV: 1, 2` without a working `LOCK` is
//! one the Windows Mini-Redirector will mount and then fail against on the
//! first `PUT`, because it locks before every write. So [`dav_header`] answers
//! `1, 2` exactly when `LOCK` is in the list and `1` otherwise, and the claim
//! cannot outrun the code.
//!
//! The list is now the whole of RFC 4918's core, so `DAV` reads `1, 2` — and it
//! reads that because [`crate::dav::lock`] takes a lock that actually excludes,
//! not because a header was edited.
//!
//! # The write verbs bring a second parsing surface, and it is the dangerous one
//!
//! `COPY` and `MOVE` carry their target in a `Destination` header, as a full
//! URI. That is a completely different shape from the request line's path, and a
//! server that hardened one and hand-rolled the other has hardened half of its
//! write path — a `MOVE` whose destination escapes the root is a write-anywhere
//! primitive as complete as a traversal, and `Overwrite: T` compounds it.
//! [`destination`] exists to funnel that header back into the *same*
//! [`crate::path::resolve`] the request line goes through, and its
//! documentation lists each step as a refusal somebody has exploited elsewhere.
//!
//! A verb that exists in the protocol but not in this build is `405` with an
//! `Allow` header, not `501`: `405` is what RFC 9110 §15.5.6 defines for a
//! method a resource does not support, and the `Allow` it carries tells the
//! client what to do instead. `501` would say the *server* does not understand
//! the method, which is not true and which some clients treat as fatal for the
//! whole mount rather than for the request.

use crate::dav::multistatus::{
    escape, or_internal_error, Href, DAV_ROOT, MULTI_STATUS, XML_TYPE,
};
use crate::respond::{self, BlobResponse, Disposition};
use selfhost_http::{HeaderError, Method, Request, Response, Status};
use std::fmt;
use std::time::SystemTime;

/// A WebDAV method this module has an opinion about.
///
/// Every verb in RFC 4918 is here, including the ones this build does not
/// answer, because the point of the type is to be the closed set: a token that
/// does not map to one of these is refused without ever reaching a handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    /// Describe what this resource supports.
    Options,
    /// Read properties.
    PropFind,
    /// Write properties.
    PropPatch,
    /// Create a collection.
    MkCol,
    /// Read a file.
    Get,
    /// Read a file's headers.
    Head,
    /// Write a file.
    Put,
    /// Remove a resource.
    Delete,
    /// Copy a resource to a `Destination`.
    Copy,
    /// Move a resource to a `Destination`.
    Move,
    /// Take a lock.
    Lock,
    /// Release a lock.
    Unlock,
}

impl Verb {
    /// Recognises a method token, or refuses it.
    ///
    /// `None` is the `405` answer, and it is the answer for `POST`, `PATCH`,
    /// `TRACE`, `CONNECT` and every unknown token alike — a share has no use
    /// for any of them, and a verb table with a default arm is a verb table
    /// with a hole in it.
    pub fn classify(method: &Method) -> Option<Self> {
        match method {
            Method::Options => Some(Self::Options),
            Method::Get => Some(Self::Get),
            Method::Head => Some(Self::Head),
            Method::Put => Some(Self::Put),
            Method::Delete => Some(Self::Delete),
            Method::Post | Method::Patch | Method::Trace | Method::Connect => None,
            Method::Other(token) => match token.as_str() {
                "PROPFIND" => Some(Self::PropFind),
                "PROPPATCH" => Some(Self::PropPatch),
                "MKCOL" => Some(Self::MkCol),
                "COPY" => Some(Self::Copy),
                "MOVE" => Some(Self::Move),
                "LOCK" => Some(Self::Lock),
                "UNLOCK" => Some(Self::Unlock),
                _ => None,
            },
        }
    }

    /// The token as it appears on the wire and in an `Allow` header.
    pub fn token(self) -> &'static str {
        match self {
            Self::Options => "OPTIONS",
            Self::PropFind => "PROPFIND",
            Self::PropPatch => "PROPPATCH",
            Self::MkCol => "MKCOL",
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
            Self::Copy => "COPY",
            Self::Move => "MOVE",
            Self::Lock => "LOCK",
            Self::Unlock => "UNLOCK",
        }
    }

    /// Whether this verb changes anything.
    ///
    /// The route layer needs this before it needs a handler: a writing verb on a
    /// read-only share is refused on the share's own flag, and the caller's
    /// grants are checked with [`crate::share::Want::Write`] rather than
    /// [`crate::share::Want::Read`].
    pub fn writes(self) -> bool {
        !matches!(self, Self::Options | Self::PropFind | Self::Get | Self::Head)
    }
}

/// The verbs this build actually answers.
///
/// One list, from which both advertised headers are derived. Adding a verb here
/// without implementing it is the one way to make this module lie, which is why
/// the list sits next to the sentence saying so rather than in a header string
/// somewhere else.
///
/// It is now the whole of RFC 4918's core, `LOCK` and `UNLOCK` included — see
/// [`dav_header`] for why those two are what let the claim become `1, 2`, and
/// [`crate::dav::lock`] for why the lock they take is a real one.
pub const IMPLEMENTED: [Verb; 12] = [
    Verb::Options,
    Verb::PropFind,
    Verb::PropPatch,
    Verb::MkCol,
    Verb::Get,
    Verb::Head,
    Verb::Put,
    Verb::Delete,
    Verb::Copy,
    Verb::Move,
    Verb::Lock,
    Verb::Unlock,
];

/// Whether this build answers a verb.
pub fn implemented(verb: Verb) -> bool {
    IMPLEMENTED.contains(&verb)
}

/// The `Allow` header value, derived from [`IMPLEMENTED`].
pub fn allow_header() -> String {
    IMPLEMENTED.iter().map(|verb| verb.token()).collect::<Vec<_>>().join(", ")
}

/// The `DAV` compliance classes this build may honestly claim.
///
/// Class 1 is the property machinery and class 2 is locking. Claiming class 2
/// without a working `LOCK` is worse than not claiming it — the Windows
/// Mini-Redirector locks before every write, so the mount would succeed and the
/// first `PUT` would fail — so the claim is computed from [`IMPLEMENTED`]
/// rather than written down beside it, and it became `1, 2` in the same edit
/// that added `LOCK`, with no second place to remember.
pub fn dav_header() -> &'static str {
    if implemented(Verb::Lock) {
        "1, 2"
    } else {
        "1"
    }
}

/// The answer to `OPTIONS`, on a share root and on `/` alike.
///
/// Every header here earns its place:
///
/// - **`DAV`** is what makes a client treat the URL as a WebDAV resource at all.
///   Finder issues `OPTIONS` first and gives up without it.
/// - **`MS-Author-Via: DAV`** is what stops the Windows Mini-Redirector trying
///   FrontPage Server Extensions before WebDAV. Without it a Windows mount takes
///   an extra failed round trip and, on some builds, gives up entirely.
/// - **`Allow`** is derived from [`IMPLEMENTED`], so a client is never invited
///   to use a verb that will answer `405`.
/// - **`Accept-Ranges: bytes`** tells a client it may resume a download, which
///   is what makes a large file over a tunnel survivable.
///
/// `Content-Length: 0` is not set here: `Response::write_head` derives framing
/// from the body and would remove and re-add it. An empty body is a zero length,
/// in one place, which is the arrangement that cannot disagree with itself.
pub fn options() -> Response {
    build_options().unwrap_or_else(|_| Response::error_page(Status::INTERNAL_SERVER_ERROR))
}

/// The body of [`options`], with header failures surfaced rather than ignored.
///
/// Every value set below is a compile-time constant or derived from one, so none
/// can hold the CR, LF or NUL that `Headers::set` refuses. Returning the error
/// anyway keeps that reasoning from becoming a panic if it is ever wrong — under
/// `panic = "abort"` a panic in this process is the whole box.
fn build_options() -> Result<Response, HeaderError> {
    let mut response = Response::empty(Status::OK);
    response.headers.set("DAV", dav_header())?;
    response.headers.set("MS-Author-Via", "DAV")?;
    response.headers.set("Allow", allow_header())?;
    response.headers.set("Accept-Ranges", "bytes")?;
    Ok(response)
}

/// The answer to a verb this build does not implement, and to a token it does
/// not recognise.
///
/// The `Allow` header is the part that matters: `405` without it tells a client
/// only that it was wrong, and a WebDAV client that cannot discover the verb
/// list retries the same request.
pub fn not_allowed() -> Response {
    let mut response = Response::error_page(Status::METHOD_NOT_ALLOWED);
    if response.headers.set("Allow", allow_header()).is_err() {
        // Unreachable: the value is derived from compile-time tokens. A `405`
        // without the header is still a correct refusal, so the honest fallback
        // is to send it rather than to fail the request over a header.
        response.headers.remove("Allow");
    }
    response
}

/// The `GET`/`HEAD` answer for a file in a share.
///
/// This is [`crate::respond::blob`] with the disposition pinned, and the pinning
/// is the point. A WebDAV client never renders a file in a page — it saves it,
/// or it hands the bytes to an application — so the inline path buys nothing
/// here, and what it would cost is real: `/dav` is served from the console's own
/// origin, the origin that holds the session cookie for the thing that can
/// restart services. A file a caller uploaded and then persuaded a browser to
/// render inline on that origin is a stored cross-site scripting hole with the
/// console as its target. So there is no parameter to get wrong.
///
/// `total` and `modified` come from the caller's already-open handle rather than
/// from a fresh `stat`, for the reason [`crate::respond::blob`] gives: metadata
/// read separately from the bytes describes a different file than the one the
/// body will carry.
pub fn blob(
    request: &Request,
    name: &str,
    total: u64,
    modified: Option<SystemTime>,
) -> BlobResponse {
    respond::blob(request, name, total, modified, Disposition::Attachment)
}

// ---------------------------------------------------------------------------
// The statuses the write verbs answer with.
//
// `selfhost_http::Status` has constants for the codes the proxy and the console
// use; these belong to WebDAV alone, and they are spelled here for the reason
// `multistatus::MULTI_STATUS` is spelled there. The wire consequence is a
// reason phrase of `Unknown`, which RFC 9110 §15 makes advisory and which every
// WebDAV client ignores in favour of the number — but the honest fix is a
// larger table in `crates/http`, recorded as owed rather than worked around a
// third time.
// ---------------------------------------------------------------------------

/// The resource did not exist and now does: a `PUT` to a free name, a `MKCOL`,
/// a `COPY` or `MOVE` onto a free destination.
pub const CREATED: Status = Status(201);

/// It worked and there is nothing to say: an overwrite, a `DELETE`, an
/// `UNLOCK`.
pub const NO_CONTENT: Status = Status(204);

/// The request cannot be performed in the state the resource is in — most often
/// a `PUT` or `MKCOL` whose parent collection does not exist. RFC 4918 §9.3.1
/// is explicit that a missing intermediate collection is `409` rather than
/// `404`: the *request* is fine, the tree is not.
pub const CONFLICT: Status = Status(409);

/// A condition the client stated was not met: `Overwrite: F` onto an occupied
/// destination, or an `If` header whose token nobody holds.
pub const PRECONDITION_FAILED: Status = Status(412);

/// A body of a kind this verb does not accept — a `MKCOL` carrying one, which
/// RFC 4918 §9.3 requires to be refused rather than ignored.
pub const UNSUPPORTED_MEDIA_TYPE: Status = Status(415);

/// The resource is locked by somebody who did not submit their token.
pub const LOCKED: Status = Status(423);

/// The quota, the volume, or the free-space floor refused the write.
pub const INSUFFICIENT_STORAGE: Status = Status(507);

/// Whether a `Destination` may replace something that is already there.
///
/// RFC 4918 §10.6: absent means `T`. That default is worth stating because it
/// is the dangerous one — a client that forgets the header gets the
/// destructive behaviour — and because it is the reason
/// [`crate::fs::Dir::rename_into`] refuses an occupied destination on its own
/// rather than trusting a caller to have read this header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overwrite {
    /// Replace whatever is at the destination.
    Allowed,
    /// Fail with [`PRECONDITION_FAILED`] if anything is there.
    Refused,
}

/// Reads the `Overwrite` header.
///
/// `None` for a value that is neither `T` nor `F`, which is a `400`: guessing
/// at a third spelling means guessing whether the client meant to destroy
/// something.
pub fn overwrite(header: Option<&str>) -> Option<Overwrite> {
    match header.map(str::trim) {
        None => Some(Overwrite::Allowed),
        Some(value) if value.eq_ignore_ascii_case("T") => Some(Overwrite::Allowed),
        Some(value) if value.eq_ignore_ascii_case("F") => Some(Overwrite::Refused),
        Some(_) => None,
    }
}

/// Where a `COPY` or `MOVE` says its result should go.
///
/// Split into the share it names and the path within that share, still
/// percent-encoded, because those are two different decisions made by two
/// different pieces of code: the share is looked up in
/// [`crate::share::Shares`] and checked for its own read-only flag and its own
/// grants, and the path goes through [`crate::path::resolve`] against *that
/// share's* root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    /// The share segment, exactly as it appeared. Not decoded: a share id is
    /// `[a-z0-9-]` by [`crate::share::ShareId::parse`], so an encoded spelling
    /// simply fails to match any share and is answered as an unknown share —
    /// which is the safe direction, and cheaper than a second decoder.
    pub share: String,
    /// The path inside that share, leading slash included, **still encoded**.
    /// Handing this to [`crate::path::resolve`] is not optional; it is the same
    /// attacker-controlled text the request line carries.
    pub path: String,
}

/// Why a `Destination` header could not be used.
///
/// Typed because the three answers differ on the wire: a malformed header is `400`,
/// a destination on another server is `502` (RFC 4918 §9.8.3 says so), and a
/// destination outside the WebDAV mount is `400` rather than a redirect, since
/// a client asking us to move a file into `/etc` is not asking for something we
/// should help it spell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadDestination {
    /// The header is absent, and `COPY`/`MOVE` require it.
    Missing,
    /// It did not parse as a URI at all, or it named no path.
    Malformed,
    /// Its authority is not this server's.
    ForeignHost,
    /// Its path does not lie under the WebDAV mount.
    OutsideMount,
}

impl fmt::Display for BadDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::Missing => "this method requires a Destination header",
            Self::Malformed => "the Destination header is not a usable URI",
            Self::ForeignHost => "the Destination names another server",
            Self::OutsideMount => "the Destination is not inside the WebDAV mount",
        };
        f.write_str(reason)
    }
}

impl std::error::Error for BadDestination {}

impl BadDestination {
    /// The status this refusal is answered with.
    pub fn status(self) -> Status {
        match self {
            Self::ForeignHost => Status::BAD_GATEWAY,
            Self::Missing | Self::Malformed | Self::OutsideMount => Status::BAD_REQUEST,
        }
    }
}

/// Reads a `Destination` header.
///
/// **This is a second, entirely separate parsing surface from the request
/// line**, and it is the asymmetry that produces traversal holes: the request
/// path arrives as a path and the destination arrives as a full URI, so a
/// server that hardened one and hand-rolled the other has hardened half of its
/// write path. Everything here exists to funnel the two back into the same
/// resolver.
///
/// The steps, in order, each of which is a refusal somebody has exploited on
/// some server:
///
/// 1. **Cut the query and the fragment.** Neither is part of a WebDAV path, and
///    a `?` is how `/dav/vault/x?/../../etc` gets past a prefix check that runs
///    after a naive split.
/// 2. **Strip a scheme and authority if present, and check the host.**
///    `expected_host` is the console site's configured hostname — the same
///    value the passkey relying-party id comes from, and for the same reason:
///    the relay forwards no `Host`, so a host taken from the request would be
///    the client's own claim. A mismatch is `502`, which is what RFC 4918
///    §9.8.3 asks for and what tells a client to do the copy itself.
/// 3. **Require the `/dav/` prefix, exactly.** Not case-insensitively: the
///    mount point is ours, we spell it in lower case, and a client that spells
///    it `/DAV/` is not one of the four real clients.
/// 4. **Take one segment as the share id and leave the rest alone.** The
///    remainder is *not* decoded here and *not* cleaned here. It is handed to
///    [`crate::path::resolve`] exactly as the request line's path is, because
///    the whole point is that there is one resolver and both surfaces reach it.
///
/// What is deliberately **not** done here is any kind of `..` handling. A
/// destination of `/dav/vault/../../etc/passwd` parses cleanly at this layer
/// and is refused by the resolver with [`crate::path::Refusal::Traversal`],
/// which is where every other traversal in this crate is refused. Two places
/// that both remove `..` is two places that can disagree about what `..` is.
pub fn destination(header: Option<&str>, expected_host: Option<&str>) -> Result<Destination, BadDestination> {
    let raw = header.map(str::trim).filter(|value| !value.is_empty()).ok_or(BadDestination::Missing)?;

    // 1. Query and fragment go first, before anything looks at the path.
    let without_query = raw.split(['?', '#']).next().unwrap_or_default();

    // 2. Scheme and authority.
    let path = match without_query.find("://") {
        None => without_query,
        Some(scheme_end) => {
            let after_scheme = without_query.get(scheme_end + 3..).ok_or(BadDestination::Malformed)?;
            let (authority, rest) = match after_scheme.find('/') {
                Some(slash) => after_scheme.split_at(slash),
                // `https://host` with no path names the server root, which is
                // not inside the mount.
                None => (after_scheme, ""),
            };
            if let Some(expected) = expected_host {
                let host = authority.rsplit('@').next().unwrap_or(authority);
                let host = host.split(':').next().unwrap_or(host);
                if !host.eq_ignore_ascii_case(expected) {
                    return Err(BadDestination::ForeignHost);
                }
            }
            rest
        }
    };

    // A protocol-relative `//host/dav/...` is an authority, not a path, and
    // treating it as one is how a check for a leading `/dav/` gets fooled.
    if path.starts_with("//") || !path.starts_with('/') {
        return Err(BadDestination::Malformed);
    }

    // 3. The mount prefix.
    let inside = path.strip_prefix(DAV_ROOT).ok_or(BadDestination::OutsideMount)?;
    let inside = inside.strip_prefix('/').ok_or(BadDestination::OutsideMount)?;

    // 4. One segment for the share, everything else for the resolver.
    let (share, rest) = match inside.find('/') {
        Some(slash) => inside.split_at(slash),
        None => (inside, ""),
    };
    if share.is_empty() {
        return Err(BadDestination::OutsideMount);
    }
    let mut path = String::with_capacity(rest.len() + 1);
    if rest.is_empty() {
        path.push('/');
    } else {
        path.push_str(rest);
    }
    Ok(Destination { share: share.to_string(), path })
}

/// The largest `PROPPATCH` body that will be read.
///
/// The same cap `PROPFIND` uses, for the same reason: the body is a small
/// document from a client and anything larger is a bug or a plan.
pub const MAX_PROPPATCH_BODY_BYTES: usize = 64 * 1024;

/// The answer to `PROPPATCH`: a `207` saying, per property, that it was not
/// written.
///
/// # Why this refuses rather than pretends
///
/// Windows Explorer issues a `PROPPATCH` after every `PUT`, setting
/// `Z:Win32LastModifiedTime` and friends so a copied file keeps its timestamps.
/// This server has nowhere to put a dead property — there is no property store,
/// and inventing one would be a second database beside the filesystem — and it
/// does not apply the Win32 times either, because doing that needs a
/// `utimensat`/`SetFileTime` this crate has no other use for.
///
/// So each property is answered `403`. The known cost, recorded rather than
/// discovered: Explorer may report that some attributes could not be copied,
/// while the file itself copies correctly. The alternative is to answer `200`
/// to a property we did not store, which is a server telling a client that a
/// timestamp was preserved when it was not — and this project does not make
/// that trade anywhere else either. **Confirm the exact Explorer behaviour on
/// ALEX-DESKTOP**; it is the one client whose reaction cannot be tested from
/// this machine.
///
/// A body that does not parse is answered `403` whole, rather than `400`: the
/// client asked to change properties and none were changed, which is the true
/// statement either way.
///
/// # Why the `href` is a type and not a `&str`
///
/// [`Href`] exists because a stored name rendered into a URL without the encoder
/// is a URL that names a *different* resource: a directory can hold `a%2fb`,
/// whose own text in a URL asks for `a/b` one directory down. That rule was
/// enforced by there being no way to build an [`Href`] from a `String` — and
/// then this function took a `&str` and put it in a `<D:href>` unencoded, which
/// is the same hole with the type standing next to it. A caller now has one way
/// to name a resource here, and it is [`crate::dav::multistatus::Mount::href`].
pub fn proppatch(href: &Href, body: &[u8]) -> Response {
    let names = requested_properties(body);
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">\n<D:response>\n<D:href>",
    );
    xml.push_str(&escape(href.as_str()));
    xml.push_str("</D:href>\n<D:propstat>\n<D:prop>\n");
    for name in &names {
        // The element name is written into the body, so only names this scanner
        // accepted as a plain NCName reach here — a "name" holding `>` would end
        // the element early and let a client's request shape our answer.
        xml.push('<');
        xml.push_str(name);
        xml.push_str("/>\n");
    }
    xml.push_str("</D:prop>\n<D:status>HTTP/1.1 ");
    xml.push_str(&Status::FORBIDDEN.to_string());
    xml.push_str("</D:status>\n</D:propstat>\n</D:response>\n</D:multistatus>\n");
    or_internal_error(Response::bytes(MULTI_STATUS, XML_TYPE, xml.into_bytes()))
}

/// The property names a `PROPPATCH` body asks to change.
///
/// A deliberately small scanner rather than a general XML reader, for the
/// reason [`crate::dav::propfind`] gives at length: a parser fed by strangers
/// costs the whole process under `panic = "abort"`, so this one has no
/// recursion, no entity handling, and a hard cap on how much it will read.
///
/// Only the local name is kept, and only if it is a plain ASCII NCName — the
/// same narrow rule [`crate::dav::multistatus::PropertyName::new`] applies, and
/// for the same reason: these names are written back into a document as element
/// names.
fn requested_properties(body: &[u8]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(body) else {
        return Vec::new();
    };
    if text.len() > MAX_PROPPATCH_BODY_BYTES || text.to_ascii_lowercase().contains("<!doctype") {
        return Vec::new();
    }

    let mut names = Vec::new();
    let mut inside_prop = false;
    let mut rest = text;
    while let Some(open) = rest.find('<') {
        let Some(after) = rest.get(open + 1..) else {
            break;
        };
        let Some(close) = after.find('>') else {
            break;
        };
        let Some(tag) = after.get(..close) else {
            break;
        };
        rest = after.get(close + 1..).unwrap_or_default();

        let closing = tag.starts_with('/');
        let bare = tag.strip_prefix('/').unwrap_or(tag);
        if bare.starts_with('!') || bare.starts_with('?') {
            continue;
        }
        let head = bare.split([' ', '\t', '\r', '\n', '/']).next().unwrap_or_default();
        let local = head.rsplit(':').next().unwrap_or(head);
        if local == "prop" {
            inside_prop = !closing;
            continue;
        }
        if inside_prop && !closing && is_ncname(local) && !names.iter().any(|seen| seen == local) {
            names.push(local.to_string());
        }
    }
    names
}

/// Whether a local name is a plain ASCII name safe to write as an element.
///
/// Narrower than XML's `NCName` on purpose: every property any real client asks
/// for is inside this set, and a narrow rule needs no Unicode tables to be sure
/// of.
fn is_ncname(local: &str) -> bool {
    let mut characters = local.chars();
    let first_is_legal = matches!(characters.next(), Some(c) if c.is_ascii_alphabetic() || c == '_');
    first_is_legal
        && characters.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// An empty response with a status and nothing else.
///
/// The shape of most write-verb answers: `201`, `204`, `409`, `412`, `423`.
/// A body would be ignored by every WebDAV client, and `Response::error_page`'s
/// HTML would be a page nobody looks at attached to a protocol response.
pub fn status_only(status: Status) -> Response {
    Response::empty(status)
}

/// The `201` a `PUT`, `MKCOL`, `COPY` or `MOVE` sends when it created
/// something, carrying the location it created.
///
/// The `Location` header is not decoration on a `201`: RFC 9110 §15.3.2 defines
/// it as where the new resource lives, and a client that has just copied a file
/// uses it rather than re-deriving the URL from the request it sent. Which is
/// exactly why it takes an [`Href`] rather than a `&str` — see [`proppatch`] for
/// the hole that spelling left, and note that a client *follows* this one.
pub fn created(location: &Href) -> Response {
    let mut response = Response::empty(CREATED);
    if response.headers.set("Location", location.as_str()).is_err() {
        // Unreachable: an `href` is percent-encoded ASCII and cannot hold a CR,
        // an LF or a NUL. A `201` without the header is still a correct answer,
        // so the honest fallback is to send it.
        response.headers.remove("Location");
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dav::multistatus::Mount;
    use crate::listing::Kind;
    use crate::path::RelativePath;
    use crate::share::ShareId;
    use selfhost_http::{Body, Headers};

    /// The `href` for a name in the `vault` share, built the one way there is.
    fn href(name: &str, kind: Kind) -> Href {
        let share = ShareId::parse("vault").expect("a legal share id");
        let path = RelativePath::default().join(name).expect("a legal name");
        Mount::for_share(&share).href(&path, kind)
    }

    fn request(method: &str, target: &str) -> Request {
        Request {
            method: Method::parse(method),
            target: target.to_string(),
            minor_version: 1,
            headers: Headers::new(),
        }
    }

    #[test]
    fn every_webdav_verb_is_recognised_and_nothing_else_is() {
        for (token, verb) in [
            ("OPTIONS", Verb::Options),
            ("PROPFIND", Verb::PropFind),
            ("PROPPATCH", Verb::PropPatch),
            ("MKCOL", Verb::MkCol),
            ("GET", Verb::Get),
            ("HEAD", Verb::Head),
            ("PUT", Verb::Put),
            ("DELETE", Verb::Delete),
            ("COPY", Verb::Copy),
            ("MOVE", Verb::Move),
            ("LOCK", Verb::Lock),
            ("UNLOCK", Verb::Unlock),
        ] {
            assert_eq!(Verb::classify(&Method::parse(token)), Some(verb), "{token}");
        }

        // Everything else is a 405, including the ordinary HTTP verbs a share
        // has no use for and anything a prober invents.
        for token in ["POST", "PATCH", "TRACE", "CONNECT", "BREW", "propfind", "GETS", ""] {
            assert_eq!(Verb::classify(&Method::parse(token)), None, "{token}");
        }
    }

    #[test]
    fn a_verb_knows_whether_it_writes() {
        for verb in [Verb::Options, Verb::PropFind, Verb::Get, Verb::Head] {
            assert!(!verb.writes(), "{}", verb.token());
        }
        for verb in [
            Verb::PropPatch,
            Verb::MkCol,
            Verb::Put,
            Verb::Delete,
            Verb::Copy,
            Verb::Move,
            Verb::Lock,
            Verb::Unlock,
        ] {
            assert!(verb.writes(), "{}", verb.token());
        }
    }

    /// The claim and the code are one list, and this is the assertion that says
    /// so: a `DAV: 1, 2` may appear only when `LOCK` is answered.
    #[test]
    fn the_compliance_class_cannot_outrun_the_implementation() {
        assert_eq!(implemented(Verb::Lock), dav_header() == "1, 2");
        assert!(implemented(Verb::Lock), "this build answers LOCK, so it may claim class 2");
        assert_eq!(dav_header(), "1, 2");

        for verb in IMPLEMENTED {
            assert!(allow_header().contains(verb.token()), "{}", verb.token());
        }
        // And a token that is not a WebDAV verb is not on the list. Compared
        // token by token rather than as a substring, because `PROPPATCH`
        // contains `PATCH` and a substring test would have passed by accident.
        let advertised = allow_header();
        let tokens: Vec<&str> = advertised.split(", ").collect();
        for absent in ["POST", "PATCH", "TRACE", "CONNECT", "BREW"] {
            assert!(!tokens.contains(&absent), "{absent}");
        }
        assert_eq!(tokens.len(), IMPLEMENTED.len());
    }

    #[test]
    fn options_carries_everything_a_client_needs_to_mount() {
        let response = options();
        assert_eq!(response.status, Status::OK);
        assert_eq!(response.headers.get_str("dav"), Some("1, 2"));
        assert_eq!(response.headers.get_str("ms-author-via"), Some("DAV"));
        assert_eq!(response.headers.get_str("allow"), Some(allow_header().as_str()));
        for verb in ["OPTIONS", "PROPFIND", "GET", "HEAD", "PUT", "MKCOL", "LOCK"] {
            assert!(allow_header().contains(verb), "{verb}");
        }
        assert_eq!(response.headers.get_str("accept-ranges"), Some("bytes"));
        assert!(response.body.is_empty());

        // The framing layer writes the zero length, so a `Content-Length` set
        // here would be removed and re-derived — one place, no disagreement.
        let mut head = Vec::new();
        response.write_head(&mut head, true).expect("a writable head");
        assert!(String::from_utf8_lossy(&head).contains("Content-Length: 0"));
    }

    #[test]
    fn a_verb_this_build_does_not_answer_is_405_with_the_list_that_would_work() {
        let response = not_allowed();
        assert_eq!(response.status, Status::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers.get_str("allow"), Some(allow_header().as_str()));
    }

    #[test]
    fn the_overwrite_default_is_the_dangerous_one_and_is_stated_out_loud() {
        assert_eq!(overwrite(None), Some(Overwrite::Allowed));
        assert_eq!(overwrite(Some("T")), Some(Overwrite::Allowed));
        assert_eq!(overwrite(Some("t")), Some(Overwrite::Allowed));
        assert_eq!(overwrite(Some(" F ")), Some(Overwrite::Refused));
        // A third spelling is a 400 rather than a guess, because guessing means
        // guessing whether the client meant to destroy something.
        for nonsense in ["", "yes", "true", "0", "TF"] {
            assert_eq!(overwrite(Some(nonsense)), None, "{nonsense}");
        }
    }

    #[test]
    fn a_destination_is_split_into_the_share_and_the_path_the_resolver_gets() {
        let parsed = destination(Some("/dav/vault/photos/a.txt"), None).expect("a local path");
        assert_eq!(parsed.share, "vault");
        assert_eq!(parsed.path, "/photos/a.txt");

        // A full URI, which is what every real client actually sends.
        let full = destination(Some("https://admin.example/dav/vault/a.txt"), Some("admin.example"))
            .expect("a full URI");
        assert_eq!(full, Destination { share: "vault".into(), path: "/a.txt".into() });

        // A port and userinfo do not change the host.
        assert!(destination(Some("https://u@admin.example:443/dav/vault/a"), Some("admin.example"))
            .is_ok());

        // The share root, with and without its trailing slash, is the root.
        assert_eq!(destination(Some("/dav/vault"), None).expect("root").path, "/");
        assert_eq!(destination(Some("/dav/vault/"), None).expect("root").path, "/");

        // A cross-share destination parses; whether it is *allowed* is the
        // route's decision, against the target share's own flag and grants.
        assert_eq!(destination(Some("/dav/photos/a"), None).expect("other share").share, "photos");
    }

    /// The header the whole module exists to distrust. Every one of these is a
    /// write-anywhere primitive on a server that parsed it by hand.
    #[test]
    fn a_destination_that_leaves_the_mount_or_the_host_is_refused() {
        for (header, expected) in [
            // Not under the mount at all.
            ("/etc/passwd", BadDestination::OutsideMount),
            ("/davs/vault/a", BadDestination::OutsideMount),
            ("/DAV/vault/a", BadDestination::OutsideMount),
            ("/dav", BadDestination::OutsideMount),
            ("/dav/", BadDestination::OutsideMount),
            // An authority where a path was expected: `//host/dav/...` is a
            // protocol-relative URI, and reading it as a path is how a prefix
            // check gets fooled into thinking `host` is the share.
            ("//evil.example/dav/vault/a", BadDestination::Malformed),
            // Not a path at all.
            ("dav/vault/a", BadDestination::Malformed),
            ("https://admin.example", BadDestination::Malformed),
        ] {
            assert_eq!(
                destination(Some(header), Some("admin.example")),
                Err(expected),
                "{header}"
            );
        }

        assert_eq!(destination(None, None), Err(BadDestination::Missing));
        assert_eq!(destination(Some("   "), None), Err(BadDestination::Missing));

        // Another server is a 502 and not a 400, because RFC 4918 §9.8.3 asks
        // us to tell the client to do the copy itself.
        assert_eq!(
            destination(Some("https://evil.example/dav/vault/a"), Some("admin.example")),
            Err(BadDestination::ForeignHost)
        );
        assert_eq!(BadDestination::ForeignHost.status(), Status::BAD_GATEWAY);
        assert_eq!(BadDestination::OutsideMount.status(), Status::BAD_REQUEST);
    }

    /// Traversal is **not** handled here, deliberately: it is handed to the one
    /// resolver that refuses it, so the two surfaces cannot come to disagree
    /// about what `..` is. This test asserts the handoff rather than a second
    /// opinion.
    #[test]
    fn a_traversing_destination_is_left_for_the_one_resolver_that_refuses_it() {
        for hostile in [
            "/dav/vault/../../etc/passwd",
            "/dav/vault/%2e%2e/%2e%2e/etc/passwd",
            "/dav/vault/..%20/secret",
            "/dav/vault/a/..\\..\\windows\\system32",
            "/dav/vault/readme.txt:evil",
            "/dav/vault/CON.txt",
        ] {
            let parsed = destination(Some(hostile), None).expect("it parses at this layer");
            assert_eq!(parsed.share, "vault");
            // And the resolver refuses every one of them against a real root.
            assert!(
                crate::path::resolve(std::path::Path::new("/srv/vault"), &parsed.path).is_err(),
                "{hostile}"
            );
        }

        // The query and the fragment are cut before any of that, so they cannot
        // smuggle a second path past a prefix check.
        let with_query = destination(Some("/dav/vault/a?x=/../../etc"), None).expect("parsed");
        assert_eq!(with_query.path, "/a");
        let with_fragment = destination(Some("/dav/vault/a#/../../etc"), None).expect("parsed");
        assert_eq!(with_fragment.path, "/a");
    }

    /// Explorer's post-`PUT` `PROPPATCH` is answered honestly: a `207` in which
    /// each property is `403`, rather than a `200` for a value we did not store.
    #[test]
    fn a_proppatch_refuses_each_property_by_name_rather_than_pretending() {
        let body = br#"<?xml version="1.0"?>
            <D:propertyupdate xmlns:D="DAV:" xmlns:Z="urn:schemas-microsoft-com:">
              <D:set><D:prop>
                <Z:Win32LastModifiedTime>Mon, 02 Feb 2026 02:40:00 GMT</Z:Win32LastModifiedTime>
                <Z:Win32FileAttributes>00000020</Z:Win32FileAttributes>
              </D:prop></D:set>
            </D:propertyupdate>"#;
        let response = proppatch(&href("a.txt", Kind::File), body);
        assert_eq!(response.status, MULTI_STATUS);
        let rendered = match &response.body {
            Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            other => panic!("expected an in-memory body, got {other:?}"),
        };
        assert!(rendered.contains("<D:href>/dav/vault/a.txt</D:href>"));
        assert!(rendered.contains("<Win32LastModifiedTime/>"));
        assert!(rendered.contains("<Win32FileAttributes/>"));
        assert!(rendered.contains("<D:status>HTTP/1.1 403 Forbidden</D:status>"));
        // Never a 200 for something that was not written.
        assert!(!rendered.contains("200 OK"));
    }

    /// The body is attacker-controlled and the names in it are written back as
    /// element names, so a "name" that would break out of its own element is
    /// dropped rather than rendered.
    #[test]
    fn a_proppatch_never_lets_a_request_shape_the_answers_markup() {
        let hostile = br#"<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>
            <bad><script>alert(1)</script></bad>
            <ok/>
            </D:prop></D:set></D:propertyupdate>"#;
        let rendered = match &proppatch(&href("a", Kind::File), hostile).body {
            Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            other => panic!("expected an in-memory body, got {other:?}"),
        };
        assert!(rendered.contains("<ok/>"));
        // The nested elements are names too, and they are refused as properties
        // rather than reproduced as markup with their content.
        assert!(!rendered.contains("alert(1)"));

        // A document type declaration, an unreadable body and a body that names
        // nothing all answer the same way: a 207 that changed nothing.
        for body in [
            b"<!DOCTYPE x [<!ENTITY a \"a\">]><D:propertyupdate/>".as_slice(),
            &[0xff, 0xfe],
            b"",
        ] {
            let response = proppatch(&href("a", Kind::File), body);
            assert_eq!(response.status, MULTI_STATUS);
        }

        // And a body larger than the cap is not scanned at all.
        let huge = vec![b'<'; MAX_PROPPATCH_BODY_BYTES + 1];
        assert_eq!(proppatch(&href("a", Kind::File), &huge).status, MULTI_STATUS);
    }

    /// Neither answer can name a resource the encoder has not seen, because
    /// neither will take a string.
    ///
    /// A directory may hold `a%2fb`, and that name spelled straight into a URL
    /// asks for `a/b` one directory down — a different resource, which is the
    /// whole reason [`Href`] has no constructor from text. These two functions
    /// used to take `&str` and hand it out unencoded, so the guarantee was a
    /// type sitting beside the hole rather than closing it.
    #[test]
    fn the_two_answers_that_carry_a_url_can_only_be_given_an_encoded_one() {
        let hostile = href("a%2fb", Kind::File);
        assert_eq!(hostile.as_str(), "/dav/vault/a%252fb");

        let rendered = match &proppatch(&hostile, b"").body {
            Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            other => panic!("expected an in-memory body, got {other:?}"),
        };
        assert!(rendered.contains("<D:href>/dav/vault/a%252fb</D:href>"), "{rendered}");

        // And it round-trips: the URL a client follows resolves back to the name
        // it was rendered from, rather than to a file one directory down.
        let inside = hostile.as_str().strip_prefix("/dav/vault").expect("its own mount");
        let resolved =
            crate::path::resolve(std::path::Path::new("/srv/vault"), inside).expect("resolves");
        assert_eq!(resolved.relative().segments(), ["a%2fb"]);

        assert_eq!(created(&hostile).headers.get_str("location"), Some("/dav/vault/a%252fb"));
    }

    #[test]
    fn a_created_response_says_where_the_thing_it_made_is() {
        let response = created(&href("a.txt", Kind::File));
        assert_eq!(response.status, CREATED);
        assert_eq!(response.headers.get_str("location"), Some("/dav/vault/a.txt"));
        assert!(response.body.is_empty());

        // The empty answers carry nothing at all, which is what a protocol
        // client wants and what `204` requires.
        for status in [NO_CONTENT, CONFLICT, PRECONDITION_FAILED, LOCKED] {
            let response = status_only(status);
            assert_eq!(response.status, status);
            assert!(response.body.is_empty());
        }
        assert!(NO_CONTENT.forbids_body(), "a 204 may never carry one");
    }

    /// A WebDAV `GET` is always a download, and the type is always opaque.
    #[test]
    fn a_dav_get_never_offers_a_browser_something_to_render() {
        // A name that the inline path would happily serve as an image if the
        // disposition were the caller's to choose.
        let built = blob(&request("GET", "/dav/vault/photo.png"), "photo.png", 9, None);
        assert_eq!(built.response.status, Status::OK);
        assert_eq!(
            built.response.headers.get_str("content-type"),
            Some(crate::respond::OPAQUE_TYPE)
        );
        assert!(
            built
                .response
                .headers
                .get_str("content-disposition")
                .is_some_and(|value| value.starts_with("attachment;")),
            "a WebDAV GET is a download"
        );
        assert!(matches!(built.response.body, Body::Streamed(9)));
        assert_eq!(built.length, 9);

        // And a HEAD gets the same head with none of the bytes.
        let head = blob(&request("HEAD", "/dav/vault/photo.png"), "photo.png", 9, None);
        assert_eq!(head.length, 0);
        assert!(matches!(head.response.body, Body::Streamed(9)));
    }
}
