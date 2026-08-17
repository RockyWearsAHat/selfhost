//! The WebDAV path on the console site: which verbs this proxy will carry,
//! which fields travel with them, and which bodies are streamed rather than
//! held.
//!
//! Everything here is a pure decision over a head some other layer already
//! parsed — the same discipline [`crate::upgrade`] follows, and for the same
//! reason. The proxy owns ports 80 and 443 for every site on the box, the mail
//! transport and the certificate store, and the workspace sets `panic = "abort"`
//! for release, so a parser that runs in this process is a parser that can end
//! all of it at once. **No XML is parsed here. No path is resolved here. No
//! `Destination` URL is interpreted here.** Those belong to `crates/storage`,
//! behind loopback, where a malformed document costs one request.
//!
//! # Why a WebDAV mount needs the proxy to change at all
//!
//! The console relay was written for a browser talking JSON: a handful of
//! methods, small bodies, and a header allow-list narrow enough to read in one
//! line. A file share is none of those things. Finder and the Windows
//! Mini-Redirector speak verbs this relay has never seen, carry their state in
//! fields it has never forwarded, and move gigabytes in a single request. Each
//! of the three is handled deliberately below, because the lazy answer to each
//! — forward every method, forward every header, buffer every body — is a
//! different way to hand a stranger the process.
//!
//! ## Verbs: a closed allow-list, never a fallthrough
//!
//! [`VERBS`] is exhaustive and matched before anything else runs. A token
//! outside it is answered `405` with an `Allow` field naming what this path does
//! speak; it never reaches the loopback connection. The alternative — relay
//! whatever token arrived and let the admin API sort it out — makes the proxy a
//! general-purpose method tunnel into the one process on this box that can
//! deploy code, and makes every future admin route reachable by a verb nobody
//! considered when writing it.
//!
//! ## Fields: widened by exactly what the protocol needs
//!
//! [`RELAYED_FOR_DAV`] is the ordinary console allow-list plus the fields
//! WebDAV's verbs are made of. `Destination` and `If` are the load-bearing two:
//! without `Destination` there is no COPY and no MOVE, and without `If` there
//! is no lock token on a write, which on Windows means no writes at all. Both
//! are relayed **verbatim and uninterpreted** — see [`RELAYED_FOR_DAV`] for why
//! that is the safe direction and not the lazy one.
//!
//! ## What this costs, said rather than hidden
//!
//! A relayed answer is copied verbatim until the admin API closes, so a WebDAV
//! request costs one connection — and over HTTPS, one TLS handshake. That is
//! the crate's existing rule (see the module note on `crate::server`) and this
//! path inherits it rather than inventing an exception, but a file client
//! reaches for it far harder than a browser did: a Finder window copying five
//! hundred files is five hundred handshakes. Reusing the connection means
//! parsing the upstream's response framing here, which is the roadmap item that
//! rule is waiting on; doing it early, on the path that carries file bytes,
//! would be the worst possible place to get it wrong.
//!
//! ## Bodies: streamed, always, without exception
//!
//! No WebDAV request body is ever held in this process. The ordinary console
//! relay buffers, which is right for a 2 KiB JSON post and catastrophic for a
//! file: `take_body` does `Vec::with_capacity(declared_length)`, so a header
//! reading `Content-Length: 107374182400` is a 100 GiB allocation attempt, and
//! under `panic = "abort"` a failed allocation is not an error a caller sees —
//! it is the whole box going down, from one line of a request head, before a
//! single byte of that body has arrived. [`BodyPolicy`] therefore classifies
//! every verb, and the relay streams all three classes; the declared length is
//! used to *bound* the copy, never to size a buffer.

use selfhost_http::{Headers, Method};

/// The path prefix the console site reserves for WebDAV.
///
/// `/dav/{share}/{path…}` — the share name is the first segment so that one
/// mount point can expose several shares and so the admin API can apply a
/// share's own permissions before it has looked at a single path component.
///
/// Named here rather than spelled inline at the routing decision because two
/// places must agree about it forever: this proxy, which routes it, and the
/// access log, which withholds everything after it.
pub const PREFIX: &str = "/dav/";

/// The mount root itself, without a share.
///
/// Reserved alongside [`PREFIX`] because a client asks about the root before it
/// asks about a share: `OPTIONS /dav` is how a WebDAV client discovers that
/// there is a WebDAV server here at all and which compliance classes it
/// implements. Answering that from the SPA's static handler — which knows only
/// `GET` and `HEAD` — would tell every client that this is not a share.
pub const ROOT: &str = "/dav";

/// Whether a console site's path belongs to the WebDAV mount.
///
/// The root itself and anything beneath it, and nothing else: `/davos` is an
/// ordinary SPA path and stays one, exactly as `/apidocs` is not `/api`.
pub fn is_dav_path(path: &str) -> bool {
    path == ROOT || path.starts_with(PREFIX)
}

/// Every method token this proxy will carry to the WebDAV mount.
///
/// A closed list, matched exactly and case-sensitively — HTTP method tokens are
/// case-sensitive, so `propfind` is not `PROPFIND` and is refused. Anything
/// outside this list is answered `405` before the loopback connection opens;
/// see the module note on why an unknown verb is never forwarded.
///
/// `POST`, `PATCH`, `TRACE` and `CONNECT` are absent on purpose. WebDAV defines
/// no meaning for the first two on a collection or a file, and the last two have
/// no business anywhere near a relay into a loopback API.
pub const VERBS: [&str; 12] = [
    "OPTIONS", "PROPFIND", "PROPPATCH", "MKCOL", "GET", "HEAD", "PUT", "DELETE", "COPY", "MOVE",
    "LOCK", "UNLOCK",
];

/// The value of the `Allow` field sent with a `405`.
///
/// Written out rather than joined from [`VERBS`] at run time, because it is a
/// constant on a refusal path and building it per request would be work done to
/// tell a caller it was wrong. A test asserts the two agree, so the pair cannot
/// drift.
pub const ALLOW: &str =
    "OPTIONS, PROPFIND, PROPPATCH, MKCOL, GET, HEAD, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK";

/// Whether this proxy will carry `method` to the WebDAV mount.
pub fn carries(method: &Method) -> bool {
    VERBS.iter().any(|verb| *verb == method.as_str())
}

/// The most characters of a method token that ever reach the access log.
///
/// The longest verb here is nine characters; anything approaching this is
/// already a token no allow-list will accept.
const LOGGED_METHOD_CHARS: usize = 24;

/// A method token, clipped to something safe to write into a log line.
///
/// A refused verb is worth logging — it is the one refusal an operator
/// debugging a mount will want to see — but the token is chosen by the caller
/// and bounded only by the size of the whole request head. The gate in front of
/// this is a *source address*, not an identity, and on this box "inside the
/// gate" includes every co-hosted web app, so echoing an unbounded token into
/// the log would hand any of them a disk-filling primitive costing one request
/// per kilobyte. The parser has already confined the token to
/// `[A-Za-z0-9_-]`, so what is clipped here is length and nothing else.
pub fn loggable_method(method: &Method) -> &str {
    let token = method.as_str();
    match token.char_indices().nth(LOGGED_METHOD_CHARS) {
        Some((boundary, _)) => &token[..boundary],
        None => token,
    }
}

/// The header fields relayed on a WebDAV request, over and above the ordinary
/// console set in [`crate::upgrade::RELAYED`].
///
/// Every entry is something a verb is *made of*, not something a client merely
/// volunteers:
///
/// - **`Destination`** — the target of a COPY or a MOVE. Without it neither verb
///   exists, so relaying it is not optional. It is also a full URL, which makes
///   it a second attacker-controlled path arriving in a second syntax, and the
///   temptation is to parse it here and refuse anything that looks wrong. That
///   is the wrong instinct twice over. A path check in the proxy would be a
///   *second* opinion about where a file lives, and the moment two parsers
///   disagree about one string, the one that is not enforcing is the one an
///   attacker aims at. And the proxy could not enforce it correctly even if it
///   tried: whether a destination is legal depends on the share root, the target
///   share's read-only flag and the caller's grants, none of which this process
///   knows. `crates/storage` resolves it through the same confining resolver the
///   request line goes through, which is where that check belongs and where it
///   already exists. The field is therefore relayed byte for byte. It cannot
///   inject a header line on the way: `selfhost_http` refuses CR, LF and NUL in
///   a field value at parse time, so what is relayed is one field's bytes.
/// - **`If`** — the lock tokens and entity tags a write is conditional on.
///   Dropping it turns every locked write into a `423 Locked`, which on Windows
///   means a share that mounts and then refuses every save.
/// - **`Depth`**, **`Overwrite`**, **`Lock-Token`**, **`Timeout`** — the
///   remaining arguments of PROPFIND, COPY/MOVE, UNLOCK and LOCK. Each is
///   compared by the daemon, never obeyed by the proxy.
/// - **`Range`** and the five conditional fields — the ordinary HTTP machinery a
///   streaming `GET` needs for resume and revalidation, which a file client uses
///   constantly and a JSON console never did.
/// - **`X-Expected-Entity-Length`** — macOS sends a zero-length `PUT` carrying
///   this field before it sends the file, so the server can refuse a copy that
///   will not fit. Dropping it does not break the mount; it moves the refusal
///   from "before the copy" to "after twenty minutes of copying".
///
/// What is *not* here is as deliberate. No `User-Agent`, no `Referer`, no
/// `Origin`, no framing field — the relay re-derives framing itself — and no
/// `Translate`, the Microsoft field that asks a server not to execute a resource
/// before returning it, because nothing on this path ever executes anything and
/// forwarding a field to be ignored only widens what a stranger can put in front
/// of the daemon's parser.
pub const RELAYED_FOR_DAV: [&str; 13] = [
    "destination",
    "if",
    "depth",
    "overwrite",
    "lock-token",
    "timeout",
    "range",
    "if-match",
    "if-none-match",
    "if-modified-since",
    "if-unmodified-since",
    "if-range",
    "x-expected-entity-length",
];

/// Whether a header field should be passed to the admin API on a WebDAV
/// request.
///
/// Composed from [`crate::upgrade::is_relayed`] rather than restating it: the
/// body's type and the caller's credentials are relayed on this path for exactly
/// the reasons they are relayed on `/api/*`, and a WebDAV mount authenticates
/// with `Authorization` on essentially every request, so a second copy of that
/// list that could fall behind would eventually be the one that drops it.
///
/// The upgrade widening is deliberately not reachable from here: a WebDAV
/// request is never a protocol handshake, so `false` is passed and stays passed.
pub fn is_relayed(name: &str) -> bool {
    crate::upgrade::is_relayed(name, false)
        || RELAYED_FOR_DAV.iter().any(|allowed| name.eq_ignore_ascii_case(allowed))
}

/// The first WebDAV control field that arrived more than once, if any.
///
/// Every field in [`RELAYED_FOR_DAV`] is single-valued: a request carries one
/// `Destination`, one `Depth`, one `If`. A head bearing two of any of them is
/// not a client being generous, it is a request built so that two readers might
/// choose differently — the same family of ambiguity `selfhost_http` already
/// refuses for a repeated `Content-Length`, arriving in a field that names a
/// *file to overwrite*. The proxy chooses neither and relays neither; it refuses
/// the request.
///
/// Returns the offending name so the refusal can be logged as something an
/// operator can act on rather than a bare `400`.
pub fn duplicated_control_field(headers: &Headers) -> Option<&'static str> {
    RELAYED_FOR_DAV.iter().copied().find(|name| headers.count(name) > 1)
}

/// What kind of request body a WebDAV verb may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyPolicy {
    /// The verb takes no request body.
    ///
    /// A declared non-empty body on one of these is refused rather than relayed
    /// with its length forced to zero: those bytes would otherwise sit unread on
    /// the client's connection and be parsed as the *next* request, which is
    /// request smuggling with the proxy as the willing half.
    Forbidden,
    /// A small XML document — a property list, a lock request, an extended
    /// `MKCOL`.
    ///
    /// Bounded by [`MAX_DOCUMENT_BODY`] and refused above it before the loopback
    /// connection opens, because nothing legitimate on this path is large and a
    /// document is a thing the daemon must hold in memory to parse.
    Document,
    /// File content, of whatever size the caller declared.
    ///
    /// Deliberately uncapped *here*. A NAS whose largest upload is a proxy
    /// constant is not a NAS, and the ceilings that actually belong to this —
    /// the share's quota, the volume's free-space floor, the count of concurrent
    /// uploads and the global in-flight byte total — are all facts about
    /// storage that this process does not have and must not start caching. It
    /// is streamed, so an enormous declared length costs nothing until the bytes
    /// genuinely arrive, and the admin API can refuse it after one look at the
    /// head while the transfer is still in its first kilobyte.
    Content,
}

/// The largest [`BodyPolicy::Document`] body relayed to the admin API.
///
/// 256 KiB is orders of magnitude above the largest realistic WebDAV document —
/// a `PROPFIND` naming every property Finder knows is a few hundred bytes — and
/// far below anything that could trouble the daemon. It is not the daemon's own
/// limit, which stays the daemon's business; it is the point past which this
/// proxy stops believing the request is a document at all.
pub const MAX_DOCUMENT_BODY: u64 = 256 * 1024;

/// Which body policy applies to a verb.
///
/// Only ever asked about a verb [`carries`] has already accepted. An unknown
/// token maps to [`BodyPolicy::Forbidden`] so that a future editor who moves
/// this call above the allow-list gets a refusal rather than an open relay, but
/// that ordering is not the one shipped and the allow-list is where an unknown
/// verb actually dies.
pub fn body_policy(method: &Method) -> BodyPolicy {
    match method.as_str() {
        "PUT" => BodyPolicy::Content,
        "PROPFIND" | "PROPPATCH" | "MKCOL" | "LOCK" => BodyPolicy::Document,
        _ => BodyPolicy::Forbidden,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_http::Request;

    /// Builds a request head from a method and extra field lines, so a test
    /// reads as the bytes a WebDAV client would actually send.
    fn head(method: &str, lines: &[&str]) -> Request {
        let mut raw = format!("{method} /dav/vault/notes.txt HTTP/1.1\r\nHost: console.example\r\n");
        for line in lines {
            raw.push_str(line);
            raw.push_str("\r\n");
        }
        raw.push_str("\r\n");
        Request::parse(raw.as_bytes()).expect("a well-formed head").request
    }

    #[test]
    fn the_mount_claims_its_root_and_everything_under_it_and_nothing_beside_it() {
        assert!(is_dav_path("/dav"));
        assert!(is_dav_path("/dav/"));
        assert!(is_dav_path("/dav/vault/tax/2019.pdf"));
        // The neighbouring-name trap `/apidocs` already taught this codebase.
        assert!(!is_dav_path("/davos"));
        assert!(!is_dav_path("/dav-share"));
        assert!(!is_dav_path("/"));
        assert!(!is_dav_path("/api/storage/blob/vault/x"));
    }

    #[test]
    fn every_verb_webdav_needs_is_carried_and_the_token_is_matched_exactly() {
        for verb in ["OPTIONS", "PROPFIND", "PROPPATCH", "MKCOL", "GET", "HEAD", "PUT", "DELETE",
                     "COPY", "MOVE", "LOCK", "UNLOCK"] {
            assert!(carries(&Method::parse(verb)), "{verb} must reach the share");
        }
        // Case is part of the token. A client sending `propfind` is not sending
        // PROPFIND, and guessing that it meant to would be the proxy inventing a
        // request nobody made.
        assert!(!carries(&Method::parse("propfind")));
        assert!(!carries(&Method::parse("PropFind")));
    }

    #[test]
    fn an_unknown_verb_is_not_carried_no_matter_how_plausible_it_looks() {
        // The refusal that matters: anything outside the list, including the
        // ordinary HTTP verbs WebDAV gives no meaning to and the ones that have
        // no business near a loopback relay.
        for refused in ["POST", "PATCH", "TRACE", "CONNECT", "SEARCH", "REPORT", "BIND",
                        "ACL", "VERSION-CONTROL", "CHECKOUT", "X", ""] {
            assert!(!carries(&Method::parse(refused)), "{refused} was carried");
        }
    }

    #[test]
    fn a_refused_method_reaches_the_log_bounded_rather_than_whole() {
        // Behind a source-address gate that admits every co-hosted app on this
        // box, an unbounded echo into the log is a disk-filling primitive.
        let ordinary = Method::parse("PROPFIND");
        assert_eq!(loggable_method(&ordinary), "PROPFIND");

        let flood = Method::parse(&"A".repeat(4096));
        assert_eq!(loggable_method(&flood).len(), LOGGED_METHOD_CHARS);
    }

    #[test]
    fn the_allow_field_names_exactly_the_verbs_that_are_carried() {
        // These two are read by different audiences — the relay and the client
        // it just refused — and a drift between them is a client told to retry
        // with a verb that will be refused again.
        let advertised: Vec<&str> = ALLOW.split(", ").collect();
        assert_eq!(advertised, VERBS.to_vec());
        for verb in &advertised {
            assert!(carries(&Method::parse(verb)), "{verb} is advertised but not carried");
        }
    }

    #[test]
    fn the_two_fields_copy_move_and_locking_cannot_work_without_are_relayed() {
        // Stated as its own test because these are the two the feature dies
        // without: no `Destination` is no COPY and no MOVE, and no `If` is no
        // lock token on a write, which on Windows is a read-only mount.
        assert!(is_relayed("Destination"), "COPY and MOVE cannot work without Destination");
        assert!(is_relayed("If"), "locking cannot work without If");
    }

    #[test]
    fn the_widening_covers_the_verbs_arguments_and_the_credentials_and_nothing_else() {
        for allowed in RELAYED_FOR_DAV {
            assert!(is_relayed(allowed), "{allowed} stopped being relayed");
        }
        // The ordinary console set travels too — `Authorization` above all,
        // since a WebDAV client presents it on essentially every request and the
        // admin API is the only thing entitled to judge it.
        for allowed in crate::upgrade::RELAYED {
            assert!(is_relayed(allowed), "{allowed} stopped being relayed");
        }
        // Framing is re-derived by the relay; hop-by-hop fields describe a
        // connection this is not; and the handshake widening must never leak
        // onto a path that is not a handshake.
        for refused in [
            "content-length",
            "transfer-encoding",
            "connection",
            "upgrade",
            "user-agent",
            "referer",
            "origin",
            "translate",
            "x-forwarded-for",
            "sec-websocket-key",
            "sec-websocket-protocol",
        ] {
            assert!(!is_relayed(refused), "{refused} was relayed to the share");
        }
    }

    #[test]
    fn relaying_is_case_insensitive_because_clients_choose_their_own_casing() {
        assert!(is_relayed("DESTINATION"));
        assert!(is_relayed("if"));
        assert!(is_relayed("Lock-Token"));
        assert!(is_relayed("X-Expected-Entity-Length"));
    }

    #[test]
    fn a_repeated_control_field_is_caught_and_named() {
        let doubled = head("MOVE", &[
            "Destination: https://console.example/dav/vault/a",
            "Destination: https://console.example/dav/vault/b",
        ]);
        assert_eq!(duplicated_control_field(&doubled.headers), Some("destination"));

        // Casing does not smuggle a second copy past the check.
        let mixed = head("PROPFIND", &["Depth: 1", "DEPTH: infinity", "Content-Length: 0"]);
        assert_eq!(duplicated_control_field(&mixed.headers), Some("depth"));

        let ordinary = head("MOVE", &["Destination: https://console.example/dav/vault/a", "Overwrite: F"]);
        assert_eq!(duplicated_control_field(&ordinary.headers), None);
    }

    #[test]
    fn a_header_value_cannot_carry_a_second_request_line_into_the_relay() {
        // The reason `Destination` can be relayed uninterpreted: a value holding
        // CR or LF never becomes a `Request` at all, so the bytes this proxy
        // copies into the loopback head are always one field's worth.
        let raw = "MOVE /dav/vault/a HTTP/1.1\r\nHost: console.example\r\n\
                   Destination: /dav/vault/b\rX-Injected: yes\r\n\r\n";
        assert!(Request::parse(raw.as_bytes()).is_err(), "a CR inside a value must not parse");
    }

    #[test]
    fn only_the_verbs_that_carry_a_document_or_content_may_send_a_body() {
        assert_eq!(body_policy(&Method::parse("PUT")), BodyPolicy::Content);
        for document in ["PROPFIND", "PROPPATCH", "MKCOL", "LOCK"] {
            assert_eq!(body_policy(&Method::parse(document)), BodyPolicy::Document, "{document}");
        }
        // A body on any of these is refused rather than dropped: unread bytes on
        // a reused connection are the next request as far as the client is
        // concerned.
        for empty in ["OPTIONS", "GET", "HEAD", "DELETE", "COPY", "MOVE", "UNLOCK"] {
            assert_eq!(body_policy(&Method::parse(empty)), BodyPolicy::Forbidden, "{empty}");
        }
    }

    #[test]
    fn an_unknown_verb_defaults_to_carrying_no_body() {
        // Belt to the allow-list's braces: if this call ever moved above the
        // allow-list, the default must be a refusal rather than an open relay.
        assert_eq!(body_policy(&Method::parse("SEARCH")), BodyPolicy::Forbidden);
    }
}
