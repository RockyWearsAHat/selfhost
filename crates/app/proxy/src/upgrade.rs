//! Recognising a protocol upgrade, and the two rules the relay changes for one.
//!
//! Everything in this module is a pure decision over a head some other layer
//! already parsed. It opens nothing, reads nothing and — this is the point —
//! **never touches a WebSocket frame**. The proxy owns ports 80 and 443 for
//! every site on the box, the mail transport and the certificate store; the
//! workspace sets `panic = "abort"` for release, so a parser that runs in this
//! process is a parser that can end all of it at once. The frame codec therefore
//! lives in `crates/ws` and runs only in the daemon, behind loopback, where a
//! malformed frame costs one connection.
//!
//! What is left for the proxy to do is small enough to state in a sentence: spot
//! a handshake in a request head, forward the four fields that carry it, notice a
//! `101` in the answer, and then stop reading and start copying.
//!
//! # Where the containment rule actually cuts, and why it is not at the crate edge
//!
//! The rule is about which code **runs** in the process that owns 80 and 443,
//! not about which crate names appear in its `Cargo.toml`. Linking `crates/ws`
//! to call [`looks_like_upgrade`] executes four header lookups: no parser, no
//! allocation, no state machine, no failure mode. Linking it to call
//! `selfhost_ws::frame::parse`, `Assembler` or `Duplex` would execute exactly
//! the thing this module exists to keep out — a state machine over bytes a
//! stranger chose, in a process where `panic = "abort"` turns one bad input into
//! an outage of every site, the mail transport and the certificate store.
//!
//! So the line is drawn at behaviour, and it reads: **this crate may ask
//! `crates/ws` a question about a request head it has already parsed; it may
//! never hand `crates/ws` a byte that arrived after that head.** Everything past
//! the `101` is moved by `tokio::io::copy_bidirectional` and is opaque here. A
//! future reader who notices that the frame codec is one `use` away and reaches
//! for it to, say, count messages or enforce a ceiling in the proxy is undoing
//! the whole design: those ceilings live in the daemon, behind loopback, where a
//! malformed frame costs one connection.
//!
//! The predicate is imported rather than copied for the reason recorded on
//! `selfhost_ws::handshake::looks_like_upgrade`: two sniffs that can disagree
//! about whether the same bytes are a handshake is the shape of a
//! request-smuggling bug, and the only reliable way to keep two predicates equal
//! is to have one.

use selfhost_http::{IncomingResponse, Status};
use std::borrow::Cow;

/// Whether this request head is *shaped* like a protocol upgrade.
///
/// Re-exported, not reimplemented: `crates/ws` owns the one definition of this
/// question in the workspace, and the proxy's routing decision and the daemon's
/// validator must be answering the same one. See that function's own
/// documentation for what it does and does not ask — in particular that it
/// deliberately ignores `Sec-WebSocket-Version`, so a handshake offering a
/// version we do not speak still reaches the daemon and gets a clean refusal
/// instead of being buffered as an ordinary `GET` whose body never arrives.
///
/// This is the *only* symbol of `crates/ws` this crate calls at run time. See
/// the module note above for where that line comes from. (The test module below
/// additionally asks `handshake::validate` whether the head this relay writes is
/// one the daemon accepts — a compile-time cross-check that never ships into the
/// running proxy.)
pub use selfhost_ws::looks_like_upgrade;

/// The header fields relayed to the admin API on an ordinary request.
///
/// Only what the API acts on: the body's type and the caller's credentials.
/// Everything else the client sent — framing, hop-by-hop fields, anything a
/// browser volunteers — is dropped and re-derived by the relay.
pub const RELAYED: [&str; 4] = ["content-type", "cookie", "authorization", "x-selfhost-console"];

/// The extra fields relayed **only** for a request that is a handshake.
///
/// Three of them are the handshake's own content and cannot be dropped: RFC 6455
/// requires a server to refuse a handshake with no `Sec-WebSocket-Key`, the
/// accept key is computed from it, and `Sec-WebSocket-Protocol` matters for a
/// reason specific to this deployment — it is the one header a browser will let a
/// page set on a handshake, which is why the daemon's single-use ticket travels
/// in it.
///
/// **`Upgrade` and `Connection` are deliberately absent.** They are hop-by-hop
/// fields: they describe the connection they arrived on, not the message, and
/// this relay is a new connection. The proxy writes both itself, with the exact
/// values RFC 6455 requires, for two reasons. It removes an ambiguity — echoing
/// the client's `Connection: keep-alive, Upgrade` *and* writing our own would put
/// two `Connection` fields in one head, which is precisely the shape of
/// disagreement this codebase refuses everywhere else. And it narrows what a
/// stranger controls: of everything that reaches the daemon on this path, only
/// three opaque values and an `Origin` come from the client, and every one of
/// them is something the daemon compares rather than obeys.
///
/// This list is a perimeter change and is deliberately narrow. It is applied per
/// request and only when [`looks_like_upgrade`] says yes, so an ordinary `GET`
/// relays byte-for-byte what it relayed before this module existed.
pub const RELAYED_FOR_UPGRADE: [&str; 3] =
    ["sec-websocket-key", "sec-websocket-version", "sec-websocket-protocol"];

/// The two hop-by-hop lines the proxy writes for itself on the upgrade path,
/// in place of echoing whatever the client sent.
///
/// Exported so the relay and this module's tests cannot drift: the value the
/// daemon's handshake validator insists on and the value the proxy actually
/// sends are the same bytes, named once.
pub const UPGRADE_REQUEST_LINES: &[u8] = b"Upgrade: websocket\r\nConnection: Upgrade\r\n";

/// The `Origin` field, relayed for an upgrade and named separately because it is
/// the one entry in [`RELAYED_FOR_UPGRADE`]'s company that is not part of RFC
/// 6455's handshake.
pub const RELAYED_ORIGIN: &str = "origin";

/// Path prefixes whose remainder is withheld from the access log.
///
/// `request.target` is logged raw, which is right for a website: knowing that
/// someone asked for `/pricing` is the whole value of the line. It stops being
/// right the moment the path names a *file on a share* or a *machine being
/// driven* — on a NAS the path is the sensitive thing, more so than the fact
/// that a transfer happened, and an operator reading a log should not
/// incidentally learn the name of every document in the household.
///
/// The prefix is kept so the line still says which subsystem was reached; only
/// what comes after it is dropped, query string included, since a query on these
/// paths carries the same kind of detail as the path does.
///
/// [`crate::dav::PREFIX`] is named rather than spelled again: the mount point
/// and the elision must be the same string forever, and a WebDAV path is the
/// worst case this rule exists for — a Finder window walking a share writes one
/// log line per file, which is a directory listing of the household's documents
/// assembled by the machine that was supposed to be keeping them private.
pub const ELIDED_PREFIXES: [&str; 3] =
    ["/api/storage/blob/", "/api/desktop/", crate::dav::PREFIX];

/// What replaces the elided remainder, so a reader can see that something was
/// withheld rather than wonder at a truncated line.
const ELISION: &str = "[elided]";

/// Whether a header field should be passed to the admin API.
///
/// `upgrade` widens the set for exactly one request. It is a parameter rather
/// than two functions so that the caller cannot forget which list it is holding:
/// there is one call site, and it names the condition at the point of use.
pub fn is_relayed(name: &str, upgrade: bool) -> bool {
    let named = |list: &[&str]| list.iter().any(|allowed| name.eq_ignore_ascii_case(allowed));
    named(&RELAYED)
        || (upgrade && (named(&RELAYED_FOR_UPGRADE) || name.eq_ignore_ascii_case(RELAYED_ORIGIN)))
}

/// Whether the upstream agreed to leave HTTP.
///
/// The status alone decides. It is tempting to also require `Upgrade: websocket`
/// in the answer and refuse anything else, but the upstream here is our own
/// daemon on loopback, the proxy has no opinion about which protocol was
/// negotiated, and adding a second condition would only create a state where the
/// daemon believes it has upgraded and the proxy is still framing HTTP — the
/// desynchronisation this whole layer exists to avoid. One condition, checked in
/// one place, and everything after it is opaque bytes.
pub fn is_switching_protocols(response: &IncomingResponse) -> bool {
    response.status == Status::SWITCHING_PROTOCOLS
}

/// The request target as it should appear in the access log.
///
/// Borrowed unchanged for every ordinary path, so the common case allocates
/// nothing; owned only when something was withheld. See [`ELIDED_PREFIXES`].
pub fn loggable_target(target: &str) -> Cow<'_, str> {
    let path = target.split(['?', '#']).next().unwrap_or(target);
    match ELIDED_PREFIXES.iter().find(|prefix| path.starts_with(**prefix)) {
        Some(prefix) => Cow::Owned(format!("{prefix}{ELISION}")),
        None => Cow::Borrowed(target),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_http::Request;

    /// Builds a request head from lines, so a test reads as the bytes a client
    /// would actually send.
    fn request(lines: &[&str]) -> Request {
        let mut raw = String::from("GET /api/events HTTP/1.1\r\nHost: admin.example\r\n");
        for line in lines {
            raw.push_str(line);
            raw.push_str("\r\n");
        }
        raw.push_str("\r\n");
        Request::parse(raw.as_bytes()).expect("a well-formed head").request
    }

    // What [`looks_like_upgrade`] answers for a list-valued `Connection`, an
    // odd casing, a token hidden inside another word, a `POST`, or a head with
    // one field missing is settled by the tests that live beside its definition
    // in `crates/ws`. Restating them here would recreate, in test form, exactly
    // the duplication this module just deleted: two suites over one function,
    // one of which would eventually be the stale one. What the proxy owns, and
    // what is tested here, is the *interface* between the two — the bytes it
    // writes, and the fields it relays.

    #[test]
    fn the_ordinary_relay_set_is_unchanged_by_this_module() {
        // The regression that matters most here: an ordinary request must relay
        // exactly what it relayed before upgrades existed, and not one field
        // more. Every handshake field is refused when `upgrade` is false.
        for allowed in RELAYED {
            assert!(is_relayed(allowed, false), "{allowed} stopped being relayed");
        }
        for widened in RELAYED_FOR_UPGRADE.iter().chain([&RELAYED_ORIGIN]) {
            assert!(!is_relayed(widened, false), "{widened} leaked onto the ordinary path");
        }
    }

    #[test]
    fn the_widening_covers_the_handshake_and_the_origin_and_nothing_else() {
        for allowed in RELAYED.iter().chain(RELAYED_FOR_UPGRADE.iter()).chain([&RELAYED_ORIGIN]) {
            assert!(is_relayed(allowed, true), "{allowed} was dropped from a handshake");
        }
        // A sample of fields a browser really sends, none of which the admin API
        // acts on. Relaying them would be a perimeter change nobody asked for.
        // `upgrade` and `connection` are in this list on purpose: they are
        // hop-by-hop, the proxy writes them itself, and echoing them as well
        // would put two of each in one head.
        for refused in [
            "upgrade",
            "connection",
            "user-agent",
            "referer",
            "accept-language",
            "x-forwarded-for",
            "content-length",
            "transfer-encoding",
            "sec-websocket-extensions",
        ] {
            assert!(!is_relayed(refused, true), "{refused} was relayed on an upgrade");
        }
    }

    #[test]
    fn the_lines_the_proxy_writes_itself_are_what_the_daemon_insists_on() {
        // A real cross-check now that both ends read the same predicate: the
        // head assembled here is the one the relay actually sends — the proxy's
        // own two hop-by-hop lines plus the handshake fields it relays — and it
        // is judged by `crates/ws`, which is the code that will judge it in the
        // daemon. A change to either side that broke the other fails here.
        let text = std::str::from_utf8(UPGRADE_REQUEST_LINES).expect("ASCII");
        let mut lines: Vec<&str> = text.trim_end_matches("\r\n").split("\r\n").collect();
        lines.push("Sec-WebSocket-Version: 13");
        lines.push("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==");
        let relayed = request(&lines);
        assert!(looks_like_upgrade(&relayed));
        // And the daemon's stricter question, asked over the same bytes: the
        // relayed head is not merely upgrade-shaped, it is a handshake the
        // validator accepts. This is the assertion that catches a field the
        // proxy stops relaying.
        assert!(
            selfhost_ws::handshake::validate(&relayed).is_ok(),
            "the head the relay writes must survive the validator it is written for"
        );
    }

    #[test]
    fn relaying_is_case_insensitive_in_both_directions() {
        assert!(is_relayed("Sec-WebSocket-Key", true));
        assert!(is_relayed("COOKIE", false));
    }

    #[test]
    fn only_a_101_is_a_switch() {
        let switching = IncomingResponse::parse(b"HTTP/1.1 101 Switching Protocols\r\n\r\n")
            .expect("a 101 head")
            .response;
        assert!(is_switching_protocols(&switching));

        for other in ["200 OK", "401 Unauthorized", "404 Not Found", "502 Bad Gateway"] {
            let raw = format!("HTTP/1.1 {other}\r\nContent-Length: 0\r\n\r\n");
            let response = IncomingResponse::parse(raw.as_bytes()).expect("a head").response;
            assert!(!is_switching_protocols(&response), "{other} was treated as a switch");
        }
    }

    #[test]
    fn an_ordinary_target_is_logged_whole_and_borrowed() {
        let target = "/pricing?plan=small";
        assert!(matches!(loggable_target(target), Cow::Borrowed("/pricing?plan=small")));
        assert_eq!(loggable_target("/api/services"), "/api/services");
        // The prefix must match at a segment boundary the way it is written; a
        // path that merely resembles one is not elided.
        assert_eq!(loggable_target("/api/storage"), "/api/storage");
        assert_eq!(loggable_target("/api/desktopish/x"), "/api/desktopish/x");
    }

    #[test]
    fn a_file_path_and_its_query_are_both_withheld() {
        assert_eq!(
            loggable_target("/api/storage/blob/vault/tax/2019%20return.pdf"),
            "/api/storage/blob/[elided]"
        );
        assert_eq!(
            loggable_target("/api/storage/blob/vault/notes.txt?inline=1"),
            "/api/storage/blob/[elided]"
        );
        assert_eq!(loggable_target("/api/desktop/session?node=alex"), "/api/desktop/[elided]");
    }

    #[test]
    fn elision_cannot_be_escaped_by_a_fragment_or_an_empty_remainder() {
        // A target is not supposed to carry a fragment, but the log line is
        // built from whatever arrived, so the split covers it.
        assert_eq!(loggable_target("/api/storage/blob/x#frag"), "/api/storage/blob/[elided]");
        assert_eq!(loggable_target("/api/storage/blob/"), "/api/storage/blob/[elided]");
    }
}
