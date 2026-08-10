//! Deciding whether a request head is a WebSocket handshake, and answering it.
//!
//! This module is pure: it reads a `selfhost_http::Request` that some other layer
//! already parsed off a socket, and it produces either an [`Upgrade`] describing
//! what the client asked for or a [`Refusal`] naming the first thing that was
//! wrong. It opens nothing, writes nothing, and knows nothing about sessions,
//! tickets or capabilities.
//!
//! # What this module is not
//!
//! It is not the authorisation decision, and the distinction is the most
//! important sentence in the file. A handshake that validates here has proved
//! only that the *syntax* of RFC 6455 §4.1 was obeyed — that a client wants to
//! speak WebSocket and gave us a key to prove we understood. Anyone on the far
//! side of the proxy can produce such a request; a hostile page in a logged-in
//! browser can produce one *with the session cookie attached*, because a
//! handshake is a `GET`, a browser will not let a page set a custom header on
//! one, and there is no CORS preflight to refuse it. The repository's existing
//! CSRF defence is demanded only for non-`GET` requests, so on this path it does
//! not fire at all.
//!
//! Everything that actually decides *whether this caller may have a stream* —
//! the single-use ticket minted by an ordinary CSRF-protected `POST`, the Origin
//! comparison against the console's server-side canonical origin, the session
//! check and the capability check — belongs to the daemon's route, above this
//! crate, and is re-checked there rather than inferred from a successful
//! handshake. What this module contributes to that decision is only the raw
//! material: the subprotocol list the ticket travels in, and the `Origin` header
//! as it arrived, unjudged.
//!
//! # One definition of "this is an upgrade", exported for everyone
//!
//! [`looks_like_upgrade`] is the **single** definition of the router-level
//! question, and it is public so that the reverse proxy calls it rather than
//! keeping a second copy. Two sniffs that disagree about whether the same bytes
//! are a handshake is the exact shape of a request-smuggling bug: the proxy would
//! relay one set of fields while the daemon framed the message by another set of
//! rules, and the disagreement would live in whichever of the two nobody thought
//! to change. Reusing the predicate costs the proxy a link-time dependency on
//! this crate and nothing else — the containment rule that keeps the frame codec
//! out of the proxy is about which code *runs* there, and a predicate over four
//! header fields runs no parser, allocates nothing and cannot fail.
//!
//! # Why every field this module reads is read as bytes
//!
//! `Headers` stores values as raw bytes because a header value is not required to
//! be UTF-8, and `Headers::get_str` answers `None` for a value that is present but
//! not UTF-8 — which would make *malformed* indistinguishable from *absent*. On
//! this path absence is a privilege: a request with no `Origin` is how a
//! non-browser caller identifies itself, and the route above treats that case
//! differently from a browser's. So the fields are fetched as bytes and a
//! present-but-not-UTF-8 value is [`Refusal::NonUtf8Header`], never silence.
//!
//! # Why the 101 is serialised here and not by the response writer
//!
//! A `101 Switching Protocols` is the one HTTP response in this codebase whose
//! head must go out exactly as written. The general response path derives a
//! `Content-Length` or a `Connection: close` from the body it was given, and the
//! proxy splices security headers into anything it forwards; either behaviour
//! applied to a 101 produces a response that is either self-contradictory or
//! refused by the browser. So [`response_head`] writes the four fields by hand —
//! but builds them through `selfhost_http::Headers`, so that the one thing we
//! must not lose by leaving the general path, the CR/LF injection check in
//! `Header::new`, is the one thing we keep. The subprotocol we echo is chosen
//! from a list the *client* sent, which is exactly the shape of input that makes
//! response splitting possible.

use crate::accept;
use selfhost_http::{HeaderError, Headers, Method, Request};

/// The only `Sec-WebSocket-Version` RFC 6455 defines.
const VERSION: &str = "13";

/// The `Upgrade` field, named once so the sniff and the validator ask for the
/// same thing. Lookups are case-insensitive, so the canonical spelling is used
/// throughout and doubles as the label in a [`Refusal`].
const UPGRADE_FIELD: &str = "Upgrade";

/// The `Connection` field. See [`UPGRADE_FIELD`].
const CONNECTION_FIELD: &str = "Connection";

/// The `Sec-WebSocket-Key` field. See [`UPGRADE_FIELD`].
const KEY_FIELD: &str = "Sec-WebSocket-Key";

/// The `Sec-WebSocket-Version` field. See [`UPGRADE_FIELD`].
const VERSION_FIELD: &str = "Sec-WebSocket-Version";

/// The `Sec-WebSocket-Protocol` field — the one that carries the desktop ticket.
/// See [`UPGRADE_FIELD`].
const PROTOCOL_FIELD: &str = "Sec-WebSocket-Protocol";

/// The `Origin` field. See [`UPGRADE_FIELD`].
const ORIGIN_FIELD: &str = "Origin";

/// The fields that must appear at most once, checked together before any of them
/// is read.
///
/// `Sec-WebSocket-Protocol` is in this list although RFC 6455 §4.1 permits it to
/// repeat and requires a server to combine the values. Combining is refused here
/// deliberately, and the reason is specific to this deployment: that field is
/// where the single-use desktop ticket travels, because it is the only header a
/// browser lets a page set on a handshake. A credential must have exactly one
/// spelling on the wire — if we combined, the value the route compares against
/// would be one *we* assembled out of several fields rather than the one the
/// client sent, and every intermediary between here and the browser would get a
/// say in how the pieces were ordered and joined. Refusing also costs a real
/// client nothing: a browser emits the whole offer as one field, so a repeat can
/// only come from something that is not a browser or from something that rewrote
/// the request on the way.
const AT_MOST_ONCE: [&str; 4] = [KEY_FIELD, VERSION_FIELD, PROTOCOL_FIELD, ORIGIN_FIELD];

/// The largest number of subprotocols a client may offer.
///
/// Our own console offers two — the protocol name and the ticket — and a browser
/// offers exactly what the page asked it to. The cap exists so that the parsing
/// below is bounded work on a header a stranger controls, not because any real
/// client comes close to it.
const MAX_SUBPROTOCOLS: usize = 8;

/// The longest single subprotocol token accepted.
///
/// A ticket travels as `tkt.<64 hex characters>`, so the real maximum is 68; 128
/// leaves room for a longer vocabulary later without leaving room for a header
/// that exists only to be parsed.
const MAX_SUBPROTOCOL_LEN: usize = 128;

/// What a valid handshake asked for.
///
/// `subprotocols` is the client's offer in the order it was made, with the
/// tokens trimmed but otherwise untouched — the route above reads its ticket out
/// of this list and chooses which token, if any, to echo back. `origin` is the
/// header verbatim and is deliberately *not* compared to anything here: the value
/// it must equal is derived from configuration by the layer that knows which site
/// this is, exactly as the WebAuthn relying-party origin already is, and never
/// from anything the client sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upgrade {
    /// The `Sec-WebSocket-Key` exactly as it arrived.
    pub key: String,
    /// The `Sec-WebSocket-Accept` value to answer with.
    pub accept: String,
    /// The subprotocols the client offered, in order.
    pub subprotocols: Vec<String>,
    /// The `Origin` header, if the client sent one.
    pub origin: Option<String>,
}

/// Why a request is not a handshake we will answer.
///
/// Every variant names one specific missing or malformed thing. That detail is
/// for the *log*, not for the client: a route that turns these into a response
/// should answer with the same uniform refusal it gives every other unauthorised
/// caller, because telling a stranger which of our checks they failed is helping
/// them pass it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The method was not `GET`. A handshake is always a `GET`.
    NotGet,
    /// The request was HTTP/1.0, which cannot be upgraded.
    HttpTooOld,
    /// `Upgrade` was absent or did not contain the `websocket` token.
    NotWebSocketUpgrade,
    /// `Connection` was absent or did not contain the `upgrade` token.
    ConnectionNotUpgrade,
    /// `Sec-WebSocket-Version` was absent.
    MissingVersion,
    /// `Sec-WebSocket-Version` was present but not `13`.
    UnsupportedVersion(String),
    /// `Sec-WebSocket-Key` was absent.
    MissingKey,
    /// `Sec-WebSocket-Key` was not padded base64 of sixteen bytes.
    MalformedKey,
    /// A header that must appear at most once appeared more than once, which is
    /// two different requests in one and is refused rather than resolved. See
    /// the private `AT_MOST_ONCE` list for why `Sec-WebSocket-Protocol` is on it
    /// even though RFC 6455 permits that field to repeat.
    RepeatedHeader(&'static str),
    /// A header was present but its value was not UTF-8.
    ///
    /// A distinct refusal rather than the field being treated as absent, because
    /// absence is meaningful on this path — a handshake with no `Origin` is how a
    /// non-browser caller announces itself — and *malformed* must never be able to
    /// pass itself off as *not sent*.
    NonUtf8Header(&'static str),
    /// The subprotocol offer was longer than [`MAX_SUBPROTOCOLS`], or one of its
    /// tokens was over-long or contained a character a token may not.
    BadSubprotocols,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotGet => write!(f, "a handshake must be a GET"),
            Self::HttpTooOld => write!(f, "HTTP/1.0 cannot be upgraded"),
            Self::NotWebSocketUpgrade => write!(f, "Upgrade did not name websocket"),
            Self::ConnectionNotUpgrade => write!(f, "Connection did not name upgrade"),
            Self::MissingVersion => write!(f, "Sec-WebSocket-Version is absent"),
            Self::UnsupportedVersion(version) => {
                write!(f, "Sec-WebSocket-Version {version} is not supported; this server speaks 13")
            }
            Self::MissingKey => write!(f, "Sec-WebSocket-Key is absent"),
            Self::MalformedKey => write!(f, "Sec-WebSocket-Key is not base64 of sixteen bytes"),
            Self::RepeatedHeader(name) => write!(f, "{name} appeared more than once"),
            Self::NonUtf8Header(name) => write!(f, "{name} was present but is not UTF-8"),
            Self::BadSubprotocols => write!(f, "Sec-WebSocket-Protocol is malformed or over-long"),
        }
    }
}

impl std::error::Error for Refusal {}

/// Whether this request head is *shaped* like a handshake.
///
/// **This is the one definition of that question in the workspace.** Every layer
/// that has to route an upgrade — this crate's own validator, and the reverse
/// proxy deciding which fields to relay and when to stop framing HTTP — calls
/// this function rather than reimplementing it. Two answers to "is this an
/// upgrade?" that can drift apart is precisely how a request gets smuggled past
/// one layer by looking like something else to the other, and the only reliable
/// way to keep two predicates equal is to have one.
///
/// A cheap yes/no for a router deciding which branch a request belongs in,
/// answering the same question RFC 6455 §4.2.1 asks and nothing more: the method
/// is `GET`, `Upgrade` names `websocket`, `Connection` names `upgrade`, and a key
/// is present. It is deliberately weaker than [`validate`], and deliberately
/// *does not* look at `Sec-WebSocket-Version` — a handshake offering version 8
/// must still be routed down the upgrade branch so that it receives the clean
/// refusal [`validate`] produces, rather than being buffered as an ordinary `GET`
/// whose body never arrives. That asymmetry is the right way round: a request
/// that looks like an upgrade here and is refused there costs one error
/// response, while a handshake mistaken for a `GET` costs a held connection and a
/// timeout.
///
/// Values are compared as bytes, so a field that is not UTF-8 is judged on what
/// it actually contains rather than being silently treated as absent.
pub fn looks_like_upgrade(request: &Request) -> bool {
    request.method == Method::Get
        && has_token(request.headers.get(UPGRADE_FIELD), "websocket")
        && has_token(request.headers.get(CONNECTION_FIELD), "upgrade")
        && request.headers.contains(KEY_FIELD)
}

/// Validates a handshake request, or names the first thing wrong with it.
///
/// The checks run in the order RFC 6455 §4.2.1 lists them, which is also roughly
/// cheapest-first, so a request that is not remotely a handshake is dismissed
/// before any header value is parsed. Repetition is settled for every field this
/// function reads before any of their values is looked at, so no later check can
/// be reading one copy of a field while another copy sits unexamined.
pub fn validate(request: &Request) -> Result<Upgrade, Refusal> {
    if request.method != Method::Get {
        return Err(Refusal::NotGet);
    }
    if request.minor_version < 1 {
        return Err(Refusal::HttpTooOld);
    }
    if !has_token(request.headers.get(UPGRADE_FIELD), "websocket") {
        return Err(Refusal::NotWebSocketUpgrade);
    }
    if !has_token(request.headers.get(CONNECTION_FIELD), "upgrade") {
        return Err(Refusal::ConnectionNotUpgrade);
    }

    for field in AT_MOST_ONCE {
        if request.headers.count(field) > 1 {
            return Err(Refusal::RepeatedHeader(field));
        }
    }

    let version = text_field(&request.headers, VERSION_FIELD)?
        .ok_or(Refusal::MissingVersion)?
        .trim();
    if version != VERSION {
        return Err(Refusal::UnsupportedVersion(version.to_owned()));
    }

    let key = text_field(&request.headers, KEY_FIELD)?.ok_or(Refusal::MissingKey)?.trim();
    if !accept::client_key_is_well_formed(key) {
        return Err(Refusal::MalformedKey);
    }

    Ok(Upgrade {
        key: key.to_owned(),
        accept: accept::accept_key(key),
        subprotocols: subprotocols(&request.headers)?,
        origin: text_field(&request.headers, ORIGIN_FIELD)?.map(str::to_owned),
    })
}

/// The first value of `field` as text: absent, present-and-UTF-8, or a refusal.
///
/// The whole point of this function is the third case. `Headers::get_str` folds
/// "not UTF-8" into `None`, which is safe when absence is itself a refusal and
/// dangerous when absence is a *privilege* — as it is for `Origin`, where no
/// header at all is what distinguishes a non-browser caller from a browser whose
/// origin must match. Reading the raw bytes and refusing explicitly keeps
/// malformed and absent as two different answers everywhere in this file.
fn text_field<'a>(headers: &'a Headers, field: &'static str) -> Result<Option<&'a str>, Refusal> {
    match headers.get(field) {
        None => Ok(None),
        Some(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => Ok(Some(text)),
            Err(_) => Err(Refusal::NonUtf8Header(field)),
        },
    }
}

/// Serialises the `101 Switching Protocols` head, blank line included.
///
/// `subprotocol` must be one the client offered — echoing a token the client did
/// not send is a protocol error on our side, and the browser will drop the
/// connection for it. Returns a [`HeaderError`] if either value could inject a
/// line into the response, which cannot happen for an accept key we computed but
/// very much can for a subprotocol that came from the client and was not taken
/// from a validated [`Upgrade`].
pub fn response_head(accept: &str, subprotocol: Option<&str>) -> Result<Vec<u8>, HeaderError> {
    let mut headers = Headers::new();
    headers.push("Upgrade", "websocket")?;
    headers.push("Connection", "Upgrade")?;
    headers.push("Sec-WebSocket-Accept", accept)?;
    if let Some(chosen) = subprotocol {
        headers.push("Sec-WebSocket-Protocol", chosen)?;
    }

    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(b"HTTP/1.1 101 Switching Protocols\r\n");
    headers.write_to(&mut out);
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

/// Splits and validates the `Sec-WebSocket-Protocol` offer.
///
/// Absent is not an error: a client may offer nothing, in which case we echo
/// nothing. Present-but-malformed is an error, because a token list is the one
/// place a route will later go looking for a credential, and a lenient split here
/// would mean the route's ticket comparison runs against something we never
/// really parsed. That is also why the field is read through [`text_field`] and
/// why a repeat of it was already refused by [`validate`]: an offer that is
/// unreadable, and an offer whose second half arrived in a second field, are both
/// ways of making a ticket disappear while the handshake still succeeds.
fn subprotocols(headers: &Headers) -> Result<Vec<String>, Refusal> {
    let Some(offer) = text_field(headers, PROTOCOL_FIELD)? else {
        return Ok(Vec::new());
    };
    let mut tokens = Vec::new();
    for token in offer.split(',') {
        let token = token.trim();
        if token.is_empty() {
            return Err(Refusal::BadSubprotocols);
        }
        if token.len() > MAX_SUBPROTOCOL_LEN || !token.bytes().all(is_token_byte) {
            return Err(Refusal::BadSubprotocols);
        }
        if tokens.len() == MAX_SUBPROTOCOLS {
            return Err(Refusal::BadSubprotocols);
        }
        tokens.push(token.to_owned());
    }
    Ok(tokens)
}

/// Whether a comma-separated field value contains `token`, case-insensitively.
///
/// `Connection` and `Upgrade` are both list-valued and browsers do not agree on
/// their casing or spacing: Firefox has historically sent `keep-alive, Upgrade`
/// where Chrome sends `Upgrade`. Comparing the whole value would refuse perfectly
/// good clients, so the comparison is per element, which is what RFC 9110 §7.6.1
/// says the field means.
///
/// The comparison is over bytes rather than `&str` so that a value which is not
/// UTF-8 is judged on what it holds: `Upgrade: websocket\xff` contains no
/// `websocket` token and must be *refused for that reason*, not read as a missing
/// header. Only the ASCII tokens this protocol names can ever match, so byte
/// equality and string equality agree on every input that matters.
fn has_token(value: Option<&[u8]>, token: &str) -> bool {
    value.is_some_and(|value| {
        value
            .split(|&byte| byte == b',')
            .any(|element| element.trim_ascii().eq_ignore_ascii_case(token.as_bytes()))
    })
}

/// Whether a byte may appear in an HTTP token (RFC 9110 §5.6.2).
///
/// Duplicated from `selfhost_http`, where the same predicate is private to the
/// header module. Twelve bytes of `matches!` is a better trade than widening
/// another crate's public surface for one caller — but if a third caller ever
/// wants it, it should be promoted there rather than copied a third time.
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(byte, b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key from RFC 6455 §1.3, so a valid request in these tests is one a
    /// browser could really have sent.
    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

    fn request_from(lines: &[&str]) -> Request {
        let byte_lines: Vec<&[u8]> = lines.iter().map(|line| line.as_bytes()).collect();
        request_from_bytes(&byte_lines)
    }

    /// The same fixture over raw bytes, so a test can send a header value that is
    /// not UTF-8 — which is the whole point of several tests below and cannot be
    /// expressed through a `&str`.
    fn request_from_bytes(lines: &[&[u8]]) -> Request {
        let mut raw = Vec::from(&b"GET /api/events HTTP/1.1\r\nHost: admin.example\r\n"[..]);
        for line in lines {
            raw.extend_from_slice(line);
            raw.extend_from_slice(b"\r\n");
        }
        raw.extend_from_slice(b"\r\n");
        Request::parse(&raw).expect("the test's own fixture must parse").request
    }

    /// The four handshake lines, as bytes, so a case can append a fifth that is
    /// not valid UTF-8.
    fn handshake_bytes() -> Vec<Vec<u8>> {
        vec![
            b"Upgrade: websocket".to_vec(),
            b"Connection: Upgrade".to_vec(),
            b"Sec-WebSocket-Version: 13".to_vec(),
            format!("Sec-WebSocket-Key: {KEY}").into_bytes(),
        ]
    }

    /// A valid handshake plus one extra line given as raw bytes.
    fn handshake_with(extra: &[u8]) -> Request {
        let mut lines = handshake_bytes();
        lines.push(extra.to_vec());
        let borrowed: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
        request_from_bytes(&borrowed)
    }

    fn valid() -> Request {
        request_from(&[
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Version: 13",
            &format!("Sec-WebSocket-Key: {KEY}"),
        ])
    }

    #[test]
    fn a_well_formed_handshake_validates() {
        let upgrade = validate(&valid()).expect("validate");
        assert_eq!(upgrade.key, KEY);
        assert_eq!(upgrade.accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert!(upgrade.subprotocols.is_empty());
        assert_eq!(upgrade.origin, None);
    }

    #[test]
    fn the_sniff_agrees_with_the_validator_on_a_good_request() {
        assert!(looks_like_upgrade(&valid()));
    }

    #[test]
    fn a_connection_header_with_several_tokens_is_accepted() {
        let request = request_from(&[
            "Upgrade: WebSocket",
            "Connection: keep-alive, Upgrade",
            "Sec-WebSocket-Version: 13",
            &format!("Sec-WebSocket-Key: {KEY}"),
        ]);
        assert!(validate(&request).is_ok(), "casing and list form vary between browsers");
    }

    #[test]
    fn a_missing_upgrade_header_is_refused() {
        let request = request_from(&[
            "Connection: Upgrade",
            "Sec-WebSocket-Version: 13",
            &format!("Sec-WebSocket-Key: {KEY}"),
        ]);
        assert_eq!(validate(&request), Err(Refusal::NotWebSocketUpgrade));
        assert!(!looks_like_upgrade(&request));
    }

    #[test]
    fn a_connection_header_that_does_not_name_upgrade_is_refused() {
        let request = request_from(&[
            "Upgrade: websocket",
            "Connection: keep-alive",
            "Sec-WebSocket-Version: 13",
            &format!("Sec-WebSocket-Key: {KEY}"),
        ]);
        assert_eq!(validate(&request), Err(Refusal::ConnectionNotUpgrade));
    }

    #[test]
    fn a_missing_version_is_refused() {
        let request = request_from(&[
            "Upgrade: websocket",
            "Connection: Upgrade",
            &format!("Sec-WebSocket-Key: {KEY}"),
        ]);
        assert_eq!(validate(&request), Err(Refusal::MissingVersion));
    }

    #[test]
    fn an_older_websocket_version_is_named_in_the_refusal() {
        let request = request_from(&[
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Version: 8",
            &format!("Sec-WebSocket-Key: {KEY}"),
        ]);
        assert_eq!(validate(&request), Err(Refusal::UnsupportedVersion("8".into())));
    }

    #[test]
    fn a_missing_or_malformed_key_is_refused() {
        let without = request_from(&[
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Version: 13",
        ]);
        assert_eq!(validate(&without), Err(Refusal::MissingKey));

        let short = request_from(&[
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Version: 13",
            "Sec-WebSocket-Key: c2hvcnQ=",
        ]);
        assert_eq!(validate(&short), Err(Refusal::MalformedKey));
    }

    #[test]
    fn a_repeated_key_is_two_requests_in_one_and_is_refused() {
        let request = request_from(&[
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Version: 13",
            &format!("Sec-WebSocket-Key: {KEY}"),
            &format!("Sec-WebSocket-Key: {KEY}"),
        ]);
        assert_eq!(validate(&request), Err(Refusal::RepeatedHeader("Sec-WebSocket-Key")));
    }

    #[test]
    fn a_post_is_never_a_handshake() {
        let mut request = valid();
        request.method = Method::Post;
        assert_eq!(validate(&request), Err(Refusal::NotGet));
        assert!(!looks_like_upgrade(&request));
    }

    #[test]
    fn http_1_0_cannot_be_upgraded() {
        let mut request = valid();
        request.minor_version = 0;
        assert_eq!(validate(&request), Err(Refusal::HttpTooOld));
    }

    #[test]
    fn the_subprotocol_offer_is_split_in_order() {
        let request = request_from(&[
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Version: 13",
            &format!("Sec-WebSocket-Key: {KEY}"),
            "Sec-WebSocket-Protocol: selfhost.desktop.1, tkt.abc123",
        ]);
        let upgrade = validate(&request).expect("validate");
        assert_eq!(upgrade.subprotocols, vec!["selfhost.desktop.1", "tkt.abc123"]);
    }

    #[test]
    fn a_malformed_subprotocol_offer_is_refused() {
        for offer in ["", "a,,b", "a b", "a;b", &"x".repeat(200), "a,b,c,d,e,f,g,h,i"] {
            let request = request_from(&[
                "Upgrade: websocket",
                "Connection: Upgrade",
                "Sec-WebSocket-Version: 13",
                &format!("Sec-WebSocket-Key: {KEY}"),
                &format!("Sec-WebSocket-Protocol: {offer}"),
            ]);
            assert_eq!(validate(&request), Err(Refusal::BadSubprotocols), "offer: {offer:?}");
        }
    }

    #[test]
    fn a_repeated_subprotocol_offer_cannot_make_a_ticket_disappear() {
        // The defect this test exists for: the first field validated and the
        // second — the one carrying the ticket — was dropped on the floor, so the
        // route looked for a credential in a list that no longer held it.
        let request = request_from(&[
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Version: 13",
            &format!("Sec-WebSocket-Key: {KEY}"),
            "Sec-WebSocket-Protocol: selfhost.desktop.1",
            "Sec-WebSocket-Protocol: tkt.abc123",
        ]);
        assert_eq!(validate(&request), Err(Refusal::RepeatedHeader("Sec-WebSocket-Protocol")));
    }

    #[test]
    fn a_header_that_is_not_utf8_is_refused_rather_than_read_as_absent() {
        // Every one of these is a field that would otherwise be reported missing,
        // and for `Origin` "missing" is the condition that admits a non-browser
        // caller — so malformed passing itself off as absent is a privilege
        // escalation, not a cosmetic bug.
        for (field, line) in [
            ("Origin", b"Origin: https://\xff.example".to_vec()),
            ("Sec-WebSocket-Protocol", b"Sec-WebSocket-Protocol: tkt.\xff\xfe".to_vec()),
        ] {
            let request = handshake_with(&line);
            assert_eq!(
                validate(&request),
                Err(Refusal::NonUtf8Header(field)),
                "field: {field}"
            );
        }

        // The same rule on the two fields that make up the handshake proper. The
        // key and version lines replace their valid counterparts rather than
        // being appended, so the refusal is about the value and not a repeat.
        for (field, replaced, line) in [
            ("Sec-WebSocket-Version", 2usize, b"Sec-WebSocket-Version: 1\xff".to_vec()),
            ("Sec-WebSocket-Key", 3usize, b"Sec-WebSocket-Key: \xffbad".to_vec()),
        ] {
            let mut lines = handshake_bytes();
            lines[replaced] = line;
            let borrowed: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
            let request = request_from_bytes(&borrowed);
            assert_eq!(validate(&request), Err(Refusal::NonUtf8Header(field)), "field: {field}");
        }
    }

    #[test]
    fn a_non_utf8_upgrade_token_is_refused_by_both_the_sniff_and_the_validator() {
        // `Upgrade: websocket\xff` holds no `websocket` token. Judged on its
        // bytes it is refused; judged through a lossy `&str` conversion it would
        // read as an absent header, which is the same refusal by accident and
        // stops being so the moment a caller trusts the reason.
        let mut lines = handshake_bytes();
        lines[0] = b"Upgrade: websocket\xff".to_vec();
        let borrowed: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
        let request = request_from_bytes(&borrowed);
        assert_eq!(validate(&request), Err(Refusal::NotWebSocketUpgrade));
        assert!(!looks_like_upgrade(&request));
    }

    #[test]
    fn the_sniff_and_the_validator_never_disagree_about_the_upgrade_branch() {
        // The property that makes one exported predicate worth having: anything
        // the validator accepts, the router must have routed here. The converse
        // does not hold and must not — see the note on `looks_like_upgrade`.
        let cases: Vec<Request> = vec![
            valid(),
            handshake_with(b"Sec-WebSocket-Protocol: selfhost.desktop.1, tkt.abc"),
            handshake_with(b"Origin: https://admin.example"),
            request_from(&[
                "Upgrade: WebSocket",
                "Connection: keep-alive, Upgrade",
                "Sec-WebSocket-Version: 13",
                &format!("Sec-WebSocket-Key: {KEY}"),
            ]),
        ];
        for request in cases {
            assert!(validate(&request).is_ok(), "fixture must be a good handshake");
            assert!(looks_like_upgrade(&request), "the validator accepted what the sniff missed");
        }

        // A version the server does not speak is still routed to the upgrade
        // branch, so it gets a refusal instead of hanging as an ordinary GET.
        let mut lines = handshake_bytes();
        lines[2] = b"Sec-WebSocket-Version: 8".to_vec();
        let borrowed: Vec<&[u8]> = lines.iter().map(Vec::as_slice).collect();
        let old = request_from_bytes(&borrowed);
        assert!(looks_like_upgrade(&old));
        assert_eq!(validate(&old), Err(Refusal::UnsupportedVersion("8".into())));
    }

    #[test]
    fn the_origin_is_carried_through_unjudged() {
        let request = request_from(&[
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Version: 13",
            &format!("Sec-WebSocket-Key: {KEY}"),
            "Origin: https://evil.example",
        ]);
        let upgrade = validate(&request).expect("validate");
        assert_eq!(upgrade.origin.as_deref(), Some("https://evil.example"));
        // Validation says nothing about whether this origin is allowed. That is
        // the route's decision, against a value derived from config.
    }

    #[test]
    fn the_response_head_is_the_four_fields_and_nothing_else() {
        let head = response_head("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", None).expect("head");
        let text = String::from_utf8(head).expect("ascii");
        assert_eq!(
            text,
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
             \r\n"
        );
        assert!(!text.to_ascii_lowercase().contains("content-length"), "a 101 has no body framing");
    }

    #[test]
    fn a_chosen_subprotocol_is_echoed() {
        let head = response_head("abc", Some("selfhost.events.1")).expect("head");
        let text = String::from_utf8(head).expect("ascii");
        assert!(text.contains("Sec-WebSocket-Protocol: selfhost.events.1\r\n"));
    }

    #[test]
    fn a_subprotocol_carrying_a_newline_cannot_split_the_response() {
        assert!(response_head("abc", Some("evil\r\nX-Injected: 1")).is_err());
    }

    #[test]
    fn validate_never_panics_on_odd_header_values() {
        // Header values a stranger chose, including ones that are almost right.
        let oddities = [
            "Sec-WebSocket-Key: ",
            "Sec-WebSocket-Key: ================",
            "Sec-WebSocket-Version: 13, 13",
            "Sec-WebSocket-Version: ",
            "Upgrade: ,,,",
            "Connection: ,",
            "Sec-WebSocket-Protocol: ,",
            "Origin: \u{fffd}",
        ];
        for oddity in oddities {
            let request = request_from(&[
                "Upgrade: websocket",
                "Connection: Upgrade",
                "Sec-WebSocket-Version: 13",
                &format!("Sec-WebSocket-Key: {KEY}"),
                oddity,
            ]);
            let _ = validate(&request);
            let _ = looks_like_upgrade(&request);
        }
    }
}
