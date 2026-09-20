//! Signing in through the public sign-in site's own login — no admin command
//! to copy, and no privileged gate to install first.
//!
//! `auth.rockywearsahat.com` *is* the authorization server: there is no
//! third-party identity provider, because the identity that matters is
//! "a Person who can already sign in here and holds either the relay's own
//! `vpn.access` or a Grant on a Site only a Peer can reach". It shares the admin console's
//! login/passkey backend but is its own public, ungated site (see
//! `crates/foundation/config`'s `Site::public_api_paths`) — precisely so this
//! flow never depends on the console route already being installed. This
//! module's whole job is carrying that proof across the gap between a browser
//! tab and this desktop process, with PKCE (RFC 7636) binding the two ends
//! together so a code intercepted in transit is useless without the verifier
//! this process never lets leave it:
//!
//! 1. Generate a PKCE `code_verifier`/`code_challenge` pair and a `state`.
//! 2. Open the sign-in site in the system browser at a `#vpn-connect?...`
//!    link (matched by `sites/auth/app.js`'s `vpnConnectParams()`), carrying
//!    the challenge, the state, and the port of a loopback listener this
//!    process just opened.
//! 3. That page — already logged in, or logging the person in first — checks
//!    their Grants (see `Api::vpn_authorize`), mints a one-time code
//!    server-side, and redirects the browser to
//!    `http://127.0.0.1:<port>/callback?code=...&state=...`.
//! 4. This process's loopback listener catches that redirect, checks `state`,
//!    and redeems the code at `POST /api/vpn/enroll` with the `code_verifier`
//!    — the server re-derives the challenge from it and only then trusts the
//!    code.
//!
//! Everything here is synchronous/blocking: the app has no async runtime, and
//! its established idiom for slow work is `thread::spawn` plus a blocking
//! call (see `actions.rs`), not pulling in tokio for one outbound POST.

use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use selfhost_http::{IncomingResponse, ParseError, ResponseFraming, dechunk};
use selfhost_json::Json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::app::AUTH_URL;
use crate::keys;

/// How long the loopback listener waits for the browser to finish the
/// console round trip before giving up. Generous: it covers a login plus a
/// possible passkey prompt, not just a page load.
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(180);

/// How often the loopback listener polls its non-blocking accept.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Random bytes behind the PKCE verifier and the CSRF-binding state, before
/// base64url encoding. 32 bytes is comfortably inside RFC 7636's recommended
/// 43-128 character verifier length once encoded (43 characters).
const RANDOM_BYTES: usize = 32;

/// The largest response body this process will read back from the console —
/// an enrollment reply is a few hundred bytes; anything past this is refused
/// rather than buffered without bound.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// What a completed sign-in bound this install to.
pub struct SignInResult {
    /// The roster/key-file identity now writing to `~/.securevpn/account` —
    /// the value the tunnel dials as and the relay's roster tracks by.
    pub peer: String,
    /// The human-facing account name the server approved this device under,
    /// for the masthead's "@name".
    pub account: String,
}

/// Runs the whole sign-in flow to completion: opens the browser, waits for
/// the callback, and redeems the code. Blocking — run this off the UI thread.
pub fn sign_in() -> Result<SignInResult, String> {
    let rng = SystemRandom::new();
    let verifier = b64url_encode(&random_bytes(&rng)?);
    let challenge = b64url_encode(digest(&SHA256, verifier.as_bytes()).as_ref());
    let state = b64url_encode(&random_bytes(&rng)?);

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| format!("could not open a local callback listener: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("could not configure the callback listener: {error}"))?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("could not read the callback listener's port: {error}"))?
        .port();

    crate::actions::open_url(&authorize_url(&state, &challenge, port))?;

    let code = await_callback(&listener, &state)?;

    let peer = keys::account().unwrap_or_else(keys::generate_peer_name);
    let public_key = keys::generate_named_key(&peer)?;

    let reply = enroll(&code, &verifier, &peer, &public_key)?;
    keys::set_signed_in(&peer, &reply.account)?;

    Ok(SignInResult { peer, account: reply.account })
}

/// The sign-in URL the browser should open: a `#vpn-connect` fragment
/// carrying everything `sites/auth/app.js`'s `vpnConnectParams()` expects.
/// A fragment, not a query string, on the site's own side too — but this
/// process only builds it, it never reads one back.
///
/// It names no relay: which one a deployment runs is the deployment's to
/// know, and `POST /api/vpn/authorize` answers for its own.
fn authorize_url(state: &str, challenge: &str, port: u16) -> String {
    format!(
        "{AUTH_URL}#vpn-connect?state={}&challenge={}&port={port}",
        percent_encode(state),
        percent_encode(challenge),
    )
}

/// Waits for the browser's redirect to land on the loopback listener,
/// validates it, and returns the authorization code.
///
/// Any connection whose request line is not a matching `/callback` is
/// answered plainly and ignored rather than treated as a failure — a browser
/// can send an incidental request (a `/favicon.ico` fetch after the page
/// navigates away) that has nothing to do with the handoff.
fn await_callback(listener: &TcpListener, expected_state: &str) -> Result<String, String> {
    let deadline = Instant::now() + CALLBACK_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                if let Some(outcome) = handle_callback(stream, expected_state) {
                    return outcome;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("timed out waiting for the browser to finish sign-in".into());
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(format!("the local callback listener failed: {error}")),
        }
    }
}

/// Handles one connection to the loopback listener. `None` means "not the
/// callback — keep listening"; `Some` is the flow's final result.
fn handle_callback(mut stream: TcpStream, expected_state: &str) -> Option<Result<String, String>> {
    // A single `read` is not guaranteed to return the whole request — TCP is
    // a byte stream, not a message protocol, and a request can legitimately
    // arrive across more than one segment. A socket accepted from a
    // nonblocking listener can itself read as nonblocking (observed on
    // macOS), so a `WouldBlock` here means "no more bytes yet", not
    // "connection is empty" — it must be polled like `await_callback` polls
    // `accept`, never treated as an immediate "not the callback".
    let _ = stream.set_nonblocking(true);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buffer = [0u8; 8192];
    let mut filled = 0;
    while filled < buffer.len() {
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => {
                filled += read;
                if buffer[..filled].windows(2).any(|pair| pair == b"\r\n") {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return None,
        }
    }
    if filled == 0 {
        return None;
    }
    let request = String::from_utf8_lossy(&buffer[..filled]);
    let target = request.lines().next()?.split_whitespace().nth(1)?;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != "/callback" {
        respond(&mut stream, 404, "Not found");
        return None;
    }

    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let value = percent_decode(value);
        match key {
            "code" => code = Some(value),
            "state" => state = Some(value),
            _ => {}
        }
    }

    let outcome = match (code, state) {
        (Some(code), Some(state)) if state == expected_state => Ok(code),
        (Some(_), Some(_)) => Err("the sign-in link's state did not match — try again".to_string()),
        _ => Err("the sign-in link was missing its code".to_string()),
    };
    let page = match &outcome {
        Ok(_) => "Signed in. You can close this window and return to SelfHost VPN.",
        Err(message) => message.as_str(),
    };
    respond(&mut stream, 200, page);
    Some(outcome)
}

/// Writes a minimal HTML response and closes the connection.
fn respond(stream: &mut TcpStream, status: u16, message: &str) {
    let reason = if status == 200 { "OK" } else { "Not Found" };
    let body = format!(
        "<!doctype html><html><body style=\"font:16px -apple-system,sans-serif;padding:2em\">{}</body></html>",
        html_escape(message)
    );
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// Escapes the handful of characters that matter in an HTML text node — this
/// only ever wraps a fixed set of strings this module itself wrote, but a
/// closed tag should never be one bad character away from breaking out.
fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Redeems `code` at `POST /api/vpn/enroll`, over a fresh TLS connection.
fn enroll(code: &str, verifier: &str, peer: &str, public_key: &str) -> Result<EnrollReply, String> {
    let body = Json::object([
        ("code", Json::string(code)),
        ("verifier", Json::string(verifier)),
        ("peer", Json::string(peer)),
        ("public_key", Json::string(public_key)),
    ])
    .to_text();

    let host = auth_host()?;
    let response = https_post(&host, "/api/vpn/enroll", &body)?;

    let json = selfhost_json::parse(&response).map_err(|_| "the server sent back malformed JSON".to_string())?;
    if let Some(error) = json.get("error").and_then(|value| value.as_str()) {
        return Err(error.to_string());
    }
    let account =
        json.get("name").and_then(|value| value.as_str()).ok_or("the server's reply had no account name")?;
    Ok(EnrollReply { account: account.to_string() })
}

/// The server's successful reply to `/api/vpn/enroll`.
struct EnrollReply {
    account: String,
}

/// `AUTH_URL`'s host, for the TLS handshake's SNI and the `Host` header.
fn auth_host() -> Result<String, String> {
    let without_scheme = AUTH_URL.strip_prefix("https://").ok_or("AUTH_URL is not https")?;
    let host = without_scheme.split('/').next().unwrap_or(without_scheme);
    if host.is_empty() { Err("AUTH_URL has no host".into()) } else { Ok(host.to_string()) }
}

/// Posts a JSON body to `host` over TLS on 443, and returns the response body
/// as text. A blocking, single-request client — no keep-alive, no pooling,
/// mirroring `crates/services/reports/src/oauth.rs`'s `HttpsClient` but with
/// `std::net`/`rustls` in place of `tokio`/`tokio-rustls`.
fn https_post(host: &str, path: &str, body: &str) -> Result<String, String> {
    let config = tls_config()?;
    let server_name =
        ServerName::try_from(host.to_string()).map_err(|error| format!("bad server name {host}: {error}"))?;
    let connection = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|error| format!("could not start a TLS session: {error}"))?;
    let tcp = TcpStream::connect((host, 443))
        .map_err(|error| format!("could not reach {host}:443: {error}"))?;
    let mut tls = StreamOwned::new(connection, tcp);

    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: selfhost-vpn-ui\r\n\
         Accept-Encoding: identity\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(request.as_bytes()).map_err(|error| format!("could not send the request: {error}"))?;
    tls.flush().map_err(|error| format!("could not send the request: {error}"))?;

    read_response(&mut tls)
}

/// The `rustls::ClientConfig` trusting the public web PKI, matching
/// `reports/oauth.rs`'s own construction.
fn tls_config() -> Result<ClientConfig, String> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|error| format!("could not configure TLS: {error}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Reads a full HTTP/1.1 response off `stream` and returns its body as text,
/// honoring whichever framing the response head declares.
fn read_response(stream: &mut impl Read) -> Result<String, String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let (head_end, parsed) = loop {
        match IncomingResponse::parse(&buffer) {
            Ok(parsed) => break (parsed.consumed, parsed.response),
            Err(ParseError::Incomplete) => {
                let read = stream.read(&mut chunk).map_err(|error| format!("connection lost: {error}"))?;
                if read == 0 {
                    return Err("the server closed the connection before sending a response".into());
                }
                buffer.extend_from_slice(&chunk[..read]);
                if buffer.len() > MAX_RESPONSE_BYTES {
                    return Err("the server's response was too large".into());
                }
            }
            Err(error) => return Err(format!("could not parse the server's response: {error:?}")),
        }
    };

    let mut body = buffer.split_off(head_end);
    let text = match parsed.framing {
        ResponseFraming::None => String::new(),
        ResponseFraming::Fixed(len) => {
            let len = len as usize;
            while body.len() < len {
                if body.len() > MAX_RESPONSE_BYTES {
                    return Err("the server's response was too large".into());
                }
                let read = stream.read(&mut chunk).map_err(|error| format!("connection lost: {error}"))?;
                if read == 0 {
                    return Err("the connection closed before the full response arrived".into());
                }
                body.extend_from_slice(&chunk[..read]);
            }
            body.truncate(len);
            String::from_utf8_lossy(&body).into_owned()
        }
        ResponseFraming::UntilClose => {
            loop {
                let read = stream.read(&mut chunk).map_err(|error| format!("connection lost: {error}"))?;
                if read == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..read]);
                if body.len() > MAX_RESPONSE_BYTES {
                    return Err("the server's response was too large".into());
                }
            }
            String::from_utf8_lossy(&body).into_owned()
        }
        ResponseFraming::Chunked => {
            loop {
                match dechunk(&body) {
                    Ok(decoded) => break String::from_utf8_lossy(&decoded).into_owned(),
                    Err(ParseError::Incomplete) => {
                        let read =
                            stream.read(&mut chunk).map_err(|error| format!("connection lost: {error}"))?;
                        if read == 0 {
                            return Err("the connection closed mid-chunk".into());
                        }
                        body.extend_from_slice(&chunk[..read]);
                        if body.len() > MAX_RESPONSE_BYTES {
                            return Err("the server's response was too large".into());
                        }
                    }
                    Err(error) => return Err(format!("could not decode the response body: {error:?}")),
                }
            }
        }
    };
    Ok(text)
}

/// `n` cryptographically random bytes.
fn random_bytes(rng: &SystemRandom) -> Result<[u8; RANDOM_BYTES], String> {
    let mut bytes = [0u8; RANDOM_BYTES];
    rng.fill(&mut bytes).map_err(|_| "could not generate random bytes".to_string())?;
    Ok(bytes)
}

/// RFC 4648 base64url, no padding — PKCE's own required alphabet.
fn b64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18 & 0x3f) as usize] as char);
        out.push(ALPHABET[(triple >> 12 & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(triple >> 6 & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3f) as usize] as char);
        }
    }
    out
}

/// RFC 3986 unreserved-character percent-encoding, for values placed in the
/// `#vpn-connect` fragment.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Decodes a `%XX`-escaped query value; an unescaped `+` is a literal plus,
/// not a space — this is a URL query, not an `application/x-www-form-urlencoded`
/// body.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_matches_known_vectors() {
        // RFC 4648 test vectors, re-expressed in the base64url alphabet.
        assert_eq!(b64url_encode(b""), "");
        assert_eq!(b64url_encode(b"f"), "Zg");
        assert_eq!(b64url_encode(b"fo"), "Zm8");
        assert_eq!(b64url_encode(b"foo"), "Zm9v");
        assert_eq!(b64url_encode(b"foob"), "Zm9vYg");
        assert_eq!(b64url_encode(b"fooba"), "Zm9vYmE");
        assert_eq!(b64url_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn percent_round_trips_the_reserved_characters_a_challenge_can_contain() {
        let value = "abc-DEF_123~=+/";
        assert_eq!(percent_decode(&percent_encode(value)), value);
    }

    #[test]
    fn the_authorize_url_carries_every_field_vpn_connect_params_expects() {
        let url = authorize_url("st ate", "cha llenge", 54321);
        assert!(url.starts_with(&format!("{AUTH_URL}#vpn-connect?")));
        assert!(!url.contains("location="), "the relay is the server's to name");
        assert!(url.contains("state=st%20ate"));
        assert!(url.contains("challenge=cha%20llenge"));
        assert!(url.contains("port=54321"));
    }

    #[test]
    fn a_non_callback_path_is_ignored_not_treated_as_failure() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut probe = TcpStream::connect(("127.0.0.1", port)).unwrap();
        probe.write_all(b"GET /favicon.ico HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let stream = accept_blocking(&listener);
        assert!(handle_callback(stream, "expected").is_none());
    }

    #[test]
    fn a_mismatched_state_is_reported_and_still_returns() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            send_callback_request(&listener, "GET /callback?code=abc&state=wrong HTTP/1.1\r\nHost: x\r\n\r\n"),
            Some(Err("the sign-in link's state did not match — try again".to_string()))
        );
    }

    #[test]
    fn a_matching_callback_yields_its_code() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            send_callback_request(&listener, "GET /callback?code=abc123&state=expected HTTP/1.1\r\nHost: x\r\n\r\n"),
            Some(Ok("abc123".to_string()))
        );
    }

    /// Connects to `listener`, sends `request_line` in one shot, and hands
    /// back what `handle_callback` reports.
    fn send_callback_request(listener: &TcpListener, request_line: &str) -> Option<Result<String, String>> {
        let port = listener.local_addr().unwrap().port();
        let mut probe = TcpStream::connect(("127.0.0.1", port)).unwrap();
        probe.write_all(request_line.as_bytes()).unwrap();
        handle_callback(accept_blocking(listener), "expected")
    }

    /// `accept` on this nonblocking listener can return `WouldBlock` even
    /// after the peer's `connect`/`write_all` have already returned — the
    /// completed handshake is not always visible in the accept queue
    /// instantly. Poll it exactly as `await_callback` does in production.
    fn accept_blocking(listener: &TcpListener) -> TcpStream {
        loop {
            match listener.accept() {
                Ok((stream, _addr)) => return stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(POLL_INTERVAL);
                }
                Err(error) => panic!("{error}"),
            }
        }
    }

    #[test]
    fn a_request_split_across_multiple_reads_is_still_parsed() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let writer = std::thread::spawn(move || {
            let mut probe = TcpStream::connect(("127.0.0.1", port)).unwrap();
            probe.write_all(b"GET /callback?code=abc123&state=e").unwrap();
            std::thread::sleep(Duration::from_millis(50));
            probe.write_all(b"xpected HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        });
        let stream = accept_blocking(&listener);
        assert_eq!(handle_callback(stream, "expected"), Some(Ok("abc123".to_string())));
        writer.join().unwrap();
    }
}
