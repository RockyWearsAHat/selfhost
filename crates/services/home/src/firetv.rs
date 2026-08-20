//! The Fire TV remote API: the d-pad, the applications, and the wake.
//!
//! This module exists because [`crate::dial`] was wrong about the ceiling, and
//! the way it was wrong is worth stating before any code. DIAL gives launch,
//! stop and status per application, and a sweep that asked both televisions for
//! twenty-five *streaming* application names concluded that was everything a
//! Fire TV would ever offer without an operator action. The sweep never asked
//! for the one registered application that is not a streaming application.
//! `GET /apps/FireTVRemote` answers `200`, `POST` to it answers `201`, and a
//! few seconds later the television is serving **HTTPS on 8080** — the REST API
//! Amazon's own phone remote speaks. Every port scan in `home-lab.dx` honestly
//! reported 8080 closed, because the service starts on demand and a scanner
//! that never asks it to start cannot see it.
//!
//! # What it delivers, measured against the real televisions
//!
//! Ten key actions (`dpad_up`, `dpad_down`, `dpad_left`, `dpad_right`,
//! `select`, `back`, `home`, `menu`, `epg`, `sleep`), play and pause on a
//! separate `/v1/media` path, text entry, and — the one DIAL could never do —
//! **launching an application by package name**, which is how Prime Video gets
//! on the screen at all. `com.amazon.avod` is Amazon's own application, was
//! never DIAL-registered, and `home-lab.dx` recorded its `404` as a wall.
//!
//! # What it refuses, and why no endpoint will ever be found for it
//!
//! `volume_up`, `volume_down`, `mute` and every spelling of TV power answer
//! `400` with the *same body a nonsense action gets* — so they are absent from
//! the vocabulary rather than declined. Those are exactly the four buttons the
//! physical remote performs with its **own infrared emitter**: covering the
//! remote's IR window with a thumb and pressing power turns nothing off, and
//! uncovering it turns the television off again. A Fire TV Stick has no
//! emitter; the remote has. The signal path for those buttons is remote → light
//! → the photodiode behind the television's bezel, and no host on the network
//! is on it. This is physics, not a missing endpoint, and it is written here so
//! that nobody spends another afternoon looking for the port.
//!
//! # Power, which is therefore asymmetric and honest about it
//!
//! **On is real and needs no pairing at all**: the DIAL `POST /apps/FireTVRemote`
//! that starts the service also wakes the stick, and a waking stick emits
//! HDMI-CEC one-touch-play, which a television obeys by turning on and
//! switching to that input. **Off is best-effort**: `sleep` sleeps the stick,
//! and the television follows only if it honours CEC standby, which the
//! household reports as intermittent. So [`Command::Power`] `false` leaves
//! [`Power::Unknown`] behind and never [`Power::Off`] — this box told the stick
//! to sleep, the stick agreed, and whether the television obeyed is a fact
//! about a wire we cannot read.
//!
//! # Shape
//!
//! The same split as [`crate::wiz`] and [`crate::dial`]: a pure half that
//! builds requests and reads answers, provable from byte slices with no
//! network, under a thin live half. The live half brings its own TLS stream
//! because the transport in [`crate::soap`] owns a plain socket, and borrows
//! that module's response framing rather than growing a second copy of it.

use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::device::{Command, Key};
use crate::soap::{self, SoapError};

/// The port the remote service listens on once it has been started.
///
/// Not discovered: the service is not advertised over SSDP or mDNS under this
/// port, and the `_amzn-wplay` record a Fire TV does publish points at a pair
/// of ephemeral ports belonging to a different, certificate-pinned protocol
/// that this module does not speak. 8080 is measured, on both televisions.
pub const REMOTE_PORT: u16 = 8080;

/// The DIAL application whose launch starts the remote service and wakes the
/// stick. The one string this whole module hangs from.
pub const REMOTE_APP: &str = "FireTVRemote";

/// The `X-Api-Key` every request carries.
///
/// A constant and not a secret: it is the same value on every Fire TV in the
/// world, it identifies the *client kind* rather than a client, and the thing
/// that actually authorises a command is the per-television token from
/// [`confirm`]. Written out rather than hidden so nobody mistakes it for a
/// credential that needs protecting.
pub const API_KEY: &str = "0987654321";

/// What a Fire TV calls each key in this crate's vocabulary.
///
/// `None` means the television has no such action — and that is a real answer,
/// not a gap: see this module's documentation for why volume and mute can never
/// appear here. Returning `None` rather than sending a doomed request is what
/// lets the driver refuse in a sentence instead of relaying a `400`.
#[must_use]
pub fn action_for(key: Key) -> Option<&'static str> {
    match key {
        Key::Up => Some("dpad_up"),
        Key::Down => Some("dpad_down"),
        Key::Left => Some("dpad_left"),
        Key::Right => Some("dpad_right"),
        Key::Select => Some("select"),
        Key::Back => Some("back"),
        Key::Home => Some("home"),
        Key::Menu => Some("menu"),
        // Play/pause reaches the television on `/v1/media`, not as a key —
        // see `media_request`. Next and previous have no action at all.
        Key::PlayPause | Key::Next | Key::Previous => None,
        // The infrared buttons. See the module documentation.
        Key::VolumeUp | Key::VolumeDown => None,
    }
}

/// The `keyActionType` a single press travels as.
///
/// A held key splits into `keyDown` and a later `keyUp`; nothing here holds a
/// key yet, and the constant is named so the day it does is an addition rather
/// than an edit.
const PRESS: &str = "keyDownUp";

/// Builds the request that asks the television to show a pairing PIN.
#[must_use]
pub fn pin_display_request(authority: &str, friendly_name: &str) -> Vec<u8> {
    let body = selfhost_json::Json::object([(
        "friendlyName",
        selfhost_json::Json::string(friendly_name),
    )])
    .to_text();
    request("POST", authority, "/v1/FireTV/pin/display", None, Some(&body))
}

/// Builds the request that exchanges a displayed PIN for a client token.
#[must_use]
pub fn pin_verify_request(authority: &str, pin: &str) -> Vec<u8> {
    let body =
        selfhost_json::Json::object([("pin", selfhost_json::Json::string(pin))]).to_text();
    request("POST", authority, "/v1/FireTV/pin/verify", None, Some(&body))
}

/// Builds one key press: `POST /v1/FireTV?action=<action>`.
#[must_use]
pub fn key_request(authority: &str, token: &str, action: &str) -> Vec<u8> {
    let body = selfhost_json::Json::object([(
        "keyActionType",
        selfhost_json::Json::string(PRESS),
    )])
    .to_text();
    let path = format!("/v1/FireTV?action={action}");
    request("POST", authority, &path, Some(token), Some(&body))
}

/// Builds a transport command: `POST /v1/media?action=play|pause`.
///
/// A separate path from [`key_request`] because the television really does
/// serve them separately — `action=play` on `/v1/FireTV` is a `400`, and the
/// same word on `/v1/media` is a `200`.
#[must_use]
pub fn media_request(authority: &str, token: &str, action: &str) -> Vec<u8> {
    let path = format!("/v1/media?action={action}");
    request("POST", authority, &path, Some(token), None)
}

/// Builds an application launch by package name.
#[must_use]
pub fn app_request(authority: &str, token: &str, package: &str) -> Vec<u8> {
    let path = format!("/v1/FireTV/app/{package}");
    request("POST", authority, &path, Some(token), None)
}

/// Reads the `description` field every answer from this API carries.
///
/// It is the API's one-size envelope: `{"description":"OK"}` for a PIN that is
/// now on screen, `{"description":"<token>"}` for a verified PIN, and
/// `{"description":"Bad arguments supplied. Please check inputs."}` for a
/// refusal. The caller decides what the string means, because only the caller
/// knows what it asked.
#[must_use]
pub fn description(body: &str) -> Option<String> {
    selfhost_json::parse(body)
        .ok()?
        .get("description")?
        .as_str()
        .map(str::to_owned)
}

/// Serialises one request.
///
/// `Content-Length` is derived in bytes from the same string that is appended,
/// for the reason `soap::post_request` states: a declared length that disagrees
/// with the body is answered by hanging until the read deadline rather than by
/// complaining. `Connection: close` because this module opens one connection
/// per command and the framing reader relies on the close for an unlengthed
/// body.
fn request(
    method: &str,
    authority: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&str>,
) -> Vec<u8> {
    let mut request = String::with_capacity(320);
    request.push_str(method);
    request.push(' ');
    request.push_str(path);
    request.push_str(" HTTP/1.1\r\n");
    request.push_str("HOST: ");
    request.push_str(authority);
    request.push_str("\r\n");
    request.push_str("X-API-KEY: ");
    request.push_str(API_KEY);
    request.push_str("\r\n");
    if let Some(token) = token {
        request.push_str("X-CLIENT-TOKEN: ");
        request.push_str(token);
        request.push_str("\r\n");
    }
    // The television answers a request without this User-Agent, but the phone
    // remote sends it and matching a known-good client costs one line.
    request.push_str("USER-AGENT: okhttp/4.10.0\r\n");
    request.push_str("CONTENT-TYPE: application/json\r\n");
    request.push_str("ACCEPT-ENCODING: identity\r\n");
    let body = body.unwrap_or("");
    request.push_str("CONTENT-LENGTH: ");
    request.push_str(&body.len().to_string());
    request.push_str("\r\nCONNECTION: close\r\n\r\n");
    request.push_str(body);
    request.into_bytes()
}

/// How long the TLS handshake and the exchange after it may take.
///
/// Longer than [`crate::soap`]'s deadlines because this service is started on
/// demand: the first request after a wake arrives while the stick is still
/// bringing its Wi-Fi back up, and a one-second deadline turns that into a
/// spurious "not answering" on the very command a person just pressed.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
/// The deadline on everything after the connection is open.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(6);

/// Opens one TLS connection, sends `request`, reads the whole answer.
///
/// `address` is a bare `host` or a `host:port`; the remote port is appended
/// when absent, exactly as `soap::authority` does for speakers.
async fn exchange(address: &str, request: &[u8]) -> Result<(u16, String), SoapError> {
    let authority = authority(address);
    let host = authority.split(':').next().unwrap_or(&authority).to_owned();

    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(&authority))
        .await
        .map_err(|_| {
            SoapError::Connect(format!("no connection to {authority} within {CONNECT_TIMEOUT:?}"))
        })?
        .map_err(|error| SoapError::Connect(error.to_string()))?;

    // The certificate names `0.0.0.0`, so no real name would verify against it
    // even if the chain were trusted; a fixed placeholder keeps rustls happy
    // and the verifier below ignores it either way.
    let server_name = ServerName::try_from(host)
        .unwrap_or(ServerName::IpAddress(std::net::Ipv4Addr::UNSPECIFIED.into()));

    timeout(EXCHANGE_TIMEOUT, async move {
        let mut stream = connector()
            .connect(server_name, stream)
            .await
            .map_err(|error| SoapError::Io(format!("TLS handshake failed: {error}")))?;
        stream.write_all(request).await.map_err(|error| SoapError::Io(error.to_string()))?;
        stream.flush().await.map_err(|error| SoapError::Io(error.to_string()))?;
        let mut reader = BufReader::new(stream);
        let (status, _, body) = soap::read_response(&mut reader).await?;
        let body = String::from_utf8(body)
            .map_err(|_| SoapError::Malformed("the body was not UTF-8".to_owned()))?;
        Ok((status, body))
    })
    .await
    .map_err(|_| SoapError::Io(format!("no answer from {authority} within {EXCHANGE_TIMEOUT:?}")))?
}

/// The `host:port` to connect to and to put in the `Host` header.
fn authority(address: &str) -> String {
    if address.contains(':') {
        address.to_owned()
    } else {
        format!("{address}:{REMOTE_PORT}")
    }
}

/// The TLS client configuration, which accepts whatever certificate the
/// television presents.
///
/// The televisions serve a self-signed leaf (`O=Aralink`) under a self-signed
/// Amazon root (`CN=Turnstile Server`) that no trust store carries, and the
/// leaf's common name is `0.0.0.0`. There is no chain here that could be
/// verified and no name that could be matched, so verification would refuse
/// every real device without ruling out anything: **the encryption is real and
/// the authentication is not**, and what actually confines this is the same
/// thing that confines the rest of the crate — it speaks only to addresses on
/// the local network, and the server binds loopback. Stated plainly rather than
/// buried, because "TLS" reads as "authenticated" to almost everyone.
fn connector() -> TlsConnector {
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// The verifier behind [`connector`]; see its documentation for why accepting
/// any certificate is the only available choice here.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::CryptoProvider::get_default()
            .map(|provider| provider.signature_verification_algorithms.supported_schemes())
            .unwrap_or_default()
    }
}

/// Wakes the stick and starts its remote service, in one DIAL launch.
///
/// The only call in this module that needs no token, which is what makes
/// power-on work on a television nobody has paired. It is also the reason
/// every other call here can assume 8080 is listening: the port is closed
/// until this runs.
pub async fn wake(address: &str) -> Result<(), String> {
    let authority = format!("{address}:{}", crate::dial::APPS_PORT);
    let request = crate::dial::launch_request(&authority, "/apps/", REMOTE_APP);
    match crate::soap::http(&authority, &request).await {
        // 200 is an already-running service, 201 a freshly started one.
        Ok((200 | 201, _, _)) => Ok(()),
        Ok((status, _, _)) => Err(format!("The television refused the wake with {status}.")),
        Err(error) => Err(error.to_string()),
    }
}

/// Asks the television to put a pairing PIN on its screen.
///
/// Wakes it first: the service is not listening until something starts it, and
/// a person setting a television up has no reason to know that.
pub async fn begin_pairing(address: &str, friendly_name: &str) -> Result<(), String> {
    wake(address).await?;
    let request = pin_display_request(&authority(address), friendly_name);
    match exchange(address, &request).await {
        Ok((200, _)) => Ok(()),
        Ok((status, body)) => Err(refusal(status, &body)),
        Err(error) => Err(error.to_string()),
    }
}

/// Exchanges a PIN a person read off the screen for a client token.
///
/// The token is what every later command carries. It lives on the television
/// until somebody removes the pairing there, so it is stored rather than
/// re-fetched, and a later `401` or `403` means exactly that it was removed.
pub async fn confirm(address: &str, pin: &str) -> Result<String, String> {
    let request = pin_verify_request(&authority(address), pin);
    match exchange(address, &request).await {
        Ok((200, body)) => description(&body)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| "The television accepted the PIN but returned no token.".to_owned()),
        Ok((status, body)) => Err(refusal(status, &body)),
        Err(error) => Err(error.to_string()),
    }
}

/// Performs one command against a paired television.
///
/// Every command here needs a token except the power-on, which is handled
/// before this is reached — see [`wake`].
pub async fn perform(address: &str, token: &str, command: &Command) -> Result<(), String> {
    let authority = authority(address);
    let request = match command {
        Command::Key(key) => {
            let action = action_for(*key).ok_or_else(|| {
                format!(
                    "This television has no {} key — it is a button on the remote's \
                     infrared emitter, not something the stick can be asked to do.",
                    key.as_str().replace('_', " ")
                )
            })?;
            key_request(&authority, token, action)
        }
        Command::Play => media_request(&authority, token, "play"),
        Command::Pause => media_request(&authority, token, "pause"),
        Command::Launch(package) => app_request(&authority, token, package),
        // Sleeping the stick. The television follows only if it honours CEC
        // standby; the caller is responsible for not claiming it went off.
        Command::Power(false) => key_request(&authority, token, "sleep"),
        Command::Power(true) => return wake(address).await,
        other => {
            return Err(format!(
                "A Fire TV cannot be asked to {}.",
                other.as_str().replace('_', " ")
            ))
        }
    };

    match exchange(address, &request).await {
        Ok((200, _)) => Ok(()),
        Ok((status, body)) => Err(refusal(status, &body)),
        Err(error) => Err(error.to_string()),
    }
}

/// Turns a refusal into a sentence a person could be shown.
///
/// The `401`/`403` case is the one worth spelling out, because it has a single
/// cause and a single fix and neither is guessable from the number.
fn refusal(status: u16, body: &str) -> String {
    match status {
        401 | 403 => "This television no longer recognises this box. The pairing was removed \
                      on the device, so it has to be paired again."
            .to_owned(),
        400 => description(body).unwrap_or_else(|| "The television refused that.".to_owned()),
        other => format!("The television answered {other}."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every key this crate has either maps to an action or is refused for a
    /// stated reason. The volume pair is the case worth pinning: it must stay
    /// `None`, because a request for it is a `400` and the driver should say
    /// why rather than relay one.
    #[test]
    fn only_the_keys_the_television_has_are_mapped() {
        assert_eq!(action_for(Key::Up), Some("dpad_up"));
        assert_eq!(action_for(Key::Select), Some("select"));
        assert_eq!(action_for(Key::Menu), Some("menu"));
        assert_eq!(action_for(Key::VolumeUp), None);
        assert_eq!(action_for(Key::VolumeDown), None);
        assert_eq!(action_for(Key::PlayPause), None);
    }

    #[test]
    fn a_key_request_carries_the_token_and_the_press() {
        let bytes = key_request("192.168.1.12:8080", "tok", "dpad_up");
        let text = String::from_utf8(bytes).expect("ASCII request");
        assert!(text.starts_with("POST /v1/FireTV?action=dpad_up HTTP/1.1\r\n"));
        assert!(text.contains("X-API-KEY: 0987654321\r\n"));
        assert!(text.contains("X-CLIENT-TOKEN: tok\r\n"));
        assert!(text.ends_with("{\"keyActionType\":\"keyDownUp\"}"));
    }

    /// The declared length must be the body's length in bytes. A television
    /// answers a mismatch by waiting for bytes that never come, which reads as
    /// a dead device rather than as a bug here.
    #[test]
    fn the_declared_length_is_the_body_length_in_bytes() {
        let bytes = pin_display_request("host:8080", "Küche");
        let text = String::from_utf8(bytes).expect("UTF-8 request");
        let (head, body) = text.split_once("\r\n\r\n").expect("a head and a body");
        let declared: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("CONTENT-LENGTH: "))
            .and_then(|value| value.parse().ok())
            .expect("a declared length");
        assert_eq!(declared, body.len());
        assert!(body.len() > body.chars().count(), "the name is multi-byte");
    }

    /// A bodiless request still declares zero, for the same reason the DIAL
    /// module states one: a `POST` without it leaves the television waiting.
    #[test]
    fn a_bodiless_post_still_declares_a_length() {
        let bytes = app_request("host:8080", "tok", "com.amazon.avod");
        let text = String::from_utf8(bytes).expect("ASCII request");
        assert!(text.contains("CONTENT-LENGTH: 0\r\n"));
        assert!(text.starts_with("POST /v1/FireTV/app/com.amazon.avod HTTP/1.1\r\n"));
    }

    /// The pairing answer and the refusal answer are the same envelope, which
    /// is why the caller and not the parser decides what the string means.
    #[test]
    fn the_description_envelope_is_read_the_same_either_way() {
        assert_eq!(description(r#"{"description":"OK"}"#).as_deref(), Some("OK"));
        assert_eq!(
            description(r#"{"description":"z-1_ydta2Qws1Y6hzaGrkw"}"#).as_deref(),
            Some("z-1_ydta2Qws1Y6hzaGrkw")
        );
        assert_eq!(description("not json"), None);
        assert_eq!(description(r#"{"other":"OK"}"#), None);
    }

    /// A `403` must not be relayed as a number. It has one cause — the pairing
    /// was removed on the television — and a person who is shown "403" has to
    /// go and find that out.
    #[test]
    fn a_lost_pairing_is_a_sentence_and_not_a_status() {
        let sentence = refusal(403, "");
        assert!(sentence.contains("paired again"), "{sentence}");
        assert!(!sentence.contains("403"), "{sentence}");
        // A 400 carries the device's own words, which are more specific.
        assert_eq!(
            refusal(400, r#"{"description":"Bad arguments supplied. Please check inputs."}"#),
            "Bad arguments supplied. Please check inputs."
        );
    }

    /// The port is appended when absent and respected when stated, so a test
    /// can point this at a loopback listener.
    #[test]
    fn the_remote_port_is_appended_only_when_absent() {
        assert_eq!(authority("192.168.1.12"), "192.168.1.12:8080");
        assert_eq!(authority("127.0.0.1:9999"), "127.0.0.1:9999");
    }
}
