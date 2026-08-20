//! One SOAP call, over one TCP connection, to a device on the household LAN.
//!
//! This module is the authority on what a UPnP control request *looks like on
//! the wire* and on what an answer from a speaker means. Everything above it —
//! the Sonos driver, the hub, the page — is allowed to think in actions and
//! arguments, and is never allowed to see a status line, a chunk header, or a
//! `<s:Fault>`; a UPnP fault code reaching a person is a failure of this layer,
//! which is why [`SoapError`] renders itself as a sentence rather than a
//! number.
//!
//! Three decisions here were measured against the real speakers rather than
//! reasoned about, and each of them is load-bearing:
//!
//! - **One connection per call.** The device answers `Connection: close`
//!   whatever the request asked for, and *resets* a socket that is used a
//!   second time. So there is no pool and no keep-alive: a pool here would not
//!   be an optimisation, it would be a fault every second call. Control traffic
//!   is a handful of requests per refresh, so the cost is a LAN handshake.
//! - **Two framings, not one.** A SOAP reply is `Content-Length` framed and a
//!   `GET /xml/*.xml` reply is `Transfer-Encoding: chunked`. Both come from the
//!   same speaker on the same port, so a reader that handles only the first
//!   works right up until discovery asks a device to describe itself.
//! - **A short deadline.** A speaker that has been unplugged, or a battery
//!   Move that has gone to sleep, does not refuse a connection — it goes quiet.
//!   Without a deadline the refresh of the whole house would hang on one
//!   absent device, so the timeouts below are treated as part of the protocol.
//!
//! There is nothing to reuse for the sending half: `selfhost_http` is pure by
//! charter and owns no socket. So the request bytes are written here and
//! everything above them is that crate's — [`IncomingResponse::parse`] decides
//! the framing and [`selfhost_http::dechunk`] decodes the chunked case, so this
//! module never re-implements a parser that has already been hardened.
//!
//! No authentication appears anywhere in this file, and that is correct rather
//! than missing: Sonos control is plaintext HTTP on port 1400 with no auth, no
//! TLS and no token, and the security model is the LAN gate in front of the
//! site — see the crate documentation.

use std::fmt;
use std::time::Duration;

use selfhost_http::{IncomingResponse, ParseError, ResponseFraming};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// The port every Sonos player serves its control and description endpoints on.
///
/// Named because it is appended to a bare address: the rest of the crate passes
/// speakers around as plain IP literals (`"192.168.1.6"`), which is what the
/// topology document and the registry both hold.
pub const PORT: u16 = 1400;

/// How long a connection may take to establish before the device counts as gone.
///
/// One second is generous on a switched LAN, where a present speaker completes
/// the handshake in single-digit milliseconds; the value exists for the case
/// that has no answer at all — a speaker that was unplugged, or a Move that
/// went to sleep — where the kernel would otherwise retry SYNs for over a
/// minute and stall the refresh of every other device behind it.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

/// How long the request-and-answer may take once the connection is up.
///
/// Two seconds covers the slowest measured reply by a wide margin (the whole
/// household topology comes back in well under a hundred milliseconds), and it
/// bounds the *whole* exchange rather than each read, so a device that dribbles
/// bytes cannot extend the deadline indefinitely. With the connect budget above
/// it, an absent speaker fails in at most three seconds — a refresh that pauses
/// for that long is tolerable, one that hangs is not.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(2);

/// The most response bytes accepted from one exchange.
///
/// A household topology is tens of kilobytes and a device description is under
/// ten, so a quarter of a megabyte is a hundredfold headroom. The cap is
/// enforced across every framing — fixed, chunked, and until-close — because a
/// device answering nonsense must cost a bounded amount of memory, not all of
/// it.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// One read from the socket. Sized to swallow a small reply head and body whole.
const READ_CHUNK: usize = 8 * 1024;

/// A UPnP action to invoke: which service, which action, and its arguments.
///
/// The arguments are a `Vec` of pairs rather than a map because UPnP is
/// **order-sensitive** — a device validates the child elements against the SCPD
/// in the order the service declares them — and because every value is already
/// a string on the wire, so a typed argument would only be converted back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call<'a> {
    /// The full service type URN, e.g. `urn:schemas-upnp-org:service:AVTransport:1`.
    ///
    /// It appears twice in one request — as the `u:` namespace of the body
    /// element and as the first half of the `SOAPACTION` header — so it is held
    /// once here and never spelled twice by a caller.
    pub service: &'a str,
    /// The action name, e.g. `Play`. Names the body element and the header.
    pub action: &'a str,
    /// The arguments, in the order the service's SCPD declares them.
    ///
    /// Values are owned because most are computed (a volume, a URI built from a
    /// coordinator's UUID) rather than literal, and escaping happens in
    /// [`envelope`] so no caller can forget it.
    pub args: Vec<(&'a str, String)>,
}

/// Everything that can go wrong between deciding to ask and having an answer.
///
/// Split five ways because the hub reacts differently to each: a [`Connect`]
/// failure marks a device unreachable, an [`Upnp`] fault means the device is
/// fine and the *request* was wrong, and a [`Malformed`] reply means neither.
/// Collapsing them into one string would leave the caller matching on prose.
///
/// [`Connect`]: SoapError::Connect
/// [`Upnp`]: SoapError::Upnp
/// [`Malformed`]: SoapError::Malformed
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SoapError {
    /// No connection could be made, or none was made in time: the device is off
    /// the network as far as this refresh is concerned.
    Connect(String),
    /// The connection was made and then failed — a reset, a timeout mid-answer,
    /// a close before the body arrived. Worth retrying; not proof of absence.
    Io(String),
    /// The device answered with an HTTP status that is neither 200 nor a UPnP
    /// fault. Carries the code because there is nothing else to say about it.
    Http(u16),
    /// The device answered HTTP 500 carrying `<errorCode>`: a real UPnP fault,
    /// which names a *reason* the request was refused.
    Upnp(u16),
    /// The answer arrived but could not be read as HTTP or as UPnP — a truncated
    /// body, a non-UTF-8 payload, a missing out-argument.
    Malformed(String),
}

impl fmt::Display for SoapError {
    /// Renders the failure as a sentence a person could be shown.
    ///
    /// The three UPnP codes spelled out here are the three that were actually
    /// observed from the speakers, and each is a case a person can act on: a
    /// missing `SOAPACTION` header (401), a transport asked to do something it
    /// cannot from where it is (701), and an instance other than zero (718).
    /// Anything else keeps its number, because inventing a sentence for a fault
    /// nobody has seen would be a guess presented as a fact.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SoapError::Connect(detail) => write!(formatter, "the device did not answer ({detail})"),
            SoapError::Io(detail) => write!(formatter, "the connection to the device failed ({detail})"),
            SoapError::Http(code) => write!(formatter, "the device answered HTTP {code}"),
            SoapError::Upnp(401) => {
                formatter.write_str("the device did not recognise that action")
            }
            SoapError::Upnp(701) => formatter.write_str(
                "the device cannot do that from where it is — there is nothing queued, or it is playing live radio",
            ),
            SoapError::Upnp(718) => {
                formatter.write_str("the device rejected the instance number; only instance 0 exists")
            }
            SoapError::Upnp(code) => {
                write!(formatter, "the device refused the request (UPnP error {code})")
            }
            SoapError::Malformed(detail) => {
                write!(formatter, "the device's answer could not be read ({detail})")
            }
        }
    }
}

impl std::error::Error for SoapError {}

/// The exact bytes of a SOAP request body for this call.
///
/// Pure, and the reason the rest of this module needs no live speaker to be
/// tested: the shape below is the one measured against a real player, verbatim,
/// down to the absence of whitespace between elements. Argument values are
/// escaped with [`crate::xml::escape`] here and nowhere else, so a track title
/// containing an ampersand cannot break out of its element.
///
/// A call with no arguments produces a self-closing body element, which is what
/// `GetZoneGroupState` was captured sending and accepting.
#[must_use]
pub fn envelope(call: &Call<'_>) -> String {
    let mut out = String::with_capacity(256);
    out.push_str(r#"<?xml version="1.0" encoding="utf-8"?>"#);
    out.push_str(
        r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">"#,
    );
    out.push_str("<s:Body><u:");
    out.push_str(call.action);
    out.push_str(r#" xmlns:u=""#);
    out.push_str(call.service);
    out.push('"');

    if call.args.is_empty() {
        out.push_str("/>");
    } else {
        out.push('>');
        for (name, value) in &call.args {
            out.push('<');
            out.push_str(name);
            out.push('>');
            out.push_str(&crate::xml::escape(value));
            out.push_str("</");
            out.push_str(name);
            out.push('>');
        }
        out.push_str("</u:");
        out.push_str(call.action);
        out.push('>');
    }

    out.push_str("</s:Body></s:Envelope>");
    out
}

/// The `SOAPACTION` header value, quotes included.
///
/// The quotes are not decoration: a request whose `SOAPACTION` is unquoted, or
/// absent, is answered with UPnP error 401 rather than being carried out. They
/// are part of the value here so no call site can build the header without them.
#[must_use]
pub fn soap_action(call: &Call<'_>) -> String {
    format!("\"{}#{}\"", call.service, call.action)
}

/// Invokes `call` at `path` on the device at `address`, returning the reply body.
///
/// `address` is a bare IP literal (port [`PORT`] is assumed) or an explicit
/// `host:port`. The returned string is the whole SOAP envelope; reading the
/// out-arguments out of it belongs to the driver, which knows their names.
///
/// A successful setter answers HTTP 200 with an *empty* response element —
/// there is no other success signal, so the empty string being returned is a
/// result and not a symptom.
pub async fn call(address: &str, path: &str, call: &Call<'_>) -> Result<String, SoapError> {
    let body = envelope(call);
    let request = post_request(&authority(address), path, &soap_action(call), &body);
    let (status, body) = exchange(address, &request).await?;

    match status {
        200 => Ok(body),
        // A fault is an HTTP 500 whose body carries the real reason. Reading it
        // is what turns "the speaker said 500" into "there is nothing queued".
        500 => Err(match crate::xml::element(&body, "errorCode")
            .and_then(|code| code.trim().parse::<u16>().ok())
        {
            Some(code) => SoapError::Upnp(code),
            None => SoapError::Http(500),
        }),
        other => Err(SoapError::Http(other)),
    }
}

/// Fetches a document from the device by `GET`, returning its body.
///
/// This exists for `/xml/device_description.xml`, which is how a speaker states
/// its room name, model and UUID before anything else is known about it. It is
/// a separate entry point rather than a flag on [`call`] because the reply is
/// chunked rather than length-framed and carries no SOAP envelope at all.
pub async fn get(address: &str, path: &str) -> Result<String, SoapError> {
    let request = get_request(&authority(address), path);
    let (status, body) = exchange(address, &request).await?;
    if status == 200 {
        Ok(body)
    } else {
        Err(SoapError::Http(status))
    }
}

/// Opens a connection, sends `request`, and reads the whole answer.
///
/// The single place a socket is opened, which is what keeps "one connection per
/// call" a property of the module rather than a habit of its callers. Both
/// deadlines live here: one on the handshake, one on everything after it.
async fn exchange(address: &str, request: &[u8]) -> Result<(u16, String), SoapError> {
    let (status, _, body) = http(address, request).await?;
    Ok((status, body))
}

/// One raw HTTP exchange, headers included, for a sibling driver.
///
/// SOAP callers never read a response header, so [`exchange`] drops them; DIAL
/// (`crate::dial`) rides the same transport and its one navigational fact —
/// the `Application-URL` a television states over its device description —
/// arrives *only* as a header. This entry point exists so that driver reuses
/// this module's connect, deadline and framing discipline instead of growing a
/// second copy of it. The request bytes are the caller's, already serialised,
/// because each protocol's request shape belongs to its own module.
pub(crate) async fn http(
    address: &str,
    request: &[u8],
) -> Result<(u16, selfhost_http::Headers, String), SoapError> {
    let authority = authority(address);

    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(&authority))
        .await
        .map_err(|_| SoapError::Connect(format!("no connection to {authority} within {CONNECT_TIMEOUT:?}")))?
        .map_err(|error| SoapError::Connect(error.to_string()))?;

    timeout(EXCHANGE_TIMEOUT, async move {
        let mut stream = stream;
        stream.write_all(request).await.map_err(|error| SoapError::Io(error.to_string()))?;
        stream.flush().await.map_err(|error| SoapError::Io(error.to_string()))?;
        let (status, headers, body) = read_response(&mut stream).await?;
        let body = String::from_utf8(body)
            .map_err(|_| SoapError::Malformed("the body was not UTF-8".to_owned()))?;
        Ok((status, headers, body))
    })
    .await
    .map_err(|_| SoapError::Io(format!("no answer from {authority} within {EXCHANGE_TIMEOUT:?}")))?
}

/// The `host:port` to connect to and to put in the `Host` header.
///
/// Speakers are held as bare IPv4 literals everywhere else in the crate, so the
/// common case is appending [`PORT`]. An address that already names a port is
/// passed through, which is what makes a test able to point this at a loopback
/// listener. IPv6 is not handled: every device this drives is reached by the
/// IPv4 literal its own topology document publishes.
fn authority(address: &str) -> String {
    if address.contains(':') {
        address.to_owned()
    } else {
        format!("{address}:{PORT}")
    }
}

/// Serialises the `POST` that carries a SOAP body.
///
/// Written by hand because `selfhost_http` deliberately has no request encoder.
/// `Content-Length` is derived from the same `&str` that is appended below it,
/// in **bytes** and not characters, so a track title outside ASCII cannot make
/// the declared length disagree with what is sent — a mismatch the device
/// answers by hanging until the read deadline rather than by complaining.
fn post_request(authority: &str, path: &str, soap_action: &str, body: &str) -> Vec<u8> {
    let mut request = String::with_capacity(body.len() + 256);
    request.push_str("POST ");
    request.push_str(path);
    request.push_str(" HTTP/1.1\r\n");
    request.push_str("HOST: ");
    request.push_str(authority);
    request.push_str("\r\n");
    // The device accepts a request without a Content-Type, but the UPnP
    // specification requires one and sending it costs nothing.
    request.push_str("CONTENT-TYPE: text/xml; charset=\"utf-8\"\r\n");
    request.push_str("SOAPACTION: ");
    request.push_str(soap_action);
    request.push_str("\r\n");
    request.push_str(&format!("CONTENT-LENGTH: {}\r\n", body.len()));
    // Stated rather than assumed: the device closes regardless, and saying so
    // keeps this end's expectation and the wire in agreement.
    request.push_str("CONNECTION: close\r\n\r\n");
    request.push_str(body);
    request.into_bytes()
}

/// Serialises the bodiless `GET` used for the description document.
fn get_request(authority: &str, path: &str) -> Vec<u8> {
    let mut request = String::with_capacity(128);
    request.push_str("GET ");
    request.push_str(path);
    request.push_str(" HTTP/1.1\r\n");
    request.push_str("HOST: ");
    request.push_str(authority);
    request.push_str("\r\n");
    // Ask for identity bytes: the reader below hands back what it was sent and
    // knows nothing about content codings.
    request.push_str("ACCEPT-ENCODING: identity\r\n");
    request.push_str("CONNECTION: close\r\n\r\n");
    request.into_bytes()
}

/// Reads one complete HTTP/1.1 response: the head, then the body its framing says.
///
/// Generic over [`AsyncRead`] rather than taking a [`TcpStream`], so every
/// framing the speakers use can be exercised from a byte slice with no socket,
/// no speaker, and no network in the test sandbox. Enforces
/// [`MAX_RESPONSE_BYTES`] in every branch.
///
/// Visible to the crate for the same reason [`http`] is: `crate::firetv`
/// speaks HTTP/1.1 to a television, but over TLS, so it cannot ride [`http`]'s
/// socket — it brings its own stream and borrows this framing rather than
/// growing a second copy of chunked-transfer decoding. Being generic over the
/// stream is what makes that free.
pub(crate) async fn read_response<R>(
    stream: &mut R,
) -> Result<(u16, selfhost_http::Headers, Vec<u8>), SoapError>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();

    // Read until the head parses: `Incomplete` means the blank line has not
    // arrived yet, and anything else means the answer is not HTTP.
    let parsed = loop {
        if !read_more(stream, &mut buffer).await? {
            return Err(SoapError::Io("the device closed before answering".to_owned()));
        }
        match IncomingResponse::parse(&buffer) {
            Ok(parsed) => break parsed,
            Err(ParseError::Incomplete) => continue,
            Err(error) => return Err(SoapError::Malformed(error.to_string())),
        }
    };

    let head = parsed.response;
    // Whatever was read past the head is already the start of the body.
    let mut body = buffer.split_off(parsed.consumed);

    let body = match head.framing {
        ResponseFraming::None => Vec::new(),
        // What a SOAP reply uses.
        ResponseFraming::Fixed(length) => {
            let length = usize::try_from(length)
                .map_err(|_| SoapError::Malformed("an absurd Content-Length".to_owned()))?;
            if length > MAX_RESPONSE_BYTES {
                return Err(SoapError::Malformed("the answer exceeded the accepted size".to_owned()));
            }
            while body.len() < length {
                if !read_more(stream, &mut body).await? {
                    return Err(SoapError::Io(
                        "the device closed before the declared body arrived".to_owned(),
                    ));
                }
            }
            body.truncate(length);
            body
        }
        // What `GET /xml/*.xml` uses.
        ResponseFraming::Chunked => loop {
            match selfhost_http::dechunk(&body) {
                Ok(decoded) => break decoded,
                Err(ParseError::Incomplete) => {
                    if !read_more(stream, &mut body).await? {
                        return Err(SoapError::Io(
                            "the device closed inside a chunked body".to_owned(),
                        ));
                    }
                }
                Err(error) => return Err(SoapError::Malformed(error.to_string())),
            }
        },
        ResponseFraming::UntilClose => {
            while read_more(stream, &mut body).await? {}
            body
        }
    };

    Ok((head.status.code(), head.headers, body))
}

/// Appends one read to `buffer`, enforcing the size cap. `false` at end of stream.
async fn read_more<R>(stream: &mut R, buffer: &mut Vec<u8>) -> Result<bool, SoapError>
where
    R: AsyncRead + Unpin,
{
    let mut chunk = [0_u8; READ_CHUNK];
    let read = stream
        .read(&mut chunk)
        .await
        .map_err(|error| SoapError::Io(error.to_string()))?;
    if read == 0 {
        return Ok(false);
    }
    if buffer.len() + read > MAX_RESPONSE_BYTES {
        return Err(SoapError::Malformed("the answer exceeded the accepted size".to_owned()));
    }
    buffer.extend_from_slice(&chunk[..read]);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call_of<'a>(action: &'a str, args: &[(&'a str, &str)]) -> Call<'a> {
        Call {
            service: "urn:schemas-upnp-org:service:AVTransport:1",
            action,
            args: args.iter().map(|(name, value)| (*name, (*value).to_owned())).collect(),
        }
    }

    /// The shape below is the one a real speaker was measured accepting. It is
    /// asserted whole rather than in pieces because every part of it — the XML
    /// declaration, the `encodingStyle` attribute, the absence of whitespace —
    /// was present in the request that worked.
    #[test]
    fn the_envelope_is_the_measured_shape_byte_for_byte() {
        let call = call_of("Play", &[("InstanceID", "0"), ("Speed", "1")]);
        assert_eq!(
            envelope(&call),
            concat!(
                r#"<?xml version="1.0" encoding="utf-8"?>"#,
                r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" "#,
                r#"s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">"#,
                r#"<s:Body><u:Play xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">"#,
                r#"<InstanceID>0</InstanceID><Speed>1</Speed>"#,
                r#"</u:Play></s:Body></s:Envelope>"#,
            )
        );
    }

    #[test]
    fn arguments_keep_the_order_they_were_given() {
        let call = call_of("SetVolume", &[("InstanceID", "0"), ("Channel", "Master"), ("DesiredVolume", "9")]);
        let body = envelope(&call);
        let instance = body.find("<InstanceID>").unwrap();
        let channel = body.find("<Channel>").unwrap();
        let volume = body.find("<DesiredVolume>").unwrap();
        assert!(instance < channel && channel < volume);
    }

    /// `GetZoneGroupState` takes no arguments and was captured as a self-closing
    /// body element; a caller that passes no arguments must produce exactly that.
    #[test]
    fn an_argumentless_action_has_a_self_closing_body_element() {
        let call = Call {
            service: "urn:schemas-upnp-org:service:ZoneGroupTopology:1",
            action: "GetZoneGroupState",
            args: Vec::new(),
        };
        assert!(envelope(&call).contains(
            r#"<s:Body><u:GetZoneGroupState xmlns:u="urn:schemas-upnp-org:service:ZoneGroupTopology:1"/></s:Body>"#
        ));
    }

    /// A station name with an ampersand in it must not be able to close its own
    /// element: this is the difference between a request and a broken parser at
    /// the far end.
    #[test]
    fn an_argument_value_is_escaped() {
        let call = call_of("SetAVTransportURI", &[("CurrentURI", "x-rincon-mp3radio://a?b=1&c=<2>")]);
        assert!(envelope(&call).contains("<CurrentURI>x-rincon-mp3radio://a?b=1&amp;c=&lt;2&gt;</CurrentURI>"));
    }

    /// Unquoted or absent, this header is answered with UPnP error 401 rather
    /// than being carried out, so the quotes are asserted explicitly.
    #[test]
    fn the_soap_action_header_is_quoted() {
        let call = call_of("Pause", &[("InstanceID", "0")]);
        assert_eq!(
            soap_action(&call),
            "\"urn:schemas-upnp-org:service:AVTransport:1#Pause\""
        );
    }

    #[test]
    fn a_bare_address_gains_the_control_port() {
        assert_eq!(authority("192.168.1.6"), "192.168.1.6:1400");
        assert_eq!(authority("192.168.1.6:1400"), "192.168.1.6:1400");
        assert_eq!(authority("127.0.0.1:9999"), "127.0.0.1:9999");
    }

    /// The declared length must be the length in bytes. A title outside ASCII
    /// makes characters and bytes disagree, and the device answers a short body
    /// by waiting for the rest until the deadline expires.
    #[test]
    fn the_content_length_counts_bytes_not_characters() {
        let body = "<x>Sigur Rós</x>";
        assert_ne!(body.chars().count(), body.len());
        let request = post_request("192.168.1.6:1400", "/p", "\"svc#Act\"", body);
        let text = String::from_utf8(request).unwrap();
        assert!(text.contains(&format!("CONTENT-LENGTH: {}\r\n", body.len())));
        assert!(text.ends_with(body));
    }

    #[test]
    fn the_post_head_carries_host_action_and_close() {
        let request = post_request("192.168.1.17:1400", "/MediaRenderer/AVTransport/Control", "\"svc#Play\"", "<b/>");
        let text = String::from_utf8(request).unwrap();
        assert!(text.starts_with("POST /MediaRenderer/AVTransport/Control HTTP/1.1\r\n"));
        assert!(text.contains("HOST: 192.168.1.17:1400\r\n"));
        assert!(text.contains("SOAPACTION: \"svc#Play\"\r\n"));
        assert!(text.contains("CONNECTION: close\r\n"));
    }

    #[test]
    fn the_get_head_is_bodiless() {
        let text = String::from_utf8(get_request("192.168.1.6:1400", "/xml/device_description.xml")).unwrap();
        assert!(text.starts_with("GET /xml/device_description.xml HTTP/1.1\r\n"));
        assert!(!text.contains("CONTENT-LENGTH"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    /// Reads straight from a slice: `&[u8]` is an `AsyncRead`, so both framings
    /// are exercised with no speaker in reach of the sandbox.
    async fn read(raw: &[u8]) -> Result<(u16, String), SoapError> {
        let mut source = raw;
        let (status, _, body) = read_response(&mut source).await?;
        Ok((status, String::from_utf8(body).unwrap()))
    }

    #[tokio::test]
    async fn a_length_framed_soap_reply_is_read() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\n<Empty>";
        assert_eq!(read(response).await.unwrap(), (200, "<Empty>".to_owned()));
    }

    /// The description document arrives chunked from the same speaker on the
    /// same port as the length-framed SOAP replies. A reader that handles only
    /// one framing works until discovery asks a device to describe itself.
    #[tokio::test]
    async fn a_chunked_document_is_read() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\n<root>ok</\r\n6\r\nroot>\n\r\n0\r\n\r\n";
        assert_eq!(read(response).await.unwrap().1, "<root>ok</root>\n");
    }

    #[tokio::test]
    async fn a_body_cut_short_is_an_io_failure_not_a_short_answer() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\ntoo short";
        assert!(matches!(read(response).await, Err(SoapError::Io(_))));
    }

    #[tokio::test]
    async fn a_reply_that_is_not_http_is_malformed() {
        assert!(matches!(read(b"\x00\x01 not http\r\n\r\n").await, Err(SoapError::Malformed(_))));
    }

    /// The captured fault: HTTP 500 whose body names the reason. Reading the
    /// code is what lets the layer above say "nothing is queued" instead of
    /// showing a person the number 701.
    #[test]
    fn a_fault_body_yields_its_error_code() {
        let body = concat!(
            r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault>"#,
            r#"<faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>"#,
            r#"<UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>701</errorCode></UPnPError>"#,
            r#"</detail></s:Fault></s:Body></s:Envelope>"#,
        );
        let code = crate::xml::element(body, "errorCode").and_then(|c| c.trim().parse::<u16>().ok());
        assert_eq!(code, Some(701));
    }

    #[test]
    fn the_three_observed_faults_read_as_sentences() {
        for code in [401_u16, 701, 718] {
            let sentence = SoapError::Upnp(code).to_string();
            assert!(!sentence.contains(&code.to_string()), "{code} leaked its number");
            assert!(sentence.starts_with("the device"));
        }
        // An unobserved code keeps its number rather than being given invented prose.
        assert!(SoapError::Upnp(402).to_string().contains("402"));
    }
}
