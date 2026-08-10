//! A blocking HTTP client for the daemon's control API.
//!
//! Blocking, and on its own thread, on purpose. The console's other option was
//! an async runtime, which would buy nothing: there is one connection, to one
//! daemon, carrying a request every half second. What it would cost is a second
//! scheduler inside a program that already has one — the frame loop.
//!
//! One request per connection, matching what the API does at its end. Reusing a
//! connection would save a handshake over loopback, which is not a cost worth
//! the possibility of two responses disagreeing about where one ends.

use selfhost_http::{IncomingResponse, ParseError, ResponseFraming, Status};
use selfhost_json::Json;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// How long to wait for the daemon to accept a connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// How long to wait for a request to be answered.
///
/// Generous compared with what a loopback request takes, because a tunnelled
/// connection over a slow link is the same request over a much longer wire.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest **control-plane** response body accepted.
///
/// A log fetch is the biggest thing the control API is asked for, and it is
/// bounded by the number of lines requested. A reply approaching this is a
/// daemon that is not the one we think we are talking to.
///
/// A file is not a control-plane answer and is not held to this — see
/// [`Client::fetch`], which passes [`crate::nas::MAX_TRANSFER`] instead. The two
/// are separate numbers on purpose: raising one to let a film through would
/// raise the other, and the control plane's ceiling is the thing that catches a
/// daemon answering with something it should not.
const MAX_BODY: usize = 8 * 1024 * 1024;

/// Why a request did not produce an answer.
#[derive(Debug)]
pub enum ClientError {
    /// The daemon could not be reached at all.
    Unreachable(std::io::Error),
    /// The connection failed part way through.
    Io(std::io::Error),
    /// The reply was not a response this client can read.
    Protocol(String),
    /// The daemon answered, and said no.
    Refused {
        /// The status it answered with.
        status: Status,
        /// What it said was wrong.
        message: String,
    },
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(error) => write!(formatter, "cannot reach the daemon: {error}"),
            Self::Io(error) => write!(formatter, "the connection failed: {error}"),
            Self::Protocol(message) => write!(formatter, "unexpected reply: {message}"),
            Self::Refused { status, message } => {
                write!(formatter, "the daemon refused ({}): {message}", status.code())
            }
        }
    }
}

impl std::error::Error for ClientError {}

impl ClientError {
    /// Whether this means the daemon is not there, as opposed to unhappy.
    ///
    /// The distinction drives what the console shows: a daemon that refused a
    /// command is still connected, and dropping the whole interface to a
    /// "disconnected" state because one action failed would hide everything the
    /// operator was looking at.
    pub fn is_disconnection(&self) -> bool {
        matches!(self, Self::Unreachable(_) | Self::Io(_))
    }
}

/// The methods this client uses.
///
/// A closed set rather than a string, so a typo is a compile error and the
/// request line cannot be built from unvalidated text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Read.
    Get,
    /// Act.
    Post,
    /// Install or replace.
    Put,
    /// Uninstall.
    Delete,
}

impl Method {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

/// What one request came back as, refusal and all.
///
/// Three arms rather than a `Result`, because a refusal and a failure are not
/// the same event and the caller that wants this distinguishes them: the daemon
/// answering *no, and here is why in structured form* is a fact to render, and a
/// socket that would not open is a fact about the link.
#[derive(Debug)]
pub enum Answer {
    /// The daemon agreed, and this is what it said.
    Ok(Json),
    /// The daemon refused, and this is the whole body it refused with.
    Refused {
        /// The status it answered with.
        status: Status,
        /// Its body, parsed, or [`Json::Null`] when there was none.
        body: Json,
    },
    /// The request never got an answer.
    Failed(ClientError),
}

/// A connection to one daemon's control API.
#[derive(Debug, Clone)]
pub struct Client {
    address: SocketAddr,
    token: String,
}

impl Client {
    /// A client for the daemon at `address`, authenticating with `token`.
    ///
    /// The token is checked for the bytes that would let it inject a second
    /// header field. It comes from a file on disk, and a file on disk is input.
    pub fn new(address: SocketAddr, token: String) -> Result<Self, String> {
        let token = token.trim().to_owned();
        if token.is_empty() {
            return Err("the admin token is empty".into());
        }
        if token.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
            return Err("the admin token contains control characters".into());
        }
        Ok(Self { address, token })
    }

    /// Where this client's daemon is.
    ///
    /// Read by [`crate::channel`], which opens its own socket to the same place
    /// rather than borrowing this one: a desktop stream is held open for hours
    /// and this client's whole design is one request per connection.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The bearer credential, for the one caller that builds its own request.
    ///
    /// Deliberately narrow. It exists because a WebSocket handshake is written
    /// by hand — no other request in this program is — and the alternative was
    /// a second copy of the token read from the same file, which is a second
    /// thing to keep in step and a second thing to leak.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Sends a request and reads the JSON it answers with.
    pub fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&Json>,
    ) -> Result<Json, ClientError> {
        let body = body.map(|value| value.to_text().into_bytes()).unwrap_or_default();
        let content_type = (!body.is_empty()).then_some("application/json");
        let (status, payload) = self.exchange(method, path, content_type, &body, "application/json")?;
        let text = std::str::from_utf8(&payload)
            .map_err(|_| ClientError::Protocol("the body is not UTF-8".into()))?;
        let value = if text.trim().is_empty() {
            Json::Null
        } else {
            selfhost_json::parse(text)
                .map_err(|error| ClientError::Protocol(format!("bad JSON: {error}")))?
        };

        if (200..300).contains(&status.code()) {
            return Ok(value);
        }
        // The API puts its explanation in `error`; falling back to the status's
        // own phrase keeps the message useful if it ever does not.
        let message = value
            .get("error")
            .and_then(Json::as_str)
            .unwrap_or_else(|| status.reason())
            .to_owned();
        Err(ClientError::Refused { status, message })
    }

    /// Sends a request and hands the refusal back **whole**.
    ///
    /// # Why one route needs the body of a refusal
    ///
    /// [`ClientError::Refused`] keeps the daemon's `error` string, which is all
    /// every other call in this console has ever wanted. The desktop ticket mint
    /// is the exception: `crates/admin` deliberately answers it with a *legible*
    /// refusal — `reauthenticate` with the window in seconds, or `setting` with
    /// the name of the switch that is off — and those two fields are the whole
    /// difference between "authenticate again" and "no credential will ever
    /// help". Flattening them to a sentence would throw away the only thing that
    /// tells a person which of the two they are looking at.
    pub fn ask(&self, method: Method, path: &str, body: Option<&Json>) -> Answer {
        let body = body.map(|value| value.to_text().into_bytes()).unwrap_or_default();
        let content_type = (!body.is_empty()).then_some("application/json");
        let answered = self.exchange(method, path, content_type, &body, "application/json");
        let (status, payload) = match answered {
            Ok(answered) => answered,
            Err(error) => return Answer::Failed(error),
        };
        let value = std::str::from_utf8(&payload)
            .ok()
            .filter(|text| !text.trim().is_empty())
            .and_then(|text| selfhost_json::parse(text).ok())
            .unwrap_or(Json::Null);
        if (200..300).contains(&status.code()) {
            Answer::Ok(value)
        } else {
            Answer::Refused { status, body: value }
        }
    }

    /// Reads a resource.
    pub fn get(&self, path: &str) -> Result<Json, ClientError> {
        self.request(Method::Get, path, None)
    }

    /// Asks for an action.
    pub fn post(&self, path: &str) -> Result<Json, ClientError> {
        self.request(Method::Post, path, None)
    }

    /// Installs or replaces a resource.
    pub fn put(&self, path: &str, body: &Json) -> Result<Json, ClientError> {
        self.request(Method::Put, path, Some(body))
    }

    /// Removes a resource.
    pub fn delete(&self, path: &str) -> Result<Json, ClientError> {
        self.request(Method::Delete, path, None)
    }

    /// Fetches a resource as bytes rather than as JSON.
    ///
    /// The download half of the FILES plate. Kept apart from [`Client::get`]
    /// because a file is not a document this program understands: it is opaque,
    /// it goes straight to a path the operator named, and parsing it as JSON
    /// would be both wrong and — on a large file — expensive before it failed.
    ///
    /// **The whole body lands in memory**, which is why [`crate::nas::MAX_TRANSFER`]
    /// exists and is checked before the request is made. Streaming to the
    /// destination file as the bytes arrive is the right end state and is worth
    /// a note rather than a half-built one: it needs a second read loop that
    /// owns the destination, and the ceiling makes the difference an operator
    /// notices only above half a gigabyte.
    pub fn fetch(&self, path: &str) -> Result<Vec<u8>, ClientError> {
        let ceiling = usize::try_from(crate::nas::MAX_TRANSFER).unwrap_or(MAX_BODY);
        let (status, payload) =
            self.exchange_within(Method::Get, path, None, &[], "*/*", ceiling)?;
        if (200..300).contains(&status.code()) {
            return Ok(payload);
        }
        Err(self.refusal(status, &payload))
    }

    /// Sends bytes to a resource, with the content type the caller declares.
    ///
    /// The upload half. The daemon's bulk plane takes the body as it is, framed
    /// by `Content-Length`, and answers JSON — so the refusal path is the same
    /// one every other call in this client uses and the success path carries
    /// whatever the storage API chose to say about where the bytes landed.
    pub fn send(&self, path: &str, content_type: &str, body: &[u8]) -> Result<Json, ClientError> {
        let (status, payload) = self.exchange(Method::Put, path, Some(content_type), body, "application/json")?;
        if (200..300).contains(&status.code()) {
            let text = std::str::from_utf8(&payload).unwrap_or_default();
            return Ok(if text.trim().is_empty() {
                Json::Null
            } else {
                selfhost_json::parse(text).unwrap_or(Json::Null)
            });
        }
        Err(self.refusal(status, &payload))
    }

    /// One round trip: a head, an optional body, and whatever came back.
    ///
    /// The single place a request is built, so the credential, the framing and
    /// the deadlines are stated once however the body is going to be read.
    fn exchange(
        &self,
        method: Method,
        path: &str,
        content_type: Option<&str>,
        body: &[u8],
        accept: &str,
    ) -> Result<(Status, Vec<u8>), ClientError> {
        self.exchange_within(method, path, content_type, body, accept, MAX_BODY)
    }

    /// The same round trip, with the ceiling the caller is prepared to hold.
    ///
    /// The ceiling is a parameter because the two planes have genuinely
    /// different ones: eight megabytes is generous for a control answer and
    /// absurd for a file, and one number serving both would have to be the
    /// larger — which would stop the control plane from ever noticing that
    /// something other than the daemon is answering on this port.
    fn exchange_within(
        &self,
        method: Method,
        path: &str,
        content_type: Option<&str>,
        body: &[u8],
        accept: &str,
        ceiling: usize,
    ) -> Result<(Status, Vec<u8>), ClientError> {
        let mut stream = TcpStream::connect_timeout(&self.address, CONNECT_TIMEOUT)
            .map_err(ClientError::Unreachable)?;
        stream.set_read_timeout(Some(REQUEST_TIMEOUT)).map_err(ClientError::Io)?;
        stream.set_write_timeout(Some(REQUEST_TIMEOUT)).map_err(ClientError::Io)?;
        // One small request; batching it into one write avoids a needless round
        // trip caused by the head and the body landing in separate segments.
        stream.set_nodelay(true).map_err(ClientError::Io)?;

        let mut request = Vec::with_capacity(256 + body.len());
        request.extend_from_slice(method.as_str().as_bytes());
        request.extend_from_slice(b" ");
        request.extend_from_slice(path.as_bytes());
        request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        request.extend_from_slice(self.address.to_string().as_bytes());
        request.extend_from_slice(b"\r\nAuthorization: Bearer ");
        request.extend_from_slice(self.token.as_bytes());
        request.extend_from_slice(b"\r\nAccept: ");
        request.extend_from_slice(accept.as_bytes());
        request.extend_from_slice(b"\r\nConnection: close\r\n");
        if let Some(content_type) = content_type {
            request.extend_from_slice(b"Content-Type: ");
            request.extend_from_slice(content_type.as_bytes());
            request.extend_from_slice(b"\r\nContent-Length: ");
            request.extend_from_slice(body.len().to_string().as_bytes());
            request.extend_from_slice(b"\r\n");
        }
        request.extend_from_slice(b"\r\n");
        request.extend_from_slice(body);

        stream.write_all(&request).map_err(ClientError::Io)?;
        stream.flush().map_err(ClientError::Io)?;
        read_response(&mut stream, ceiling)
    }

    /// A non-success answer as a refusal, with whatever explanation it carried.
    ///
    /// A bulk route answers JSON on the way *out* even when the way in was
    /// bytes, so the same `error` field every other refusal carries is read
    /// here too; a body that is not JSON falls back to the status's own phrase.
    fn refusal(&self, status: Status, payload: &[u8]) -> ClientError {
        let message = std::str::from_utf8(payload)
            .ok()
            .and_then(|text| selfhost_json::parse(text).ok())
            .as_ref()
            .and_then(|value| value.get("error"))
            .and_then(Json::as_str)
            .unwrap_or_else(|| status.reason())
            .to_owned();
        ClientError::Refused { status, message }
    }
}

/// Reads one response: the head, then exactly the body it framed.
///
/// `ceiling` bounds what this end is prepared to hold in memory. It is checked
/// against the *declared* length before a byte of body is read and again as the
/// bytes arrive, because a peer that lies about a length and a peer that simply
/// keeps sending are two different ways to make this process allocate — and
/// under `panic = "abort"` an allocation that fails is not an error, it is the
/// console going away.
fn read_response(stream: &mut TcpStream, ceiling: usize) -> Result<(Status, Vec<u8>), ClientError> {
    let mut buffer = Vec::with_capacity(4096);
    let mut scratch = [0u8; 4096];

    let (head, consumed) = loop {
        match IncomingResponse::parse(&buffer) {
            Ok(parsed) => break (parsed.response, parsed.consumed),
            Err(ParseError::Incomplete) => {
                let read = stream.read(&mut scratch).map_err(ClientError::Io)?;
                if read == 0 {
                    return Err(ClientError::Protocol(
                        "the daemon closed the connection before answering".into(),
                    ));
                }
                buffer.extend_from_slice(&scratch[..read]);
                if buffer.len() > ceiling {
                    return Err(ClientError::Protocol("the response head is too large".into()));
                }
            }
            Err(error) => return Err(ClientError::Protocol(error.to_string())),
        }
    };

    let mut body = buffer.split_off(consumed);
    match head.framing {
        ResponseFraming::None => body.clear(),
        ResponseFraming::Fixed(length) => {
            let length = length as usize;
            if length > ceiling {
                return Err(ClientError::Protocol("the response is too large".into()));
            }
            while body.len() < length {
                let read = stream.read(&mut scratch).map_err(ClientError::Io)?;
                if read == 0 {
                    return Err(ClientError::Protocol("the response body ended early".into()));
                }
                body.extend_from_slice(&scratch[..read]);
            }
            body.truncate(length);
        }
        ResponseFraming::UntilClose => {
            loop {
                let read = stream.read(&mut scratch).map_err(ClientError::Io)?;
                if read == 0 {
                    break;
                }
                body.extend_from_slice(&scratch[..read]);
                if body.len() > ceiling {
                    return Err(ClientError::Protocol("the response is too large".into()));
                }
            }
        }
        // The control API always sends a length, so this would mean we are
        // talking to something else. Saying so is more useful than writing a
        // dechunker for a case that should never arrive.
        ResponseFraming::Chunked => {
            return Err(ClientError::Protocol(
                "the reply used chunked framing, which the control API never does — \
                 is something else listening on this port?"
                    .into(),
            ));
        }
    }

    Ok((head.status, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> SocketAddr {
        "127.0.0.1:9191".parse().expect("a valid address")
    }

    #[test]
    fn a_token_that_could_inject_a_header_is_refused() {
        for bad in ["abc\r\nX-Evil: yes", "abc\ndef", "abc\0def"] {
            assert!(
                Client::new(address(), bad.into()).is_err(),
                "accepted a token containing control characters: {bad:?}"
            );
        }
    }

    #[test]
    fn an_empty_token_is_refused() {
        assert!(Client::new(address(), String::new()).is_err());
        assert!(Client::new(address(), "   \n".into()).is_err());
    }

    #[test]
    fn surrounding_whitespace_is_trimmed_from_a_token() {
        let client = Client::new(address(), "  deadbeef\n".into()).expect("a valid token");
        assert_eq!(client.token, "deadbeef");
    }

    #[test]
    fn methods_name_themselves_exactly_as_the_wire_wants() {
        assert_eq!(Method::Get.as_str(), "GET");
        assert_eq!(Method::Delete.as_str(), "DELETE");
    }

    #[test]
    fn a_missing_daemon_reads_as_a_disconnection_and_a_refusal_does_not() {
        let unreachable =
            ClientError::Unreachable(std::io::Error::other("connection refused"));
        assert!(unreachable.is_disconnection());

        let refused = ClientError::Refused {
            status: Status(404),
            message: "no such service".into(),
        };
        assert!(!refused.is_disconnection());
        assert!(refused.to_string().contains("no such service"));
    }
}
