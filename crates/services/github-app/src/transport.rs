//! A minimal outbound HTTPS client for `api.github.com`.
//!
//! **Known duplication, deliberately not resolved here.** `crates/net/acme/src/transport.rs`
//! already implements exactly this shape — TCP connect, `rustls` handshake with
//! the `ring` provider, a hand-written HTTP/1.1 request head, and a response
//! reader that drains `crates/foundation/http`'s three framings (fixed,
//! until-close, chunked). This module is a sibling of it, not a reuse of it: the
//! `acme` crate does not expose its client independent of [`selfhost-acme`'s
//! `AcmeError`], and extracting a shared client into `crates/foundation/http`
//! would mean either giving `crates/foundation/http` a socket (it is
//! deliberately pure — see that crate's own docs) or adding a new
//! `crates/net/tls-client`-shaped crate, both bigger moves than this increment
//! should make on its own. The two implementations should converge the next
//! time either one needs real changes — extracting a shared minimal-HTTPS-client
//! crate at that point is the better long-term shape. Tracked here rather than
//! silently accepted.
//!
//! Same connection policy as `acme`'s client: one connection per request
//! (`Connection: close`) — an App's own requests (mint a JWT, mint an
//! installation token) are low-volume, so keep-alive is not worth the state.

use std::sync::Arc;

use selfhost_http::{Headers, IncomingResponse, ParseError, ResponseFraming, Status};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::GithubAppError;

/// The most response bytes accepted from one exchange. GitHub's App API
/// responses are small (a token, an error object), so a reply growing past
/// this is a broken or hostile peer, not a real answer.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// One read from the socket.
const READ_CHUNK: usize = 8 * 1024;

/// A response, read whole into memory.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// The status code.
    pub status: Status,
    /// Every response header, in arrival order.
    pub headers: Headers,
    /// The decoded body, framing removed.
    pub body: Vec<u8>,
}

/// A reusable outbound HTTPS client, verifying servers against the bundled
/// Mozilla roots (never disabled) via the `ring` crypto provider named
/// explicitly, matching `acme`'s client.
#[derive(Clone)]
pub struct HttpsClient {
    config: Arc<rustls::ClientConfig>,
}

impl HttpsClient {
    /// Builds a client. Fails only if the TLS stack itself cannot be assembled.
    pub fn new() -> Result<Self, GithubAppError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| GithubAppError::Transport(error.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(Self { config: Arc::new(config) })
    }

    /// Issues a request against `host` (always port 443) for `path`, carrying
    /// `headers` and `body` (empty for a bodiless method).
    pub async fn request(
        &self,
        host: &str,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, GithubAppError> {
        let head = build_request(host, method, path, headers, body);

        let tcp = TcpStream::connect((host, 443))
            .await
            .map_err(|error| GithubAppError::Transport(error.to_string()))?;

        let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|error| GithubAppError::Transport(error.to_string()))?;

        let connector = TlsConnector::from(self.config.clone());
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|error| GithubAppError::Transport(error.to_string()))?;

        tls.write_all(&head).await.map_err(|error| GithubAppError::Transport(error.to_string()))?;
        if !body.is_empty() {
            tls.write_all(body).await.map_err(|error| GithubAppError::Transport(error.to_string()))?;
        }
        tls.flush().await.map_err(|error| GithubAppError::Transport(error.to_string()))?;

        read_response(&mut tls).await
    }
}

/// Serialises a request head. Framing fields (`Content-Length`, `Connection:
/// close`) are set here alone, so the declared length always matches what is
/// sent; `headers` (Authorization, Accept, ...) ride after them verbatim.
fn build_request(host: &str, method: &str, path: &str, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut head = Vec::new();
    head.extend_from_slice(method.as_bytes());
    head.push(b' ');
    head.extend_from_slice(path.as_bytes());
    head.extend_from_slice(b" HTTP/1.1\r\n");

    head.extend_from_slice(b"Host: ");
    head.extend_from_slice(host.as_bytes());
    head.extend_from_slice(b"\r\n");

    head.extend_from_slice(b"Accept-Encoding: identity\r\n");
    head.extend_from_slice(b"Connection: close\r\n");

    for (name, value) in headers {
        head.extend_from_slice(name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }

    if !body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
        head.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }

    head.extend_from_slice(b"\r\n");
    head
}

/// Reads a complete HTTP/1.1 response — head, then body per its framing.
async fn read_response<R>(stream: &mut R) -> Result<HttpResponse, GithubAppError>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();

    let parsed = loop {
        if !read_more(stream, &mut buffer).await? {
            return Err(GithubAppError::Transport(
                "connection closed before a response head arrived".into(),
            ));
        }
        match IncomingResponse::parse(&buffer) {
            Ok(parsed) => break parsed,
            Err(ParseError::Incomplete) => continue,
            Err(error) => return Err(GithubAppError::Transport(format!("malformed response: {error}"))),
        }
    };

    let head = parsed.response;
    let mut body = buffer.split_off(parsed.consumed);

    let body = match head.framing {
        ResponseFraming::None => Vec::new(),
        ResponseFraming::Fixed(length) => {
            let length = length as usize;
            while body.len() < length {
                if !read_more(stream, &mut body).await? {
                    return Err(GithubAppError::Transport(
                        "connection closed before the declared body length arrived".into(),
                    ));
                }
            }
            body.truncate(length);
            body
        }
        ResponseFraming::UntilClose => {
            while read_more(stream, &mut body).await? {}
            body
        }
        ResponseFraming::Chunked => loop {
            match selfhost_http::dechunk(&body) {
                Ok(decoded) => break decoded,
                Err(ParseError::Incomplete) => {
                    if !read_more(stream, &mut body).await? {
                        return Err(GithubAppError::Transport(
                            "connection closed in the middle of a chunked body".into(),
                        ));
                    }
                }
                Err(error) => {
                    return Err(GithubAppError::Transport(format!("malformed chunked body: {error}")));
                }
            }
        },
    };

    Ok(HttpResponse { status: head.status, headers: head.headers, body })
}

/// Appends one read from `stream` to `buffer`, enforcing the response cap.
async fn read_more<R>(stream: &mut R, buffer: &mut Vec<u8>) -> Result<bool, GithubAppError>
where
    R: AsyncRead + Unpin,
{
    let mut chunk = [0_u8; READ_CHUNK];
    let read =
        stream.read(&mut chunk).await.map_err(|error| GithubAppError::Transport(error.to_string()))?;
    if read == 0 {
        return Ok(false);
    }
    if buffer.len() + read > MAX_RESPONSE_BYTES {
        return Err(GithubAppError::Transport("response exceeded the maximum accepted size".into()));
    }
    buffer.extend_from_slice(&chunk[..read]);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn as_text(head: &[u8]) -> String {
        String::from_utf8(head.to_vec()).unwrap()
    }

    #[test]
    fn a_post_declares_bearer_header_and_length() {
        let headers = vec![
            ("Authorization".to_owned(), "Bearer abc".to_owned()),
            ("Accept".to_owned(), "application/vnd.github+json".to_owned()),
        ];
        let head = as_text(&build_request("api.github.com", "POST", "/app/installations/1/access_tokens", &headers, b""));
        assert!(head.starts_with("POST /app/installations/1/access_tokens HTTP/1.1\r\n"));
        assert!(head.contains("Host: api.github.com\r\n"));
        assert!(head.contains("Authorization: Bearer abc\r\n"));
        assert!(head.contains("Accept: application/vnd.github+json\r\n"));
        assert!(head.contains("Content-Length: 0\r\n"));
        assert!(head.contains("Connection: close\r\n"));
        assert!(head.ends_with("\r\n\r\n"));
    }

    #[tokio::test]
    async fn reads_a_fixed_length_body() {
        let mut source: &[u8] = b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\n\r\nhello";
        let response = read_response(&mut source).await.unwrap();
        assert_eq!(response.status, Status(201));
        assert_eq!(response.body, b"hello");
    }

    #[tokio::test]
    async fn a_closed_connection_before_the_head_is_an_error() {
        let mut source: &[u8] = b"HTTP/1.1 200 OK\r\n";
        let result = read_response(&mut source).await;
        assert!(matches!(result, Err(GithubAppError::Transport(_))));
    }
}
