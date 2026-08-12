//! The outbound HTTPS client the ACME core speaks over.
//!
//! There is nothing to reuse for the sending half: `crates/http` is pure by
//! charter and holds no socket. So this module owns the socket and the request
//! bytes, and reuses `crates/http` for everything above them — [`Status`] and
//! [`Headers`] come back exactly as parsed, and the response body is drained by
//! the framing [`selfhost_http::IncomingResponse::parse`] already decided
//! ([`selfhost_http::dechunk`] handles the chunked case).
//!
//! Server certificates are verified against the bundled Mozilla roots
//! ([`webpki_roots`]) — verification is never disabled. The provider is `ring`,
//! chosen explicitly so this does not depend on a process-wide default being
//! installed first, and ALPN advertises `http/1.1` to match `proxy::tls`.
//!
//! One connection per request (`Connection: close`), mirroring the proxy's
//! upstream `forward`: ACME is low volume and keep-alive is not worth the state.

use std::sync::Arc;

use selfhost_http::{Headers, IncomingResponse, ParseError, ResponseFraming, Status};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::AcmeError;

/// The most response bytes accepted from one exchange.
///
/// ACME responses are small (a directory, an order, a certificate chain), so a
/// reply that keeps growing past this is a broken or hostile peer, not a real
/// answer. The cap bounds every framing — fixed, until-close, and chunked — so
/// none of them can be made to buffer without limit.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// One read from the socket. Sized to swallow a whole small response head at once.
const READ_CHUNK: usize = 8 * 1024;

/// The default port for `https`.
const HTTPS_PORT: u16 = 443;

/// An absolute `https` URL, split into the parts a request needs.
///
/// The project's dependency policy rules out a URL crate, and ACME URLs are
/// always `https` with a DNS host, so this parses only that shape. IPv6 literals
/// and userinfo are refused rather than half-handled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// The DNS host, used both to connect and as the TLS server name.
    pub host: String,
    /// The TCP port, defaulting to 443.
    pub port: u16,
    /// The request-target: an origin-form path beginning with `/`, query included.
    pub path: String,
}

impl Url {
    /// Parses an absolute `https` URL.
    ///
    /// Returns [`AcmeError::Transport`] for anything that is not an `https` URL
    /// with a plain DNS authority — the shape every ACME endpoint uses.
    pub fn parse(absolute_https: &str) -> Result<Self, AcmeError> {
        let rest = absolute_https
            .strip_prefix("https://")
            .ok_or_else(|| AcmeError::Transport(format!("not an https URL: {absolute_https}")))?;

        // The authority runs up to the first path, query, or fragment delimiter.
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(authority_end);

        if authority.is_empty() {
            return Err(AcmeError::Transport(format!("no host in URL: {absolute_https}")));
        }
        if authority.contains('@') {
            return Err(AcmeError::Transport(format!("userinfo is not supported: {absolute_https}")));
        }
        if authority.contains('[') {
            return Err(AcmeError::Transport(format!("IPv6 literals are not supported: {absolute_https}")));
        }

        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port_text)) => {
                let port = port_text
                    .parse()
                    .map_err(|_| AcmeError::Transport(format!("invalid port in URL: {absolute_https}")))?;
                (host, port)
            }
            None => (authority, HTTPS_PORT),
        };

        if host.is_empty() {
            return Err(AcmeError::Transport(format!("no host in URL: {absolute_https}")));
        }

        // A fragment is client-side only and never sent; drop it from the target.
        let target = match tail.split_once('#') {
            Some((before, _)) => before,
            None => tail,
        };
        let path = if target.is_empty() {
            "/".to_owned()
        } else if target.starts_with('/') {
            target.to_owned()
        } else {
            // A bare `?query` with no path: origin-form still needs a leading `/`.
            format!("/{target}")
        };

        Ok(Self { host: host.to_owned(), port, path })
    }

    /// The value for the `Host` header: the authority, with the port only when
    /// it is not the `https` default.
    fn host_header(&self) -> String {
        if self.port == HTTPS_PORT {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// A response, read whole into memory.
///
/// ACME needs the header fields as much as the body — `Replay-Nonce` seeds the
/// next request, and `Location` names the account and the order — so both are
/// returned verbatim as `crates/http` parsed them.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// The status code.
    pub status: Status,
    /// Every response header, in arrival order (includes `Replay-Nonce`/`Location`).
    pub headers: Headers,
    /// The decoded body, framing removed.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The first value of a header as UTF-8, or `None` when absent or non-UTF-8.
    ///
    /// A convenience for the two headers ACME pulls off nearly every response.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get_str(name)
    }
}

/// A reusable outbound HTTPS client.
///
/// Holds one `rustls` configuration (roots, provider, ALPN) and opens a fresh
/// connection per request. Cheap to clone — the configuration is shared behind
/// an `Arc`.
#[derive(Clone)]
pub struct HttpsClient {
    config: Arc<rustls::ClientConfig>,
}

impl HttpsClient {
    /// Builds a client that verifies servers against the bundled Mozilla roots.
    ///
    /// The `ring` provider is named explicitly so the client stands on its own
    /// rather than relying on a process-default provider having been installed.
    pub fn new() -> Result<Self, AcmeError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| AcmeError::Tls(error.to_string()))?
            .with_root_certificates(roots)
            .with_no_client_auth();

        // Match proxy::tls: this stack speaks HTTP/1.1 and nothing else.
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(Self { config: Arc::new(config) })
    }

    /// Issues a `GET` and reads the whole response.
    pub async fn get(&self, url: &Url) -> Result<HttpResponse, AcmeError> {
        self.request("GET", url, &[], b"").await
    }

    /// Issues a `POST` carrying `body` with the given `Content-Type`.
    ///
    /// ACME requests are `application/jose+json`; the type is a parameter so the
    /// transport need not know that.
    pub async fn post(
        &self,
        url: &Url,
        content_type: &str,
        body: &[u8],
    ) -> Result<HttpResponse, AcmeError> {
        let headers = [("Content-Type".to_owned(), content_type.to_owned())];
        self.request("POST", url, &headers, body).await
    }

    /// Issues a request of any method, carrying `extra_headers` verbatim.
    ///
    /// The general entry point non-ACME callers use — the reachability probes
    /// drive third-party services whose requests need their own headers and
    /// methods (`PUT`, `PATCH`, `DELETE`) the two ACME shapes above never send.
    /// `extra_headers` ride after the standard head; the framing fields
    /// (`Host`, `Content-Length`, `Connection`) stay this client's alone, so a
    /// caller cannot make the declared length and the sent bytes disagree. An
    /// HTTP error status is a *successful* exchange returned for the caller to
    /// interpret, exactly as for `get`/`post`.
    pub async fn request(
        &self,
        method: &str,
        url: &Url,
        extra_headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, AcmeError> {
        let head = build_request(url, method, extra_headers, body);

        let tcp = TcpStream::connect((url.host.as_str(), url.port))
            .await
            .map_err(|error| AcmeError::Transport(error.to_string()))?;

        let server_name = rustls::pki_types::ServerName::try_from(url.host.clone())
            .map_err(|error| AcmeError::Tls(error.to_string()))?;

        let connector = TlsConnector::from(self.config.clone());
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|error| AcmeError::Tls(error.to_string()))?;

        tls.write_all(&head).await.map_err(|error| AcmeError::Transport(error.to_string()))?;
        if !body.is_empty() {
            tls.write_all(body).await.map_err(|error| AcmeError::Transport(error.to_string()))?;
        }
        tls.flush().await.map_err(|error| AcmeError::Transport(error.to_string()))?;

        read_response(&mut tls).await
    }
}

/// Serialises a request head (and declares the body length when one is framed).
///
/// Hand-written for the same reason `proxy::server::forward` hand-writes its
/// upstream head: `crates/http` has no request encoder, deliberately. The
/// framing fields — `Content-Length` and `Connection: close` — are set here and
/// nowhere else, so the declared length and the bytes actually sent agree;
/// `extra_headers` (a `Content-Type`, an API key) are appended verbatim after
/// the standard lines. A body-bearing method (`POST`/`PUT`/`PATCH`) always
/// declares its length — some APIs refuse such a request without one even when
/// the body is empty — while a bodiless `GET`/`DELETE` declares nothing.
fn build_request(url: &Url, method: &str, extra_headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
    let mut head = Vec::new();
    head.extend_from_slice(method.as_bytes());
    head.push(b' ');
    head.extend_from_slice(url.path.as_bytes());
    head.extend_from_slice(b" HTTP/1.1\r\n");

    head.extend_from_slice(b"Host: ");
    head.extend_from_slice(url.host_header().as_bytes());
    head.extend_from_slice(b"\r\n");

    head.extend_from_slice(b"User-Agent: selfhost-acme/1\r\n");
    // Do not advertise a content coding: the reply arrives as identity bytes,
    // which is all the body reader below knows how to hand back.
    head.extend_from_slice(b"Accept-Encoding: identity\r\n");
    head.extend_from_slice(b"Connection: close\r\n");

    for (name, value) in extra_headers {
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
///
/// Split out from the socket setup so it can be tested against any [`AsyncRead`],
/// not just a live TLS stream. Enforces [`MAX_RESPONSE_BYTES`] across every
/// framing so a peer cannot make it buffer without bound.
async fn read_response<R>(stream: &mut R) -> Result<HttpResponse, AcmeError>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = Vec::new();

    // Read until the head parses. `Incomplete` means the blank line has not
    // arrived; anything else is a malformed response.
    let parsed = loop {
        if !read_more(stream, &mut buffer).await? {
            return Err(AcmeError::Transport("connection closed before a response head arrived".into()));
        }
        match IncomingResponse::parse(&buffer) {
            Ok(parsed) => break parsed,
            Err(ParseError::Incomplete) => continue,
            Err(error) => {
                return Err(AcmeError::Protocol {
                    kind: "malformed-response".into(),
                    detail: error.to_string(),
                });
            }
        }
    };

    let head = parsed.response;
    // Whatever was read past the head is the first of the body.
    let mut body = buffer.split_off(parsed.consumed);

    let body = match head.framing {
        ResponseFraming::None => Vec::new(),
        ResponseFraming::Fixed(length) => {
            let length = length as usize;
            while body.len() < length {
                if !read_more(stream, &mut body).await? {
                    return Err(AcmeError::Transport(
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
                        return Err(AcmeError::Transport(
                            "connection closed in the middle of a chunked body".into(),
                        ));
                    }
                }
                Err(error) => {
                    return Err(AcmeError::Protocol {
                        kind: "malformed-response".into(),
                        detail: error.to_string(),
                    });
                }
            }
        },
    };

    Ok(HttpResponse { status: head.status, headers: head.headers, body })
}

/// Appends one read from `stream` to `buffer`, enforcing the response cap.
///
/// Returns `false` at end of stream. A peer that keeps sending past
/// [`MAX_RESPONSE_BYTES`] is cut off with an error rather than allowed to grow
/// the buffer without limit.
async fn read_more<R>(stream: &mut R, buffer: &mut Vec<u8>) -> Result<bool, AcmeError>
where
    R: AsyncRead + Unpin,
{
    let mut chunk = [0_u8; READ_CHUNK];
    let read = stream.read(&mut chunk).await.map_err(|error| AcmeError::Transport(error.to_string()))?;
    if read == 0 {
        return Ok(false);
    }
    if buffer.len() + read > MAX_RESPONSE_BYTES {
        return Err(AcmeError::Transport("response exceeded the maximum accepted size".into()));
    }
    buffer.extend_from_slice(&chunk[..read]);
    Ok(true)
}

#[cfg(test)]
mod url_tests {
    use super::*;

    #[test]
    fn parses_host_and_path() {
        let url = Url::parse("https://acme-v02.api.letsencrypt.org/directory").unwrap();
        assert_eq!(url.host, "acme-v02.api.letsencrypt.org");
        assert_eq!(url.port, 443);
        assert_eq!(url.path, "/directory");
    }

    #[test]
    fn a_missing_path_becomes_root() {
        let url = Url::parse("https://example.org").unwrap();
        assert_eq!(url.path, "/");
    }

    #[test]
    fn a_query_is_kept_in_the_target() {
        let url = Url::parse("https://example.org/acme/order?cursor=7").unwrap();
        assert_eq!(url.path, "/acme/order?cursor=7");
    }

    #[test]
    fn a_fragment_is_dropped() {
        let url = Url::parse("https://example.org/path#section").unwrap();
        assert_eq!(url.path, "/path");
    }

    #[test]
    fn an_explicit_port_is_read_and_kept_in_the_host_header() {
        let url = Url::parse("https://example.org:8443/x").unwrap();
        assert_eq!(url.port, 8443);
        assert_eq!(url.host_header(), "example.org:8443");
    }

    #[test]
    fn the_default_port_is_omitted_from_the_host_header() {
        let url = Url::parse("https://example.org/x").unwrap();
        assert_eq!(url.host_header(), "example.org");
    }

    #[test]
    fn a_non_https_scheme_is_refused() {
        assert!(matches!(Url::parse("http://example.org/"), Err(AcmeError::Transport(_))));
        assert!(matches!(Url::parse("example.org/"), Err(AcmeError::Transport(_))));
    }

    #[test]
    fn a_bad_port_is_refused() {
        assert!(matches!(Url::parse("https://example.org:notaport/"), Err(AcmeError::Transport(_))));
    }

    #[test]
    fn userinfo_and_ipv6_literals_are_refused() {
        assert!(matches!(Url::parse("https://user@example.org/"), Err(AcmeError::Transport(_))));
        assert!(matches!(Url::parse("https://[::1]/"), Err(AcmeError::Transport(_))));
    }
}

#[cfg(test)]
mod request_tests {
    use super::*;

    fn as_text(head: &[u8]) -> String {
        String::from_utf8(head.to_vec()).unwrap()
    }

    /// A `Content-Type` header pair, as [`HttpsClient::post`] builds it.
    fn content_type(value: &str) -> Vec<(String, String)> {
        vec![("Content-Type".to_owned(), value.to_owned())]
    }

    #[test]
    fn a_get_carries_no_body_framing() {
        let url = Url::parse("https://acme.test/directory").unwrap();
        let head = as_text(&build_request(&url, "GET", &[], b""));
        assert!(head.starts_with("GET /directory HTTP/1.1\r\n"));
        assert!(head.contains("Host: acme.test\r\n"));
        assert!(head.contains("Connection: close\r\n"));
        assert!(!head.contains("Content-Length"));
        assert!(head.ends_with("\r\n\r\n"));
    }

    #[test]
    fn a_post_declares_its_type_and_length() {
        let url = Url::parse("https://acme.test/new-order").unwrap();
        let head = as_text(&build_request(&url, "POST", &content_type("application/jose+json"), b"{}"));
        assert!(head.starts_with("POST /new-order HTTP/1.1\r\n"));
        assert!(head.contains("Content-Type: application/jose+json\r\n"));
        assert!(head.contains("Content-Length: 2\r\n"));
    }

    #[test]
    fn extra_headers_ride_after_the_standard_head() {
        // The third-party-API path: an API-key header must arrive verbatim, and
        // a body-bearing method must still declare its length even when empty —
        // some APIs refuse a length-less POST outright.
        let url = Url::parse("https://api.example.test/v1/records").unwrap();
        let headers = vec![("Authorization".to_owned(), "Bearer tok".to_owned())];
        let head = as_text(&build_request(&url, "PUT", &headers, b""));
        assert!(head.starts_with("PUT /v1/records HTTP/1.1\r\n"));
        assert!(head.contains("Authorization: Bearer tok\r\n"));
        assert!(head.contains("Content-Length: 0\r\n"));

        // A DELETE with no body declares nothing, like a GET.
        let bare = as_text(&build_request(&url, "DELETE", &[], b""));
        assert!(!bare.contains("Content-Length"));
    }
}

#[cfg(test)]
mod read_tests {
    use super::*;

    /// Reads a response straight from a byte slice — `&[u8]` is an `AsyncRead`,
    /// so the body-draining logic is exercised with no socket in sight.
    async fn read(raw: &[u8]) -> Result<HttpResponse, AcmeError> {
        let mut source = raw;
        read_response(&mut source).await
    }

    #[tokio::test]
    async fn reads_a_fixed_length_body() {
        let response = read(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello").await.unwrap();
        assert_eq!(response.status, Status(200));
        assert_eq!(response.body, b"hello");
    }

    #[tokio::test]
    async fn a_fixed_body_ignores_bytes_past_its_length() {
        // Nothing should follow on a `Connection: close` exchange, but if it did
        // the declared length is authoritative.
        let response = read(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcXYZ").await.unwrap();
        assert_eq!(response.body, b"abc");
    }

    #[tokio::test]
    async fn a_status_that_forbids_a_body_has_none() {
        // newNonce answers 204: the Replay-Nonce header carries the payload.
        let response =
            read(b"HTTP/1.1 204 No Content\r\nReplay-Nonce: abc123\r\n\r\n").await.unwrap();
        assert_eq!(response.status, Status(204));
        assert!(response.body.is_empty());
        assert_eq!(response.header("Replay-Nonce"), Some("abc123"));
    }

    #[tokio::test]
    async fn reads_a_body_delimited_by_connection_close() {
        let response = read(b"HTTP/1.1 200 OK\r\n\r\nstreamed to EOF").await.unwrap();
        assert_eq!(response.body, b"streamed to EOF");
    }

    #[tokio::test]
    async fn reads_and_dechunks_a_chunked_body() {
        let response =
            read(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
                .await
                .unwrap();
        assert_eq!(response.body, b"hello");
    }

    #[tokio::test]
    async fn a_fixed_body_cut_short_is_an_error() {
        let result = read(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort").await;
        assert!(matches!(result, Err(AcmeError::Transport(_))));
    }

    #[tokio::test]
    async fn a_closed_connection_before_the_head_is_an_error() {
        let result = read(b"HTTP/1.1 200 OK\r\n").await;
        assert!(matches!(result, Err(AcmeError::Transport(_))));
    }

    #[tokio::test]
    async fn the_client_configuration_builds() {
        // Proves the roots load and the ring provider assembles a ClientConfig.
        assert!(HttpsClient::new().is_ok());
    }
}
