//! The loopback HTTP server the reverse proxy forwards to.
//!
//! This is deliberately the smallest thing that can serve the routes below. It binds
//! **loopback only**, and that is not a default to be overridden later: the
//! deployment's rule is one public surface — the reverse proxy on 80/443 — and
//! this process gaining its own would be a second front door onto a box with a
//! real public IP. The proxy resolves an owner-node instance to
//! `127.0.0.1:<port>`, so loopback is also all that is needed for the
//! dashboard to work from a phone across the house.
//!
//! It authenticates nothing, and that is a decision rather than an omission.
//! The site's `allowed_cidrs` gate is the security model for this subsystem,
//! recorded as such in `docs/labs/home-lab.dx`; a caller that reaches this
//! socket has already passed it, or is something already running on this
//! machine, which the gate never claimed to stop. Nothing here may be written
//! as though reaching it proved anything about who is asking.
//!
//! # Routes
//!
//! | Method | Path | What |
//! |---|---|---|
//! | `GET` | `/api/home` | the whole house, one object |
//! | `POST` | `/api/home/devices/<id>/command` | ask one device to do one thing, or write the house's memory (`rename`, `room`, `hide`, `show`) |
//! | `GET` | `/api/home/health` | a liveness answer for the proxy's probe |
//!
//! Anything else is a 404 carrying a JSON sentence, because every caller here
//! is the dashboard and a JSON error is what it can render.

use std::sync::Arc;

use selfhost_http::request::{BodyLength, ParseError};
use selfhost_http::{Method, Request, Response, Status};
use selfhost_json::Json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::api;
use crate::device::DeviceId;
use crate::hub::Hub;

/// The largest command body accepted.
///
/// A command is a handful of fields; anything approaching a kilobyte is a
/// mistake or a probe. Capping it here means the read loop below can hold the
/// body in one buffer without a streaming path that nothing would exercise.
const MAX_BODY: usize = 8 * 1024;

/// How long one connection may take to send its head and body.
///
/// The dashboard polls every second, so a connection that has not finished
/// speaking within this is not a slow phone — it is a socket that will never
/// complete, and holding it costs a task each.
const READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// The largest request head accepted before the connection is abandoned.
///
/// `selfhost_http` enforces its own cap when it parses, but it does so only
/// once a complete head has arrived; this bound is what stops a peer that
/// never sends a blank line from growing the buffer without limit. Stated here
/// rather than imported because the crate keeps its own constant private.
const MAX_HEAD: usize = 16 * 1024;

/// Serves the home API until the process ends.
///
/// `bind` must be a loopback address; a caller passing anything else is
/// refused rather than obeyed, because the one thing this module must never do
/// is open a second public surface, and a typo in a config file should not be
/// able to cause it.
pub async fn serve(bind: &str, hub: Arc<Hub>) -> std::io::Result<()> {
    let address: std::net::SocketAddr = bind.parse().map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{bind} is not an address"))
    })?;
    if !address.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{bind} is not a loopback address; the home API may not bind a public interface"),
        ));
    }

    let listener = TcpListener::bind(address).await?;
    eprintln!("[home] serving the house on http://{address}");

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            // One failed accept is not a reason to stop answering. A listener
            // that exits here takes the dashboard down for the rest of the
            // process's life, which is a far worse outcome than a dropped
            // connection.
            Err(error) => {
                eprintln!("[home] accept failed: {error}");
                continue;
            }
        };
        let hub = Arc::clone(&hub);
        tokio::spawn(async move {
            if let Err(error) = answer(stream, hub).await {
                eprintln!("[home] connection ended: {error}");
            }
        });
    }
}

/// Reads one request, answers it, and closes.
///
/// No keep-alive. The dashboard makes roughly one request a second over
/// loopback, where a connection costs nothing worth pooling, and a
/// connection-per-request removes every question about framing a reused socket.
async fn answer(mut stream: TcpStream, hub: Arc<Hub>) -> std::io::Result<()> {
    let deadline = tokio::time::Instant::now() + READ_TIMEOUT;

    let mut buffer = Vec::with_capacity(1024);
    let parsed = loop {
        match Request::parse(&buffer) {
            Ok(parsed) => break parsed,
            Err(ParseError::Incomplete) => {}
            Err(error) => return write(&mut stream, bad_request(&error.to_string())).await,
        }
        let mut chunk = [0_u8; 1024];
        let read = match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(read)) => read,
            Ok(Err(error)) => return Err(error),
            Err(_) => return write(&mut stream, bad_request("timed out reading the request")).await,
        };
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_BODY + MAX_HEAD {
            return write(&mut stream, bad_request("the request is too large")).await;
        }
    };

    let request = parsed.request;
    let mut body = buffer[parsed.consumed..].to_vec();

    // Only a fixed-length body is accepted. The dashboard is the only caller
    // and always sends one; refusing chunked here removes a decoder from a
    // surface that has no use for it.
    match request.body_length() {
        Ok(BodyLength::None) => body.clear(),
        Ok(BodyLength::Fixed(length)) => {
            let length = length as usize;
            if length > MAX_BODY {
                return write(&mut stream, refuse(Status::CONTENT_TOO_LARGE, "That command is too large.")).await;
            }
            while body.len() < length {
                let mut chunk = [0_u8; 1024];
                let read = match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
                    Ok(Ok(0)) => break,
                    Ok(Ok(read)) => read,
                    Ok(Err(error)) => return Err(error),
                    Err(_) => return write(&mut stream, bad_request("timed out reading the body")).await,
                };
                body.extend_from_slice(&chunk[..read]);
            }
            body.truncate(length);
        }
        Ok(BodyLength::Chunked) => {
            return write(&mut stream, bad_request("a chunked body is not accepted here")).await
        }
        Err(error) => return write(&mut stream, bad_request(&error.to_string())).await,
    }

    let response = route(&request, &body, &hub).await;
    write(&mut stream, response).await
}

/// Decides what a request means and produces its answer.
async fn route(request: &Request, body: &[u8], hub: &Hub) -> Response {
    // The target may carry a query string; the routes here take none, so it is
    // cut off rather than made part of the match.
    let path = request.path();
    let path = path.split('?').next().unwrap_or(path);
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();

    match (&request.method, segments.as_slice()) {
        (&Method::Get, ["api", "home"]) => {
            let (generation, at, devices) = hub.snapshot().await;
            json(Status::OK, &api::house(generation, &at, &devices))
        }
        // Two spellings of the same answer, and the bare `/` is the one that
        // matters. The proxy health-probes an instance at `[sites.health]
        // path`, which defaults to `/`; an instance that answers 404 there is
        // removed from rotation and every request to it becomes a 502. That
        // is exactly what happened the first time this was wired up, and the
        // symptom — a working API that the proxy refuses to forward to —
        // points at the proxy rather than here. Answering `/` makes the
        // default configuration correct, so a person copying the site block
        // out of the lab does not have to know this.
        (&Method::Get, ["api", "home", "health"]) | (&Method::Get, [""]) | (&Method::Get, []) => {
            json(Status::OK, &Json::object([("ok", Json::Bool(true))]))
        }
        (&Method::Post, ["api", "home", "devices", id, "command"]) => {
            // Decoded *after* the split, never before. A device id is
            // `<driver>:<key>`, and a browser is entitled to send that colon as
            // `%3A` — `encodeURIComponent` does, which is why the dashboard's
            // first real click answered "there is no device with that name
            // here". Decoding before the split would be the actual danger:
            // `%2F` would become a separator and a crafted id could climb into
            // another route. Splitting first makes that impossible, so a
            // segment can be decoded freely.
            command(&percent_decode(id), body, hub).await
        }
        // A GET where a POST was meant is a common enough mistake to answer in
        // words rather than with a bare 404 that reads as "no such device".
        (_, ["api", "home", "devices", _, "command"]) => refuse(
            Status::METHOD_NOT_ALLOWED,
            "A command must be sent with POST.",
        ),
        _ => refuse(Status::NOT_FOUND, "There is nothing at that address."),
    }
}

/// Expands `%XX` escapes in one already-split path segment.
///
/// Deliberately not a general URL decoder: it does not turn `+` into a space,
/// because `+` is a literal plus in a path and only means a space in a query
/// string, and a device whose id genuinely contained one would otherwise be
/// unreachable. A malformed escape at the end of the segment, or one with a
/// non-hex digit, is left exactly as it was found rather than dropped — a
/// mangled id should fail to match a device and produce "there is no device
/// with that name here", not silently become a different id that does match.
fn percent_decode(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &segment[i + 1..i + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // A device id is ASCII by construction (`DeviceId::new` guarantees it), so
    // invalid UTF-8 here means the segment never named a device. Replacing
    // rather than failing keeps the answer a sentence.
    String::from_utf8_lossy(&out).into_owned()
}

/// Performs one command against one device.
async fn command(id: &str, body: &[u8], hub: &Hub) -> Response {
    let text = match std::str::from_utf8(body) {
        Ok(text) => text,
        Err(_) => return refuse(Status::BAD_REQUEST, "That command was not valid text."),
    };
    let parsed = match selfhost_json::parse(text) {
        Ok(parsed) => parsed,
        Err(_) => return refuse(Status::BAD_REQUEST, "That command was not valid JSON."),
    };
    let act = match api::act(&parsed) {
        Ok(act) => act,
        Err(refusal) => return refuse(Status::BAD_REQUEST, &refusal.sentence()),
    };

    match hub.apply(&DeviceId::from_wire(id), act).await {
        Ok(()) => json(Status::OK, &api::accepted()),
        // Every failure below this line is a sentence the hub composed about a
        // real device, so it is passed through verbatim rather than replaced
        // with a status the reader would have to interpret.
        Err(sentence) => refuse(Status::BAD_REQUEST, &sentence),
    }
}

/// A JSON response, or a plain 500 if the body could not be framed.
fn json(status: Status, value: &Json) -> Response {
    Response::bytes(status, "application/json", value.to_text().into_bytes())
        .unwrap_or_else(|_| Response::empty(Status::INTERNAL_SERVER_ERROR))
}

/// A refusal carrying a sentence the dashboard can show as it is.
fn refuse(status: Status, sentence: &str) -> Response {
    json(status, &api::refused(sentence))
}

fn bad_request(why: &str) -> Response {
    refuse(Status::BAD_REQUEST, why)
}

/// Writes one response and closes the connection.
async fn write(stream: &mut TcpStream, response: Response) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(512);
    if response.write_head(&mut out, false).is_err() {
        return Ok(());
    }
    if let selfhost_http::Body::Bytes(bytes) = &response.body {
        out.extend_from_slice(bytes);
    }
    stream.write_all(&out).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{Capability, Device, Kind};

    fn hub() -> Hub {
        let mut kitchen = Device::new(
            DeviceId::new("sonos", "RINCON_A"),
            "Kitchen",
            Kind::Speaker,
        )
        .advertise(&[Capability::Transport, Capability::Volume]);
        kitchen.reachable = true;
        Hub::for_test(vec![kitchen])
    }

    async fn get(path: &str) -> (u16, Json) {
        let request = Request::parse(
            format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes(),
        )
        .expect("a valid request")
        .request;
        let response = route(&request, b"", &hub()).await;
        decode(response)
    }

    async fn post(path: &str, body: &str) -> (u16, Json) {
        let head = format!(
            "POST {path} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let request = Request::parse(head.as_bytes()).expect("a valid request").request;
        let response = route(&request, body.as_bytes(), &hub()).await;
        decode(response)
    }

    fn decode(response: Response) -> (u16, Json) {
        let status = response.status.code();
        let body = match &response.body {
            selfhost_http::Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            _ => String::new(),
        };
        (status, selfhost_json::parse(&body).unwrap_or(Json::Null))
    }

    #[tokio::test]
    async fn the_house_is_served_as_one_object() {
        let (status, body) = get("/api/home").await;
        assert_eq!(status, 200);
        assert!(body.get("generation").is_some());
        assert_eq!(body.get("devices").and_then(Json::as_array).map(<[Json]>::len), Some(1));
    }

    #[tokio::test]
    async fn a_query_string_does_not_change_the_route() {
        let (status, _) = get("/api/home?since=3").await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn health_answers_for_the_proxys_probe() {
        let (status, body) = get("/api/home/health").await;
        assert_eq!(status, 200);
        assert_eq!(body.get("ok").and_then(Json::as_bool), Some(true));
    }

    /// The proxy health-probes at `/` by default, and an instance that 404s
    /// there is removed from rotation — every request through the proxy then
    /// becomes a 502. This is a regression test for exactly that, found by
    /// running the real daemon rather than by reading the code.
    #[tokio::test]
    async fn the_bare_root_answers_the_proxys_default_health_probe() {
        let (status, body) = get("/").await;
        assert_eq!(status, 200, "the proxy's default probe path must not 404");
        assert_eq!(body.get("ok").and_then(Json::as_bool), Some(true));
    }

    #[tokio::test]
    async fn an_unknown_path_is_refused_in_words() {
        let (status, body) = get("/api/home/elsewhere").await;
        assert_eq!(status, 404);
        assert!(body.get("error").and_then(Json::as_str).is_some());
    }

    /// A GET where a POST was meant should not read as "no such device".
    #[tokio::test]
    async fn a_command_sent_by_get_says_so() {
        let (status, body) = get("/api/home/devices/sonos:rincon_a/command").await;
        assert_eq!(status, 405);
        assert!(body.get("error").and_then(Json::as_str).unwrap().contains("POST"));
    }

    #[tokio::test]
    async fn a_command_a_device_admits_is_accepted() {
        let (status, body) = post(
            "/api/home/devices/sonos:rincon_a/command",
            r#"{"command":"play"}"#,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(body.get("ok").and_then(Json::as_bool), Some(true));
    }

    /// The capability gate, reached through the real route rather than tested
    /// in isolation — this is the path a browser actually takes.
    #[tokio::test]
    async fn a_command_a_device_does_not_advertise_is_refused_with_a_sentence() {
        let (status, body) = post(
            "/api/home/devices/sonos:rincon_a/command",
            r#"{"command":"color","value":"FF0000"}"#,
        )
        .await;
        assert_eq!(status, 400);
        let sentence = body.get("error").and_then(Json::as_str).expect("a sentence");
        assert!(!sentence.is_empty());
    }

    /// The bug the dashboard's very first click found: `encodeURIComponent`
    /// turns the id's colon into `%3A`, and a server that never decodes it
    /// answers "there is no device with that name here" for every command.
    #[tokio::test]
    async fn a_percent_encoded_device_id_reaches_its_device() {
        let (status, body) = post(
            "/api/home/devices/sonos%3Arincon_a/command",
            r#"{"command":"play"}"#,
        )
        .await;
        assert_eq!(status, 200, "a browser-encoded id must reach its device");
        assert_eq!(body.get("ok").and_then(Json::as_bool), Some(true));
    }

    /// Lowercase escapes are as legal as uppercase ones.
    #[tokio::test]
    async fn a_lowercase_escape_decodes_too() {
        let (status, _) = post(
            "/api/home/devices/sonos%3arincon_a/command",
            r#"{"command":"play"}"#,
        )
        .await;
        assert_eq!(status, 200);
    }

    #[test]
    fn an_escape_decodes_and_a_plus_stays_a_plus() {
        assert_eq!(percent_decode("sonos%3Arincon_a"), "sonos:rincon_a");
        assert_eq!(percent_decode("sonos%3arincon_a"), "sonos:rincon_a");
        assert_eq!(percent_decode("a%2Fb"), "a/b");
        // A literal plus, not a space: `+` only means a space in a query.
        assert_eq!(percent_decode("a+b"), "a+b");
        assert_eq!(percent_decode("plain"), "plain");
    }

    /// A mangled escape must stay mangled, so it fails to match a device
    /// rather than quietly becoming a different one that does.
    #[test]
    fn a_malformed_escape_is_left_alone() {
        assert_eq!(percent_decode("a%ZZb"), "a%ZZb");
        assert_eq!(percent_decode("trailing%"), "trailing%");
        assert_eq!(percent_decode("short%3"), "short%3");
    }

    /// Decoding happens after the split, so an encoded separator can never
    /// introduce a new path segment.
    #[tokio::test]
    async fn an_encoded_slash_cannot_climb_into_another_route() {
        let (status, body) = post(
            "/api/home/devices/sonos%3Arincon_a%2F..%2Fhealth/command",
            r#"{"command":"play"}"#,
        )
        .await;
        assert_eq!(status, 400, "it must be read as an id, not as a path");
        assert!(body.get("error").and_then(Json::as_str).is_some());
    }

    #[tokio::test]
    async fn a_command_for_an_unknown_device_is_refused() {
        let (status, body) = post(
            "/api/home/devices/sonos:nobody/command",
            r#"{"command":"play"}"#,
        )
        .await;
        assert_eq!(status, 400);
        assert!(body.get("error").and_then(Json::as_str).is_some());
    }

    #[tokio::test]
    async fn a_body_that_is_not_json_is_refused() {
        let (status, _) = post("/api/home/devices/sonos:rincon_a/command", "not json").await;
        assert_eq!(status, 400);
    }

    /// The registry words travel the same route as device commands, so the
    /// house's memory has a door a caller can actually reach.
    #[tokio::test]
    async fn a_rename_travels_the_command_route() {
        let (status, body) = post(
            "/api/home/devices/sonos:rincon_a/command",
            r#"{"command":"rename","value":"Coffee Corner"}"#,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(body.get("ok").and_then(Json::as_bool), Some(true));
    }

    /// A registry act is still gated on the device being known — a typo must
    /// not become an entry the registry carries forever.
    #[tokio::test]
    async fn a_rename_of_an_unknown_device_is_refused() {
        let (status, body) = post(
            "/api/home/devices/sonos:nobody/command",
            r#"{"command":"rename","value":"Ghost"}"#,
        )
        .await;
        assert_eq!(status, 400);
        assert!(body.get("error").and_then(Json::as_str).is_some());
    }

    /// The one thing this module must never do, checked rather than trusted.
    #[tokio::test]
    async fn a_public_bind_address_is_refused() {
        let hub = Arc::new(Hub::for_test(Vec::new()));
        let error = serve("0.0.0.0:9210", hub).await.expect_err("must refuse");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("loopback"));
    }

    #[tokio::test]
    async fn an_unparseable_bind_address_is_refused() {
        let hub = Arc::new(Hub::for_test(Vec::new()));
        assert!(serve("not-an-address", hub).await.is_err());
    }
}
