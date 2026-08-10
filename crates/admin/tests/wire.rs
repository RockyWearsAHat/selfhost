//! The socket layer of the control API, spoken to over a real loopback port.
//!
//! # Why this file exists
//!
//! `tests/api.rs` drives [`Api::handle`] and `Api::upgrade_for`, which are pure
//! decisions over a request head, and that is the right way to test
//! authorisation: every refusal is a unit test and no port is bound. But it is
//! only half of what an upgrade *is*. Everything after the decision — writing
//! the `101`, handing the connection over, and the first frame that follows it —
//! happens on a socket, and none of it was covered anywhere.
//!
//! The cost of that gap was not theoretical. The desktop route wrote the
//! handshake response **twice**: once generically for every stream and once
//! again inside the desktop arm. Three thousand tests passed, because not one of
//! them read a byte off a socket. Every real client failed, because the second
//! head is what the first frame is supposed to be — its leading `H` is `0x48`,
//! so RSV1 is set and the opcode is `8`, and an RFC 6455 client closes the
//! connection on it.
//!
//! So these tests bind a loopback port, speak an actual handshake, and assert on
//! the **bytes**: exactly one HTTP head, the right accept key, the subprotocol
//! that was offered and no other, a well-formed first frame, and a clean close.
//! They do not replace the pure tests and are not redundant with them — they
//! cover the half that has no `Request` and no `Response` in it.
//!
//! # And the route that had no test because it had no code
//!
//! `GET /api/mesh/link` is the owner's half of a peer link: a worker dials in,
//! is answered, and proves its enrolment in the first frame *after* the `101`.
//! It is the one upgrade on this API whose credential does not exist when the
//! handshake is answered, so it cannot be exercised at all without a socket.
//! Both ends of it are here.

use selfhost_admin::desk_api::Task;
use selfhost_admin::{AgentReport, Api, Fleet, Handover, NodeReport, Peerage, Store, Token};
use selfhost_json::Json;
use selfhost_mesh::accept::MemoryTokens;
use selfhost_mesh::channel::{ChannelId, Open, Role};
use selfhost_mesh::enroll::{Binding, NodeToken};
use selfhost_mesh::link::{Hello, LINK_CONTROL_SERVICE};
use selfhost_mesh::mux::{self, Kind, VERSION};
use selfhost_mesh::registry::{NodeName, Registry, SharedRegistry};
use selfhost_supervisor::Supervisor;
use selfhost_ws::{CloseCode, Duplex, Event, Limits};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The bearer token every test authenticates with.
const TOKEN: &str = "0123456789abcdef";

/// RFC 6455 §1.3's own example key, and the accept value it must produce.
///
/// A fixed pair rather than a random one, because the accept key is a *computed*
/// answer and a test that generated its own key could only check it by
/// recomputing it with the same function it is testing.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

/// A second key, for a test that needs two handshakes the replay ledger will
/// treat as two.
const OTHER_KEY: &str = "b3RoZXIgY29ubmVjdGlvbg==";

// ---------------------------------------------------------------------------
// The daemon under test
// ---------------------------------------------------------------------------

/// A running control API on a loopback port, stopped when it goes out of scope.
struct Daemon {
    /// Where to reach it.
    address: SocketAddr,
    /// The accept loop, aborted on drop so a failing test does not leak a task.
    serving: tokio::task::JoinHandle<std::io::Result<()>>,
    /// Removed on drop, after the daemon that was reading it has stopped.
    _scratch: Scratch,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.serving.abort();
    }
}

/// Starts an API on an ephemeral loopback port.
///
/// Port zero, so tests may run in parallel; `selfhost_admin::bind` refuses any
/// address that is not loopback, which is the property under test everywhere
/// else and is simply inherited here.
async fn start(api: Api, scratch: Scratch) -> Daemon {
    let listener = selfhost_admin::bind("127.0.0.1:0".parse().expect("a loopback address"))
        .await
        .expect("an ephemeral loopback port");
    let address = listener.local_addr().expect("the bound address");
    let serving = tokio::spawn(selfhost_admin::serve(listener, api));
    Daemon { address, serving, _scratch: scratch }
}

/// An API over a scratch directory with a known bearer token.
fn api(name: &str) -> (Api, Scratch) {
    let scratch = Scratch::new(name);
    std::fs::write(scratch.path().join(selfhost_admin::token::TOKEN_FILENAME), TOKEN)
        .expect("a token file");
    let api = Api::new(
        Supervisor::new(scratch.path()),
        Store::new(scratch.path()),
        Token::load_or_create(scratch.path()).expect("the token just written"),
        selfhost_git::Watches::default(),
        selfhost_firewall::Manager::for_config(&minimal_config()),
    );
    (api, scratch)
}

/// A minimal valid configuration, for the firewall manager's sake.
fn minimal_config() -> selfhost_config::Config {
    selfhost_config::Config::parse(
        "version = 1\n\
         [server]\n\
         http_bind = \"127.0.0.1:8080\"\n\
         https_bind = \"127.0.0.1:8443\"\n\
         acme_email = \"a@b.com\"\n\
         acme = \"self-signed\"\n\
         data_dir = \"./data\"\n\
         [[nodes]]\n\
         name = \"home\"\n\
         role = \"owner\"\n",
    )
    .expect("a minimal valid config")
}

/// A directory that removes itself when dropped.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("selfhost-wire-{name}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Speaking to it
// ---------------------------------------------------------------------------

/// Sends one request and reads the whole answer.
///
/// The API serves one request per connection, so reading to end is the response
/// and nothing else.
async fn once(address: SocketAddr, text: &str) -> String {
    let mut stream = TcpStream::connect(address).await.expect("a connection");
    stream.write_all(text.as_bytes()).await.expect("the request");
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.expect("the answer");
    String::from_utf8_lossy(&answer).into_owned()
}

/// Mints a stream ticket over the wire and returns its value.
///
/// A `POST`, which is the whole trick the ticket exists for: a handshake is a
/// `GET` and cannot carry a custom header, so the CSRF-protected moment is moved
/// here and the handshake is made to carry proof that it happened.
async fn mint(address: SocketAddr, body: &str) -> String {
    let request = format!(
        "POST /api/desktop/ticket HTTP/1.1\r\nHost: 127.0.0.1\r\n\
         Authorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let answer = once(address, &request).await;
    let (head, payload) = answer.split_once("\r\n\r\n").expect("a framed response");
    assert!(head.starts_with("HTTP/1.1 200"), "the mint refused: {answer}");
    selfhost_json::parse(payload)
        .expect("JSON")
        .get("ticket")
        .and_then(Json::as_str)
        .expect("a ticket")
        .to_owned()
}

/// Opens a connection and sends a handshake, returning the connection and the
/// head that answered it.
///
/// `credential` is the `Authorization` header a console stream must still carry:
/// the ticket proves the CSRF-protected moment happened, it does not replace the
/// credential, and a handshake presenting one without the other is refused. A
/// browser sends its cookie here; the native console sends the bearer token, and
/// so does this. A peer link passes `None` — its credential is the proof in the
/// frame after the `101`, which is the whole reason that route exists.
async fn handshake(
    address: SocketAddr,
    target: &str,
    key: &str,
    credential: Option<&str>,
    protocols: Option<&str>,
) -> (TcpStream, String) {
    let mut stream = TcpStream::connect(address).await.expect("a connection");
    let mut request = format!(
        "GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n"
    );
    if let Some(token) = credential {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if let Some(offered) = protocols {
        request.push_str(&format!("Sec-WebSocket-Protocol: {offered}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.expect("the handshake");
    let head = read_head(&mut stream).await;
    (stream, head)
}

/// Reads one HTTP head off a stream, and not one byte past it.
async fn read_head(stream: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let read = stream.read(&mut byte).await.expect("the head");
        assert_ne!(read, 0, "the connection ended mid-head: {:?}", String::from_utf8_lossy(&head));
        head.push(byte[0]);
    }
    String::from_utf8(head).expect("an ASCII head")
}

/// Asserts a head is a well-formed `101` for `KEY`, and returns it.
fn assert_upgraded(head: &str) {
    assert!(head.starts_with("HTTP/1.1 101 Switching Protocols\r\n"), "{head}");
    assert_eq!(head.matches("HTTP/1.1").count(), 1, "more than one head in the answer: {head}");
    assert!(head.contains("Upgrade: websocket\r\n"), "{head}");
    assert!(head.contains("Connection: Upgrade\r\n"), "{head}");
    assert!(head.contains(&format!("Sec-WebSocket-Accept: {ACCEPT}\r\n")), "{head}");
    // The two fields that would break a handshake if the ordinary response path
    // or the proxy's security-header splice had written it.
    let folded = head.to_ascii_lowercase();
    assert!(!folded.contains("content-length"), "{head}");
    assert!(!folded.contains("x-frame-options"), "{head}");
}

// ---------------------------------------------------------------------------
// A desktop that sends one frame
// ---------------------------------------------------------------------------

/// What the fleet below says on every session it is handed.
const FROM_THE_FLEET: &[u8] = b"one frame from the fleet";

/// A [`Fleet`] that sends exactly one frame and closes.
///
/// Stands in for the daemon's screens: what these tests are about is whether the
/// connection reaching a session driver is a usable WebSocket, and a real
/// capture pipeline would answer that question with a display attached and not
/// otherwise.
struct OneFrame;

impl Fleet for OneFrame {
    fn nodes(&self) -> Vec<NodeReport> {
        vec![NodeReport::local()]
    }

    fn agent(&self, node: &str) -> AgentReport {
        AgentReport::absent(node, "a test fleet has no agent")
    }

    fn serve<'a>(&'a self, session: Handover) -> Task<'a, String> {
        Box::pin(async move {
            let mut duplex = Duplex::server(session.io, Limits::default());
            if duplex.send(FROM_THE_FLEET).await.is_err() {
                return "the viewer had gone".to_owned();
            }
            let _ = duplex.close(CloseCode::Normal, "that is all").await;
            "one frame".to_owned()
        })
    }
}

/// An API with the desktop subsystem switched on over [`OneFrame`].
fn desktop_api(name: &str) -> (Api, Scratch) {
    let (api, scratch) = api(name);
    let config = selfhost_config::Desktop { enabled: true, ..selfhost_config::Desktop::default() };
    (api.with_desktop(config, Arc::new(OneFrame) as Arc<dyn Fleet>), scratch)
}

// ---------------------------------------------------------------------------
// 1. The events stream
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_events_handshake_is_answered_once_and_the_first_bytes_are_a_snapshot() {
    let (api, scratch) = api("events-handshake");
    let daemon = start(api, scratch).await;

    let ticket = mint(daemon.address, "").await;
    let (stream, head) = handshake(
        daemon.address,
        "/api/events",
        KEY,
        Some(TOKEN),
        Some(&format!("selfhost.events.1, tkt.{ticket}")),
    )
    .await;

    assert_upgraded(&head);
    // The route's own token is echoed and the ticket never is: a response header
    // is written into logs and shown in a browser's network panel, and the
    // ticket is a credential.
    assert!(head.contains("Sec-WebSocket-Protocol: selfhost.events.1\r\n"), "{head}");
    assert!(!head.contains("tkt."), "the ticket was echoed back: {head}");

    // What follows the head is a frame, and it parses as one.
    let mut peer = Duplex::client(stream, Limits::default());
    let Event::Message(payload) = peer.recv().await.expect("a snapshot") else {
        panic!("the stream ended instead of pushing a snapshot");
    };
    let snapshot = selfhost_json::parse(&String::from_utf8(payload).expect("UTF-8"))
        .expect("the snapshot is JSON");
    assert_eq!(snapshot.get("kind").and_then(Json::as_str), Some("snapshot"));
    assert!(snapshot.get("services").is_some());

    // And a close is answered rather than the socket simply dying.
    peer.close(CloseCode::Normal, "closing the tab").await.expect("the close");
}

// ---------------------------------------------------------------------------
// 2. The desktop stream — the regression that three thousand tests missed
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_desktop_handshake_puts_exactly_one_head_on_the_wire() {
    // The finding, asserted the way it was found: count the heads in the raw
    // bytes. This route wrote two — once in the generic stream path and once
    // again in the desktop arm — and the second one was read by every client as
    // a frame with RSV1 set and opcode 8.
    let (api, scratch) = desktop_api("desktop-one-head");
    let daemon = start(api, scratch).await;

    let ticket = mint(daemon.address, "{\"want\":[\"desktop.view\"],\"peer\":\"self\"}").await;
    let (mut stream, head) = handshake(
        daemon.address,
        "/api/desktop/session?peer=self",
        KEY,
        Some(TOKEN),
        Some(&format!("selfhost.desktop.1, tkt.{ticket}")),
    )
    .await;

    assert_upgraded(&head);
    assert!(head.contains("Sec-WebSocket-Protocol: selfhost.desktop.1\r\n"), "{head}");

    // Everything the connection produces after the head, to the very end.
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.expect("the rest of the stream");
    let whole = [head.as_bytes(), &rest].concat();
    assert_eq!(
        whole.windows(8).filter(|window| *window == b"HTTP/1.1").count(),
        1,
        "the handshake response was written more than once: {:?}",
        String::from_utf8_lossy(&whole)
    );

    // And what did follow the head is a well-formed binary frame, unmasked as a
    // server frame must be, carrying exactly what the fleet sent.
    assert_eq!(rest[0], 0x82, "the first byte after the head is not FIN|binary");
    let length = usize::from(rest[1]);
    assert_eq!(length, FROM_THE_FLEET.len(), "the payload length was not the fleet's");
    assert!(rest[1] < 0x80, "a server frame must not be masked");
    assert_eq!(&rest[2..2 + length], FROM_THE_FLEET);
    // Then a close, and nothing after it.
    assert_eq!(rest[2 + length], 0x88, "the fleet's close did not follow its frame");
}

#[tokio::test]
async fn a_desktop_stream_is_a_usable_websocket_from_the_first_frame() {
    // The same route through a real RFC 6455 client rather than a byte scan.
    // Under the duplicated head this failed at `recv` with a protocol error,
    // which is precisely what the shipped native console does.
    let (api, scratch) = desktop_api("desktop-usable");
    let daemon = start(api, scratch).await;

    let ticket = mint(daemon.address, "{\"want\":[\"desktop.view\"],\"peer\":\"self\"}").await;
    let (stream, head) = handshake(
        daemon.address,
        "/api/desktop/session?peer=self",
        KEY,
        Some(TOKEN),
        Some(&format!("selfhost.desktop.1, tkt.{ticket}")),
    )
    .await;
    assert_upgraded(&head);

    let mut peer = Duplex::client(stream, Limits::default());
    let Event::Message(payload) = peer.recv().await.expect("the fleet's frame") else {
        panic!("the desktop stream ended before saying anything");
    };
    assert_eq!(payload, FROM_THE_FLEET);

    // The fleet closes; the client sees a close and not a transport failure.
    let Event::Closed(reason) = peer.recv().await.expect("a close") else {
        panic!("expected the fleet's close");
    };
    assert!(
        matches!(reason, selfhost_ws::Closed::Peer(_) | selfhost_ws::Closed::Abrupt),
        "expected a clean close, got {reason}"
    );
}

#[tokio::test]
async fn a_handshake_without_a_ticket_is_refused_and_never_upgraded() {
    // The uniform 401, on the socket: no `101`, no frame, and nothing that says
    // which check was failed.
    let (api, scratch) = desktop_api("no-ticket");
    let daemon = start(api, scratch).await;

    let request = format!(
        "GET /api/desktop/session?peer=self HTTP/1.1\r\nHost: 127.0.0.1\r\n\
         Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Protocol: selfhost.desktop.1\r\n\r\n"
    );
    let answer = once(daemon.address, &request).await;
    assert!(answer.starts_with("HTTP/1.1 401"), "{answer}");
    assert_eq!(answer.matches("HTTP/1.1").count(), 1, "{answer}");
    assert!(!answer.contains("101"), "{answer}");
    assert!(!answer.contains("Sec-WebSocket-Accept"), "{answer}");
}

// ---------------------------------------------------------------------------
// 3. The peer link — a route that had no test because it had no code
// ---------------------------------------------------------------------------

/// The worker every link test is.
fn worker() -> NodeName {
    NodeName::parse("alex-desktop").expect("a legal node name")
}

/// The secret the owner minted for it.
fn worker_token() -> NodeToken {
    NodeToken::from_bytes([7u8; 32])
}

/// An owner that has declared and invited [`worker`].
fn owner_peerage() -> Peerage {
    let mut registry = Registry::new();
    registry.declare(worker());
    Peerage::new(
        SharedRegistry::from_registry(registry),
        MemoryTokens::from_pairs([(worker(), worker_token())]),
    )
}

/// The greeting a worker sends: a link-control `OPEN` on channel 0, carrying a
/// proof bound to this handshake.
fn greeting(node: &NodeName, key: &str, secret: &NodeToken) -> Vec<u8> {
    let binding = Binding::new(key, &selfhost_ws::accept_key(key), node.clone()).expect("binding");
    let hello = Hello { node: node.clone(), version: VERSION, proof: binding.prove(secret) };
    let params = hello.encode();
    let payload = Open { service: LINK_CONTROL_SERVICE, params: &params }.encode().expect("open");
    mux::encode_frame(Kind::Open, ChannelId::CONTROL, &payload).expect("a frame")
}

#[tokio::test]
async fn an_enrolled_worker_links_and_the_owner_can_reach_it() {
    let (api, scratch) = api("mesh-admitted");
    let peers = owner_peerage();
    let daemon = start(api.with_peers(peers.clone()), scratch).await;

    // The dialler offers no subprotocol, so none may be echoed: a token nobody
    // offered is a protocol error on this side.
    let (stream, head) = handshake(daemon.address, "/api/mesh/link", KEY, None, None).await;
    assert_upgraded(&head);
    assert!(!head.contains("Sec-WebSocket-Protocol"), "{head}");
    // The accept value the proof is bound to is the one the owner sent.
    assert_eq!(
        selfhost_mesh::dial::check_upgrade(head.as_bytes(), KEY).expect("a usable 101"),
        ACCEPT
    );

    let mut peer = Duplex::client(stream, Limits::default());
    peer.send(&greeting(&worker(), KEY, &worker_token())).await.expect("the greeting");

    let Event::Message(answer) = peer.recv().await.expect("an answer") else {
        panic!("the owner closed instead of admitting an enrolled worker");
    };
    let (frame, rest) = mux::parse_frame(&answer).expect("a mux frame");
    assert_eq!(frame.header.kind, Kind::Accept);
    assert!(frame.header.channel.is_control());
    assert!(rest.is_empty());

    // The peer is registered, and the link is reachable for a splice.
    let record = peers.registry().get(&worker()).expect("a record");
    assert!(record.is_linked(), "an admitted worker was not marked linked");
    assert_eq!(record.consecutive_failures, 0);
    assert_eq!(peers.linked(), vec!["alex-desktop".to_owned()]);
    let handle = peers.link(&worker()).expect("a handle to splice onto");
    assert_eq!(handle.role(), Role::Accepter, "the owner is the accepting end");

    peer.close(CloseCode::Normal, "").await.expect("the close");
}

#[tokio::test]
async fn an_unenrolled_node_gets_a_bare_code_and_writes_nothing_into_the_registry() {
    // The refusal says nothing at all, on purpose: an owner that answered
    // "unknown node" to one name and "bad proof" to another has published a way
    // to enumerate the operator's own machines to anyone who can reach the
    // console site.
    let (api, scratch) = api("mesh-stranger");
    let peers = owner_peerage();
    let daemon = start(api.with_peers(peers.clone()), scratch).await;

    let stranger = NodeName::parse("somebody-elses-box").expect("a legal name");
    let (stream, head) = handshake(daemon.address, "/api/mesh/link", OTHER_KEY, None, None).await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert_eq!(head.matches("HTTP/1.1").count(), 1, "{head}");

    let mut peer = Duplex::client(stream, Limits::default());
    peer.send(&greeting(&stranger, OTHER_KEY, &worker_token())).await.expect("the greeting");

    let Event::Closed(selfhost_ws::Closed::Peer(close)) = peer.recv().await.expect("a verdict")
    else {
        panic!("an unenrolled node was not refused");
    };
    assert_eq!(close.code, Some(CloseCode::PolicyViolation));
    assert!(close.reason.is_empty(), "a refusal must say nothing at all: {:?}", close.reason);

    // The registry never learns a peer from the wire: a refusal must not be a way
    // to insert rows into the operator's list of their own machines.
    assert_eq!(peers.registry().get(&stranger), None);
    assert!(peers.linked().is_empty());
    assert_eq!(peers.registry().snapshot().len(), 1);
}

#[tokio::test]
async fn a_stale_token_is_refused_and_counted_against_that_node_alone() {
    let (api, scratch) = api("mesh-stale");
    let peers = owner_peerage();
    let daemon = start(api.with_peers(peers.clone()), scratch).await;

    let (stream, _head) = handshake(daemon.address, "/api/mesh/link", KEY, None, None).await;
    let mut peer = Duplex::client(stream, Limits::default());
    let stale = NodeToken::from_bytes([9u8; 32]);
    peer.send(&greeting(&worker(), KEY, &stale)).await.expect("the greeting");

    let Event::Closed(selfhost_ws::Closed::Peer(close)) = peer.recv().await.expect("a verdict")
    else {
        panic!("a stale token was not refused");
    };
    assert_eq!(close.code, Some(CloseCode::PolicyViolation));
    assert!(close.reason.is_empty());

    let record = peers.registry().get(&worker()).expect("a declared node keeps its row");
    assert!(!record.is_linked());
    assert_eq!(record.consecutive_failures, 1, "the failure is counted per node, and here only");
}

#[tokio::test]
async fn a_deployment_with_no_workers_serves_no_link_route_at_all() {
    // Not a 401: there is no credential to have got wrong yet, and a dialler
    // told *authorisation required* would report a stale token to its operator
    // when the truth is that the far end has no mesh.
    let (api, scratch) = api("mesh-unwired");
    let daemon = start(api, scratch).await;

    let request = format!(
        "GET /api/mesh/link HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n\r\n"
    );
    let answer = once(daemon.address, &request).await;
    assert!(answer.starts_with("HTTP/1.1 404"), "{answer}");
    assert!(!answer.contains("101"), "{answer}");
}

#[tokio::test]
async fn the_link_path_is_only_a_stream_when_the_head_is_a_handshake() {
    // A plain `GET` of a stream path is not a stream: it falls through to the
    // ordinary router, behind the ordinary authorisation wall. So a stranger
    // gets the uniform 401 that every unauthorised request gets — the path
    // itself tells them nothing — and a caller who *is* authorised gets the same
    // "no such endpoint" 404 any unmatched route answers with, because this path
    // is only ever a stream and never a document.
    let (api, scratch) = api("mesh-plain-get");
    let daemon = start(api.with_peers(owner_peerage()), scratch).await;

    let stranger =
        once(daemon.address, "GET /api/mesh/link HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").await;
    assert!(stranger.starts_with("HTTP/1.1 401"), "{stranger}");
    assert!(!stranger.contains("Sec-WebSocket-Accept"), "{stranger}");

    let authorised = once(
        daemon.address,
        &format!(
            "GET /api/mesh/link HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {TOKEN}\r\n\r\n"
        ),
    )
    .await;
    assert!(authorised.starts_with("HTTP/1.1 404"), "{authorised}");
    assert!(!authorised.contains("Sec-WebSocket-Accept"), "{authorised}");
}
