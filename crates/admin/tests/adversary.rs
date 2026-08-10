//! The adversarial review's findings against the stream authorisation path,
//! each one now stated as the property that holds.
//!
//! Every test here began as a *review artefact*: a demonstration, written to
//! pass against the code as it stood, that some property the design documents
//! claimed was in fact absent. They are kept — under the same names, carrying
//! the same threat model — and turned inside out, so that the file which once
//! recorded the gaps now guards against their return. A regression here is the
//! reappearance of a finding somebody already took the trouble to write down.
//!
//! The adversary assumed throughout is the one the design documents name: a
//! hostile web page in the operator's logged-in browser, and a co-hosted web app
//! on the same box able to make requests to loopback. "Already on the box" is a
//! given, not a stretch — the console site's `allowed_cidrs` gate is loopback,
//! because the operator's VPN tunnel exits there, so the gate is a perimeter
//! against the internet and the LAN and is no perimeter at all against this
//! machine.

use selfhost_admin::stream::{self, Watch};
use selfhost_admin::upgrade::{Holder, MintError};
use selfhost_admin::{
    Ability, Admission, Api, ConsolePassword, Denial, Sessions, Store, Streams, Tickets, Token,
};
use selfhost_http::{Body, Request, Response};
use selfhost_identity::{
    Capability, Caller, Grants, Identity, Opening, People, PersonName, Refusal,
};
use selfhost_json::Json;
use selfhost_supervisor::Supervisor;
use std::time::Duration;

/// The bearer token every API built here is loaded with.
const TOKEN: &str = "0123456789abcdef";

/// The console password, which no test below ever needs to guess.
const PASSWORD: &str = "hunter2";

/// The console site's canonical origin, as configuration would fix it.
const CONSOLE: &str = "https://admin.example.com";

/// A directory that removes itself when dropped.
struct ScratchDir(std::path::PathBuf);

impl ScratchDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("selfhost-adversary-{name}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A firewall manager over a minimal, unmanaged configuration.
fn firewall_manager() -> selfhost_firewall::Manager {
    let config = selfhost_config::Config::parse(
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
    .expect("a minimal valid config");
    selfhost_firewall::Manager::for_config(&config)
}

/// An API with cookie sessions, a console origin and an empty people registry,
/// plus the pieces a test needs to mint a session or a grant for whoever it
/// likes.
fn console_api(name: &str) -> (Api, Sessions, People, ScratchDir) {
    let dir = ScratchDir::new(name);
    std::fs::write(dir.path().join("admin.token"), TOKEN).expect("token written");
    ConsolePassword::write(dir.path(), PASSWORD).expect("password written");
    let sessions = Sessions::new();
    let people = People::load(dir.path());
    let api = Api::new(
        Supervisor::new(dir.path()),
        Store::new(dir.path()),
        Token::load_or_create(dir.path()).expect("a token"),
        selfhost_git::Watches::default(),
        firewall_manager(),
    )
    .with_console_auth_parts(ConsolePassword::load(dir.path()), sessions.clone())
    .with_people(people.clone())
    .with_console_origin("admin.example.com");
    (api, sessions, people, dir)
}

/// A validated person's name.
fn person(name: &str) -> PersonName {
    PersonName::parse(name).expect("a valid person's name")
}

/// Parses a request head written out as bytes, as a client really sends it.
fn request(raw: &str) -> Request {
    Request::parse(raw.as_bytes()).expect("a well-formed head").request
}

/// A handshake for `/api/events` carrying the given cookie, subprotocol offer
/// and `Origin`.
fn handshake(cookie: &str, offer: &str, origin: &str) -> Request {
    request(&format!(
        "GET /api/events HTTP/1.1\r\n\
         Host: admin.example.com\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Protocol: {offer}\r\n\
         Origin: {origin}\r\n\
         Cookie: selfhost_session={cookie}\r\n\r\n"
    ))
}

/// A `POST /api/desktop/ticket` from the browser holding `cookie`.
fn mint_request(cookie: &str) -> Request {
    request(&format!(
        "POST /api/desktop/ticket HTTP/1.1\r\n\
         Host: admin.example.com\r\n\
         x-selfhost-console: 1\r\n\
         Cookie: selfhost_session={cookie}\r\n\
         Content-Length: 0\r\n\r\n"
    ))
}

/// The JSON body of a response, for the routes that answer with one.
fn body_json(response: &Response) -> Json {
    let Body::Bytes(bytes) = &response.body else {
        panic!("expected a byte body");
    };
    selfhost_json::parse(std::str::from_utf8(bytes).expect("UTF-8")).expect("JSON")
}

/// Mints a ticket through the real route and returns its value.
async fn ticket_for(api: &Api, cookie: &str) -> String {
    let response = api.handle(&mint_request(cookie), b"").await;
    assert_eq!(response.status.0, 200, "the mint was refused");
    body_json(&response).get("ticket").and_then(Json::as_str).expect("a ticket").to_owned()
}

// ---------------------------------------------------------------------------
// 1. The ticket ceiling is per holder, so no principal can flush another's.
// ---------------------------------------------------------------------------

#[test]
fn no_authenticated_principal_can_flush_another_principals_tickets() {
    // The finding: `Tickets::mint` evicted the oldest entry when the store was
    // full, across holders. The store is global to the deployment, so a *second*
    // principal — any passkey holder with a live session, whatever their
    // standing — could destroy the credential the owner's browser was about to
    // redeem, simply by minting. A ticket lives thirty seconds and the console
    // mints one per CONNECT, so keeping that up denied the owner the streaming
    // console for as long as the attacker cared to loop.
    //
    // The ceiling is now counted per holder and refuses rather than evicting,
    // which is the choice the sibling implementation in `crates/desk/src/grant.rs`
    // already made.
    let tickets = Tickets::new();
    let owner = Holder::Session("owner-session".to_owned());
    let intruder = Holder::Session("intruder-session".to_owned());

    let owners = tickets.mint(owner.clone(), vec![Ability::Events]).expect("entropy");

    // Well past the ceiling, all from a different credential. The intruder is
    // stopped at their own limit and never touches anybody else's.
    let mut refused = 0;
    for _ in 0..64 {
        if let Err(MintError::TooManyOutstanding) =
            tickets.mint(intruder.clone(), vec![Ability::Events])
        {
            refused += 1;
        }
    }
    assert!(refused > 0, "an unbounded minter was never refused");

    assert_eq!(
        tickets.redeem(&owners, &owner),
        Some(vec![Ability::Events]),
        "another principal's minting destroyed this one's ticket"
    );
}

// ---------------------------------------------------------------------------
// 2. A ticket carries only what its holder may have.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_non_owner_session_mints_no_stream_ticket_and_opens_no_stream() {
    // The headline finding: `crates/identity` — `Caller`, `Capability`,
    // `Policy::decide`, `Grants` — was a complete authorisation model that
    // nothing depended on. No crate in the workspace listed `selfhost-identity`
    // in its `[dependencies]`, so the shipped mint performed no capability check
    // at all: it read the ability words out of the request body and handed them
    // back bound to whoever asked, and the handshake admitted the result.
    //
    // Sessions already carry a *person's* name — a passkey login mints
    // `Sessions::create(&passkey.user, Opening::Passkey)` — so the deployment
    // already had principals the policy crate was written to distinguish.
    let (api, sessions, people, _dir) = console_api("non-owner-mint");
    let mom = sessions.create("Mom", Opening::Passkey).expect("entropy");

    // Mom is a person with no grants. She is refused, and with the same
    // uninformative 401 an anonymous caller gets: being known to the deployment
    // must not be observable from outside it.
    let refused = api.handle(&mint_request(&mom), b"").await;
    assert_eq!(refused.status.0, 401, "a person with no grants minted a stream ticket");
    let anonymous = api
        .handle(
            &request("GET /api/services HTTP/1.1\r\nHost: admin.example.com\r\n\r\n"),
            b"",
        )
        .await;
    assert_eq!(body_json(&refused), body_json(&anonymous), "the refusal named her");

    // A ticket she never got cannot open a stream, and neither can the cookie on
    // its own: the handshake asks the policy the same question a second time.
    let denial = api
        .upgrade_for(&handshake(&mom, "selfhost.events.1", CONSOLE), Ability::Events)
        .expect_err("a stream opened for a principal holding nothing");
    assert_eq!(
        denial,
        Denial::NotPermitted(Capability::ConsoleRead, Refusal::NotGranted),
        "the handshake refused for some reason other than the policy's"
    );

    // Granted the capability by the owner, the very same person and the very
    // same routes work — the model is a gate, not a wall.
    people
        .set_grants(&person("Mom"), Grants::new([Capability::ConsoleRead]).expect("one grant"))
        .expect("the registry persists");
    let ticket = ticket_for(&api, &mom).await;
    let admitted = api
        .upgrade_for(
            &handshake(&mom, &format!("selfhost.events.1, tkt.{ticket}"), CONSOLE),
            Ability::Events,
        )
        .expect("a granted person");
    assert_eq!(admitted.identity(), &Identity::Person(person("Mom")));
}

#[tokio::test]
async fn the_owners_own_console_is_unchanged_by_any_of_this() {
    // The equivalence requirement, stated where the refusals are. Everything
    // above is a narrowing for people; for the owner — the only principal this
    // deployment has had until now — every route answers exactly as it did.
    let (api, sessions, _people, _dir) = console_api("owner-equivalence");
    let owner = sessions.create("owner", Opening::Password).expect("entropy");

    let ticket = ticket_for(&api, &owner).await;
    let admitted = api
        .upgrade_for(
            &handshake(&owner, &format!("selfhost.events.1, tkt.{ticket}"), CONSOLE),
            Ability::Events,
        )
        .expect("the owner's own console");
    assert!(admitted.identity().is_owner());

    // And the owner's authority does not come from the registry, so no state in
    // it — empty, hostile, or missing — can take the console away.
    for path in ["/api/services", "/api/firewall"] {
        let response = api
            .handle(
                &request(&format!(
                    "GET {path} HTTP/1.1\r\n\
                     Host: admin.example.com\r\n\
                     Cookie: selfhost_session={owner}\r\n\r\n"
                )),
                b"",
            )
            .await;
        assert_eq!(response.status.0, 200, "{path} closed for the owner");
    }
}

// ---------------------------------------------------------------------------
// 3. Streams are counted.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn one_session_may_not_open_unlimited_concurrent_streams() {
    // The finding: the design calls for a bounded number of concurrent upgraded
    // streams, and no counter existed. Neither `upgrade::decide` nor the socket
    // layer held any notion of how many were already open, and the ticket
    // ceiling did not bound it, because a ticket is consumed the instant it is
    // redeemed: mint-then-connect in a loop never holds more than one
    // outstanding ticket. The reviewer opened two hundred. Each one would, in
    // the daemon, be a live socket and a task sweeping the supervisor and the
    // firewall ten times a second.
    let (api, sessions, _people, _dir) = console_api("bounded-streams");
    let id = sessions.create("owner", Opening::Password).expect("entropy");

    let mut open: Vec<Admission> = Vec::new();
    let mut refusal = None;
    for _ in 0..200 {
        let ticket = ticket_for(&api, &id).await;
        match api.upgrade_for(
            &handshake(&id, &format!("selfhost.events.1, tkt.{ticket}"), CONSOLE),
            Ability::Events,
        ) {
            Ok(admission) => open.push(admission),
            Err(denial) => {
                refusal = Some(denial);
                break;
            }
        }
    }
    assert_eq!(refusal, Some(Denial::TooManyStreams), "the ceiling never bound");
    assert!(open.len() <= selfhost_admin::upgrade::MAX_STREAMS, "{} admitted", open.len());

    // And a place is given back when a stream ends, so the ceiling is a limit on
    // concurrency rather than a lifetime quota that eventually locks the console
    // out of itself.
    open.clear();
    let ticket = ticket_for(&api, &id).await;
    assert!(
        api.upgrade_for(
            &handshake(&id, &format!("selfhost.events.1, tkt.{ticket}"), CONSOLE),
            Ability::Events
        )
        .is_ok(),
        "the places held by ended streams were never released"
    );
}

// ---------------------------------------------------------------------------
// 4. A close the server decides on is a close.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_close_the_server_decided_on_ends_a_peer_that_keeps_talking() {
    // The finding: `stream::sweep`, on discovering that the session which opened
    // a stream had ended, called `Sender::close` and returned. `Sender::close`
    // only *queues* an `Outgoing::Close`; `Duplex::recv` handled that wake-up by
    // writing the frame and **looping**, without finishing. Two things followed.
    // `close_sent` suppresses every further ping, so the only remaining liveness
    // check was the pong deadline measured from the last byte the *peer* sent —
    // and the peer decides that. A client that did nothing but emit an empty
    // masked pong now and then held the socket, both tasks and the connection
    // open until `max_lifetime`, which is twelve hours in production.
    //
    // So `stream.rs` said a stream whose credential goes stale is closed, and it
    // was not: it was *asked* to close, by a peer that need not agree. The reader
    // now races the producer and enforces the close on a deadline this end owns.
    let (api, sessions, _people, _dir) = console_api("enforced-close");
    let id = sessions.create("owner", Opening::Password).expect("entropy");
    let holder = Holder::Session(id.clone());

    let streams = Streams::new();
    let admission = Admission {
        slot: streams.reserve(&holder).expect("an empty ceiling"),
        holder,
        caller: Caller::bearer(),
        abilities: vec![Ability::Events],
        accept: "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".to_owned(),
        subprotocol: None,
    };

    let (mut peer, server) = tokio::io::duplex(64 * 1024);
    let watch = Watch {
        credential_recheck: Duration::from_millis(20),
        close_grace: Duration::from_millis(200),
    };
    let serving = tokio::spawn(stream::events(server, api, admission, watch));

    // The session ends underneath the open stream — a logout, an idle expiry, or
    // an operator revoking a device.
    sessions.revoke(&id);

    // A peer that ignores the close and keeps the transport warm. Under the old
    // behaviour these pongs were enough to hold the stream open indefinitely.
    let chatter = tokio::spawn(async move {
        for _ in 0..200 {
            if tokio::io::AsyncWriteExt::write_all(&mut peer, &[0x8A, 0x80, 1, 2, 3, 4])
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    let ended = tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .expect("the stream outlived the close its own server decided on")
        .expect("the task finished")
        .expect("a clean end");
    let selfhost_ws::Closed::Peer(close) = ended else {
        panic!("expected the server's own close, got {ended}");
    };
    assert_eq!(close.code, Some(selfhost_ws::CloseCode::PolicyViolation));
    chatter.abort();
}

// ---------------------------------------------------------------------------
// 5. Cookie shadowing: every `selfhost_session` pair is tried.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_second_session_cookie_cannot_shadow_the_real_one() {
    // The finding: `session_cookie` took the *first* pair named
    // `selfhost_session` out of the `Cookie` header. A browser sends every cookie
    // for the host in one header, and cookie scope is not origin scope: any site
    // under the same registrable domain — and this box's whole purpose is hosting
    // several — can set `selfhost_session=…; Domain=<parent>`, which the browser
    // will then also send to the console host. The console's real session was
    // still there, second in the list, and was never looked at.
    //
    // That was never an authentication bypass — the planted value names no
    // session — but it was a persistent, remotely-triggered lockout of the
    // console from a neighbouring site, and it meant the string that becomes
    // `Holder::Session(..)` was chosen by whichever cookie sorted first.
    //
    // The fix is to try every candidate rather than to refuse a duplicate:
    // refusing would leave the neighbour holding exactly the same lockout, since
    // the planted cookie rides on every request.
    let (api, sessions, _people, _dir) = console_api("cookie-shadow");
    let real = sessions.create("owner", Opening::Password).expect("entropy");

    for header in [
        format!("selfhost_session={real}"),
        format!("selfhost_session=planted-by-a-sibling-site; selfhost_session={real}"),
        format!("selfhost_session={real}; selfhost_session=planted-by-a-sibling-site"),
        format!("other=1; selfhost_session=planted; selfhost_session={real}; another=2"),
    ] {
        let probe = request(&format!(
            "GET /api/session HTTP/1.1\r\n\
             Host: admin.example.com\r\n\
             Cookie: {header}\r\n\r\n"
        ));
        let response = api.handle(&probe, b"").await;
        assert_eq!(response.status.0, 200, "a planted cookie hid the real session: {header}");
        assert_eq!(body_json(&response).get("user").and_then(Json::as_str), Some("owner"));
    }

    // A planted value alone still authenticates nobody.
    let forged = request(
        "GET /api/session HTTP/1.1\r\n\
         Host: admin.example.com\r\n\
         Cookie: selfhost_session=planted-by-a-sibling-site\r\n\r\n",
    );
    assert_eq!(api.handle(&forged, b"").await.status.0, 401);
}

// ---------------------------------------------------------------------------
// 6. The login gate refuses guesses, never the operator.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_caller_that_can_reach_loopback_cannot_lock_the_operator_out() {
    // The finding: pre-existing behaviour rather than something this branch
    // introduced, but now load-bearing in a new way. The freshness rule the
    // desktop design depends on ("re-authenticate before you are handed a
    // keyboard") routes the operator back through exactly this door.
    // `FailureGate` is deliberately global — five failures in sixty seconds,
    // with no per-source counting, because loopback makes every source look the
    // same — so a co-hosted app with an SSRF that can POST to `127.0.0.1:9191`
    // with one custom header could hold the console's only re-authentication
    // path shut indefinitely.
    //
    // The sources-look-alike problem is not fixable here and this does not
    // pretend to fix it. What is fixed is the consequence: a lockout may refuse
    // a wrong credential and may never refuse a right one.
    let (api, _sessions, _people, _dir) = console_api("global-lockout");
    let neighbour = request(
        "POST /api/session HTTP/1.1\r\n\
         Host: admin.example.com\r\n\
         x-selfhost-console: 1\r\n\
         Content-Length: 20\r\n\r\n",
    );
    for _ in 0..5 {
        assert_eq!(api.handle(&neighbour, br#"{"password":"wrong"}"#).await.status.0, 401);
    }
    // The gate really is locked: the neighbour's next guess is refused.
    assert_eq!(
        api.handle(&neighbour, br#"{"password":"wrong"}"#).await.status.0,
        429,
        "the lockout stopped costing a guesser anything"
    );

    let honest = request(
        "POST /api/session HTTP/1.1\r\n\
         Host: admin.example.com\r\n\
         x-selfhost-console: 1\r\n\
         Content-Length: 22\r\n\r\n",
    );
    let admitted = api.handle(&honest, format!("{{\"password\":\"{PASSWORD}\"}}").as_bytes()).await;
    assert_eq!(admitted.status.0, 200, "the operator's own correct password was refused");
    assert!(admitted.headers.get_str("set-cookie").is_some(), "and no session was minted");
}

// ---------------------------------------------------------------------------
// 7. A ticket mint cannot end the daemon.
// ---------------------------------------------------------------------------

#[test]
fn a_ticket_expiry_that_cannot_be_represented_is_refused_rather_than_fatal() {
    // The finding: `Tickets::mint` used an unchecked `now + self.lifetime`.
    // `Instant + Duration` panics on overflow, and this workspace builds with
    // `panic = "abort"` in release — so on a box that self-updates unattended, a
    // failed mint would be the whole daemon going down.
    let tickets = Tickets::with_lifetime(Duration::MAX);
    assert!(matches!(
        tickets.mint(Holder::Bearer, vec![Ability::Events]),
        Err(MintError::ExpiryUnrepresentable)
    ));
    assert_eq!(tickets.outstanding(), 0);
}
