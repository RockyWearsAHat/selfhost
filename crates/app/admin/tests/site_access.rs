//! Access by identity, end to end through [`Api::handle`]: the one delegation
//! (`site.admin:<site>` hands out `site.access:<site>` and nothing broader),
//! signing in to a gated Site, and enrolling a Peer on the strength of a
//! private-Site Grant.

use selfhost_admin::site_pass::SitePasses;
use selfhost_admin::{Api, ConsolePassword, Sessions, Store, Token};
use selfhost_http::{Body, Request, Response};
use selfhost_identity::{Capability, Grants, Opening, PassKey, People, PersonName, SiteName, VpnLocationId};
use selfhost_json::Json;
use selfhost_supervisor::Supervisor;

const CONFIG: &str = "version = 1\n\
    [server]\n\
    http_bind = \"127.0.0.1:8080\"\n\
    https_bind = \"127.0.0.1:8443\"\n\
    acme_email = \"a@b.com\"\n\
    acme = \"self-signed\"\n\
    data_dir = \"./data\"\n\
    [[nodes]]\n\
    name = \"home\"\n\
    role = \"owner\"\n\
    [[sites]]\n\
    name = \"blog\"\n\
    domains = [\"blog.example.com\"]\n\
    static_root = \"./sites/blog\"\n\
    exposure = \"people\"\n\
    owner = \"carol\"\n\
    [[sites]]\n\
    name = \"ledger\"\n\
    domains = [\"ledger.example.com\"]\n\
    static_root = \"./sites/ledger\"\n\
    exposure = \"private\"\n\
    allowed_cidrs = [\"10.0.0.0/8\"]\n\
    [[sites]]\n\
    name = \"hello\"\n\
    domains = [\"hello.example.com\"]\n\
    static_root = \"./sites/hello\"\n\
    [[sites]]\n\
    name = \"auth\"\n\
    domains = [\"auth.example.com\"]\n\
    static_root = \"./sites/auth\"\n\
    public_api_paths = [\"/api/pass/authorize\"]\n\
    [[vpn]]\n\
    name = \"home\"\n\
    backend = \"secure-vpn\"\n\
    enabled = false\n\
    public = false\n\
    listen = \"127.0.0.1:8444\"\n\
    forward = \"127.0.0.1:443\"\n";

/// Two independent tenants on one box, each with its own private Site and its
/// own `[[vpn]]` relay — the shape Finding 1's regression test needs: a Grant
/// on one tenant's Site must never stand in for the other tenant's relay.
const CONFIG_MULTI_TENANT: &str = "version = 1\n\
    [server]\n\
    http_bind = \"127.0.0.1:8080\"\n\
    https_bind = \"127.0.0.1:8443\"\n\
    acme_email = \"a@b.com\"\n\
    acme = \"self-signed\"\n\
    data_dir = \"./data\"\n\
    [[nodes]]\n\
    name = \"home\"\n\
    role = \"owner\"\n\
    [[sites]]\n\
    name = \"office-portal\"\n\
    domains = [\"office.example.com\"]\n\
    static_root = \"./sites/office\"\n\
    exposure = \"private\"\n\
    allowed_cidrs = [\"10.0.0.0/8\"]\n\
    [[sites]]\n\
    name = \"clientb-portal\"\n\
    domains = [\"clientb.example.com\"]\n\
    static_root = \"./sites/clientb\"\n\
    exposure = \"private\"\n\
    allowed_cidrs = [\"10.1.0.0/16\"]\n\
    [[sites]]\n\
    name = \"auth\"\n\
    domains = [\"auth.example.com\"]\n\
    static_root = \"./sites/auth\"\n\
    public_api_paths = [\"/api/pass/authorize\"]\n\
    [[vpn]]\n\
    name = \"office\"\n\
    backend = \"secure-vpn\"\n\
    enabled = false\n\
    public = false\n\
    listen = \"127.0.0.1:8444\"\n\
    forward = \"127.0.0.1:443\"\n\
    [[vpn]]\n\
    name = \"clientb\"\n\
    backend = \"secure-vpn\"\n\
    enabled = false\n\
    public = false\n\
    listen = \"127.0.0.1:8445\"\n\
    forward = \"127.0.0.1:8443\"\n";

/// A 32-byte key in base64: what a device would present.
const PUBLIC_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

struct Deployment {
    api: Api,
    dir: std::path::PathBuf,
    sessions: Sessions,
    passes: SitePasses,
}

impl Drop for Deployment {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn deployment(name: &str) -> Deployment {
    deployment_with_config(name, CONFIG)
}

fn deployment_with_config(name: &str, config_text: &str) -> Deployment {
    let dir = std::env::temp_dir().join(format!("selfhost-site-access-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(selfhost_admin::token::TOKEN_FILENAME), "0123456789abcdef").unwrap();
    let config_path = dir.join("selfhost.config.toml");
    std::fs::write(&config_path, config_text).unwrap();
    let config = selfhost_config::Config::parse(config_text).expect("a valid config");
    ConsolePassword::write(&dir, "hunter2").unwrap();
    let sessions = Sessions::new();
    let passes = SitePasses::new(PassKey::ephemeral().unwrap());
    let api = Api::new(
        Supervisor::new(&dir),
        Store::new(&dir),
        Token::load_or_create(&dir).unwrap(),
        selfhost_firewall::Manager::for_config(&config),
    )
    .with_console_auth_parts(ConsolePassword::load(&dir), sessions.clone())
    .with_people(People::load(&dir))
    .with_audit(selfhost_identity::AuditLog::in_dir(&dir))
    .with_site_admin(config_path, dir.clone())
    .with_vpn(config.vpn.clone(), dir.clone())
    .with_agents(&dir)
    .with_site_passes(passes.clone());
    Deployment { api, dir, sessions, passes }
}

fn site(name: &str) -> SiteName {
    SiteName::parse(name).unwrap()
}

impl Deployment {
    fn grant(&self, person: &str, capabilities: &[Capability]) {
        let grants = Grants::new(capabilities.iter().cloned()).unwrap();
        People::load(&self.dir).set_grants(&PersonName::parse(person).unwrap(), grants).unwrap();
    }

    fn holds(&self, person: &str, capability: &Capability) -> bool {
        People::load(&self.dir)
            .find(&PersonName::parse(person).unwrap())
            .is_some_and(|entry| entry.grants.iter().any(|held| held == capability))
    }

    async fn call_as(&self, person: &str, method: &str, target: &str, body: &str) -> Response {
        let id = self.sessions.create(person, Opening::Passkey).expect("a session");
        let cookie = format!("selfhost_session={id}");
        let text = format!(
            "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: {cookie}\r\n\
             X-Selfhost-Console: 1\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let parsed = Request::parse(text.as_bytes()).expect("well-formed request");
        self.api.handle(&parsed.request, body.as_bytes()).await
    }

    async fn call_anonymously(&self, method: &str, target: &str, body: &str) -> Response {
        let text = format!(
            "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let parsed = Request::parse(text.as_bytes()).expect("well-formed request");
        self.api.handle(&parsed.request, body.as_bytes()).await
    }
}

fn body_json(response: &Response) -> Json {
    match &response.body {
        Body::Bytes(bytes) => selfhost_json::parse(std::str::from_utf8(bytes).unwrap()).unwrap(),
        _ => panic!("a JSON body"),
    }
}

// ─── Delegation ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_site_admin_hands_out_access_to_their_own_site() {
    let box_ = deployment("delegate");
    box_.grant("alice", &[Capability::SiteAdminOf(site("blog"))]);
    box_.grant("bob", &[Capability::ConsoleRead]);

    let response = box_
        .call_as("alice", "PUT", "/api/people/bob", r#"{"grants":["console.read","site.access:blog"]}"#)
        .await;
    assert_eq!(response.status.code(), 200);
    assert!(box_.holds("bob", &Capability::SiteAccess(site("blog"))));
    assert!(box_.holds("bob", &Capability::ConsoleRead), "what bob already held is untouched");

    let response =
        box_.call_as("alice", "PUT", "/api/people/bob", r#"{"grants":["console.read"]}"#).await;
    assert_eq!(response.status.code(), 200);
    assert!(!box_.holds("bob", &Capability::SiteAccess(site("blog"))), "and may take it back");
}

#[tokio::test]
async fn the_sites_owner_field_delegates_exactly_as_the_grant_does() {
    let box_ = deployment("site-owner");
    box_.grant("carol", &[Capability::ConsoleRead]);
    box_.grant("bob", &[]);
    let response =
        box_.call_as("carol", "PUT", "/api/people/bob", r#"{"grants":["site.access:blog"]}"#).await;
    assert_eq!(response.status.code(), 200);
    let response =
        box_.call_as("carol", "PUT", "/api/people/bob", r#"{"grants":["site.access:ledger"]}"#).await;
    assert_eq!(response.status.code(), 401, "carol owns blog, not ledger");
}

/// Regression: a Site's `owner` field names a Person, and only ever a
/// Person. An Agent enrolled under the exact same word must not inherit that
/// Person's ownership by sharing their name — `Identity::as_str()` renders
/// both the same way, so a bare string comparison against `caller.identity()`
/// would let it.
#[tokio::test]
async fn an_agent_with_the_same_name_as_a_site_owner_gets_none_of_their_authority() {
    let box_ = deployment("owner-vs-agent");
    // "carol" owns "blog" (see CONFIG). An Agent named "carol" exists too,
    // holding nothing of its own — the same name, a different Identity.
    let dir = box_.dir.clone();
    let agents = selfhost_admin::agent_store::AgentStore::in_dir(&dir);
    let agent_name = selfhost_identity::AgentName::parse("carol").expect("a valid agent name");
    let minted = agents.mint(&agent_name, Grants::none()).expect("mints");

    let body = r#"{"grants":["site.access:blog"]}"#;
    let text = format!(
        "PUT /api/people/bob HTTP/1.1\r\nHost: 127.0.0.1\r\n\
         Authorization: Bearer {}\r\nX-Selfhost-Console: 1\r\n\
         Content-Length: {}\r\n\r\n{body}",
        minted.as_str(),
        body.len(),
    );
    let parsed = Request::parse(text.as_bytes()).expect("well-formed request");
    let response = box_.api.handle(&parsed.request, body.as_bytes()).await;
    assert_eq!(response.status.code(), 401, "an Agent named carol is not the Person who owns blog");
    assert!(!box_.holds("bob", &Capability::SiteAccess(site("blog"))), "the refusal writes nothing");
}

#[tokio::test]
async fn a_site_admin_can_do_nothing_broader() {
    let box_ = deployment("nothing-broader");
    box_.grant("alice", &[Capability::SiteAdminOf(site("blog"))]);
    box_.grant("bob", &[Capability::ConsoleRead]);

    let refused = [
        // Another Site.
        ("/api/people/bob", r#"{"grants":["console.read","site.access:ledger"]}"#),
        // Any other word, alone or smuggled beside a legal one.
        ("/api/people/bob", r#"{"grants":["console.read","site.access:blog","service.control"]}"#),
        ("/api/people/bob", r#"{"grants":["console.read","site.admin:blog"]}"#),
        ("/api/people/bob", r#"{"grants":["console.read","vpn.access:home"]}"#),
        // Taking away something that is not theirs to take.
        ("/api/people/bob", r#"{"grants":["site.access:blog"]}"#),
        // Themselves, upward.
        ("/api/people/alice", r#"{"grants":["site.admin:blog","site.admin"]}"#),
        // A Person who does not exist yet: creating one is the owner's act.
        ("/api/people/mallory", r#"{"grants":["site.access:blog"]}"#),
        // Credentials and Peers.
        ("/api/people/bob", r#"{"grants":["console.read","site.access:blog"],"password":"a-long-enough-password"}"#),
        ("/api/people/bob", r#"{"grants":["console.read","site.access:blog"],"email":"bob@example.com"}"#),
        ("/api/people/bob", r#"{"grants":["console.read","site.access:blog"],"peer":"bob-laptop"}"#),
    ];
    for (target, body) in refused {
        let response = box_.call_as("alice", "PUT", target, body).await;
        assert_eq!(response.status.code(), 401, "{target} {body}");
    }
    assert!(!box_.holds("bob", &Capability::SiteAccess(site("blog"))), "a refusal writes nothing");
    assert!(box_.holds("bob", &Capability::ConsoleRead));
    assert!(People::load(&box_.dir).find(&PersonName::parse("mallory").unwrap()).is_none());

    // Holding access is not holding the right to hand it out.
    box_.grant("dave", &[Capability::SiteAccess(site("blog"))]);
    let response = box_
        .call_as("dave", "PUT", "/api/people/bob", r#"{"grants":["console.read","site.access:blog"]}"#)
        .await;
    assert_eq!(response.status.code(), 401);
}

// ─── Signing in to a Site ─────────────────────────────────────────────────────

#[tokio::test]
async fn a_grant_buys_a_one_time_code_for_that_site_and_a_safe_path() {
    let box_ = deployment("pass-authorize");
    box_.grant("bob", &[Capability::SiteAccess(site("blog"))]);

    let response = box_
        .call_as("bob", "POST", "/api/pass/authorize", r#"{"return":"https://blog.example.com/drafts?x=1"}"#)
        .await;
    assert_eq!(response.status.code(), 200);
    let redirect = body_json(&response).get("redirect").and_then(Json::as_str).unwrap().to_owned();
    let code = redirect.strip_prefix("https://blog.example.com/.selfhost/pass?code=").expect("the site's own door");

    let redeemed = box_.passes.redeem(code, &site("blog")).expect("the proxy's half redeems it");
    assert_eq!(redeemed.return_path, "/drafts?x=1");
    assert_eq!(redeemed.person.as_str(), "bob");
    assert!(box_.passes.redeem(code, &site("blog")).is_none(), "once");
}

#[tokio::test]
async fn signed_in_without_a_grant_is_a_plain_403_and_the_site_owner_needs_none() {
    let box_ = deployment("pass-no-grant");
    box_.grant("bob", &[Capability::SiteAccess(site("blog"))]);
    box_.grant("carol", &[]);
    let ledger = r#"{"return":"https://ledger.example.com/"}"#;
    assert_eq!(box_.call_as("bob", "POST", "/api/pass/authorize", ledger).await.status.code(), 403);
    let blog = r#"{"return":"https://blog.example.com/"}"#;
    assert_eq!(box_.call_as("carol", "POST", "/api/pass/authorize", blog).await.status.code(), 200);
    assert_eq!(box_.call_anonymously("POST", "/api/pass/authorize", blog).await.status.code(), 401);
}

#[tokio::test]
async fn a_return_url_that_is_not_a_gated_site_of_this_deployment_is_refused() {
    let box_ = deployment("pass-open-redirect");
    box_.grant("bob", &[Capability::SiteAccess(site("blog"))]);
    for wanted in [
        "https://evil.example/",
        "http://blog.example.com/",
        "//blog.example.com/",
        "https://blog.example.com@evil.example/",
        "https://blog.example.com:8443/",
        "https://blog.example.com//evil.example/",
        "https://blog.example.com/\\evil.example/",
        "https://blog.example.com/.selfhost/pass?code=x",
        // A Site of this deployment, but a public one: it has no Pass to give.
        "https://hello.example.com/",
    ] {
        let body = Json::object([("return", Json::string(wanted))]).to_text();
        let response = box_.call_as("bob", "POST", "/api/pass/authorize", &body).await;
        assert_eq!(response.status.code(), 400, "{wanted}");
    }
}

// ─── Enrolling a Peer ─────────────────────────────────────────────────────────

fn challenge_for(verifier: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
    selfhost_identity::pass::b64url_encode(digest.as_ref())
}

async fn authorize(box_: &Deployment, person: &str, verifier: &str) -> Response {
    // No `location`: the deployment's own relay is the default.
    let body = Json::object([("codeChallenge", Json::string(&challenge_for(verifier)))]).to_text();
    box_.call_as(person, "POST", "/api/vpn/authorize", &body).await
}

async fn authorize_for(box_: &Deployment, person: &str, verifier: &str, location: &str) -> Response {
    let body = Json::object([
        ("location", Json::string(location)),
        ("codeChallenge", Json::string(&challenge_for(verifier))),
    ])
    .to_text();
    box_.call_as(person, "POST", "/api/vpn/authorize", &body).await
}

async fn enroll(box_: &Deployment, code: &str, verifier: &str, peer: &str) -> Response {
    let body = Json::object([
        ("code", Json::string(code)),
        ("verifier", Json::string(verifier)),
        ("peer", Json::string(peer)),
        ("public_key", Json::string(PUBLIC_KEY)),
    ])
    .to_text();
    box_.call_anonymously("POST", "/api/vpn/enroll", &body).await
}

#[tokio::test]
async fn a_grant_on_a_private_site_authorises_enrolling_a_peer() {
    let box_ = deployment("enroll-by-site");
    box_.grant("bob", &[Capability::SiteAccess(site("ledger"))]);
    // `blog` is `people`: reachable from anywhere, so it is no reason for a Peer.
    box_.grant("dave", &[Capability::SiteAccess(site("blog"))]);
    box_.grant("erin", &[Capability::ConsoleRead]);

    assert_eq!(authorize(&box_, "dave", "v-dave").await.status.code(), 403);
    assert_eq!(authorize(&box_, "erin", "v-erin").await.status.code(), 403);

    let response = authorize(&box_, "bob", "v-bob").await;
    assert_eq!(response.status.code(), 200);
    let code = body_json(&response).get("code").and_then(Json::as_str).unwrap().to_owned();
    let response = enroll(&box_, &code, "v-bob", "bob-laptop-4f2a").await;
    assert_eq!(response.status.code(), 200);
    let reply = body_json(&response);
    assert_eq!(reply.get("name").and_then(Json::as_str), Some("bob"));
    assert_eq!(reply.get("location").and_then(Json::as_str), Some("home"));

    // The roster side effect still happens, under the Peer's own name.
    let relay = &selfhost_config::Config::parse(CONFIG).unwrap().vpn[0];
    let key_dir = selfhost_vpn::keys::key_dir(relay, &box_.dir);
    assert!(selfhost_vpn::keys::peer_key_file(&key_dir, "bob-laptop-4f2a").exists());
    assert_eq!(
        selfhost_admin::peer_binding::owner_of(&box_.dir, "bob-laptop-4f2a").as_deref(),
        Some("bob")
    );
}

/// Regression: with more than one `[[vpn]]` relay on the box (independent
/// tenants), a Grant on one tenant's private Site must never authorise
/// enrolling a Peer on *any* relay by falling back on "reaches some
/// network-gated Site" — that fallback only holds when there is exactly one
/// relay for it to mean. A contractor holding only the office tenant's Site
/// access must not be able to ask for `clientb`'s relay and get in, nor even
/// for `office`'s own relay without an explicit `vpn.access` Grant.
#[tokio::test]
async fn a_site_grant_never_authorises_a_relay_on_a_multi_relay_deployment() {
    let box_ = deployment_with_config("multi-tenant", CONFIG_MULTI_TENANT);
    box_.grant("mallory", &[Capability::SiteAccess(site("office-portal"))]);

    // The exact exploit: asking for a different tenant's relay.
    assert_eq!(authorize_for(&box_, "mallory", "v-cross", "clientb").await.status.code(), 403);
    // Even the matching tenant's own relay is refused — once there is more
    // than one relay, a Site Grant alone no longer says which one.
    assert_eq!(authorize_for(&box_, "mallory", "v-same", "office").await.status.code(), 403);

    // An explicit vpn.access Grant still works, exactly as before.
    box_.grant(
        "mallory",
        &[Capability::SiteAccess(site("office-portal")), Capability::VpnAccess(VpnLocationId::parse("office").unwrap())],
    );
    assert_eq!(authorize_for(&box_, "mallory", "v-explicit", "office").await.status.code(), 200);
}

#[tokio::test]
async fn a_peer_is_one_persons_and_never_the_shared_client() {
    let box_ = deployment("enroll-binding");
    box_.grant("bob", &[Capability::SiteAccess(site("ledger"))]);
    box_.grant("frank", &[Capability::SiteAccess(site("ledger"))]);

    let code = |response: Response| body_json(&response).get("code").and_then(Json::as_str).unwrap().to_owned();

    let first = code(authorize(&box_, "bob", "v1").await);
    assert_eq!(enroll(&box_, &first, "v1", "client").await.status.code(), 409);

    let second = code(authorize(&box_, "bob", "v2").await);
    assert_eq!(enroll(&box_, &second, "v2", "shared-laptop").await.status.code(), 200);

    let third = code(authorize(&box_, "frank", "v3").await);
    assert_eq!(
        enroll(&box_, &third, "v3", "shared-laptop").await.status.code(),
        409,
        "bob's Peer is not frank's to re-key"
    );
}
