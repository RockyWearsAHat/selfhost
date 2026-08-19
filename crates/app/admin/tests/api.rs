//! Route and authorisation behaviour of the control API.
//!
//! Driven through [`Api::handle`] rather than a socket, so every route — and
//! every way of getting authorisation wrong — is exercised without binding a
//! port. The socket layer is tested separately in `wire.rs`.

use selfhost_admin::{Api, ConsolePassword, Sessions, Store, Token};
use selfhost_http::{Body, Request, Response};
use selfhost_json::Json;
use selfhost_supervisor::Supervisor;

const TOKEN: &str = "0123456789abcdef";

/// The console password every session test logs in with.
const PASSWORD: &str = "hunter2";

/// An API over a scratch directory, plus the directory that cleans it up.
fn api(name: &str) -> (Api, ScratchDir) {
    let (api, _watches, dir) = api_with_watches(name);
    (api, dir)
}

/// The same, keeping hold of the watch set so a test can see what it follows.
fn api_with_watches(name: &str) -> (Api, selfhost_git::Watches, ScratchDir) {
    let dir = ScratchDir::new(name);
    let token = write_token(dir.path(), TOKEN);
    let watches = selfhost_git::Watches::default();
    let api = Api::new(
        Supervisor::new(dir.path()),
        Store::new(dir.path()),
        token,
        watches.clone(),
        firewall_manager(),
    );
    (api, watches, dir)
}

/// A firewall manager over a minimal, unmanaged config.
///
/// Built from real config text so the test does not have to track the shape of
/// `Server`. `manage` is off by default, so `for_config` derives no rules and the
/// firewall routes exercise the wiring without depending on a drivable firewall.
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
         role = \"owner\"\n\
         [[sites]]\n\
         name = \"hello\"\n\
         domains = [\"localhost\"]\n\
         static_root = \"./sites/hello\"\n",
    )
    .expect("a minimal valid config");
    selfhost_firewall::Manager::for_config(&config)
}

/// A service definition carrying a Git watch, as JSON.
fn watched_body(name: &str, interval: u64) -> String {
    Json::object([
        ("name", Json::string(name)),
        ("program", Json::string("/bin/true")),
        ("startMode", Json::string("manual")),
        (
            "git",
            Json::object([
                ("repository", Json::string("https://github.com/owner/repo.git")),
                ("path", Json::string("checkouts/site")),
                ("intervalSecs", Json::Number(interval as f64)),
            ]),
        ),
    ])
    .to_text()
}

/// Plants a known token so tests can authenticate deterministically.
fn write_token(dir: &std::path::Path, value: &str) -> Token {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(selfhost_admin::token::TOKEN_FILENAME), value).unwrap();
    Token::load_or_create(dir).expect("loads the token we just wrote")
}

/// The same API, with console login enabled over a known password.
///
/// Sessions are injectable so the expiry test can use lifetimes measured in
/// nothing rather than hours; every other test passes `Sessions::new()`.
fn console_api(name: &str, sessions: Sessions) -> (Api, ScratchDir) {
    let (api, dir) = api(name);
    ConsolePassword::write(dir.path(), PASSWORD).expect("password written");
    let api = api.with_console_auth_parts(ConsolePassword::load(dir.path()), sessions);
    (api, dir)
}

/// Builds a request, parsing it the same way the server would.
fn request(method: &str, target: &str, auth: Option<&str>, body: &str) -> (Request, Vec<u8>) {
    request_with(method, target, auth, &[], body)
}

/// The same, with arbitrary extra headers — how a test presents a cookie or
/// the CSRF header.
fn request_with(
    method: &str,
    target: &str,
    auth: Option<&str>,
    headers: &[(&str, &str)],
    body: &str,
) -> (Request, Vec<u8>) {
    let mut text = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    if let Some(token) = auth {
        text.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    for (name, value) in headers {
        text.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty() {
        text.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    text.push_str("\r\n");
    let parsed = Request::parse(text.as_bytes()).expect("well-formed request");
    (parsed.request, body.as_bytes().to_vec())
}

/// Sends a request and returns the status code and parsed JSON body.
async fn send(api: &Api, method: &str, target: &str, body: &str) -> (u16, Json) {
    call(api, method, target, Some(TOKEN), body).await
}

async fn call(
    api: &Api,
    method: &str,
    target: &str,
    auth: Option<&str>,
    body: &str,
) -> (u16, Json) {
    let (request, body) = request(method, target, auth, body);
    let response = api.handle(&request, &body).await;
    (response.status.code(), body_json(&response))
}

/// Sends a request with extra headers, returning the full response.
///
/// Returns the [`Response`] rather than the digested pair because the session
/// tests assert on the `Set-Cookie` header, not just the body.
async fn call_with(api: &Api, method: &str, target: &str, headers: &[(&str, &str)], body: &str) -> Response {
    let (request, body) = request_with(method, target, None, headers, body);
    api.handle(&request, &body).await
}

/// Logs in and returns the session cookie's `name=value` pair.
async fn login(api: &Api) -> String {
    let response =
        call_with(api, "POST", "/api/session", &[("X-Selfhost-Console", "1")], &format!(r#"{{"password":"{PASSWORD}"}}"#)).await;
    assert_eq!(response.status.code(), 200, "login should succeed: {:?}", body_json(&response));
    session_cookie_pair(&response)
}

/// Sends a request as the deployment's owner: a console password login.
///
/// The routes that create authority — the people registry, the invitations,
/// revoking a passkey — stopped accepting the bearer token when the token
/// stopped being the owner. Nothing that holds the token has ever needed to
/// mint a person, so a test that means "the operator did this" has to say so
/// rather than reach for the credential that used to answer for everybody.
async fn as_owner(api: &Api, method: &str, target: &str, body: &str) -> (u16, Json) {
    let cookie = login(api).await;
    let response = call_with(
        api,
        method,
        target,
        &[("Cookie", &cookie), ("X-Selfhost-Console", "1")],
        body,
    )
    .await;
    (response.status.code(), body_json(&response))
}

/// Logs in with a registered passkey and returns the session cookie.
///
/// The credential that names its holder, which is what the authority routes ask
/// for once a deployment has one.
async fn passkey_login(api: &Api, device: &Authenticator) -> String {
    let challenge = login_challenge(api).await;
    assert_eq!(challenge.status.code(), 200, "a challenge once a passkey exists");
    let challenge =
        body_json(&challenge).get("challenge").and_then(Json::as_str).expect("a challenge").to_owned();
    let reply = call_with(
        api,
        "POST",
        "/api/webauthn/login",
        &[("X-Selfhost-Console", "1")],
        &device.login_body(&challenge),
    )
    .await;
    assert_eq!(reply.status.code(), 200, "{:?}", body_json(&reply));
    session_cookie_pair(&reply)
}

/// Extracts `selfhost_session=<id>` from a response's `Set-Cookie` header.
fn session_cookie_pair(response: &Response) -> String {
    let header = response.headers.get_str("set-cookie").expect("a Set-Cookie header");
    let pair = header.split(';').next().expect("cookie pair").trim();
    assert!(pair.starts_with("selfhost_session="), "unexpected cookie: {header}");
    pair.to_owned()
}

fn body_json(response: &Response) -> Json {
    match &response.body {
        Body::Bytes(bytes) => selfhost_json::parse(std::str::from_utf8(bytes).expect("utf-8"))
            .expect("responses are JSON"),
        _ => Json::Null,
    }
}

/// A service definition that stays up, as JSON.
fn long_running_body(name: &str) -> String {
    let (program, args) = selfhost_supervisor::shell_command(if cfg!(windows) {
        "ping -n 31 127.0.0.1 >NUL"
    } else {
        "sleep 30"
    });
    Json::object([
        ("name", Json::string(name)),
        ("program", Json::string(program.display().to_string())),
        ("args", Json::array(args.iter().map(Json::string))),
        ("startMode", Json::string("manual")),
        ("restartDelaySecs", Json::Number(1.0)),
        ("stopTimeoutSecs", Json::Number(2.0)),
    ])
    .to_text()
}

#[tokio::test]
async fn health_needs_no_credentials_so_a_tunnel_can_be_checked() {
    let (api, _dir) = api("health");
    let (status, body) = call(&api, "GET", "/api/health", None, "").await;
    assert_eq!(status, 200);
    assert_eq!(body.get("ok").and_then(Json::as_bool), Some(true));
}

#[tokio::test]
async fn every_real_endpoint_refuses_an_unauthenticated_caller() {
    let (api, _dir) = api("noauth");
    for (method, target) in [
        ("GET", "/api/services"),
        ("GET", "/api/services/x"),
        ("PUT", "/api/services/x"),
        ("DELETE", "/api/services/x"),
        ("GET", "/api/services/x/logs"),
        ("POST", "/api/services/x/start"),
        ("POST", "/api/services/x/deploy"),
        // The firewall reveals the deployment's open ports, so it too is behind
        // the token wall — only /api/health is unauthenticated.
        ("GET", "/api/firewall"),
        ("POST", "/api/firewall/reconcile"),
        // The session probe: POST and DELETE /api/session are deliberately
        // reachable without credentials (logging in is how credentials are
        // *obtained*), but the GET probe is a refusal like any other.
        ("GET", "/api/session"),
    ] {
        let (status, _) = call(&api, method, target, None, "").await;
        assert_eq!(status, 401, "{method} {target} should require a token");
    }
}

#[tokio::test]
async fn firewall_state_is_reported_as_json() {
    let (api, _dir) = api("firewall-state");
    let (status, body) = send(&api, "GET", "/api/firewall", "").await;
    assert_eq!(status, 200);
    // The scratch config leaves `manage` off, so the daemon governs nothing and
    // says so rather than erroring.
    assert_eq!(body.get("managed").and_then(Json::as_bool), Some(false));
    assert!(body.get("backend").and_then(Json::as_str).is_some(), "{body:?}");
    assert!(body.get("rules").and_then(Json::as_array).is_some(), "{body:?}");
}

#[tokio::test]
async fn firewall_reconcile_is_wired_and_answers_in_json() {
    let (api, _dir) = api("firewall-reconcile");
    // Route is wired (not a 404) and returns JSON. Whether the host firewall can
    // actually be driven is the backend's concern and machine-dependent, so this
    // asserts the daemon-admin contract only: reconcile either succeeds (200) or
    // reports why it could not (500) — never a silent 404.
    let (status, body) = send(&api, "POST", "/api/firewall/reconcile", "").await;
    assert_ne!(status, 404, "the reconcile route must be wired");
    assert!(
        status == 200 || status == 500,
        "reconcile answers 200 or a 500 with a reason, got {status}: {body:?}"
    );
    if status == 500 {
        assert!(body.get("error").and_then(Json::as_str).is_some(), "{body:?}");
    }
}

#[tokio::test]
async fn a_wrong_token_is_refused_and_told_nothing_useful() {
    let (api, _dir) = api("wrongtoken");
    let (status, body) = call(&api, "GET", "/api/services", Some("not-the-token"), "").await;
    assert_eq!(status, 401);
    // The reply must not distinguish "no token" from "wrong token", or it
    // confirms to a guesser that they are making progress.
    let (_, missing) = call(&api, "GET", "/api/services", None, "").await;
    assert_eq!(body, missing);
}

#[tokio::test]
async fn a_token_that_is_a_prefix_of_the_real_one_is_refused() {
    let (api, _dir) = api("prefix");
    let (status, _) = call(&api, "GET", "/api/services", Some(&TOKEN[..8]), "").await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn an_empty_deployment_lists_no_services() {
    let (api, _dir) = api("empty");
    let (status, body) = send(&api, "GET", "/api/services", "").await;
    assert_eq!(status, 200);
    assert_eq!(body.get("services").and_then(Json::as_array).map(<[Json]>::len), Some(0));
}

#[tokio::test]
async fn installing_a_service_persists_it_and_lists_it() {
    let (api, dir) = api("install");
    let (status, _) = send(&api, "PUT", "/api/services/webapp", &long_running_body("webapp")).await;
    assert_eq!(status, 200);

    let (_, listed) = send(&api, "GET", "/api/services", "").await;
    let services = listed.get("services").and_then(Json::as_array).expect("an array");
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].get("name").and_then(Json::as_str), Some("webapp"));

    // Persisted, not merely running: a service absent from the catalogue would
    // vanish at the next daemon restart.
    let catalog = std::fs::read_to_string(dir.path().join("services.toml")).expect("written");
    assert!(catalog.contains("webapp"), "{catalog}");

    api.supervisor().shutdown().await;
}

#[tokio::test]
async fn the_path_names_the_service_even_when_the_body_disagrees() {
    // Ambiguity is resolved rather than guessed at, and visibly: PUT /x with a
    // body naming "y" installs "x".
    let (api, _dir) = api("naming");
    let body = long_running_body("from-body");
    let (status, _) = send(&api, "PUT", "/api/services/from-path", &body).await;
    assert_eq!(status, 200);

    let (_, listed) = send(&api, "GET", "/api/services", "").await;
    let services = listed.get("services").and_then(Json::as_array).unwrap();
    assert_eq!(services[0].get("name").and_then(Json::as_str), Some("from-path"));

    api.supervisor().shutdown().await;
}

#[tokio::test]
async fn a_definition_missing_a_program_is_refused() {
    let (api, _dir) = api("noprogram");
    let (status, body) = send(&api, "PUT", "/api/services/x", r#"{"name":"x"}"#).await;
    assert_eq!(status, 400);
    assert!(body.get("error").is_some());
}

#[tokio::test]
async fn a_definition_that_fails_validation_reports_the_offending_field() {
    let (api, _dir) = api("badspec");
    let body = Json::object([
        ("name", Json::string("x")),
        ("program", Json::string("/bin/true")),
        ("restart", Json::string("always")),
        // Zero delay respawns as fast as the machine can fork.
        ("restartDelaySecs", Json::Number(0.0)),
    ])
    .to_text();

    let (status, reply) = send(&api, "PUT", "/api/services/x", &body).await;
    assert_eq!(status, 422);
    let problems = reply.get("problems").and_then(Json::as_array).expect("problems listed");
    assert!(
        problems.iter().any(|p| p
            .get("field")
            .and_then(Json::as_str)
            .is_some_and(|f| f.contains("restart_delay_secs"))),
        "{reply:?}"
    );
}

#[tokio::test]
async fn malformed_json_is_refused_with_an_explanation() {
    let (api, _dir) = api("badjson");
    let (status, body) = send(&api, "PUT", "/api/services/x", "{not json").await;
    assert_eq!(status, 400);
    assert!(body.get("error").and_then(Json::as_str).is_some_and(|e| e.contains("JSON")));
}

#[tokio::test]
async fn lifecycle_actions_are_accepted_and_take_effect() {
    let (api, _dir) = api("lifecycle");
    send(&api, "PUT", "/api/services/app", &long_running_body("app")).await;

    let (status, _) = send(&api, "POST", "/api/services/app/start", "").await;
    assert_eq!(status, 202, "the command is accepted, not awaited");

    let running = selfhost_supervisor::await_state(
        api.supervisor(),
        "app",
        std::time::Duration::from_secs(15),
        |s| matches!(s, selfhost_supervisor::state::ServiceState::Running { .. }),
    )
    .await;
    assert!(running.is_some(), "start should actually start it");

    let (_, described) = send(&api, "GET", "/api/services/app", "").await;
    assert_eq!(
        described.get("status").and_then(|s| s.get("state")).and_then(Json::as_str),
        Some("running")
    );

    send(&api, "POST", "/api/services/app/stop", "").await;
    let stopped = selfhost_supervisor::await_state(
        api.supervisor(),
        "app",
        std::time::Duration::from_secs(15),
        |s| matches!(s, selfhost_supervisor::state::ServiceState::Stopped),
    )
    .await;
    assert!(stopped.is_some(), "stop should actually stop it");

    api.supervisor().shutdown().await;
}

#[tokio::test]
async fn logs_are_returned_incrementally_with_a_resume_point() {
    let (api, _dir) = api("logs");
    send(&api, "PUT", "/api/services/app", &long_running_body("app")).await;
    send(&api, "POST", "/api/services/app/start", "").await;

    let (status, body) = send(&api, "GET", "/api/services/app/logs?from=0", "").await;
    assert_eq!(status, 200);
    assert!(body.get("nextSeq").and_then(Json::as_u64).is_some());
    assert_eq!(body.get("missed").and_then(Json::as_u64), Some(0));

    api.supervisor().shutdown().await;
}

#[tokio::test]
async fn uninstalling_removes_it_from_the_catalogue_too() {
    let (api, dir) = api("uninstall");
    send(&api, "PUT", "/api/services/gone", &long_running_body("gone")).await;

    let (status, _) = send(&api, "DELETE", "/api/services/gone", "").await;
    assert_eq!(status, 200);

    let (_, listed) = send(&api, "GET", "/api/services", "").await;
    assert_eq!(listed.get("services").and_then(Json::as_array).map(<[Json]>::len), Some(0));

    let catalog = std::fs::read_to_string(dir.path().join("services.toml")).unwrap_or_default();
    assert!(!catalog.contains("gone"), "still in the catalogue: {catalog}");
}

#[tokio::test]
async fn acting_on_a_service_that_does_not_exist_is_a_404_not_a_silent_success() {
    let (api, _dir) = api("missing");
    for (method, target) in [
        ("GET", "/api/services/ghost"),
        ("DELETE", "/api/services/ghost"),
        ("GET", "/api/services/ghost/logs"),
        ("POST", "/api/services/ghost/start"),
        ("POST", "/api/services/ghost/deploy"),
    ] {
        let (status, _) = send(&api, method, target, "").await;
        assert_eq!(status, 404, "{method} {target}");
    }
}

#[tokio::test]
async fn an_unknown_endpoint_is_a_404() {
    let (api, _dir) = api("unknown");
    let (status, _) = send(&api, "GET", "/api/nonsense", "").await;
    assert_eq!(status, 404);
    let (status, _) = send(&api, "POST", "/api/services/x/detonate", "").await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn installing_a_watched_service_starts_watching_it_there_and_then() {
    // Not at the next daemon restart: a service installed from the console that
    // is not polled until somebody reboots the daemon looks exactly like one
    // whose branch nobody has pushed to.
    let (api, watches, _dir) = api_with_watches("install-watch");
    let (status, _) = send(&api, "PUT", "/api/services/site", &watched_body("site", 60)).await;
    assert_eq!(status, 200);
    assert_eq!(watches.count().await, 1);

    let (status, _) = send(&api, "DELETE", "/api/services/site", "").await;
    assert_eq!(status, 200);
    assert_eq!(watches.count().await, 0, "a watch must not outlive its service");
}

#[tokio::test]
async fn a_service_whose_watch_is_invalid_is_refused_with_the_offending_field() {
    let (api, watches, _dir) = api_with_watches("bad-watch");
    let (status, body) = send(&api, "PUT", "/api/services/site", &watched_body("site", 1)).await;
    assert_eq!(status, 422);

    let problems = body.get("problems").and_then(Json::as_array).expect("problems").to_vec();
    assert!(
        problems
            .iter()
            .any(|p| p.get("field").and_then(Json::as_str) == Some("service.git.interval_secs")),
        "{problems:?}"
    );
    assert_eq!(watches.count().await, 0, "a refused service must not be watched");
}

#[tokio::test]
async fn a_repository_url_that_would_run_a_command_is_refused_by_the_api() {
    let (api, _watches, _dir) = api_with_watches("evil-watch");
    let body = Json::object([
        ("name", Json::string("site")),
        ("program", Json::string("/bin/true")),
        (
            "git",
            Json::object([
                ("repository", Json::string("ext::sh -c 'id > /tmp/pwned'")),
                ("path", Json::string("checkouts/site")),
            ]),
        ),
    ])
    .to_text();

    let (status, _) = send(&api, "PUT", "/api/services/site", &body).await;
    assert_eq!(status, 422, "git's ext:: transport runs its argument as a command");
}

#[tokio::test]
async fn deploying_a_service_with_no_git_watch_is_a_404() {
    let (api, _dir) = api("deploy-no-watch");
    send(&api, "PUT", "/api/services/app", &long_running_body("app")).await;

    let (status, body) = send(&api, "POST", "/api/services/app/deploy", "").await;
    assert_eq!(status, 404);
    assert!(body.get("error").and_then(Json::as_str).is_some());

    api.supervisor().shutdown().await;
}

#[tokio::test]
async fn deploying_a_watched_service_is_accepted_without_waiting_for_the_poll_interval() {
    // 202, not 200 — this reports the deployment was accepted, mirroring every
    // other action route; it does not await the stop/pull/build/start sequence,
    // which can take as long as the build step allows.
    let (api, watches, _dir) = api_with_watches("deploy-watched");
    send(&api, "PUT", "/api/services/site", &watched_body("site", 60)).await;
    assert_eq!(watches.count().await, 1);

    let (status, body) = send(&api, "POST", "/api/services/site/deploy", "").await;
    assert_eq!(status, 202);
    assert_eq!(body.get("accepted").and_then(Json::as_bool), Some(true));
    assert_eq!(body.get("service").and_then(Json::as_str), Some("site"));
}

// ---- cookie-session authentication -----------------------------------------

#[tokio::test]
async fn logging_in_sets_a_cookie_that_authorises_reads_without_extra_headers() {
    let (api, _dir) = console_api("login", Sessions::new());
    let response =
        call_with(&api, "POST", "/api/session", &[("X-Selfhost-Console", "1")], &format!(r#"{{"password":"{PASSWORD}"}}"#))
            .await;
    assert_eq!(response.status.code(), 200);
    assert_eq!(body_json(&response).get("ok").and_then(Json::as_bool), Some(true));

    // The cookie carries every defensive attribute, not just the id.
    let header = response.headers.get_str("set-cookie").expect("a Set-Cookie header");
    for attribute in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/", "Max-Age=43200"] {
        assert!(header.contains(attribute), "missing {attribute}: {header}");
    }

    // A GET with the cookie needs no CSRF header.
    let cookie = session_cookie_pair(&response);
    let listed = call_with(&api, "GET", "/api/services", &[("Cookie", &cookie)], "").await;
    assert_eq!(listed.status.code(), 200, "the session should open the API");

    // And the probe agrees the session is live.
    let probe = call_with(&api, "GET", "/api/session", &[("Cookie", &cookie)], "").await;
    assert_eq!(probe.status.code(), 200);
}

#[tokio::test]
async fn a_wrong_console_password_gets_the_same_uninformative_401_as_no_credentials() {
    let (api, _dir) = console_api("wrongpw", Sessions::new());
    let response =
        call_with(&api, "POST", "/api/session", &[("X-Selfhost-Console", "1")], r#"{"password":"not-the-password"}"#).await;
    assert_eq!(response.status.code(), 401);
    assert!(response.headers.get_str("set-cookie").is_none(), "no cookie on failure");

    // Identical body to any other unauthorised request: a guesser learns
    // nothing about whether a console password is even configured.
    let (_, unauthenticated) = call(&api, "GET", "/api/services", None, "").await;
    assert_eq!(body_json(&response), unauthenticated);
}

#[tokio::test]
async fn a_locked_gate_refuses_more_guesses_and_never_the_right_password() {
    // The rule the adversarial review changed, and the whole of it in one test.
    //
    // The old rule refused *everything* once five failures had landed inside the
    // window, the operator's own correct password included. On this box that is a
    // weapon pointed the wrong way: the admin API binds loopback and the console
    // site's `allowed_cidrs` gate is loopback too, so anything already executing
    // here — including three co-hosted web apps — can drive five failures and
    // hold the console's only login shut. The desktop design sends the operator
    // back through this exact door to be handed a keyboard.
    //
    // The rule now: a lockout may refuse a wrong credential and may never refuse
    // a right one.
    let (api, _dir) = console_api("ratelimit", Sessions::new());
    for _ in 0..5 {
        let response = call_with(&api, "POST", "/api/session", &[("X-Selfhost-Console", "1")], r#"{"password":"wrong"}"#).await;
        assert_eq!(response.status.code(), 401, "failures under the limit are ordinary 401s");
    }

    // A sixth guess meets the lockout, and pays for it.
    let guess = call_with(&api, "POST", "/api/session", &[("X-Selfhost-Console", "1")], r#"{"password":"wrong"}"#).await;
    assert_eq!(guess.status.code(), 429, "a guess past the limit is refused");
    assert_eq!(body_json(&guess).get("error").and_then(Json::as_str), Some("too many attempts"));

    // The operator, at the same instant, with the same locked gate, gets in.
    let response =
        call_with(&api, "POST", "/api/session", &[("X-Selfhost-Console", "1")], &format!(r#"{{"password":"{PASSWORD}"}}"#))
            .await;
    assert_eq!(response.status.code(), 200, "a locked gate refused the right password");
    assert!(response.headers.get_str("set-cookie").is_some(), "and it minted a session");

    // A success clears the count, so the next wrong guess is an ordinary 401
    // again rather than the tail of somebody else's burst.
    let after = call_with(&api, "POST", "/api/session", &[("X-Selfhost-Console", "1")], r#"{"password":"wrong"}"#).await;
    assert_eq!(after.status.code(), 401);
}

#[tokio::test]
async fn a_cookie_authenticated_write_needs_the_console_header() {
    let (api, _dir) = console_api("csrf", Sessions::new());
    let cookie = login(&api).await;

    // Without X-Selfhost-Console a non-GET is refused — 401 with the standard
    // body, indistinguishable from any other refusal — because a cross-site
    // page can make the browser attach the cookie but not a custom header.
    let forged =
        call_with(&api, "POST", "/api/services/ghost/start", &[("Cookie", &cookie)], "").await;
    assert_eq!(forged.status.code(), 401);

    // With the header the same request passes authorisation and reaches the
    // route, which answers 404 for the nonexistent service.
    let real = call_with(
        &api,
        "POST",
        "/api/services/ghost/start",
        &[("Cookie", &cookie), ("X-Selfhost-Console", "1")],
        "",
    )
    .await;
    assert_eq!(real.status.code(), 404, "authorised, then refused only by the route");
}

#[tokio::test]
async fn a_login_post_without_the_console_header_is_refused_before_the_gate() {
    let (api, _dir) = console_api("login-csrf", Sessions::new());

    // A cross-site simple POST (no custom header, no preflight) must not even
    // reach the password check — otherwise it could drive the global failure
    // gate and lock every legitimate login. The refusal is the standard 401,
    // and crucially it does NOT count as a failure: the correct password still
    // works immediately afterwards from a real (header-bearing) request.
    let forged =
        call_with(&api, "POST", "/api/session", &[], &format!(r#"{{"password":"{PASSWORD}"}}"#)).await;
    assert_eq!(forged.status.code(), 401);

    let real = login(&api).await;
    assert!(real.starts_with("selfhost_session="), "real login still works: {real}");
}

#[tokio::test]
async fn bearer_requests_never_need_the_console_header() {
    // The console client and the webhook relay present the token exactly as
    // they always have; the CSRF rule is for cookies only.
    let (api, _dir) = console_api("bearer-no-header", Sessions::new());
    let (status, _) = send(&api, "POST", "/api/services/ghost/start", "").await;
    assert_eq!(status, 404, "authorised by the token alone, refused only by the route");
}

#[tokio::test]
async fn logging_out_revokes_the_session_and_expires_the_cookie() {
    let (api, _dir) = console_api("logout", Sessions::new());
    let cookie = login(&api).await;

    let out = call_with(&api, "DELETE", "/api/session", &[("Cookie", &cookie)], "").await;
    assert_eq!(out.status.code(), 200);
    let header = out.headers.get_str("set-cookie").expect("an expiring Set-Cookie");
    assert!(header.contains("Max-Age=0"), "the browser must discard the cookie: {header}");

    let after = call_with(&api, "GET", "/api/services", &[("Cookie", &cookie)], "").await;
    assert_eq!(after.status.code(), 401, "a revoked session must stop working");
}

#[tokio::test]
async fn an_expired_session_is_refused() {
    use std::time::Duration;
    // Zero lifetimes via the injectable store: the session is expired the
    // moment it is minted, standing in for the 12-hour absolute and 2-hour
    // idle limits without a 12-hour test.
    let (api, _dir) = console_api("expired", Sessions::with_expiry(Duration::ZERO, Duration::ZERO));
    let cookie = login(&api).await;
    let response = call_with(&api, "GET", "/api/services", &[("Cookie", &cookie)], "").await;
    assert_eq!(response.status.code(), 401);
}

#[tokio::test]
async fn login_without_a_configured_password_fails_closed() {
    // No console.passwd on disk: the login route answers the standard 401 —
    // never a panic, never a hint that the password is simply unset.
    let (plain, dir) = api("nopasswd");
    let api = plain.with_console_auth(dir.path());
    let response = call_with(&api, "POST", "/api/session", &[("X-Selfhost-Console", "1")], r#"{"password":"anything"}"#).await;
    assert_eq!(response.status.code(), 401);

    let (_, unauthenticated) = call(&api, "GET", "/api/services", None, "").await;
    assert_eq!(body_json(&response), unauthenticated);
}

#[tokio::test]
async fn a_login_body_that_is_not_json_is_a_400_not_a_counted_failure() {
    let (api, _dir) = console_api("badbody", Sessions::new());
    let response = call_with(&api, "POST", "/api/session", &[("X-Selfhost-Console", "1")], "{not json").await;
    assert_eq!(response.status.code(), 400);
    let response = call_with(&api, "POST", "/api/session", &[("X-Selfhost-Console", "1")], r#"{"password":42}"#).await;
    assert_eq!(response.status.code(), 400, "a non-string password is malformed, not a guess");
}

#[tokio::test]
async fn an_invented_cookie_does_not_authorise_anything() {
    let (api, _dir) = console_api("forged-cookie", Sessions::new());
    let forged = format!("selfhost_session={}", "0".repeat(64));
    let response = call_with(&api, "GET", "/api/services", &[("Cookie", &forged)], "").await;
    assert_eq!(response.status.code(), 401);
}

// ---- passkey (WebAuthn) login -----------------------------------------------
//
// The ceremony crypto — signatures, origins, flags, challenges — is unit-tested
// inside `webauthn.rs`; these tests cover the route glue: which door needs what
// credential, the uniform refusals, and that a verified assertion mints the
// same session cookie a password login would.

/// The relying party every passkey test speaks for, and the origin the test
/// authenticator therefore claims.
const RP: &str = "console.example.com";

/// The console API with passkey login enabled for [`RP`].
fn passkey_api(name: &str) -> (Api, ScratchDir) {
    let (api, dir) = console_api(name, Sessions::new());
    let api = api.with_console_webauthn(RP, dir.path());
    (api, dir)
}

/// Unpadded base64url, for building ceremony bodies by hand.
fn b64url(data: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let bits = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        out.push(B64[(bits >> 18 & 0x3f) as usize] as char);
        out.push(B64[(bits >> 12 & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[(bits >> 6 & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[(bits & 0x3f) as usize] as char);
        }
    }
    out
}

/// A stand-in platform authenticator: a real P-256 keypair that answers
/// ceremonies for [`RP`] the way a browser's `PublicKeyCredential` would.
struct Authenticator {
    keys: ring::signature::EcdsaKeyPair,
    id: String,
}

impl Authenticator {
    fn new() -> Self {
        use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).expect("keypair");
        let keys = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("keypair parses");
        Self { keys, id: b64url(b"test-credential") }
    }

    /// Authenticator data for [`RP`]: rpIdHash, `flags`, and a counter.
    fn auth_data(flags: u8) -> Vec<u8> {
        let mut out =
            ring::digest::digest(&ring::digest::SHA256, RP.as_bytes()).as_ref().to_vec();
        out.push(flags);
        out.extend_from_slice(&[0, 0, 0, 1]);
        out
    }

    fn client_data(ceremony: &str, challenge: &str) -> Vec<u8> {
        Json::object([
            ("type", Json::string(ceremony)),
            ("challenge", Json::string(challenge)),
            ("origin", Json::string(format!("https://{RP}"))),
        ])
        .to_text()
        .into_bytes()
    }

    /// The registration body for a challenge, as the SPA would send it.
    fn register_body(&self, challenge: &str, label: &str) -> String {
        use ring::signature::KeyPair;
        // getPublicKey()'s SPKI: the fixed P-256 prefix plus the raw point.
        let mut spki = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        spki.extend_from_slice(self.keys.public_key().as_ref());
        Json::object([
            ("id", Json::string(&self.id)),
            ("algorithm", Json::Number(-7.0)),
            ("publicKey", Json::string(b64url(&spki))),
            ("clientDataJSON", Json::string(b64url(&Self::client_data("webauthn.create", challenge)))),
            ("authenticatorData", Json::string(b64url(&Self::auth_data(0x45)))), // UP|UV|AT
            ("label", Json::string(label)),
        ])
        .to_text()
    }

    /// A signed login assertion for a challenge, as the SPA would send it.
    fn login_body(&self, challenge: &str) -> String {
        let client = Self::client_data("webauthn.get", challenge);
        let auth = Self::auth_data(0x05); // UP|UV
        let mut message = auth.clone();
        message
            .extend_from_slice(ring::digest::digest(&ring::digest::SHA256, &client).as_ref());
        let signature = self
            .keys
            .sign(&ring::rand::SystemRandom::new(), &message)
            .expect("signing with the test key");
        Json::object([
            ("id", Json::string(&self.id)),
            ("clientDataJSON", Json::string(b64url(&client))),
            ("authenticatorData", Json::string(b64url(&auth))),
            ("signature", Json::string(b64url(signature.as_ref()))),
        ])
        .to_text()
    }
}

/// Registers `device` through the routes, driven by an authenticated cookie.
async fn register_passkey(api: &Api, cookie: &str, device: &Authenticator, label: &str) {
    let challenge = call_with(
        api,
        "POST",
        "/api/webauthn/register/challenge",
        &[("Cookie", cookie), ("X-Selfhost-Console", "1")],
        "",
    )
    .await;
    assert_eq!(challenge.status.code(), 200, "an authenticated caller gets a challenge");
    let reply = body_json(&challenge);
    assert_eq!(reply.get("rpId").and_then(Json::as_str), Some(RP));
    let challenge = reply.get("challenge").and_then(Json::as_str).expect("a challenge").to_owned();

    let registered = call_with(
        api,
        "POST",
        "/api/webauthn/register",
        &[("Cookie", cookie), ("X-Selfhost-Console", "1")],
        &device.register_body(&challenge, label),
    )
    .await;
    assert_eq!(registered.status.code(), 200, "{:?}", body_json(&registered));
}

/// Fetches a login challenge through the unauthenticated route.
async fn login_challenge(api: &Api) -> Response {
    call_with(api, "POST", "/api/webauthn/login/challenge", &[("X-Selfhost-Console", "1")], "")
        .await
}

#[tokio::test]
async fn a_registered_passkey_logs_in_and_the_session_it_mints_opens_the_api() {
    let (api, _dir) = passkey_api("passkey-roundtrip");
    let device = Authenticator::new();
    register_passkey(&api, &login(&api).await, &device, "MacBook").await;

    let challenge = login_challenge(&api).await;
    assert_eq!(challenge.status.code(), 200, "a challenge once a passkey exists");
    let challenge =
        body_json(&challenge).get("challenge").and_then(Json::as_str).unwrap().to_owned();

    let reply = call_with(
        &api,
        "POST",
        "/api/webauthn/login",
        &[("X-Selfhost-Console", "1")],
        &device.login_body(&challenge),
    )
    .await;
    assert_eq!(reply.status.code(), 200, "{:?}", body_json(&reply));
    let cookie = session_cookie_pair(&reply);
    let listed = call_with(&api, "GET", "/api/services", &[("Cookie", &cookie)], "").await;
    assert_eq!(listed.status.code(), 200, "the passkey session opens the API");
}

#[tokio::test]
async fn passkey_routes_refuse_uniformly_when_absent_or_unearned() {
    // Console auth without passkeys configured: the login pair answers the
    // API's uniform 401, and management routes are an honest 404 behind auth.
    let (api, _dir) = console_api("passkey-absent", Sessions::new());
    assert_eq!(login_challenge(&api).await.status.code(), 401);
    let (status, _) = call(&api, "GET", "/api/webauthn/credentials", Some(TOKEN), "").await;
    assert_eq!(status, 404, "an authenticated caller may learn the feature is off");

    // Configured but with nothing registered: the same 401, so an
    // unauthenticated probe cannot tell these deployments apart.
    let (api, _dir) = passkey_api("passkey-empty");
    assert_eq!(login_challenge(&api).await.status.code(), 401);

    // The login pair is CSRF-guarded like the password login.
    let bare = call_with(&api, "POST", "/api/webauthn/login/challenge", &[], "").await;
    assert_eq!(bare.status.code(), 401, "no console header, no challenge");

    // Registration is behind the wall entirely.
    let anonymous =
        call_with(&api, "POST", "/api/webauthn/register/challenge", &[("X-Selfhost-Console", "1")], "")
            .await;
    assert_eq!(anonymous.status.code(), 401, "registering needs a session or token");
}

#[tokio::test]
async fn a_forged_assertion_is_refused_and_counts_toward_the_shared_gate() {
    let (api, _dir) = passkey_api("passkey-forged");
    let device = Authenticator::new();
    register_passkey(&api, &login(&api).await, &device, "MacBook").await;

    // A different key signing under the same credential id: refused, and each
    // attempt feeds the same gate the password door uses.
    let stranger = Authenticator::new();
    for _ in 0..5 {
        let challenge = login_challenge(&api).await;
        assert_eq!(challenge.status.code(), 200);
        let challenge =
            body_json(&challenge).get("challenge").and_then(Json::as_str).unwrap().to_owned();
        let refused = call_with(
            &api,
            "POST",
            "/api/webauthn/login",
            &[("X-Selfhost-Console", "1")],
            &stranger.login_body(&challenge),
        )
        .await;
        assert_eq!(refused.status.code(), 401);
        assert!(refused.headers.get_str("set-cookie").is_none(), "no cookie on refusal");
    }
    // One gate over both login doors: a sixth forged assertion meets the
    // lockout the password failures would have met.
    let challenge =
        body_json(&login_challenge(&api).await).get("challenge").and_then(Json::as_str).unwrap().to_owned();
    let sixth = call_with(
        &api,
        "POST",
        "/api/webauthn/login",
        &[("X-Selfhost-Console", "1")],
        &stranger.login_body(&challenge),
    )
    .await;
    assert_eq!(sixth.status.code(), 429, "the gate has locked");

    // But the challenge route keeps answering, and the password door keeps
    // opening for the right password. A challenge is a random number that grants
    // nothing without a signature from hardware the guesser does not have, so
    // refusing it only ever shut the operator's own second door — and refusing
    // the correct password is the lockout this deployment cannot afford at all.
    assert_eq!(login_challenge(&api).await.status.code(), 200, "the biometric door stayed open");
    let password = call_with(
        &api,
        "POST",
        "/api/session",
        &[("X-Selfhost-Console", "1")],
        &format!(r#"{{"password":"{PASSWORD}"}}"#),
    )
    .await;
    assert_eq!(password.status.code(), 200, "a locked gate refused the operator");
}

/// A definition that is legal but never started, for asking whether a caller
/// may *change* the machine rather than whether the change worked.
const A_SERVICE: &str = r#"{"name":"x","program":"/bin/echo","args":["hi"]}"#;

#[tokio::test]
async fn the_console_password_owns_a_fresh_box_and_stops_owning_it_at_the_first_passkey() {
    // The rule that resolves itself, end to end and in both states. There is no
    // setting here: the deployment's own state is the switch, so a box nobody has
    // finished installing is usable and a box with a real credential is not
    // one shared secret away from being owned.
    let (api, _dir) = passkey_api("password-demotion");

    // State one: nothing enrolled. The password is the only way in, so it is the
    // owner outright — every route it opened before this change, it still opens.
    let cookie = login(&api).await;
    let headers: [(&str, &str); 2] = [("Cookie", &cookie), ("X-Selfhost-Console", "1")];
    let controlling = call_with(&api, "PUT", "/api/services/x", &headers, A_SERVICE).await;
    assert_ne!(controlling.status.code(), 401, "a fresh box must admit its installer");
    assert_eq!(call_with(&api, "GET", "/api/services", &headers, "").await.status.code(), 200);

    // State two: one passkey enrolled, by this very session. The same cookie now
    // reads the console and can change nothing about the machine.
    let device = Authenticator::new();
    register_passkey(&api, &cookie, &device, "MacBook").await;
    assert_eq!(
        call_with(&api, "GET", "/api/services", &headers, "").await.status.code(),
        200,
        "reading the console is what the password keeps"
    );
    assert_eq!(
        call_with(&api, "PUT", "/api/services/x", &headers, A_SERVICE).await.status.code(),
        401,
        "and controlling a service is what it loses"
    );
    assert_eq!(
        call_with(&api, "GET", "/api/audit", &headers, "").await.status.code(),
        200,
        "reads stay open: the demotion is about acts that change the box, not about looking at it"
    );

    // And the passkey it enrolled holds everything the password just lost, which
    // is the point rather than a consolation: authority moved to the credential
    // that says who is using it.
    let named = passkey_login(&api, &device).await;
    let named_headers: [(&str, &str); 2] = [("Cookie", &named), ("X-Selfhost-Console", "1")];
    assert_ne!(
        call_with(&api, "PUT", "/api/services/x", &named_headers, A_SERVICE).await.status.code(),
        401,
        "the named credential controls the machine"
    );
}

#[tokio::test]
async fn a_lost_passkey_is_replaced_through_the_password_and_never_deleted_by_it() {
    // Why the demotion cannot lock anybody out, which is the whole reason it is
    // safe to do without a flag. The operator's only enrolled device is gone.
    // They log in with the password — still admitted — and enrol a replacement.
    let (api, _dir) = passkey_api("password-recovery");
    let lost = Authenticator::new();
    register_passkey(&api, &login(&api).await, &lost, "the one in the drawer").await;

    let cookie = login(&api).await;
    let replacement = Authenticator::new();
    register_passkey(&api, &cookie, &replacement, "the new laptop").await;
    let recovered = passkey_login(&api, &replacement).await;
    let headers: [(&str, &str); 2] = [("Cookie", &recovered), ("X-Selfhost-Console", "1")];
    assert_ne!(
        call_with(&api, "PUT", "/api/services/x", &headers, A_SERVICE).await.status.code(),
        401,
        "the operator has their box back, through a credential that names them"
    );

    // The half that makes the recovery path safe rather than a bypass: the
    // password may add a credential and may never take one away. If it could,
    // "enrol a replacement" would be "delete everything that outranks me".
    let listed = call_with(&api, "GET", "/api/webauthn/credentials", &headers, "").await;
    let ids: Vec<String> = body_json(&listed)
        .get("passkeys")
        .and_then(Json::as_array)
        .expect("a list")
        .iter()
        .filter_map(|entry| entry.get("id").and_then(Json::as_str).map(str::to_owned))
        .collect();
    // One entry, not two: this harness's authenticator reuses a single credential
    // id, so the replacement supersedes the lost device exactly as a real
    // re-registration on the same authenticator would. What matters here is that
    // the roster is readable and that the next loop cannot empty it.
    assert!(!ids.is_empty(), "the replacement is on the roster");
    let password_headers: [(&str, &str); 2] = [("Cookie", &cookie), ("X-Selfhost-Console", "1")];
    for id in &ids {
        let refused =
            call_with(&api, "DELETE", &format!("/api/webauthn/credentials/{id}"), &password_headers, "")
                .await;
        assert_eq!(refused.status.code(), 401, "a password login may not un-enrol {id}");
    }
}

#[tokio::test]
async fn the_bearer_token_is_the_machine_and_holds_the_machines_list() {
    // The other door the identity audit found open. The token still drives every
    // route the CLI and the native console call over the SSH tunnel; what it
    // stopped being is the operator.
    let (api, dir) = passkey_api("bearer-scope");
    let api = api.with_people(People::load(dir.path()));

    let (status, answered) = call(&api, "GET", "/api/whoami", Some(TOKEN), "").await;
    assert_eq!(status, 200);
    assert_eq!(
        answered.get("name").and_then(Json::as_str),
        Some("machine"),
        "the audit record can now say which of the two acted"
    );
    assert_eq!(answered.get("owner").and_then(Json::as_bool), Some(false));
    assert_eq!(answered.get("credential").and_then(Json::as_str), Some("bearer"));

    // What the native console reads and drives: unchanged.
    for (method, target, body) in [
        ("GET", "/api/services", ""),
        ("GET", "/api/firewall", ""),
        ("GET", "/api/webauthn/credentials", ""),
        ("GET", "/api/storage/shares", ""),
        ("GET", "/api/audit", ""),
        ("PUT", "/api/services/x", A_SERVICE),
    ] {
        let (status, body) = call(&api, method, target, Some(TOKEN), body).await;
        assert_ne!(status, 401, "the native console still calls {method} {target}: {body:?}");
    }

    // What it may not do: create or alter people. Nothing holding the token has
    // ever needed to, and a secret in a file should not be able to mint a person
    // who is still here after it is rotated.
    for (method, target, body) in [
        ("GET", "/api/people", ""),
        ("PUT", "/api/people/mom", r#"{"grants":["console.read"]}"#),
        ("DELETE", "/api/people/mom", ""),
        ("POST", "/api/people/mom/invite", "{}"),
        ("GET", "/api/people/invites", ""),
        ("POST", "/api/webauthn/register/challenge", ""),
    ] {
        let (status, _) = call(&api, method, target, Some(TOKEN), body).await;
        assert_eq!(status, 401, "the machine must be refused {method} {target}");
    }
}

#[tokio::test]
async fn a_passkey_can_be_listed_and_revoked() {
    let (api, _dir) = passkey_api("passkey-revoke");
    let device = Authenticator::new();
    let cookie = login(&api).await;
    register_passkey(&api, &cookie, &device, "MacBook").await;

    let (status, listed) = call(&api, "GET", "/api/webauthn/credentials", Some(TOKEN), "").await;
    assert_eq!(status, 200);
    let passkeys = listed.get("passkeys").and_then(Json::as_array).expect("a list");
    assert_eq!(passkeys.len(), 1);
    assert_eq!(passkeys[0].get("label").and_then(Json::as_str), Some("MacBook"));
    let id = passkeys[0].get("id").and_then(Json::as_str).expect("an id").to_owned();

    // Revoking is not listing. Taking a credential away is destroying authority,
    // so it asks for a credential that names whoever is doing it — and neither
    // the box's own token nor the shared password is one. Refusing the token is
    // deliberate and visible: a token that could delete the passkeys which
    // outrank it would restore the console password to root, which is exactly
    // the escalation this model exists to close.
    let (refused, _) =
        call(&api, "DELETE", &format!("/api/webauthn/credentials/{id}"), Some(TOKEN), "").await;
    assert_eq!(refused, 401, "the machine may read the roster and may not edit it");
    let refused = call_with(
        &api,
        "DELETE",
        &format!("/api/webauthn/credentials/{id}"),
        &[("Cookie", &cookie), ("X-Selfhost-Console", "1")],
        "",
    )
    .await;
    assert_eq!(
        refused.status.code(),
        401,
        "the password login that enrolled it may not un-enrol it"
    );

    // The passkey itself can. That is the whole shape: the credential that names
    // a person is the one that manages credentials.
    let named = passkey_login(&api, &device).await;
    let headers: [(&str, &str); 2] = [("Cookie", &named), ("X-Selfhost-Console", "1")];
    let path = format!("/api/webauthn/credentials/{id}");
    let revoked = call_with(&api, "DELETE", &path, &headers, "").await;
    assert_eq!(revoked.status.code(), 200, "{:?}", body_json(&revoked));
    let again = call_with(&api, "DELETE", &path, &headers, "").await;
    assert_eq!(again.status.code(), 404, "revoking twice names the absence");

    // With the store empty again, the login door returns to its uniform 401.
    assert_eq!(login_challenge(&api).await.status.code(), 401);
}

struct ScratchDir(std::path::PathBuf);

impl ScratchDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir()
            .join(format!("selfhost-api-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create scratch directory");
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

// ---- storage: the browser file manager's backend ----------------------------
//
// The rules about *what a path may reach* live in `selfhost-storage` and are
// tested there, without a socket, against every traversal shape Windows and
// APFS make possible. What is tested here is the other half — who may reach a
// share at all, what an unknown share looks like to somebody who may not have
// it, and that a bulk transfer inherits every guard an ordinary write has.

use selfhost_admin::storage_api::{self, Denied, Volumes};
use selfhost_identity::{Capability, Grants, NodeName, Opening, People, PersonName, ShareId};
use selfhost_storage::api::Volume;
use selfhost_storage::quota::Ledger;
use selfhost_storage::share::{Reserved, Share};
use std::sync::Arc;
use tokio::io::AsyncReadExt;

/// A share rooted at `<scratch>/<id>`, opened.
///
/// The reserved set points at a sibling directory that no share is rooted in,
/// so these fixtures exercise the ordinary path rather than the refusal — the
/// refusals belong to `selfhost-storage`'s own suite.
fn open_share(
    dir: &std::path::Path,
    id: &str,
    ledger: &Arc<Ledger>,
    read_only: bool,
    grants: Vec<selfhost_storage::share::Grant>,
) -> Volume {
    let base = std::fs::canonicalize(dir).expect("a real scratch directory");
    let root = base.join(id);
    std::fs::create_dir_all(&root).expect("a share root");
    let reserved = Reserved::new(base.join("reserved-data"), None).expect("a reserved set");
    let share = Share::new(&reserved, id, root, read_only, false, None)
        .expect("a legal share")
        .with_grants(grants);
    Volume::open(share, Arc::clone(ledger)).expect("the root opens")
}

/// The console API with two shares: a writable `vault` and a read-only `photos`.
fn storage_api_with_shares(name: &str) -> (Api, ScratchDir) {
    let (api, dir) = api(name);
    let ledger = Arc::new(Ledger::new());
    let volumes = Volumes::from_opened(vec![
        open_share(dir.path(), "vault", &ledger, false, Vec::new()),
        open_share(dir.path(), "photos", &ledger, true, Vec::new()),
    ]);
    (api.with_storage(volumes), dir)
}

#[tokio::test]
async fn every_storage_and_desktop_route_refuses_an_unauthenticated_caller() {
    let (api, _dir) = storage_api_with_shares("storage-noauth");
    for (method, target) in [
        ("GET", "/api/storage/shares"),
        ("GET", "/api/storage/shares/vault/list?path="),
        ("GET", "/api/storage/shares/vault/stat?path=a"),
        ("POST", "/api/storage/shares/vault/mkdir"),
        ("POST", "/api/storage/shares/vault/rename"),
        ("DELETE", "/api/storage/shares/vault/entry?path=a"),
        ("GET", "/api/desktop"),
        ("GET", "/api/desktop/nodes"),
        ("GET", "/api/desktop/agent?peer=self"),
        ("POST", "/api/desktop/ticket"),
    ] {
        let (status, _) = call(&api, method, target, None, "").await;
        assert_eq!(status, 401, "{method} {target} should require a credential");
    }
}

#[tokio::test]
async fn storage_routes_are_the_uniform_401_when_no_share_is_declared() {
    // A deployment that serves no files must not be distinguishable from one
    // whose shares this caller simply may not have: both are the same 401, and
    // neither is a 404 that says the prefix exists.
    let (api, _dir) = api("storage-none");
    // To an unauthenticated caller: the uniform 401, so a stranger cannot learn
    // whether this box serves files at all.
    for target in [
        "/api/storage/shares",
        "/api/storage/shares/vault/list?path=",
        "/api/storage/shares/vault/stat?path=a",
    ] {
        let (status, _) = call(&api, "GET", target, None, "").await;
        assert_eq!(status, 401, "{target}");
    }
    // To the owner, who could list every share if there were any: an honest
    // answer, because there is nothing they could learn that they do not hold.
    // `vault/list` still 404s — a specific id names a share that does not
    // exist. The bare list route is different: it demands only `ConsoleRead`,
    // which this caller already holds, so the honest answer to "what may I
    // open" is an empty list, not a refusal that claims their session died —
    // a 401 here used to send an authenticated console straight back to its
    // login screen the instant it loaded (crates/admin/src/lib.rs, `shares`).
    let (status, body) = send(&api, "GET", "/api/storage/shares/vault/list?path=", "").await;
    assert_eq!(status, 404, "{body:?}");
    let (status, body) = send(&api, "GET", "/api/storage/shares", "").await;
    assert_eq!(status, 200, "{body:?}");
    assert_eq!(body.get("shares").and_then(Json::as_array).map(<[Json]>::len), Some(0), "{body:?}");
}

#[tokio::test]
async fn a_share_lists_creates_stats_renames_and_deletes_for_the_owner() {
    let (api, dir) = storage_api_with_shares("storage-roundtrip");
    std::fs::write(dir.path().join("vault").join("notes.txt"), b"hello").expect("a seed file");

    let (status, body) = send(&api, "GET", "/api/storage/shares", "").await;
    assert_eq!(status, 200, "{body:?}");
    let listed = body.get("shares").and_then(Json::as_array).expect("a shares array");
    assert_eq!(listed.len(), 2, "{body:?}");

    let (status, body) = send(&api, "GET", "/api/storage/shares/vault/list?path=", "").await;
    assert_eq!(status, 200, "{body:?}");
    let entries = body.get("entries").and_then(Json::as_array).expect("an entries array");
    assert!(
        entries.iter().any(|e| e.get("name").and_then(Json::as_str) == Some("notes.txt")),
        "{body:?}"
    );

    let (status, body) =
        send(&api, "POST", "/api/storage/shares/vault/mkdir", r#"{"path":"papers"}"#).await;
    assert_eq!(status, 200, "{body:?}");
    assert!(dir.path().join("vault").join("papers").is_dir());

    let (status, body) = send(&api, "GET", "/api/storage/shares/vault/stat?path=papers", "").await;
    assert_eq!(status, 200, "{body:?}");
    assert_eq!(body.get("kind").and_then(Json::as_str), Some("dir"), "{body:?}");

    let (status, body) = send(
        &api,
        "POST",
        "/api/storage/shares/vault/rename",
        r#"{"from":"notes.txt","to":"papers/notes.txt"}"#,
    )
    .await;
    assert!(status == 201 || status == 204, "a move lands as created or replaced: {status} {body:?}");
    assert!(dir.path().join("vault").join("papers").join("notes.txt").is_file());

    let (status, body) =
        send(&api, "DELETE", "/api/storage/shares/vault/entry?path=papers", "").await;
    assert_eq!(status, 200, "{body:?}");
    assert!(!dir.path().join("vault").join("papers").exists());
}

#[tokio::test]
async fn a_read_only_share_refuses_a_write_to_everybody_including_the_owner() {
    // The flag describes the *data*, not a permission level, so it is checked
    // before grants and the owner is not an exception to it.
    let (api, _dir) = storage_api_with_shares("storage-readonly");
    let (status, body) =
        send(&api, "POST", "/api/storage/shares/photos/mkdir", r#"{"path":"new"}"#).await;
    assert_eq!(status, 403, "{body:?}");
}

#[tokio::test]
async fn a_share_id_that_could_never_exist_is_the_uniform_401_not_a_404() {
    // A refusal that told "no such share" apart from "not yours" would be a way
    // to enumerate what sits behind the wall, one guess at a time.
    let (api, _dir) = storage_api_with_shares("storage-badid");
    let too_long = "a".repeat(64);
    for id in ["Vault", "va%20ult", "..", too_long.as_str()] {
        let target = format!("/api/storage/shares/{id}/list?path=");
        let (status, body) = send(&api, "GET", &target, "").await;
        assert_eq!(status, 401, "{id} leaked a different refusal: {body:?}");
    }
}

#[tokio::test]
async fn an_unknown_but_legal_share_is_a_404_only_after_the_capability_held() {
    // The owner holds every share capability, so for them a well-formed id that
    // names nothing is an honest 404. Nobody who could not already list the
    // shares can reach this answer.
    let (api, _dir) = storage_api_with_shares("storage-unknown");
    let (status, _) = send(&api, "GET", "/api/storage/shares/attic/list?path=", "").await;
    assert_eq!(status, 404);
}

/// A console API with one share and a named person holding `grants`.
///
/// The session is minted directly rather than through a passkey ceremony: what
/// is under test is what a *person* may do, and the ceremony that proves they
/// are one is tested above.
async fn person_api(
    name: &str,
    person: &str,
    grants: Grants,
) -> (Api, String, ScratchDir) {
    let sessions = Sessions::new();
    let (api, dir) = console_api(name, sessions.clone());
    let ledger = Arc::new(Ledger::new());
    // The share's own `[[shares.access]]` list grants this person write, so the
    // only thing these tests vary is the *capability* — the layer this crate
    // owns. Both layers are real and both must pass; see the note on
    // `Volume::permit`.
    let on_the_share = vec![
        selfhost_storage::share::Grant::parse(person, selfhost_storage::share::Mode::Write)
            .expect("a legal grant"),
    ];
    let volumes =
        Volumes::from_opened(vec![open_share(dir.path(), "vault", &ledger, false, on_the_share)]);
    let people = People::load(dir.path());
    people
        .set_grants(&PersonName::parse(person).expect("a legal name"), grants)
        .expect("grants are written");
    let id = sessions.create(person, Opening::Passkey).expect("a session");
    (api.with_storage(volumes).with_people(people), format!("selfhost_session={id}"), dir)
}

#[tokio::test]
async fn a_person_without_the_capability_gets_the_identical_401_an_anonymous_caller_gets() {
    // They may read the console — which is what gets them past the floor — and
    // hold no share capability at all.
    let mut grants = Grants::none();
    grants.grant(Capability::ConsoleRead).expect("room for one grant");
    let (api, cookie, _dir) = person_api("storage-person-none", "Mom", grants).await;

    let refused = call_with(&api, "GET", "/api/storage/shares/vault/list?path=", &[("Cookie", &cookie)], "").await;
    let anonymous = call_with(&api, "GET", "/api/storage/shares/vault/list?path=", &[], "").await;
    assert_eq!(refused.status.code(), 401);
    assert_eq!(anonymous.status.code(), 401);
    // Byte for byte: a known person holding nothing must not be able to tell
    // themselves apart from a stranger, or the console becomes a way to
    // enumerate what exists behind it.
    assert_eq!(body_json(&refused).to_text(), body_json(&anonymous).to_text());

    // And the set route answers them with an empty list rather than a refusal:
    // they may read the console, and they may open nothing.
    let listed = call_with(&api, "GET", "/api/storage/shares", &[("Cookie", &cookie)], "").await;
    assert_eq!(listed.status.code(), 200);
    assert_eq!(
        body_json(&listed).get("shares").and_then(Json::as_array).map(<[Json]>::len),
        Some(0),
        "a person holding nothing sees no shares"
    );
}

#[tokio::test]
async fn a_person_granted_read_may_list_and_may_not_write() {
    let mut grants = Grants::none();
    grants.grant(Capability::ConsoleRead).expect("room for one grant");
    grants
        .grant(Capability::FilesRead(ShareId::parse("vault").expect("a legal id")))
        .expect("room for one grant");
    let (api, cookie, _dir) = person_api("storage-person-read", "Mom", grants).await;

    let listed = call_with(&api, "GET", "/api/storage/shares/vault/list?path=", &[("Cookie", &cookie)], "").await;
    assert_eq!(listed.status.code(), 200, "{:?}", body_json(&listed));

    let write = call_with(
        &api,
        "POST",
        "/api/storage/shares/vault/mkdir",
        &[("Cookie", &cookie), ("X-Selfhost-Console", "1")],
        r#"{"path":"nope"}"#,
    )
    .await;
    assert_eq!(write.status.code(), 401, "read does not imply write");
}

#[tokio::test]
async fn a_cookie_authenticated_storage_write_needs_the_console_header() {
    // The CSRF-header-before-store ordering, on the newest non-GET routes: a
    // forged cross-site write is refused before the session store is consulted,
    // so it cannot even refresh the operator's idle timer.
    let mut grants = Grants::none();
    grants.grant(Capability::ConsoleRead).expect("room for one grant");
    grants
        .grant(Capability::FilesWrite(ShareId::parse("vault").expect("a legal id")))
        .expect("room for one grant");
    let (api, cookie, dir) = person_api("storage-csrf", "Mom", grants).await;

    let forged = call_with(
        &api,
        "POST",
        "/api/storage/shares/vault/mkdir",
        &[("Cookie", &cookie)],
        r#"{"path":"forged"}"#,
    )
    .await;
    assert_eq!(forged.status.code(), 401, "no console header, no write");
    assert!(!dir.path().join("vault").join("forged").exists(), "nothing was created");

    let honest = call_with(
        &api,
        "POST",
        "/api/storage/shares/vault/mkdir",
        &[("Cookie", &cookie), ("X-Selfhost-Console", "1")],
        r#"{"path":"honest"}"#,
    )
    .await;
    assert_eq!(honest.status.code(), 200, "{:?}", body_json(&honest));
}

// ---- storage: the bulk plane ------------------------------------------------

#[tokio::test]
async fn a_bulk_transfer_refuses_an_anonymous_caller_and_a_person_identically() {
    let (api, cookie, _dir) = person_api("bulk-refusals", "Mom", Grants::none()).await;

    let (anonymous, _) = request_with("GET", "/api/storage/blob/vault/notes.txt", None, &[], "");
    let (known, _) = request_with(
        "GET",
        "/api/storage/blob/vault/notes.txt",
        None,
        &[("Cookie", &cookie)],
        "",
    );
    let one = api.bulk_for(&anonymous).expect_err("no credential");
    let two = api.bulk_for(&known).expect_err("a person holding nothing");
    assert!(matches!(one, Denied::Unauthorised));
    assert!(matches!(two, Denied::Unauthorised));
    assert_eq!(one.response().status.code(), two.response().status.code());
}

#[tokio::test]
async fn a_bulk_upload_is_refused_before_the_store_without_the_console_header() {
    let mut grants = Grants::none();
    grants.grant(Capability::ConsoleRead).expect("room for one grant");
    grants
        .grant(Capability::FilesWrite(ShareId::parse("vault").expect("a legal id")))
        .expect("room for one grant");
    let (api, cookie, _dir) = person_api("bulk-csrf", "Mom", grants).await;

    let (forged, _) = request_with(
        "PUT",
        "/api/storage/blob/vault/notes.txt",
        None,
        &[("Cookie", &cookie), ("Content-Length", "5")],
        "",
    );
    assert!(
        matches!(api.bulk_for(&forged), Err(Denied::Unauthorised)),
        "a PUT without the console header must not reach the session store"
    );

    let (honest, _) = request_with(
        "PUT",
        "/api/storage/blob/vault/notes.txt",
        None,
        &[("Cookie", &cookie), ("X-Selfhost-Console", "1"), ("Content-Length", "5")],
        "",
    );
    assert!(api.bulk_for(&honest).is_ok(), "the same request with the header is admitted");
}

#[tokio::test]
async fn a_bulk_transfer_refuses_a_body_it_cannot_frame_and_a_method_it_does_not_serve() {
    let (api, _dir) = storage_api_with_shares("bulk-framing");
    let (chunked, _) = request_with(
        "PUT",
        "/api/storage/blob/vault/a.txt",
        Some(TOKEN),
        &[("Transfer-Encoding", "chunked")],
        "",
    );
    assert!(matches!(api.bulk_for(&chunked), Err(Denied::Unframed(_))));

    let (deleted, _) = request_with("DELETE", "/api/storage/blob/vault/a.txt", Some(TOKEN), &[], "");
    assert!(matches!(api.bulk_for(&deleted), Err(Denied::WrongMethod)));

    let (bare, _) = request_with("GET", "/api/storage/blob/vault", Some(TOKEN), &[], "");
    assert!(matches!(api.bulk_for(&bare), Err(Denied::NoPath)));
}

#[tokio::test]
async fn a_file_uploaded_over_the_bulk_plane_comes_back_down_it() {
    let (api, dir) = storage_api_with_shares("bulk-roundtrip");

    // Up. The body travels as the prefix, which is exactly what the socket
    // layer hands over: the first bytes of a body arrive in the same segment as
    // the headers far more often than not.
    let (request, body) =
        request_with("PUT", "/api/storage/blob/vault/hello.txt", Some(TOKEN), &[], "hello there");
    let plan = api.bulk_for(&request).expect("the owner may write");
    let answer = drive(body, request, plan).await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("vault").join("hello.txt")).expect("the file"),
        "hello there"
    );

    // Down.
    let (request, _) =
        request_with("GET", "/api/storage/blob/vault/hello.txt", Some(TOKEN), &[], "");
    let plan = api.bulk_for(&request).expect("the owner may read");
    let answer = drive(Vec::new(), request, plan).await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.ends_with("hello there"), "{answer}");
}

#[tokio::test]
async fn an_upload_that_ends_early_publishes_nothing() {
    // A truncated body must leave the destination untouched: the temporary file
    // is abandoned and the reservation rolled back, because a closed socket
    // cannot tell "the client finished" from "the client vanished" and only one
    // of those may publish a file.
    let (api, dir) = storage_api_with_shares("bulk-truncated");
    let (mut ours, theirs) = tokio::io::duplex(64 * 1024);
    let (request, _) = request_with(
        "PUT",
        "/api/storage/blob/vault/partial.txt",
        Some(TOKEN),
        &[("Content-Length", "64")],
        "",
    );
    let plan = api.bulk_for(&request).expect("the owner may write");
    // The peer hangs up having sent four of the sixty-four bytes it promised.
    let feeder = tokio::spawn(async move {
        let mut theirs = theirs;
        tokio::io::AsyncWriteExt::write_all(&mut theirs, b"abcd").await.expect("four bytes");
        // The write half only: the peer stops sending and stays there to read
        // the answer, which is what a client that lost its file does.
        tokio::io::AsyncWriteExt::shutdown(&mut theirs).await.expect("half-closed");
        let mut answer = Vec::new();
        theirs.read_to_end(&mut answer).await.expect("the answer is readable");
        answer
    });
    let report = storage_api::serve(&mut ours, Vec::new(), &request, plan)
        .await
        .expect("the transfer is answered");
    drop(ours);
    let answer = feeder.await.expect("the feeder finished");
    assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 400"), "{report}");
    assert_eq!(report.status, 400, "a short body is the request's fault, not the box's");
    assert!(!dir.path().join("vault").join("partial.txt").exists(), "nothing was published");
}

/// Runs a bulk transfer over a duplex and returns everything written back.
async fn drive(prefix: Vec<u8>, request: Request, plan: storage_api::Bulk) -> String {
    let (mut ours, mut theirs) = tokio::io::duplex(1024 * 1024);
    let served = tokio::spawn(async move {
        let report = storage_api::serve(&mut ours, prefix, &request, plan).await;
        drop(ours);
        report
    });
    let mut written = Vec::new();
    theirs.read_to_end(&mut written).await.expect("the answer is readable");
    served.await.expect("the task finished").expect("the transfer is answered");
    String::from_utf8_lossy(&written).into_owned()
}

/// The JSON body of a raw response the bulk plane wrote to a socket.
///
/// The bulk plane writes its own head, so a test that wants to read what it
/// said has to split the body off itself. Worth doing rather than matching on
/// the text: the number in a `wrong-offset` refusal is the whole point of that
/// refusal, and a `contains` check would pass on a body that merely mentioned
/// it somewhere.
fn answered_json(answer: &str) -> Json {
    let body = answer.split_once("\r\n\r\n").map(|(_, body)| body).unwrap_or("");
    selfhost_json::parse(body).expect("the bulk plane answers JSON")
}

#[tokio::test]
async fn an_interrupted_upload_resumes_from_the_offset_the_session_reports() {
    // The end-to-end resume, driven through the real routes rather than
    // through `Sessions` — because the defect this test exists for was
    // *between* the two. Every piece of the session machinery worked in
    // isolation and no production caller ever appended a byte, so a client
    // could begin a session, read an offset that was zero for ever, and finish
    // an empty file while the API reported a live upload.
    let (api, dir) = storage_api_with_shares("bulk-resume");

    // Patterned rather than repetitive, so a file assembled in the wrong order,
    // or with a chunk written twice, cannot pass by luck.
    let whole: Vec<u8> = (0..200_000u32).map(|index| (index % 251) as u8).collect();

    // 1. Begin, over the control route a client actually calls.
    let (status, begun) = send(
        &api,
        "POST",
        &format!("/api/storage/shares/vault/sessions?path=/big.bin&size={}", whole.len()),
        "",
    )
    .await;
    assert_eq!(status, 200, "{begun:?}");
    let ticket = begun.get("ticket").and_then(Json::as_str).expect("a ticket").to_owned();
    assert_eq!(begun.get("offset").and_then(Json::as_f64), Some(0.0), "a new session is at zero");

    // 2. Send part of it and vanish: the peer promises 120 000 bytes, sends
    //    70 000 and hangs up, which is what a tunnel dropping looks like.
    let promised = 120_000usize;
    let delivered = 70_000usize;
    let (request, _) = request_with(
        "PUT",
        &format!("/api/storage/blob/vault/big.bin?ticket={ticket}&offset=0"),
        Some(TOKEN),
        &[("Content-Length", &promised.to_string())],
        "",
    );
    let plan = api.bulk_for(&request).expect("the owner may write");
    let (mut ours, theirs) = tokio::io::duplex(64 * 1024);
    let first = whole[..delivered].to_vec();
    let feeder = tokio::spawn(async move {
        let mut theirs = theirs;
        tokio::io::AsyncWriteExt::write_all(&mut theirs, &first).await.expect("the first part");
        tokio::io::AsyncWriteExt::shutdown(&mut theirs).await.expect("half-closed");
        let mut answer = Vec::new();
        theirs.read_to_end(&mut answer).await.expect("the answer is readable");
        answer
    });
    let report = storage_api::serve(&mut ours, Vec::new(), &request, plan)
        .await
        .expect("the transfer is answered");
    drop(ours);
    feeder.await.expect("the feeder finished");
    assert_eq!(report.status, 400, "a body that stopped short is still the request's fault");
    assert_eq!(report.bytes, delivered as u64, "what arrived is what was counted");

    // 3. Ask where it got to. This is the assertion the defect fails: with no
    //    production caller for `Sessions::append` the answer stays zero and the
    //    client restarts from the beginning for ever.
    let (status, progress) =
        send(&api, "GET", &format!("/api/storage/shares/vault/sessions/{ticket}"), "").await;
    assert_eq!(status, 200, "{progress:?}");
    let offset = progress.get("offset").and_then(Json::as_f64).expect("an offset") as u64;
    assert_ne!(offset, 0, "an interrupted upload that reports zero has not resumed anything");
    assert_eq!(offset, delivered as u64, "the session kept exactly what landed");

    // 4. A client that seeks to the wrong place is told the right one, in the
    //    body, before it spends its uplink on bytes that cannot be taken.
    let (request, _) = request_with(
        "PUT",
        &format!("/api/storage/blob/vault/big.bin?ticket={ticket}&offset=0"),
        Some(TOKEN),
        &[("Content-Length", "10")],
        "",
    );
    let plan = api.bulk_for(&request).expect("the owner may write");
    let answer = drive(whole[..10].to_vec(), request, plan).await;
    assert!(answer.starts_with("HTTP/1.1 409"), "{answer}");
    let refusal = answered_json(&answer);
    assert_eq!(refusal.get("error").and_then(Json::as_str), Some("wrong-offset"));
    assert_eq!(
        refusal.get("offset").and_then(Json::as_f64),
        Some(delivered as f64),
        "the refusal has to carry the offset to seek to, or the client is stuck"
    );

    // 5. Resume from the reported offset with the rest of the file.
    let rest = whole[offset as usize..].to_vec();
    let (request, _) = request_with(
        "PUT",
        &format!("/api/storage/blob/vault/big.bin?ticket={ticket}&offset={offset}"),
        Some(TOKEN),
        &[("Content-Length", &rest.len().to_string())],
        "",
    );
    let plan = api.bulk_for(&request).expect("the owner may write");
    let answer = drive(rest, request, plan).await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    let accepted = answered_json(&answer);
    assert_eq!(
        accepted.get("offset").and_then(Json::as_f64),
        Some(whole.len() as f64),
        "an accepted chunk answers with the new offset, so the client needs no second request"
    );

    // 6. Finish, over the control route again.
    let (status, done) = send(
        &api,
        "POST",
        &format!("/api/storage/shares/vault/sessions/{ticket}?finish=1"),
        "",
    )
    .await;
    assert_eq!(status, 200, "{done:?}");

    // 7. The file on disk is what was sent, byte for byte.
    let landed = std::fs::read(dir.path().join("vault").join("big.bin")).expect("the file");
    assert_eq!(landed.len(), whole.len(), "the whole declared length is on disk");
    assert!(landed == whole, "the resumed file must be byte-for-byte what was sent");
}

#[tokio::test]
async fn a_ticket_cannot_carry_bytes_into_a_share_it_was_not_minted_for() {
    // A ticket is a capability naming one session, and the URL is what decides
    // which share's capability the caller had to hold. If the two were never
    // compared, a ticket that leaked out of a `vault` upload plus a write
    // capability on some other share would put the holder's bytes into `vault`
    // — a share they were never granted. The refusal is the same 404 an unknown
    // ticket gets, so nobody can use the difference to confirm that somebody
    // else's upload exists.
    let (api, dir) = storage_api_with_shares("bulk-resume-cross-share");

    let (status, begun) = send(
        &api,
        "POST",
        "/api/storage/shares/vault/sessions?path=/secret.bin&size=64",
        "",
    )
    .await;
    assert_eq!(status, 200, "{begun:?}");
    let ticket = begun.get("ticket").and_then(Json::as_str).expect("a ticket").to_owned();

    // The same ticket, presented on a different share's blob path.
    let (request, _) = request_with(
        "PUT",
        &format!("/api/storage/blob/photos/secret.bin?ticket={ticket}&offset=0"),
        Some(TOKEN),
        &[("Content-Length", "4")],
        "",
    );
    let plan = api.bulk_for(&request).expect("the owner may write to photos");
    let answer = drive(b"oops".to_vec(), request, plan).await;
    assert!(answer.starts_with("HTTP/1.1 404"), "{answer}");
    assert_eq!(
        answered_json(&answer).get("error").and_then(Json::as_str),
        Some("no-session"),
        "a ticket on another share is answered as though it named no session at all"
    );

    // Nothing moved, in either share: not the session's offset, and not a file
    // under the name the URL supplied.
    let (_, progress) =
        send(&api, "GET", &format!("/api/storage/shares/vault/sessions/{ticket}"), "").await;
    assert_eq!(progress.get("offset").and_then(Json::as_f64), Some(0.0));
    assert!(!dir.path().join("photos").join("secret.bin").exists(), "nothing was written");
}

#[tokio::test]
async fn a_put_with_no_ticket_is_the_ordinary_upload_it_always_was() {
    // The resume parameters are additive: without `?ticket=` the bulk plane
    // must behave exactly as it did, including refusing an offset it has no
    // session to check it against.
    let (api, dir) = storage_api_with_shares("bulk-resume-absent");

    let (request, body) = request_with(
        "PUT",
        "/api/storage/blob/vault/plain.txt?offset=99",
        Some(TOKEN),
        &[],
        "written the old way",
    );
    let plan = api.bulk_for(&request).expect("the owner may write");
    assert!(
        matches!(plan.transfer, storage_api::Transfer::Upload { .. }),
        "no ticket means the plan is the ordinary upload it always was"
    );
    let answer = drive(body, request, plan).await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("vault").join("plain.txt")).expect("the file"),
        "written the old way"
    );

    // And an offset that is not a number is refused rather than guessed at.
    let (request, _) = request_with(
        "PUT",
        "/api/storage/blob/vault/plain.txt?ticket=deadbeef&offset=soon",
        Some(TOKEN),
        &[("Content-Length", "4")],
        "",
    );
    assert!(matches!(api.bulk_for(&request), Err(Denied::BadOffset)));
}

// ---- WebDAV -----------------------------------------------------------------
//
// The rules about *what a path may reach*, what a `207` looks like and what a
// lock excludes live in `selfhost-storage` and are tested there without a
// socket. What is tested here is the joining: which credential opens a mount,
// what an unauthenticated request looks like whatever the verb, and — the rule
// that is the opposite of every other route in this crate — that a refusal
// *after* authentication is never a second 401, because macOS and Windows both
// read one as "the stored password is wrong" and prompt for ever.

use selfhost_admin::dav_api;

/// The console API with a password, a writable `vault` and a read-only
/// `photos`, and a configured console hostname so `Destination` has an
/// authority to be checked against.
fn dav_api_with_shares(name: &str) -> (Api, ScratchDir) {
    let (plain, dir) = api(name);
    ConsolePassword::write(dir.path(), PASSWORD).expect("password written");
    let ledger = Arc::new(Ledger::new());
    let volumes = Volumes::from_opened(vec![
        open_share(dir.path(), "vault", &ledger, false, Vec::new()),
        open_share(dir.path(), "photos", &ledger, true, Vec::new()),
    ]);
    let api = plain
        .with_console_auth_parts(ConsolePassword::load(dir.path()), Sessions::new())
        .with_console_origin(CONSOLE_HOST)
        .with_storage(volumes);
    (api, dir)
}

/// The console site's configured hostname in these tests.
const CONSOLE_HOST: &str = "console.example";

/// Every verb this build answers, as a WebDAV client spells it.
const DAV_VERBS: [&str; 12] = [
    "OPTIONS", "PROPFIND", "PROPPATCH", "MKCOL", "GET", "HEAD", "PUT", "DELETE", "COPY", "MOVE",
    "LOCK", "UNLOCK",
];

/// An `Authorization: Basic` header value.
fn basic(user: &str, password: &str) -> String {
    format!("Basic {}", base64(format!("{user}:{password}").as_bytes()))
}

/// Standard base64, written here because this crate deliberately has no base64
/// dependency and its own decoder is private.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut packed = 0u32;
        for index in 0..3 {
            packed = (packed << 8) | u32::from(chunk.get(index).copied().unwrap_or(0));
        }
        for index in 0..4 {
            if index <= chunk.len() {
                let position = usize::try_from((packed >> (18 - 6 * index)) & 0x3f).expect("6 bits");
                out.push(char::from(ALPHABET[position]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A WebDAV request carrying the console password.
async fn dav(api: &Api, method: &str, target: &str, body: &str) -> Response {
    dav_with(api, method, target, &[], body).await
}

/// The same, with extra headers.
async fn dav_with(
    api: &Api,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Response {
    let credential = basic("owner", PASSWORD);
    let mut all = vec![("Authorization", credential.as_str())];
    all.extend_from_slice(headers);
    call_with(api, method, target, &all, body).await
}

/// A response body as text, for the XML answers.
fn body_text(response: &Response) -> String {
    match &response.body {
        Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        _ => String::new(),
    }
}

#[tokio::test]
async fn every_webdav_verb_refuses_an_unauthenticated_caller_with_one_identical_challenge() {
    // The uniform-401 property, and the realm is the part that must never vary:
    // Finder keys its keychain item on it and Windows keys its credential on
    // it, so a challenge that differed by share, by verb or by whether the
    // share exists would look like a different server on every request.
    let (api, _dir) = dav_api_with_shares("dav-noauth");
    let mut challenge: Option<String> = None;
    for verb in DAV_VERBS {
        for target in ["/dav", "/dav/", "/dav/vault", "/dav/vault/a.txt", "/dav/attic/secret.txt"]
        {
            let response = call_with(&api, verb, target, &[], "").await;
            assert_eq!(response.status.code(), 401, "{verb} {target}");
            assert!(body_text(&response).is_empty(), "{verb} {target} said something");
            let offered = response
                .headers
                .get_str("www-authenticate")
                .expect("every 401 here carries a challenge")
                .to_owned();
            match &challenge {
                None => challenge = Some(offered),
                Some(first) => assert_eq!(first, &offered, "{verb} {target}"),
            }
        }
    }
    let challenge = challenge.expect("at least one challenge");
    assert!(challenge.starts_with("Basic realm="), "{challenge}");
    assert!(challenge.contains("charset=\"UTF-8\""), "{challenge}");
}

#[tokio::test]
async fn a_wrong_password_and_a_malformed_header_are_the_same_answer_as_none_at_all() {
    let (api, _dir) = dav_api_with_shares("dav-wrong");
    let anonymous = call_with(&api, "PROPFIND", "/dav/vault", &[], "").await;
    for hostile in [
        basic("owner", "not the password"),
        basic("", ""),
        "Basic !!!!".to_owned(),
        "Basic".to_owned(),
        "Digest username=\"owner\"".to_owned(),
    ] {
        let refused =
            call_with(&api, "PROPFIND", "/dav/vault", &[("Authorization", &hostile)], "").await;
        assert_eq!(refused.status.code(), 401, "{hostile}");
        assert_eq!(
            refused.headers.get_str("www-authenticate"),
            anonymous.headers.get_str("www-authenticate"),
            "{hostile}"
        );
        assert_eq!(body_text(&refused), body_text(&anonymous), "{hostile}");
    }
}

#[tokio::test]
async fn neither_the_bearer_token_nor_a_session_cookie_opens_a_mount() {
    // Deliberate. A cookie would make every `/dav` path a cross-site request
    // forgery surface on the very origin that holds the console session, and
    // the bearer token would put the deployment's root credential into a
    // keychain that replays it for the life of a mount.
    let (api, _dir) = dav_api_with_shares("dav-otherdoors");
    let cookie = login(&api).await;
    let bearer = format!("Bearer {TOKEN}");
    for headers in [
        vec![("Authorization", bearer.as_str())],
        vec![("Cookie", cookie.as_str())],
        vec![("Cookie", cookie.as_str()), ("X-Selfhost-Console", "1")],
    ] {
        let refused = call_with(&api, "PROPFIND", "/dav/vault", &headers, "").await;
        assert_eq!(refused.status.code(), 401, "{headers:?}");
        assert!(refused.headers.get_str("www-authenticate").is_some(), "{headers:?}");
    }
}

#[tokio::test]
async fn the_credential_that_opens_a_mount_opens_nothing_that_drives_the_machine() {
    // The identity rule made observable. `Credential::Password` is unattended —
    // a keychain replays it on every request for the life of a mount, with
    // nobody present — so the Basic door reaches shares and reaches nothing
    // else, whatever `[desktop].bearer_may_control` is set to.
    let (api, _dir) = dav_api_with_shares("dav-onedoor");
    let credential = basic("owner", PASSWORD);

    let opened = dav(&api, "OPTIONS", "/dav", "").await;
    assert_eq!(opened.status.code(), 200, "the mount opens");

    for target in [
        "/api/services",
        "/api/desktop",
        "/api/desktop/nodes",
        "/api/desktop/agent?peer=local",
        "/api/storage/shares",
        "/api/audit",
        "/api/firewall",
    ] {
        let refused =
            call_with(&api, "GET", target, &[("Authorization", &credential)], "").await;
        assert_eq!(refused.status.code(), 401, "{target}");
    }
    let minted = call_with(
        &api,
        "POST",
        "/api/desktop/ticket",
        &[("Authorization", &credential), ("X-Selfhost-Console", "1")],
        "",
    )
    .await;
    assert_eq!(minted.status.code(), 401, "a mount must never mint a stream ticket");
}

#[tokio::test]
async fn options_answers_the_four_headers_that_make_a_mount_happen() {
    let (api, _dir) = dav_api_with_shares("dav-options");
    // Both the mount root and a share root: Finder asks the first before it
    // knows a share exists, and a 404 for it ends the attempt.
    for target in ["/dav", "/dav/", "/dav/vault", "/dav/vault/"] {
        let response = dav(&api, "OPTIONS", target, "").await;
        assert_eq!(response.status.code(), 200, "{target}");
        // Class 2 is locking, and without it both clients mount read-only.
        assert_eq!(response.headers.get_str("dav"), Some("1, 2"), "{target}");
        // Without this the Windows Mini-Redirector tries FrontPage first.
        assert_eq!(response.headers.get_str("ms-author-via"), Some("DAV"), "{target}");
        assert_eq!(response.headers.get_str("accept-ranges"), Some("bytes"), "{target}");
        let allow = response.headers.get_str("allow").expect("an Allow header").to_owned();
        for verb in DAV_VERBS {
            assert!(allow.contains(verb), "{target}: {allow} omits {verb}");
        }
    }
}

#[tokio::test]
async fn a_verb_this_build_does_not_serve_is_a_405_that_says_what_to_send_instead() {
    // Not a 501: that says the *server* does not understand the method, which is
    // untrue and which some clients treat as fatal for the whole mount.
    let (api, _dir) = dav_api_with_shares("dav-405");
    for verb in ["POST", "PATCH", "TRACE", "REPORT", "SEARCH"] {
        let response = dav(&api, verb, "/dav/vault/a.txt", "").await;
        assert_eq!(response.status.code(), 405, "{verb}");
        assert!(response.headers.get_str("allow").is_some(), "{verb} must say what is allowed");
    }
}

#[tokio::test]
async fn a_propfind_lists_a_share_and_reports_the_free_space_finder_insists_on() {
    let (api, dir) = dav_api_with_shares("dav-propfind");
    std::fs::write(dir.path().join("vault").join("notes.txt"), "hello").expect("a file");

    let response = dav_with(&api, "PROPFIND", "/dav/vault", &[("Depth", "1")], "").await;
    assert_eq!(response.status.code(), 207, "{:?}", body_text(&response));
    let body = body_text(&response);
    // The collection's own href ends in a slash: Finder builds a child's URL by
    // appending to it, so one without would produce children a level too high.
    assert!(body.contains("<D:href>/dav/vault/</D:href>"), "{body}");
    assert!(body.contains("<D:href>/dav/vault/notes.txt</D:href>"), "{body}");
    assert!(body.contains("<D:collection/>"), "{body}");
    // RFC 4331. Without these Finder reads zero free space and refuses every
    // copy before it starts.
    assert!(body.contains("quota-available-bytes"), "{body}");
    assert!(body.contains("quota-used-bytes"), "{body}");

    // Depth 0 is the resource alone.
    let alone = dav_with(&api, "PROPFIND", "/dav/vault", &[("Depth", "0")], "").await;
    assert_eq!(alone.status.code(), 207);
    assert!(!body_text(&alone).contains("notes.txt"), "{}", body_text(&alone));
}

#[tokio::test]
async fn a_hostile_filename_reaches_the_client_as_a_link_to_itself_and_not_to_another_file() {
    // A directory can hold `a%2fb.txt`, whose own text placed in a URL asks for
    // `a/b.txt` one level down — so a client shown the raw name copies,
    // overwrites or deletes a different file than the one it was shown. Every
    // href goes through the encoded type, which has no constructor from a
    // String, and this is that rule observed from outside.
    let (api, dir) = dav_api_with_shares("dav-href");
    std::fs::write(dir.path().join("vault").join("a%2fb.txt"), "x").expect("a hostile name");

    let response = dav_with(&api, "PROPFIND", "/dav/vault", &[("Depth", "1")], "").await;
    assert_eq!(response.status.code(), 207);
    let body = body_text(&response);
    assert!(body.contains("a%252fb.txt"), "the percent is encoded: {body}");
    assert!(!body.contains("<D:href>/dav/vault/a%2fb.txt</D:href>"), "{body}");
}

#[tokio::test]
async fn depth_infinity_is_refused_with_the_condition_that_tells_a_client_to_retry() {
    let (api, _dir) = dav_api_with_shares("dav-depth");
    // An absent Depth header means infinity, which RFC 4918 requires and which
    // is the opposite of the safe-looking default.
    for headers in [vec![], vec![("Depth", "infinity")], vec![("Depth", "Infinity")]] {
        let response = dav_with(&api, "PROPFIND", "/dav/vault", &headers, "").await;
        assert_eq!(response.status.code(), 403, "{headers:?}");
        assert!(body_text(&response).contains("propfind-finite-depth"), "{headers:?}");
    }
    let confused = dav_with(&api, "PROPFIND", "/dav/vault", &[("Depth", "2")], "").await;
    assert_eq!(confused.status.code(), 400);
}

#[tokio::test]
async fn an_authenticated_caller_naming_no_share_gets_a_404_and_is_never_asked_again() {
    // The one place this crate's uniform 401 is deliberately not the answer. A
    // second 401 is what makes both desktop clients throw away the credential
    // they stored and prompt for ever — and it conceals nothing, because the
    // only credential that opens /dav is the deployment-wide one, which holds
    // every share there is.
    let (api, _dir) = dav_api_with_shares("dav-noshare");
    for target in ["/dav/attic", "/dav/attic/deep/file.txt", "/dav/NOT%20A%20SHARE/x"] {
        let response = dav_with(&api, "PROPFIND", target, &[("Depth", "0")], "").await;
        assert_eq!(response.status.code(), 404, "{target}");
        assert!(
            response.headers.get_str("www-authenticate").is_none(),
            "{target} must not re-challenge"
        );
    }
    let missing = dav_with(&api, "PROPFIND", "/dav/vault/nowhere.txt", &[("Depth", "0")], "").await;
    assert_eq!(missing.status.code(), 404);
}

#[tokio::test]
async fn a_share_the_caller_may_not_write_refuses_every_writing_verb_with_403() {
    // `read_only` is a statement about the data and binds the owner too, so
    // this is the refusal a mount meets even holding the root credential — and
    // it is made by the route, before a descriptor is opened, for the byte
    // plane as much as for the document plane.
    let (api, dir) = dav_api_with_shares("dav-readonly");
    std::fs::write(dir.path().join("photos").join("holiday.jpg"), "x").expect("a file");

    for (verb, target, headers) in [
        ("MKCOL", "/dav/photos/new", vec![]),
        ("DELETE", "/dav/photos/holiday.jpg", vec![]),
        ("PROPPATCH", "/dav/photos/holiday.jpg", vec![]),
        ("PUT", "/dav/photos/new.txt", vec![("Content-Length", "0")]),
        (
            "MOVE",
            "/dav/photos/holiday.jpg",
            vec![("Destination", "https://console.example/dav/photos/other.jpg")],
        ),
    ] {
        let response = dav_with(&api, verb, target, &headers, "").await;
        assert_eq!(response.status.code(), 403, "{verb} {target}");
    }

    // Reading it is fine, which is the whole point of a read-only share.
    let listed = dav_with(&api, "PROPFIND", "/dav/photos", &[("Depth", "1")], "").await;
    assert_eq!(listed.status.code(), 207, "{:?}", body_text(&listed));

    // And a copy *into* it is refused by the destination's own rules, not the
    // source's — the asymmetry a function given only a path would have missed.
    let copied = dav_with(
        &api,
        "COPY",
        "/dav/vault",
        &[("Destination", "https://console.example/dav/photos/vault-copy")],
        "",
    )
    .await;
    assert_eq!(copied.status.code(), 403);

    // The other direction is an ordinary request and must not be refused: a
    // COPY *reads* its source, so a read-only share is a perfectly good place
    // to copy out of. Asking the source for write would have broken it.
    let rescued = dav_with(
        &api,
        "COPY",
        "/dav/photos/holiday.jpg",
        &[("Destination", "https://console.example/dav/vault/holiday.jpg")],
        "",
    )
    .await;
    assert_eq!(rescued.status.code(), 201, "{:?}", body_text(&rescued));
    assert!(dir.path().join("vault").join("holiday.jpg").exists());
    assert!(dir.path().join("photos").join("holiday.jpg").exists(), "the source is untouched");
}

#[tokio::test]
async fn mkcol_makes_one_directory_and_refuses_a_second_a_body_and_a_missing_parent() {
    let (api, dir) = dav_api_with_shares("dav-mkcol");

    let made = dav(&api, "MKCOL", "/dav/vault/papers", "").await;
    assert_eq!(made.status.code(), 201, "{:?}", body_text(&made));
    // A collection's Location ends in a slash, and it is built by the encoder
    // rather than spelled here.
    assert_eq!(made.headers.get_str("location"), Some("/dav/vault/papers/"));
    assert!(dir.path().join("vault").join("papers").is_dir());

    // RFC 4918 §9.3.1: onto an existing resource this is 405, not 409.
    let again = dav(&api, "MKCOL", "/dav/vault/papers", "").await;
    assert_eq!(again.status.code(), 405);

    // A body is 415: this build implements no extended MKCOL, and ignoring one
    // would create a collection that is not the one that was asked for.
    let bodied = dav(&api, "MKCOL", "/dav/vault/other", "<x/>").await;
    assert_eq!(bodied.status.code(), 415);

    // One directory, never a tree: a missing parent is 409, so a typo does not
    // build a path.
    let orphan = dav(&api, "MKCOL", "/dav/vault/nope/deeper", "").await;
    assert_eq!(orphan.status.code(), 409);
    assert!(!dir.path().join("vault").join("nope").exists());
}

#[tokio::test]
async fn delete_removes_a_tree_and_then_says_it_is_gone() {
    let (api, dir) = dav_api_with_shares("dav-delete");
    std::fs::create_dir_all(dir.path().join("vault").join("tree").join("inner"))
        .expect("a tree");
    std::fs::write(dir.path().join("vault").join("tree").join("inner").join("a.txt"), "x")
        .expect("a leaf");

    let removed = dav(&api, "DELETE", "/dav/vault/tree", "").await;
    assert_eq!(removed.status.code(), 204, "{:?}", body_text(&removed));
    assert!(!dir.path().join("vault").join("tree").exists(), "depth-infinity, as §9.6 means");

    let gone = dav_with(&api, "PROPFIND", "/dav/vault/tree", &[("Depth", "0")], "").await;
    assert_eq!(gone.status.code(), 404);
}

#[tokio::test]
async fn copy_and_move_funnel_the_destination_through_the_same_resolver_as_the_request_line() {
    // A MOVE whose destination escapes its root is a write-anywhere primitive
    // as complete as a traversal, and Overwrite: T compounds it. Every refusal
    // below is one somebody has exploited on some other server.
    let (api, dir) = dav_api_with_shares("dav-transfer");
    let vault = dir.path().join("vault");
    std::fs::write(vault.join("one.txt"), "first").expect("a file");
    std::fs::write(vault.join("two.txt"), "second").expect("another file");

    let destination = format!("https://{CONSOLE_HOST}/dav/vault/copied.txt");
    let copied =
        dav_with(&api, "COPY", "/dav/vault/one.txt", &[("Destination", &destination)], "").await;
    assert_eq!(copied.status.code(), 201, "{:?}", body_text(&copied));
    assert_eq!(copied.headers.get_str("location"), Some("/dav/vault/copied.txt"));
    assert_eq!(std::fs::read_to_string(vault.join("copied.txt")).expect("the copy"), "first");

    // Overwrite: F onto an occupied destination is a precondition the client
    // stated, so 412 — never 409, which the client reads as a missing parent.
    let refused = dav_with(
        &api,
        "COPY",
        "/dav/vault/two.txt",
        &[("Destination", &destination), ("Overwrite", "F")],
        "",
    )
    .await;
    assert_eq!(refused.status.code(), 412);
    assert_eq!(std::fs::read_to_string(vault.join("copied.txt")).expect("untouched"), "first");

    // With T (the default) it replaces, and a replacement is 204.
    let replaced =
        dav_with(&api, "COPY", "/dav/vault/two.txt", &[("Destination", &destination)], "").await;
    assert_eq!(replaced.status.code(), 204);
    assert_eq!(std::fs::read_to_string(vault.join("copied.txt")).expect("replaced"), "second");

    // A MOVE leaves nothing behind.
    let moved = dav_with(
        &api,
        "MOVE",
        "/dav/vault/one.txt",
        &[("Destination", &format!("https://{CONSOLE_HOST}/dav/vault/moved.txt"))],
        "",
    )
    .await;
    assert_eq!(moved.status.code(), 201);
    assert!(!vault.join("one.txt").exists());

    // Every way of getting the header wrong.
    for (header, expected) in [
        (None, 400),
        (Some("https://elsewhere.example/dav/vault/x"), 502),
        (Some("/etc/passwd"), 400),
        (Some("//elsewhere.example/dav/vault/x"), 400),
        (Some(&format!("https://{CONSOLE_HOST}/dav/vault/../../etc/passwd")), 404),
        (Some(&format!("https://{CONSOLE_HOST}/dav/attic/x")), 409),
        (Some(&format!("https://{CONSOLE_HOST}/dav/photos/x")), 403),
    ] {
        let headers: Vec<(&str, &str)> =
            header.map_or_else(Vec::new, |value| vec![("Destination", value)]);
        let response = dav_with(&api, "MOVE", "/dav/vault/two.txt", &headers, "").await;
        assert_eq!(response.status.code(), expected, "Destination: {header:?}");
        assert!(vault.join("two.txt").exists(), "nothing moved: {header:?}");
    }

    // An Overwrite spelling that is neither T nor F is a 400: guessing at a
    // third means guessing whether the client meant to destroy something.
    let confused = dav_with(
        &api,
        "MOVE",
        "/dav/vault/two.txt",
        &[("Destination", &destination), ("Overwrite", "maybe")],
        "",
    )
    .await;
    assert_eq!(confused.status.code(), 400);
}

#[tokio::test]
async fn a_lock_excludes_a_second_client_and_the_token_is_what_lets_a_write_through() {
    // Locking is not a formality: both the Windows Mini-Redirector and macOS
    // WebDAVFS lock before every write, and a server that claimed `DAV: 1, 2`
    // without one would be mounted and then fail on the first PUT.
    let (api, _dir) = dav_api_with_shares("dav-lock");
    let lockinfo = "<?xml version=\"1.0\"?><D:lockinfo xmlns:D=\"DAV:\">\
                    <D:lockscope><D:exclusive/></D:lockscope>\
                    <D:locktype><D:write/></D:locktype>\
                    <D:owner>Rocky</D:owner></D:lockinfo>";

    // A lock on a name that does not exist yet is granted and answered 201 —
    // the lock-null resource Windows takes before it creates a file.
    let granted =
        dav_with(&api, "LOCK", "/dav/vault/doc.txt", &[("Depth", "0")], lockinfo).await;
    assert_eq!(granted.status.code(), 201, "{:?}", body_text(&granted));
    let token = granted
        .headers
        .get_str("lock-token")
        .expect("a Lock-Token header, which is where every client reads it")
        .to_owned();
    assert!(token.starts_with('<') && token.ends_with('>'), "coded-URL grammar: {token}");
    assert!(body_text(&granted).contains("lockdiscovery"), "Finder parses the timeout from it");
    let inner = token.trim_matches(['<', '>']).to_owned();

    // A second client is excluded.
    let contested =
        dav_with(&api, "LOCK", "/dav/vault/doc.txt", &[("Depth", "0")], lockinfo).await;
    assert_eq!(contested.status.code(), 423);
    assert!(body_text(&contested).contains("lock-token-submitted"), "{}", body_text(&contested));

    // And so is a write that does not submit the token.
    let blocked = dav_with(&api, "PUT", "/dav/vault/doc.txt", &[("Content-Length", "0")], "").await;
    assert_eq!(blocked.status.code(), 423);

    // Submitting it lets the holder through. The byte plane owns a connection,
    // so what is asserted here is the decision the socket layer makes.
    let condition = format!("(<{inner}>)");
    let (request, _) = request_with(
        "PUT",
        "/dav/vault/doc.txt",
        None,
        &[
            ("Authorization", &basic("owner", PASSWORD)),
            ("If", &condition),
            ("Content-Length", "0"),
        ],
        "",
    );
    let wiring = api.dav_wiring().expect("a wired mount");
    assert!(dav_api::admit(&wiring, &request).await.is_ok(), "the lock holder writes");

    // A refresh extends what the client already holds; a refresh naming no live
    // lock is a precondition that is not true.
    let refreshed = dav_with(
        &api,
        "LOCK",
        "/dav/vault/doc.txt",
        &[("If", &condition), ("Timeout", "Second-120")],
        "",
    )
    .await;
    assert_eq!(refreshed.status.code(), 200);
    let stale = dav_with(
        &api,
        "LOCK",
        "/dav/vault/doc.txt",
        &[("If", "(<urn:uuid:0000>)")],
        "",
    )
    .await;
    assert_eq!(stale.status.code(), 412);

    // A token at the wrong URL releases nothing: the token is the capability
    // and the URL is what an operator reads in a log.
    let elsewhere =
        dav_with(&api, "UNLOCK", "/dav/vault/other.txt", &[("Lock-Token", &token)], "").await;
    assert_eq!(elsewhere.status.code(), 409);

    let released =
        dav_with(&api, "UNLOCK", "/dav/vault/doc.txt", &[("Lock-Token", &token)], "").await;
    assert_eq!(released.status.code(), 204);
    let twice =
        dav_with(&api, "UNLOCK", "/dav/vault/doc.txt", &[("Lock-Token", &token)], "").await;
    assert_eq!(twice.status.code(), 409);
    let missing = dav(&api, "UNLOCK", "/dav/vault/doc.txt", "").await;
    assert_eq!(missing.status.code(), 400);

    // With the lock gone the write goes through the document plane's decision
    // unopposed.
    let clear = dav_with(&api, "PUT", "/dav/vault/doc.txt", &[("Content-Length", "0")], "").await;
    assert_ne!(clear.status.code(), 423, "the lock was released");
}

#[tokio::test]
async fn a_shared_lock_is_refused_rather_than_quietly_granted_as_an_exclusive_one() {
    // A client that asked for a lock several writers may hold and received one
    // only it may hold would behave correctly; one that asked for exclusivity
    // and got a shared lock would not, and a server that blurs the two
    // eventually does the second.
    let (api, _dir) = dav_api_with_shares("dav-shared-lock");
    let shared = "<D:lockinfo xmlns:D=\"DAV:\"><D:lockscope><D:shared/></D:lockscope>\
                  <D:locktype><D:write/></D:locktype></D:lockinfo>";
    let response = dav_with(&api, "LOCK", "/dav/vault/x.txt", &[("Depth", "0")], shared).await;
    assert_eq!(response.status.code(), 403);

    let nonsense = dav_with(&api, "LOCK", "/dav/vault/x.txt", &[("Depth", "0")], "<not-xml").await;
    assert_eq!(nonsense.status.code(), 400);

    let deep = dav_with(
        &api,
        "LOCK",
        "/dav/vault/x.txt",
        &[("Depth", "1")],
        "<D:lockinfo xmlns:D=\"DAV:\"><D:lockscope><D:exclusive/></D:lockscope>\
         <D:locktype><D:write/></D:locktype></D:lockinfo>",
    )
    .await;
    assert_eq!(deep.status.code(), 400, "Depth: 1 is not a lock depth");
}

#[tokio::test]
async fn proppatch_says_plainly_that_it_stored_nothing() {
    // Explorer issues one after every PUT. Answering 200 to a property we did
    // not store is a server telling a client a timestamp was preserved when it
    // was not, and this project does not make that trade anywhere else.
    let (api, dir) = dav_api_with_shares("dav-proppatch");
    std::fs::write(dir.path().join("vault").join("a.txt"), "x").expect("a file");

    let body = "<D:propertyupdate xmlns:D=\"DAV:\" xmlns:Z=\"urn:schemas-microsoft-com:\">\
                <D:set><D:prop><Z:Win32LastModifiedTime>Mon, 1 Jan 2024 00:00:00 GMT\
                </Z:Win32LastModifiedTime></D:prop></D:set></D:propertyupdate>";
    let response = dav(&api, "PROPPATCH", "/dav/vault/a.txt", body).await;
    assert_eq!(response.status.code(), 207, "{:?}", body_text(&response));
    let answered = body_text(&response);
    assert!(answered.contains("<D:href>/dav/vault/a.txt</D:href>"), "{answered}");
    assert!(answered.contains("403"), "each property is refused: {answered}");

    // Of something that is not there, it is a 404 rather than a 207 full of
    // refusals about a file that does not exist.
    let nowhere = dav(&api, "PROPPATCH", "/dav/vault/absent.txt", body).await;
    assert_eq!(nowhere.status.code(), 404);
}

#[tokio::test]
async fn a_put_creates_then_replaces_and_a_get_brings_the_bytes_back_as_an_attachment() {
    let (api, dir) = dav_api_with_shares("dav-bytes");

    let created = drive_dav(&api, "PUT", "/dav/vault/hello.txt", &[], "hello there").await;
    assert!(created.starts_with("HTTP/1.1 201"), "{created}");
    assert!(created.contains("Location: /dav/vault/hello.txt"), "{created}");
    assert_eq!(
        std::fs::read_to_string(dir.path().join("vault").join("hello.txt")).expect("the file"),
        "hello there"
    );

    // A second PUT replaces, and a replacement is 204 — which is what a client
    // uses to decide whether to refresh its view.
    let replaced = drive_dav(&api, "PUT", "/dav/vault/hello.txt", &[], "again").await;
    assert!(replaced.starts_with("HTTP/1.1 204"), "{replaced}");

    let fetched = drive_dav(&api, "GET", "/dav/vault/hello.txt", &[], "").await;
    assert!(fetched.starts_with("HTTP/1.1 200"), "{fetched}");
    // Pinned to an attachment: /dav is served from the console's own origin, and
    // a file a caller uploaded and then had rendered inline there is stored
    // cross-site scripting with the console as its target.
    assert!(fetched.to_ascii_lowercase().contains("attachment"), "{fetched}");
    assert!(fetched.ends_with("again"), "{fetched}");

    let headed = drive_dav(&api, "HEAD", "/dav/vault/hello.txt", &[], "").await;
    assert!(headed.starts_with("HTTP/1.1 200"), "{headed}");
    assert!(!headed.ends_with("again"), "a HEAD carries no body: {headed}");
}

#[tokio::test]
async fn the_byte_plane_refuses_what_it_cannot_frame_and_what_it_cannot_reach() {
    let (api, _dir) = dav_api_with_shares("dav-byteplane");
    let credential = basic("owner", PASSWORD);
    let wiring = api.dav_wiring().expect("a wired mount");

    let (chunked, _) = request_with(
        "PUT",
        "/dav/vault/a.txt",
        None,
        &[("Authorization", &credential), ("Transfer-Encoding", "chunked")],
        "",
    );
    let refused = dav_api::admit(&wiring, &chunked).await.expect_err("chunked is not framed");
    assert_eq!(refused.response().status.code(), 411);

    let (anonymous, _) = request_with("GET", "/dav/vault/a.txt", None, &[], "");
    let challenged = dav_api::admit(&wiring, &anonymous).await.expect_err("no credential");
    assert_eq!(challenged.response().status.code(), 401);
    assert!(challenged.response().headers.get_str("www-authenticate").is_some());

    let (document, _) = request_with(
        "PROPFIND",
        "/dav/vault",
        None,
        &[("Authorization", &credential)],
        "",
    );
    let wrong_plane = dav_api::admit(&wiring, &document).await.expect_err("not a byte verb");
    assert_eq!(wrong_plane.response().status.code(), 405);
}

#[tokio::test]
async fn the_verified_credential_cache_is_on_this_path() {
    // Not an optimisation. `ConsolePassword::verify` is 600,000 PBKDF2
    // iterations, WebDAV re-authenticates on essentially every request, and
    // Finder's first act on a mount is a PROPFIND sweep — so an uncached path
    // spends roughly seventy milliseconds of a core per file, and a
    // five-hundred-file mount is thirty-five seconds during which the daemon
    // serves nobody.
    let (api, _dir) = dav_api_with_shares("dav-cache");
    let password = ConsolePassword::load(_dir.path());

    // What one cold verification costs on this machine, measured rather than
    // assumed: the iteration count is deliberate and the hardware is not.
    let cold = std::time::Instant::now();
    assert!(password.verify(PASSWORD), "the password is the one we wrote");
    let one_verification = cold.elapsed();

    // Warm the cache, then run a sweep the size of a small directory.
    let first = dav_with(&api, "PROPFIND", "/dav/vault", &[("Depth", "0")], "").await;
    assert_eq!(first.status.code(), 207);

    const SWEEP: u32 = 20;
    let swept = std::time::Instant::now();
    for _ in 0..SWEEP {
        let response = dav_with(&api, "PROPFIND", "/dav/vault", &[("Depth", "0")], "").await;
        assert_eq!(response.status.code(), 207);
    }
    let sweep = swept.elapsed();
    assert!(
        sweep < one_verification * SWEEP / 4,
        "{SWEEP} requests took {sweep:?}; one verification alone is {one_verification:?}, \
         so the credential cache is not on this path"
    );

    // Bounded and keyed: the sweep is one entry, not twenty-one.
    let wiring = api.dav_wiring().expect("a wired mount");
    assert_eq!(wiring.webdav.credentials().len(), 1);
}

#[tokio::test]
async fn a_credential_that_keeps_failing_is_throttled_and_the_console_door_is_untouched() {
    // Every WebDAV client's first request is unauthenticated by protocol
    // design, so feeding those refusals to the console's global login gate
    // would let mounting a single share lock the operator out of the console
    // they would use to unmount it. WebDAV gets a counter of its own: per
    // credential, self-clearing, and in a crate the session code does not call.
    let (api, _dir) = dav_api_with_shares("dav-throttle");
    let wrong = basic("owner", "not the password");
    for _ in 0..(selfhost_storage::auth::MAX_FAILURES * 2) {
        let refused =
            call_with(&api, "PROPFIND", "/dav/vault", &[("Authorization", &wrong)], "").await;
        assert_eq!(refused.status.code(), 401);
    }

    // The right password still works — the throttle names one credential.
    let allowed = dav_with(&api, "PROPFIND", "/dav/vault", &[("Depth", "0")], "").await;
    assert_eq!(allowed.status.code(), 207);

    // And the console's own login is untouched, which is the whole point.
    let cookie = login(&api).await;
    let response = call_with(&api, "GET", "/api/services", &[("Cookie", &cookie)], "").await;
    assert_eq!(response.status.code(), 200);
}

#[tokio::test]
async fn a_deployment_with_no_shares_challenges_rather_than_saying_so() {
    // A mount point that answered 404 with no password and 401 with one would
    // be a way to read the deployment's configuration from outside it.
    let (plain, dir) = api("dav-unwired");
    ConsolePassword::write(dir.path(), PASSWORD).expect("password written");
    let api = plain.with_console_auth_parts(ConsolePassword::load(dir.path()), Sessions::new());
    for verb in DAV_VERBS {
        let response = dav(&api, verb, "/dav/vault/a.txt", "").await;
        assert_eq!(response.status.code(), 401, "{verb}");
        assert!(response.headers.get_str("www-authenticate").is_some(), "{verb}");
    }
}

/// Runs a WebDAV byte transfer over a duplex and returns everything written
/// back, exactly as the socket layer would.
async fn drive_dav(
    api: &Api,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> String {
    let credential = basic("owner", PASSWORD);
    let length = body.len().to_string();
    let mut all = vec![("Authorization", credential.as_str())];
    all.extend_from_slice(headers);
    if method == "PUT" {
        all.push(("Content-Length", length.as_str()));
    }
    let (request, prefix) = request_with(method, target, None, &all, body);
    let passage = {
        let wiring = api.dav_wiring().expect("a wired mount");
        dav_api::admit(&wiring, &request).await.expect("the owner may transfer")
    };

    let (mut ours, mut theirs) = tokio::io::duplex(1024 * 1024);
    let served = tokio::spawn(async move {
        let report = dav_api::serve(&mut ours, prefix, &request, passage).await;
        drop(ours);
        report
    });
    let mut written = Vec::new();
    theirs.read_to_end(&mut written).await.expect("the answer is readable");
    served.await.expect("the task finished").expect("the transfer is answered");
    String::from_utf8_lossy(&written).into_owned()
}

// ---- desktop ----------------------------------------------------------------

/// A fleet that reports two machines and drives nothing.
///
/// The whole point of the [`Fleet`] seam: every refusal, every capability
/// filter and every ticket rule below is exercised on a laptop with no capture
/// backend, no agent and no peer link.
struct TestFleet;

impl selfhost_admin::Fleet for TestFleet {
    fn nodes(&self) -> Vec<selfhost_admin::NodeReport> {
        vec![
            selfhost_admin::NodeReport::local(),
            selfhost_admin::NodeReport {
                node: "alex-desktop".to_owned(),
                live: false,
                last_seen_secs: Some(90),
                reason: Some("the link was closed by the peer".to_owned()),
            },
        ]
    }

    fn agent(&self, node: &str) -> selfhost_admin::AgentReport {
        selfhost_admin::AgentReport::absent(node, "no capture backend is built for this host")
    }

    fn serve<'a>(
        &'a self,
        _session: selfhost_admin::Handover,
    ) -> selfhost_admin::desk_api::Task<'a, String> {
        Box::pin(async { "the test fleet drives nothing".to_owned() })
    }
}

/// The console API with the desktop switched on.
fn desktop_api(name: &str, config: selfhost_config::Desktop) -> (Api, ScratchDir) {
    let (api, dir) = api(name);
    (api.with_desktop(config, Arc::new(TestFleet)), dir)
}

/// A desktop configuration that is on, allows input, and re-authenticates
/// within `window` seconds.
fn desktop_on(window: u64) -> selfhost_config::Desktop {
    selfhost_config::Desktop {
        enabled: true,
        allow_input: true,
        reauth_window_secs: window,
        ..selfhost_config::Desktop::default()
    }
}

#[tokio::test]
async fn a_deployment_with_no_desktop_says_so_only_to_a_caller_who_is_already_in() {
    let (api, _dir) = api("desktop-absent");
    // Authenticated: an honest 404, the same shape the passkey routes use when
    // the feature is off.
    for target in ["/api/desktop", "/api/desktop/nodes", "/api/desktop/agent"] {
        let (status, _) = send(&api, "GET", target, "").await;
        assert_eq!(status, 404, "{target}");
    }
    // Unauthenticated: the uniform 401, so a stranger cannot learn whether this
    // box has a screen.
    for target in ["/api/desktop", "/api/desktop/nodes", "/api/desktop/agent"] {
        let (status, _) = call(&api, "GET", target, None, "").await;
        assert_eq!(status, 401, "{target}");
    }
}

#[tokio::test]
async fn a_desktop_that_is_configured_off_is_indistinguishable_from_one_that_is_absent() {
    // `[desktop].enabled = false` is not a soft default: the routes behave
    // exactly as they do with no `[desktop]` block at all.
    let (api, _dir) = desktop_api("desktop-off", selfhost_config::Desktop::default());
    let (status, _) = send(&api, "GET", "/api/desktop", "").await;
    assert_eq!(status, 404);
    let (status, _) = send(&api, "POST", "/api/desktop/ticket", r#"{"want":["desktop.view"]}"#).await;
    assert_eq!(status, 401, "no desktop, no desktop ticket");
}

#[tokio::test]
async fn the_desktop_settings_report_the_operators_own_switches() {
    let (api, _dir) = desktop_api("desktop-settings", desktop_on(120));
    let (status, body) = send(&api, "GET", "/api/desktop", "").await;
    assert_eq!(status, 200, "{body:?}");
    assert_eq!(body.get("enabled").and_then(Json::as_bool), Some(true));
    assert_eq!(body.get("allowInput").and_then(Json::as_bool), Some(true));
    assert_eq!(body.get("reauthWindowSecs").and_then(Json::as_u64), Some(120));
}

#[tokio::test]
async fn a_node_that_is_down_is_reported_with_its_reason_rather_than_omitted() {
    let (api, _dir) = desktop_api("desktop-nodes", desktop_on(120));
    let (status, body) = send(&api, "GET", "/api/desktop/nodes", "").await;
    assert_eq!(status, 200, "{body:?}");
    let nodes = body.get("nodes").and_then(Json::as_array).expect("a nodes array");
    assert_eq!(nodes.len(), 2, "{body:?}");
    let down = nodes
        .iter()
        .find(|node| node.get("node").and_then(Json::as_str) == Some("alex-desktop"))
        .expect("the second machine");
    assert_eq!(down.get("live").and_then(Json::as_bool), Some(false));
    assert!(down.get("reason").and_then(Json::as_str).is_some(), "absence is never the answer");
}

#[tokio::test]
async fn the_node_list_is_filtered_to_the_machines_a_person_may_watch() {
    let sessions = Sessions::new();
    let (api, dir) = console_api("desktop-node-filter", sessions.clone());
    let people = People::load(dir.path());
    let mut grants = Grants::none();
    grants.grant(Capability::ConsoleRead).expect("room for one grant");
    grants
        .grant(Capability::DesktopView(NodeName::parse("self").expect("a legal node")))
        .expect("room for one grant");
    people
        .set_grants(&PersonName::parse("Mom").expect("a legal name"), grants)
        .expect("grants are written");
    let id = sessions.create("Mom", Opening::Passkey).expect("a session");
    let cookie = format!("selfhost_session={id}");
    let api = api.with_people(people).with_desktop(desktop_on(120), Arc::new(TestFleet));

    let listed = call_with(&api, "GET", "/api/desktop/nodes", &[("Cookie", &cookie)], "").await;
    assert_eq!(listed.status.code(), 200);
    let body = body_json(&listed);
    let nodes = body.get("nodes").and_then(Json::as_array).expect("a nodes array");
    assert_eq!(nodes.len(), 1, "only the machine they hold a view of: {body:?}");
    assert_eq!(nodes[0].get("node").and_then(Json::as_str), Some("self"));

    // The machine they hold nothing for is the ordinary 401 on the agent route,
    // which is the same answer an unparseable node name gets.
    let refused =
        call_with(&api, "GET", "/api/desktop/agent?peer=alex-desktop", &[("Cookie", &cookie)], "")
            .await;
    assert_eq!(refused.status.code(), 401);
    let nonsense =
        call_with(&api, "GET", "/api/desktop/agent?peer=Not%20A%20Node", &[("Cookie", &cookie)], "")
            .await;
    assert_eq!(nonsense.status.code(), refused.status.code());
}

#[tokio::test]
async fn a_desktop_ticket_names_its_machine_and_control_always_implies_view() {
    let (api, dir) = desktop_api("desktop-ticket", desktop_on(900));
    // A cookie session, because a control ticket is decided against a login
    // moment and the bearer token has none.
    ConsolePassword::write(dir.path(), PASSWORD).expect("password written");
    let sessions = Sessions::new();
    let api = api
        .with_console_auth_parts(ConsolePassword::load(dir.path()), sessions)
        .with_console_origin(DESKTOP_RP);
    let cookie = login(&api).await;

    let minted = call_with(
        &api,
        "POST",
        "/api/desktop/ticket",
        &[("Cookie", &cookie), ("X-Selfhost-Console", "1")],
        r#"{"want":["desktop.control"],"peer":"alex-desktop"}"#,
    )
    .await;
    assert_eq!(minted.status.code(), 200, "{:?}", body_json(&minted));
    let ticket = body_json(&minted).get("ticket").and_then(Json::as_str).expect("a ticket").to_owned();

    // The ticket carries view as well as control, and it is bound to the machine
    // that was named: a handshake against a different one must not redeem it.
    let redeemed = api
        .upgrade_for(
            &handshake("/api/desktop/session?peer=alex-desktop", &ticket, &cookie),
            selfhost_admin::Ability::DesktopView(
                NodeName::parse("alex-desktop").expect("a legal node"),
            ),
        )
        .expect("the ticket opens the machine it named");
    assert!(
        redeemed
            .abilities
            .iter()
            .any(|a| matches!(a, selfhost_admin::Ability::DesktopControl(_))),
        "control was asked for and is carried"
    );
}

#[tokio::test]
async fn a_ticket_minted_for_one_machine_does_not_open_another() {
    let (api, dir) = desktop_api("desktop-wrong-machine", desktop_on(900));
    ConsolePassword::write(dir.path(), PASSWORD).expect("password written");
    let api = api
        .with_console_auth_parts(ConsolePassword::load(dir.path()), Sessions::new())
        .with_console_origin(DESKTOP_RP);
    let cookie = login(&api).await;

    let minted = call_with(
        &api,
        "POST",
        "/api/desktop/ticket",
        &[("Cookie", &cookie), ("X-Selfhost-Console", "1")],
        r#"{"want":["desktop.view"],"peer":"alex-desktop"}"#,
    )
    .await;
    let ticket = body_json(&minted).get("ticket").and_then(Json::as_str).expect("a ticket").to_owned();

    let refused = api.upgrade_for(
        &handshake("/api/desktop/session?peer=self", &ticket, &cookie),
        selfhost_admin::Ability::DesktopView(NodeName::parse("self").expect("a legal node")),
    );
    assert!(refused.is_err(), "a ticket for the study opens the study and nothing else");
}

#[tokio::test]
async fn a_stale_login_is_refused_a_control_ticket_and_told_to_re_authenticate() {
    // Zero seconds: every login is already too old, which is the boundary this
    // rule is written around. The rule's own arithmetic is unit-tested in
    // `desk_api`; what is tested here is that the route applies it and that the
    // console is told what to do about it.
    let (api, dir) = desktop_api("desktop-stale", desktop_on(0));
    ConsolePassword::write(dir.path(), PASSWORD).expect("password written");
    let api = api
        .with_console_auth_parts(ConsolePassword::load(dir.path()), Sessions::new())
        .with_console_origin(DESKTOP_RP);
    let cookie = login(&api).await;

    let refused = call_with(
        &api,
        "POST",
        "/api/desktop/ticket",
        &[("Cookie", &cookie), ("X-Selfhost-Console", "1")],
        r#"{"want":["desktop.control"],"peer":"self"}"#,
    )
    .await;
    assert_eq!(refused.status.code(), 403, "{:?}", body_json(&refused));
    assert_eq!(
        body_json(&refused).get("reauthenticate").and_then(Json::as_bool),
        Some(true),
        "the console has to know to prompt rather than send them to a login page"
    );

    // Viewing is unaffected: the freshness rule is about driving a machine.
    let watching = call_with(
        &api,
        "POST",
        "/api/desktop/ticket",
        &[("Cookie", &cookie), ("X-Selfhost-Console", "1")],
        r#"{"want":["desktop.view"],"peer":"self"}"#,
    )
    .await;
    assert_eq!(watching.status.code(), 200, "{:?}", body_json(&watching));
}

#[tokio::test]
async fn an_unattended_credential_is_refused_a_keyboard_until_the_operator_arms_it() {
    // The bearer token opens every existing route and will not open a keyboard,
    // because no person is proven to be there and it skips every browser-side
    // defence at once.
    let (api, _dir) = desktop_api("desktop-bearer", desktop_on(900));
    let (status, _) = send(
        &api,
        "POST",
        "/api/desktop/ticket",
        r#"{"want":["desktop.control"],"peer":"self"}"#,
    )
    .await;
    assert_eq!(status, 401, "an unarmed token may not drive the machine");

    let (armed, _) = desktop_api("desktop-bearer-armed", desktop_on(900));
    let armed = armed.with_policy(selfhost_identity::Policy::new(true));
    let (status, body) = send(
        &armed,
        "POST",
        "/api/desktop/ticket",
        r#"{"want":["desktop.control"],"peer":"self"}"#,
    )
    .await;
    assert_eq!(status, 200, "{body:?}");
}

#[tokio::test]
async fn a_desktop_ticket_naming_no_legal_machine_is_a_400_rather_than_a_default() {
    // A target this API chose is not the target the caller asked for, and it
    // would be authorised as though it were.
    let (api, _dir) = desktop_api("desktop-badpeer", desktop_on(900));
    let (status, _) = send(
        &api,
        "POST",
        "/api/desktop/ticket",
        r#"{"want":["desktop.view"],"peer":"Not A Node"}"#,
    )
    .await;
    assert_eq!(status, 400);
}

/// The console origin the desktop upgrade tests speak for.
///
/// A browser always sends `Origin` on a handshake, so its absence from a cookie
/// caller is refused — which means every handshake test has to send one, and the
/// API has to have been told what its own is.
const DESKTOP_RP: &str = "console.example.com";

/// A handshake head carrying a ticket, a cookie and the console's own origin.
fn handshake(target: &str, ticket: &str, cookie: &str) -> Request {
    let raw = format!(
        "GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: AAAAAAAAAAAAAAAAAAAAAA==\r\n\
         Sec-WebSocket-Protocol: selfhost.desktop.1, tkt.{ticket}\r\n\
         Origin: https://{DESKTOP_RP}\r\n\
         Cookie: {cookie}\r\n\r\n"
    );
    Request::parse(raw.as_bytes()).expect("a well-formed handshake").request
}

/// A desktop configuration with the clipboard switched on as well.
fn desktop_with_clipboard(window: u64) -> selfhost_config::Desktop {
    selfhost_config::Desktop { allow_clipboard: true, ..desktop_on(window) }
}

/// Logs in over a cookie against a deployment whose desktop is `config`.
async fn desktop_console(name: &str, config: selfhost_config::Desktop) -> (Api, String, ScratchDir) {
    let (api, dir) = desktop_api(name, config);
    ConsolePassword::write(dir.path(), PASSWORD).expect("password written");
    let api = api
        .with_console_auth_parts(ConsolePassword::load(dir.path()), Sessions::new())
        .with_console_origin(DESKTOP_RP);
    let cookie = login(&api).await;
    (api, cookie, dir)
}

/// Asks for a ticket over a cookie, with the CSRF header the mint demands.
async fn mint(api: &Api, cookie: &str, body: &str) -> Response {
    call_with(
        api,
        "POST",
        "/api/desktop/ticket",
        &[("Cookie", cookie), ("X-Selfhost-Console", "1")],
        body,
    )
    .await
}

#[tokio::test]
async fn the_clipboard_is_a_capability_of_its_own_and_is_off_until_the_operator_says_otherwise() {
    // Seeing a screen and taking what was last copied on it are different
    // powers: the second exfiltrates a password the person at the machine
    // copied, leaving none of the evidence that watching a screen leaves.
    let (api, cookie, _dir) = desktop_console("desktop-clipboard-off", desktop_on(900)).await;
    let refused = mint(&api, &cookie, r#"{"want":["desktop.clipboard"],"peer":"self"}"#).await;
    assert_eq!(refused.status.code(), 403, "{:?}", body_json(&refused));
    assert_eq!(
        body_json(&refused).get("setting").and_then(Json::as_str),
        Some("[desktop].allow_clipboard"),
        "the console has to be able to say which switch, in a file, is off"
    );
    // Watching the same machine is unaffected: this is one capability, not a
    // mode the whole subsystem is in.
    let watching = mint(&api, &cookie, r#"{"want":["desktop.view"],"peer":"self"}"#).await;
    assert_eq!(watching.status.code(), 200, "{:?}", body_json(&watching));

    let (armed, cookie, _dir) =
        desktop_console("desktop-clipboard-on", desktop_with_clipboard(900)).await;
    let minted = mint(&armed, &cookie, r#"{"want":["desktop.clipboard"],"peer":"self"}"#).await;
    assert_eq!(minted.status.code(), 200, "{:?}", body_json(&minted));
    let ticket =
        body_json(&minted).get("ticket").and_then(Json::as_str).expect("a ticket").to_owned();

    // The clipboard travels on the desktop stream, so the ticket carries view
    // as well — a stream that may read a clipboard but not see a screen is a
    // stream whose only purpose is exfiltration, and the wire refuses that set.
    let redeemed = armed
        .upgrade_for(
            &handshake("/api/desktop/session?peer=self", &ticket, &cookie),
            selfhost_admin::Ability::DesktopView(NodeName::parse("self").expect("a legal node")),
        )
        .expect("the ticket opens the machine it named");
    assert!(
        redeemed
            .abilities
            .iter()
            .any(|a| matches!(a, selfhost_admin::Ability::ClipboardRead(_))),
        "the clipboard was asked for and is carried: {:?}",
        redeemed.abilities
    );
}

#[tokio::test]
async fn the_clipboard_is_held_to_the_same_freshness_standard_as_a_keyboard() {
    // A keyboard types a password out of the operator; a clipboard reads one
    // they already copied. The window is zero, so every login is already stale.
    let (api, cookie, _dir) =
        desktop_console("desktop-clipboard-stale", desktop_with_clipboard(0)).await;
    let refused = mint(&api, &cookie, r#"{"want":["desktop.clipboard"],"peer":"self"}"#).await;
    assert_eq!(refused.status.code(), 403, "{:?}", body_json(&refused));
    assert_eq!(
        body_json(&refused).get("reauthenticate").and_then(Json::as_bool),
        Some(true)
    );
}

#[tokio::test]
async fn a_deployment_that_does_not_allow_input_refuses_a_control_ticket_naming_the_switch() {
    // `[desktop].allow_input = false` is the outermost of the three gates and
    // the only one that cannot be reached from the console at all.
    let no_input = selfhost_config::Desktop {
        enabled: true,
        allow_input: false,
        reauth_window_secs: 900,
        ..selfhost_config::Desktop::default()
    };
    let (api, cookie, _dir) = desktop_console("desktop-no-input", no_input).await;
    let refused = mint(&api, &cookie, r#"{"want":["desktop.control"],"peer":"self"}"#).await;
    assert_eq!(refused.status.code(), 403, "{:?}", body_json(&refused));
    assert_eq!(
        body_json(&refused).get("setting").and_then(Json::as_str),
        Some("[desktop].allow_input")
    );
    let watching = mint(&api, &cookie, r#"{"want":["desktop.view"],"peer":"self"}"#).await;
    assert_eq!(watching.status.code(), 200, "{:?}", body_json(&watching));
}

/// Writes one audit record, as the daemon's own writer would.
fn record_action(log: &selfhost_identity::AuditLog, detail: &str) {
    let record = selfhost_identity::AuditRecord::now(
        selfhost_identity::Identity::Owner,
        selfhost_identity::Credential::Passkey,
        selfhost_identity::Capability::DesktopControl(
            NodeName::parse("self").expect("a legal node"),
        ),
        selfhost_identity::Decision::Allow,
        detail,
    )
    .expect("entropy");
    log.append(&record).expect("the log is writable");
}

#[tokio::test]
async fn the_audit_trail_reaches_the_console_newest_first() {
    // An audit trail an operator cannot read is an audit trail nobody checks,
    // and the person who needs it most is looking at a browser rather than at a
    // shell on the box.
    let (api, dir) = api("audit-trail");
    let log = selfhost_identity::AuditLog::in_dir(dir.path());
    for index in 0..5 {
        record_action(&log, &format!("keydown:0x{index:02x}"));
    }
    let api = api.with_audit(log);

    let (status, body) = send(&api, "GET", "/api/audit", "").await;
    assert_eq!(status, 200, "{body:?}");
    let records = body.get("records").and_then(Json::as_array).expect("a records array");
    assert_eq!(records.len(), 5);
    assert_eq!(
        records[0].get("detail").and_then(Json::as_str),
        Some("keydown:0x04"),
        "newest first is the order a tail is read in"
    );
    assert_eq!(records[0].get("capability").and_then(Json::as_str), Some("desktop.control"));
    assert_eq!(records[0].get("target").and_then(Json::as_str), Some("self"));
    assert_eq!(records[0].get("who").and_then(Json::as_str), Some("owner"));
    assert_eq!(records[0].get("credential").and_then(Json::as_str), Some("passkey"));
    assert_eq!(body.get("unreadable").and_then(Json::as_f64), Some(0.0));

    // The caller may ask for less, and may not ask for more than the ceiling.
    let (_, fewer) = send(&api, "GET", "/api/audit?limit=2", "").await;
    assert_eq!(fewer.get("returned").and_then(Json::as_f64), Some(2.0));
    let (_, capped) = send(&api, "GET", "/api/audit?limit=100000", "").await;
    assert_eq!(capped.get("returned").and_then(Json::as_f64), Some(5.0));
}

#[tokio::test]
async fn a_deployment_that_has_recorded_nothing_answers_with_an_empty_trail() {
    // Not a 404: the console asks this on every refresh, and "there is no audit
    // here" is a different and wrong thing to show an operator.
    let (api, dir) = api("audit-empty");
    let api = api.with_audit(selfhost_identity::AuditLog::in_dir(dir.path()));
    let (status, body) = send(&api, "GET", "/api/audit", "").await;
    assert_eq!(status, 200);
    assert_eq!(body.get("returned").and_then(Json::as_f64), Some(0.0));
}

#[tokio::test]
async fn the_trail_is_the_owners_and_a_granted_person_cannot_read_it() {
    // There is no capability that honestly says "may read the record of
    // everybody else", and a person who could be granted one could watch the
    // record of their own supervision.
    let (api, dir) = api("audit-owner-only");
    let log = selfhost_identity::AuditLog::in_dir(dir.path());
    record_action(&log, "keydown:0x04");
    ConsolePassword::write(dir.path(), PASSWORD).expect("password written");
    let sessions = Sessions::new();
    let people = selfhost_identity::People::load(dir.path());
    let mut grants = selfhost_identity::Grants::none();
    grants.grant(selfhost_identity::Capability::ConsoleRead).expect("room for one grant");
    grants
        .grant(selfhost_identity::Capability::DesktopControl(
            NodeName::parse("self").expect("a legal node"),
        ))
        .expect("room for one grant");
    people
        .set_grants(&PersonName::parse("Mom").expect("a legal name"), grants)
        .expect("grants are written");
    let id = sessions.create("Mom", Opening::Passkey).expect("a session");
    let api = api
        .with_console_auth_parts(ConsolePassword::load(dir.path()), sessions)
        .with_people(people)
        .with_audit(log);

    let refused =
        call_with(&api, "GET", "/api/audit", &[("Cookie", &format!("selfhost_session={id}"))], "")
            .await;
    assert_eq!(refused.status.code(), 401);
    // The owner's own credential reads it.
    let (status, _) = send(&api, "GET", "/api/audit", "").await;
    assert_eq!(status, 200);
}

// ─── The people plane ─────────────────────────────────────────────────────────
//
// The seam that turns `crates/identity`'s permission model from a description
// into something an operator can actually use: three owner-only routes that
// read and write the registry, and one route that answers any admitted caller
// the question a permission-shaped interface has to ask first.

#[tokio::test]
async fn whoami_answers_a_person_who_holds_nothing_rather_than_refusing_them() {
    // The whole reason this route is not owner-only. A client cannot draw only
    // the screens a person may use until it can ask what they may use, and a
    // person holding nothing must get an honest empty answer — otherwise "you
    // were refused" and "you hold nothing yet" are the same event to the one
    // program that could tell them apart.
    let sessions = Sessions::new();
    let (api, dir) = console_api("whoami-empty", sessions.clone());
    let people = People::load(dir.path());
    people
        .set_grants(&PersonName::parse("Mom").expect("a legal name"), Grants::none())
        .expect("grants are written");
    let api = api.with_people(people);
    let id = sessions.create("Mom", Opening::Passkey).expect("a session");
    let cookie = format!("selfhost_session={id}");

    let answered = call_with(&api, "GET", "/api/whoami", &[("Cookie", &cookie)], "").await;
    assert_eq!(answered.status.code(), 200);
    let body = body_json(&answered);
    assert_eq!(body.get("name").and_then(Json::as_str), Some("Mom"));
    assert_eq!(body.get("owner").and_then(Json::as_bool), Some(false));
    assert_eq!(body.get("grants").and_then(Json::as_array).map(<[Json]>::len), Some(0));

    // And an anonymous caller still gets nothing at all: the route is behind
    // the wall, it is only not behind a capability.
    let anonymous = call_with(&api, "GET", "/api/whoami", &[], "").await;
    assert_eq!(anonymous.status.code(), 401);
}

#[tokio::test]
async fn whoami_names_what_a_person_holds_in_the_words_a_grant_editor_submits_back() {
    let sessions = Sessions::new();
    let (api, dir) = console_api("whoami-grants", sessions.clone());
    let people = People::load(dir.path());
    let mut grants = Grants::none();
    grants.grant(Capability::ConsoleRead).expect("room for one grant");
    grants
        .grant(Capability::DesktopView(NodeName::parse("alex-desktop").expect("a legal node")))
        .expect("room for one grant");
    people.set_grants(&PersonName::parse("Mom").expect("a legal name"), grants).expect("written");
    let api = api.with_people(people);
    let id = sessions.create("Mom", Opening::Passkey).expect("a session");
    let cookie = format!("selfhost_session={id}");

    let answered = call_with(&api, "GET", "/api/whoami", &[("Cookie", &cookie)], "").await;
    let answers = body_json(&answered);
    let held: Vec<&str> = answers
        .get("grants")
        .and_then(Json::as_array)
        .expect("a grants array")
        .iter()
        .filter_map(Json::as_str)
        .collect();
    assert!(held.contains(&"console.read"));
    // The target travels with the word, because a client that dropped it would
    // be showing a person a machine they may not watch.
    assert!(held.contains(&"desktop.view:alex-desktop"), "{held:?}");
}

#[tokio::test]
async fn the_owner_reads_the_roster_and_a_person_who_may_read_the_console_cannot() {
    // Reading the roster is reading a list of who can reach what — a target
    // list, as the registry says in its own header — so it is owner-only even
    // for somebody the console otherwise admits.
    let sessions = Sessions::new();
    let (api, dir) = console_api("people-roster", sessions.clone());
    let people = People::load(dir.path());
    let mut grants = Grants::none();
    grants.grant(Capability::ConsoleRead).expect("room for one grant");
    people.set_grants(&PersonName::parse("Mom").expect("a legal name"), grants).expect("written");
    let api = api.with_people(people);
    let id = sessions.create("Mom", Opening::Passkey).expect("a session");
    let cookie = format!("selfhost_session={id}");

    let refused = call_with(&api, "GET", "/api/people", &[("Cookie", &cookie)], "").await;
    let anonymous = call_with(&api, "GET", "/api/people", &[], "").await;
    assert_eq!(refused.status.code(), 401);
    assert_eq!(body_json(&refused).to_text(), body_json(&anonymous).to_text());

    // The owner's own credential reads it, and sees the one entry. The bearer
    // token is not that credential any more: it names the machine, and reading
    // a list of who can reach what is not the machine's business.
    let (refused, _) = call(&api, "GET", "/api/people", Some(TOKEN), "").await;
    assert_eq!(refused, 401, "the box's own token is not the operator");
    let (status, body) = as_owner(&api, "GET", "/api/people", "").await;
    assert_eq!(status, 200);
    let listed = body.get("people").and_then(Json::as_array).expect("a people array");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].get("name").and_then(Json::as_str), Some("Mom"));
}

#[tokio::test]
async fn a_grant_written_through_the_api_is_the_grant_the_policy_then_enforces() {
    // The end of the seam: a permission set through the route is not a record
    // in a file, it is a power the next request actually has.
    let sessions = Sessions::new();
    let (api, dir) = console_api("people-write", sessions.clone());
    let api = api.with_people(People::load(dir.path()));

    let (status, body) =
        as_owner(&api, "PUT", "/api/people/mom", r#"{"grants":["console.read","mail.admin"]}"#).await;
    assert_eq!(status, 200, "{body:?}");
    assert_eq!(body.get("name").and_then(Json::as_str), Some("mom"));

    // Read back through the person's own credential, which is the only proof
    // that matters: the daemon resolved the session to those capabilities.
    let id = sessions.create("mom", Opening::Passkey).expect("a session");
    let cookie = format!("selfhost_session={id}");
    let answered = call_with(&api, "GET", "/api/whoami", &[("Cookie", &cookie)], "").await;
    let answers = body_json(&answered);
    let held: Vec<&str> = answers
        .get("grants")
        .and_then(Json::as_array)
        .expect("a grants array")
        .iter()
        .filter_map(Json::as_str)
        .collect();
    assert_eq!(held, ["console.read", "mail.admin"]);

    // And it is a whole-set write: submitting a smaller set takes the rest away
    // rather than adding to it.
    let (status, _) = as_owner(&api, "PUT", "/api/people/mom", r#"{"grants":["console.read"]}"#).await;
    assert_eq!(status, 200);
    let (status, body) = as_owner(&api, "GET", "/api/people", "").await;
    assert_eq!(status, 200);
    let listed = body.get("people").and_then(Json::as_array).expect("a people array");
    let grants = listed[0].get("grants").and_then(Json::as_array).expect("a grants array");
    assert_eq!(grants.len(), 1, "the set was replaced, not merged");
}

#[tokio::test]
async fn a_permission_change_that_does_not_parse_changes_nothing() {
    let (api, dir) = console_api("people-atomic", Sessions::new());
    let api = api.with_people(People::load(dir.path()));
    as_owner(&api, "PUT", "/api/people/mom", r#"{"grants":["console.read"]}"#).await;

    // One unknown word in an otherwise good set. The failure this prevents is a
    // set applied minus the entry that did not parse.
    let (status, body) =
        as_owner(&api, "PUT", "/api/people/mom", r#"{"grants":["service.control","files.read"]}"#).await;
    assert_eq!(status, 400);
    assert!(
        body.get("error").and_then(Json::as_str).unwrap_or_default().contains("files.read"),
        "the refusal names the word that was wrong: {body:?}"
    );

    let (_, body) = as_owner(&api, "GET", "/api/people", "").await;
    let listed = body.get("people").and_then(Json::as_array).expect("a people array");
    let grants = listed[0].get("grants").and_then(Json::as_array).expect("a grants array");
    assert_eq!(grants.len(), 1, "the previous set is untouched");
    assert_eq!(grants[0].as_str(), Some("console.read"));
}

#[tokio::test]
async fn the_owner_cannot_be_written_into_the_registry_as_a_person() {
    // The property everything else rests on: no request to this API can create
    // an entry that edits the operator's own authority, because the owner's
    // authority is an identity and `PersonName` refuses that spelling.
    let (api, dir) = console_api("people-owner", Sessions::new());
    let api = api.with_people(People::load(dir.path()));
    // `machine` joins the list: the bearer token now has an identity of its own,
    // and a person able to spell it would authenticate into the box's own.
    for name in ["owner", "OWNER", "Owner", "machine", "MACHINE", "Machine"] {
        let (status, _) =
            as_owner(&api, "PUT", &format!("/api/people/{name}"), r#"{"grants":[]}"#).await;
        assert_eq!(status, 400, "{name} was accepted as a person");
    }
}

#[tokio::test]
async fn forgetting_a_person_is_reported_separately_from_never_having_known_them() {
    let (api, dir) = console_api("people-forget", Sessions::new());
    let api = api.with_people(People::load(dir.path()));
    as_owner(&api, "PUT", "/api/people/mom", r#"{"grants":["console.read"]}"#).await;

    let (status, _) = as_owner(&api, "DELETE", "/api/people/mom", "").await;
    assert_eq!(status, 200);
    let (status, _) = as_owner(&api, "DELETE", "/api/people/mom", "").await;
    assert_eq!(status, 404, "gone and never-there are different facts");
}

/// A minimal, valid `selfhost.config.toml` text — the same shape
/// [`firewall_manager`] parses, written to disk so `site_api`'s handlers have
/// a real file to read and rewrite.
const MINIMAL_CONFIG: &str = "version = 1\n\
     [server]\n\
     http_bind = \"127.0.0.1:8080\"\n\
     https_bind = \"127.0.0.1:8443\"\n\
     acme_email = \"a@b.com\"\n\
     acme = \"self-signed\"\n\
     data_dir = \"./data\"\n\
     [[nodes]]\n\
     name = \"home\"\n\
     role = \"owner\"\n";

/// An API wired for site administration: a real config file on disk, plus the
/// agent store and site-admin door open over the same scratch directory.
fn site_admin_api(name: &str) -> (Api, ScratchDir, std::path::PathBuf) {
    let (api, dir) = api(name);
    let config_path = dir.path().join("selfhost.config.toml");
    std::fs::write(&config_path, MINIMAL_CONFIG).expect("writes a starter config");
    let api = api.with_agents(dir.path()).with_site_admin(config_path.clone(), dir.path().to_path_buf());
    (api, dir, config_path)
}

/// Mints an agent holding exactly `capabilities` and returns its whole token.
fn mint_agent(
    dir: &std::path::Path,
    name: &str,
    capabilities: Vec<selfhost_identity::Capability>,
) -> String {
    let store = selfhost_admin::agent_store::AgentStore::in_dir(dir);
    let agent_name = selfhost_identity::AgentName::parse(name).expect("a valid agent name");
    let grants = selfhost_identity::Grants::new(capabilities).expect("under the grant cap");
    store.mint(&agent_name, grants).expect("mints").as_str().to_owned()
}

/// The security property this whole feature exists for: an agent token
/// scoped to `site.admin` can create a site over the API, the plain
/// deployment bearer token cannot (it is `Identity::Machine`, and
/// `Policy::decide`'s fixed list withholds `SiteAdmin` from it — see
/// `selfhost_identity::policy`), an unauthenticated request cannot, and a
/// revoked agent's token stops working immediately.
#[tokio::test]
async fn only_a_scoped_agent_token_may_administer_sites() {
    let (api, dir, config_path) = site_admin_api("sites-agent-only");
    let agent_token = mint_agent(dir.path(), "claude-mac", vec![selfhost_identity::Capability::SiteAdmin]);

    let add_body = r#"{"name":"blog","domains":["blog.example.com"],"static":true}"#;

    // No credential at all: the ordinary uninformative 401.
    let (status, _) = call(&api, "POST", "/api/sites", None, add_body).await;
    assert_eq!(status, 401);

    // The deployment's own bearer token: `Identity::Machine`'s fixed list
    // withholds `SiteAdmin` — this must still be refused even though the
    // token opens most of the rest of this API.
    let (status, _) = call(&api, "POST", "/api/sites", Some(TOKEN), add_body).await;
    assert_eq!(status, 401, "the bearer token must never reach SiteAdmin");

    // The scoped agent token: succeeds, and the config file actually gained
    // the site.
    let (status, body) = call(&api, "POST", "/api/sites", Some(&agent_token), add_body).await;
    assert_eq!(status, 200, "{body:?}");
    let written = std::fs::read_to_string(&config_path).expect("reads the config back");
    assert!(written.contains("blog.example.com"), "{written}");

    // Listing and showing the site over the same agent token both see it.
    let (status, listed) = call(&api, "GET", "/api/sites", Some(&agent_token), "").await;
    assert_eq!(status, 200);
    assert_eq!(listed.get("count").and_then(Json::as_u64), Some(1));
    let (status, _) = call(&api, "GET", "/api/sites/blog", Some(&agent_token), "").await;
    assert_eq!(status, 200);

    // Revoked: the very next request with the same token is refused, with
    // nothing to restart.
    let store = selfhost_admin::agent_store::AgentStore::in_dir(dir.path());
    let agent_name = selfhost_identity::AgentName::parse("claude-mac").unwrap();
    assert!(store.revoke(&agent_name).expect("revokes"));
    let (status, _) = call(&api, "GET", "/api/sites", Some(&agent_token), "").await;
    assert_eq!(status, 401, "a revoked agent's token must stop working immediately");
}

/// An agent granted a capability *other* than `SiteAdmin` still cannot reach
/// `/api/sites` — the grant model is exact, not "any agent token opens the
/// site door".
#[tokio::test]
async fn an_agent_without_site_admin_is_refused_the_site_routes() {
    let (api, dir, _config_path) = site_admin_api("sites-agent-scoped");
    let narrow_token = mint_agent(dir.path(), "narrow", vec![selfhost_identity::Capability::ConsoleRead]);

    let (status, _) = call(&api, "GET", "/api/sites", Some(&narrow_token), "").await;
    assert_eq!(status, 401, "console.read must not open the site door");
}

/// A caller over this API can never choose an arbitrary filesystem path for a
/// site's static content — only `static: true`, which the server answers with
/// its own managed directory. See `site_api`'s module documentation.
#[tokio::test]
async fn a_remote_caller_cannot_name_an_arbitrary_static_root() {
    let (api, dir, _config_path) = site_admin_api("sites-no-arbitrary-path");
    let agent_token = mint_agent(dir.path(), "claude-mac", vec![selfhost_identity::Capability::SiteAdmin]);

    // The wire shape has no field for a path at all — `static` is a boolean —
    // so the only way to ask for content is the managed directory. Confirm a
    // request that tries to smuggle one in through an unrecognised field is
    // simply ignored rather than honoured.
    let body = r#"{"name":"evil","domains":["evil.example.com"],"static":true,"staticRoot":"/etc"}"#;
    let (status, response) = call(&api, "POST", "/api/sites", Some(&agent_token), body).await;
    assert_eq!(status, 200, "{response:?}");
    let (status, show) = call(&api, "GET", "/api/sites/evil", Some(&agent_token), "").await;
    assert_eq!(status, 200);
    assert_eq!(show.get("hasStaticContent").and_then(Json::as_bool), Some(true));
    // The managed root lives under the scratch data directory, never `/etc`.
    let managed_root = dir.path().join("sites").join("evil");
    assert!(managed_root.is_dir(), "the server allocated its own content directory");
}

/// Uploading, listing and deleting a file in a site's managed content, all
/// through the safe `selfhost_storage::fs::Dir`/`Upload` primitives — and a
/// traversal attempt on the same routes is refused.
#[tokio::test]
async fn site_files_round_trip_and_traversal_is_refused() {
    let (api, dir, _config_path) = site_admin_api("sites-files");
    let agent_token = mint_agent(dir.path(), "claude-mac", vec![selfhost_identity::Capability::SiteAdmin]);
    call(
        &api,
        "POST",
        "/api/sites",
        Some(&agent_token),
        r#"{"name":"blog","domains":["blog.example.com"],"static":true}"#,
    )
    .await;

    let (status, _) =
        call(&api, "PUT", "/api/sites/blog/files/entry?path=index.html", Some(&agent_token), "<h1>hi</h1>").await;
    assert_eq!(status, 200);

    let (status, listing) = call(&api, "GET", "/api/sites/blog/files/list", Some(&agent_token), "").await;
    assert_eq!(status, 200);
    let entries = listing.as_array().expect("a JSON array");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].get("name").and_then(Json::as_str), Some("index.html"));

    let (status, _) =
        call(&api, "DELETE", "/api/sites/blog/files/entry?path=index.html", Some(&agent_token), "").await;
    assert_eq!(status, 200);
    let (status, listing) = call(&api, "GET", "/api/sites/blog/files/list", Some(&agent_token), "").await;
    assert_eq!(status, 200);
    assert_eq!(listing.as_array().expect("a JSON array").len(), 0);

    // A traversal attempt: refused by the same resolver every share route
    // already relies on, never a write outside the managed directory.
    let (status, _) = call(
        &api,
        "PUT",
        "/api/sites/blog/files/entry?path=../../etc/passwd",
        Some(&agent_token),
        "pwned",
    )
    .await;
    assert_eq!(status, 400, "a traversal attempt must be refused, not resolved");
    assert!(!dir.path().join("etc").exists(), "nothing was written outside the managed directory");
}
