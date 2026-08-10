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

    let (status, _) =
        call(&api, "DELETE", &format!("/api/webauthn/credentials/{id}"), Some(TOKEN), "").await;
    assert_eq!(status, 200);
    let (status, _) =
        call(&api, "DELETE", &format!("/api/webauthn/credentials/{id}"), Some(TOKEN), "").await;
    assert_eq!(status, 404, "revoking twice names the absence");

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
    let (status, body) = send(&api, "GET", "/api/storage/shares/vault/list?path=", "").await;
    assert_eq!(status, 404, "{body:?}");
    let (status, body) = send(&api, "GET", "/api/storage/shares", "").await;
    assert_eq!(status, 401, "with no storage wired there is no set to answer with: {body:?}");
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
