//! Route and authorisation behaviour of the control API.
//!
//! Driven through [`Api::handle`] rather than a socket, so every route — and
//! every way of getting authorisation wrong — is exercised without binding a
//! port. The socket layer is tested separately in `wire.rs`.

use selfhost_admin::{Api, Store, Token};
use selfhost_http::{Body, Request, Response};
use selfhost_json::Json;
use selfhost_supervisor::Supervisor;

const TOKEN: &str = "0123456789abcdef";

/// An API over a scratch directory, plus the directory that cleans it up.
fn api(name: &str) -> (Api, ScratchDir) {
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

/// Builds a request, parsing it the same way the server would.
fn request(method: &str, target: &str, auth: Option<&str>, body: &str) -> (Request, Vec<u8>) {
    let mut text = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    if let Some(token) = auth {
        text.push_str(&format!("Authorization: Bearer {token}\r\n"));
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
    ] {
        let (status, _) = call(&api, method, target, None, "").await;
        assert_eq!(status, 401, "{method} {target} should require a token");
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

/// A scratch directory that removes itself when dropped.
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
