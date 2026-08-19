//! `--remote <host>` — asking *another* box's admin API from this command line.
//!
//! A console site's proxy relays `/api/*` to that box's loopback admin API and
//! forwards the caller's own `Authorization` header verbatim
//! ([`selfhost_proxy::upgrade::RELAYED`]), so a bearer token presented over
//! HTTPS here reaches the admin API on the far side without anything in between
//! having to hold a credential. That relay is the whole mechanism; this module
//! is an HTTPS client for it and nothing more.
//!
//! Four rules shape it, and each one is a failure mode that has to be impossible
//! rather than merely unlikely:
//!
//! * **A command with no remote implementation fails, loudly.** This is the
//!   dangerous one. An operator who typed `--remote alex-desktop` and got the
//!   *local* machine acted on instead has been lied to at the moment they were
//!   most careful, and the damage — a service restarted, a tree redeployed — is
//!   done on the wrong machine before anything prints. So the routing is a
//!   closed match over the commands that are actually implemented ([`plan`]),
//!   and everything else is an error and a non-zero exit. There is deliberately
//!   no fall-through arm.
//! * **`--remote <host>` itself stays read-only.** [`plan`] — the closed set
//!   `--remote` drives — only ever calls [`RemoteClient::get`], so nothing
//!   reachable through the global `--remote` flag can mutate the far side.
//!   [`RemoteClient::request`] can send any method with a body, but it is
//!   deliberately **not** wired into [`plan`]/[`run`] at all: `selfhost mcp`
//!   (`crate::mcp_command`) is the one caller, it takes its own `--host` flag
//!   rather than the global `--remote` (so a long-running stdio server is
//!   never confused with a one-shot read-only query), and it authenticates
//!   with a scoped **agent** token rather than the deployment's bearer token —
//!   see that module for why an unattended process gets a bounded credential
//!   instead of the root one.
//! * **HTTPS only.** `http://` is refused by [`Remote::parse`] rather than
//!   upgraded, because the request carries a bearer token that is the whole of
//!   this deployment's authority: sending it in clear once is a compromise, and
//!   a silent upgrade would hide that the operator asked for it. The
//!   certificate is verified against the bundled Mozilla roots with no
//!   accept-any path, the same policy `mesh_task`'s dialler holds to.
//! * **The token never comes from `argv`.** Command lines are readable by every
//!   process on the machine through `ps` and land in shell history, so the token
//!   is read from `SELFHOST_TOKEN` or `~/.selfhost/token` and there is no flag
//!   that would accept one.

use selfhost_config::ServiceCatalog;
use selfhost_http::{IncomingResponse, ResponseFraming};
use selfhost_json::Json;
use selfhost_supervisor::state::{ServiceStatus, spec_from_json, start_mode_name};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The token file consulted when `SELFHOST_TOKEN` is not set.
const TOKEN_FILE: &str = ".selfhost/token";

/// How long to wait for the far side to accept a connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long one request may take, handshake to last byte.
///
/// Generous because this crosses the internet and may cross a VPN as well, but
/// bounded: every answer these commands ask for is a small JSON document, so a
/// request still running after this is a wedged link, not a slow one.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The most of an answer this will hold in memory.
///
/// The far side is authenticated but not trusted to be well behaved — a proxy
/// in front of it, or a bug behind it, can send more than was asked for — and a
/// command-line tool that grows without bound because the peer keeps writing is
/// a denial of service on the operator's own machine.
const MAX_ANSWER: usize = 1024 * 1024;

/// A host named by `--remote`, already checked for the things that would make it
/// unsafe to put in a request line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    host: String,
    port: u16,
}

impl Remote {
    /// Reads `example.com`, `example.com:8443` or `https://example.com`.
    ///
    /// Everything this rejects, it rejects because the value is about to be
    /// written into a request line and a `Host` field: a path or a query would
    /// silently replace the path the command chose, embedded credentials would
    /// put a password on the command line (the thing this module exists to
    /// avoid), and whitespace or a control character is header injection. An
    /// `http://` scheme is refused rather than upgraded — see the module note.
    pub fn parse(given: &str) -> Result<Self, String> {
        let trimmed = given.trim();
        if trimmed.is_empty() {
            return Err("--remote needs a hostname, for example: --remote admin.example.com".into());
        }

        let rest = match trimmed.split_once("://") {
            Some(("https", rest)) => rest,
            Some(("http", _)) => {
                return Err(format!(
                    "--remote {trimmed} is plain HTTP, which would send this deployment's bearer \
                     token in clear. Name the host over HTTPS: --remote {}",
                    trimmed.trim_start_matches("http://")
                ));
            }
            Some((scheme, _)) => {
                return Err(format!("--remote {trimmed}: {scheme}:// is not a scheme this speaks"));
            }
            None => trimmed,
        };

        if rest.contains('@') {
            return Err(format!(
                "--remote {trimmed} carries credentials in the host. The bearer token is read \
                 from SELFHOST_TOKEN or ~/{TOKEN_FILE}, never from the command line"
            ));
        }
        if rest.contains('/') || rest.contains('?') || rest.contains('#') {
            return Err(format!(
                "--remote {trimmed}: name only the host, not a path — the path is the command's \
                 to choose"
            ));
        }

        let (host, port) = match rest.rsplit_once(':') {
            Some((host, port)) => {
                let port: u16 = port
                    .parse()
                    .map_err(|_| format!("--remote {trimmed}: {port} is not a port number"))?;
                if port == 0 {
                    return Err(format!("--remote {trimmed}: port 0 is not a port to dial"));
                }
                (host, port)
            }
            None => (rest, 443),
        };

        if host.is_empty() {
            return Err(format!("--remote {trimmed} names a port but no host"));
        }
        if host.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err(format!("--remote {trimmed}: a hostname cannot contain spaces or control characters"));
        }

        Ok(Self { host: host.to_owned(), port })
    }

    /// The `Host` field, which carries the port only when it is not the default.
    fn authority(&self) -> String {
        if self.port == 443 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl std::fmt::Display for Remote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "https://{}", self.authority())
    }
}

/// Takes `--remote <host>` out of the arguments, leaving the command behind.
///
/// A global option rather than a per-command flag because the question it
/// answers — *which machine* — is asked of every command, including the ones
/// with no remote implementation, which have to be able to refuse rather than
/// see an argument they do not recognise and carry on locally.
///
/// Pure, and returning a new vector rather than mutating in place, so the
/// parsing can be exercised without a process.
pub fn split(arguments: Vec<String>) -> Result<(Vec<String>, Option<Remote>), String> {
    let mut kept = Vec::with_capacity(arguments.len());
    let mut remote: Option<Remote> = None;
    let mut waiting = false;

    for argument in arguments {
        if waiting {
            waiting = false;
            remote = Some(claim(remote, Remote::parse(&argument)?)?);
            continue;
        }
        if argument == "--remote" {
            waiting = true;
            continue;
        }
        if let Some(value) = argument.strip_prefix("--remote=") {
            remote = Some(claim(remote, Remote::parse(value)?)?);
            continue;
        }
        kept.push(argument);
    }

    if waiting {
        return Err("--remote needs a hostname, for example: --remote admin.example.com".into());
    }
    Ok((kept, remote))
}

/// Refuses a second `--remote`.
///
/// Two of them would leave the choice of machine to argument order, and the
/// cost of guessing wrong is acting on the machine the operator did not mean.
fn claim(existing: Option<Remote>, given: Remote) -> Result<Remote, String> {
    match existing {
        Some(first) if first != given => {
            Err(format!("--remote was given twice ({first} and {given}); name one machine"))
        }
        _ => Ok(given),
    }
}

/// Reads the bearer token from `SELFHOST_TOKEN`, or from `~/.selfhost/token`.
///
/// The characters are checked because the value is written into an
/// `Authorization` field: a newline in it would let whatever produced the token
/// append header fields of its own choosing to every request this makes.
pub fn read_token() -> Result<String, String> {
    if let Ok(from_environment) = std::env::var("SELFHOST_TOKEN") {
        return usable(from_environment.trim(), "SELFHOST_TOKEN");
    }

    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map_err(|_| {
            format!(
                "no bearer token: SELFHOST_TOKEN is not set and this account has no home \
                 directory to read ~/{TOKEN_FILE} from"
            )
        })?;
    let path = std::path::Path::new(&home).join(TOKEN_FILE);

    let text = std::fs::read_to_string(&path).map_err(|error| {
        format!(
            "no bearer token: SELFHOST_TOKEN is not set and {} could not be read ({error}).\n  \
             Copy the far side's data/admin.token there, or export SELFHOST_TOKEN — never pass \
             it as an argument, where `ps` and the shell history would keep it",
            path.display()
        )
    })?;
    usable(text.trim(), &path.display().to_string())
}

/// Accepts a token only if every byte of it is safe in a header field.
///
/// Shared with the loopback deployment request in [`crate::app_command`] so
/// there is one answer to "may this go in an `Authorization` field" rather than
/// two that can drift — the daemon writes its own token file, but a file is
/// still a file and can be edited by hand.
pub fn usable(token: &str, source: &str) -> Result<String, String> {
    if token.is_empty() {
        return Err(format!("the bearer token in {source} is empty"));
    }
    if token.bytes().any(|b| !(0x21..=0x7e).contains(&b)) {
        return Err(format!(
            "the bearer token in {source} contains a space or a control character, which cannot \
             go in an Authorization field"
        ));
    }
    Ok(token.to_owned())
}

/// An authenticated, read-only HTTPS client for one far-side admin API.
pub struct RemoteClient {
    remote: Remote,
    token: String,
}

impl RemoteClient {
    /// Binds a token to a host. Both are already checked by their own parsers.
    pub fn new(remote: Remote, token: String) -> Self {
        Self { remote, token }
    }

    /// Asks the far side one question and hands back the answer's JSON.
    ///
    /// `GET` and no body — the shape every `--remote` command in this file
    /// uses. See [`RemoteClient::request`] for the general form the MCP server
    /// (`crate::mcp_command`) needs, which this is now a thin wrapper over.
    pub async fn get(&self, path: &str) -> Result<Json, String> {
        self.request("GET", path, None).await
    }

    /// Asks the far side one question, with a method and an optional body, and
    /// hands back the answer's JSON.
    ///
    /// The general form [`RemoteClient::get`] wraps. Unlike `get`, this is not
    /// restricted to read-only verbs — it is what `selfhost mcp` uses to reach
    /// `POST`/`PUT`/`DELETE` site-management routes on the far side, always
    /// authenticated with an **agent** token (see `crate::agent_command` and
    /// `selfhost_admin::agent_store`) rather than the deployment's own bearer
    /// token, so what this method can do on the far side is bounded by
    /// whatever that agent was granted — never by what this method itself
    /// permits. Every invariant [`RemoteClient::get`] held still holds: HTTPS
    /// only, the connection closed after one answer, a bounded read.
    pub async fn request(&self, method: &str, path: &str, body: Option<&[u8]>) -> Result<Json, String> {
        let name = rustls::pki_types::ServerName::try_from(self.remote.host.clone())
            .map_err(|_| format!("{} is not a usable server name for TLS", self.remote.host))?;
        let body = body.unwrap_or(&[]);
        // A file upload's body is orders of magnitude larger than any JSON
        // document, and the fixed deadline that suits a question does not suit
        // a transfer: allow one extra second per 256 KiB sent, so a site asset
        // crossing a tunnel is judged by how much is being sent rather than by
        // a constant chosen for reading service lists.
        let deadline = REQUEST_TIMEOUT + Duration::from_secs((body.len() / (256 * 1024)) as u64);

        // The bundled Mozilla roots and the `ring` provider named explicitly,
        // exactly as `mesh_task`'s dialler does it: what verifies the far side
        // should not depend on which subsystem happened to install a crypto
        // provider first, and reading the OS trust store would differ across the
        // three platforms this binary ships to.
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| format!("could not build the TLS client: {error}"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        let exchange = async {
            let tcp = tokio::time::timeout(
                CONNECT_TIMEOUT,
                TcpStream::connect((self.remote.host.as_str(), self.remote.port)),
            )
            .await
            .map_err(|_| format!("{} did not answer within {}s", self.remote, CONNECT_TIMEOUT.as_secs()))?
            .map_err(|error| format!("cannot reach {}: {error}", self.remote))?;

            let mut stream = connector
                .connect(name, tcp)
                .await
                .map_err(|error| format!("TLS to {} failed: {error}", self.remote))?;

            let request = format!(
                "{method} {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\n\
                 Accept: application/json\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                self.remote.authority(),
                self.token,
                body.len(),
            );
            stream
                .write_all(request.as_bytes())
                .await
                .map_err(|error| format!("cannot send to {}: {error}", self.remote))?;
            if !body.is_empty() {
                stream
                    .write_all(body)
                    .await
                    .map_err(|error| format!("cannot send to {}: {error}", self.remote))?;
            }

            let mut raw = Vec::new();
            let mut buffer = [0u8; 8192];
            loop {
                let read = stream
                    .read(&mut buffer)
                    .await
                    .map_err(|error| format!("the answer from {} stopped: {error}", self.remote))?;
                if read == 0 {
                    break;
                }
                raw.extend_from_slice(buffer.get(..read).unwrap_or_default());
                if raw.len() > MAX_ANSWER {
                    return Err(format!("{} sent more than this command will read", self.remote));
                }
                // Stop as soon as the framing says the body is complete, rather
                // than waiting for the close: a proxy that ignores
                // `Connection: close` and holds the connection open would
                // otherwise stall every command until the request timeout.
                if complete(&raw) {
                    break;
                }
            }
            Ok(raw)
        };

        let raw = tokio::time::timeout(deadline, exchange)
            .await
            .map_err(|_| {
                format!("{} did not finish answering within {}s", self.remote, deadline.as_secs())
            })??;

        answer(&raw)
    }
}

/// Whether these bytes already hold a whole response.
///
/// Framing is read with the workspace's own response parser rather than by
/// hunting for a blank line here: this crate does not get to have a second
/// opinion about where a body ends, which is precisely the disagreement request
/// smuggling lives in.
fn complete(raw: &[u8]) -> bool {
    let Ok(parsed) = IncomingResponse::parse(raw) else {
        return false;
    };
    let body = raw.len() - parsed.consumed;
    match parsed.response.framing {
        ResponseFraming::None => true,
        ResponseFraming::Fixed(length) => body as u64 >= length,
        // A chunked body ends with the zero-length chunk and its blank line;
        // anything short of that is still arriving.
        ResponseFraming::Chunked => raw.ends_with(b"0\r\n\r\n"),
        ResponseFraming::UntilClose => false,
    }
}

/// Turns one complete response into the JSON it carried, or into the far side's
/// own refusal.
///
/// The status is kept in the error rather than flattened into "it did not work",
/// because a 401 and a 404 send the operator to entirely different places: the
/// first is the wrong token against a working box, the second is a working token
/// against a box that does not serve that route.
fn answer(raw: &[u8]) -> Result<Json, String> {
    let parsed = IncomingResponse::parse(raw)
        .map_err(|error| format!("the answer is not a response this understands: {error}"))?;
    let body = raw.get(parsed.consumed..).unwrap_or_default();
    let body = match parsed.response.framing {
        ResponseFraming::Chunked => selfhost_http::dechunk(body)
            .map_err(|error| format!("the answer's chunked body is malformed: {error}"))?,
        _ => body.to_vec(),
    };
    let text = String::from_utf8_lossy(&body);
    let text = text.trim();
    let status = parsed.response.status;
    let value = selfhost_json::parse(text).ok();

    if (200..300).contains(&status.0) {
        // Only a success has to be JSON. A refusal is often a page — a proxy's
        // own error, a login form — and reporting "the body is not JSON" for one
        // would bury the status, which is the part that says what to do next.
        return match (text.is_empty(), value) {
            (true, _) => Ok(Json::Null),
            (false, Some(value)) => Ok(value),
            (false, None) => Err(format!(
                "{} {} — but the body is not JSON, so this is not the admin API answering",
                status.0,
                status.reason()
            )),
        };
    }
    let said = value
        .as_ref()
        .and_then(|value| value.get("error"))
        .and_then(Json::as_str)
        .unwrap_or(status.reason());
    Err(match status.0 {
        401 | 403 => format!(
            "{} {said} — the far side refused this token. Check SELFHOST_TOKEN (or ~/{TOKEN_FILE}) \
             against that box's data/admin.token",
            status.0
        ),
        // "does not serve that route" is the right reading only when the far
        // side said nothing — a bare 404 from a proxy or an old build. When
        // the admin API sent its own explanation ("no site named …", "this
        // site has no static content directory …"), that explanation *is* the
        // answer, and stamping a routing diagnosis over it sends the operator
        // hunting for a deployment problem that does not exist.
        404 if said == status.reason() => {
            format!("{} {said} — this box does not serve that route", status.0)
        }
        404 => format!("{} {said}", status.0),
        _ => format!("{} {said}", status.0),
    })
}

/// What a `--remote` run has been asked to do.
///
/// A closed set, listed once, so that adding a remote command is a deliberate
/// act and forgetting to add one cannot degrade into acting locally.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// Every service the far side's daemon is supervising.
    Services,
    /// The applications among them.
    AppList,
    /// One application's definition.
    AppShow(String),
}

/// Decides what a command means on a remote box, or refuses it.
///
/// Pure and separate from the socket so the refusal — the half that matters — is
/// testable without a network, and so it happens before a token is even read: an
/// operator who mistyped a command should be told that, not told their token is
/// missing.
fn plan(arguments: &[String]) -> Result<Plan, String> {
    let word = |at: usize| arguments.get(at).map(String::as_str);
    match (word(0), word(1)) {
        (Some("services"), _) => Ok(Plan::Services),
        (Some("app"), None | Some("list")) => Ok(Plan::AppList),
        (Some("app"), Some("show")) => match word(2) {
            Some(name) => Ok(Plan::AppShow(name.to_owned())),
            None => Err("app show needs an application name".into()),
        },
        (Some(command), _) => Err(refusal(command)),
        (None, _) => Err(refusal("(no command)")),
    }
}

/// Why a command stopped instead of running.
///
/// Phrased to make the alternative explicit — drop `--remote` and it runs here —
/// because the one thing this must never do is decide that for the operator.
fn refusal(command: &str) -> String {
    format!(
        "`{command}` has no remote implementation, so it was NOT run — neither there nor on this \
         machine.\n  --remote carries these, all read-only:\n    \
         services            every service the far side is supervising\n    \
         app list            its applications\n    \
         app show <name>     one application's definition\n  \
         Run it without --remote to act on this machine instead."
    )
}

/// Runs one command against a remote box.
///
/// The async work is bridged here with `block_on` rather than making `main`
/// async, which is this binary's established shape — see `doctor_command` and
/// the DNS commands.
pub fn run(arguments: &[String], remote: &Remote) -> Result<(), String> {
    let plan = plan(arguments)?;
    let client = RemoteClient::new(remote.clone(), read_token()?);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    runtime.block_on(carry_out(&client, &plan, remote, arguments))
}

/// Asks for what the plan needs and prints it.
async fn carry_out(
    client: &RemoteClient,
    plan: &Plan,
    remote: &Remote,
    arguments: &[String],
) -> Result<(), String> {
    match plan {
        Plan::Services => services(client, remote).await,
        Plan::AppList => {
            let catalog = applications(client).await?;
            println!("{remote}\n");
            crate::app_command::list(&catalog)
        }
        Plan::AppShow(name) => {
            let catalog = ServiceCatalog { version: 1, services: vec![describe(client, name).await?] };
            println!("{remote}\n");
            crate::app_command::show(arguments, &catalog, Some(&remote.authority()))
        }
    }
}

/// Prints the far side's service table.
///
/// The columns are not the local `services` command's, and deliberately so: this
/// answer comes from a *running* daemon, so it can say what each service is
/// actually doing, where the local command reads a catalogue file that knows
/// only what was installed.
async fn services(client: &RemoteClient, remote: &Remote) -> Result<(), String> {
    let statuses = statuses(client).await?;
    if statuses.is_empty() {
        println!("{remote} has no services installed");
        return Ok(());
    }

    let width = statuses.iter().map(|s| s.name.len()).max().unwrap_or(4).max(4);
    println!("{remote}\n");
    println!("  {:<width$}  {:<10}  STATE", "NAME", "START");
    for status in &statuses {
        println!(
            "  {:<width$}  {:<10}  {}",
            status.name,
            start_mode_name(status.start_mode),
            status.state.label()
        );
    }
    Ok(())
}

/// Every service the far side is supervising, as statuses.
async fn statuses(client: &RemoteClient) -> Result<Vec<ServiceStatus>, String> {
    read_statuses(&client.get("/api/services").await?)
}

/// One service's full definition, including its Git watch.
async fn describe(client: &RemoteClient, name: &str) -> Result<selfhost_config::ServiceSpec, String> {
    let answer = client.get(&format!("/api/services/{}", segment(name)?)).await?;
    read_spec(&answer, name)
}

/// Reads the service list out of an answer.
///
/// Separate from the request so the shape of the wire contract can be asserted
/// without a network: this and [`read_spec`] are the only two places the CLI
/// depends on what `crates/app/admin` sends, and a rename on that side should
/// fail a test here rather than an operator's command.
fn read_statuses(answer: &Json) -> Result<Vec<ServiceStatus>, String> {
    let listed = answer
        .get("services")
        .and_then(Json::as_array)
        .ok_or_else(|| "the far side's service list has no \"services\" array".to_string())?;
    Ok(listed.iter().filter_map(ServiceStatus::from_json).collect())
}

/// Reads one service definition out of an answer.
fn read_spec(answer: &Json, name: &str) -> Result<selfhost_config::ServiceSpec, String> {
    answer
        .get("spec")
        .and_then(spec_from_json)
        .ok_or_else(|| format!("the far side's answer for \"{name}\" carries no service definition"))
}

/// The far side's applications, as a catalogue the local printer can render.
///
/// Two round trips per application, because the list route answers *statuses*
/// and a status does not say whether the service is built from a repository —
/// only the per-service route carries the watch. Asking once per service is
/// wasteful in handshakes and honest about where the answer lives; the
/// alternative was widening an admin API route to suit one CLI command.
async fn applications(client: &RemoteClient) -> Result<ServiceCatalog, String> {
    let mut services = Vec::new();
    for status in statuses(client).await? {
        let spec = describe(client, &status.name).await?;
        if spec.git.is_some() {
            services.push(spec);
        }
    }
    Ok(ServiceCatalog { version: 1, services })
}

/// Checks a name before it becomes a path segment.
///
/// The name comes from the command line and is about to be written into a
/// request line, so a slash would redirect the request to a route nobody asked
/// for and a CR/LF would append header fields to it. Service names are already
/// restricted to this alphabet by `ServiceSpec::check`, so nothing legitimate is
/// turned away — and encoding the value instead would let a caller reach a
/// different route while looking like it named a service.
fn segment(name: &str) -> Result<&str, String> {
    let usable = !name.is_empty()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    if usable && name != "." && name != ".." {
        Ok(name)
    } else {
        Err(format!(
            "\"{name}\" is not a service name — letters, digits, dot, dash and underscore only"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn a_bare_host_is_dialled_over_https_on_443() {
        let remote = Remote::parse("admin.example.com").expect("a bare host is enough");
        assert_eq!(remote.port, 443);
        assert_eq!(remote.authority(), "admin.example.com");
        assert_eq!(remote.to_string(), "https://admin.example.com");
    }

    #[test]
    fn an_explicit_port_travels_into_the_host_field() {
        let remote = Remote::parse("https://box.example.com:8443").expect("scheme and port parse");
        assert_eq!(remote.port, 8443);
        assert_eq!(remote.authority(), "box.example.com:8443");
    }

    #[test]
    fn plain_http_is_refused_rather_than_upgraded() {
        // The request carries a bearer token; sending it in clear even once is a
        // compromise, and quietly "fixing" the scheme would hide that it was asked for.
        let error = Remote::parse("http://box.example.com").expect_err("http is refused");
        assert!(error.contains("clear"), "{error}");
    }

    #[test]
    fn a_host_carrying_credentials_or_a_path_is_refused() {
        for given in ["user:secret@box.example.com", "box.example.com/api/services", "box?x=1"] {
            assert!(Remote::parse(given).is_err(), "{given} should be refused");
        }
    }

    #[test]
    fn a_hostname_cannot_smuggle_a_header_into_the_request() {
        assert!(Remote::parse("box.example.com\r\nX-Evil: 1").is_err());
    }

    #[test]
    fn the_flag_is_taken_out_of_the_arguments_wherever_it_appears() {
        let (kept, remote) = split(words("app list --remote box.example.com")).expect("parses");
        assert_eq!(kept, words("app list"));
        assert_eq!(remote, Some(Remote::parse("box.example.com").unwrap()));

        let (kept, remote) = split(words("--remote=box.example.com services")).expect("parses");
        assert_eq!(kept, words("services"));
        assert_eq!(remote.map(|r| r.to_string()), Some("https://box.example.com".to_owned()));
    }

    #[test]
    fn no_flag_leaves_the_arguments_exactly_as_they_were() {
        let (kept, remote) = split(words("doctor --deep")).expect("parses");
        assert_eq!(kept, words("doctor --deep"));
        assert_eq!(remote, None);
    }

    #[test]
    fn a_flag_with_no_value_is_an_error_rather_than_a_local_run() {
        assert!(split(words("services --remote")).is_err());
    }

    #[test]
    fn two_different_remotes_are_refused_instead_of_the_last_one_winning() {
        assert!(split(words("--remote a.example.com --remote b.example.com services")).is_err());
    }

    #[test]
    fn the_read_only_commands_are_planned() {
        assert_eq!(plan(&words("services")).unwrap(), Plan::Services);
        assert_eq!(plan(&words("app")).unwrap(), Plan::AppList);
        assert_eq!(plan(&words("app list")).unwrap(), Plan::AppList);
        assert_eq!(plan(&words("app show blog")).unwrap(), Plan::AppShow("blog".into()));
    }

    #[test]
    fn a_command_with_no_remote_implementation_refuses_and_says_it_did_nothing() {
        // The whole point of the module: never the local machine by surprise.
        for line in ["app deploy blog", "teardown --everything", "doctor", "people list", "run"] {
            let error = plan(&words(line)).expect_err("{line} has no remote implementation");
            assert!(error.contains("NOT run"), "{line}: {error}");
            assert!(error.contains("without --remote"), "{line}: {error}");
        }
    }

    #[test]
    fn a_service_name_that_would_change_the_route_is_refused() {
        for name in ["../secrets", "blog/logs", "blog\r\nX-Evil: 1", "", "..", "blog?x=1"] {
            assert!(segment(name).is_err(), "{name:?} should be refused");
        }
        assert_eq!(segment("blog-2.staging_1").unwrap(), "blog-2.staging_1");
    }

    #[test]
    fn an_empty_or_unprintable_token_is_refused_before_it_reaches_a_header() {
        assert!(usable("", "SELFHOST_TOKEN").is_err());
        assert!(usable("abc\ndef", "SELFHOST_TOKEN").is_err());
        assert!(usable("token with spaces", "SELFHOST_TOKEN").is_err());
        assert_eq!(usable("9f2c-ABC_1", "SELFHOST_TOKEN").unwrap(), "9f2c-ABC_1");
    }

    #[test]
    fn a_fixed_length_answer_is_read_as_soon_as_its_body_has_arrived() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 9\r\n\r\n";
        let mut raw = head.to_vec();
        assert!(!complete(&raw), "the head alone is not the whole answer");
        raw.extend_from_slice(b"{\"a\":1}");
        assert!(!complete(&raw), "a short body is not the whole answer");
        raw.extend_from_slice(b"  ");
        assert!(complete(&raw));
        assert_eq!(answer(&raw).unwrap().get("a").and_then(Json::as_f64), Some(1.0));
    }

    #[test]
    fn a_chunked_answer_is_decoded_rather_than_handed_back_with_its_framing() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n7\r\n{\"a\":1}\r\n0\r\n\r\n";
        assert!(complete(raw));
        assert_eq!(answer(raw).unwrap().get("a").and_then(Json::as_f64), Some(1.0));
    }

    #[test]
    fn a_service_list_from_the_admin_api_is_read_into_statuses() {
        // The exact shape `crates/app/admin` sends: `ServiceStatus::to_json` for
        // each service, wrapped in a `services` array.
        let answer = selfhost_json::parse(
            "{\"services\":[{\"name\":\"blog\",\"displayName\":\"blog\",\"description\":\"\",\
             \"state\":\"running\",\"pid\":4242,\"uptimeSecs\":90,\"startMode\":\"automatic\",\
             \"totalRestarts\":0,\"logSeq\":7}]}",
        )
        .expect("the sample parses");

        let statuses = read_statuses(&answer).expect("the list is read");
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].name, "blog");
        assert_eq!(statuses[0].state.label(), "Running");
        assert_eq!(start_mode_name(statuses[0].start_mode), "automatic");
    }

    #[test]
    fn a_described_service_carries_the_watch_that_makes_it_an_application() {
        // Without the watch, `app list` could not tell an application from any
        // other service — which is why it asks the per-service route at all.
        let answer = selfhost_json::parse(
            "{\"status\":{\"name\":\"blog\",\"state\":\"running\",\"pid\":1,\"uptimeSecs\":1},\
             \"spec\":{\"name\":\"blog\",\"program\":\"node\",\"args\":[\"server.js\"],\
             \"git\":{\"repository\":\"https://example.com/blog.git\",\"path\":\"checkouts/blog\",\
             \"branch\":\"release\"}}}",
        )
        .expect("the sample parses");

        let spec = read_spec(&answer, "blog").expect("the definition is read");
        assert_eq!(spec.name, "blog");
        assert_eq!(spec.git.expect("an application is watched").branch, "release");
        let empty = selfhost_json::parse("{}").expect("an empty object parses");
        assert!(read_spec(&empty, "blog").is_err(), "an answer with no spec is an error");
    }

    #[test]
    fn a_refusal_that_is_not_json_still_reports_its_status() {
        // A proxy's own error page is the common case, and "the body is not
        // JSON" would bury the 404 that says what to do about it.
        let page = b"HTTP/1.1 404 Not Found\r\nContent-Length: 22\r\n\r\n<html>Not found</html>";
        let error = answer(page).expect_err("a 404 is an error");
        assert!(error.contains("404") && error.contains("route"), "{error}");
    }

    #[test]
    fn a_refusal_keeps_the_status_because_401_and_404_need_different_reactions() {
        let unauthorised = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 21\r\n\r\n{\"error\":\"bad token\"}";
        let error = answer(unauthorised).expect_err("a 401 is an error");
        assert!(error.contains("401") && error.contains("token"), "{error}");

        let missing = b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}";
        let error = answer(missing).expect_err("a 404 is an error");
        assert!(error.contains("404") && error.contains("route"), "{error}");
    }
}
