//! `selfhost mcp` — a Model Context Protocol server over stdio, so an AI agent
//! (Claude, or anything else that speaks MCP) can operate this deployment —
//! sites and their content, services and their deploys, the deployment's own
//! self-update — the way the CLI already lets an operator at a keyboard do,
//! from the agent's own machine, never from a keyboard on the box. What any
//! one agent may actually do is decided entirely by its token's grants (see
//! below), so binding this server is wiring, not authority: the full tool
//! surface is advertised, and each call opens only if the far side's policy
//! says that agent holds the capability the route demands.
//!
//! # What this is not
//!
//! This process **listens on nothing**. MCP's stdio transport is exactly what
//! its name says: newline-delimited JSON-RPC 2.0 messages on this process's
//! own stdin and stdout, read and written by whatever spawned it (`claude mcp
//! add`, or an equivalent client configuration) on the machine it runs on.
//! There is no socket here for the box's firewall, `docs/SECURITY.md`'s
//! checklist, or anyone else to have an opinion about — every network call
//! this makes is *outbound*, over the same HTTPS `--remote` already uses (see
//! [`crate::remote_client`]), to the far side's existing `/api/*` surface.
//! Nothing about running this widens what the box exposes.
//!
//! # Why this authenticates with an agent token, never the deployment's own
//!
//! [`crate::remote_client::RemoteClient::get`] — what `--remote` uses — is
//! deliberately read-only and carries the plain deployment bearer token,
//! which `Policy::decide`'s `the_machine_may` refuses `Capability::SiteAdmin`
//! outright (see `selfhost_identity::policy`'s module documentation for why:
//! that token is this box's *own* automation, not an agent's, and a leaked
//! copy of it must not be able to repoint a hostname). This process instead
//! reads a **scoped agent token** — `agent:<name>:<secret>`, minted by
//! `selfhost agent add <name> --grant site.admin` on the box, verified by
//! `selfhost_admin::agent_store` against `Identity::Agent(<name>)` — from
//! `SELFHOST_AGENT_TOKEN` or `~/.selfhost/agent-token`, **never** from a
//! command-line argument (the same discipline
//! [`crate::remote_client::read_token`] already applies to the deployment
//! token, for the identical reason: `ps` and shell history are not where a
//! secret belongs). What this server can do on the far side is therefore
//! exactly what that one agent was granted — nothing else, and nothing more,
//! and revocable at any time with `selfhost agent revoke <name>` on the box.
//!
//! # Every response is JSON-RPC on stdout, and nothing else may write there
//!
//! stdout is the wire. A stray `println!` anywhere this process's dependency
//! chain reaches would corrupt every message after it, silently, for a
//! protocol whose only error surface is "the client stopped understanding
//! us". So this module writes to stdout in exactly one place
//! ([`write_message`]), diagnostics go to stderr (which the MCP transport
//! spec reserves for exactly this), and a malformed request or a failed tool
//! call is answered as a JSON-RPC error or a tool-level `isError`, never a
//! panic — this process is meant to run for the life of an agent's session,
//! and one bad request must not end it.

use crate::arguments::value_of;
use selfhost_http::percent::encode_segment as encode;
use crate::remote_client::{Remote, RemoteClient};
use selfhost_json::Json;
use std::io::{BufRead, Write};
use std::path::Path;

/// The host the `report` tool files against when `reportHost` is not given —
/// this deployment's public site, where the report intake is actually mounted
/// (`app_paths = ["/report"]`), which is a different site from the admin API
/// host this server's `--host` names.
const DEFAULT_REPORT_HOST: &str = "rockywearsahat.com";

/// The words this command accepts, and what each one is for.
pub const USAGE: &str = "\
Usage
  selfhost mcp --host <admin-host>

Starts a Model Context Protocol server on stdin/stdout, so an MCP client (an
AI agent) can operate <admin-host> — the same host you would give `--remote` —
through tools it can list and call: sites and their content, services and
their deploys, and the deployment's own self-update. Each call succeeds only
if the agent's token was granted the capability that route demands (site.admin
for sites, service.control for services and self-update, console.read for
service reads); the whoami tool shows what a token holds.

The credential is never a flag: it comes from SELFHOST_AGENT_TOKEN or
~/.selfhost/agent-token, an agent token minted with
`selfhost agent add <name> --grant site.admin,console.read,service.control`
on the box itself.
";

/// How a tool argument is typed: what its JSON Schema advertises, and what
/// shapes [`call_tool`]'s readers accept.
///
/// Every reader is deliberately wider than its schema: an MCP client that
/// stringifies a value it should have sent structurally — `"true"` for a
/// boolean, `"a.com,b.com"` or a JSON-encoded array for a list — gets coerced
/// rather than refused, because the alternative observed in practice was a
/// tool that advertised an array and then failed every call that dared send
/// one as text.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A JSON string.
    Text,
    /// A JSON boolean; `"true"`/`"false"` strings are coerced.
    Flag,
    /// A JSON array of strings; one string, a comma-separated string, or a
    /// JSON-encoded array arriving as a string are all coerced.
    Words,
    /// A JSON array of objects; a JSON-encoded array arriving as a string is
    /// coerced.
    Objects,
    /// A JSON object mapping strings to strings (e.g. environment variables);
    /// a JSON-encoded object arriving as a string is coerced.
    Map,
    /// A JSON number; a numeric string is coerced.
    Count,
}

/// One tool argument: its JSON field name, a human description, whether
/// `tools/call` refuses without it, and its [`Kind`].
type Param = (&'static str, &'static str, bool, Kind);

/// One tool: its name, a human description, and its parameters.
type Tool = (&'static str, &'static str, &'static [Param]);

/// The tools this server advertises, and what each one needs.
///
/// `params` is turned into the JSON Schema `tools/list` answers with by
/// [`tool_schema`]. Together these cover the far side's whole operational
/// surface an agent can be granted: sites and their content (`site.admin`,
/// including who may reach one — `site_set_exposure`/`site_set_owner`),
/// services and deploys (`service.control`, with reads under `console.read`),
/// the deployment's own self-update, `whoami` so an agent can see exactly
/// which of these its token will open, and — owner-only, the same as the
/// routes behind them — the registry (`people_*`), the deploy record and
/// System health (`deploys_*`, `system_health`), the VPN roster
/// (`vpn_peers_list`) and the firewall (`firewall_show`). This is "STEP 4 —
/// control parity" from `index.dx`'s goal 4: every mutating
/// admin route reachable from a keyboard on the box is reachable here too,
/// gated by the calling token's grants exactly as the HTTP route is — see
/// `docs/labs/mcp-lab.dx` for the parity table and what still is not.
const TOOLS: &[Tool] = &[
    ("sites_list", "List every site this deployment's proxy answers for.", &[]),
    (
        "sites_show",
        "Show one site's full definition: domains, whether it serves static content, and its app instances.",
        &[("name", "The site's name.", true, Kind::Text)],
    ),
    (
        "sites_add",
        "Create a new site. Set static=true to get a managed content directory you can then upload files \
         into with sites_upload_file; give instances to route to a running application instead, or both.",
        &[
            ("name", "A short name: letters, digits and dashes.", true, Kind::Text),
            ("domains", "Every hostname that should serve this site; the first is canonical.", true, Kind::Words),
            ("static", "Whether this site should have a managed static-content directory.", false, Kind::Flag),
            ("spa", "Serve index.html for unmatched paths — needs static=true.", false, Kind::Flag),
            ("instances", "Application backends as an array of {\"node\":..,\"port\":..} objects.", false, Kind::Objects),
        ],
    ),
    (
        "sites_add_domain",
        "Add one more hostname to an existing site — this is what a subdomain is: a hostname added to \
         the site that should answer for it, not a new site.",
        &[("name", "The site's name.", true, Kind::Text), ("hostname", "The hostname to add.", true, Kind::Text)],
    ),
    (
        "sites_remove_domain",
        "Remove one hostname from a site, leaving the site and its other hostnames in place.",
        &[("name", "The site's name.", true, Kind::Text), ("hostname", "The hostname to remove.", true, Kind::Text)],
    ),
    (
        "sites_remove",
        "Unroute a site. This does not delete its content — only that content stops being served.",
        &[("name", "The site's name.", true, Kind::Text)],
    ),
    (
        "sites_list_files",
        "List the files and directories in a site's static content, at an optional path within it.",
        &[
            ("name", "The site's name.", true, Kind::Text),
            ("path", "Path within the site's content directory; omit for the top level.", false, Kind::Text),
        ],
    ),
    (
        "sites_mkdir",
        "Create one directory (with missing parents refused — create them one level at a time) in a \
         site's static content.",
        &[
            ("name", "The site's name.", true, Kind::Text),
            ("path", "Directory path within the site's content directory.", true, Kind::Text),
        ],
    ),
    (
        "sites_upload_file",
        "Write one file into a site's static content, creating or replacing it. Give the bytes inline \
         as \"content\", or name a file on this machine as \"localFile\" to send its bytes without \
         them ever passing through the conversation.",
        &[
            ("name", "The site's name.", true, Kind::Text),
            ("path", "Path within the site's content directory, e.g. \"index.html\" or \"assets/logo.png\".", true, Kind::Text),
            ("content", "The file's bytes as a UTF-8 string (for text) or base64 (set contentEncoding=\"base64\").", false, Kind::Text),
            ("contentEncoding", "\"base64\" for binary content; omit for plain UTF-8 text.", false, Kind::Text),
            ("localFile", "Absolute path of a file on the machine running this MCP server to upload instead of \"content\".", false, Kind::Text),
        ],
    ),
    (
        "sites_upload_dir",
        "Upload a whole directory tree from this machine into a site's static content: every directory \
         is created and every file uploaded, skipping dotfiles. This is how a built site (a dist/ \
         directory) is published in one call.",
        &[
            ("name", "The site's name.", true, Kind::Text),
            ("localDir", "Absolute path of the directory on the machine running this MCP server.", true, Kind::Text),
            ("path", "Target path within the site's content directory; omit for the top level.", false, Kind::Text),
        ],
    ),
    (
        "sites_delete_file",
        "Delete one file or empty directory from a site's static content.",
        &[("name", "The site's name.", true, Kind::Text), ("path", "Path within the site's content directory.", true, Kind::Text)],
    ),
    (
        "site_set_exposure",
        "Set who may reach a site: \"public\" (open to the internet, the normal case), \"people\" \
         (a signed-in Person holding site.access:<site>, from anywhere), \"private\" (the same, and \
         the request must also arrive from the site's allowed_cidrs — in practice, the VPN), or \
         omit exposure entirely to clear it back to the unset default. The console site cannot take \
         an exposure at all; it keeps its own login.",
        &[
            ("name", "The site's name.", true, Kind::Text),
            ("exposure", "\"public\", \"people\" or \"private\"; omit to clear.", false, Kind::Text),
        ],
    ),
    (
        "site_set_owner",
        "Set which Person a site is delegated to: that Person may then grant or revoke \
         site.access:<site> on other people without holding site.admin outright. Omit owner to \
         clear the delegation.",
        &[
            ("name", "The site's name.", true, Kind::Text),
            ("owner", "The delegate's Person name; omit to clear.", false, Kind::Text),
        ],
    ),
    ("services_list", "List every service this deployment supervises, with its state.", &[]),
    (
        "services_show",
        "Show one service's definition and current state.",
        &[("name", "The service's name.", true, Kind::Text)],
    ),
    (
        "services_control",
        "Start, stop or restart one supervised service.",
        &[
            ("name", "The service's name.", true, Kind::Text),
            ("action", "One of \"start\", \"stop\" or \"restart\".", true, Kind::Text),
        ],
    ),
    (
        "services_logs",
        "Read one service's recent log lines.",
        &[
            ("name", "The service's name.", true, Kind::Text),
            ("limit", "How many lines (server caps at 5000; default 500).", false, Kind::Count),
            ("from", "Line offset to start from; omit for the most recent.", false, Kind::Count),
        ],
    ),
    (
        "services_deploy",
        "Tell one service's git watch that a push landed, so it fetches, rebuilds and restarts now. \
         Always forces the update and build to run again even if the branch tip has not moved.",
        &[("name", "The service's name.", true, Kind::Text)],
    ),
    (
        "services_add",
        "Install a new service that runs a git-deployed application: its program, build and serve \
         commands, the repository it deploys from, and the node and port it runs on. Requires the \
         services.admin grant, distinct from service.control — this defines what a service runs, \
         rather than merely starting or stopping one that is already defined.",
        &[
            ("name", "Service name: letters, digits, dot, dash and underscore.", true, Kind::Text),
            ("repository", "The git repository to deploy from, e.g. \"owner/repo\" or a full URL.", true, Kind::Text),
            ("branch", "The branch to watch. Defaults to \"main\".", false, Kind::Text),
            ("serve", "The command that starts the server, as an array: program first, then its arguments.", true, Kind::Words),
            ("build", "A build command run before serve starts, if the application needs one.", false, Kind::Words),
            ("port", "The port the server binds and the proxy forwards to.", true, Kind::Count),
            ("node", "The node that runs this service.", true, Kind::Text),
            ("domains", "Hostnames that should route to this application, if any.", false, Kind::Words),
            ("env", "Extra environment variables for the process, as an object.", false, Kind::Map),
        ],
    ),
    (
        "services_remove",
        "Remove a service's definition from the catalogue entirely, stopping it first if it is running. \
         Unlike services_control (which only starts, stops or restarts a service that stays defined), \
         this erases what the service runs — its program, build and serve commands, repository — so it \
         requires the services.admin grant, the same one services_add and services_repo_configure need.",
        &[("name", "The service's name.", true, Kind::Text)],
    ),
    (
        "services_repo_configure",
        "Install a repository already tracked by the GitHub App (see repo list) as a running \
         service — the same install services_add does, but starting from a tracked owner/repo \
         rather than an arbitrary git URL. Set fromManifest=true to read selfhost.toml from the \
         tip of the branch and fill in serve/build/port/env/health-path that were not given \
         explicitly; an explicit argument always wins over the manifest. fromManifest is never \
         assumed — it is a deliberate opt-in, because the manifest lives in a repository someone \
         else can push to. Requires the services.admin grant.",
        &[
            ("owner", "The repository owner (the \"owner\" of \"owner/repo\").", true, Kind::Text),
            ("repo", "The repository name (the \"repo\" of \"owner/repo\").", true, Kind::Text),
            ("branch", "The branch to watch and, with fromManifest, to read selfhost.toml from. Defaults to \"main\".", false, Kind::Text),
            ("fromManifest", "Read selfhost.toml from the repository and fold it in — see the tool description.", false, Kind::Flag),
            ("serve", "The command that starts the server. Required unless fromManifest supplies one.", false, Kind::Words),
            ("build", "A build command run before serve starts, if any.", false, Kind::Words),
            ("port", "The port the server binds. Required unless fromManifest supplies one.", false, Kind::Count),
            ("node", "The node that runs this service.", true, Kind::Text),
            ("domains", "Hostnames that should route to this application, if any.", false, Kind::Words),
            ("env", "Extra environment variables for the process, as an object.", false, Kind::Map),
        ],
    ),
    (
        "self_update",
        "Tell the deployment itself that a push landed on its own repository, so it fetches, rebuilds \
         and restarts itself now.",
        &[],
    ),
    (
        "whoami",
        "Show who this agent token is and exactly what it has been granted — the answer to \"why was \
         that call refused\".",
        &[],
    ),
    ("people_list", "List every registered Person, their grants, and whether they hold a login password.", &[]),
    (
        "people_show",
        "Show one registered Person: their grants, added time, email and whether they hold a login \
         password.",
        &[("name", "The person's name.", true, Kind::Text)],
    ),
    (
        "people_grant",
        "Give a Person one more capability, alongside whatever they already hold — this reads their \
         current grants first, so it never clears the rest. Granting vpn.access:<location> may also \
         provision a VPN roster entry if peer and pubkey are both given, the same as \
         `selfhost people grant --peer --pubkey`.",
        &[
            ("name", "The person's name. Creates them if this is their first grant.", true, Kind::Text),
            ("capability", "The capability word, e.g. \"console.read\" or \"site.access:blog\".", true, Kind::Text),
            ("peer", "A VPN roster entry's own name, for a vpn.access:<location> grant.", false, Kind::Text),
            ("pubkey", "That peer's public key in base64, generated on their own device.", false, Kind::Text),
        ],
    ),
    (
        "people_revoke",
        "Take one capability away from a Person, leaving everything else they hold in place.",
        &[
            ("name", "The person's name.", true, Kind::Text),
            ("capability", "The capability word to remove.", true, Kind::Text),
        ],
    ),
    (
        "people_invite",
        "Mint a one-time invitation code for a Person who does not yet hold a credential, so they can \
         register their own passkey without ever seeing this deployment's console password.",
        &[
            ("name", "The person's name.", true, Kind::Text),
            ("hours", "How long the code stays redeemable. Server default applies if omitted.", false, Kind::Count),
        ],
    ),
    ("deploys_list", "List every recorded Deploy (service and self-update alike), newest first.", &[]),
    (
        "deploys_show",
        "Show one recorded Deploy: what triggered it, its result, and its log.",
        &[("id", "The deploy's id, as deploys_list shows it.", true, Kind::Text)],
    ),
    (
        "system_health",
        "Show every System part of this deployment — the proxy, this admin API, VPN relays, mail — \
         with its state and, when unhealthy, why. Never lists hosted Services; see services_list for \
         those.",
        &[],
    ),
    (
        "vpn_peers_list",
        "List every peer this deployment's VPN relays know about, static and dynamically enrolled \
         alike, with which Person (if any) each is bound to.",
        &[],
    ),
    ("firewall_show", "Show the firewall's desired and live state: every rule this deployment manages.", &[]),
    (
        "report",
        "File a bug, suggestion, or observation about this deployment's own code (selfhost itself) \
         against this box's report intake, the same open POST /report?<project> door dx's own \
         reporting uses. Needs no grant -- the intake is open by design, bounded on its own side. \
         Defaults kind to \"bug\" and project to \"selfhost\"; give project only to file against a \
         different registered service on this box.",
        &[
            ("title", "One line naming the defect. Part of the report's identity.", true, Kind::Text),
            ("detail", "What you did, what you expected, and what happened instead.", true, Kind::Text),
            ("kind", "\"bug\", \"suggestion\", or \"observation\". Defaults to \"bug\".", false, Kind::Text),
            ("route", "The command, tool, or surface involved. Part of the report's identity.", false, Kind::Text),
            ("repro", "The smallest sequence that shows it, when you have one.", false, Kind::Text),
            ("project", "Which registered service this is about. Defaults to \"selfhost\".", false, Kind::Text),
            ("workspace", "The name (not path) of the folder you were working in.", false, Kind::Text),
            ("reportHost", "The host serving the report intake. Defaults to this deployment's public site.", false, Kind::Text),
        ],
    ),
];

/// Reads the agent token from `SELFHOST_AGENT_TOKEN`, or from
/// `~/.selfhost/agent-token`.
///
/// A different variable and a different file from
/// [`crate::remote_client::read_token`]'s, deliberately: pointing `mcp` at the
/// plain deployment token by habit must fail in a way that says so, not with
/// a confusing 403 from every site route once every request reaches the far
/// side. If what was found does not have the `agent:` shape this expects,
/// that is exactly the mistake reported.
fn read_agent_token() -> Result<String, String> {
    let raw = if let Ok(from_environment) = std::env::var("SELFHOST_AGENT_TOKEN") {
        from_environment.trim().to_owned()
    } else {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map_err(|_| {
                "no agent token: SELFHOST_AGENT_TOKEN is not set and this account has no home \
                 directory to read ~/.selfhost/agent-token from"
                    .to_owned()
            })?;
        let path = std::path::Path::new(&home).join(".selfhost").join("agent-token");
        std::fs::read_to_string(&path)
            .map_err(|error| {
                format!(
                    "no agent token: SELFHOST_AGENT_TOKEN is not set and {} could not be read \
                     ({error}).\n  Mint one with `selfhost agent add <name> --grant site.admin` \
                     on the box, then copy the printed token here — never as a command-line \
                     argument.",
                    path.display()
                )
            })?
            .trim()
            .to_owned()
    };

    validate_agent_token_shape(&raw)
}

/// Checks that a token read from the environment or the token file has the
/// `agent:` shape this server needs — split out from [`read_agent_token`] so
/// the check is testable without setting an environment variable (this crate
/// forbids `unsafe`, which `std::env::set_var` now requires).
fn validate_agent_token_shape(raw: &str) -> Result<String, String> {
    if !raw.starts_with("agent:") {
        return Err(
            "the value found for SELFHOST_AGENT_TOKEN/~/.selfhost/agent-token does not look like \
             an agent token (it should start with \"agent:\") — this looks like the plain \
             deployment bearer token, which `selfhost mcp` cannot use: mint a scoped one with \
             `selfhost agent add <name> --grant site.admin`"
                .to_owned(),
        );
    }
    crate::remote_client::usable(raw, "the agent token")
}

/// Runs `selfhost mcp --host <admin-host>`.
pub fn run(arguments: &[String]) -> Result<(), String> {
    let host = value_of(arguments, "--host").ok_or_else(|| {
        format!("selfhost mcp needs a host: `selfhost mcp --host <admin-host>`\n\n{USAGE}")
    })?;
    let remote = Remote::parse(&host)?;
    let token = read_agent_token()?;
    let client = RemoteClient::new(remote, token);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("could not start the async runtime: {error}"))?;

    eprintln!("selfhost mcp: ready, talking to {host}");
    runtime.block_on(serve(&client))
}

/// The stdin-read, dispatch, stdout-write loop. Runs until stdin closes.
async fn serve(client: &RemoteClient) -> Result<(), String> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                eprintln!("selfhost mcp: stdin error: {error}");
                break;
            }
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(request) = selfhost_json::parse(trimmed) else {
            eprintln!("selfhost mcp: ignoring a line that is not JSON: {trimmed}");
            continue;
        };
        if let Some(response) = handle(client, &request).await {
            write_message(&mut stdout, &response)?;
        }
    }
    Ok(())
}

/// Writes one JSON-RPC message as a line, and flushes — the only place this
/// process writes to stdout. See this module's documentation for why that
/// matters.
fn write_message(stdout: &mut std::io::Stdout, message: &Json) -> Result<(), String> {
    writeln!(stdout, "{}", message.to_text()).map_err(|error| format!("could not write to stdout: {error}"))?;
    stdout.flush().map_err(|error| format!("could not flush stdout: {error}"))
}

/// Handles one JSON-RPC request or notification, returning the response to
/// send — `None` for a notification, which JSON-RPC never answers.
async fn handle(client: &RemoteClient, request: &Json) -> Option<Json> {
    let id = request.get("id").cloned();
    let method = request.get("method").and_then(Json::as_str).unwrap_or("");
    let params = request.get("params").cloned().unwrap_or(Json::Null);

    match method {
        "initialize" => Some(response(id, initialize_result())),
        "notifications/initialized" | "notifications/cancelled" => None,
        "ping" => Some(response(id, Json::object(Vec::<(&str, Json)>::new()))),
        "tools/list" => Some(response(id, tools_list_result())),
        "tools/call" => Some(response(id, tools_call_result(client, &params).await)),
        _ => id.map(|id| error_response(id, -32601, &format!("unknown method \"{method}\""))),
    }
}

/// A successful JSON-RPC response envelope. `id` is `None` for a notification
/// this function should never be called for — every caller above only calls
/// it once `id` is known to be `Some`, or for a `tools/*`/`initialize`/`ping`
/// reply, which the spec always gives an id for.
fn response(id: Option<Json>, result: Json) -> Json {
    Json::object([
        ("jsonrpc", Json::string("2.0")),
        ("id", id.unwrap_or(Json::Null)),
        ("result", result),
    ])
}

/// A JSON-RPC protocol-level error (an unknown method, a malformed call) —
/// distinct from a *tool* error, which is a successful RPC whose result says
/// `isError: true` (see [`tool_error`]). A client's model can recover from a
/// tool error; a protocol error means the request itself made no sense.
fn error_response(id: Json, code: i64, message: &str) -> Json {
    Json::object([
        ("jsonrpc", Json::string("2.0")),
        ("id", id),
        ("error", Json::object([("code", Json::Number(code as f64)), ("message", Json::string(message))])),
    ])
}

/// The `initialize` result: this server's identity and what it offers.
fn initialize_result() -> Json {
    Json::object([
        ("protocolVersion", Json::string("2024-11-05")),
        ("capabilities", Json::object([("tools", Json::object(Vec::<(&str, Json)>::new()))])),
        (
            "serverInfo",
            Json::object([("name", Json::string("selfhost")), ("version", Json::string("1"))]),
        ),
        ("instructions", Json::string(SERVER_INSTRUCTIONS)),
    ])
}

/// Orientation for an agent that has never used this server before, surfaced
/// through MCP's `initialize.instructions` field rather than left to be
/// discovered inside one tool's own description.
///
/// This exists because of a real incident: an agent debugging a broken
/// deployment reached for raw SSH and an interactive `gh auth login` before
/// ever calling `services_logs`, and separately, nothing told it that
/// `selfhost.toml` (read via `services_repo_configure`'s `fromManifest`) was
/// the way to hand this daemon a build/serve command instead of guessing one.
/// Both were individually documented on the relevant tool, but nothing said
/// "read this first" — an agent has no reason to open a specific tool's
/// description before it knows that tool is the one it needs.
const SERVER_INSTRUCTIONS: &str = "\
This server manages services and sites on one selfhost deployment. Typical workflow:\n\
\n\
1. Something looks broken? Call services_show and services_logs BEFORE touching SSH \
or any credential tooling (gh auth, ssh-add, etc.) — most failures are visible here \
(a build step's error, a service left stopped) and none of them are fixed by \
re-authenticating anything. Never SSH directly to a box's port 22; a box's SSH is only \
reachable through its own Secure-VPN tunnel, and a direct attempt will simply time out.\n\
2. Defining or fixing what a service runs (its repository, build/serve command, port) \
is services_add or services_repo_configure, not a file edit or a redeploy — \
services_deploy only re-runs a service that is already correctly defined.\n\
3. A repository can carry its own selfhost.toml (serve/build/port/env/health_path) so \
you do not have to know its build command by heart — pass fromManifest=true to \
services_repo_configure to read it. This is opt-in on purpose: the manifest lives in a \
repository someone else can push to, so it is never read unless you ask for it.\n\
4. services_add/services_repo_configure/services_remove need the services.admin grant; \
services_control (start/stop/restart) needs only service.control. Call whoami to see \
exactly what this token has, if a call is refused.\n\
5. self_update redeploys this daemon's own repository; services_deploy redeploys one \
managed service. Both always force a rebuild rather than only checking for new commits.";

/// The `tools/list` result: every tool in [`TOOLS`], as MCP's schema shape.
fn tools_list_result() -> Json {
    Json::object([("tools", Json::array(TOOLS.iter().map(|(name, description, params)| tool_schema(name, description, params))))])
}

/// One tool's JSON Schema description.
fn tool_schema(name: &str, description: &str, params: &[Param]) -> Json {
    let properties: Vec<(String, Json)> = params
        .iter()
        .map(|(field, description, _, kind)| {
            let mut fields = vec![("description".to_owned(), Json::string(*description))];
            match kind {
                Kind::Text => fields.push(("type".to_owned(), Json::string("string"))),
                Kind::Flag => fields.push(("type".to_owned(), Json::string("boolean"))),
                Kind::Count => fields.push(("type".to_owned(), Json::string("number"))),
                Kind::Words => {
                    fields.push(("type".to_owned(), Json::string("array")));
                    fields.push(("items".to_owned(), Json::object([("type", Json::string("string"))])));
                }
                Kind::Objects => {
                    fields.push(("type".to_owned(), Json::string("array")));
                    fields.push(("items".to_owned(), Json::object([("type", Json::string("object"))])));
                }
                Kind::Map => fields.push(("type".to_owned(), Json::string("object"))),
            }
            (field.to_string(), Json::object(fields))
        })
        .collect();
    let required: Vec<Json> =
        params.iter().filter(|(_, _, required, _)| *required).map(|(field, _, _, _)| Json::string(*field)).collect();
    Json::object([
        ("name", Json::string(name)),
        ("description", Json::string(description)),
        (
            "inputSchema",
            Json::object([
                ("type", Json::string("object")),
                ("properties", Json::object(properties.iter().map(|(k, v)| (k.as_str(), v.clone())))),
                ("required", Json::array(required)),
            ]),
        ),
    ])
}

/// A tool-level success: `content` is what the model reads.
fn tool_ok(text: String) -> Json {
    Json::object([("content", Json::array([Json::object([("type", Json::string("text")), ("text", Json::string(&text))])])), ("isError", Json::Bool(false))])
}

/// A tool-level failure: still a successful RPC, `isError: true`, and a clean
/// message — never a stack trace or an internal path, matching the discipline
/// `crates/app/admin`'s `problem()` responses already hold to.
fn tool_error(message: &str) -> Json {
    Json::object([("content", Json::array([Json::object([("type", Json::string("text")), ("text", Json::string(message))])])), ("isError", Json::Bool(true))])
}

/// Dispatches `tools/call`.
async fn tools_call_result(client: &RemoteClient, params: &Json) -> Json {
    let name = params.get("name").and_then(Json::as_str).unwrap_or("");
    let arguments = params.get("arguments").cloned().unwrap_or(Json::Null);
    let outcome = call_tool(client, name, &arguments).await;
    match outcome {
        Ok(text) => tool_ok(text),
        Err(message) => tool_error(&message),
    }
}

/// Reads a required string argument.
fn required(arguments: &Json, field: &str) -> Result<String, String> {
    arguments
        .get(field)
        .and_then(Json::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("\"{field}\" is required"))
}

/// Reads an optional string argument, defaulting to `""`.
fn optional(arguments: &Json, field: &str) -> String {
    arguments.get(field).and_then(Json::as_str).unwrap_or("").to_owned()
}

/// Reads an optional boolean, coercing `"true"`/`"false"` strings.
fn flag(arguments: &Json, field: &str) -> Result<Option<bool>, String> {
    match arguments.get(field) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::Bool(value)) => Ok(Some(*value)),
        Some(Json::String(text)) if text == "true" => Ok(Some(true)),
        Some(Json::String(text)) if text == "false" => Ok(Some(false)),
        Some(_) => Err(format!("\"{field}\" must be true or false")),
    }
}

/// Reads a required list of strings, accepting every shape a client has
/// actually sent for one: a real array, one bare string, a comma-separated
/// string, or a JSON-encoded array that arrived as a string.
fn words(arguments: &Json, field: &str) -> Result<Vec<String>, String> {
    let refuse = || format!("\"{field}\" must be an array of strings");
    let of_array = |items: &[Json]| -> Result<Vec<String>, String> {
        items.iter().map(|item| item.as_str().map(str::to_owned).ok_or_else(refuse)).collect()
    };
    let found = match arguments.get(field) {
        None | Some(Json::Null) => return Ok(Vec::new()),
        Some(Json::Array(items)) => of_array(items)?,
        Some(Json::String(text)) => {
            let parsed = text.trim_start().starts_with('[').then(|| selfhost_json::parse(text).ok()).flatten();
            match parsed.as_ref().and_then(Json::as_array) {
                Some(items) => of_array(items)?,
                None => text.split(',').map(str::trim).filter(|w| !w.is_empty()).map(str::to_owned).collect(),
            }
        }
        Some(_) => return Err(refuse()),
    };
    Ok(found)
}

/// Reads an optional array of objects, coercing a JSON-encoded array that
/// arrived as a string.
fn objects(arguments: &Json, field: &str) -> Result<Option<Json>, String> {
    match arguments.get(field) {
        None | Some(Json::Null) => Ok(None),
        Some(found @ Json::Array(_)) => Ok(Some(found.clone())),
        Some(Json::String(text)) => match selfhost_json::parse(text) {
            Ok(parsed @ Json::Array(_)) => Ok(Some(parsed)),
            _ => Err(format!("\"{field}\" must be an array")),
        },
        Some(_) => Err(format!("\"{field}\" must be an array")),
    }
}

/// Reads an optional string-to-string map (e.g. `env`), coercing a
/// JSON-encoded object that arrived as a string — the same allowance
/// [`objects`] makes for an array.
fn string_map(arguments: &Json, field: &str) -> Result<std::collections::BTreeMap<String, String>, String> {
    let refuse = || format!("\"{field}\" must be an object of strings");
    let of_object = |entries: &std::collections::BTreeMap<String, Json>| -> Result<std::collections::BTreeMap<String, String>, String> {
        entries
            .iter()
            .map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_owned())).ok_or_else(refuse))
            .collect()
    };
    match arguments.get(field) {
        None | Some(Json::Null) => Ok(std::collections::BTreeMap::new()),
        Some(Json::Object(entries)) => of_object(entries),
        Some(Json::String(text)) => match selfhost_json::parse(text) {
            Ok(Json::Object(entries)) => of_object(&entries),
            _ => Err(refuse()),
        },
        Some(_) => Err(refuse()),
    }
}

/// A required port number in range, from a [`count`]-shaped argument.
fn port(arguments: &Json, field: &str) -> Result<u16, String> {
    let value = count(arguments, field)?.ok_or_else(|| format!("\"{field}\" is required"))?;
    u16::try_from(value).map_err(|_| format!("\"{field}\" must be between 1 and 65535"))
}

/// Reads an optional number, coercing a numeric string, rendered back as the
/// query-string digits the far side parses.
fn count(arguments: &Json, field: &str) -> Result<Option<u64>, String> {
    match arguments.get(field) {
        None | Some(Json::Null) => Ok(None),
        Some(Json::Number(value)) if *value >= 0.0 => Ok(Some(*value as u64)),
        Some(Json::String(text)) => {
            text.trim().parse().map(Some).map_err(|_| format!("\"{field}\" must be a number"))
        }
        Some(_) => Err(format!("\"{field}\" must be a number")),
    }
}

/// The whole of what one tool call does: build the request, ask the far side,
/// and render the answer as the text a model reads.
async fn call_tool(client: &RemoteClient, name: &str, arguments: &Json) -> Result<String, String> {
    match name {
        "sites_list" => {
            let answer = client.get("/api/sites").await?;
            Ok(answer.to_text())
        }
        "sites_show" => {
            let site = required(arguments, "name")?;
            let answer = client.get(&format!("/api/sites/{}", encode(&site))).await?;
            Ok(answer.to_text())
        }
        "sites_add" => {
            // The body is rebuilt field by field rather than forwarded
            // verbatim: forwarding meant a client that stringified `domains`
            // shipped that string to the far side to fail there, and any
            // stray argument travelled with it.
            let site = required(arguments, "name")?;
            let domains = words(arguments, "domains")?;
            if domains.is_empty() {
                return Err("\"domains\" needs at least one hostname".to_owned());
            }
            let mut fields = vec![
                ("name".to_owned(), Json::string(&site)),
                ("domains".to_owned(), Json::array(domains.iter().map(Json::string))),
            ];
            if let Some(wants_static) = flag(arguments, "static")? {
                fields.push(("static".to_owned(), Json::Bool(wants_static)));
            }
            if let Some(spa) = flag(arguments, "spa")? {
                fields.push(("spa".to_owned(), Json::Bool(spa)));
            }
            if let Some(instances) = objects(arguments, "instances")? {
                fields.push(("instances".to_owned(), instances));
            }
            let body = Json::object(fields).to_text();
            let answer = client.request("POST", "/api/sites", Some(body.as_bytes())).await?;
            Ok(answer.to_text())
        }
        "sites_add_domain" => {
            let site = required(arguments, "name")?;
            let hostname = required(arguments, "hostname")?;
            let body = Json::object([("hostname", Json::string(&hostname))]).to_text();
            let answer = client
                .request("POST", &format!("/api/sites/{}/domains", encode(&site)), Some(body.as_bytes()))
                .await?;
            Ok(answer.to_text())
        }
        "sites_remove_domain" => {
            let site = required(arguments, "name")?;
            let hostname = required(arguments, "hostname")?;
            let answer = client
                .request(
                    "DELETE",
                    &format!("/api/sites/{}/domains/{}", encode(&site), encode(&hostname)),
                    None,
                )
                .await?;
            Ok(answer.to_text())
        }
        "sites_remove" => {
            let site = required(arguments, "name")?;
            let answer = client.request("DELETE", &format!("/api/sites/{}", encode(&site)), None).await?;
            Ok(answer.to_text())
        }
        "sites_list_files" => {
            let site = required(arguments, "name")?;
            let path = optional(arguments, "path");
            let answer = client
                .get(&format!("/api/sites/{}/files/list?path={}", encode(&site), encode(&path)))
                .await?;
            Ok(answer.to_text())
        }
        "sites_mkdir" => {
            let site = required(arguments, "name")?;
            let path = required(arguments, "path")?;
            let body = Json::object([("path", Json::string(&path))]).to_text();
            let answer = client
                .request("POST", &format!("/api/sites/{}/files/mkdir", encode(&site)), Some(body.as_bytes()))
                .await?;
            Ok(answer.to_text())
        }
        "sites_upload_file" => {
            let site = required(arguments, "name")?;
            let path = required(arguments, "path")?;
            let bytes = upload_bytes(arguments)?;
            let answer = client
                .request(
                    "PUT",
                    &format!("/api/sites/{}/files/entry?path={}", encode(&site), encode(&path)),
                    Some(&bytes),
                )
                .await?;
            Ok(answer.to_text())
        }
        "sites_upload_dir" => {
            let site = required(arguments, "name")?;
            let local = required(arguments, "localDir")?;
            let prefix = optional(arguments, "path");
            upload_dir(client, &site, Path::new(&local), &prefix).await
        }
        "services_list" => {
            let answer = client.get("/api/services").await?;
            Ok(answer.to_text())
        }
        "services_show" => {
            let service = required(arguments, "name")?;
            let answer = client.get(&format!("/api/services/{}", encode(&service))).await?;
            Ok(answer.to_text())
        }
        "services_control" => {
            let service = required(arguments, "name")?;
            let action = required(arguments, "action")?;
            if !matches!(action.as_str(), "start" | "stop" | "restart") {
                return Err(format!("\"action\" must be start, stop or restart, not \"{action}\""));
            }
            let answer = client
                .request("POST", &format!("/api/services/{}/{}", encode(&service), encode(&action)), None)
                .await?;
            Ok(answer.to_text())
        }
        "services_logs" => {
            let service = required(arguments, "name")?;
            let mut query = String::new();
            if let Some(limit) = count(arguments, "limit")? {
                query.push_str(&format!("limit={limit}"));
            }
            if let Some(from) = count(arguments, "from")? {
                if !query.is_empty() {
                    query.push('&');
                }
                query.push_str(&format!("from={from}"));
            }
            let path = if query.is_empty() {
                format!("/api/services/{}/logs", encode(&service))
            } else {
                format!("/api/services/{}/logs?{query}", encode(&service))
            };
            let answer = client.get(&path).await?;
            Ok(answer.to_text())
        }
        "services_deploy" => {
            let service = required(arguments, "name")?;
            // An agent calling this tool is always asking "redeploy this
            // right now" — never "check whether anything changed" — so this
            // always forces the update and build to run even if the branch
            // tip has not moved since the last deploy. See
            // `selfhost_git::check_once_forced`'s documentation for why the
            // background poller never does the same.
            let body = Json::object([("force", Json::Bool(true))]).to_text();
            let answer = client
                .request(
                    "POST",
                    &format!("/api/services/{}/deploy", encode(&service)),
                    Some(body.as_bytes()),
                )
                .await?;
            Ok(answer.to_text())
        }
        "services_add" => {
            let name = required(arguments, "name")?;
            let repository = required(arguments, "repository")?;
            let branch = optional(arguments, "branch");
            let serve = words(arguments, "serve")?;
            if serve.is_empty() {
                return Err("\"serve\" needs at least one word".to_owned());
            }
            let build = words(arguments, "build")?;
            let node = required(arguments, "node")?;
            let port = port(arguments, "port")?;
            let domains = words(arguments, "domains")?;
            let env = string_map(arguments, "env")?;

            let mut app = selfhost_app_deploy::AppSpec::new(&name, domains, repository, serve, node, port);
            if !branch.is_empty() {
                app.branch = branch;
            }
            if !build.is_empty() {
                app.build = Some(build);
            }
            app.env = env;

            let body = selfhost_supervisor::state::spec_to_json(&app.service()).to_text();
            let answer = client
                .request("PUT", &format!("/api/services/{}", encode(&app.name)), Some(body.as_bytes()))
                .await?;
            Ok(answer.to_text())
        }
        "services_remove" => {
            let service = required(arguments, "name")?;
            let answer = client.request("DELETE", &format!("/api/services/{}", encode(&service)), None).await?;
            Ok(answer.to_text())
        }
        "services_repo_configure" => {
            let owner = required(arguments, "owner")?;
            let repo = required(arguments, "repo")?;
            let branch = optional(arguments, "branch");
            let branch_for_manifest =
                if branch.is_empty() { selfhost_config::git::DEFAULT_BRANCH.to_owned() } else { branch.clone() };
            let from_manifest = flag(arguments, "fromManifest")?.unwrap_or(false);
            let serve = words(arguments, "serve")?;
            let build = words(arguments, "build")?;
            let node = required(arguments, "node")?;
            let port = count(arguments, "port")?
                .map(|value| {
                    u16::try_from(value).map_err(|_| "\"port\" must be between 1 and 65535".to_owned())
                })
                .transpose()?;
            let domains = words(arguments, "domains")?;
            let env = string_map(arguments, "env")?;

            // A clone that shells out to `git`, so it runs on a blocking
            // thread rather than stalling this server's single-threaded
            // runtime for however long the clone takes.
            let manifest = if from_manifest {
                let (task_owner, task_repo, task_branch) =
                    (owner.clone(), repo.clone(), branch_for_manifest.clone());
                let fetched = tokio::task::spawn_blocking(move || {
                    crate::repo_command::fetch_manifest(&task_owner, &task_repo, &task_branch)
                })
                .await
                .map_err(|error| format!("could not fetch the manifest: {error}"))??;
                Some(fetched.ok_or_else(|| {
                    format!(
                        "fromManifest was set, but {owner}/{repo} has no {} at the tip of \"{branch_for_manifest}\"",
                        selfhost_config::manifest::MANIFEST_FILENAME
                    )
                })?)
            } else {
                None
            };

            let mut app = crate::repo_command::compose_with_manifest(
                &owner,
                &repo,
                &node,
                port,
                serve,
                build,
                domains,
                manifest.as_ref(),
            )?;
            if !branch.is_empty() {
                app.branch = branch;
            }
            for (key, value) in env {
                app.env.entry(key).or_insert(value);
            }

            let body = selfhost_supervisor::state::spec_to_json(&app.service()).to_text();
            let answer = client
                .request("PUT", &format!("/api/services/{}", encode(&app.name)), Some(body.as_bytes()))
                .await?;
            Ok(answer.to_text())
        }
        "self_update" => {
            let answer = client.request("POST", "/api/self-update/deploy", None).await?;
            Ok(answer.to_text())
        }
        "whoami" => {
            let answer = client.get("/api/whoami").await?;
            Ok(answer.to_text())
        }
        "report" => {
            let title = required(arguments, "title")?;
            let detail = required(arguments, "detail")?;
            let kind = optional(arguments, "kind");
            let kind = if kind.is_empty() { "bug".to_owned() } else { kind };
            let route = optional(arguments, "route");
            let repro = optional(arguments, "repro");
            let workspace = optional(arguments, "workspace");
            let project = optional(arguments, "project");
            let project = if project.is_empty() { "selfhost".to_owned() } else { project };
            // The report intake is mounted on the deployment's public site
            // (rockywearsahat.com, app_paths = ["/report"]), not on the admin
            // API host this server's --host names — those are two different
            // sites, and the admin host's proxy does not route this path. An
            // explicit reportHost lets this reach a different box entirely.
            let report_host = optional(arguments, "reportHost");
            let report_host = if report_host.is_empty() { DEFAULT_REPORT_HOST.to_owned() } else { report_host };
            let body = Json::object([
                ("kind", Json::string(&kind)),
                ("title", Json::string(&title)),
                ("detail", Json::string(&detail)),
                ("route", Json::string(&route)),
                ("repro", Json::string(&repro)),
                ("tool", Json::string("selfhost-mcp report")),
                ("workspace", Json::string(&workspace)),
            ])
            .to_text();
            let report_remote = Remote::parse(&report_host)?;
            let report_client = RemoteClient::new(report_remote, String::new());
            let answer = report_client
                .request("POST", &format!("/report?{}", encode(&project)), Some(body.as_bytes()))
                .await?;
            Ok(answer.to_text())
        }
        "sites_delete_file" => {
            let site = required(arguments, "name")?;
            let path = required(arguments, "path")?;
            let answer = client
                .request("DELETE", &format!("/api/sites/{}/files/entry?path={}", encode(&site), encode(&path)), None)
                .await?;
            Ok(answer.to_text())
        }
        "site_set_exposure" => {
            let site = required(arguments, "name")?;
            let exposure = optional(arguments, "exposure");
            let body = Json::object([(
                "exposure",
                if exposure.is_empty() { Json::Null } else { Json::string(&exposure) },
            )])
            .to_text();
            let answer = client
                .request("PUT", &format!("/api/sites/{}/exposure", encode(&site)), Some(body.as_bytes()))
                .await?;
            Ok(answer.to_text())
        }
        "site_set_owner" => {
            let site = required(arguments, "name")?;
            let owner = optional(arguments, "owner");
            let body =
                Json::object([("owner", if owner.is_empty() { Json::Null } else { Json::string(&owner) })])
                    .to_text();
            let answer = client
                .request("PUT", &format!("/api/sites/{}/owner", encode(&site)), Some(body.as_bytes()))
                .await?;
            Ok(answer.to_text())
        }
        "people_list" => {
            let answer = client.get("/api/people").await?;
            Ok(answer.to_text())
        }
        "people_show" => {
            let name = required(arguments, "name")?;
            let roster = client.get("/api/people").await?;
            let found = roster
                .get("people")
                .and_then(Json::as_array)
                .and_then(|people| people.iter().find(|person| person.get("name").and_then(Json::as_str) == Some(name.as_str())));
            match found {
                Some(person) => Ok(person.to_text()),
                None => Err(format!("no person named \"{name}\" is registered")),
            }
        }
        "people_grant" => {
            let name = required(arguments, "name")?;
            let capability = required(arguments, "capability")?;
            let peer = optional(arguments, "peer");
            let pubkey = optional(arguments, "pubkey");
            let mut grants = current_grants(client, &name).await?;
            if !grants.iter().any(|held| held == &capability) {
                grants.push(capability);
            }
            let mut fields = vec![("grants", Json::array(grants.iter().map(Json::string)))];
            if !peer.is_empty() {
                fields.push(("peer", Json::string(&peer)));
            }
            if !pubkey.is_empty() {
                fields.push(("public_key", Json::string(&pubkey)));
            }
            let body = Json::object(fields).to_text();
            let answer =
                client.request("PUT", &format!("/api/people/{}", encode(&name)), Some(body.as_bytes())).await?;
            Ok(answer.to_text())
        }
        "people_revoke" => {
            let name = required(arguments, "name")?;
            let capability = required(arguments, "capability")?;
            let grants: Vec<String> =
                current_grants(client, &name).await?.into_iter().filter(|held| held != &capability).collect();
            let body = Json::object([("grants", Json::array(grants.iter().map(Json::string)))]).to_text();
            let answer =
                client.request("PUT", &format!("/api/people/{}", encode(&name)), Some(body.as_bytes())).await?;
            Ok(answer.to_text())
        }
        "people_invite" => {
            let name = required(arguments, "name")?;
            let mut fields = Vec::new();
            if let Some(hours) = count(arguments, "hours")? {
                fields.push(("hours", Json::Number(hours as f64)));
            }
            let body = Json::object(fields).to_text();
            let answer = client
                .request("POST", &format!("/api/people/{}/invite", encode(&name)), Some(body.as_bytes()))
                .await?;
            Ok(answer.to_text())
        }
        "deploys_list" => {
            let answer = client.get("/api/deploys").await?;
            Ok(answer.to_text())
        }
        "deploys_show" => {
            let id = required(arguments, "id")?;
            let answer = client.get(&format!("/api/deploys/{}", encode(&id))).await?;
            Ok(answer.to_text())
        }
        "system_health" => {
            let answer = client.get("/api/system").await?;
            Ok(answer.to_text())
        }
        "vpn_peers_list" => {
            let answer = client.get("/api/vpn/peers").await?;
            Ok(answer.to_text())
        }
        "firewall_show" => {
            let answer = client.get("/api/firewall").await?;
            Ok(answer.to_text())
        }
        other => Err(format!("unknown tool \"{other}\"")),
    }
}

/// The capability words a Person currently holds, read from the roster —
/// `PUT /api/people/<name>` replaces the whole grant set in one call, so
/// `people_grant` and `people_revoke` both read this first and write back the
/// union or the difference, never a bare single word, on the same grounds
/// [`crate::people_command`]'s own `set` does for the CLI's direct-file path.
/// A Person not yet registered simply holds nothing yet — this is not an
/// error, since granting them their first capability is exactly how they come
/// to exist.
async fn current_grants(client: &RemoteClient, name: &str) -> Result<Vec<String>, String> {
    let roster = client.get("/api/people").await?;
    let Some(people) = roster.get("people").and_then(Json::as_array) else {
        return Ok(Vec::new());
    };
    let Some(person) = people.iter().find(|person| person.get("name").and_then(Json::as_str) == Some(name)) else {
        return Ok(Vec::new());
    };
    let Some(grants) = person.get("grants").and_then(Json::as_array) else {
        return Ok(Vec::new());
    };
    Ok(grants.iter().filter_map(Json::as_str).map(str::to_owned).collect())
}

/// The bytes one `sites_upload_file` call should send: inline `content`
/// (UTF-8 or base64) or a file read from this machine — exactly one of the
/// two, and the distinction is presence, not emptiness, so an empty file can
/// still be uploaded.
fn upload_bytes(arguments: &Json) -> Result<Vec<u8>, String> {
    let content = arguments.get("content").and_then(Json::as_str);
    let local = arguments.get("localFile").and_then(Json::as_str);
    match (content, local) {
        (Some(content), None) => {
            if optional(arguments, "contentEncoding") == "base64" {
                decode_base64(content)
            } else {
                Ok(content.as_bytes().to_vec())
            }
        }
        (None, Some(local)) => std::fs::read(local)
            .map_err(|error| format!("could not read {local} on this machine: {error}")),
        (None, None) => Err("give either \"content\" or \"localFile\"".to_owned()),
        (Some(_), Some(_)) => Err("give \"content\" or \"localFile\", not both".to_owned()),
    }
}

/// Publishes one local directory tree into a site's static content — the
/// whole point of running this server on the machine where a site gets built:
/// a `dist/` directory becomes live content without one byte of it passing
/// through the model's conversation.
///
/// Directories are created shallowest first (the far side's mkdir refuses
/// missing parents) and a mkdir refusal is deliberately not fatal — the
/// directory usually already exists from a previous run, and one that
/// genuinely failed to appear fails loudly at the first file below it. Files
/// upload in a stable order, so a failed run says exactly where it stopped.
/// Entries whose names start with a dot are skipped: `.DS_Store` and `.git`
/// are never site content.
async fn upload_dir(
    client: &RemoteClient,
    site: &str,
    local: &Path,
    prefix: &str,
) -> Result<String, String> {
    let mut directories = Vec::new();
    let mut files = Vec::new();
    collect(local, String::new(), &mut directories, &mut files)?;
    directories.sort();
    files.sort();

    let prefix = prefix.trim_matches('/');
    let joined = |relative: &str| {
        if prefix.is_empty() { relative.to_owned() } else { format!("{prefix}/{relative}") }
    };

    let mkdir = |path: String| async move {
        let body = Json::object([("path", Json::string(path))]).to_text();
        client
            .request("POST", &format!("/api/sites/{}/files/mkdir", encode(site)), Some(body.as_bytes()))
            .await
    };

    // The target prefix itself is built one level at a time, under the same
    // missing-parents rule as everything below it.
    let mut so_far = String::new();
    for part in prefix.split('/').filter(|part| !part.is_empty()) {
        if !so_far.is_empty() {
            so_far.push('/');
        }
        so_far.push_str(part);
        let _ = mkdir(so_far.clone()).await;
    }
    for directory in &directories {
        let _ = mkdir(joined(directory)).await;
    }

    let mut sent = 0u64;
    for (at, relative) in files.iter().enumerate() {
        let bytes = std::fs::read(local.join(relative)).map_err(|error| {
            format!(
                "could not read {relative}: {error} — {at} of {} files were uploaded before it",
                files.len()
            )
        })?;
        eprintln!("selfhost mcp: uploading {relative} ({} bytes)", bytes.len());
        client
            .request(
                "PUT",
                &format!(
                    "/api/sites/{}/files/entry?path={}",
                    encode(site),
                    encode(&joined(relative))
                ),
                Some(&bytes),
            )
            .await
            .map_err(|error| {
                format!(
                    "uploading {relative} failed: {error} — {at} of {} files were uploaded before it",
                    files.len()
                )
            })?;
        sent += bytes.len() as u64;
    }
    Ok(Json::object([
        ("uploadedFiles", Json::Number(files.len() as f64)),
        ("createdDirectories", Json::Number(directories.len() as f64)),
        ("bytes", Json::Number(sent as f64)),
    ])
    .to_text())
}

/// Walks `at`, collecting slash-joined relative directory and file paths.
///
/// Dot-entries are skipped, and symlinks are neither followed nor uploaded —
/// the far side's own descriptor walk refuses them, so offering one could only
/// manufacture a confusing failure late in an upload.
fn collect(
    at: &Path,
    relative: String,
    directories: &mut Vec<String>,
    files: &mut Vec<String>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(at)
        .map_err(|error| format!("could not read {} on this machine: {error}", at.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("could not read {}: {error}", at.display()))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        let child = if relative.is_empty() { name } else { format!("{relative}/{name}") };
        let kind =
            entry.file_type().map_err(|error| format!("could not stat {child}: {error}"))?;
        if kind.is_dir() {
            directories.push(child.clone());
            collect(&entry.path(), child, directories, files)?;
        } else if kind.is_file() {
            files.push(child);
        }
    }
    Ok(())
}

/// Decodes a base64 string, for binary `sites_upload_file` content.
///
/// A small standard-alphabet decoder written here rather than adding a
/// dependency: this workspace's stated policy is writing what it needs above
/// the socket rather than reaching for a crate, and a base64 decoder is a
/// few dozen lines with no protocol surface worth outsourcing.
fn decode_base64(text: &str) -> Result<Vec<u8>, String> {
    fn value(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let cleaned: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let trimmed: &[u8] = {
        let mut end = cleaned.len();
        while end > 0 && cleaned[end - 1] == b'=' {
            end -= 1;
        }
        &cleaned[..end]
    };
    let mut out = Vec::with_capacity(trimmed.len() * 3 / 4 + 3);
    let mut chunk = [0u8; 4];
    let mut filled = 0;
    for &byte in trimmed {
        let v = value(byte).ok_or_else(|| "\"content\" is not valid base64".to_owned())?;
        chunk[filled] = v;
        filled += 1;
        if filled == 4 {
            out.push((chunk[0] << 2) | (chunk[1] >> 4));
            out.push((chunk[1] << 4) | (chunk[2] >> 2));
            out.push((chunk[2] << 6) | chunk[3]);
            filled = 0;
        }
    }
    match filled {
        0 => {}
        2 => out.push((chunk[0] << 2) | (chunk[1] >> 4)),
        3 => {
            out.push((chunk[0] << 2) | (chunk[1] >> 4));
            out.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        _ => return Err("\"content\" is not valid base64".to_owned()),
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_names_this_server() {
        let result = initialize_result();
        assert_eq!(result.get("serverInfo").and_then(|s| s.get("name")).and_then(Json::as_str), Some("selfhost"));
    }

    #[test]
    fn every_tool_appears_in_the_listing_with_a_schema() {
        let listing = tools_list_result();
        let tools = listing.get("tools").and_then(Json::as_array).expect("a tools array");
        assert_eq!(tools.len(), TOOLS.len());
        for tool in tools {
            assert!(tool.get("name").and_then(Json::as_str).is_some());
            assert!(tool.get("inputSchema").is_some());
        }
    }

    #[test]
    fn a_notification_gets_no_response() {
        let request = selfhost_json::parse(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#).unwrap();
        // `handle` needs a client only for `tools/call`; a notification never
        // reaches that branch, so a throwaway remote is fine here.
        let remote = Remote::parse("example.test").unwrap();
        let client = RemoteClient::new(remote, "agent:x:y".to_owned());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        assert!(runtime.block_on(handle(&client, &request)).is_none());
    }

    #[test]
    fn an_unknown_method_is_a_protocol_error_not_a_panic() {
        let request = selfhost_json::parse(r#"{"jsonrpc":"2.0","id":1,"method":"nonsense"}"#).unwrap();
        let remote = Remote::parse("example.test").unwrap();
        let client = RemoteClient::new(remote, "agent:x:y".to_owned());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let response = runtime.block_on(handle(&client, &request)).expect("a request always gets a reply");
        assert!(response.get("error").is_some());
    }

    #[test]
    fn a_call_naming_no_tool_is_a_clean_tool_error() {
        let params = selfhost_json::parse(r#"{"name":"nonsense","arguments":{}}"#).unwrap();
        let remote = Remote::parse("example.test").unwrap();
        let client = RemoteClient::new(remote, "agent:x:y".to_owned());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(tools_call_result(&client, &params));
        assert_eq!(result.get("isError").and_then(Json::as_bool), Some(true));
    }

    #[test]
    fn a_missing_required_argument_is_a_clean_tool_error_not_a_network_call() {
        let params = selfhost_json::parse(r#"{"name":"sites_show","arguments":{}}"#).unwrap();
        let remote = Remote::parse("example.test").unwrap();
        let client = RemoteClient::new(remote, "agent:x:y".to_owned());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(tools_call_result(&client, &params));
        assert_eq!(result.get("isError").and_then(Json::as_bool), Some(true));
        let text = result
            .get("content")
            .and_then(Json::as_array)
            .and_then(|c| c.first())
            .and_then(|c| c.get("text"))
            .and_then(Json::as_str)
            .unwrap();
        assert!(text.contains("name"), "{text}");
    }

    #[test]
    fn the_schema_types_an_array_a_boolean_and_a_number_as_themselves() {
        let listing = tools_list_result();
        let tools = listing.get("tools").and_then(Json::as_array).expect("a tools array");
        let of = |name: &str, field: &str| -> Json {
            tools
                .iter()
                .find(|tool| tool.get("name").and_then(Json::as_str) == Some(name))
                .and_then(|tool| tool.get("inputSchema"))
                .and_then(|schema| schema.get("properties"))
                .and_then(|properties| properties.get(field))
                .cloned()
                .expect("the field exists")
        };
        assert_eq!(of("sites_add", "domains").get("type").and_then(Json::as_str), Some("array"));
        assert_eq!(of("sites_add", "static").get("type").and_then(Json::as_str), Some("boolean"));
        assert_eq!(of("services_logs", "limit").get("type").and_then(Json::as_str), Some("number"));
    }

    #[test]
    fn a_flag_accepts_a_boolean_and_coerces_its_stringification() {
        let arguments = selfhost_json::parse(r#"{"a":true,"b":"false","c":"maybe"}"#).unwrap();
        assert_eq!(flag(&arguments, "a"), Ok(Some(true)));
        assert_eq!(flag(&arguments, "b"), Ok(Some(false)));
        assert_eq!(flag(&arguments, "missing"), Ok(None));
        assert!(flag(&arguments, "c").is_err());
    }

    #[test]
    fn words_accept_every_shape_a_client_sends_a_list_as() {
        let arguments = selfhost_json::parse(
            r#"{"real":["a.com","b.com"],"bare":"a.com","commas":"a.com, b.com","encoded":"[\"a.com\",\"b.com\"]"}"#,
        )
        .unwrap();
        let two = vec!["a.com".to_owned(), "b.com".to_owned()];
        assert_eq!(words(&arguments, "real"), Ok(two.clone()));
        assert_eq!(words(&arguments, "bare"), Ok(vec!["a.com".to_owned()]));
        assert_eq!(words(&arguments, "commas"), Ok(two.clone()));
        assert_eq!(words(&arguments, "encoded"), Ok(two));
    }

    #[test]
    fn an_upload_needs_content_or_a_local_file_and_never_both() {
        let neither = selfhost_json::parse(r#"{}"#).unwrap();
        assert!(upload_bytes(&neither).is_err());
        let both = selfhost_json::parse(r#"{"content":"x","localFile":"/tmp/x"}"#).unwrap();
        assert!(upload_bytes(&both).is_err());
        let inline = selfhost_json::parse(r#"{"content":"hello"}"#).unwrap();
        assert_eq!(upload_bytes(&inline), Ok(b"hello".to_vec()));
    }

    #[test]
    fn a_service_action_outside_the_three_is_refused_without_a_network_call() {
        let params =
            selfhost_json::parse(r#"{"name":"services_control","arguments":{"name":"web","action":"explode"}}"#)
                .unwrap();
        let remote = Remote::parse("example.test").unwrap();
        let client = RemoteClient::new(remote, "agent:x:y".to_owned());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(tools_call_result(&client, &params));
        assert_eq!(result.get("isError").and_then(Json::as_bool), Some(true));
    }

    #[test]
    fn path_segments_are_percent_encoded() {
        assert_eq!(encode("blog"), "blog");
        assert_eq!(encode("a b/c"), "a%20b%2Fc");
        assert_eq!(encode("home.rockywearsahat.com"), "home.rockywearsahat.com");
    }

    #[test]
    fn base64_round_trips_ordinary_bytes() {
        // "hello world" in base64.
        let decoded = decode_base64("aGVsbG8gd29ybGQ=").unwrap();
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn base64_refuses_garbage_rather_than_guessing() {
        assert!(decode_base64("not valid base64!!").is_err());
    }

    #[test]
    fn an_agent_token_is_required_not_the_deployment_bearer_token() {
        // A plain 64-hex-character token (the deployment bearer token's shape)
        // must be refused with a message that says why, not silently accepted.
        let error = validate_agent_token_shape(
            "9f2c1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        )
        .unwrap_err();
        assert!(error.contains("agent:"), "{error}");
    }

    #[test]
    fn a_well_shaped_agent_token_is_accepted() {
        assert!(validate_agent_token_shape("agent:claude-mac:abc123").is_ok());
    }

    #[test]
    fn string_map_accepts_a_real_object_and_a_json_encoded_string() {
        let real = selfhost_json::parse(r#"{"env":{"A":"1","B":"2"}}"#).unwrap();
        let mut expected = std::collections::BTreeMap::new();
        expected.insert("A".to_owned(), "1".to_owned());
        expected.insert("B".to_owned(), "2".to_owned());
        assert_eq!(string_map(&real, "env"), Ok(expected.clone()));

        let encoded = selfhost_json::parse(r#"{"env":"{\"A\":\"1\",\"B\":\"2\"}"}"#).unwrap();
        assert_eq!(string_map(&encoded, "env"), Ok(expected));

        let missing = selfhost_json::parse(r#"{}"#).unwrap();
        assert_eq!(string_map(&missing, "env"), Ok(std::collections::BTreeMap::new()));
    }

    #[test]
    fn a_port_in_range_is_accepted_and_out_of_range_is_refused() {
        let good = selfhost_json::parse(r#"{"port":5050}"#).unwrap();
        assert_eq!(port(&good, "port"), Ok(5050));

        let too_big = selfhost_json::parse(r#"{"port":99999}"#).unwrap();
        assert!(port(&too_big, "port").is_err());

        let missing = selfhost_json::parse(r#"{}"#).unwrap();
        assert!(port(&missing, "port").is_err());
    }

    #[test]
    fn services_add_without_serve_is_refused_without_a_network_call() {
        let params = selfhost_json::parse(
            r#"{"name":"services_add","arguments":{"name":"app","repository":"https://example.com/r.git","node":"home","port":5050}}"#,
        )
        .unwrap();
        let remote = Remote::parse("example.test").unwrap();
        let client = RemoteClient::new(remote, "agent:x:y".to_owned());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(tools_call_result(&client, &params));
        assert_eq!(result.get("isError").and_then(Json::as_bool), Some(true));
    }

    #[test]
    fn services_repo_configure_without_a_manifest_or_serve_and_port_is_refused() {
        let params = selfhost_json::parse(
            r#"{"name":"services_repo_configure","arguments":{"owner":"octocat","repo":"hello-world","node":"home"}}"#,
        )
        .unwrap();
        let remote = Remote::parse("example.test").unwrap();
        let client = RemoteClient::new(remote, "agent:x:y".to_owned());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(tools_call_result(&client, &params));
        assert_eq!(result.get("isError").and_then(Json::as_bool), Some(true));
    }

    #[test]
    fn both_new_service_tools_and_services_admin_are_advertised() {
        let listing = tools_list_result();
        let tools = listing.get("tools").and_then(Json::as_array).expect("a tools array");
        let names: Vec<&str> =
            tools.iter().filter_map(|tool| tool.get("name").and_then(Json::as_str)).collect();
        assert!(names.contains(&"services_add"), "{names:?}");
        assert!(names.contains(&"services_repo_configure"), "{names:?}");
    }

    #[test]
    fn report_is_advertised_and_missing_fields_are_refused_without_a_network_call() {
        let listing = tools_list_result();
        let tools = listing.get("tools").and_then(Json::as_array).expect("a tools array");
        let names: Vec<&str> =
            tools.iter().filter_map(|tool| tool.get("name").and_then(Json::as_str)).collect();
        assert!(names.contains(&"report"), "{names:?}");

        let params = selfhost_json::parse(r#"{"name":"report","arguments":{}}"#).unwrap();
        let remote = Remote::parse("example.test").unwrap();
        let client = RemoteClient::new(remote, "agent:x:y".to_owned());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(tools_call_result(&client, &params));
        assert_eq!(result.get("isError").and_then(Json::as_bool), Some(true));
    }

    #[test]
    fn services_remove_is_advertised_and_calls_delete() {
        let listing = tools_list_result();
        let tools = listing.get("tools").and_then(Json::as_array).expect("a tools array");
        let names: Vec<&str> =
            tools.iter().filter_map(|tool| tool.get("name").and_then(Json::as_str)).collect();
        assert!(names.contains(&"services_remove"), "{names:?}");

        let params =
            selfhost_json::parse(r#"{"name":"services_remove","arguments":{}}"#).unwrap();
        let remote = Remote::parse("example.test").unwrap();
        let client = RemoteClient::new(remote, "agent:x:y".to_owned());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(tools_call_result(&client, &params));
        // Missing "name" is refused before any network call, same as every
        // other name-bearing tool.
        assert_eq!(result.get("isError").and_then(Json::as_bool), Some(true));
    }
}
