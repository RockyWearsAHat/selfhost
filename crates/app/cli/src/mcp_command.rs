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

use crate::remote_client::{Remote, RemoteClient};
use selfhost_json::Json;
use std::io::{BufRead, Write};
use std::path::Path;

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
/// surface an agent can be granted: sites and their content (`site.admin`),
/// services and deploys (`service.control`, with reads under `console.read`),
/// the deployment's own self-update, and `whoami` so an agent can see exactly
/// which of these its token will open.
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
        "Tell one service's git watch that a push landed, so it fetches, rebuilds and restarts now.",
        &[("name", "The service's name.", true, Kind::Text)],
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

/// The value immediately following the first occurrence of `name`.
fn value_of(arguments: &[String], name: &str) -> Option<String> {
    arguments.iter().position(|argument| argument == name).and_then(|at| arguments.get(at + 1)).cloned()
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
    ])
}

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
            }
            (field.to_string(), Json::object(fields.into_iter()))
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
            let body = Json::object(fields.into_iter()).to_text();
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
            let answer = client
                .request("POST", &format!("/api/services/{}/deploy", encode(&service)), None)
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
        "sites_delete_file" => {
            let site = required(arguments, "name")?;
            let path = required(arguments, "path")?;
            let answer = client
                .request("DELETE", &format!("/api/sites/{}/files/entry?path={}", encode(&site), encode(&path)), None)
                .await?;
            Ok(answer.to_text())
        }
        other => Err(format!("unknown tool \"{other}\"")),
    }
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

/// Percent-encodes one path segment or query value for a request line.
///
/// Deliberately conservative — everything outside `[A-Za-z0-9._~-]` is
/// escaped, well past what any of these fields actually need — because the
/// cost of over-escaping is a slightly longer request line and the cost of
/// under-escaping is a byte that changes which route this reaches. The far
/// side's own resolver (`selfhost_storage::path::resolve`) fully
/// percent-decodes and re-validates every one of these regardless, so this
/// encoder's only job is getting the bytes there intact.
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'~' | b'-' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
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
}
