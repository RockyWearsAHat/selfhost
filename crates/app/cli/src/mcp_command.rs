//! `selfhost mcp` — a Model Context Protocol server over stdio, so an AI agent
//! (Claude, or anything else that speaks MCP) can manage this deployment's
//! websites the way `selfhost site` already lets an operator at a keyboard
//! do — from the agent's own machine, never from a keyboard on the box.
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

/// The words this command accepts, and what each one is for.
pub const USAGE: &str = "\
Usage
  selfhost mcp --host <admin-host>

Starts a Model Context Protocol server on stdin/stdout, so an MCP client (an
AI agent) can manage websites on <admin-host> — the same host you would give
`--remote` — through tools it can list and call.

The credential is never a flag: it comes from SELFHOST_AGENT_TOKEN or
~/.selfhost/agent-token, an agent token minted with
`selfhost agent add <name> --grant site.admin` on the box itself.
";

/// The tools this server advertises, and what each one needs.
///
/// `(name, description, params)` — `params` is `(json_name, description,
/// required)` for each argument, which [`tool_schema`] turns into the JSON
/// Schema `tools/list` answers with.
const TOOLS: &[(&str, &str, &[(&str, &str, bool)])] = &[
    ("sites_list", "List every site this deployment's proxy answers for.", &[]),
    (
        "sites_show",
        "Show one site's full definition: domains, whether it serves static content, and its app instances.",
        &[("name", "The site's name.", true)],
    ),
    (
        "sites_add",
        "Create a new site. Set static=true to get a managed content directory you can then upload files \
         into with sites_upload_file; give instances to route to a running application instead, or both.",
        &[
            ("name", "A short name: letters, digits and dashes.", true),
            ("domains", "Every hostname that should serve this site (JSON array of strings; the first is canonical).", true),
            ("static", "Whether this site should have a managed static-content directory (boolean).", false),
            ("spa", "Serve index.html for unmatched paths — needs static=true (boolean).", false),
            ("instances", "Application backends as a JSON array of {\"node\":..,\"port\":..} objects.", false),
        ],
    ),
    (
        "sites_add_domain",
        "Add one more hostname to an existing site — this is what a subdomain is: a hostname added to \
         the site that should answer for it, not a new site.",
        &[("name", "The site's name.", true), ("hostname", "The hostname to add.", true)],
    ),
    (
        "sites_remove_domain",
        "Remove one hostname from a site, leaving the site and its other hostnames in place.",
        &[("name", "The site's name.", true), ("hostname", "The hostname to remove.", true)],
    ),
    (
        "sites_remove",
        "Unroute a site. This does not delete its content — only that content stops being served.",
        &[("name", "The site's name.", true)],
    ),
    (
        "sites_list_files",
        "List the files and directories in a site's managed content, at an optional path within it.",
        &[
            ("name", "The site's name.", true),
            ("path", "Path within the site's content directory; omit for the top level.", false),
        ],
    ),
    (
        "sites_upload_file",
        "Write one file into a site's managed content directory, creating or replacing it. \
         The site must have been created with static=true.",
        &[
            ("name", "The site's name.", true),
            ("path", "Path within the site's content directory, e.g. \"index.html\" or \"assets/logo.png\".", true),
            ("content", "The file's bytes as a UTF-8 string (for text) or base64 (set contentEncoding=\"base64\").", true),
            ("contentEncoding", "\"base64\" for binary content; omit for plain UTF-8 text.", false),
        ],
    ),
    (
        "sites_delete_file",
        "Delete one file or empty directory from a site's managed content.",
        &[("name", "The site's name.", true), ("path", "Path within the site's content directory.", true)],
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
fn tool_schema(name: &str, description: &str, params: &[(&str, &str, bool)]) -> Json {
    let properties: Vec<(String, Json)> = params
        .iter()
        .map(|(field, description, _)| {
            (field.to_string(), Json::object([("type", Json::string("string")), ("description", Json::string(*description))]))
        })
        .collect();
    let required: Vec<Json> =
        params.iter().filter(|(_, _, required)| *required).map(|(field, _, _)| Json::string(*field)).collect();
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
            let body = arguments.to_text();
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
        "sites_upload_file" => {
            let site = required(arguments, "name")?;
            let path = required(arguments, "path")?;
            let content = required(arguments, "content")?;
            let encoding = optional(arguments, "contentEncoding");
            let bytes = if encoding == "base64" {
                decode_base64(&content)?
            } else {
                content.into_bytes()
            };
            let answer = client
                .request(
                    "PUT",
                    &format!("/api/sites/{}/files/entry?path={}", encode(&site), encode(&path)),
                    Some(&bytes),
                )
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
        other => Err(format!("unknown tool \"{other}\"")),
    }
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
