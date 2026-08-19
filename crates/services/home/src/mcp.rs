//! The house as MCP tools, for an agent instead of a browser.
//!
//! The dashboard reaches the house through [`crate::server`]'s two HTTP
//! routes. An agent harness speaks MCP — JSON-RPC 2.0, one message per line,
//! over stdio — and this module is that same surface in that shape: the same
//! [`Hub`], the same [`api::act`] vocabulary, the same capability gate in
//! [`Hub::perform`]. Nothing here may drive a device any way the dashboard
//! could not, because both go through the one [`Hub::apply`].
//!
//! Two tools, deliberately mirroring the two HTTP routes:
//!
//! | Tool | HTTP twin | What |
//! |---|---|---|
//! | `house` | `GET /api/home` | the whole house, one object |
//! | `command` | `POST …/command` | ask one device to do one thing |
//!
//! The `command` tool's arguments minus `device` **are** the HTTP body: they
//! are handed to [`api::act`] unmodified, so the vocabulary an agent may
//! use is exactly the one the dashboard uses, and a word added there appears
//! here without this file changing.
//!
//! Security is the process boundary. This serves stdio — the pipe of whoever
//! spawned it — never a socket, so reaching it means already running code on
//! this machine, the same thing the loopback HTTP bind means. Everything the
//! agent sends is data; nothing in a device name or a tool argument is ever
//! executed.

use std::sync::Arc;

use selfhost_json::Json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::api;
use crate::device::DeviceId;
use crate::hub::Hub;

/// The MCP protocol revision this speaks.
///
/// Old on purpose: it is the floor every client still accepts, and nothing
/// newer is needed for two tools that take strings.
const PROTOCOL: &str = "2024-11-05";

/// Serves MCP over this process's stdio until stdin closes.
///
/// stdout carries JSON-RPC and nothing else — every human-facing line in this
/// crate goes to stderr, which the harness shows as server logs.
pub async fn serve(hub: Arc<Hub>) -> std::io::Result<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    eprintln!("[home] MCP serving the house on stdio");

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        if let Some(reply) = answer(&line, &hub).await {
            stdout.write_all(reply.to_text().as_bytes()).await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

/// Answers one JSON-RPC message, or decides none is owed (a notification).
async fn answer(line: &str, hub: &Hub) -> Option<Json> {
    let Ok(message) = selfhost_json::parse(line) else {
        return Some(error(Json::Null, -32700, "That line was not JSON."));
    };
    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Json::as_str).unwrap_or("");

    // A notification expects silence, whatever it says.
    let id = id?;

    let result = match method {
        "initialize" => initialize(),
        "ping" => Json::object::<&str>([]),
        "tools/list" => tools(),
        "tools/call" => {
            let params = message.get("params").cloned().unwrap_or(Json::Null);
            call(&params, hub).await
        }
        _ => return Some(error(id, -32601, &format!("There is no method called {method:?}."))),
    };
    Some(Json::object([
        ("jsonrpc", Json::string("2.0")),
        ("id", id),
        ("result", result),
    ]))
}

/// The handshake: what this server is and what it can do.
fn initialize() -> Json {
    Json::object([
        ("protocolVersion", Json::string(PROTOCOL)),
        ("capabilities", Json::object([("tools", Json::object::<&str>([]))])),
        (
            "serverInfo",
            Json::object([
                ("name", Json::string("selfhost-home")),
                ("version", Json::string(env!("CARGO_PKG_VERSION"))),
            ]),
        ),
    ])
}

/// The two tools, described for a caller that has never seen this house.
fn tools() -> Json {
    let house = Json::object([
        ("name", Json::string("house")),
        (
            "description",
            Json::string(
                "Every controllable device in the house, with its live state: id, name, room, \
                 kind, whether it is reachable, what it can be asked to do (capabilities), and \
                 what it is currently doing (power, brightness, color, volume…). Call this \
                 first to learn the device ids the command tool needs.",
            ),
        ),
        (
            "inputSchema",
            Json::object([
                ("type", Json::string("object")),
                ("properties", Json::object::<&str>([])),
            ]),
        ),
    ]);

    let string = |description: &str| {
        Json::object([
            ("type", Json::string("string")),
            ("description", Json::string(description)),
        ])
    };
    let command = Json::object([
        ("name", Json::string("command")),
        (
            "description",
            Json::string(
                "Ask one device to do one thing. Commands: \"on\", \"off\", \"power\" \
                 (value: true/false), \"brightness\" (value: 0-100), \"color\" (value: \
                 \"RRGGBB\" — translated to this bulb family's LEDs through the calibrated \
                 pipeline, so a screen colour lands looking right), \"color_temp\" (value: \
                 kelvin), \"volume\" (value: 0-100), \"volume_step\" (delta), \"mute\" \
                 (value), \"play\", \"pause\", \"stop\", \"next\", \"previous\", \"launch\" \
                 (app), \"key\" (name). The house's own memory takes \"rename\" (value: the \
                 new name; empty clears it), \"room\" (value: the room; empty clears it), \
                 \"hide\" and \"show\". A device refuses in a sentence anything it cannot do.",
            ),
        ),
        (
            "inputSchema",
            Json::object([
                ("type", Json::string("object")),
                (
                    "properties",
                    Json::object([
                        (
                            "device",
                            string("The device's id from the house tool (e.g. \"wiz:9877…\"), or its exact name."),
                        ),
                        ("command", string("The command word.")),
                        (
                            "value",
                            Json::object([(
                                "description",
                                Json::string(
                                    "The command's value, when it takes one: a number, a \
                                     true/false, or a string such as an RRGGBB colour.",
                                ),
                            )]),
                        ),
                        ("delta", Json::object([("description", Json::string("For volume_step: the signed step."))])),
                        ("target", string("For join: the device to join.")),
                        ("name", string("For key: the key's name.")),
                        ("app", string("For launch: the application.")),
                    ]),
                ),
                (
                    "required",
                    Json::array([Json::string("device"), Json::string("command")]),
                ),
            ]),
        ),
    ]);

    Json::object([("tools", Json::array([house, command]))])
}

/// Performs one tools/call.
async fn call(params: &Json, hub: &Hub) -> Json {
    let name = params.get("name").and_then(Json::as_str).unwrap_or("");
    let arguments = params.get("arguments").cloned().unwrap_or(Json::object::<&str>([]));

    match name {
        "house" => {
            // An empty house right after startup is far more likely a sweep
            // that has not finished than a house with nothing in it; sweeping
            // now costs seconds and answers with devices instead of [].
            if hub.snapshot().await.2.is_empty() {
                hub.discover().await;
            }
            let (generation, at, devices) = hub.snapshot().await;
            ok(api::house(generation, &at, &devices).to_text())
        }
        "command" => match command(&arguments, hub).await {
            Ok(text) => ok(text),
            Err(sentence) => refusal(&sentence),
        },
        other => refusal(&format!("There is no tool called {other:?}.")),
    }
}

/// Resolves the device, parses the command, performs it, reports the result.
async fn command(arguments: &Json, hub: &Hub) -> Result<String, String> {
    let device = arguments
        .get("device")
        .and_then(Json::as_str)
        .ok_or("The command must name a device.")?;
    let id = resolve(device, hub).await?;

    // Everything except `device` *is* the command body the HTTP route takes,
    // so api::command stays the one place the vocabulary lives.
    let body = match arguments {
        Json::Object(entries) => Json::Object(
            entries.iter().filter(|(k, _)| k.as_str() != "device").map(|(k, v)| (k.clone(), v.clone())).collect(),
        ),
        _ => return Err("The arguments were not an object.".to_owned()),
    };
    let act = api::act(&body).map_err(|refusal| refusal.sentence())?;

    hub.apply(&id, act).await?;

    // The device's fresh state is the useful answer — `perform` refreshed it —
    // so the agent sees what the command did without a second call.
    let (_, _, devices) = hub.snapshot().await;
    Ok(devices
        .iter()
        .find(|d| d.id == id)
        .map(|d| api::device(d).to_text())
        .unwrap_or_else(|| api::accepted().to_text()))
}

/// A device id from what the caller said: an exact id, or an exact name.
///
/// Case-insensitive on the name because an agent quotes names from prose;
/// ambiguity is refused in a sentence naming the ids, never guessed at.
async fn resolve(given: &str, hub: &Hub) -> Result<DeviceId, String> {
    // An exact id is checked against everything the house has ever adopted,
    // not against the snapshot — the snapshot filters hidden devices out, and
    // a hidden device must stay reachable by id or `show` could never be said.
    let id = DeviceId::from_wire(given);
    if hub.contains(&id).await {
        return Ok(id);
    }
    let (_, _, devices) = hub.snapshot().await;
    let matches: Vec<_> =
        devices.iter().filter(|d| d.name.eq_ignore_ascii_case(given)).collect();
    match matches.as_slice() {
        [one] => Ok(one.id.clone()),
        [] => Err("There is no device with that name here.".to_owned()),
        many => Err(format!(
            "{given:?} names {} devices — use an id: {}.",
            many.len(),
            many.iter().map(|d| d.id.as_str()).collect::<Vec<_>>().join(", ")
        )),
    }
}

/// A successful tool result carrying one text block.
fn ok(text: String) -> Json {
    Json::object([(
        "content",
        Json::array([Json::object([
            ("type", Json::string("text")),
            ("text", Json::string(text)),
        ])]),
    )])
}

/// A refused tool call: the sentence, flagged as an error, still a result —
/// JSON-RPC errors are for broken protocol, not for a lamp saying no.
fn refusal(sentence: &str) -> Json {
    Json::object([
        (
            "content",
            Json::array([Json::object([
                ("type", Json::string("text")),
                ("text", Json::string(sentence)),
            ])]),
        ),
        ("isError", Json::Bool(true)),
    ])
}

/// A JSON-RPC error, for messages that were never a usable call.
fn error(id: Json, code: i64, message: &str) -> Json {
    Json::object([
        ("jsonrpc", Json::string("2.0")),
        ("id", id),
        (
            "error",
            Json::object([
                ("code", Json::Number(code as f64)),
                ("message", Json::string(message)),
            ]),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{Capability, Device, Kind, Power, State};

    /// A hub with one recording light, for driving the surface without a network.
    fn hub() -> Arc<Hub> {
        let mut light = Device::new(DeviceId::from_wire("wiz:aabbccddeeff"), "Desk lamp", Kind::Light);
        light.reachable = true;
        light.capabilities = vec![Capability::Power, Capability::Brightness, Capability::Color];
        light.state = State { power: Some(Power::On), ..State::default() };
        Arc::new(Hub::for_test(vec![light]))
    }

    async fn reply(line: &str, hub: &Hub) -> Json {
        answer(line, hub).await.expect("a request with an id gets an answer")
    }

    #[tokio::test]
    async fn the_handshake_names_the_server() {
        let got = reply(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#, &hub()).await;
        let text = got.to_text();
        assert!(text.contains("selfhost-home"), "{text}");
        assert!(text.contains(PROTOCOL), "{text}");
    }

    #[tokio::test]
    async fn a_notification_gets_silence() {
        assert_eq!(answer(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#, &hub()).await, None);
    }

    #[tokio::test]
    async fn the_tools_are_listed() {
        let got = reply(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#, &hub()).await.to_text();
        assert!(got.contains(r#""name":"house""#), "{got}");
        assert!(got.contains(r#""name":"command""#), "{got}");
    }

    /// The whole path: a command by device *name*, through api::command, to
    /// the hub's log, answered with the device's state.
    #[tokio::test]
    async fn a_command_by_name_reaches_the_device() {
        let hub = hub();
        let line = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"command","arguments":{"device":"desk LAMP","command":"color","value":"0800FF"}}}"#;
        let got = reply(line, &hub).await.to_text();
        assert!(!got.contains(r#""isError""#), "{got}");
        let performed = hub.performed();
        assert_eq!(performed.len(), 1);
        assert_eq!(performed[0].0.as_str(), "wiz:aabbccddeeff");
    }

    #[tokio::test]
    async fn a_command_a_device_cannot_do_is_refused_in_a_sentence() {
        let line = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"command","arguments":{"device":"Desk lamp","command":"play"}}}"#;
        let got = reply(line, &hub()).await.to_text();
        assert!(got.contains(r#""isError":true"#), "{got}");
        assert!(got.contains("cannot be asked"), "{got}");
    }

    #[tokio::test]
    async fn an_unknown_device_is_refused_in_a_sentence() {
        let line = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"command","arguments":{"device":"garage door","command":"on"}}}"#;
        let got = reply(line, &hub()).await.to_text();
        assert!(got.contains("no device with that name"), "{got}");
    }

    #[tokio::test]
    async fn an_unknown_method_is_a_jsonrpc_error() {
        let got = reply(r#"{"jsonrpc":"2.0","id":6,"method":"resources/list"}"#, &hub()).await.to_text();
        assert!(got.contains("-32601"), "{got}");
    }
}
