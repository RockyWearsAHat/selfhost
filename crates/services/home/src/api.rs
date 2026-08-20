//! The shape the browser sees, and the vocabulary it may speak back.
//!
//! This module is the contract, and it is pure so that the contract can be
//! tested without a network, a speaker, or a browser. Rendering a [`Device`]
//! to JSON and reading a [`Command`] out of a request body are the two halves,
//! and they are written next to each other deliberately: a field added to one
//! and forgotten in the other is the commonest way an interface and its server
//! drift apart, and here the drift is visible in one screen.
//!
//! Two decisions are load-bearing.
//!
//! **Absent is not zero.** Every optional field is emitted as `null` rather
//! than as a default, because the page draws a volume slider only when the
//! device reported a volume. A `0` standing in for "did not say" is how a
//! dashboard ends up showing every speaker silent.
//!
//! **The command vocabulary is closed and capability-gated.** [`act`] parses a
//! body into an [`Act`] — a device [`Command`], or one of the registry words
//! (`rename`, `room`, `hide`, `show`) — and nothing else; whether a device
//! command may be *performed* is [`Device::admits`]'s question, asked
//! afterwards by the caller. Parsing and permission are separate so that an
//! unknown command and a forbidden one produce different sentences — "no such
//! command" and "a speaker cannot change colour" are different problems for
//! the reader.

use crate::device::{Command, Device, DeviceId, Key};
use selfhost_json::Json;

/// Renders the whole house.
///
/// `generation` is a counter the hub increments whenever anything at all
/// changes. The page compares it with the last one it drew and skips the
/// render when it has not moved, which is what lets the poll run every second
/// without the interface repainting every second.
#[must_use]
pub fn house(generation: u64, at: &str, devices: &[Device]) -> Json {
    Json::object([
        ("generation", Json::Number(generation as f64)),
        ("at", Json::string(at)),
        ("devices", Json::array(devices.iter().map(device))),
    ])
}

/// Renders one device.
#[must_use]
pub fn device(device: &Device) -> Json {
    Json::object([
        ("id", Json::string(device.id.as_str())),
        ("name", Json::string(&device.name)),
        ("room", optional_string(device.room.as_deref())),
        ("kind", Json::string(device.kind.as_str())),
        ("driver", Json::string(device.id.driver())),
        ("address", optional_string(device.address.as_deref())),
        ("reachable", Json::Bool(device.reachable)),
        (
            "capabilities",
            Json::array(device.capabilities.iter().map(|c| Json::string(c.as_str()))),
        ),
        ("note", optional_string(device.note.as_deref())),
        ("state", state(device)),
    ])
}

/// Renders a device's state, every field present, absent ones as `null`.
///
/// Emitting the full set of keys even when they are null costs a few hundred
/// bytes and buys the page the right to read `state.volume` without first
/// asking whether the key exists — which is the difference between a render
/// function and a render function full of guards.
fn state(device: &Device) -> Json {
    let state = &device.state;
    Json::object([
        (
            "transport",
            state.transport.map_or(Json::Null, |t| Json::string(t.as_str())),
        ),
        ("volume", optional_number(state.volume.map(u64::from))),
        ("muted", state.muted.map_or(Json::Null, Json::Bool)),
        ("power", state.power.map_or(Json::Null, |p| Json::string(p.as_str()))),
        ("brightness", optional_number(state.brightness.map(u64::from))),
        ("color", optional_string(state.color.as_deref())),
        ("color_temp", optional_number(state.color_temp.map(u64::from))),
        ("title", optional_string(state.title.as_deref())),
        ("artist", optional_string(state.artist.as_deref())),
        ("source", optional_string(state.source.as_deref())),
        ("duration_secs", optional_number(state.duration_secs.map(u64::from))),
        ("position_secs", optional_number(state.position_secs.map(u64::from))),
        (
            "coordinator",
            state.coordinator.as_ref().map_or(Json::Null, |id| Json::string(id.as_str())),
        ),
        (
            "group",
            Json::array(state.group.iter().map(|id| Json::string(id.as_str()))),
        ),
        ("battery_pct", optional_number(state.battery_pct.map(u64::from))),
        (
            "battery_charging",
            state.battery_charging.map_or(Json::Null, Json::Bool),
        ),
        ("app", optional_string(state.app.as_deref())),
    ])
}

fn optional_string(value: Option<&str>) -> Json {
    value.map_or(Json::Null, Json::string)
}

fn optional_number(value: Option<u64>) -> Json {
    value.map_or(Json::Null, |n| Json::Number(n as f64))
}

/// Why a command body could not be turned into a command.
///
/// Each variant becomes a sentence the reader sees, so the enum is shaped
/// around what a person can act on rather than around where the parse failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The body was not a JSON object.
    NotAnObject,
    /// No `command` key, or it was not a string.
    NoCommand,
    /// A command word nothing here implements.
    UnknownCommand(String),
    /// The command needs a value and it was missing or the wrong type.
    BadValue(&'static str),
}

impl Refusal {
    /// The sentence shown to the reader.
    #[must_use]
    pub fn sentence(&self) -> String {
        match self {
            Refusal::NotAnObject => "The request body must be a JSON object.".to_owned(),
            Refusal::NoCommand => "The request must name a command.".to_owned(),
            Refusal::UnknownCommand(word) => format!("There is no command called {word:?}."),
            Refusal::BadValue(what) => format!("This command needs {what}."),
        }
    }
}

/// Reads a command out of a request body.
///
/// Numbers are clamped rather than refused — a slider that sends 101 means
/// "loudest", and an error teaches nobody anything — but a *missing* number is
/// refused, because that is a caller bug rather than an edge.
pub fn command(body: &Json) -> Result<Command, Refusal> {
    if !matches!(body, Json::Object(_)) {
        return Err(Refusal::NotAnObject);
    }
    let word = body.get("command").and_then(Json::as_str).ok_or(Refusal::NoCommand)?;

    // An agent client whose tool schema leaves `value` untyped may quote the
    // number — `"50"` for 50 — and the digits are the caller's intent either
    // way, so a numeric or boolean string is read as its value rather than
    // refused for its quotes.
    let integer = |field: &str| -> Option<i64> {
        let value = body.get(field)?;
        value
            .as_i64()
            .or_else(|| value.as_str().and_then(|s| s.trim().parse::<f64>().ok().map(|f| f.round() as i64)))
    };
    let percent = || -> Result<u8, Refusal> {
        integer("value")
            .map(|v| crate::device::clamp_percent(v as i32))
            .ok_or(Refusal::BadValue("a value between 0 and 100"))
    };
    let flag = || -> Result<bool, Refusal> {
        body.get("value")
            .and_then(|v| v.as_bool().or_else(|| v.as_str().and_then(|s| s.trim().parse().ok())))
            .ok_or(Refusal::BadValue("a true or false value"))
    };

    let command = match word {
        "play" => Command::Play,
        "pause" => Command::Pause,
        "stop" => Command::Stop,
        "next" => Command::Next,
        "previous" => Command::Previous,
        "volume" => Command::Volume(percent()?),
        "volume_step" => {
            let delta = integer("delta").ok_or(Refusal::BadValue("a delta to change the volume by"))?;
            // Clamped to a sane single step so a malformed request cannot ask
            // for a jump of thousands, which the driver would then have to
            // clamp anyway — better to bound it where the number enters.
            Command::VolumeStep(delta.clamp(-100, 100) as i16)
        }
        "mute" => Command::Mute(flag()?),
        "join" => {
            let target = body
                .get("target")
                .and_then(Json::as_str)
                .ok_or(Refusal::BadValue("the device to join"))?;
            Command::Join(DeviceId::from_wire(target))
        }
        "leave" => Command::Leave,
        "power" => Command::Power(flag()?),
        "on" => Command::Power(true),
        "off" => Command::Power(false),
        "brightness" => Command::Brightness(percent()?),
        "color" => {
            let value = body
                .get("value")
                .and_then(Json::as_str)
                .ok_or(Refusal::BadValue("a colour as RRGGBB"))?;
            let clean = value.trim_start_matches('#').to_ascii_uppercase();
            if clean.len() != 6 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(Refusal::BadValue("a colour as six hex digits, RRGGBB"));
            }
            Command::Color(clean)
        }
        "color_temp" => {
            let kelvin = integer("value").ok_or(Refusal::BadValue("a colour temperature in kelvin"))?;
            // The union of what the lamps in this world accept; a value
            // outside it is saturated rather than refused, for the same reason
            // a percentage is.
            Command::ColorTemp(kelvin.clamp(1800, 6500) as u16)
        }
        "key" => {
            let name = body
                .get("name")
                .and_then(Json::as_str)
                .ok_or(Refusal::BadValue("the name of a key"))?;
            Key::parse(name)
                .map(Command::Key)
                .ok_or(Refusal::BadValue("the name of a key this understands"))?
        }
        "launch" => {
            let app = body
                .get("app")
                .and_then(Json::as_str)
                .ok_or(Refusal::BadValue("the application to launch"))?;
            Command::Launch(app.to_owned())
        }
        other => return Err(Refusal::UnknownCommand(other.to_owned())),
    };
    Ok(command)
}

/// One thing a request may ask for: a device command, or a write to the
/// house's memory.
///
/// The registry acts live beside [`Command`] rather than inside it because
/// they are not capability-gated — a lamp does not advertise "can be renamed";
/// the name is the person's, kept by the registry, and clearing it just lets
/// the protocol's own name show through again.
#[derive(Debug, Clone, PartialEq)]
pub enum Act {
    /// Ask the device itself to do one thing.
    Command(Command),
    /// Name the device, or clear the name back to what its protocol says.
    Rename(Option<String>),
    /// Move the device to a room, or clear the room.
    Room(Option<String>),
    /// Hide the device from the house, or show it again.
    Hide(bool),
    /// Ask the device to put a pairing PIN on its own screen.
    ///
    /// Not a command to a device that can already be driven: it is how a
    /// device *becomes* drivable, which is why it sits here beside the
    /// registry words rather than in [`Command`], and why it is not
    /// capability-gated. A television advertises no "can be paired".
    Pair,
    /// Hand back the PIN a person read off the screen, completing the pairing.
    PairConfirm(String),
}

/// Reads an act out of a request body: the registry words, or a [`Command`].
///
/// This is the whole vocabulary both surfaces speak — the HTTP command route
/// and the MCP `command` tool call this, not [`command`], so the registry
/// finally has a door. For `rename` and `room`, an absent, null or empty
/// `value` means "clear": the difference between "call it nothing" and "stop
/// calling it anything" does not exist for a person, so it does not exist
/// here.
pub fn act(body: &Json) -> Result<Act, Refusal> {
    if !matches!(body, Json::Object(_)) {
        return Err(Refusal::NotAnObject);
    }
    let word = body.get("command").and_then(Json::as_str).ok_or(Refusal::NoCommand)?;

    let cleared = || -> Option<String> {
        body.get("value")
            .and_then(Json::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };

    let act = match word {
        "rename" => Act::Rename(cleared()),
        "room" => Act::Room(cleared()),
        // `hide` and `show` are spellings of one act, exactly as `on` and
        // `off` are spellings of `power`.
        "hide" => Act::Hide(true),
        "show" => Act::Hide(false),
        "pair" => Act::Pair,
        // The PIN is four digits a person copied off a screen, so it is
        // trimmed and its emptiness is a refusal rather than a cleared value —
        // unlike `rename`, "pair with no PIN" is not a thing anybody means.
        "pair_confirm" => Act::PairConfirm(
            cleared().ok_or(Refusal::BadValue("the PIN shown on the television"))?,
        ),
        _ => Act::Command(command(body)?),
    };
    Ok(act)
}

/// The body returned when a command was accepted.
#[must_use]
pub fn accepted() -> Json {
    Json::object([("ok", Json::Bool(true))])
}

/// The body returned when something was refused, carrying a sentence.
#[must_use]
pub fn refused(sentence: &str) -> Json {
    Json::object([("error", Json::string(sentence))])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{Capability, Kind, State, Transport};

    fn speaker() -> Device {
        let mut device = Device::new(
            DeviceId::new("sonos", "RINCON_7828CA1491AE01400"),
            "Kitchen",
            Kind::Speaker,
        )
        .advertise(&[
            Capability::Transport,
            Capability::Volume,
            Capability::Mute,
            Capability::Group,
        ]);
        device.reachable = true;
        device.address = Some("192.168.1.6".into());
        device.room = Some("Kitchen".into());
        device.state = State {
            transport: Some(Transport::Playing),
            volume: Some(9),
            muted: Some(false),
            title: Some("Reject".into()),
            artist: Some("Nacho Sotomayor".into()),
            ..State::default()
        };
        device
    }

    #[test]
    fn a_device_renders_every_field_the_page_reads() {
        let json = device(&speaker());
        assert_eq!(json.get("id").and_then(Json::as_str), Some("sonos:rincon_7828ca1491ae01400"));
        assert_eq!(json.get("name").and_then(Json::as_str), Some("Kitchen"));
        assert_eq!(json.get("driver").and_then(Json::as_str), Some("sonos"));
        assert_eq!(json.get("kind").and_then(Json::as_str), Some("speaker"));
        assert_eq!(json.get("reachable").and_then(Json::as_bool), Some(true));
        let state = json.get("state").expect("a state object");
        assert_eq!(state.get("transport").and_then(Json::as_str), Some("playing"));
        assert_eq!(state.get("volume").and_then(Json::as_u64), Some(9));
    }

    /// The page reads `state.volume` without guarding, so every key must be
    /// present even when there is nothing to say.
    #[test]
    fn an_unknown_field_is_null_and_not_absent() {
        let bare = Device::new(DeviceId::new("wyze", "lamp"), "Lamp", Kind::Light);
        let json = device(&bare);
        let state = json.get("state").expect("a state object");
        for key in ["transport", "volume", "muted", "brightness", "color", "title", "battery_pct"] {
            let value = state.get(key).unwrap_or_else(|| panic!("{key} must be present"));
            assert!(value.is_null(), "{key} should be null, not absent or defaulted");
        }
    }

    /// A volume of zero and an unknown volume are different facts, and a
    /// dashboard that renders the second as the first is lying.
    #[test]
    fn a_volume_of_zero_is_not_the_same_as_no_volume() {
        let mut silent = speaker();
        silent.state.volume = Some(0);
        let json = device(&silent);
        assert_eq!(json.get("state").unwrap().get("volume").and_then(Json::as_u64), Some(0));

        let mut unknown = speaker();
        unknown.state.volume = None;
        let json = device(&unknown);
        assert!(json.get("state").unwrap().get("volume").unwrap().is_null());
    }

    #[test]
    fn the_house_carries_its_generation() {
        let json = house(42, "2026-08-17T19:20:00Z", &[speaker()]);
        assert_eq!(json.get("generation").and_then(Json::as_u64), Some(42));
        assert_eq!(json.get("at").and_then(Json::as_str), Some("2026-08-17T19:20:00Z"));
        assert_eq!(json.get("devices").and_then(Json::as_array).map(<[Json]>::len), Some(1));
    }

    fn parse(text: &str) -> Result<Command, Refusal> {
        command(&selfhost_json::parse(text).expect("valid JSON in a test"))
    }

    #[test]
    fn every_transport_word_parses() {
        assert_eq!(parse(r#"{"command":"play"}"#), Ok(Command::Play));
        assert_eq!(parse(r#"{"command":"pause"}"#), Ok(Command::Pause));
        assert_eq!(parse(r#"{"command":"stop"}"#), Ok(Command::Stop));
        assert_eq!(parse(r#"{"command":"next"}"#), Ok(Command::Next));
        assert_eq!(parse(r#"{"command":"previous"}"#), Ok(Command::Previous));
    }

    #[test]
    fn a_volume_is_read_and_clamped() {
        assert_eq!(parse(r#"{"command":"volume","value":25}"#), Ok(Command::Volume(25)));
        assert_eq!(parse(r#"{"command":"volume","value":150}"#), Ok(Command::Volume(100)));
        assert_eq!(parse(r#"{"command":"volume","value":-5}"#), Ok(Command::Volume(0)));
    }

    /// A missing number is a caller bug, unlike an out-of-range one.
    #[test]
    fn a_volume_with_no_value_is_refused() {
        assert!(matches!(parse(r#"{"command":"volume"}"#), Err(Refusal::BadValue(_))));
    }

    /// An agent client whose schema leaves `value` untyped sends `"50"` for
    /// 50; the quotes are the client's accident, not the caller's intent.
    #[test]
    fn a_quoted_number_or_boolean_is_read_as_its_value() {
        assert_eq!(parse(r#"{"command":"brightness","value":"50"}"#), Ok(Command::Brightness(50)));
        assert_eq!(parse(r#"{"command":"brightness","value":"50.0"}"#), Ok(Command::Brightness(50)));
        assert_eq!(parse(r#"{"command":"color_temp","value":"2700"}"#), Ok(Command::ColorTemp(2700)));
        assert_eq!(parse(r#"{"command":"volume_step","delta":"-5"}"#), Ok(Command::VolumeStep(-5)));
        assert_eq!(parse(r#"{"command":"power","value":"true"}"#), Ok(Command::Power(true)));
        assert!(matches!(parse(r#"{"command":"brightness","value":"bright"}"#), Err(Refusal::BadValue(_))));
    }

    #[test]
    fn a_colour_is_normalised_and_validated() {
        assert_eq!(parse(r##"{"command":"color","value":"#ff8800"}"##), Ok(Command::Color("FF8800".into())));
        assert_eq!(parse(r#"{"command":"color","value":"ff8800"}"#), Ok(Command::Color("FF8800".into())));
        assert!(matches!(parse(r#"{"command":"color","value":"orange"}"#), Err(Refusal::BadValue(_))));
        assert!(matches!(parse(r#"{"command":"color","value":"FF88"}"#), Err(Refusal::BadValue(_))));
    }

    #[test]
    fn on_and_off_are_spellings_of_power() {
        assert_eq!(parse(r#"{"command":"on"}"#), Ok(Command::Power(true)));
        assert_eq!(parse(r#"{"command":"off"}"#), Ok(Command::Power(false)));
        assert_eq!(parse(r#"{"command":"power","value":true}"#), Ok(Command::Power(true)));
    }

    #[test]
    fn a_key_is_read_by_name() {
        assert_eq!(parse(r#"{"command":"key","name":"up"}"#), Ok(Command::Key(Key::Up)));
        assert!(matches!(parse(r#"{"command":"key","name":"eject"}"#), Err(Refusal::BadValue(_))));
    }

    #[test]
    fn an_unknown_command_names_itself_in_the_refusal() {
        let refusal = parse(r#"{"command":"self_destruct"}"#).expect_err("must refuse");
        assert_eq!(refusal, Refusal::UnknownCommand("self_destruct".into()));
        assert!(refusal.sentence().contains("self_destruct"));
    }

    #[test]
    fn a_body_that_is_not_an_object_is_refused() {
        assert_eq!(parse("[1,2,3]"), Err(Refusal::NotAnObject));
        assert_eq!(parse("\"play\""), Err(Refusal::NotAnObject));
    }

    #[test]
    fn a_join_carries_the_device_it_names() {
        assert_eq!(
            parse(r#"{"command":"join","target":"sonos:rincon_a"}"#),
            Ok(Command::Join(DeviceId::from_wire("sonos:rincon_a")))
        );
    }

    fn parse_act(text: &str) -> Result<Act, Refusal> {
        act(&selfhost_json::parse(text).expect("valid JSON in a test"))
    }

    #[test]
    fn the_registry_words_parse_as_acts() {
        assert_eq!(
            parse_act(r#"{"command":"rename","value":"Porch"}"#),
            Ok(Act::Rename(Some("Porch".into())))
        );
        assert_eq!(
            parse_act(r#"{"command":"room","value":"Kitchen"}"#),
            Ok(Act::Room(Some("Kitchen".into())))
        );
        assert_eq!(parse_act(r#"{"command":"hide"}"#), Ok(Act::Hide(true)));
        assert_eq!(parse_act(r#"{"command":"show"}"#), Ok(Act::Hide(false)));
    }

    /// Pairing is two words, and the second needs its PIN. An empty PIN is a
    /// refusal rather than a cleared value: unlike a name, "pair with no PIN"
    /// is not something a person can mean.
    #[test]
    fn pairing_is_two_words_and_the_pin_is_required() {
        assert_eq!(parse_act(r#"{"command":"pair"}"#), Ok(Act::Pair));
        assert_eq!(
            parse_act(r#"{"command":"pair_confirm","value":"2275"}"#),
            Ok(Act::PairConfirm("2275".to_owned()))
        );
        // Read off a screen and typed by hand, so it arrives with whitespace.
        assert_eq!(
            parse_act(r#"{"command":"pair_confirm","value":" 2275 "}"#),
            Ok(Act::PairConfirm("2275".to_owned()))
        );
        assert!(matches!(
            parse_act(r#"{"command":"pair_confirm"}"#),
            Err(Refusal::BadValue(_))
        ));
        assert!(matches!(
            parse_act(r#"{"command":"pair_confirm","value":""}"#),
            Err(Refusal::BadValue(_))
        ));
    }

    /// Absent, empty and blank are all "clear" — the difference between "call
    /// it nothing" and "stop calling it anything" does not exist for a person.
    #[test]
    fn an_empty_rename_clears_rather_than_naming_nothing() {
        assert_eq!(parse_act(r#"{"command":"rename"}"#), Ok(Act::Rename(None)));
        assert_eq!(parse_act(r#"{"command":"rename","value":""}"#), Ok(Act::Rename(None)));
        assert_eq!(parse_act(r#"{"command":"room","value":"  "}"#), Ok(Act::Room(None)));
    }

    /// `act` wraps `command` rather than replacing it: every device word still
    /// parses, and an unknown word still refuses by name.
    #[test]
    fn every_device_command_still_parses_through_act() {
        assert_eq!(parse_act(r#"{"command":"play"}"#), Ok(Act::Command(Command::Play)));
        assert_eq!(
            parse_act(r#"{"command":"volume","value":25}"#),
            Ok(Act::Command(Command::Volume(25)))
        );
        assert!(matches!(
            parse_act(r#"{"command":"self_destruct"}"#),
            Err(Refusal::UnknownCommand(_))
        ));
    }

    /// Parsing succeeds for a command the target cannot perform; permission is
    /// a separate question, asked by the caller, so the two produce different
    /// sentences.
    #[test]
    fn parsing_does_not_decide_permission() {
        let command = parse(r#"{"command":"color","value":"FF0000"}"#).expect("parses");
        let speaker = speaker();
        assert!(!speaker.admits(&command));
    }
}
