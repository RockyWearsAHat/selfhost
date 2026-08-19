//! The WiZ driver: Wi-Fi lights spoken to directly, in JSON over UDP.
//!
//! WiZ (Signify's no-hub brand, sold both under its own name and as
//! Philips-branded "WiZ connected" bulbs) is the simplest protocol in this
//! crate: every bulb runs a JSON-RPC-shaped server on UDP port [`PORT`], with
//! no authentication, no pairing and no session. `getPilot` reads the light's
//! state, `setPilot` writes it, `getSystemConfig` names the hardware — and a
//! `getPilot` sent to the broadcast address is also the discovery mechanism,
//! because every bulb on the subnet answers it. One port, three methods,
//! nothing else.
//!
//! # What decides a bulb's capabilities
//!
//! The protocol does not advertise capabilities; the module name in
//! `getSystemConfig` implies them. WiZ module names carry a family code —
//! `ESP25_SHRGB_01` and kin — whose middle segment says what the light can do:
//! `RGB` is full colour plus tunable white, `TW` is tunable white only, `DW`
//! is dimmable white only, and `SOCKET` is a switched outlet with no light in
//! it at all. [`capabilities_of`] reads that segment and nothing else, and an
//! unrecognised module falls back to power-and-brightness — every WiZ light
//! dims, and a new family code should appear as a dimmable light rather than
//! as nothing.
//!
//! # Why the state carries either a colour or a temperature, never both
//!
//! A WiZ bulb is always in exactly one mode: colour (the `r`/`g`/`b` fields
//! are present in the pilot) or white (the `temp` field is). The page gets the
//! same shape: `color` set and `color_temp` empty, or the reverse. Reporting a
//! stale temperature alongside a live colour would show two contradictory
//! swatches for one bulb.
//!
//! # The parts a test cannot reach
//!
//! Everything above the socket is pure and proved against datagrams captured
//! from the four real bulbs in this house on 2026-08-18. The socket half is
//! four small functions, and the live acceptance suite
//! (`tests/live_wiz.rs`, `#[ignore]`d) walks them against the real hardware
//! with the same restore discipline the Sonos suite uses.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use selfhost_json::Json;
use tokio::net::UdpSocket;

use crate::device::{Capability, Command, Device, DeviceId, Kind, Power};

/// The driver's name, and the first half of every device id it produces.
pub const DRIVER: &str = "wiz";

/// The UDP port every WiZ device serves its JSON protocol on.
pub const PORT: u16 = 38899;

/// How long one request may wait for its answer before the attempt fails.
///
/// A bulb on the same network answers in single-digit milliseconds; a second
/// is only ever spent in full against a bulb that is gone, and the refresh
/// loop must not stall behind it.
const ANSWER_BUDGET: Duration = Duration::from_secs(1);

/// How many times a request is sent before the bulb counts as not answering.
///
/// Two, not one, because this is UDP on wireless: a single lost datagram in
/// either direction reads exactly like an absent bulb, and marking a light
/// unreachable over one dropped packet makes the dashboard flicker. Two, not
/// five, because a genuinely absent bulb costs the full budget per attempt.
const ATTEMPTS: u32 = 2;

/// How many times the discovery broadcast is sent across the caller's window.
///
/// The same reasoning as SSDP's bursts in [`crate::discovery`]: broadcast is
/// unacknowledged, one datagram misses a bulb now and then, and a missing
/// light is worse than a slow sweep.
const BURSTS: u32 = 3;

/// The largest response worth reading. Real pilots and configs are a few
/// hundred bytes; a fixed buffer means a hostile datagram cannot make a sweep
/// allocate.
const DATAGRAM_LIMIT: usize = 4096;

/// The lowest brightness a WiZ bulb accepts.
///
/// The firmware refuses `dimming` below 10 on several module families rather
/// than clamping it, so the driver clamps before sending: a slider dragged to
/// 3 means "very dim", and refusing it teaches nobody anything.
const DIMMING_FLOOR: u8 = 10;

/// The white-temperature range accepted across WiZ module families, in
/// kelvin. Individual bulbs may be narrower (the `cctRange` in their model
/// config); the bulb clamps the remainder itself.
const TEMP_RANGE: std::ops::RangeInclusive<u16> = 2200..=6500;

/// The id a bulb's MAC maps to.
///
/// The MAC is the one identity the protocol repeats in every single response,
/// and it survives a DHCP lease where the address does not.
#[must_use]
pub fn id_of(mac: &str) -> DeviceId {
    DeviceId::new(DRIVER, mac)
}

/// Everything a `getPilot` response says about a light.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pilot {
    /// The bulb's MAC, lowercase hex, no separators — its stable identity.
    pub mac: String,
    /// Whether the light is on.
    pub on: bool,
    /// Brightness, 0–100.
    pub dimming: Option<u8>,
    /// White temperature in kelvin, when the bulb is in white mode.
    pub temp: Option<u16>,
    /// Colour as `RRGGBB`, when the bulb is in colour mode.
    pub color: Option<String>,
}

/// What `getSystemConfig` says about the hardware.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemConfig {
    /// The bulb's MAC, matching [`Pilot::mac`].
    pub mac: String,
    /// The module family name, e.g. `ESP25_SHRGB_01`.
    pub module: String,
    /// The firmware version, e.g. `1.38.0`.
    pub firmware: Option<String>,
}

/// Builds the one request body a method with no parameters needs.
#[must_use]
pub fn request(method: &str) -> String {
    Json::object([
        ("method", Json::string(method)),
        ("params", Json::Object(BTreeMap::new())),
    ])
    .to_text()
}

/// Builds the `setPilot` body for one command, or says why it cannot.
///
/// Pure, so every command's exact wire shape is a test against a string
/// rather than a bulb. The error is a sentence because it travels to the
/// reader verbatim.
pub fn set_pilot(command: &Command) -> Result<String, String> {
    let params = match command {
        Command::Power(on) => Json::object([("state", Json::Bool(*on))]),
        Command::Brightness(level) => Json::object([(
            "dimming",
            Json::Number(f64::from((*level).max(DIMMING_FLOOR).min(100))),
        )]),
        Command::ColorTemp(kelvin) => Json::object([(
            "temp",
            Json::Number(f64::from(
                (*kelvin).clamp(*TEMP_RANGE.start(), *TEMP_RANGE.end()),
            )),
        )]),
        Command::Color(hex) => {
            // The screen's colour is translated to LED duties — gamma,
            // correction matrix, white extraction — in `color`, not sent raw;
            // see that module for the calibration. Both white channels are
            // written every time so a leftover white from a previous state
            // can never tint the new colour.
            let duties = crate::color::duties_of(hex)
                .ok_or_else(|| format!("\"{hex}\" is not a colour — RRGGBB is the shape."))?;
            Json::object([
                ("r", Json::Number(f64::from(duties.r))),
                ("g", Json::Number(f64::from(duties.g))),
                ("b", Json::Number(f64::from(duties.b))),
                ("c", Json::Number(f64::from(duties.white))),
                ("w", Json::Number(0.0)),
                // Darkness rides here so the chroma keeps full duty
                // resolution — see the color module.
                ("dimming", Json::Number(f64::from(duties.dimming))),
            ])
        }
        other => {
            return Err(format!(
                "A WiZ light cannot be asked to {}.",
                other.as_str().replace('_', " ")
            ))
        }
    };
    Ok(Json::object([("method", Json::string("setPilot")), ("params", params)]).to_text())
}

/// Reads a `getPilot` response, or decides it is not one.
///
/// Tolerant of extra fields on purpose: firmware adds them between versions,
/// and a new field must never blank a working light. Only a missing MAC or a
/// missing `state` refuses the datagram, because without those there is
/// nothing true to record.
#[must_use]
pub fn parse_pilot(text: &str) -> Option<Pilot> {
    let json = selfhost_json::parse(text).ok()?;
    let result = json.get("result")?;
    let mac = result.get("mac")?.as_str()?.to_ascii_lowercase();
    let on = result.get("state")?.as_bool()?;

    let byte = |key: &str| result.get(key).and_then(Json::as_u64).map(|v| v.min(255) as u8);
    // The swatch shows what the light looks like, so raw duties run backwards
    // through the calibration in `color` — including the cold-white channel,
    // which desaturates whatever the colour LEDs are doing.
    let dimming = result.get("dimming").and_then(Json::as_u64).map(|v| v.min(100) as u8);
    let color = match (byte("r"), byte("g"), byte("b")) {
        (Some(r), Some(g), Some(b)) => {
            Some(crate::color::hex_of(r, g, b, byte("c").unwrap_or(0), dimming.unwrap_or(100)))
        }
        _ => None,
    };
    // A pilot in colour mode still carries the last white temperature on some
    // firmware; the mode the bulb is actually in is the one the page gets.
    let temp = if color.is_some() {
        None
    } else {
        result.get("temp").and_then(Json::as_u64).map(|v| v.min(u64::from(u16::MAX)) as u16)
    };

    Some(Pilot {
        mac,
        on,
        dimming,
        temp,
        color,
    })
}

/// Reads a `getSystemConfig` response, or decides it is not one.
#[must_use]
pub fn parse_system_config(text: &str) -> Option<SystemConfig> {
    let json = selfhost_json::parse(text).ok()?;
    let result = json.get("result")?;
    Some(SystemConfig {
        mac: result.get("mac")?.as_str()?.to_ascii_lowercase(),
        module: result.get("moduleName")?.as_str()?.to_owned(),
        firmware: result.get("fwVersion").and_then(Json::as_str).map(str::to_owned),
    })
}

/// Whether a `setPilot` response reports the write landing.
#[must_use]
pub fn set_succeeded(text: &str) -> bool {
    selfhost_json::parse(text)
        .ok()
        .and_then(|json| json.get("result")?.get("success")?.as_bool())
        == Some(true)
}

/// What a module family name says the light can do, and what kind it is.
///
/// The fallback for an unrecognised family is deliberately power and
/// brightness rather than nothing: every WiZ light dims, and a family code
/// this function has not met should appear as a dimmable light, not vanish.
#[must_use]
pub fn capabilities_of(module: &str) -> (Kind, Vec<Capability>) {
    let module = module.to_ascii_uppercase();
    if module.contains("SOCKET") {
        return (Kind::Plug, vec![Capability::Power]);
    }
    let capabilities = if module.contains("RGB") {
        vec![Capability::Power, Capability::Brightness, Capability::Color, Capability::ColorTemp]
    } else if module.contains("TW") {
        vec![Capability::Power, Capability::Brightness, Capability::ColorTemp]
    } else {
        vec![Capability::Power, Capability::Brightness]
    };
    (Kind::Light, capabilities)
}

/// Builds a device from what discovery learned about one bulb.
///
/// The name is `WiZ light` plus the MAC's tail, because the protocol carries
/// no friendly name — the name a person gave the bulb lives in WiZ's app and
/// cloud, which this driver never touches. The registry's rename is the
/// supported way to a real name, and the tail keeps four identical bulbs
/// tellable apart until somebody does.
#[must_use]
pub fn device_from(pilot: &Pilot, config: Option<&SystemConfig>, address: &str) -> Device {
    let (kind, capabilities) = config
        .map(|config| capabilities_of(&config.module))
        .unwrap_or_else(|| (Kind::Light, vec![Capability::Power, Capability::Brightness]));

    let tail = &pilot.mac[pilot.mac.len().saturating_sub(4)..];
    let noun = if kind == Kind::Plug { "plug" } else { "light" };
    let mut device = Device::new(id_of(&pilot.mac), format!("WiZ {noun} {tail}"), kind)
        .advertise(&capabilities);
    device.address = Some(address.to_owned());
    device.reachable = true;
    apply_pilot(&mut device, pilot);
    device
}

/// Writes a pilot's facts into a device's state.
fn apply_pilot(device: &mut Device, pilot: &Pilot) {
    device.state.power = Some(if pilot.on { Power::On } else { Power::Off });
    device.state.brightness = pilot.dimming;
    device.state.color = pilot.color.clone();
    device.state.color_temp = pilot.temp;
}

/// Sends one request and returns the answer's text.
///
/// A fresh socket per call, exactly as [`crate::soap`] opens a fresh TCP
/// connection per call: the cost is nothing on a LAN and there is no
/// connection state to go stale. Retried once because UDP on wireless loses
/// the odd datagram, and one loss must not read as an absent bulb.
async fn call(address: &str, body: &str) -> Result<String, String> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|error| format!("no UDP socket to send from: {error}"))?;
    let mut buffer = vec![0_u8; DATAGRAM_LIMIT];
    for _ in 0..ATTEMPTS {
        if socket.send_to(body.as_bytes(), (address, PORT)).await.is_err() {
            continue;
        }
        if let Ok(Ok((length, _))) =
            tokio::time::timeout(ANSWER_BUDGET, socket.recv_from(&mut buffer)).await
        {
            return Ok(String::from_utf8_lossy(&buffer[..length]).into_owned());
        }
    }
    Err(format!("no answer from {address}:{PORT} within {}s", ANSWER_BUDGET.as_secs() * u64::from(ATTEMPTS)))
}

/// Every WiZ device that answered a broadcast within the window.
///
/// The sweep is `getPilot` sent to the broadcast address — the pilot *is* the
/// discovery announcement, state included — followed by one `getSystemConfig`
/// per responder to learn what the hardware can do. A bulb whose config does
/// not answer is still returned, with the dimmable-light fallback, because a
/// light that answered its pilot is a light the house has.
///
/// Every failure path returns what was found so far rather than an error, for
/// the same reason [`crate::discovery::sweep`] cannot fail: an empty house and
/// a network that drops broadcast look identical from here, and neither is
/// something the caller can act on.
pub async fn discover(window: Duration) -> Vec<Device> {
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await else {
        return Vec::new();
    };
    if socket.set_broadcast(true).is_err() {
        return Vec::new();
    }

    // Deduplicated by MAC, not address: three bursts mean up to three answers
    // per bulb, and the MAC is the identity the pilot itself declares.
    let mut found: BTreeMap<String, (Pilot, String)> = BTreeMap::new();
    let body = request("getPilot");
    let started = Instant::now();
    let deadline = started + window;
    let spacing = window / BURSTS;

    let mut buffer = vec![0_u8; DATAGRAM_LIMIT];
    let mut sent = 0_u32;
    let mut next_burst = started;
    loop {
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        if sent < BURSTS && now >= next_burst {
            let _ = socket.send_to(body.as_bytes(), ("255.255.255.255", PORT)).await;
            sent += 1;
            next_burst = now + spacing;
            continue;
        }
        let wake = if sent < BURSTS { next_burst.min(deadline) } else { deadline };
        let slice = wake.saturating_duration_since(now);
        match tokio::time::timeout(slice, socket.recv_from(&mut buffer)).await {
            Ok(Ok((length, from))) => {
                let text = String::from_utf8_lossy(&buffer[..length.min(DATAGRAM_LIMIT)]);
                if let Some(pilot) = parse_pilot(&text) {
                    found.entry(pilot.mac.clone()).or_insert((pilot, from.ip().to_string()));
                }
            }
            Ok(Err(_)) => {}
            Err(_) => {}
        }
    }

    let mut devices = Vec::new();
    for (pilot, address) in found.values() {
        let config = match call(address, &request("getSystemConfig")).await {
            Ok(answer) => parse_system_config(&answer),
            Err(_) => None,
        };
        devices.push(device_from(pilot, config.as_ref(), address));
    }
    devices
}

/// Re-reads one light's state.
///
/// A failure marks the device unreachable and says so in a sentence, exactly
/// as the Sonos driver does: one unscrewed bulb must not fail the refresh,
/// and "did not answer" on its tile beats a blank page.
pub async fn refresh(device: &mut Device) {
    let Some(address) = device.address.clone() else {
        device.reachable = false;
        device.note = Some("This light has no address yet.".to_owned());
        return;
    };
    match call(&address, &request("getPilot")).await {
        Ok(answer) => match parse_pilot(&answer) {
            Some(pilot) => {
                device.reachable = true;
                device.note = None;
                apply_pilot(device, &pilot);
            }
            None => {
                device.reachable = false;
                device.note = Some(format!("{} answered something that is not a light's state.", device.name));
            }
        },
        Err(error) => {
            device.reachable = false;
            device.note = Some(format!("{} did not answer: {error}", device.name));
        }
    }
}

/// Performs one command against one light.
///
/// The bulb acknowledges every write with `success`, and the acknowledgement
/// is checked rather than assumed — a `setPilot` the firmware rejects answers
/// with an error object, and reporting that write as landed would leave the
/// page showing a state the bulb never took.
pub async fn perform(device: &Device, command: &Command) -> Result<(), String> {
    let address = device
        .address
        .clone()
        .ok_or_else(|| format!("{} has no address to send to.", device.name))?;
    let body = set_pilot(command)?;
    let answer = call(&address, &body)
        .await
        .map_err(|error| format!("{} did not answer: {error}", device.name))?;
    if set_succeeded(&answer) {
        Ok(())
    } else {
        Err(format!("{} refused that: {answer}", device.name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured from 192.168.1.19 on 2026-08-18 — a real bulb in white mode.
    const PILOT_WHITE: &str = r#"{"method":"getPilot","env":"pro","result":{"mac":"9877d5c238c8","rssi":-55,"state":true,"sceneId":0,"temp":2700,"dimming":100}}"#;

    /// Captured from 192.168.1.18 on 2026-08-18.
    const SYSTEM_CONFIG: &str = r#"{"method":"getSystemConfig","env":"pro","result":{"mac":"9877d5b15e48","homeId":21401862,"roomId":36311013,"rgn":"eu","moduleName":"ESP25_SHRGB_01","fwVersion":"1.38.0","groupId":0,"ping":0,"accUdpPropRate":100,"rdIdUidHash":"2bed8ff0f85ce0d68e6dfafe7646955dbe298faf1805f4dbe653cbfef5882c4a"}}"#;

    /// Captured from 192.168.1.19 on 2026-08-18 — the acknowledgement of a
    /// real write.
    const SET_OK: &str = r#"{"method":"setPilot","env":"pro","result":{"success":true}}"#;

    #[test]
    fn a_real_pilot_reads_correctly() {
        let pilot = parse_pilot(PILOT_WHITE).expect("a real pilot must parse");
        assert_eq!(pilot.mac, "9877d5c238c8");
        assert!(pilot.on);
        assert_eq!(pilot.dimming, Some(100));
        assert_eq!(pilot.temp, Some(2700));
        assert_eq!(pilot.color, None);
    }

    /// A bulb in colour mode reports its colour and not a stale temperature —
    /// the page must never show two contradictory swatches for one light.
    #[test]
    fn a_colour_pilot_reports_a_colour_and_no_temperature() {
        let text = r#"{"method":"getPilot","env":"pro","result":{"mac":"9877d5c238c8","rssi":-55,"state":true,"sceneId":0,"r":255,"g":128,"b":0,"c":0,"w":0,"temp":2700,"dimming":40}}"#;
        let pilot = parse_pilot(text).expect("must parse");
        // Raw duties (255,128,0) at dimming 40 read back through the
        // calibration inverse — the swatch reports the light, not the bytes.
        assert_eq!(pilot.color.as_deref(), Some("977C40"));
        assert_eq!(pilot.temp, None);
        assert_eq!(pilot.dimming, Some(40));
    }

    #[test]
    fn a_real_system_config_reads_correctly() {
        let config = parse_system_config(SYSTEM_CONFIG).expect("must parse");
        assert_eq!(config.mac, "9877d5b15e48");
        assert_eq!(config.module, "ESP25_SHRGB_01");
        assert_eq!(config.firmware.as_deref(), Some("1.38.0"));
    }

    #[test]
    fn a_write_acknowledgement_reads_correctly() {
        assert!(set_succeeded(SET_OK));
        assert!(!set_succeeded(r#"{"env":"pro","error":{"code":-32600,"message":"Invalid Request"}}"#));
        assert!(!set_succeeded("not json at all"));
    }

    /// Something that is not a pilot — an error object, another method's
    /// answer, junk — must not become a device.
    #[test]
    fn a_datagram_that_is_not_a_pilot_is_refused() {
        assert_eq!(parse_pilot(r#"{"env":"pro","error":{"code":-32600}}"#), None);
        assert_eq!(parse_pilot(SET_OK), None);
        assert_eq!(parse_pilot(""), None);
    }

    #[test]
    fn the_module_family_decides_the_capabilities() {
        let (kind, capabilities) = capabilities_of("ESP25_SHRGB_01");
        assert_eq!(kind, Kind::Light);
        assert_eq!(
            capabilities,
            [Capability::Power, Capability::Brightness, Capability::Color, Capability::ColorTemp]
        );

        let (_, tunable) = capabilities_of("ESP56_SHTW3_01");
        assert_eq!(tunable, [Capability::Power, Capability::Brightness, Capability::ColorTemp]);

        let (_, dimmable) = capabilities_of("ESP03_SHDW1_31");
        assert_eq!(dimmable, [Capability::Power, Capability::Brightness]);

        let (kind, socket) = capabilities_of("ESP10_SOCKET_06");
        assert_eq!(kind, Kind::Plug);
        assert_eq!(socket, [Capability::Power]);
    }

    /// A family code this driver has not met appears as a dimmable light
    /// rather than vanishing.
    #[test]
    fn an_unknown_module_family_falls_back_to_a_dimmable_light() {
        let (kind, capabilities) = capabilities_of("ESP99_NEWTHING_01");
        assert_eq!(kind, Kind::Light);
        assert_eq!(capabilities, [Capability::Power, Capability::Brightness]);
    }

    #[test]
    fn a_device_is_built_from_a_pilot_and_a_config() {
        let pilot = parse_pilot(PILOT_WHITE).expect("must parse");
        let config = parse_system_config(SYSTEM_CONFIG).expect("must parse");
        let device = device_from(&pilot, Some(&config), "192.168.1.19");
        assert_eq!(device.id.as_str(), "wiz:9877d5c238c8");
        assert_eq!(device.name, "WiZ light 38c8");
        assert_eq!(device.kind, Kind::Light);
        assert!(device.reachable);
        assert_eq!(device.address.as_deref(), Some("192.168.1.19"));
        assert_eq!(device.state.power, Some(Power::On));
        assert_eq!(device.state.brightness, Some(100));
        assert_eq!(device.state.color_temp, Some(2700));
    }

    #[test]
    fn every_command_takes_its_wire_shape() {
        assert_eq!(
            set_pilot(&Command::Power(true)).unwrap(),
            r#"{"method":"setPilot","params":{"state":true}}"#
        );
        assert_eq!(
            set_pilot(&Command::Brightness(40)).unwrap(),
            r#"{"method":"setPilot","params":{"dimming":40}}"#
        );
        assert_eq!(
            set_pilot(&Command::ColorTemp(2700)).unwrap(),
            r#"{"method":"setPilot","params":{"temp":2700}}"#
        );
        // Not the raw bytes: `FF8000` runs through the calibration in
        // `color` (gamma, matrix, white extraction) before it reaches a wire.
        assert_eq!(
            set_pilot(&Command::Color("FF8000".into())).unwrap(),
            r#"{"method":"setPilot","params":{"b":0,"c":0,"dimming":100,"g":52,"r":255,"w":0}}"#
        );
    }

    /// The firmware refuses `dimming` below 10 rather than clamping it, so
    /// the driver clamps first — a slider at 3 means "very dim", not an error.
    #[test]
    fn brightness_below_the_firmware_floor_is_clamped_up() {
        assert_eq!(
            set_pilot(&Command::Brightness(3)).unwrap(),
            r#"{"method":"setPilot","params":{"dimming":10}}"#
        );
    }

    #[test]
    fn a_temperature_outside_the_wiz_range_is_clamped_into_it() {
        assert!(set_pilot(&Command::ColorTemp(1000)).unwrap().contains("2200"));
        assert!(set_pilot(&Command::ColorTemp(9000)).unwrap().contains("6500"));
    }

    #[test]
    fn a_malformed_colour_is_refused_in_words() {
        let error = set_pilot(&Command::Color("red".into())).expect_err("must refuse");
        assert!(error.contains("RRGGBB"));
        set_pilot(&Command::Color("GGGGGG".into())).expect_err("not hex");
        set_pilot(&Command::Color("FFFFFF00".into())).expect_err("too long");
    }

    /// The hub's capability gate keeps these from arriving, but the driver
    /// still answers in a sentence rather than panicking if one ever does.
    #[test]
    fn a_command_no_light_understands_is_refused_in_words() {
        let error = set_pilot(&Command::Play).expect_err("a light has no transport");
        assert!(error.contains("cannot be asked"));
    }

    #[test]
    fn the_id_is_stable_and_url_safe() {
        assert_eq!(id_of("9877D5C238C8").as_str(), "wiz:9877d5c238c8");
    }
}
