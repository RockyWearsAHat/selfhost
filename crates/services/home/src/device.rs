//! What a device is, what it can be asked to do, and what may be asked of it.
//!
//! This module is the whole reason the interface does not know what a Sonos
//! is. A driver's output is a [`Device`] carrying a set of [`Capability`]
//! values and a [`State`]; the page renders capabilities; a [`Command`] is
//! admitted only when the device it names advertises the capability that
//! command needs. That check is here, in a pure function over a closed enum,
//! rather than in each driver — a driver that forgot it would be a device
//! answering a command it cannot perform, which is the failure mode that makes
//! a home dashboard feel unreliable.
//!
//! Everything in this module is pure and total. Nothing here opens a socket,
//! reads a clock, or fails.

use std::fmt;

/// A device's stable identity: `<driver>:<key>`.
///
/// The key is whatever the driver's own protocol calls the thing permanently —
/// a Sonos `RINCON_…` UUID, a television's MAC — and never its address, which
/// changes on a DHCP lease and would silently rename every device in the
/// house. The driver prefix keeps two protocols from colliding on a key and
/// makes the id readable in a log without a lookup.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(String);

impl DeviceId {
    /// Builds an id from a driver name and that driver's stable key.
    ///
    /// Both halves are lowercased and anything outside `[a-z0-9_.-]` becomes
    /// `-`, so an id is always safe in a URL path segment without escaping.
    /// That matters because the id *is* the path segment the command route
    /// takes, and a device name is text a stranger's firmware chose.
    #[must_use]
    pub fn new(driver: &str, key: &str) -> Self {
        let clean = |text: &str| -> String {
            text.chars()
                .map(|c| {
                    let c = c.to_ascii_lowercase();
                    if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' { c } else { '-' }
                })
                .collect()
        };
        DeviceId(format!("{}:{}", clean(driver), clean(key)))
    }

    /// The id as it travels in JSON and in a URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The driver half, for dispatching a command to the right driver.
    #[must_use]
    pub fn driver(&self) -> &str {
        self.0.split_once(':').map_or("", |(driver, _)| driver)
    }

    /// The driver's own key, for handing back to that protocol.
    #[must_use]
    pub fn key(&self) -> &str {
        self.0.split_once(':').map_or("", |(_, key)| key)
    }

    /// Rebuilds an id from a string that was already in this form.
    ///
    /// Used when a command arrives naming a device; it is not a parser and
    /// does not validate, because the id is then looked up in the registry and
    /// an unknown one is refused there — one rejection site, not two.
    #[must_use]
    pub fn from_wire(text: &str) -> Self {
        DeviceId(text.to_owned())
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What sort of thing a device is — decides only which icon and grouping the
/// page uses, never what may be done to it. That is [`Capability`]'s job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Something that plays audio.
    Speaker,
    /// A television or streaming box.
    Television,
    /// A light.
    Light,
    /// A switched outlet.
    Plug,
    /// Something on the network worth showing but not driving.
    Fixture,
}

impl Kind {
    /// The lowercase word this kind travels as in JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Speaker => "speaker",
            Kind::Television => "television",
            Kind::Light => "light",
            Kind::Plug => "plug",
            Kind::Fixture => "fixture",
        }
    }
}

/// One thing a device can be asked to do.
///
/// A closed set on purpose. A capability that exists on exactly one brand is
/// not a capability — it is that brand's driver doing something extra — and
/// admitting one here would put a brand back into the interface, which is the
/// arrangement this module exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    /// Play, pause, stop, next, previous.
    Transport,
    /// A volume level, 0–100.
    Volume,
    /// Muting, separately from volume — a muted speaker remembers its level.
    Mute,
    /// Joining and leaving a playback group.
    Group,
    /// On and off.
    Power,
    /// Directional and playback keys, for something driven like a remote.
    Keys,
    /// Launching a named application.
    Apps,
    /// A brightness level, 0–100.
    Brightness,
    /// An RGB colour.
    Color,
    /// A white colour temperature in kelvin.
    ColorTemp,
}

impl Capability {
    /// The lowercase word this capability travels as in JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::Transport => "transport",
            Capability::Volume => "volume",
            Capability::Mute => "mute",
            Capability::Group => "group",
            Capability::Power => "power",
            Capability::Keys => "keys",
            Capability::Apps => "apps",
            Capability::Brightness => "brightness",
            Capability::Color => "color",
            Capability::ColorTemp => "color_temp",
        }
    }
}

/// What a transport is doing.
///
/// `Transitioning` is a real state a Sonos reports for a second or so after
/// being told to play, not an error and not a synonym for playing. It is
/// carried through to the page so a button can show the request landing rather
/// than appearing to do nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// Not playing.
    Stopped,
    /// Playing.
    Playing,
    /// Paused, and able to resume where it stopped.
    Paused,
    /// Between states.
    Transitioning,
}

impl Transport {
    /// The word this state travels as in JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Stopped => "stopped",
            Transport::Playing => "playing",
            Transport::Paused => "paused",
            Transport::Transitioning => "transitioning",
        }
    }

    /// Reads the four values a UPnP `TransportState` may hold.
    ///
    /// An unrecognised value reads as `Stopped` rather than failing: a speaker
    /// inventing a fifth state should leave the page saying "not playing",
    /// which is nearly always right, instead of blanking the device.
    #[must_use]
    pub fn from_upnp(value: &str) -> Self {
        match value {
            "PLAYING" => Transport::Playing,
            "PAUSED_PLAYBACK" => Transport::Paused,
            "TRANSITIONING" => Transport::Transitioning,
            _ => Transport::Stopped,
        }
    }
}

/// Whether something is on, off, or has not said.
///
/// Three-valued because "we have not been able to ask" is a different fact
/// from "off", and a dashboard that renders the first as the second is lying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Power {
    /// Known to be on.
    On,
    /// Known to be off.
    Off,
    /// Not known.
    Unknown,
}

impl Power {
    /// The word this state travels as in JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Power::On => "on",
            Power::Off => "off",
            Power::Unknown => "unknown",
        }
    }
}

/// Everything currently true of a device.
///
/// Every field is optional, and that is the point: a driver fills what its
/// protocol actually told it, and the page renders what is present. A zero
/// standing in for "unknown" is how a volume slider ends up snapping to
/// silence on a device that never reported one.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct State {
    /// What the transport is doing.
    pub transport: Option<Transport>,
    /// Volume, 0–100.
    pub volume: Option<u8>,
    /// Whether it is muted.
    pub muted: Option<bool>,
    /// Whether it is on.
    pub power: Option<Power>,
    /// Brightness, 0–100.
    pub brightness: Option<u8>,
    /// Colour as `RRGGBB`, uppercase, no leading hash.
    pub color: Option<String>,
    /// White colour temperature in kelvin.
    pub color_temp: Option<u16>,
    /// What is playing, as one line.
    pub title: Option<String>,
    /// Who it is by.
    pub artist: Option<String>,
    /// Where the audio is coming from, in the protocol's own words.
    pub source: Option<String>,
    /// Track length in seconds, when the source has one. A live stream does
    /// not, and reports `None` rather than zero.
    pub duration_secs: Option<u32>,
    /// How far into the track, in seconds.
    pub position_secs: Option<u32>,
    /// The device coordinating this device's playback group, if grouped.
    pub coordinator: Option<DeviceId>,
    /// Every device in this device's group, coordinator first.
    pub group: Vec<DeviceId>,
    /// Battery charge, 0–100, for something that has one.
    pub battery_pct: Option<u8>,
    /// Whether that battery is charging.
    pub battery_charging: Option<bool>,
    /// The application currently in the foreground.
    pub app: Option<String>,
}

/// A device as the rest of the system sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct Device {
    /// Stable identity.
    pub id: DeviceId,
    /// The name a person should see. A driver supplies the device's own name;
    /// the registry overrides it when somebody has renamed the thing.
    pub name: String,
    /// The room it is in, when known.
    pub room: Option<String>,
    /// What sort of thing it is.
    pub kind: Kind,
    /// Where it is on the network, for display and for diagnosis.
    pub address: Option<String>,
    /// Whether the last attempt to reach it succeeded.
    pub reachable: bool,
    /// What it can be asked to do. Sorted and deduplicated by
    /// [`Device::advertise`] so the page's ordering never depends on the order
    /// a driver happened to push capabilities.
    pub capabilities: Vec<Capability>,
    /// Everything currently true of it.
    pub state: State,
    /// Why it cannot be driven, when it is present but cannot be. Shown to the
    /// reader verbatim, so it must be a sentence, not a code.
    pub note: Option<String>,
}

impl Device {
    /// A device with nothing known about it but its identity and kind.
    #[must_use]
    pub fn new(id: DeviceId, name: impl Into<String>, kind: Kind) -> Self {
        Device {
            id,
            name: name.into(),
            room: None,
            kind,
            address: None,
            reachable: false,
            capabilities: Vec::new(),
            state: State::default(),
            note: None,
        }
    }

    /// Records what this device can do, sorted and deduplicated.
    #[must_use]
    pub fn advertise(mut self, capabilities: &[Capability]) -> Self {
        self.capabilities.extend_from_slice(capabilities);
        self.capabilities.sort_unstable();
        self.capabilities.dedup();
        self
    }

    /// Whether this device advertises a capability.
    #[must_use]
    pub fn can(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }

    /// Whether this device may be asked to do this.
    ///
    /// The single gate every command passes through. A device that is not
    /// reachable refuses everything — attempting a command against something
    /// known to be absent produces a timeout the reader has to interpret,
    /// where a refusal produces a sentence.
    #[must_use]
    pub fn admits(&self, command: &Command) -> bool {
        self.reachable && self.can(command.needs())
    }
}

/// One thing the interface asks of a device.
///
/// Parsed from the request body and then checked against the target's
/// capabilities. Values are clamped at construction rather than validated,
/// because every one of them has a defensible saturation: a browser sending
/// 150 for a volume means "loud", and refusing it teaches nobody anything.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    /// Start playing.
    Play,
    /// Pause, keeping the position.
    Pause,
    /// Stop.
    Stop,
    /// Skip forward.
    Next,
    /// Skip back.
    Previous,
    /// Set volume, 0–100.
    Volume(u8),
    /// Change volume by a signed amount, clamped into 0–100 by the driver.
    ///
    /// A separate command from [`Command::Volume`] because it must be atomic:
    /// read-then-write from the browser loses one of two taps that arrive
    /// together, and Sonos offers a relative action precisely for this.
    VolumeStep(i16),
    /// Mute or unmute.
    Mute(bool),
    /// Join the group coordinated by another device.
    Join(DeviceId),
    /// Leave the current group and stand alone.
    Leave,
    /// Turn on or off.
    Power(bool),
    /// Set brightness, 0–100.
    Brightness(u8),
    /// Set colour, as `RRGGBB`.
    Color(String),
    /// Set white colour temperature in kelvin.
    ColorTemp(u16),
    /// Press a key, in the vocabulary of [`Key`].
    Key(Key),
    /// Bring an application to the foreground.
    Launch(String),
}

impl Command {
    /// The capability a device must advertise to be asked this.
    #[must_use]
    pub fn needs(&self) -> Capability {
        match self {
            Command::Play
            | Command::Pause
            | Command::Stop
            | Command::Next
            | Command::Previous => Capability::Transport,
            Command::Volume(_) | Command::VolumeStep(_) => Capability::Volume,
            Command::Mute(_) => Capability::Mute,
            Command::Join(_) | Command::Leave => Capability::Group,
            Command::Power(_) => Capability::Power,
            Command::Brightness(_) => Capability::Brightness,
            Command::Color(_) => Capability::Color,
            Command::ColorTemp(_) => Capability::ColorTemp,
            Command::Key(_) => Capability::Keys,
            Command::Launch(_) => Capability::Apps,
        }
    }

    /// The word this command travels as in JSON.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Command::Play => "play",
            Command::Pause => "pause",
            Command::Stop => "stop",
            Command::Next => "next",
            Command::Previous => "previous",
            Command::Volume(_) => "volume",
            Command::VolumeStep(_) => "volume_step",
            Command::Mute(_) => "mute",
            Command::Join(_) => "join",
            Command::Leave => "leave",
            Command::Power(_) => "power",
            Command::Brightness(_) => "brightness",
            Command::Color(_) => "color",
            Command::ColorTemp(_) => "color_temp",
            Command::Key(_) => "key",
            Command::Launch(_) => "launch",
        }
    }
}

/// A key on something driven like a remote control.
///
/// Named after what a person presses, not after the numeric code any one
/// platform assigns it — the mapping to `KEYCODE_*` belongs in the driver that
/// speaks to that platform, so a second platform does not inherit Android's
/// numbering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// Up.
    Up,
    /// Down.
    Down,
    /// Left.
    Left,
    /// Right.
    Right,
    /// Select the focused thing.
    Select,
    /// Go back.
    Back,
    /// Go to the home screen.
    Home,
    /// Open the menu.
    Menu,
    /// Play or pause, whichever applies.
    PlayPause,
    /// Skip forward.
    Next,
    /// Skip back.
    Previous,
    /// Volume up.
    VolumeUp,
    /// Volume down.
    VolumeDown,
}

impl Key {
    /// The word this key travels as in JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Key::Up => "up",
            Key::Down => "down",
            Key::Left => "left",
            Key::Right => "right",
            Key::Select => "select",
            Key::Back => "back",
            Key::Home => "home",
            Key::Menu => "menu",
            Key::PlayPause => "play_pause",
            Key::Next => "next",
            Key::Previous => "previous",
            Key::VolumeUp => "volume_up",
            Key::VolumeDown => "volume_down",
        }
    }

    /// Reads a key from the word the page sent.
    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        let key = match word {
            "up" => Key::Up,
            "down" => Key::Down,
            "left" => Key::Left,
            "right" => Key::Right,
            "select" => Key::Select,
            "back" => Key::Back,
            "home" => Key::Home,
            "menu" => Key::Menu,
            "play_pause" => Key::PlayPause,
            "next" => Key::Next,
            "previous" => Key::Previous,
            "volume_up" => Key::VolumeUp,
            "volume_down" => Key::VolumeDown,
            _ => return None,
        };
        Some(key)
    }
}

/// Clamps a signed number into a percentage.
///
/// Shared by every driver so "0–100" means the same thing everywhere, and a
/// relative step that would run off either end stops at the end rather than
/// wrapping — which is what an unsigned subtraction would do.
#[must_use]
pub fn clamp_percent(value: i32) -> u8 {
    value.clamp(0, 100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_id_carries_its_driver_and_key() {
        let id = DeviceId::new("sonos", "RINCON_7828CA1491AE01400");
        assert_eq!(id.as_str(), "sonos:rincon_7828ca1491ae01400");
        assert_eq!(id.driver(), "sonos");
        assert_eq!(id.key(), "rincon_7828ca1491ae01400");
    }

    /// The id is a URL path segment, so a name a stranger's firmware chose
    /// must not be able to introduce a slash or a space into it.
    #[test]
    fn an_id_is_safe_in_a_url_without_escaping() {
        let id = DeviceId::new("wyze", "Alex's Desk Lamp/2");
        assert_eq!(id.as_str(), "wyze:alex-s-desk-lamp-2");
        assert!(id.as_str().chars().all(|c| c.is_ascii_alphanumeric()
            || c == ':'
            || c == '_'
            || c == '.'
            || c == '-'));
    }

    #[test]
    fn capabilities_are_sorted_and_deduplicated() {
        let device = Device::new(DeviceId::new("sonos", "a"), "Kitchen", Kind::Speaker)
            .advertise(&[Capability::Volume, Capability::Transport, Capability::Volume]);
        assert_eq!(
            device.capabilities,
            [Capability::Transport, Capability::Volume]
        );
    }

    #[test]
    fn a_command_names_the_capability_it_needs() {
        assert_eq!(Command::Play.needs(), Capability::Transport);
        assert_eq!(Command::Volume(30).needs(), Capability::Volume);
        assert_eq!(Command::Leave.needs(), Capability::Group);
        assert_eq!(Command::Key(Key::Up).needs(), Capability::Keys);
    }

    /// The gate the whole design rests on: a speaker is not asked to change
    /// colour, and the refusal happens before any driver is involved.
    #[test]
    fn a_device_refuses_a_command_it_does_not_advertise() {
        let mut speaker = Device::new(DeviceId::new("sonos", "a"), "Kitchen", Kind::Speaker)
            .advertise(&[Capability::Transport, Capability::Volume]);
        speaker.reachable = true;

        assert!(speaker.admits(&Command::Play));
        assert!(speaker.admits(&Command::Volume(20)));
        assert!(!speaker.admits(&Command::Color("FF0000".into())));
        assert!(!speaker.admits(&Command::Brightness(50)));
    }

    /// An unreachable device refuses everything, so the reader gets a sentence
    /// rather than a timeout.
    #[test]
    fn an_unreachable_device_admits_nothing() {
        let speaker = Device::new(DeviceId::new("sonos", "a"), "Kitchen", Kind::Speaker)
            .advertise(&[Capability::Transport]);
        assert!(!speaker.reachable);
        assert!(!speaker.admits(&Command::Play));
    }

    #[test]
    fn the_four_upnp_transport_states_read_correctly() {
        assert_eq!(Transport::from_upnp("PLAYING"), Transport::Playing);
        assert_eq!(Transport::from_upnp("PAUSED_PLAYBACK"), Transport::Paused);
        assert_eq!(Transport::from_upnp("TRANSITIONING"), Transport::Transitioning);
        assert_eq!(Transport::from_upnp("STOPPED"), Transport::Stopped);
    }

    /// A speaker inventing a fifth state should leave the page saying "not
    /// playing", not blank the device.
    #[test]
    fn an_unknown_transport_state_reads_as_stopped() {
        assert_eq!(Transport::from_upnp("NO_MEDIA_PRESENT"), Transport::Stopped);
        assert_eq!(Transport::from_upnp(""), Transport::Stopped);
    }

    #[test]
    fn a_percentage_saturates_rather_than_wrapping() {
        assert_eq!(clamp_percent(-30), 0);
        assert_eq!(clamp_percent(150), 100);
        assert_eq!(clamp_percent(42), 42);
    }

    #[test]
    fn every_key_word_round_trips() {
        for key in [
            Key::Up, Key::Down, Key::Left, Key::Right, Key::Select, Key::Back,
            Key::Home, Key::Menu, Key::PlayPause, Key::Next, Key::Previous,
            Key::VolumeUp, Key::VolumeDown,
        ] {
            assert_eq!(Key::parse(key.as_str()), Some(key));
        }
    }

    #[test]
    fn an_unknown_key_word_is_refused() {
        assert_eq!(Key::parse("eject"), None);
    }

    /// State defaults to "nothing known" rather than to zeroes, so a volume
    /// slider never snaps to silence on a device that reported nothing.
    #[test]
    fn an_unknown_state_is_empty_rather_than_zero() {
        let state = State::default();
        assert_eq!(state.volume, None);
        assert_eq!(state.transport, None);
        assert!(state.group.is_empty());
    }
}
