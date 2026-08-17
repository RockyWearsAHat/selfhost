//! What the DESKTOP plate knows: the deployment's switches, the machines it can
//! reach, and the decisions about who may type.
//!
//! # What is mirrored, and what is not
//!
//! `selfhost-desk` already owns the *words*: [`Notice::sentence`] and
//! [`Refusal::sentence`] are written once in Rust and the browser copies them,
//! so this console links the originals and copies nothing. What it does mirror
//! from `sites/console/app.js` are the decisions the browser makes on top of
//! them — which of the four input modes a session is in, what a refused mint
//! means, what advice a refusal carries — because those are this console's own
//! judgement and the two must agree. Each one names its counterpart.
//!
//! # Control is a second, separate authorisation, here as in the browser
//!
//! Watching and driving are never one press. A viewing session is opened with a
//! ticket asking only for `desktop.view`; taking the keyboard mints a **second**
//! ticket asking for `desktop.control`, and the daemon decides that one against
//! [`Ability::needs_a_fresh_credential`] — a login no older than
//! `[desktop].reauth_window`. Nothing here weakens that because the console is
//! native: the freshness rule lives in the daemon, this end simply cannot ask
//! for a keyboard without a mint that can be refused, and [`ControlRefusal`]
//! exists to say *which* of the three refusals came back.
//!
//! [`Ability::needs_a_fresh_credential`]: https://docs.rs/
//! [`Notice::sentence`]: selfhost_desk::state::Notice::sentence
//! [`Refusal::sentence`]: selfhost_desk::wire::Refusal::sentence

use crate::nas::usable_token;
use rui::{KeyCode, Modifiers, Status};
use selfhost_desk::keys::{Modifier, Side, Usage};
use selfhost_desk::wire::Refusal;
use selfhost_json::Json;

/// The pseudo-node naming the machine the daemon is running on.
///
/// Mirrors `selfhost_admin::desk_api::LOCAL_NODE`, which itself mirrors
/// `selfhost_mesh::LOCAL_NAME`. Controlling the box the daemon runs on and
/// controlling another one are one code path with one name in it.
pub const LOCAL_NODE: &str = "self";

/// The largest node name this console will put in a query string.
const MAX_NODE_NAME: usize = 64;

/// Whether a machine's name may appear in a request path or a query.
///
/// Mirrors `usableNodeName`. Checked rather than escaped for the reason every
/// other identifier in this console is: a value that does not match the
/// daemon's grammar did not come from the daemon.
pub fn usable_node_name(name: &str) -> bool {
    usable_token(name, MAX_NODE_NAME)
}

/// The operator's own switches, as `GET /api/desktop` reports them.
///
/// Read rather than assumed, because three of these decide what the plate may
/// even offer: a deployment with `allow_input = false` must not draw a TAKE
/// CONTROL button that is guaranteed to be refused, and one with
/// `enabled = false` has no desktop at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Settings {
    /// Whether the subsystem exists on this deployment.
    pub enabled: bool,
    /// Whether anybody, however authorised, may drive a keyboard here.
    pub allow_input: bool,
    /// Whether the clipboard channel is switched on.
    pub allow_clipboard: bool,
    /// Whether an unattended bearer token may drive a keyboard.
    ///
    /// **This console authenticates with the bearer token**, so this is the
    /// switch that decides whether TAKE CONTROL can ever succeed from here.
    pub bearer_may_control: bool,
    /// Concurrent streams per node.
    pub max_viewers: u32,
    /// The frame rate the agent will not exceed.
    pub max_fps: u32,
    /// The tile edge in pixels.
    pub tile: u32,
    /// How recent a login must be before a keyboard is minted.
    pub reauth_window_secs: u64,
    /// The hard ceiling on one session.
    pub max_session_secs: u64,
}

impl Settings {
    /// Reads the switches off the wire.
    pub fn from_json(value: &Json) -> Option<Self> {
        let flag = |name: &str| value.get(name).and_then(Json::as_bool).unwrap_or(false);
        let count = |name: &str| value.get(name).and_then(Json::as_u64).unwrap_or(0);
        Some(Self {
            enabled: value.get("enabled")?.as_bool()?,
            allow_input: flag("allowInput"),
            allow_clipboard: flag("allowClipboard"),
            bearer_may_control: flag("bearerMayControl"),
            max_viewers: count("maxViewers") as u32,
            max_fps: count("maxFps") as u32,
            tile: count("tile") as u32,
            reauth_window_secs: count("reauthWindowSecs"),
            max_session_secs: count("maxSessionSecs"),
        })
    }
}

/// One machine this deployment can reach.
///
/// Absence is never the answer: a peer that is down is drawn with the reason it
/// dropped and when it was last seen, because a picker that silently omits a
/// machine tells an operator their configuration is wrong when the truth is
/// that a laptop is asleep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// The declared name, which is also what a ticket names.
    pub node: String,
    /// Whether a link to it is up right now.
    pub live: bool,
    /// Seconds since it was last seen, when it has ever been seen.
    pub last_seen_secs: Option<u64>,
    /// Why the last link ended, for a node that is not live.
    pub reason: Option<String>,
}

impl Node {
    /// Reads one node off the wire, or `None` for a name no request could carry.
    pub fn from_json(value: &Json) -> Option<Self> {
        let node = value.get("node")?.as_str()?.to_owned();
        if !usable_node_name(&node) {
            return None;
        }
        Some(Self {
            node,
            live: value.get("live").and_then(Json::as_bool).unwrap_or(false),
            last_seen_secs: value.get("lastSeenSecs").and_then(Json::as_u64),
            reason: value.get("reason").and_then(Json::as_str).map(str::to_owned),
        })
    }

    /// What the picker says under the name: why it is down, or how long ago it
    /// was seen.
    ///
    /// A live node says nothing at all here — the lamp beside it already does —
    /// and only a node that is *not* answering spends a line explaining itself.
    /// That is the same restraint the rail applies to a healthy service.
    pub fn summary(&self) -> String {
        if self.live {
            return String::new();
        }
        let seen = match self.last_seen_secs {
            Some(secs) => format!("last seen {} ago", crate::view::duration(secs)),
            None => "never seen".into(),
        };
        match &self.reason {
            Some(reason) if !reason.is_empty() => format!("{seen} · {reason}"),
            _ => seen,
        }
    }

    /// The lamp beside the name.
    pub fn status(&self) -> Status {
        if self.live { Status::Ok } else { Status::Bad }
    }
}

/// What the capture agent on one machine is doing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Agent {
    /// The node this describes.
    pub node: String,
    /// Whether an agent is running and answering.
    pub live: bool,
    /// The agent's own one-line statement of where it landed.
    pub sentence: String,
    /// How many displays it can see.
    pub monitors: u32,
    /// How many times it has been respawned since the daemon started, which is
    /// what a crash loop looks like from the outside.
    pub respawns: u32,
}

impl Agent {
    /// Reads the report off the wire.
    pub fn from_json(value: &Json) -> Option<Self> {
        Some(Self {
            node: value.get("node")?.as_str()?.to_owned(),
            live: value.get("live").and_then(Json::as_bool).unwrap_or(false),
            sentence: value
                .get("sentence")
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_owned(),
            monitors: value.get("monitors").and_then(Json::as_u64).unwrap_or(0) as u32,
            respawns: value.get("respawns").and_then(Json::as_u64).unwrap_or(0) as u32,
        })
    }
}

/// Which of the four input modes a session is in.
///
/// Mirrors `inputMode`. Four rather than two, because "may I type" and "will my
/// typing land" are different questions, and a console that answers only the
/// first leaves the operator pressing keys into a machine that is not taking
/// them. The order of the tests is the order of the truths: what the ticket
/// granted, then what the far machine is doing, then where the keyboard is
/// pointed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// No keyboard was granted; the session watches.
    Watching,
    /// A keyboard was granted and the far machine is not taking input.
    Suspended,
    /// A keyboard was granted and this window does not have it aimed.
    Armed,
    /// Every key goes to the far machine.
    Driving,
}

impl Mode {
    /// Which mode a session is in.
    pub fn of(granted: bool, live: bool, focused: bool) -> Self {
        if !granted {
            return Self::Watching;
        }
        if !live {
            return Self::Suspended;
        }
        if focused { Self::Driving } else { Self::Armed }
    }

    /// The mode's word, in the rail's small capitals.
    pub fn word(self) -> &'static str {
        match self {
            Self::Watching => "WATCHING",
            Self::Suspended => "INPUT SUSPENDED",
            Self::Armed => "KEYBOARD ARMED",
            Self::Driving => "DRIVING",
        }
    }

    /// The mode's sentence.
    ///
    /// A person must never be unsure whether what they type is going somewhere,
    /// so each of these states what happens to the *next* key pressed, in the
    /// present tense. `Armed` gets an instruction rather than a description
    /// because it is the only one of the four with something to do.
    pub fn line(self) -> &'static str {
        match self {
            Self::Watching => "This session watches the screen and cannot type on it.",
            Self::Suspended => {
                "You hold the keyboard, and the far machine is not accepting input just now."
            }
            Self::Armed => {
                "Click the screen to take the keyboard. Until you do, keys stay in this window."
            }
            Self::Driving => "Every key, click and scroll goes to the far machine.",
        }
    }

    /// The mode's lamp.
    ///
    /// Green only while keys are actually landing. An armed keyboard that is not
    /// aimed is amber precisely because it looks like driving and is not.
    pub fn status(self) -> Status {
        match self {
            Self::Driving => Status::Ok,
            Self::Armed | Self::Suspended => Status::Warn,
            Self::Watching => Status::Idle,
        }
    }
}

/// What a refused control mint means, and what the console should do about it.
///
/// Mirrors `controlRefusal`. Three of the daemon's answers are deliberately
/// legible where every other refusal in that API is a uniform 401, and each
/// wants a different response, so they are told apart here rather than at the
/// call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlRefusal {
    /// The login is older than `[desktop].reauth_window_secs`.
    ///
    /// In a browser the answer is the passkey prompt. **This console
    /// authenticates with the bearer token and has no prompt to offer**, so the
    /// sentence says what a person must actually do, which is open the browser
    /// console and authenticate there. Inventing a re-authentication this
    /// program cannot perform would be worse than saying so.
    Stale {
        /// How recent a login has to be.
        within_secs: u64,
    },
    /// A switch in a file on the box is off.
    ///
    /// No amount of re-authenticating will help, and offering to try again
    /// would be the console lying about what it is asking for.
    Switch {
        /// Which switch.
        setting: String,
    },
    /// A plain 401: this credential may watch this machine and has not been
    /// granted a keyboard for it.
    Denied,
    /// Anything else the daemon said.
    Other {
        /// Its own words.
        text: String,
    },
}

impl ControlRefusal {
    /// Reads the refusal out of a status and a body.
    pub fn of(status: u16, body: Option<&Json>) -> Self {
        let flag = |name: &str| {
            body.and_then(|body| body.get(name)).and_then(Json::as_bool).unwrap_or(false)
        };
        if status == 403 && flag("reauthenticate") {
            let within =
                body.and_then(|body| body.get("withinSecs")).and_then(Json::as_u64).unwrap_or(0);
            return Self::Stale { within_secs: within };
        }
        if status == 403 {
            if let Some(setting) =
                body.and_then(|body| body.get("setting")).and_then(Json::as_str)
            {
                return Self::Switch { setting: setting.to_owned() };
            }
        }
        if status == 401 {
            return Self::Denied;
        }
        Self::Other { text: crate::nas::refusal_text(status, body) }
    }

    /// What to put in front of the operator.
    pub fn sentence(&self) -> String {
        match self {
            Self::Stale { within_secs: 0 } => {
                "this login is too old to drive a machine — open the browser console and \
                 authenticate there"
                    .into()
            }
            Self::Stale { within_secs } => format!(
                "a keyboard needs a login no older than {} — open the browser console and \
                 authenticate there",
                crate::view::duration(*within_secs)
            ),
            Self::Switch { setting } => format!(
                "{setting} is off in the configuration file on the box, and nothing in this \
                 console can turn it on"
            ),
            Self::Denied => {
                "the daemon refused a keyboard for this machine — this session may watch it, \
                 and has not been granted control of it"
                    .into()
            }
            Self::Other { text } => text.clone(),
        }
    }
}

/// What to do about an input refusal the agent reported.
///
/// Mirrors `refusalAdvice`. The sentence itself belongs to
/// [`Refusal::sentence`] and is not repeated; this is the half that is advice,
/// and it exists because an input event that vanishes with no word is the one
/// fault that makes a person decide software is broken — there is nothing to act
/// on and nothing to report.
pub fn refusal_advice(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::NotPermitted => {
            "ask for the keyboard — TAKE CONTROL mints a separate, freshly authorised ticket"
        }
        Refusal::InputDisabled => {
            "input is off in [desktop] on the box itself; nothing in this console can turn it on"
        }
        Refusal::SecureDesktop => {
            "the prompt in front of the far screen will go on its own, and the keyboard comes \
             back with it"
        }
        Refusal::ElevatedWindow => {
            "click a window that is not running as administrator; the platform never delivers \
             synthetic input to an elevated one, by design"
        }
        Refusal::NotLive => "wait for the state above to read LIVE",
        Refusal::Unmappable => {
            "that one physical key has no mapping on the far platform; the rest of the keyboard \
             is unaffected"
        }
    }
}

/// The refusal banner's own words: the agent's sentence, opened so it reads as a
/// refusal, and repeated for the count.
///
/// Mirrors `refusalHeadline`.
pub fn refusal_headline(refusal: Refusal, count: u32) -> String {
    let tally = if count > 1 { format!(" · {count} events refused") } else { String::new() };
    format!("input refused — {}{tally}", refusal.sentence())
}

/// The HID usage one physical key on *this* machine's keyboard corresponds to,
/// or `None` for a key this build cannot name.
///
/// # Why this is a reverse lookup and not a table
///
/// `selfhost_screen::keymap` already owns both platform tables, in the direction
/// an *injector* needs them: HID usage → the platform's own code. A console that
/// forwards a keystroke needs the other direction, and the one thing it must not
/// do is write a second table — two tables disagree, and a keyboard that types
/// the wrong character is exactly the class of bug the single table exists to
/// close. So this walks the one table backwards. It is a linear scan over about
/// a hundred rows on a key press, which is free at human typing rates and is
/// worth more than a cached index that could go stale against the table it came
/// from.
///
/// # What the platform gives, and where it is lossy
///
/// `rui` reports the platform's own number: a `CGKeyCode` on macOS, a Win32
/// virtual key on Windows, an X11 hardware keycode under X11.
///
/// - **macOS** is exact. `MACOS_ALIASES` means four `CGKeyCode`s are named by
///   two usages each (`PrintScreen`/`F13` and so on); the lower usage wins,
///   deterministically, and the far machine receives a key that is on the same
///   physical position either way.
/// - **Windows is lossy for the four paired modifiers.** `WM_KEYDOWN` carries
///   `VK_SHIFT`, `VK_CONTROL` and `VK_MENU` — the side-less codes — where the
///   table holds `VK_LSHIFT`/`VK_RSHIFT` and so on. A side-less code is mapped
///   to the **left** key, which is what the table's own left rows already say
///   and what every keyboard's unmodified layout means by it. The right-hand
///   Alt is AltGr on most non-US layouts, so this is a real difference and it is
///   stated rather than hidden.
/// - **X11 is not mapped at all.** An X11 keycode is a hardware number with no
///   fixed meaning — it is the index into a per-server keymap — so there is
///   nothing to look it up in without reading the server's table, which this
///   console does not do. The plate says so; the same session drives fine from
///   a Mac or a Windows machine.
pub fn usage_for_code(code: KeyCode) -> Option<Usage> {
    #[cfg(target_os = "macos")]
    {
        let raw = u16::try_from(code.raw()).ok()?;
        let hid = selfhost_screen::keymap::MACOS_KEYS
            .iter()
            .find(|row| row.key_code == raw)
            .map(|row| row.usage)?;
        Usage::from_hid(hid).ok()
    }
    #[cfg(windows)]
    {
        /// The side-less virtual keys Windows reports for a modifier press, and
        /// the left-hand key each is read as. See this function's own notes.
        const SIDELESS: [(u32, u16); 3] = [(0x10, 0xA0), (0x11, 0xA2), (0x12, 0xA4)];
        let raw = SIDELESS
            .iter()
            .find(|(sideless, _)| *sideless == code.raw())
            .map(|(_, left)| *left)
            .or_else(|| u16::try_from(code.raw()).ok())?;
        let hid = selfhost_screen::keymap::WINDOWS_KEYS
            .iter()
            .find(|row| row.key.virtual_key == raw)
            .map(|row| row.usage)?;
        Usage::from_hid(hid).ok()
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = code;
        None
    }
}

/// The usage of one of the four modifier roles, on its left-hand key.
///
/// Looked up through the vocabulary rather than written as four hexadecimal
/// constants, so a table edit cannot leave this pointing at the wrong key.
fn modifier_usage(role: Modifier) -> Option<Usage> {
    Usage::all().find(|usage| usage.modifier() == Some((role, Side::Left)))
}

/// The modifier presses and releases that turn one modifier state into another.
///
/// # Why the modifiers travel separately from the keys
///
/// Neither platform reports a modifier as an ordinary key event that this
/// library can see: macOS sends `NSFlagsChanged`, which is not a `keyDown`, and
/// `rui` folds both platforms' modifier state into every keystroke instead. So
/// a session that forwarded only keystrokes would leave the far machine with no
/// Shift, and one that forwarded the modifier bits *with* each key would leave
/// them held after the last key came up. Diffing the state on every event and
/// sending only the changes is what makes Shift, Control, Alt and Command
/// behave — and it is what makes them come back up, which
/// [`selfhost_desk::keys::HeldKeys`] exists to insist on.
///
/// Answers `(usage, down)` pairs in a fixed order so a test can assert them.
pub fn modifier_changes(previous: Modifiers, current: Modifiers) -> Vec<(Usage, bool)> {
    let roles = [
        (Modifier::Control, previous.control, current.control),
        (Modifier::Shift, previous.shift, current.shift),
        (Modifier::Alt, previous.alt, current.alt),
        (Modifier::Meta, previous.command, current.command),
    ];
    roles
        .into_iter()
        .filter(|(_, was, now)| was != now)
        .filter_map(|(role, _, now)| Some((modifier_usage(role)?, now)))
        .collect()
}

/// Every key movement one keystroke turns into, in the order it must be sent.
///
/// Pure, and the piece with the ordering in it, so the rule is asserted without
/// a socket. The rule is the one a keyboard itself obeys and the one the far
/// machine has to see for `Shift+A` to be a capital rather than an `a` and a
/// shift: **on a press the modifiers go down first and on a release they come up
/// last**. A stroke with no position contributes nothing of its own —
/// [`Usage`] is a *physical* vocabulary and a synthesized keystroke names no key
/// another machine could be told about — but the modifiers that changed with it
/// still travel, because those were read from the platform's own state.
pub fn keystroke_messages(previous: Modifiers, stroke: rui::KeyStroke) -> Vec<(Usage, bool)> {
    let changes = modifier_changes(previous, stroke.modifiers);
    let down = stroke.phase == rui::KeyPhase::Down;
    let key = stroke.code.and_then(usage_for_code).map(|usage| (usage, down));

    let mut messages = Vec::with_capacity(changes.len() + 1);
    if down {
        messages.extend(changes.iter().copied());
        messages.extend(key);
    } else {
        messages.extend(key);
        messages.extend(changes.iter().copied());
    }
    messages
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_four_input_modes_are_decided_in_the_order_of_the_truths() {
        assert_eq!(Mode::of(false, true, true), Mode::Watching, "no grant beats everything");
        assert_eq!(Mode::of(true, false, true), Mode::Suspended, "a dead session beats focus");
        assert_eq!(Mode::of(true, true, false), Mode::Armed);
        assert_eq!(Mode::of(true, true, true), Mode::Driving);
    }

    #[test]
    fn only_a_landing_keystroke_lights_the_lamp_green() {
        assert_eq!(Mode::Driving.status(), Status::Ok);
        for mode in [Mode::Armed, Mode::Suspended] {
            assert_eq!(mode.status(), Status::Warn, "{} is not driving", mode.word());
        }
        assert_eq!(Mode::Watching.status(), Status::Idle);
    }

    #[test]
    fn every_mode_says_what_happens_to_the_next_key() {
        for mode in [Mode::Watching, Mode::Suspended, Mode::Armed, Mode::Driving] {
            assert!(!mode.line().is_empty(), "{} has nothing to say", mode.word());
            assert!(mode.line().ends_with('.'));
        }
    }

    #[test]
    fn the_three_legible_control_refusals_are_told_apart() {
        let stale = Json::object([
            ("reauthenticate", Json::Bool(true)),
            ("withinSecs", Json::Number(120.0)),
        ]);
        assert_eq!(ControlRefusal::of(403, Some(&stale)), ControlRefusal::Stale { within_secs: 120 });

        let switch = Json::object([("setting", Json::string("desktop.allow_input"))]);
        assert!(matches!(ControlRefusal::of(403, Some(&switch)), ControlRefusal::Switch { .. }));

        assert_eq!(ControlRefusal::of(401, None), ControlRefusal::Denied);
        assert!(matches!(ControlRefusal::of(500, None), ControlRefusal::Other { .. }));
    }

    #[test]
    fn a_switch_refusal_never_suggests_authenticating_again() {
        // The distinction the browser draws and this must too: a file on the
        // box is off, and no credential will change that.
        let refusal = ControlRefusal::Switch { setting: "desktop.allow_input".into() };
        let sentence = refusal.sentence();
        assert!(sentence.contains("configuration file"));
        assert!(!sentence.contains("login"), "a switch is not a stale login: {sentence}");
    }

    #[test]
    fn a_stale_login_says_where_a_person_can_actually_re_authenticate() {
        // This console holds a bearer token and has no biometric prompt. The
        // browser's answer — "the passkey prompt is right here" — would be a
        // claim this program cannot honour.
        let sentence = ControlRefusal::Stale { within_secs: 120 }.sentence();
        assert!(sentence.contains("2m 0s"));
        assert!(sentence.contains("browser console"));
    }

    #[test]
    fn every_refusal_carries_both_a_sentence_and_something_to_do() {
        for refusal in [
            Refusal::NotPermitted,
            Refusal::InputDisabled,
            Refusal::SecureDesktop,
            Refusal::ElevatedWindow,
            Refusal::NotLive,
            Refusal::Unmappable,
        ] {
            assert!(!refusal_advice(refusal).is_empty(), "{refusal:?} has no advice");
            assert!(refusal_headline(refusal, 1).starts_with("input refused — "));
        }
        assert!(refusal_headline(Refusal::NotLive, 4).ends_with("· 4 events refused"));
    }

    #[test]
    fn a_node_that_is_down_says_when_it_was_last_seen_and_why() {
        let down = Node {
            node: "alex-desktop".into(),
            live: false,
            last_seen_secs: Some(3_600),
            reason: Some("the link was closed".into()),
        };
        assert_eq!(down.summary(), "last seen 1h 0m ago · the link was closed");
        assert_eq!(down.status(), Status::Bad);

        let never = Node { last_seen_secs: None, reason: None, ..down.clone() };
        assert_eq!(never.summary(), "never seen");

        let live = Node { live: true, ..down };
        assert_eq!(live.summary(), "", "a live node's lamp already said it");
    }

    #[test]
    fn a_node_whose_name_could_not_appear_in_a_query_is_not_offered() {
        for bad in ["Not A Node", "a/b", "", "-lead"] {
            let value = Json::object([("node", Json::string(bad))]);
            assert!(Node::from_json(&value).is_none(), "accepted the node name {bad:?}");
        }
        assert!(usable_node_name(LOCAL_NODE));
        assert!(usable_node_name("alex-desktop"));
    }

    #[test]
    fn the_switches_are_read_rather_than_assumed() {
        let value = Json::object([
            ("enabled", Json::Bool(true)),
            ("allowInput", Json::Bool(true)),
            ("bearerMayControl", Json::Bool(false)),
            ("reauthWindowSecs", Json::Number(120.0)),
            ("maxFps", Json::Number(30.0)),
        ]);
        let settings = Settings::from_json(&value).expect("the switches");
        assert!(settings.allow_input);
        assert!(!settings.bearer_may_control, "the default is the safe one");
        assert_eq!(settings.reauth_window_secs, 120);
        assert_eq!(settings.max_fps, 30);
        assert!(Settings::from_json(&Json::object([("maxFps", Json::Number(30.0))])).is_none());
    }

    #[test]
    fn a_modifier_going_down_and_up_is_two_messages_and_never_one() {
        let none = Modifiers::default();
        let shift = Modifiers { shift: true, ..Modifiers::default() };

        let down = modifier_changes(none, shift);
        assert_eq!(down.len(), 1);
        assert!(down[0].1, "the press is a press");
        assert_eq!(down[0].0.code(), "ShiftLeft");

        let up = modifier_changes(shift, none);
        assert_eq!(up.len(), 1);
        assert!(!up[0].1, "and the release comes back up");
        assert_eq!(up[0].0, down[0].0, "the same key it went down on");

        assert!(modifier_changes(shift, shift).is_empty(), "an unchanged state says nothing");
    }

    #[test]
    fn every_modifier_role_resolves_to_a_key_in_the_vocabulary() {
        for role in [Modifier::Control, Modifier::Shift, Modifier::Alt, Modifier::Meta] {
            let usage = modifier_usage(role).unwrap_or_else(|| panic!("{role:?} has no key"));
            assert_eq!(usage.modifier(), Some((role, Side::Left)));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_mac_key_code_names_the_key_that_is_in_that_position() {
        // `CGKeyCode` 0 is A, 49 is Space. Both are asserted because the two
        // sit in different families of the table, and a reverse lookup that
        // silently matched on the usage instead would still pass one of them.
        assert_eq!(usage_for_code(KeyCode::new(0)).map(Usage::code), Some("KeyA"));
        assert_eq!(usage_for_code(KeyCode::new(49)).map(Usage::code), Some("Space"));
        assert_eq!(usage_for_code(KeyCode::new(60_000)), None, "an unknown code names nothing");
    }

    #[test]
    fn a_stroke_with_no_position_still_carries_the_modifiers_that_changed() {
        // The modifiers were read from the platform's own state, so they are
        // true whether or not the key that came with them can be named.
        let stroke = rui::KeyStroke {
            code: None,
            key: Some(rui::Key::Character('a')),
            modifiers: Modifiers { shift: true, ..Modifiers::default() },
            phase: rui::KeyPhase::Down,
        };
        let messages = keystroke_messages(Modifiers::default(), stroke);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].0.code(), "ShiftLeft");
        assert!(messages[0].1);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_press_puts_its_modifiers_down_first_and_a_release_takes_them_up_last() {
        // The order a keyboard itself produces, and the order the far machine
        // needs to see: Shift then A makes a capital; A then Shift makes an `a`
        // and a stranded modifier.
        let shift = Modifiers { shift: true, ..Modifiers::default() };
        let press = rui::KeyStroke {
            code: Some(KeyCode::new(0)),
            key: Some(rui::Key::Character('a')),
            modifiers: shift,
            phase: rui::KeyPhase::Down,
        };
        let down = keystroke_messages(Modifiers::default(), press);
        assert_eq!(down.len(), 2);
        assert_eq!(down[0].0.code(), "ShiftLeft", "the modifier leads a press");
        assert_eq!(down[1].0.code(), "KeyA");
        assert!(down.iter().all(|(_, pressed)| *pressed));

        let release = rui::KeyStroke {
            modifiers: Modifiers::default(),
            phase: rui::KeyPhase::Up,
            ..press
        };
        let up = keystroke_messages(shift, release);
        assert_eq!(up.len(), 2);
        assert_eq!(up[0].0.code(), "KeyA", "the key leads a release");
        assert_eq!(up[1].0.code(), "ShiftLeft");
        assert!(up.iter().all(|(_, pressed)| !*pressed));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn an_aliased_mac_key_code_resolves_the_same_way_every_time() {
        // `MACOS_ALIASES` puts PrintScreen and F13 on one `CGKeyCode`. Which of
        // the two is answered does not matter — they are the same physical key
        // — but it must not change between calls.
        let first = usage_for_code(KeyCode::new(105));
        assert_eq!(first, usage_for_code(KeyCode::new(105)));
    }
}
