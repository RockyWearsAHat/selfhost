//! Remote desktop: the highest-privilege capability this repository has.
//!
//! Every other subsystem described in `selfhost.config.toml` *serves data*. This
//! one *drives the machine*. A hijacked desktop session is categorically worse
//! than a hijacked admin session: it is a keyboard at the console user's
//! integrity level, so the admin API's route table stops being the boundary; it
//! reads every password the operator types anywhere, including into the console
//! itself and including the credential that satisfies the freshness check below;
//! it can exfiltrate the VPN client key and this box's own `server.key` — the
//! outermost layer of its own perimeter — and it can edit and push the working
//! tree, which the box builds and runs unattended, making the self-updater a
//! remote code execution channel with a commit as the payload.
//!
//! That is why this section is shaped the way it is.
//!
//! # Absence is the default, and every dangerous field defaults off
//!
//! No `[desktop]` block means the subsystem does not exist: no agent is spawned,
//! no route is served, and the daemon's arm for it pends forever. A present
//! block still starts from `enabled = false`, and `allow_input`,
//! `allow_clipboard` and `bearer_may_control` each default to `false`
//! independently of it. Turning any of them on is a config edit and a restart —
//! deliberately not a toggle in a UI that an attacker who reached the console
//! would already be holding.
//!
//! **Viewing and driving are separate decisions.** `enabled` alone is a window;
//! `allow_input` is a keyboard. The two are separate capabilities all the way
//! down: `desk::Policy` refuses to mint a control ticket when `allow_input` is
//! false whatever the caller asks for or proves, and the control capability is
//! re-checked per input message rather than inferred from the handshake.
//!
//! # Why this refuses a configuration that is merely dishonest
//!
//! A block reading `enabled = false` beside `allow_input = true` describes
//! nothing: it is one word away from a keyboard, and it reads to whoever
//! inherits the file as though input is already permitted. The same is true of
//! `bearer_may_control` on a deployment where nothing may be controlled. These
//! are refused rather than silently reduced to their safe meaning, because the
//! next person to edit this file will act on what it appears to say.
//!
//! The one bound that is subtler: a `reauth_window` at least as long as
//! `max_session` makes the freshness check *meaningless*. Proving a password at
//! the moment a console session begins would then satisfy every control ticket
//! that session ever mints, which is exactly the "a live session is enough"
//! posture the freshness check exists to reject.
//!
//! # This crate does not depend on `selfhost-desk`
//!
//! `desk` depends on this crate's siblings and is linked into both consoles; it
//! must compile without the box's config. So the legal tile edges are mirrored
//! here rather than imported, the same way [`crate::mail`] mirrors the address
//! limits it checks against. The mirrored values are asserted against nothing —
//! they are a short, closed list — but they are named as mirrors so that a
//! change on either side is visibly a change to both.

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::validate::Problem;

/// Tile edges the codec understands, in pixels. Mirrors
/// `desk::tiles::LEGAL_TILE_EDGES`, kept local so `config` stays free of a
/// dependency on the `desk` crate.
///
/// A closed set rather than a range because the grid arithmetic's bounds are
/// proved against these four: at the smallest edge and the largest display the
/// column count still fits a `u16`.
pub const LEGAL_TILE_EDGES: [u16; 4] = [16, 32, 64, 128];

/// Default tile edge: 64 pixels, the size the diff was tuned against.
pub const DEFAULT_TILE: u16 = 64;

/// Default frame ceiling.
pub const DEFAULT_MAX_FPS: u8 = 30;

/// Fastest frame rate that may be asked for.
///
/// Above this the encoder is the bottleneck rather than the link, and a desktop
/// stream that saturates a core is a denial of service against every other
/// service this box runs — including the proxy that the operator would need in
/// order to turn the stream off.
pub const MAX_FPS_CEILING: u8 = 60;

/// Default concurrent viewers per node.
pub const DEFAULT_MAX_VIEWERS: u32 = 2;

/// Most concurrent viewers that may be asked for.
///
/// Each viewer is a full encode of every changed tile, so this is a cost
/// ceiling; it is also a blast-radius ceiling, since every viewer sees whatever
/// is on the screen.
pub const MAX_VIEWERS_CEILING: u32 = 8;

/// Default freshness window for a control ticket: two minutes.
pub const DEFAULT_REAUTH_WINDOW_SECS: u64 = 120;

/// Shortest freshness window that is still usable by a person.
///
/// Below this the operator cannot finish typing a password before the proof they
/// just gave has expired, and a control ticket becomes unmintable — a control
/// that fails closed so hard it is indistinguishable from a broken deployment.
pub const MIN_REAUTH_WINDOW_SECS: u64 = 5;

/// Longest freshness window that still means anything: fifteen minutes.
///
/// The check exists so that driving the machine costs a *recent* proof. Past
/// this, "recent" has stopped describing anything an attacker who is already in
/// the operator's browser would find inconvenient.
pub const MAX_REAUTH_WINDOW_SECS: u64 = 15 * 60;

/// Default hard ceiling on one desktop session: four hours.
pub const DEFAULT_MAX_SESSION_SECS: u64 = 4 * 60 * 60;

/// Shortest session ceiling worth configuring: one minute.
pub const MIN_MAX_SESSION_SECS: u64 = 60;

/// Longest session ceiling: twenty-four hours.
///
/// A ceiling longer than a day is not a ceiling; the session outlives the
/// operator's working day, their laptop's lid, and any memory of having opened
/// it.
pub const MAX_MAX_SESSION_SECS: u64 = 24 * 60 * 60;

/// Default agent respawns tolerated per hour before the state machine gives up.
pub const DEFAULT_AGENT_RESPAWN_CAP: u32 = 10;

/// Most respawns per hour that may be configured.
///
/// Ten per minute is already a crash loop; anything above this is a config that
/// asks the daemon to spend the machine relaunching a process that cannot run,
/// rather than to report that it cannot run.
pub const MAX_AGENT_RESPAWN_CAP: u32 = 600;

/// The documented `[desktop]` example, as live TOML.
///
/// Shipped commented out — through [`crate::commented`] — in
/// `selfhost.config.toml` and in the `selfhost init` template, so that adding
/// this section to a deployment is an act rather than a side effect. Held here
/// as parseable text so the crate's own tests validate the exact block an
/// operator is shown; a documented example that does not load is worse than none.
pub const EXAMPLE: &str = "\
# ─── Remote desktop ────────────────────────────────────────────────────────────
# Absent means the subsystem does not exist: no agent is spawned, no route is
# served, and the daemon's arm for it pends forever. This is the default, and it
# stays the default because this is the only capability here that drives the
# machine rather than serving data — a hijacked desktop session is a keyboard at
# the console user's integrity level.

[desktop]
enabled = false            # nothing below matters until this is true
allow_input = false        # viewing and driving are separate decisions
reauth_window_secs = 120   # a control ticket needs a password or passkey this recent
max_session_secs = 14400   # 4h hard ceiling; the console session's own expiry still wins
max_viewers = 2            # concurrent streams per node
max_fps = 30
tile = 64                  # 16 | 32 | 64 | 128
allow_clipboard = false    # a clipboard channel exfiltrates whatever was last copied
agent_respawn_cap = 10     # per hour, before the state machine gives up and says so
bearer_may_control = false # an unattended automation token should not drive a keyboard
";

/// The `[desktop]` section.
///
/// See the module documentation for why every dangerous field defaults to
/// `false` and why an internally dishonest block is refused rather than reduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Desktop {
    /// Whether the subsystem runs at all. Nothing below matters until this is
    /// true: no agent is spawned and no route is served.
    #[serde(default)]
    pub enabled: bool,

    /// Whether a viewer may ever be granted a keyboard and mouse.
    ///
    /// False means no ticket ever carries the control capability, whatever the
    /// caller asks for or proves. Viewing and driving are separate decisions,
    /// and this is the second one.
    #[serde(default)]
    pub allow_input: bool,

    /// How recently a password or passkey must have been proved for a *control*
    /// ticket to be minted, in seconds.
    ///
    /// A live console session is explicitly not enough. The session cookie is
    /// what an attacker who reached the console already holds; this is the one
    /// thing they must obtain again, in the seconds before they use it.
    #[serde(default = "default_reauth_window_secs")]
    pub reauth_window_secs: u64,

    /// Hard ceiling on one desktop session, in seconds. The console session's
    /// own expiry still wins when it is shorter — this is a ceiling, not a
    /// grant.
    #[serde(default = "default_max_session_secs")]
    pub max_session_secs: u64,

    /// Concurrent streams per node.
    #[serde(default = "default_max_viewers")]
    pub max_viewers: u32,

    /// Frame ceiling, in frames per second.
    #[serde(default = "default_max_fps")]
    pub max_fps: u8,

    /// Tile edge in pixels: one of [`LEGAL_TILE_EDGES`].
    #[serde(default = "default_tile")]
    pub tile: u16,

    /// Whether a clipboard channel is offered.
    ///
    /// Defaults to `false`, because a clipboard channel exfiltrates whatever was
    /// last copied — which on an operator's machine is routinely a password, a
    /// token, or a recovery phrase that was never typed into any of the fields
    /// this project protects.
    #[serde(default)]
    pub allow_clipboard: bool,

    /// Agent respawns tolerated per hour before the state machine stops trying
    /// and says so.
    ///
    /// Zero is legal and means "never respawn": a single failure ends the
    /// session with a reported reason. That is a defensible posture, so it is
    /// not refused.
    #[serde(default = "default_agent_respawn_cap")]
    pub agent_respawn_cap: u32,

    /// Whether the bearer credential may drive the machine.
    ///
    /// Defaults to `false`. The bearer token is an unattended automation
    /// credential: it bypasses every browser-side defence at once — no CSRF
    /// header, no Origin, no SameSite, no session expiry, no passkey — and it
    /// cannot satisfy a freshness check, because there is nobody present to
    /// re-prove anything. It is refused control and clipboard access unless this
    /// says otherwise.
    #[serde(default)]
    pub bearer_may_control: bool,
}

fn default_reauth_window_secs() -> u64 {
    DEFAULT_REAUTH_WINDOW_SECS
}

fn default_max_session_secs() -> u64 {
    DEFAULT_MAX_SESSION_SECS
}

fn default_max_viewers() -> u32 {
    DEFAULT_MAX_VIEWERS
}

fn default_max_fps() -> u8 {
    DEFAULT_MAX_FPS
}

fn default_tile() -> u16 {
    DEFAULT_TILE
}

fn default_agent_respawn_cap() -> u32 {
    DEFAULT_AGENT_RESPAWN_CAP
}

impl Default for Desktop {
    /// The disarmed posture, which is also what every omitted field parses to:
    /// off, no input, no clipboard, no automation control.
    ///
    /// This exists so that a caller building a `Desktop` in code — a test, a
    /// future API — starts where the document starts, rather than at
    /// `bool::default()` for some fields and zero for the rest.
    fn default() -> Self {
        Self {
            enabled: false,
            allow_input: false,
            reauth_window_secs: DEFAULT_REAUTH_WINDOW_SECS,
            max_session_secs: DEFAULT_MAX_SESSION_SECS,
            max_viewers: DEFAULT_MAX_VIEWERS,
            max_fps: DEFAULT_MAX_FPS,
            tile: DEFAULT_TILE,
            allow_clipboard: false,
            agent_respawn_cap: DEFAULT_AGENT_RESPAWN_CAP,
            bearer_may_control: false,
        }
    }
}

impl Desktop {
    /// The freshness window as a [`Duration`], which is the shape `desk::Policy`
    /// takes it in.
    ///
    /// Provided so the one conversion from the config's seconds happens here
    /// rather than at each call site, where a `from_millis` typo would quietly
    /// shorten the window by a thousand.
    pub fn reauth_window(&self) -> Duration {
        Duration::from_secs(self.reauth_window_secs)
    }

    /// The session ceiling as a [`Duration`].
    pub fn max_session(&self) -> Duration {
        Duration::from_secs(self.max_session_secs)
    }

    /// Collects every structural problem with this section.
    ///
    /// `at` is the dotted path problems are reported under (`desktop`), matching
    /// every other `check` in this crate. Every rule is checked and every
    /// violation collected, so one `selfhost check` names everything that needs
    /// fixing rather than the first thing.
    pub fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        self.check_honesty(at, problems);
        self.check_limits(at, problems);
    }

    /// Refuses a block that claims a capability the block itself has switched
    /// off. See the module documentation for why these are errors rather than
    /// silent reductions.
    fn check_honesty(&self, at: &str, problems: &mut Vec<Problem>) {
        if !self.enabled {
            for (field, claimed) in [
                ("allow_input", self.allow_input),
                ("allow_clipboard", self.allow_clipboard),
                ("bearer_may_control", self.bearer_may_control),
            ] {
                if claimed {
                    problems.push(Problem {
                        field: format!("{at}.{field}"),
                        message: format!(
                            "is true while {at}.enabled is false, so it grants nothing today \
                             and grants everything the moment somebody flips one word. Set \
                             enabled = true if that is what is meant, or remove {field}; a \
                             line that reads as permission must not be one edit away from \
                             being permission."
                        ),
                    });
                }
            }
        }

        if self.bearer_may_control && !self.allow_input && !self.allow_clipboard {
            problems.push(Problem {
                field: format!("{at}.bearer_may_control"),
                message: format!(
                    "widens the bearer token to capabilities this deployment does not grant \
                     anyone: {at}.allow_input and {at}.allow_clipboard are both false. Grant \
                     one of them, or remove this line rather than leaving an automation \
                     credential documented as privileged."
                ),
            });
        }
    }

    /// Refuses a value outside the range the running subsystem can honour.
    fn check_limits(&self, at: &str, problems: &mut Vec<Problem>) {
        if !LEGAL_TILE_EDGES.contains(&self.tile) {
            problems.push(Problem {
                field: format!("{at}.tile"),
                message: format!(
                    "{} is not one of {LEGAL_TILE_EDGES:?}. The tile edge is a closed set \
                     rather than a range because the codec's grid arithmetic is bounded \
                     against exactly these four.",
                    self.tile
                ),
            });
        }

        if self.max_fps == 0 || self.max_fps > MAX_FPS_CEILING {
            let why = if self.max_fps == 0 {
                "a stream that never sends a frame"
            } else {
                "past the point where the encoder, not the link, is the bottleneck — and a \
                 desktop stream that saturates a core starves every other service on this box, \
                 including the proxy the operator would need in order to turn it off"
            };
            problems.push(Problem {
                field: format!("{at}.max_fps"),
                message: format!(
                    "must be between 1 and {MAX_FPS_CEILING}; {} is {why}",
                    self.max_fps
                ),
            });
        }

        if self.max_viewers == 0 || self.max_viewers > MAX_VIEWERS_CEILING {
            problems.push(Problem {
                field: format!("{at}.max_viewers"),
                message: format!(
                    "must be between 1 and {MAX_VIEWERS_CEILING}; {} either admits nobody at \
                     all or asks this box to encode the same screen more times than it can \
                     afford — and every viewer sees whatever is on it",
                    self.max_viewers
                ),
            });
        }

        if self.reauth_window_secs < MIN_REAUTH_WINDOW_SECS {
            problems.push(Problem {
                field: format!("{at}.reauth_window_secs"),
                message: format!(
                    "must be at least {MIN_REAUTH_WINDOW_SECS}; below that the operator \
                     cannot finish typing a password before the proof expires, so no control \
                     ticket can ever be minted"
                ),
            });
        } else if self.reauth_window_secs > MAX_REAUTH_WINDOW_SECS {
            problems.push(Problem {
                field: format!("{at}.reauth_window_secs"),
                message: format!(
                    "must be at most {MAX_REAUTH_WINDOW_SECS} ({} minutes); the check exists \
                     so that driving this machine costs a *recent* proof, and past that \
                     \"recent\" no longer describes anything an attacker sitting in the \
                     operator's browser would find inconvenient",
                    MAX_REAUTH_WINDOW_SECS / 60
                ),
            });
        }

        if self.max_session_secs < MIN_MAX_SESSION_SECS
            || self.max_session_secs > MAX_MAX_SESSION_SECS
        {
            problems.push(Problem {
                field: format!("{at}.max_session_secs"),
                message: format!(
                    "must be between {MIN_MAX_SESSION_SECS} and {MAX_MAX_SESSION_SECS} \
                     seconds; a ceiling longer than a day outlives the operator's working \
                     day, their laptop's lid, and any memory of having opened the session"
                ),
            });
        }

        // Checked after both bounds so the operator is not told the window is
        // meaningless when the real complaint is that one of the two numbers is
        // outside its own range.
        if self.reauth_window_secs >= self.max_session_secs {
            problems.push(Problem {
                field: format!("{at}.reauth_window_secs"),
                message: format!(
                    "is {}s, which is not shorter than {at}.max_session_secs ({}s), so \
                     proving a password once at the start of a session would satisfy every \
                     control ticket that session ever mints. That is exactly the \"a live \
                     session is enough\" posture the freshness check exists to reject.",
                    self.reauth_window_secs, self.max_session_secs
                ),
            });
        }

        if self.agent_respawn_cap > MAX_AGENT_RESPAWN_CAP {
            problems.push(Problem {
                field: format!("{at}.agent_respawn_cap"),
                message: format!(
                    "must be at most {MAX_AGENT_RESPAWN_CAP} per hour; above that the daemon \
                     is being asked to spend the machine relaunching a process that cannot \
                     run, rather than to report that it cannot run"
                ),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problems_of(desktop: &Desktop) -> Vec<Problem> {
        let mut problems = Vec::new();
        desktop.check("desktop", &mut problems);
        problems
    }

    fn has(problems: &[Problem], field: &str) -> bool {
        problems.iter().any(|p| p.field == field)
    }

    /// An enabled, view-only deployment: the smallest thing that is not off.
    fn viewing_only() -> Desktop {
        Desktop { enabled: true, ..Desktop::default() }
    }

    #[test]
    fn every_dangerous_default_is_off() {
        // The whole safety argument for this section rests on this test. If any
        // of these flips, adding an empty [desktop] block arms a keyboard.
        let default = Desktop::default();
        assert!(!default.enabled);
        assert!(!default.allow_input);
        assert!(!default.allow_clipboard);
        assert!(!default.bearer_may_control);
        assert!(problems_of(&default).is_empty(), "the off posture must itself be valid");
    }

    #[test]
    fn an_empty_block_parses_to_the_off_posture() {
        // A bare `[desktop]` with no keys must equal Default, or the document's
        // safety argument and the type's would differ.
        let parsed: Desktop = toml::from_str("").expect("every field defaults");
        assert_eq!(parsed, Desktop::default());
    }

    #[test]
    fn a_capability_claimed_while_disabled_is_refused() {
        for field in ["allow_input", "allow_clipboard", "bearer_may_control"] {
            let mut broken = Desktop::default();
            match field {
                "allow_input" => broken.allow_input = true,
                "allow_clipboard" => broken.allow_clipboard = true,
                _ => broken.bearer_may_control = true,
            }
            let problems = problems_of(&broken);
            assert!(has(&problems, &format!("desktop.{field}")), "{field}: {problems:?}");
        }
    }

    #[test]
    fn bearer_control_over_capabilities_nobody_holds_is_refused() {
        let mut broken = viewing_only();
        broken.bearer_may_control = true;
        assert!(has(&problems_of(&broken), "desktop.bearer_may_control"));

        // Granting either one makes the line mean something.
        let mut driving = broken;
        driving.allow_input = true;
        assert!(problems_of(&driving).is_empty(), "{:?}", problems_of(&driving));

        let mut pasting = broken;
        pasting.allow_clipboard = true;
        assert!(problems_of(&pasting).is_empty(), "{:?}", problems_of(&pasting));
    }

    #[test]
    fn the_tile_edge_is_a_closed_set() {
        for edge in LEGAL_TILE_EDGES {
            let ok = Desktop { tile: edge, ..viewing_only() };
            assert!(problems_of(&ok).is_empty(), "{edge}: {:?}", problems_of(&ok));
        }
        for edge in [0, 1, 15, 48, 100, 129, 256, u16::MAX] {
            let broken = Desktop { tile: edge, ..viewing_only() };
            assert!(has(&problems_of(&broken), "desktop.tile"), "{edge}");
        }
    }

    #[test]
    fn max_fps_must_be_between_one_and_the_ceiling() {
        for fps in [0, MAX_FPS_CEILING + 1, u8::MAX] {
            let broken = Desktop { max_fps: fps, ..viewing_only() };
            assert!(has(&problems_of(&broken), "desktop.max_fps"), "{fps}");
        }
        for fps in [1, 30, MAX_FPS_CEILING] {
            let ok = Desktop { max_fps: fps, ..viewing_only() };
            assert!(problems_of(&ok).is_empty(), "{fps}");
        }
    }

    #[test]
    fn max_viewers_must_admit_someone_and_not_everyone() {
        for viewers in [0, MAX_VIEWERS_CEILING + 1, u32::MAX] {
            let broken = Desktop { max_viewers: viewers, ..viewing_only() };
            assert!(has(&problems_of(&broken), "desktop.max_viewers"), "{viewers}");
        }
        for viewers in [1, MAX_VIEWERS_CEILING] {
            let ok = Desktop { max_viewers: viewers, ..viewing_only() };
            assert!(problems_of(&ok).is_empty(), "{viewers}");
        }
    }

    #[test]
    fn a_reauth_window_outside_the_usable_range_is_refused() {
        for window in [0, MIN_REAUTH_WINDOW_SECS - 1, MAX_REAUTH_WINDOW_SECS + 1] {
            let broken = Desktop { reauth_window_secs: window, ..viewing_only() };
            assert!(has(&problems_of(&broken), "desktop.reauth_window_secs"), "{window}");
        }
    }

    #[test]
    fn a_reauth_window_that_spans_the_session_is_refused_as_meaningless() {
        // The subtle one: both numbers are individually legal, and together they
        // reduce the freshness check to "you logged in at some point".
        let broken =
            Desktop { reauth_window_secs: 600, max_session_secs: 600, ..viewing_only() };
        let problems = problems_of(&broken);
        assert!(has(&problems, "desktop.reauth_window_secs"), "{problems:?}");
        assert!(
            problems.iter().any(|p| p.message.contains("max_session_secs")),
            "the message must name the other half of the comparison: {problems:?}"
        );

        let ok = Desktop { reauth_window_secs: 599, max_session_secs: 600, ..viewing_only() };
        assert!(problems_of(&ok).is_empty(), "{:?}", problems_of(&ok));
    }

    #[test]
    fn a_session_ceiling_outside_its_range_is_refused() {
        for ceiling in [0, MIN_MAX_SESSION_SECS - 1, MAX_MAX_SESSION_SECS + 1] {
            let broken = Desktop { max_session_secs: ceiling, ..viewing_only() };
            assert!(has(&problems_of(&broken), "desktop.max_session_secs"), "{ceiling}");
        }
    }

    #[test]
    fn never_respawning_is_a_posture_and_not_an_error() {
        let ok = Desktop { agent_respawn_cap: 0, ..viewing_only() };
        assert!(problems_of(&ok).is_empty(), "{:?}", problems_of(&ok));

        let broken = Desktop { agent_respawn_cap: MAX_AGENT_RESPAWN_CAP + 1, ..viewing_only() };
        assert!(has(&problems_of(&broken), "desktop.agent_respawn_cap"));
    }

    #[test]
    fn durations_convert_from_seconds_exactly_once() {
        let desktop = Desktop::default();
        assert_eq!(desktop.reauth_window(), Duration::from_secs(DEFAULT_REAUTH_WINDOW_SECS));
        assert_eq!(desktop.max_session(), Duration::from_secs(DEFAULT_MAX_SESSION_SECS));
    }

    #[test]
    fn every_problem_is_collected_rather_than_only_the_first() {
        let broken = Desktop {
            enabled: false,
            allow_input: true,
            allow_clipboard: true,
            tile: 63,
            max_fps: 0,
            ..Desktop::default()
        };
        let problems = problems_of(&broken);
        for field in [
            "desktop.allow_input",
            "desktop.allow_clipboard",
            "desktop.tile",
            "desktop.max_fps",
        ] {
            assert!(has(&problems, field), "{field} missing from {problems:?}");
        }
    }

    #[test]
    fn the_section_parses_from_toml_and_is_optional() {
        let with = crate::Config::parse(
            r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "a"
domains = ["example.com"]
static_root = "./public"

[desktop]
enabled = true
allow_input = true
reauth_window_secs = 60
max_session_secs = 3600
max_viewers = 1
max_fps = 24
tile = 32
"#,
        )
        .expect("valid");
        let desktop = with.desktop.expect("desktop present");
        assert!(desktop.enabled);
        assert!(desktop.allow_input);
        assert_eq!(desktop.tile, 32);
        // Fields the block never mentioned stay at the closed default.
        assert!(!desktop.allow_clipboard);
        assert!(!desktop.bearer_may_control);
        assert_eq!(desktop.agent_respawn_cap, DEFAULT_AGENT_RESPAWN_CAP);

        let without = crate::Config::parse(
            r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "a"
domains = ["example.com"]
static_root = "./public"
"#,
        )
        .expect("valid");
        assert!(without.desktop.is_none(), "absent means the subsystem does not exist");
    }

    #[test]
    fn the_documented_example_loads_and_describes_the_off_posture() {
        // A documented example that does not parse is worse than none, and one
        // that parses to something other than what it says is worse still.
        let document = format!("{}\n{EXAMPLE}", crate::BASE_DOCUMENT);
        let config = crate::Config::parse(&document).expect("the documented example must load");
        assert_eq!(config.desktop, Some(Desktop::default()));
    }

    #[test]
    fn the_shipped_example_arms_nothing() {
        // The whole point of shipping it commented out: pasting the block into a
        // config file, as `selfhost init` writes it, must leave the subsystem
        // non-existent until somebody deliberately uncomments it.
        let document = format!("{}\n{}", crate::BASE_DOCUMENT, crate::commented(EXAMPLE));
        let config = crate::Config::parse(&document).expect("valid");
        assert!(config.desktop.is_none());
    }

    #[test]
    fn a_dishonest_section_fails_validation_at_load() {
        let outcome = crate::Config::parse(
            r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "a"
domains = ["example.com"]
static_root = "./public"

[desktop]
enabled = false
allow_input = true
"#,
        );
        match outcome {
            Err(crate::ConfigError::Invalid(problems)) => {
                assert!(has(&problems, "desktop.allow_input"), "{problems:?}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }
}
