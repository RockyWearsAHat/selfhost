//! The Windows session-0 plan: the pure half here, the FFI in the submodules.
//!
//! # The problem this module exists to solve
//!
//! On the production box the daemon is a Scheduled Task running as `SYSTEM` at
//! system startup, which puts it in **session 0** — a session with no
//! interactive display, created for services precisely so that services cannot
//! be reached by the person at the keyboard. Nothing running there can capture
//! the user's desktop. `DuplicateOutput` fails; `GetDC(NULL)` returns a device
//! context for session 0's own blank desktop and blits black pixels from it all
//! day without reporting an error. The fix is not a privilege or a flag: it is a
//! second process, running inside the console session, that the daemon starts and
//! talks to. Building that first, before any capture code exists, is the whole
//! shape of this phase.
//!
//! The sequence, each step of which is load-bearing:
//!
//! 1. `WTSGetActiveConsoleSessionId` — which session is on the physical console.
//!    `0xFFFFFFFF` means *ask again*, not *error*.
//! 2. `WTSQueryUserToken` — the console user's token. Needs `LocalSystem` and
//!    `SE_TCB_NAME`, which the daemon has. `ERROR_NO_TOKEN` means nobody is
//!    logged in, which is a state and not a failure.
//! 3. `DuplicateTokenEx` to a *primary* token, because `CreateProcessAsUserW`
//!    will not take an impersonation token.
//! 4. `CreateEnvironmentBlock` — **mandatory**. Without it the agent inherits
//!    `SYSTEM`'s `APPDATA`, `TEMP` and `USERPROFILE` and writes into the service
//!    profile while appearing to run as the user.
//! 5. `STARTUPINFOW.lpDesktop = "winsta0\\default"` — **mandatory**. Without it
//!    the process lands on a non-interactive desktop where it is running, is
//!    invisible, and can capture nothing.
//! 6. `CreateProcessAsUserW` with `bInheritHandles = FALSE`, because handles
//!    cannot be inherited across sessions — which is *why* the IPC has to be a
//!    named object rather than an inherited pipe.
//!
//! The command line that call is given is built by
//! [`crate::agent::agent_arguments`] and carries two things: the session the
//! supervisor aimed at, and whether this deployment permits input at all. The
//! second is the *only* route by which `[desktop].allow_input` reaches the agent,
//! which is a separate process that cannot read the daemon's config — see
//! [`crate::agent::InputPolicy`] for why it travels here rather than as a message
//! on the pipe.
//!
//! # Why the pure half lives up here
//!
//! Three of the decisions in that sequence are strings, and all three are
//! security-critical: the pipe's name, the pipe's DACL, and the command line. A
//! wrong DACL is a keyboard that any local process can drive. So they are built
//! by pure functions in this file, which compiles on **every** platform and is
//! therefore tested on the developer's Mac, where the rest of this module cannot
//! even be compiled. The submodules below hold the `unsafe` and are Windows-only.
//!
//! The capture half that arrived later keeps the same split. Every decision about
//! *pixels* — a cursor's identity, the alpha rescue, the four monochrome mask
//! combinations — is a pure function down this file with a test beside it, and
//! [`cursor`] is left holding only the calls and the handles they hand over.
//!
//! # The submodules
//!
//! - [`sys`] — the raw declarations, and nothing else.
//! - [`desktop`] — which session is on the console, who is in it, which desktop is
//!   in front.
//! - [`spawn`] — the sequence above, written out once.
//! - [`pipe`] — both ends of the channel: the daemon's `AgentPipe` and the agent's
//!   `DaemonLink`.
//! - [`gdi`] — screen capture: one reused top-down DIB section, one `BitBlt` a
//!   frame, and the layout checks that turn a resolution, topology or DPI change
//!   into a rebuild rather than a stale picture. It cannot see Direct3D.
//! - [`dxgi`] — the other screen capture: DXGI Desktop Duplication, which reads
//!   the composited output and therefore *can* see a game. The only COM in this
//!   workspace.
//! - [`capture`] — which of the two a machine gets, and the sentence explaining
//!   what it loses if it gets the older one.
//! - [`cursor`] — the pointer, captured separately so the client composites it,
//!   and the `DeleteObject` discipline that keeps the GDI handle count flat.
//! - [`identity`] — what the agent can only learn about itself from inside its own
//!   session: DPI awareness, window station, desktop and integrity level.
//! - [`inject`] — `SendInput`, the foreground window's integrity level, and the
//!   release of everything held when the session ends.
//!
//! # The pipe's ACL is the authentication
//!
//! There is no shared secret between daemon and agent, and deliberately so.
//! `\\.\pipe\selfhost-desk-<sessionId>` is created with
//! `FILE_FLAG_FIRST_PIPE_INSTANCE` and an explicit DACL naming only `SYSTEM` and
//! the console user's own SID — never a NULL DACL, which grants everyone
//! everything. A loopback TCP socket with a token in the environment block was
//! considered and rejected outright: a loopback listener is reachable by every
//! local process, a same-user process can read another process's environment
//! block, and the resulting exposure is the operator's remote keystrokes plus a
//! race to become the screen source.

use crate::agent::Integrity;
use selfhost_desk::wire::{Monitor, Refusal};
use std::fmt;
use std::path::Path;

#[cfg(windows)]
pub mod capture;
#[cfg(windows)]
pub mod cursor;
#[cfg(windows)]
pub mod desktop;
#[cfg(windows)]
pub mod dxgi;
#[cfg(windows)]
pub mod gdi;
#[cfg(windows)]
pub mod identity;
#[cfg(windows)]
pub mod inject;
#[cfg(windows)]
pub mod pipe;
#[cfg(windows)]
pub mod spawn;
#[cfg(windows)]
pub(crate) mod sys;

/// The prefix every agent pipe name shares.
///
/// Local (`\\.\`) rather than a network path: a pipe reachable over SMB would be
/// a keyboard reachable from the LAN, which no ACL should be the only thing
/// standing in front of.
pub const PIPE_PREFIX: &str = r"\\.\pipe\selfhost-desk-";

/// The window station and desktop an interactive process must be started on.
///
/// Spelled here rather than at the call site because getting it wrong produces a
/// process that starts, runs, reports no error and is invisible — the single
/// hardest failure in this module to recognise from a log.
pub const INTERACTIVE_DESKTOP: &str = r"winsta0\default";

/// Something the plan refused to build.
///
/// All three are refusals of *input* rather than platform failures, which is why
/// they are not [`crate::Fault`]: nothing was called yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// A security identifier that is not in the form `S-1-…`.
    ///
    /// The SID reaching this function comes from `ConvertSidToStringSidW` and is
    /// therefore already trustworthy — the check is defence in depth. It matters
    /// because the SID is *concatenated into an SDDL string*: a value containing
    /// `)(A;;FA;;;WD` would append an access-control entry granting Everyone full
    /// access to the pipe that drives the keyboard, and the resulting descriptor
    /// would parse perfectly.
    MalformedSid {
        /// What was offered, so the operator can see it.
        offered: String,
    },
    /// A string destined for a Win32 wide string contained a NUL.
    ///
    /// Refused rather than truncated: a truncated path is a different file, and a
    /// truncated command line is different arguments.
    InteriorNul {
        /// Which string it was.
        field: &'static str,
    },
    /// An executable path with nothing in it.
    NoExecutable,
}

impl PlanError {
    /// The refusal as one sentence.
    pub fn sentence(&self) -> String {
        match self {
            Self::MalformedSid { offered } => format!(
                "Refusing to build a security descriptor around {offered:?}, which is not a \
                 well-formed security identifier."
            ),
            Self::InteriorNul { field } => {
                format!("The {field} contains a NUL character and cannot be passed to Windows.")
            }
            Self::NoExecutable => "No agent executable was given to start.".to_owned(),
        }
    }
}

impl fmt::Display for PlanError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(&self.sentence())
    }
}

impl std::error::Error for PlanError {}

/// The pipe the agent for `session` connects to.
///
/// Named per session rather than once per machine, so that two sessions — the
/// console and an RDP session mid-switch — cannot collide on one object, and so
/// that a stale agent from the previous session cannot answer for the new one.
pub fn pipe_name(session: u32) -> String {
    format!("{PIPE_PREFIX}{session}")
}

/// The security descriptor the agent pipe is created under.
///
/// `D:P(A;;FA;;;SY)(A;;FRFW;;;<user>)`:
///
/// - `D:` a discretionary ACL, and `P` for **protected** — no access-control
///   entry is inherited from anywhere, so the descriptor says exactly what it
///   says and nothing the containing object grants leaks in.
/// - `(A;;FA;;;SY)` full access for `LocalSystem`, which is what the daemon runs
///   as and therefore what has to create, listen on and tear down the pipe.
/// - `(A;;FRFW;;;<user>)` read and write — and nothing else — for the console
///   user's own SID. Not `FA`: full access includes `WRITE_DAC`, and an agent
///   that can rewrite the descriptor of its own channel can open that channel to
///   anybody. The agent needs to read and write bytes; that is all it gets.
///
/// Nobody else is named, and the absence of a `WD` (Everyone) entry is the whole
/// security property: a same-user process at the same integrity level *is* still
/// admitted, which is inherent — Windows has no way to distinguish two processes
/// of one user on a pipe — and is why `FILE_FLAG_FIRST_PIPE_INSTANCE` and the
/// client-identity check in the `pipe` submodule both exist alongside this.
///
/// Modelled on `crates/admin/src/token.rs`'s `SECRET_DACL`, which protects the
/// deployment's root credential with the same protected-DACL shape.
pub fn pipe_descriptor(user_sid: &str) -> Result<String, PlanError> {
    if !is_well_formed_sid(user_sid) {
        return Err(PlanError::MalformedSid { offered: user_sid.to_owned() });
    }
    Ok(format!("D:P(A;;FA;;;SY)(A;;FRFW;;;{user_sid})"))
}

/// The longest a string-form SID can be, from the format's own limits.
///
/// A SID holds at most 15 sub-authorities; the string form is `S-1-` plus a
/// 48-bit identifier authority plus those, each up to ten digits with a
/// separator. 184 is the documented ceiling and is used here so that a
/// pathologically long value is refused before it is measured against a pattern.
const MAX_SID_TEXT: usize = 184;

/// Whether a string is a well-formed string-form security identifier.
///
/// Strict on purpose: `S-1-` then decimal components separated by single hyphens,
/// nothing else, no leading or trailing hyphen, no empty component, no letters.
/// Windows also accepts a hexadecimal identifier authority and two-letter
/// abbreviations such as `BA`, and this function accepts neither — the value we
/// pass always comes from `ConvertSidToStringSidW`, which produces the decimal
/// form, and every character we do not accept is a character that cannot appear
/// inside an SDDL access-control entry we did not write.
pub fn is_well_formed_sid(text: &str) -> bool {
    if text.len() > MAX_SID_TEXT || !text.is_ascii() {
        return false;
    }
    let Some(rest) = text.strip_prefix("S-1-") else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    rest.split('-').all(|component| {
        !component.is_empty()
            && component.len() <= 20
            && component.bytes().all(|byte| byte.is_ascii_digit())
    })
}

/// Builds the writable `lpCommandLine` `CreateProcessAsUserW` needs.
///
/// Windows does not take an argument vector: it takes one string that the child
/// parses back apart, and the rules for doing so are the ones `CommandLineToArgvW`
/// implements — quotes around anything containing whitespace, backslashes doubled
/// only where they precede a quote. Getting them wrong does not fail; it starts
/// the agent with different arguments than intended, which for a process that is
/// handed a session id and a pipe name means it connects to the wrong object or
/// to none.
///
/// The executable is repeated as the first element, as `argv[0]`, because
/// `lpApplicationName` is passed separately and non-NULL — the documented way to
/// avoid Windows' path-searching heuristics, which will happily run
/// `C:\Program.exe` for an unquoted `C:\Program Files\…`.
pub fn command_line(executable: &Path, arguments: &[&str]) -> Result<String, PlanError> {
    let program = executable.to_string_lossy();
    if program.is_empty() {
        return Err(PlanError::NoExecutable);
    }
    if program.contains('\0') {
        return Err(PlanError::InteriorNul { field: "agent executable path" });
    }

    let mut line = String::new();
    append_argument(&mut line, &program);
    for argument in arguments {
        if argument.contains('\0') {
            return Err(PlanError::InteriorNul { field: "agent argument" });
        }
        line.push(' ');
        append_argument(&mut line, argument);
    }
    Ok(line)
}

/// Appends one argument, quoted by `CommandLineToArgvW`'s rules.
fn append_argument(line: &mut String, argument: &str) {
    let needs_quotes = argument.is_empty()
        || argument.chars().any(|character| matches!(character, ' ' | '\t' | '"'));
    if !needs_quotes {
        line.push_str(argument);
        return;
    }

    line.push('"');
    let mut backslashes = 0usize;
    for character in argument.chars() {
        match character {
            '\\' => {
                backslashes += 1;
                line.push('\\');
            }
            '"' => {
                // A quote is escaped by one backslash, and every backslash
                // immediately before it must itself be doubled — so the run of
                // `backslashes` already written needs that many more, plus one.
                for _ in 0..=backslashes {
                    line.push('\\');
                }
                line.push('"');
                backslashes = 0;
            }
            other => {
                backslashes = 0;
                line.push(other);
            }
        }
    }
    // Backslashes at the very end sit immediately before the closing quote and
    // must be doubled too, or the quote is escaped and the argument runs on.
    for _ in 0..backslashes {
        line.push('\\');
    }
    line.push('"');
}

/// Which desktop is receiving input in the interactive session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputDesktop {
    /// The ordinary interactive desktop, where the user's programs live.
    Default,
    /// `Winlogon`: the secure desktop. A UAC consent dialog, the lock screen, or
    /// the credential provider. Never captured and input suspends here — a
    /// channel that could both render and drive the consent dialog would be a
    /// remote privilege-escalation channel by construction.
    Secure,
    /// The screen saver's own desktop.
    ScreenSaver,
    /// A desktop this build does not recognise, named so the operator can see it
    /// rather than being told "unknown".
    Other(String),
}

impl InputDesktop {
    /// Whether the screen may be captured and input performed here.
    pub fn is_capturable(&self) -> bool {
        matches!(self, Self::Default)
    }
}

/// Classifies a desktop by the name `GetUserObjectInformationW` reported.
///
/// Case-insensitive because the platform's own spelling has varied across
/// releases and a comparison that depends on it would break silently — into
/// "unrecognised desktop", which suspends a session that should be live.
pub fn classify_desktop(name: &str) -> InputDesktop {
    if name.eq_ignore_ascii_case("Default") {
        InputDesktop::Default
    } else if name.eq_ignore_ascii_case("Winlogon") {
        InputDesktop::Secure
    } else if name.eq_ignore_ascii_case("Screen-saver") || name.eq_ignore_ascii_case("Screensaver")
    {
        InputDesktop::ScreenSaver
    } else {
        InputDesktop::Other(name.to_owned())
    }
}

/// An identity for a cursor shape that survives a recycled handle.
///
/// The obvious identity is the `HCURSOR` value, and it is what the wire carries.
/// The trouble is that an application which creates cursors — an image editor with
/// a brush preview, a terminal with its own I-beam — destroys them too, and
/// Windows reuses handle values. A client caching by handle alone would eventually
/// draw a stale bitmap for a shape that merely inherited an address.
///
/// So the id folds the handle together with the extent and the hotspot. Two
/// different shapes that share a recycled handle *and* have identical dimensions
/// can still collide, and are then drawn with the wrong one of two same-sized
/// bitmaps until the shape changes again — a far smaller wrong than the
/// alternative, and the honest description of what a handle-derived identity can
/// promise.
pub fn shape_id(handle: u64, width: u32, height: u32, hotspot_x: u32, hotspot_y: u32) -> u64 {
    // FNV-1a: four lines, no dependency, and asked to spread five small integers
    // rather than to resist an adversary.
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for value in [
        handle,
        u64::from(width),
        u64::from(height),
        u64::from(hotspot_x),
        u64::from(hotspot_y),
    ] {
        for byte in value.to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(PRIME);
        }
    }
    hash
}

/// Whether a BGRA image carries any alpha at all.
///
/// Asked of every colour cursor, because plenty of 32-bit cursors — including ones
/// Windows itself ships — have an all-zero alpha channel and rely entirely on the
/// AND mask. Sending those through unchanged produces a **completely invisible
/// pointer** on any client that correctly honours the alpha it was given.
pub fn alpha_present(bgra: &[u8]) -> bool {
    bgra.chunks_exact(4).any(|pixel| pixel.get(3).is_some_and(|alpha| *alpha != 0))
}

/// Makes every pixel opaque, for a shape with neither alpha nor a usable mask.
pub fn force_opaque(bgra: &mut [u8]) {
    for pixel in bgra.chunks_exact_mut(4) {
        if let Some(alpha) = pixel.get_mut(3) {
            *alpha = 0xFF;
        }
    }
}

/// Recovers a cursor's alpha from its AND mask.
///
/// The mask arrives having been read back as 32-bit BGRA, so a set mask bit is a
/// white pixel and a clear one is black. White means *the desktop shows through*,
/// which is the opposite polarity to alpha and is the sign error this function
/// exists to make once, in a place a test can see.
///
/// A mask shorter than the image leaves the remaining pixels opaque rather than
/// refusing: a partly-decoded pointer is visible and slightly wrong, where a
/// refusal is a session with no pointer at all.
pub fn mask_alpha(bgra: &mut [u8], mask: &[u8]) {
    for (index, pixel) in bgra.chunks_exact_mut(4).enumerate() {
        let transparent = mask.get(index * 4).is_some_and(|blue| *blue != 0);
        if let Some(alpha) = pixel.get_mut(3) {
            *alpha = if transparent { 0x00 } else { 0xFF };
        }
    }
}

/// Composes a monochrome cursor from the stacked AND and XOR masks.
///
/// A monochrome cursor has no colour bitmap: its mask bitmap is twice the cursor's
/// height and holds the AND mask above the XOR mask. Both halves arrive here
/// already read back as 32-bit BGRA, so a set bit is a white pixel.
///
/// | AND | XOR | meaning                   |
/// |-----|-----|---------------------------|
/// | 0   | 0   | opaque black              |
/// | 0   | 1   | opaque white              |
/// | 1   | 0   | transparent               |
/// | 1   | 1   | **invert** what is behind |
///
/// The last combination cannot be expressed in a bitmap the client composites, and
/// there is no honest way to fake it: inverting needs the pixels behind the
/// pointer, which the client has and this format does not describe. It is drawn as
/// opaque black — what the classic monochrome I-beam looks like over the light
/// background it spends its life on, and legible against most others.
///
/// Missing bytes are treated as transparent rather than refused, for the same
/// reason as [`mask_alpha`].
pub fn monochrome_bgra(width: u32, height: u32, stacked: &[u8]) -> Vec<u8> {
    let pixels = (width as usize).saturating_mul(height as usize);
    let half = pixels.saturating_mul(4);
    let mut bgra = vec![0u8; half];
    for index in 0..pixels {
        let byte = index * 4;
        let and = stacked.get(byte).copied().unwrap_or(0xFF) != 0;
        let xor = stacked.get(half.saturating_add(byte)).copied().unwrap_or(0) != 0;
        let (colour, alpha) = match (and, xor) {
            (false, false) => (0x00u8, 0xFFu8),
            (false, true) => (0xFF, 0xFF),
            (true, false) => (0x00, 0x00),
            (true, true) => (0x00, 0xFF),
        };
        if let Some(pixel) = bgra.get_mut(byte..byte + 4) {
            pixel.fill(colour);
            if let Some(slot) = pixel.get_mut(3) {
                *slot = alpha;
            }
        }
    }
    bgra
}

// ══ User Interface Privilege Isolation ════════════════════════════════════════
//
// The pure half of the honest-refusal requirement. The calls that produce a
// `ForegroundIntegrity` live in `inject`, and the policy that turns one into a
// refusal lives here, where it is tested on a machine with no windows at all.

/// What could be learned about the window that currently has the focus.
///
/// Three answers rather than two, because "we could not find out" and "Windows
/// refused to tell us" mean opposite things and lead to opposite decisions. See
/// [`uipi_verdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForegroundIntegrity {
    /// The window's integrity level was read.
    Known(Integrity),
    /// Opening the window's process, or reading its token, was refused.
    ///
    /// This is **evidence**, not an absence of it. Windows grants
    /// `PROCESS_QUERY_LIMITED_INFORMATION` to a medium-integrity process against
    /// any process of the same user at the same or a lower level; being refused
    /// therefore means the target is above us or belongs to somebody else, and in
    /// both cases injection into it will be discarded.
    Denied,
    /// There is no foreground window, or the query failed for a reason that says
    /// nothing about integrity — a window that closed between two calls, a desktop
    /// switch in progress.
    Unknown,
}

/// Whether input must be refused because the focused window is above the agent.
///
/// # Why this exists at all, and why it must never be "fixed"
///
/// The agent runs as the console user at **medium** integrity, deliberately and
/// permanently. User Interface Privilege Isolation therefore discards any input it
/// synthesises into a window at a higher level — an elevated PowerShell, an
/// installer, anything launched through a consent prompt — and it does so
/// *silently*: `SendInput` returns the full count and `GetLastError` is untouched.
/// From the far end that is indistinguishable from a frozen machine.
///
/// So the agent detects what can be detected and reports `input-refused (elevated
/// window)` as a **state**. This is normal behaviour to be surfaced, never a bug to
/// be chased.
///
/// The tempting fix — running the agent as `SYSTEM`, or with `uiAccess` — would
/// make this feature a **remote privilege-escalation channel**: a session that can
/// drive an elevated window can drive the UAC consent dialog that creates one, and
/// at that point the remote-desktop capability and full administrative control of
/// the machine are the same capability. `uiAccess` is unavailable here anyway (it
/// requires an Authenticode signature and installation under a UAC-protected path,
/// while this tree builds ad-hoc-signed binaries into a user directory and rewrites
/// them on every push), but the reason it is not pursued is the first one.
pub fn uipi_verdict(own: Integrity, foreground: ForegroundIntegrity) -> Option<Refusal> {
    match foreground {
        ForegroundIntegrity::Known(level) if level.rid() > own.rid() => {
            Some(Refusal::ElevatedWindow)
        }
        ForegroundIntegrity::Known(_) => None,
        ForegroundIntegrity::Denied => Some(Refusal::ElevatedWindow),
        // Never refuse on an absence of evidence: a session that suspended input
        // every time a window closed mid-query would be unusable, and the honest
        // description of this case is that UIPI's silence has not been detected —
        // which is exactly what the trait's documentation already promises.
        ForegroundIntegrity::Unknown => None,
    }
}

/// Whether an event is one that UIPI would swallow.
///
/// Pointer **movement** is excluded on purpose. The window server moves the cursor
/// itself, so a move is not delivered *to* the elevated window and is not blocked;
/// refusing it would freeze the pointer whenever an elevated window has focus,
/// which looks exactly like a dead session. Everything that is actually delivered
/// to the focused window — keys, text, buttons, the wheel — is refused, so the
/// console can say why it did nothing.
///
/// The same split is made on macOS for secure input, for the same reason.
pub fn blocked_by_elevation(event: &crate::input::InjectedEvent) -> bool {
    use crate::input::InjectedEvent;
    match event {
        InjectedEvent::Key { .. }
        | InjectedEvent::Text { .. }
        | InjectedEvent::Button { .. }
        | InjectedEvent::Scroll { .. } => true,
        InjectedEvent::PointerMove { .. } => false,
    }
}

/// Whether a DXGI output's rectangle is the display a [`Monitor`] describes.
///
/// # Why the match is on geometry and not on an index
///
/// `IDXGIAdapter::EnumOutputs` and `EnumDisplayMonitors` are two independent
/// orderings of the same displays. They agree on most machines and not on all, and
/// a viewer that quietly shows the *other* monitor is a failure no log records and
/// nobody reports as one — the picture is a real screen, just not the one that was
/// asked for. `DXGI_OUTPUT_DESC::DesktopCoordinates` is the same virtual-desktop
/// rectangle [`gdi::monitors`] already read, so the two can be compared exactly.
///
/// Takes the four edges rather than the structure so that it lives here, in the
/// half of this module that compiles on every platform and is therefore tested on
/// a machine with no graphics adapter at all. See [`dxgi::DxgiCapture`].
pub fn output_covers(
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
    monitor: &Monitor,
) -> bool {
    // Saturating, because these arrive from a driver: a rectangle whose edges run
    // backwards must be refused, not overflow, in a crate that aborts on a panic.
    let width = right.saturating_sub(left);
    let height = bottom.saturating_sub(top);
    left == monitor.origin_x
        && top == monitor.origin_y
        && u32::try_from(width).is_ok_and(|width| width == monitor.width)
        && u32::try_from(height).is_ok_and(|height| height == monitor.height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A display at a place on the virtual desktop.
    fn display(origin_x: i32, origin_y: i32, width: u32, height: u32) -> Monitor {
        Monitor { id: 0, origin_x, origin_y, width, height, scale_permille: 1000, primary: true }
    }

    #[test]
    fn an_output_at_the_displays_place_is_the_display() {
        assert!(output_covers(0, 0, 2560, 1440, &display(0, 0, 2560, 1440)));
    }

    #[test]
    fn a_second_display_of_the_same_size_is_told_apart_by_where_it_is() {
        // The failure this rule prevents: two identical monitors, and a viewer
        // showing the wrong one because the two enumerations disagreed about
        // which comes first.
        let right_hand = display(2560, 0, 2560, 1440);
        assert!(!output_covers(0, 0, 2560, 1440, &right_hand));
        assert!(output_covers(2560, 0, 5120, 1440, &right_hand));
    }

    #[test]
    fn a_display_left_of_the_primary_has_negative_coordinates_and_still_matches() {
        assert!(output_covers(-1920, -200, 0, 880, &display(-1920, -200, 1920, 1080)));
    }

    #[test]
    fn an_output_of_a_different_size_at_the_same_origin_is_not_the_display() {
        assert!(!output_covers(0, 0, 1920, 1080, &display(0, 0, 2560, 1440)));
    }

    #[test]
    fn a_rectangle_whose_edges_run_backwards_matches_nothing() {
        assert!(!output_covers(0, 0, -100, -100, &display(0, 0, 2560, 1440)));
    }

    #[test]
    fn a_pipe_is_named_per_session() {
        // Per session so a stale agent from the session that just went away
        // cannot answer for the one that replaced it.
        assert_eq!(pipe_name(1), r"\\.\pipe\selfhost-desk-1");
        assert_ne!(pipe_name(1), pipe_name(2));
        assert!(pipe_name(0).starts_with(r"\\.\pipe\"), "must be a local pipe, never a UNC path");
    }

    #[test]
    fn the_descriptor_names_system_and_the_console_user_and_nobody_else() {
        let sddl = pipe_descriptor("S-1-5-21-1004336348-1177238915-682003330-1001").unwrap();
        assert_eq!(
            sddl,
            "D:P(A;;FA;;;SY)(A;;FRFW;;;S-1-5-21-1004336348-1177238915-682003330-1001)"
        );
        assert!(sddl.starts_with("D:P"), "the DACL must be protected against inheritance");
        assert!(!sddl.contains(";;;WD"), "Everyone must never appear");
        assert!(!sddl.contains(";;;AU"), "Authenticated Users must never appear");
        assert!(!sddl.contains("(A;;FA;;;S-1-5-21"), "the user gets read and write, not full access");
    }

    #[test]
    fn a_sid_that_could_smuggle_an_extra_ace_is_refused() {
        // The attack this check exists for: the SID is concatenated into SDDL, so
        // a value carrying its own access-control entry would be granted.
        let hostile = "S-1-5-21-1)(A;;FA;;;WD";
        assert_eq!(
            pipe_descriptor(hostile),
            Err(PlanError::MalformedSid { offered: hostile.to_owned() })
        );
        for bad in [
            "",
            "BA",
            "S-1-",
            "S-1--5",
            "S-1-5-",
            "-S-1-5-21-1",
            "S-1-0x5-21",
            "s-1-5-21-1",
            "S-1-5-21-1 ",
            "S-1-5-21-1;;",
            "S-1-5-21-99999999999999999999999",
        ] {
            assert!(
                pipe_descriptor(bad).is_err(),
                "{bad:?} should not have produced a descriptor"
            );
        }
    }

    #[test]
    fn ordinary_sids_are_accepted() {
        for good in [
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-5-21-1004336348-1177238915-682003330-1001",
        ] {
            assert!(is_well_formed_sid(good), "{good} should be well formed");
        }
    }

    #[test]
    fn an_absurdly_long_sid_is_refused_before_it_is_parsed() {
        let long = format!("S-1-5-21-{}", "1-".repeat(200));
        assert!(!is_well_formed_sid(&long));
    }

    #[test]
    fn a_plain_command_line_repeats_the_executable_as_argv_zero() {
        // `lpApplicationName` is non-NULL, so the first token of the command line
        // is argv[0] and not the thing Windows runs — but it still has to be
        // there or the agent reads its own first argument as its program name.
        let line = command_line(&PathBuf::from(r"C:\Selfhost\selfhost.exe"), &["desk-agent"])
            .unwrap();
        assert_eq!(line, r"C:\Selfhost\selfhost.exe desk-agent");
    }

    #[test]
    fn a_path_with_spaces_is_quoted() {
        // Unquoted, Windows would try `C:\Program.exe` first. That is a
        // privilege-escalation classic and it is why `lpApplicationName` is also
        // passed separately.
        let line =
            command_line(&PathBuf::from(r"C:\Program Files\Selfhost\selfhost.exe"), &["desk-agent"])
                .unwrap();
        assert_eq!(line, "\"C:\\Program Files\\Selfhost\\selfhost.exe\" desk-agent");
    }

    #[test]
    fn arguments_are_quoted_by_the_rules_the_child_parses_them_by() {
        let exe = PathBuf::from(r"C:\a.exe");
        assert_eq!(command_line(&exe, &["a b"]).unwrap(), r#"C:\a.exe "a b""#);
        assert_eq!(command_line(&exe, &[""]).unwrap(), r#"C:\a.exe """#);
        assert_eq!(command_line(&exe, &[r#"a"b"#]).unwrap(), r#"C:\a.exe "a\"b""#);
        // A trailing backslash inside quotes must be doubled or it escapes the
        // closing quote and the argument swallows the next one.
        assert_eq!(command_line(&exe, &[r"a b\"]).unwrap(), r#"C:\a.exe "a b\\""#);
        // Backslashes not before a quote are left alone.
        assert_eq!(command_line(&exe, &[r"C:\x\y"]).unwrap(), r"C:\a.exe C:\x\y");
        assert_eq!(command_line(&exe, &[r#"C:\x\"y"#]).unwrap(), r#"C:\a.exe "C:\x\\\"y""#);
    }

    #[test]
    fn a_nul_anywhere_is_refused_rather_than_truncating_the_command_line() {
        let exe = PathBuf::from(r"C:\a.exe");
        assert_eq!(
            command_line(&exe, &["desk-agent\0--pipe"]),
            Err(PlanError::InteriorNul { field: "agent argument" })
        );
        assert_eq!(command_line(&PathBuf::from(""), &[]), Err(PlanError::NoExecutable));
    }

    #[test]
    fn the_secure_desktop_is_recognised_however_windows_spells_it() {
        assert_eq!(classify_desktop("Winlogon"), InputDesktop::Secure);
        assert_eq!(classify_desktop("WINLOGON"), InputDesktop::Secure);
        assert!(!classify_desktop("Winlogon").is_capturable());
        assert_eq!(classify_desktop("Default"), InputDesktop::Default);
        assert!(classify_desktop("default").is_capturable());
        assert_eq!(classify_desktop("Screen-saver"), InputDesktop::ScreenSaver);
        assert!(!classify_desktop("Screen-saver").is_capturable());
    }

    #[test]
    fn an_unrecognised_desktop_is_named_rather_than_called_unknown() {
        assert_eq!(
            classify_desktop("Some-Other-Desktop"),
            InputDesktop::Other("Some-Other-Desktop".to_owned())
        );
        assert!(!classify_desktop("Some-Other-Desktop").is_capturable());
    }

    #[test]
    fn a_shape_id_separates_shapes_that_share_a_recycled_handle() {
        // The bug this blunts: an application destroys a cursor, Windows hands the
        // same address to the next one, and a client caching by handle draws the
        // old bitmap for the new shape.
        let arrow = shape_id(0x1234, 32, 32, 0, 0);
        let beam = shape_id(0x1234, 16, 24, 8, 12);
        assert_ne!(arrow, beam);
        assert_eq!(arrow, shape_id(0x1234, 32, 32, 0, 0), "one shape keeps one id");
        assert_ne!(shape_id(0x1000, 32, 32, 0, 0), shape_id(0x2000, 32, 32, 0, 0));
    }

    #[test]
    fn a_cursor_with_no_alpha_at_all_is_recognised() {
        // Every pixel opaque black with a zero alpha channel: the case that makes
        // an unrescued pointer invisible.
        let none = vec![0u8; 64];
        assert!(!alpha_present(&none));
        let mut some = none.clone();
        some[7] = 0x01;
        assert!(alpha_present(&some));
    }

    #[test]
    fn the_and_mask_is_the_opposite_polarity_to_alpha() {
        // White in the mask means the desktop shows through, which is alpha zero.
        // Getting this backwards produces a pointer-shaped hole.
        let mut bgra = vec![0u8; 8];
        let mask = [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00];
        mask_alpha(&mut bgra, &mask);
        assert_eq!(bgra[3], 0x00, "a set mask bit is transparent");
        assert_eq!(bgra[7], 0xFF, "a clear mask bit is opaque");
    }

    #[test]
    fn a_short_mask_leaves_the_rest_of_the_pointer_visible() {
        // A partly-decoded pointer is visible and slightly wrong; a refusal is a
        // session with no pointer at all.
        let mut bgra = vec![0u8; 16];
        mask_alpha(&mut bgra, &[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(bgra[3], 0x00);
        assert_eq!(bgra[7], 0xFF);
        assert_eq!(bgra[15], 0xFF);
    }

    #[test]
    fn every_monochrome_combination_composes_to_the_documented_pixel() {
        // One row of four pixels, exercising all four AND/XOR combinations. The
        // AND mask is the first half of the buffer and the XOR mask the second.
        let and = [
            0x00, 0x00, 0x00, 0x00, // 0
            0x00, 0x00, 0x00, 0x00, // 0
            0xFF, 0xFF, 0xFF, 0xFF, // 1
            0xFF, 0xFF, 0xFF, 0xFF, // 1
        ];
        let xor = [
            0x00, 0x00, 0x00, 0x00, // 0 → opaque black
            0xFF, 0xFF, 0xFF, 0xFF, // 1 → opaque white
            0x00, 0x00, 0x00, 0x00, // 0 → transparent
            0xFF, 0xFF, 0xFF, 0xFF, // 1 → invert, drawn opaque black
        ];
        let stacked: Vec<u8> = and.iter().chain(xor.iter()).copied().collect();
        let bgra = monochrome_bgra(4, 1, &stacked);
        assert_eq!(bgra.len(), 16);
        assert_eq!(&bgra[0..4], &[0x00, 0x00, 0x00, 0xFF], "opaque black");
        assert_eq!(&bgra[4..8], &[0xFF, 0xFF, 0xFF, 0xFF], "opaque white");
        assert_eq!(&bgra[8..12], &[0x00, 0x00, 0x00, 0x00], "transparent");
        assert_eq!(&bgra[12..16], &[0x00, 0x00, 0x00, 0xFF], "invert, drawn black");
    }

    #[test]
    fn a_truncated_monochrome_mask_is_composed_rather_than_refused() {
        // Under `panic = "abort"` an indexing mistake here is the whole daemon, so
        // every read is bounded and a short buffer produces a transparent pixel.
        let bgra = monochrome_bgra(4, 4, &[]);
        assert_eq!(bgra.len(), 4 * 4 * 4);
        assert!(bgra.chunks_exact(4).all(|pixel| pixel[3] == 0x00));
    }

    #[test]
    fn an_absurd_monochrome_extent_allocates_nothing_it_cannot_index() {
        // The extent comes from a bitmap descriptor Windows filled in; a lie in it
        // must not become an overflowing multiplication.
        let bgra = monochrome_bgra(0, 0, &[]);
        assert!(bgra.is_empty());
    }

    #[test]
    fn an_elevated_window_refuses_input_rather_than_swallowing_it() {
        // The honest-failure requirement, as a table. The agent is medium; anything
        // above it discards what we send and reports nothing.
        assert_eq!(
            uipi_verdict(Integrity::Medium, ForegroundIntegrity::Known(Integrity::High)),
            Some(Refusal::ElevatedWindow)
        );
        assert_eq!(
            uipi_verdict(Integrity::Medium, ForegroundIntegrity::Known(Integrity::System)),
            Some(Refusal::ElevatedWindow)
        );
        assert_eq!(
            uipi_verdict(Integrity::Medium, ForegroundIntegrity::Known(Integrity::Medium)),
            None
        );
        assert_eq!(
            uipi_verdict(Integrity::Medium, ForegroundIntegrity::Known(Integrity::Low)),
            None,
            "a sandboxed browser tab is below us and receives input normally"
        );
    }

    #[test]
    fn being_refused_the_windows_token_is_evidence_and_not_ignorance() {
        // Windows grants `PROCESS_QUERY_LIMITED_INFORMATION` against same-user
        // processes at or below our level. A refusal therefore means the window is
        // above us, and reporting it is more honest than typing into nothing.
        assert_eq!(
            uipi_verdict(Integrity::Medium, ForegroundIntegrity::Denied),
            Some(Refusal::ElevatedWindow)
        );
    }

    #[test]
    fn nothing_is_refused_on_an_absence_of_evidence() {
        // A window that closed between two calls, or a desktop switch in progress.
        // Suspending input here would make the session unusable for a condition
        // that says nothing about integrity.
        assert_eq!(uipi_verdict(Integrity::Medium, ForegroundIntegrity::Unknown), None);
    }

    #[test]
    fn an_unnamed_integrity_level_still_compares() {
        // The mandatory-label identifiers are ordered, which is why the comparison
        // is on the number rather than on the enumeration.
        assert_eq!(
            uipi_verdict(Integrity::Medium, ForegroundIntegrity::Known(Integrity::Other(0x2100))),
            Some(Refusal::ElevatedWindow),
            "medium-plus is above medium"
        );
        assert_eq!(
            uipi_verdict(Integrity::Medium, ForegroundIntegrity::Known(Integrity::Other(0x1500))),
            None
        );
    }

    #[test]
    fn the_pointer_keeps_moving_while_an_elevated_window_has_focus() {
        // Everything delivered *to* the window is refused; movement is not, because
        // the window server moves the cursor itself and a frozen pointer reads as a
        // dead session.
        use crate::input::InjectedEvent;
        use selfhost_desk::keys::Usage;
        let key = Usage::from_code("KeyA").expect("the vocabulary has this key");
        assert!(blocked_by_elevation(&InjectedEvent::Key { usage: key, down: true }));
        assert!(blocked_by_elevation(&InjectedEvent::Text { unit: 65, down: true }));
        assert!(blocked_by_elevation(&InjectedEvent::Scroll { dx: 0, dy: 120 }));
        assert!(blocked_by_elevation(&InjectedEvent::Button {
            button: selfhost_desk::wire::Button::Left,
            down: true
        }));
        assert!(!blocked_by_elevation(&InjectedEvent::PointerMove { monitor: 0, x: 1, y: 1 }));
    }

    #[test]
    fn forcing_opacity_touches_only_the_alpha_channel() {
        let mut bgra = vec![0x11, 0x22, 0x33, 0x00, 0x44, 0x55, 0x66, 0x00];
        force_opaque(&mut bgra);
        assert_eq!(bgra, vec![0x11, 0x22, 0x33, 0xFF, 0x44, 0x55, 0x66, 0xFF]);
    }
}
