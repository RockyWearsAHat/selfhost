//! Which synthetic events one input event becomes. Pure, and tested without a
//! keyboard, a pointer, a screen or a platform.
//!
//! [`crate::input`] answers *which mechanism* a protocol message uses and keeps
//! the held-key bookkeeping honest. This module answers the next question down:
//! given one [`InjectedEvent`], exactly which platform events does an injector
//! post, with which flags, in which order? That question has a surprising number
//! of wrong answers, every one of which fails silently:
//!
//! - A pointer move without `MOUSEEVENTF_VIRTUALDESK` lands on the primary display
//!   no matter which display the operator was looking at.
//! - A macOS button-down posted as `mouseMoved` while a button is held is not a
//!   drag, so a window being dragged simply stops following the pointer — with no
//!   error, on either side.
//! - A modifier held on macOS does not affect later events at all unless its flag
//!   mask is set on each of them, so `Cmd+C` becomes `C`.
//! - A wheel delta in 1/120ths handed to macOS as a line count scrolls a hundred
//!   and twenty lines.
//!
//! None of those can be caught by a type checker and none of them raises an error
//! at run time. They are caught by being *decisions in a pure function with a
//! table of cases beside it* — which is why the FFI in `windows/inject.rs` and
//! `macos/inject.rs` is left holding almost nothing but the call.
//!
//! # Why the platform flag constants live here and not in a `sys` module
//!
//! `windows/sys.rs` holds raw declarations and no logic, deliberately. But
//! `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK | MOUSEEVENTF_MOVE_NOCOALESCE`
//! is not a declaration — it is a decision, it is the decision most likely to be
//! wrong, and a constant that only exists behind `#[cfg(windows)]` is a constant
//! no test on this branch's development machine can assert. So the numbers used to
//! *compose* an event are here, in a file that compiles on every platform, and the
//! numbers used to *call* an API stay in `sys`.
//!
//! # The held set is the release plan
//!
//! [`InputState`] exists because of one requirement the plan calls non-negotiable:
//! the agent applies a full release **autonomously whenever the channel closes**.
//! Not when the client remembers to ask — the client is a browser tab on the far
//! end of a VPN, and the case that matters is precisely the one where it has
//! vanished mid-drag. So the injector owns one of these, updates it from the
//! events it actually posts, and hands its contents back as releases when it is
//! dropped. A modifier left down on a remote machine turns every subsequent
//! keystroke by the person sitting at it into a shortcut; a mouse button left down
//! makes the desktop unusable until a reboot.

use crate::coords::{self, Normalised, Point, PointOrigin};
use crate::input::InjectedEvent;
use crate::keymap;
use selfhost_desk::keys::{HeldKeys, Modifier, Side, Usage};
use selfhost_desk::wire::{Button, Monitor, Refusal};

// ── Windows composition constants ─────────────────────────────────────────────

/// `MOUSEEVENTF_MOVE`.
pub const MOUSEEVENTF_MOVE: u32 = 0x0001;
/// `MOUSEEVENTF_LEFTDOWN`.
pub const MOUSEEVENTF_LEFTDOWN: u32 = 0x0002;
/// `MOUSEEVENTF_LEFTUP`.
pub const MOUSEEVENTF_LEFTUP: u32 = 0x0004;
/// `MOUSEEVENTF_RIGHTDOWN`.
pub const MOUSEEVENTF_RIGHTDOWN: u32 = 0x0008;
/// `MOUSEEVENTF_RIGHTUP`.
pub const MOUSEEVENTF_RIGHTUP: u32 = 0x0010;
/// `MOUSEEVENTF_MIDDLEDOWN`.
pub const MOUSEEVENTF_MIDDLEDOWN: u32 = 0x0020;
/// `MOUSEEVENTF_MIDDLEUP`.
pub const MOUSEEVENTF_MIDDLEUP: u32 = 0x0040;
/// `MOUSEEVENTF_XDOWN`, whose *which* thumb button lives in `mouse_data`.
pub const MOUSEEVENTF_XDOWN: u32 = 0x0080;
/// `MOUSEEVENTF_XUP`.
pub const MOUSEEVENTF_XUP: u32 = 0x0100;
/// `MOUSEEVENTF_WHEEL`.
pub const MOUSEEVENTF_WHEEL: u32 = 0x0800;
/// `MOUSEEVENTF_HWHEEL`.
pub const MOUSEEVENTF_HWHEEL: u32 = 0x1000;
/// `MOUSEEVENTF_MOVE_NOCOALESCE`: deliver every move rather than merging the ones
/// that arrive close together. A remote pointer's path *is* the input — a drag
/// across a menu depends on the intermediate positions — and coalescing turns a
/// gesture into its endpoints.
pub const MOUSEEVENTF_MOVE_NOCOALESCE: u32 = 0x2000;
/// `MOUSEEVENTF_VIRTUALDESK`: interpret the absolute coordinates against the
/// **whole virtual desktop** rather than the primary display. Without it every
/// pointer position lands on the primary monitor, which on a two-display machine
/// is the single most visible bug this subsystem can have.
pub const MOUSEEVENTF_VIRTUALDESK: u32 = 0x4000;
/// `MOUSEEVENTF_ABSOLUTE`. Relative motion is never sent by this protocol at all:
/// Windows multiplies relative deltas by pointer acceleration by up to four times,
/// so a relative event lands somewhere the client cannot predict or correct.
pub const MOUSEEVENTF_ABSOLUTE: u32 = 0x8000;
/// `XBUTTON1`, the thumb button that means "back".
pub const XBUTTON1: i32 = 0x0001;
/// `XBUTTON2`, the thumb button that means "forward".
pub const XBUTTON2: i32 = 0x0002;

/// `KEYEVENTF_EXTENDEDKEY`: the `E0` prefix. See [`crate::keymap`].
pub const KEYEVENTF_EXTENDEDKEY: u32 = 0x0001;
/// `KEYEVENTF_KEYUP`.
pub const KEYEVENTF_KEYUP: u32 = 0x0002;
/// `KEYEVENTF_UNICODE`: `wScan` carries a UTF-16 code unit and `wVk` must be zero.
/// This path bypasses the keyboard layout, which is the only way to type a
/// character the remote layout cannot reach — and it ignores modifier state
/// entirely, which is why [`crate::input::blocks_text`] refuses text while a
/// shortcut modifier is held.
pub const KEYEVENTF_UNICODE: u32 = 0x0004;

// ── macOS composition constants ───────────────────────────────────────────────

/// `kCGEventLeftMouseDown`.
pub const CG_LEFT_MOUSE_DOWN: u32 = 1;
/// `kCGEventLeftMouseUp`.
pub const CG_LEFT_MOUSE_UP: u32 = 2;
/// `kCGEventRightMouseDown`.
pub const CG_RIGHT_MOUSE_DOWN: u32 = 3;
/// `kCGEventRightMouseUp`.
pub const CG_RIGHT_MOUSE_UP: u32 = 4;
/// `kCGEventMouseMoved`.
pub const CG_MOUSE_MOVED: u32 = 5;
/// `kCGEventLeftMouseDragged`.
pub const CG_LEFT_MOUSE_DRAGGED: u32 = 6;
/// `kCGEventRightMouseDragged`.
pub const CG_RIGHT_MOUSE_DRAGGED: u32 = 7;
/// `kCGEventOtherMouseDown`.
pub const CG_OTHER_MOUSE_DOWN: u32 = 25;
/// `kCGEventOtherMouseUp`.
pub const CG_OTHER_MOUSE_UP: u32 = 26;
/// `kCGEventOtherMouseDragged`.
pub const CG_OTHER_MOUSE_DRAGGED: u32 = 27;

/// `kCGMouseButtonLeft`.
pub const CG_BUTTON_LEFT: u32 = 0;
/// `kCGMouseButtonRight`.
pub const CG_BUTTON_RIGHT: u32 = 1;
/// `kCGMouseButtonCenter`.
pub const CG_BUTTON_CENTER: u32 = 2;
/// Button 3, which macOS applications read as "back".
pub const CG_BUTTON_BACK: u32 = 3;
/// Button 4, which macOS applications read as "forward".
pub const CG_BUTTON_FORWARD: u32 = 4;

/// `kCGEventFlagMaskShift`.
pub const CG_FLAG_SHIFT: u64 = 1 << 17;
/// `kCGEventFlagMaskControl`.
pub const CG_FLAG_CONTROL: u64 = 1 << 18;
/// `kCGEventFlagMaskAlternate` — the Option key.
pub const CG_FLAG_ALTERNATE: u64 = 1 << 19;
/// `kCGEventFlagMaskCommand`.
pub const CG_FLAG_COMMAND: u64 = 1 << 20;
/// `NX_DEVICELCTLKEYMASK`: the *left* Control specifically.
pub const CG_FLAG_LEFT_CONTROL: u64 = 0x0000_0001;
/// `NX_DEVICELSHIFTKEYMASK`.
pub const CG_FLAG_LEFT_SHIFT: u64 = 0x0000_0002;
/// `NX_DEVICERSHIFTKEYMASK`.
pub const CG_FLAG_RIGHT_SHIFT: u64 = 0x0000_0004;
/// `NX_DEVICELCMDKEYMASK`.
pub const CG_FLAG_LEFT_COMMAND: u64 = 0x0000_0008;
/// `NX_DEVICERCMDKEYMASK`.
pub const CG_FLAG_RIGHT_COMMAND: u64 = 0x0000_0010;
/// `NX_DEVICELALTKEYMASK`.
pub const CG_FLAG_LEFT_ALTERNATE: u64 = 0x0000_0020;
/// `NX_DEVICERALTKEYMASK`. The right Option is AltGr's counterpart and composes
/// different characters from the left one, so the side is carried rather than
/// collapsed.
pub const CG_FLAG_RIGHT_ALTERNATE: u64 = 0x0000_0040;
/// `NX_DEVICERCTLKEYMASK`.
pub const CG_FLAG_RIGHT_CONTROL: u64 = 0x0000_2000;

/// The wheel movement one notch of a physical wheel reports, in the protocol's own
/// 1/120ths. `WHEEL_DELTA` on Windows, and the divisor macOS line counts come from.
pub const WHEEL_NOTCH: i32 = 120;

// ── The pointer, and the state an injector carries ────────────────────────────

/// Where the pointer was last told to go, in a display's own pixel space.
///
/// Kept because macOS button events carry a location and Windows' do not: a
/// `CGEventCreateMouseEvent` for a button press needs a point, and posting it at
/// the wrong one moves the pointer as a side effect of clicking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pointer {
    /// Which display's pixel space the coordinates are in.
    pub monitor: u8,
    /// x within that display, in pixels.
    pub x: i32,
    /// y within that display, in pixels.
    pub y: i32,
}

/// Everything an injector must remember between batches.
///
/// Deliberately *not* the same object as the [`HeldKeys`] the session driver keeps.
/// The session's copy records what the client *asked for*; this one records what
/// the injector *actually posted*, and the difference is the whole point: a batch
/// refused halfway through, or an event the platform never accepted, must not leave
/// this believing a key is down that is not — or, far worse, believing a key is up
/// that is down.
#[derive(Debug, Default)]
pub struct InputState {
    /// Physical keys currently pressed.
    keys: HeldKeys,
    /// Pointer buttons currently pressed, in the order they went down.
    buttons: Vec<Button>,
    /// The last commanded pointer position.
    pointer: Option<Pointer>,
    /// Undelivered horizontal wheel movement, in 1/120ths.
    wheel_x: i32,
    /// Undelivered vertical wheel movement, in 1/120ths.
    wheel_y: i32,
}

impl InputState {
    /// A state with nothing held.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records what an injector has just posted.
    ///
    /// Called **after** the platform call rather than before it, so that a call
    /// which failed does not leave a key recorded as held — the release plan would
    /// then press-and-release a key nobody touched.
    ///
    /// [`InjectedEvent::Text`] is deliberately not recorded. A unicode packet is
    /// not a physical key: it carries a character rather than a key state, and
    /// there is no "up" that any application is waiting for. Recording it would
    /// mean a release plan that injects stray characters.
    pub fn observe(&mut self, event: &InjectedEvent) {
        match event {
            InjectedEvent::Key { usage, down } => {
                if *down {
                    self.keys.press(*usage);
                } else {
                    self.keys.release(*usage);
                }
            }
            InjectedEvent::Button { button, down } => {
                if *down {
                    if !self.buttons.contains(button) {
                        self.buttons.push(*button);
                    }
                } else {
                    self.buttons.retain(|held| held != button);
                }
            }
            InjectedEvent::PointerMove { monitor, x, y } => {
                self.pointer = Some(Pointer { monitor: *monitor, x: *x, y: *y });
            }
            InjectedEvent::Text { .. } | InjectedEvent::Scroll { .. } => {}
        }
    }

    /// The events that undo everything currently held, draining the state.
    ///
    /// **Buttons are released before keys**, and that order is not cosmetic: a drag
    /// held with a modifier down changes meaning when the modifier goes first (a
    /// Finder move becomes a copy, a text selection becomes a column selection).
    /// Releasing the button first ends the gesture the way the operator's own hand
    /// would.
    ///
    /// Draining means calling it twice is harmless and the second call produces
    /// nothing, which matters because it is called both on an explicit `RELEASE_ALL`
    /// and again when the injector is dropped.
    pub fn release_plan(&mut self) -> Vec<InjectedEvent> {
        let mut events: Vec<InjectedEvent> = self
            .buttons
            .drain(..)
            .map(|button| InjectedEvent::Button { button, down: false })
            .collect();
        events.extend(
            self.keys.drain().into_iter().map(|usage| InjectedEvent::Key { usage, down: false }),
        );
        self.wheel_x = 0;
        self.wheel_y = 0;
        events
    }

    /// Whether anything at all is held.
    pub fn is_idle(&self) -> bool {
        self.keys.is_empty() && self.buttons.is_empty()
    }

    /// The buttons currently down, in press order.
    pub fn buttons(&self) -> &[Button] {
        &self.buttons
    }

    /// Whether a particular key is recorded as held.
    pub fn is_held(&self, usage: Usage) -> bool {
        self.keys.is_held(usage)
    }

    /// The last commanded pointer position, if the pointer has been moved at all.
    pub fn pointer(&self) -> Option<Pointer> {
        self.pointer
    }

    /// The macOS event flags the currently held modifiers imply.
    ///
    /// macOS does **not** derive modifier state from posted key events: a
    /// synthesised Command-down changes nothing about the events that follow it
    /// unless each of them carries the mask. So every synthetic event this module
    /// plans for macOS carries this value, and `Cmd+C` works.
    ///
    /// Both the generic mask and the device-dependent side mask are set, because
    /// applications read both — a text field reads `maskAlternate`, a layout engine
    /// reads `NX_DEVICERALTKEYMASK` to know that AltGr rather than the left Option
    /// composed the character.
    pub fn macos_flags(&self) -> u64 {
        self.macos_flags_without(None)
    }

    /// The flags the held modifiers imply, with one key treated as though it
    /// were already up.
    ///
    /// The seam a modifier's own key-**up** needs. Subtracting that key's mask
    /// from the current flags is the obvious thing and it is wrong on a keyboard
    /// with two of anything: with both Shifts down, lifting the left one would
    /// clear the generic `maskShift` that the still-held right one is entitled
    /// to, and the event would carry `NX_DEVICERSHIFTKEYMASK` set with
    /// `maskShift` clear — a flag word describing no keyboard that exists.
    /// Recomputing over the remaining keys cannot produce that, because the
    /// generic bit is only ever set by a key that is still down.
    fn macos_flags_without(&self, lifted: Option<Usage>) -> u64 {
        let mut flags = 0u64;
        for key in self.keys.held() {
            if Some(key) == lifted {
                continue;
            }
            let Some((role, side)) = key.modifier() else {
                continue;
            };
            flags |= modifier_mask(role, side);
        }
        flags
    }

    /// Converts a wheel movement in 1/120ths into whole notches, keeping the
    /// remainder for next time.
    ///
    /// A trackpad on the client's side reports single-unit movements, and a
    /// converter that truncates each one to zero notches makes a trackpad scroll
    /// nothing at all, forever. The remainder is dropped by [`Self::release_plan`],
    /// because an accumulated fraction from a session that ended is a scroll nobody
    /// asked for.
    fn take_notches(&mut self, delta_x: i32, delta_y: i32) -> (i32, i32) {
        self.wheel_x = self.wheel_x.saturating_add(delta_x);
        self.wheel_y = self.wheel_y.saturating_add(delta_y);
        let notches_x = self.wheel_x / WHEEL_NOTCH;
        let notches_y = self.wheel_y / WHEEL_NOTCH;
        self.wheel_x -= notches_x * WHEEL_NOTCH;
        self.wheel_y -= notches_y * WHEEL_NOTCH;
        (notches_x, notches_y)
    }
}

// ── Windows ───────────────────────────────────────────────────────────────────

/// One `INPUT` structure, described rather than built.
///
/// The injector turns each of these into the tagged union `SendInput` takes. Kept
/// as a plain enum so the composition above can be asserted on a machine with no
/// `user32.dll` in sight.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsInput {
    /// A `MOUSEINPUT`.
    Mouse {
        /// `dx`: the normalised x when [`MOUSEEVENTF_ABSOLUTE`] is set, otherwise
        /// zero.
        dx: i32,
        /// `dy`.
        dy: i32,
        /// `mouseData`: the wheel delta, or the thumb-button selector.
        mouse_data: i32,
        /// `dwFlags`.
        flags: u32,
    },
    /// A `KEYBDINPUT`.
    Key {
        /// `wVk`, or zero on the unicode path.
        virtual_key: u16,
        /// `wScan`: the set-1 scancode, or the UTF-16 code unit on the unicode
        /// path.
        scancode: u16,
        /// `dwFlags`.
        flags: u32,
    },
}

/// Plans the Windows events one input event becomes.
///
/// # Errors
///
/// [`Refusal::Unmappable`] for a key this build has no Win32 mapping for, and for
/// a pointer position outside the display it claims to be on — refused rather than
/// clamped, because a channel whose whole purpose is doing what it is told must not
/// quietly move the pointer somewhere else.
pub fn windows_inputs(
    event: &InjectedEvent,
    monitors: &[Monitor],
    state: &mut InputState,
) -> Result<Vec<WindowsInput>, Refusal> {
    match event {
        InjectedEvent::Key { usage, down } => {
            let key = keymap::windows_key(*usage).ok_or(Refusal::Unmappable)?;
            let mut flags = 0u32;
            if key.extended {
                flags |= KEYEVENTF_EXTENDEDKEY;
            }
            if !down {
                flags |= KEYEVENTF_KEYUP;
            }
            Ok(vec![WindowsInput::Key {
                virtual_key: key.virtual_key,
                scancode: key.scancode,
                flags,
            }])
        }
        InjectedEvent::Text { unit, down } => Ok(vec![WindowsInput::Key {
            // `wVk` must be zero on the unicode path; a non-zero one is taken as a
            // virtual key and the code unit is ignored.
            virtual_key: 0,
            scancode: *unit,
            flags: KEYEVENTF_UNICODE | if *down { 0 } else { KEYEVENTF_KEYUP },
        }]),
        InjectedEvent::PointerMove { monitor, x, y } => {
            let NormalisedMove { x: dx, y: dy } = normalised_move(monitors, *monitor, *x, *y)?;
            Ok(vec![WindowsInput::Mouse {
                dx: i32::from(dx),
                dy: i32::from(dy),
                mouse_data: 0,
                flags: MOUSEEVENTF_MOVE
                    | MOUSEEVENTF_ABSOLUTE
                    | MOUSEEVENTF_VIRTUALDESK
                    | MOUSEEVENTF_MOVE_NOCOALESCE,
            }])
        }
        InjectedEvent::Button { button, down } => {
            let (flags, mouse_data) = match (button, down) {
                (Button::Left, true) => (MOUSEEVENTF_LEFTDOWN, 0),
                (Button::Left, false) => (MOUSEEVENTF_LEFTUP, 0),
                (Button::Right, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
                (Button::Right, false) => (MOUSEEVENTF_RIGHTUP, 0),
                (Button::Middle, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
                (Button::Middle, false) => (MOUSEEVENTF_MIDDLEUP, 0),
                (Button::Back, true) => (MOUSEEVENTF_XDOWN, XBUTTON1),
                (Button::Back, false) => (MOUSEEVENTF_XUP, XBUTTON1),
                (Button::Forward, true) => (MOUSEEVENTF_XDOWN, XBUTTON2),
                (Button::Forward, false) => (MOUSEEVENTF_XUP, XBUTTON2),
            };
            Ok(vec![WindowsInput::Mouse { dx: 0, dy: 0, mouse_data, flags }])
        }
        InjectedEvent::Scroll { dx, dy } => {
            // Windows takes the delta in 1/120ths directly and has done since it
            // grew a high-resolution wheel, so no accumulation happens here: the
            // remainder is the operating system's to keep, and keeping our own as
            // well would round twice.
            let _ = state;
            let mut inputs = Vec::new();
            if *dy != 0 {
                inputs.push(WindowsInput::Mouse {
                    dx: 0,
                    dy: 0,
                    mouse_data: *dy,
                    flags: MOUSEEVENTF_WHEEL,
                });
            }
            if *dx != 0 {
                inputs.push(WindowsInput::Mouse {
                    dx: 0,
                    dy: 0,
                    mouse_data: *dx,
                    flags: MOUSEEVENTF_HWHEEL,
                });
            }
            Ok(inputs)
        }
    }
}

/// The normalised destination of a pointer move, as two 16-bit fractions.
///
/// A private shape rather than [`Normalised`] used directly, so the destructuring
/// at the call site names both axes and cannot swap them silently.
struct NormalisedMove {
    x: u16,
    y: u16,
}

/// Maps a display-local pixel to the virtual desktop's 16-bit fraction.
fn normalised_move(
    monitors: &[Monitor],
    monitor: u8,
    x: i32,
    y: i32,
) -> Result<NormalisedMove, Refusal> {
    let normalised: Normalised =
        coords::absolute(monitors, monitor, x, y).map_err(|_| Refusal::Unmappable)?;
    Ok(NormalisedMove { x: normalised.x, y: normalised.y })
}

// ── macOS ─────────────────────────────────────────────────────────────────────

/// A display as the macOS injector needs it.
///
/// Both coordinate spaces, because the protocol addresses pixels and
/// `CGEventCreateMouseEvent` takes points, and the conversion between them is
/// per-display on any Mac with an external monitor attached. The point origin comes
/// from `CGDisplayBounds` rather than being reconstructed — see
/// [`crate::coords::PointOrigin`] for why reconstruction is only sometimes right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplaySpace {
    /// The protocol's id for this display.
    pub monitor: u8,
    /// Its top-left corner in the global point space.
    pub origin: PointOrigin,
    /// Its scale in thousandths: 2000 for a Retina panel.
    pub scale_permille: u16,
    /// Width in physical pixels.
    pub pixel_width: u32,
    /// Height in physical pixels.
    pub pixel_height: u32,
}

/// One `CGEvent`, described rather than built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacEvent {
    /// A mouse event: a move, a drag, or a button transition.
    Mouse {
        /// The `CGEventType`.
        event_type: u32,
        /// The `CGMouseButton`, which macOS wants even for a move.
        button: u32,
        /// Where, in the global point space. `None` means "wherever the pointer
        /// already is" — the case where a button arrives before any move, and the
        /// injector reads the live location rather than inventing one.
        point: Option<Point>,
        /// The modifier flags every event must carry.
        flags: u64,
    },
    /// A scroll, in whole lines.
    Scroll {
        /// Vertical lines; positive is away from the operator.
        lines_y: i32,
        /// Horizontal lines, already in `CGEvent`'s own sense.
        lines_x: i32,
        /// The modifier flags.
        flags: u64,
    },
    /// A physical key.
    Key {
        /// The `CGKeyCode`.
        key_code: u16,
        /// True for a press.
        down: bool,
        /// The modifier flags.
        flags: u64,
    },
    /// One UTF-16 code unit through `CGEventKeyboardSetUnicodeString`.
    Unicode {
        /// The code unit.
        unit: u16,
        /// True for a press. Each unit is pressed and released in turn.
        down: bool,
    },
}

/// Plans the macOS events one input event becomes.
///
/// # Errors
///
/// [`Refusal::Unmappable`] for a key with no `CGKeyCode` and for a pointer position
/// outside the display it claims to be on.
pub fn macos_events(
    event: &InjectedEvent,
    displays: &[DisplaySpace],
    state: &mut InputState,
) -> Result<Vec<MacEvent>, Refusal> {
    let flags = state.macos_flags();
    match event {
        InjectedEvent::Key { usage, down } => {
            let key_code = keymap::macos_key(*usage).ok_or(Refusal::Unmappable)?;
            // The flags are computed from the state *including* this key when it is
            // a modifier going down, and excluding it when it is coming up — which
            // is what a real keyboard reports, and what an application checking
            // "was Shift down when this arrived" expects.
            let flags = with_modifier(state, *usage, *down, flags);
            Ok(vec![MacEvent::Key { key_code, down: *down, flags }])
        }
        InjectedEvent::Text { unit, down } => {
            Ok(vec![MacEvent::Unicode { unit: *unit, down: *down }])
        }
        InjectedEvent::PointerMove { monitor, x, y } => {
            let point = global_point(displays, *monitor, *x, *y)?;
            let (event_type, button) = drag_or_move(state.buttons());
            Ok(vec![MacEvent::Mouse { event_type, button, point: Some(point), flags }])
        }
        InjectedEvent::Button { button, down } => {
            let point = match state.pointer() {
                Some(pointer) => Some(global_point(displays, pointer.monitor, pointer.x, pointer.y)?),
                None => None,
            };
            let (event_type, cg_button) = button_event(*button, *down);
            Ok(vec![MacEvent::Mouse { event_type, button: cg_button, point, flags }])
        }
        InjectedEvent::Scroll { dx, dy } => {
            let (notches_x, notches_y) = state.take_notches(*dx, *dy);
            if notches_x == 0 && notches_y == 0 {
                return Ok(Vec::new());
            }
            Ok(vec![MacEvent::Scroll {
                lines_y: notches_y,
                // The wire says positive x is movement to the right; `CGEvent`'s
                // horizontal wheel axis is positive to the *left*, so the sign is
                // inverted exactly here. This is the one axis in the subsystem whose
                // sense could not be established from documentation alone, and it is
                // negated in one tested line so that flipping it is a one-character
                // change rather than an expedition.
                lines_x: -notches_x,
                flags,
            }])
        }
    }
}

/// The flags an event carries when the event is itself a modifier transition.
///
/// A modifier's own key-down must carry its own mask (that is what makes the
/// following events' masks consistent with what applications saw), and its key-up
/// must not.
fn with_modifier(state: &InputState, usage: Usage, down: bool, base: u64) -> u64 {
    let Some((role, side)) = usage.modifier() else {
        return base;
    };
    if down {
        return base | modifier_mask(role, side);
    }
    if state.is_held(usage) {
        // Recorded as held and coming up: recompute over what is left rather
        // than subtracting this key's mask, so the generic half survives a
        // second key of the same role that is still down. See
        // [`InputState::macos_flags_without`].
        return state.macos_flags_without(Some(usage));
    }
    base
}

/// The two masks one modifier key sets: the generic one every application
/// reads, and the device-dependent one that says which side it was.
///
/// Both, always. A text field reads `maskAlternate` and a layout engine reads
/// `NX_DEVICERALTKEYMASK` to know that AltGr rather than the left Option
/// composed the character, so a flag word carrying only one of the pair is a
/// keyboard half the applications on the far machine cannot see.
const fn modifier_mask(role: Modifier, side: Side) -> u64 {
    match (role, side) {
        (Modifier::Shift, Side::Left) => CG_FLAG_SHIFT | CG_FLAG_LEFT_SHIFT,
        (Modifier::Shift, Side::Right) => CG_FLAG_SHIFT | CG_FLAG_RIGHT_SHIFT,
        (Modifier::Control, Side::Left) => CG_FLAG_CONTROL | CG_FLAG_LEFT_CONTROL,
        (Modifier::Control, Side::Right) => CG_FLAG_CONTROL | CG_FLAG_RIGHT_CONTROL,
        (Modifier::Alt, Side::Left) => CG_FLAG_ALTERNATE | CG_FLAG_LEFT_ALTERNATE,
        (Modifier::Alt, Side::Right) => CG_FLAG_ALTERNATE | CG_FLAG_RIGHT_ALTERNATE,
        (Modifier::Meta, Side::Left) => CG_FLAG_COMMAND | CG_FLAG_LEFT_COMMAND,
        (Modifier::Meta, Side::Right) => CG_FLAG_COMMAND | CG_FLAG_RIGHT_COMMAND,
    }
}

/// Whether a pointer move is a move or a drag, and which button owns the drag.
///
/// This is the decision that makes dragging work at all on macOS. A window being
/// dragged follows `leftMouseDragged` and ignores `mouseMoved` entirely, so getting
/// it wrong produces a drag that starts, does nothing, and ends — with no error on
/// either side of the link.
///
/// The **first** button pressed owns the drag, because that is the one whose
/// down-event opened the gesture the application is tracking.
pub fn drag_or_move(buttons: &[Button]) -> (u32, u32) {
    match buttons.first() {
        Some(Button::Left) => (CG_LEFT_MOUSE_DRAGGED, CG_BUTTON_LEFT),
        Some(Button::Right) => (CG_RIGHT_MOUSE_DRAGGED, CG_BUTTON_RIGHT),
        Some(Button::Middle) => (CG_OTHER_MOUSE_DRAGGED, CG_BUTTON_CENTER),
        Some(Button::Back) => (CG_OTHER_MOUSE_DRAGGED, CG_BUTTON_BACK),
        Some(Button::Forward) => (CG_OTHER_MOUSE_DRAGGED, CG_BUTTON_FORWARD),
        None => (CG_MOUSE_MOVED, CG_BUTTON_LEFT),
    }
}

/// The event type and button number one button transition becomes.
pub fn button_event(button: Button, down: bool) -> (u32, u32) {
    match (button, down) {
        (Button::Left, true) => (CG_LEFT_MOUSE_DOWN, CG_BUTTON_LEFT),
        (Button::Left, false) => (CG_LEFT_MOUSE_UP, CG_BUTTON_LEFT),
        (Button::Right, true) => (CG_RIGHT_MOUSE_DOWN, CG_BUTTON_RIGHT),
        (Button::Right, false) => (CG_RIGHT_MOUSE_UP, CG_BUTTON_RIGHT),
        (Button::Middle, true) => (CG_OTHER_MOUSE_DOWN, CG_BUTTON_CENTER),
        (Button::Middle, false) => (CG_OTHER_MOUSE_UP, CG_BUTTON_CENTER),
        (Button::Back, true) => (CG_OTHER_MOUSE_DOWN, CG_BUTTON_BACK),
        (Button::Back, false) => (CG_OTHER_MOUSE_UP, CG_BUTTON_BACK),
        (Button::Forward, true) => (CG_OTHER_MOUSE_DOWN, CG_BUTTON_FORWARD),
        (Button::Forward, false) => (CG_OTHER_MOUSE_UP, CG_BUTTON_FORWARD),
    }
}

/// A display-local pixel as a point in macOS' global space.
///
/// # Errors
///
/// [`Refusal::Unmappable`] for an unknown display, a position outside it, or a
/// geometry the conversion cannot represent.
pub fn global_point(
    displays: &[DisplaySpace],
    monitor: u8,
    x: i32,
    y: i32,
) -> Result<Point, Refusal> {
    let display =
        displays.iter().find(|candidate| candidate.monitor == monitor).ok_or(Refusal::Unmappable)?;
    if x < 0
        || y < 0
        || u32::try_from(x).is_ok_and(|value| value >= display.pixel_width)
        || u32::try_from(y).is_ok_and(|value| value >= display.pixel_height)
    {
        return Err(Refusal::Unmappable);
    }
    coords::global_point(display.origin, display.scale_permille, x, y)
        .map_err(|_| Refusal::Unmappable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_desk::wire::Monitor;

    fn key(code: &str) -> Usage {
        Usage::from_code(code).expect("the vocabulary has this key")
    }

    fn two_displays() -> Vec<Monitor> {
        vec![
            Monitor {
                id: 0,
                origin_x: 0,
                origin_y: 0,
                width: 1920,
                height: 1080,
                scale_permille: 1000,
                primary: true,
            },
            Monitor {
                id: 1,
                origin_x: -1920,
                origin_y: 0,
                width: 1920,
                height: 1080,
                scale_permille: 1000,
                primary: false,
            },
        ]
    }

    fn retina() -> Vec<DisplaySpace> {
        vec![DisplaySpace {
            monitor: 0,
            origin: PointOrigin { x: 0, y: 0 },
            scale_permille: 2000,
            pixel_width: 3024,
            pixel_height: 1964,
        }]
    }

    #[test]
    fn a_pointer_move_is_absolute_across_the_whole_virtual_desktop() {
        // Without VIRTUALDESK every position lands on the primary display, which on
        // the two-display machine this ships to is the most visible bug available.
        let mut state = InputState::new();
        let inputs = windows_inputs(
            &InjectedEvent::PointerMove { monitor: 1, x: 0, y: 0 },
            &two_displays(),
            &mut state,
        )
        .unwrap();
        let WindowsInput::Mouse { dx, dy, flags, .. } = inputs[0] else {
            panic!("a move must be a mouse input");
        };
        assert_eq!((dx, dy), (0, 0), "display 1 starts at the desktop's own left edge");
        assert!(flags & MOUSEEVENTF_ABSOLUTE != 0);
        assert!(flags & MOUSEEVENTF_VIRTUALDESK != 0);
        assert!(flags & MOUSEEVENTF_MOVE_NOCOALESCE != 0);
        assert!(flags & MOUSEEVENTF_MOVE != 0);
    }

    #[test]
    fn the_far_corner_of_the_desktop_normalises_to_the_last_addressable_fraction() {
        let mut state = InputState::new();
        let inputs = windows_inputs(
            &InjectedEvent::PointerMove { monitor: 0, x: 1919, y: 1079 },
            &two_displays(),
            &mut state,
        )
        .unwrap();
        assert_eq!(
            inputs[0],
            WindowsInput::Mouse {
                dx: 65_535,
                dy: 65_535,
                mouse_data: 0,
                flags: MOUSEEVENTF_MOVE
                    | MOUSEEVENTF_ABSOLUTE
                    | MOUSEEVENTF_VIRTUALDESK
                    | MOUSEEVENTF_MOVE_NOCOALESCE,
            }
        );
    }

    #[test]
    fn a_position_outside_its_display_is_refused_on_both_platforms() {
        let mut state = InputState::new();
        assert_eq!(
            windows_inputs(
                &InjectedEvent::PointerMove { monitor: 0, x: 1920, y: 0 },
                &two_displays(),
                &mut state,
            ),
            Err(Refusal::Unmappable)
        );
        assert_eq!(
            macos_events(
                &InjectedEvent::PointerMove { monitor: 0, x: 3024, y: 0 },
                &retina(),
                &mut state,
            ),
            Err(Refusal::Unmappable)
        );
    }

    #[test]
    fn a_key_carries_its_scancode_and_the_extended_flag_only_where_it_belongs() {
        let mut state = InputState::new();
        let inputs =
            windows_inputs(&InjectedEvent::Key { usage: key("ArrowLeft"), down: true }, &[], &mut state)
                .unwrap();
        assert_eq!(
            inputs[0],
            WindowsInput::Key { virtual_key: 0x25, scancode: 0x4B, flags: KEYEVENTF_EXTENDEDKEY }
        );
        let inputs =
            windows_inputs(&InjectedEvent::Key { usage: key("KeyA"), down: false }, &[], &mut state)
                .unwrap();
        assert_eq!(
            inputs[0],
            WindowsInput::Key { virtual_key: 0x41, scancode: 0x1E, flags: KEYEVENTF_KEYUP }
        );
    }

    #[test]
    fn text_takes_the_unicode_path_with_a_zero_virtual_key() {
        // A non-zero `wVk` is taken as a virtual key and the code unit is ignored,
        // which types nothing and reports success.
        let mut state = InputState::new();
        let inputs =
            windows_inputs(&InjectedEvent::Text { unit: 0x00E9, down: true }, &[], &mut state)
                .unwrap();
        assert_eq!(
            inputs[0],
            WindowsInput::Key { virtual_key: 0, scancode: 0x00E9, flags: KEYEVENTF_UNICODE }
        );
    }

    #[test]
    fn the_thumb_buttons_travel_in_mouse_data_rather_than_in_the_flags() {
        let mut state = InputState::new();
        let back =
            windows_inputs(&InjectedEvent::Button { button: Button::Back, down: true }, &[], &mut state)
                .unwrap();
        assert_eq!(
            back[0],
            WindowsInput::Mouse { dx: 0, dy: 0, mouse_data: XBUTTON1, flags: MOUSEEVENTF_XDOWN }
        );
        let forward = windows_inputs(
            &InjectedEvent::Button { button: Button::Forward, down: false },
            &[],
            &mut state,
        )
        .unwrap();
        assert_eq!(
            forward[0],
            WindowsInput::Mouse { dx: 0, dy: 0, mouse_data: XBUTTON2, flags: MOUSEEVENTF_XUP }
        );
    }

    #[test]
    fn a_windows_wheel_delta_passes_through_in_the_hundred_and_twentieths_it_arrived_in() {
        // Windows has taken high-resolution wheel deltas for years; accumulating
        // here as well would round the movement twice.
        let mut state = InputState::new();
        let inputs =
            windows_inputs(&InjectedEvent::Scroll { dx: 0, dy: 40 }, &[], &mut state).unwrap();
        assert_eq!(
            inputs[0],
            WindowsInput::Mouse { dx: 0, dy: 0, mouse_data: 40, flags: MOUSEEVENTF_WHEEL }
        );
        let both = windows_inputs(&InjectedEvent::Scroll { dx: -120, dy: 120 }, &[], &mut state)
            .unwrap();
        assert_eq!(both.len(), 2, "the two axes are two events");
    }

    #[test]
    fn a_macos_move_becomes_a_drag_while_a_button_is_held() {
        // The decision that makes dragging work at all: a window follows
        // `leftMouseDragged` and ignores `mouseMoved`.
        let mut state = InputState::new();
        let displays = retina();
        let moved =
            macos_events(&InjectedEvent::PointerMove { monitor: 0, x: 10, y: 20 }, &displays, &mut state)
                .unwrap();
        assert!(matches!(moved[0], MacEvent::Mouse { event_type: CG_MOUSE_MOVED, .. }));
        state.observe(&InjectedEvent::PointerMove { monitor: 0, x: 10, y: 20 });
        state.observe(&InjectedEvent::Button { button: Button::Left, down: true });
        let dragged =
            macos_events(&InjectedEvent::PointerMove { monitor: 0, x: 12, y: 22 }, &displays, &mut state)
                .unwrap();
        assert!(matches!(dragged[0], MacEvent::Mouse { event_type: CG_LEFT_MOUSE_DRAGGED, .. }));
    }

    #[test]
    fn the_first_button_pressed_owns_the_drag() {
        assert_eq!(drag_or_move(&[]), (CG_MOUSE_MOVED, CG_BUTTON_LEFT));
        assert_eq!(
            drag_or_move(&[Button::Right, Button::Left]),
            (CG_RIGHT_MOUSE_DRAGGED, CG_BUTTON_RIGHT)
        );
    }

    #[test]
    fn a_macos_pointer_position_is_converted_to_points_at_the_displays_own_scale() {
        // A Retina display reports 3024 pixels and 1512 points; injecting the pixel
        // number would land the pointer at twice the intended distance.
        let mut state = InputState::new();
        let events =
            macos_events(&InjectedEvent::PointerMove { monitor: 0, x: 3022, y: 1962 }, &retina(), &mut state)
                .unwrap();
        let MacEvent::Mouse { point: Some(point), .. } = events[0] else {
            panic!("a move carries a point");
        };
        assert_eq!(point, Point { x: 1511, y: 981 });
    }

    #[test]
    fn a_macos_button_before_any_move_is_posted_wherever_the_pointer_already_is() {
        // Inventing a point here would move the pointer as a side effect of
        // clicking, which is worse than clicking where it is.
        let mut state = InputState::new();
        let events =
            macos_events(&InjectedEvent::Button { button: Button::Left, down: true }, &retina(), &mut state)
                .unwrap();
        assert!(matches!(
            events[0],
            MacEvent::Mouse { event_type: CG_LEFT_MOUSE_DOWN, point: None, .. }
        ));
    }

    #[test]
    fn a_held_modifier_is_carried_on_every_later_macos_event() {
        // macOS does not derive modifier state from posted key events. Without this
        // `Cmd+C` is `C`.
        let mut state = InputState::new();
        state.observe(&InjectedEvent::Key { usage: key("MetaLeft"), down: true });
        let events =
            macos_events(&InjectedEvent::Key { usage: key("KeyC"), down: true }, &retina(), &mut state)
                .unwrap();
        let MacEvent::Key { flags, .. } = events[0] else {
            panic!("a key event");
        };
        assert!(flags & CG_FLAG_COMMAND != 0, "the generic Command mask");
        assert!(flags & CG_FLAG_LEFT_COMMAND != 0, "the left-hand device mask");
    }

    #[test]
    fn lifting_one_shift_leaves_the_other_ones_masks_intact() {
        // Both Shifts down and the left one comes up. Subtracting the lifted
        // key's mask would clear the generic `maskShift` while the right-hand
        // device bit stayed set — a flag word describing no keyboard that
        // exists, on the one event an application uses to decide what the
        // operator was holding.
        let mut state = InputState::new();
        state.observe(&InjectedEvent::Key { usage: key("ShiftLeft"), down: true });
        state.observe(&InjectedEvent::Key { usage: key("ShiftRight"), down: true });
        let events = macos_events(
            &InjectedEvent::Key { usage: key("ShiftLeft"), down: false },
            &retina(),
            &mut state,
        )
        .unwrap();
        let MacEvent::Key { flags, .. } = events[0] else { panic!("a key event") };
        assert!(flags & CG_FLAG_SHIFT != 0, "the right Shift is still down");
        assert!(flags & CG_FLAG_RIGHT_SHIFT != 0);
        assert_eq!(flags & CG_FLAG_LEFT_SHIFT, 0, "the lifted side's own bit goes");

        // And once it is the last one, everything goes.
        state.observe(&InjectedEvent::Key { usage: key("ShiftLeft"), down: false });
        let events = macos_events(
            &InjectedEvent::Key { usage: key("ShiftRight"), down: false },
            &retina(),
            &mut state,
        )
        .unwrap();
        let MacEvent::Key { flags, .. } = events[0] else { panic!("a key event") };
        assert_eq!(flags, 0, "nothing is held any more");
    }

    #[test]
    fn the_right_option_is_distinguishable_from_the_left_one() {
        // AltGr composes different characters. Collapsing the sides silently
        // changes what the operator typed on a European layout.
        let mut left = InputState::new();
        left.observe(&InjectedEvent::Key { usage: key("AltLeft"), down: true });
        let mut right = InputState::new();
        right.observe(&InjectedEvent::Key { usage: key("AltRight"), down: true });
        assert_ne!(left.macos_flags(), right.macos_flags());
        assert!(left.macos_flags() & CG_FLAG_LEFT_ALTERNATE != 0);
        assert!(right.macos_flags() & CG_FLAG_RIGHT_ALTERNATE != 0);
    }

    #[test]
    fn a_modifiers_own_press_carries_its_mask_and_its_release_does_not() {
        let mut state = InputState::new();
        let press =
            macos_events(&InjectedEvent::Key { usage: key("ShiftLeft"), down: true }, &retina(), &mut state)
                .unwrap();
        let MacEvent::Key { flags, .. } = press[0] else { panic!("a key event") };
        assert!(flags & CG_FLAG_SHIFT != 0);

        state.observe(&InjectedEvent::Key { usage: key("ShiftLeft"), down: true });
        let release =
            macos_events(&InjectedEvent::Key { usage: key("ShiftLeft"), down: false }, &retina(), &mut state)
                .unwrap();
        let MacEvent::Key { flags, .. } = release[0] else { panic!("a key event") };
        assert_eq!(flags & CG_FLAG_SHIFT, 0, "the mask goes away with the key");
    }

    #[test]
    fn a_trackpad_sized_scroll_accumulates_rather_than_truncating_to_nothing() {
        // Truncating each 1/120th to zero lines makes a trackpad scroll nothing at
        // all, forever, with no error anywhere.
        let mut state = InputState::new();
        let displays = retina();
        for _ in 0..119 {
            let events =
                macos_events(&InjectedEvent::Scroll { dx: 0, dy: 1 }, &displays, &mut state).unwrap();
            assert!(events.is_empty(), "no whole notch yet");
        }
        let events =
            macos_events(&InjectedEvent::Scroll { dx: 0, dy: 1 }, &displays, &mut state).unwrap();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], MacEvent::Scroll { lines_y: 1, .. }));
    }

    #[test]
    fn the_macos_horizontal_wheel_is_inverted_in_exactly_one_place() {
        let mut state = InputState::new();
        let events =
            macos_events(&InjectedEvent::Scroll { dx: 120, dy: 0 }, &retina(), &mut state).unwrap();
        assert!(matches!(events[0], MacEvent::Scroll { lines_x: -1, lines_y: 0, .. }));
    }

    #[test]
    fn a_release_plan_lets_go_of_the_button_before_the_modifier() {
        // A drag held with a modifier changes meaning if the modifier goes first: a
        // Finder move becomes a copy.
        let mut state = InputState::new();
        state.observe(&InjectedEvent::Key { usage: key("AltLeft"), down: true });
        state.observe(&InjectedEvent::Button { button: Button::Left, down: true });
        let plan = state.release_plan();
        assert_eq!(plan.len(), 2);
        assert_eq!(plan[0], InjectedEvent::Button { button: Button::Left, down: false });
        assert_eq!(plan[1], InjectedEvent::Key { usage: key("AltLeft"), down: false });
        assert!(state.is_idle());
        assert!(state.release_plan().is_empty(), "a second plan produces nothing");
    }

    #[test]
    fn a_dropped_link_mid_drag_leaves_nothing_held() {
        // The operational test the plan names: start a drag, pull the network,
        // reconnect. Every button and every modifier must come back up, and the
        // agent must do it without being asked.
        let mut state = InputState::new();
        for event in [
            InjectedEvent::Key { usage: key("ControlLeft"), down: true },
            InjectedEvent::Key { usage: key("ShiftLeft"), down: true },
            InjectedEvent::PointerMove { monitor: 0, x: 100, y: 100 },
            InjectedEvent::Button { button: Button::Left, down: true },
            InjectedEvent::PointerMove { monitor: 0, x: 400, y: 300 },
        ] {
            state.observe(&event);
        }
        assert!(!state.is_idle());
        let plan = state.release_plan();
        assert!(plan.iter().all(|event| matches!(
            event,
            InjectedEvent::Key { down: false, .. } | InjectedEvent::Button { down: false, .. }
        )));
        assert_eq!(plan.len(), 3, "two modifiers and one button");
        assert!(state.is_idle());
    }

    #[test]
    fn text_is_never_recorded_as_held() {
        // A unicode packet is a character, not a key state. Recording it would make
        // the release plan inject stray characters into whatever has focus.
        let mut state = InputState::new();
        state.observe(&InjectedEvent::Text { unit: u16::from(b'a'), down: true });
        assert!(state.is_idle());
        assert!(state.release_plan().is_empty());
    }

    #[test]
    fn every_key_in_the_vocabulary_plans_on_both_platforms() {
        // The end-to-end version of the coverage test in `keymap`: a key that has a
        // table entry but cannot be planned is still a key that does nothing.
        let displays = retina();
        for usage in Usage::all() {
            let mut state = InputState::new();
            let event = InjectedEvent::Key { usage, down: true };
            assert!(windows_inputs(&event, &[], &mut state).is_ok(), "{}", usage.code());
            assert!(macos_events(&event, &displays, &mut state).is_ok(), "{}", usage.code());
        }
    }
}

