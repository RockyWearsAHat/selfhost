//! macOS input injection: `CGEvent`, and the two refusals it is honest about.
//!
//! Every decision this file could get wrong has already been made in
//! [`crate::synth`], where it is a pure function with a table of cases beside it —
//! which event type a move becomes while a button is held, which modifier mask
//! every event has to carry, how a wheel delta in 1/120ths becomes whole lines,
//! and which `CGKeyCode` a HID usage is. What is left here is the calls, the
//! ownership of the Core Foundation objects they produce, and the two things only
//! this layer can know.
//!
//! # `Ok(())` means *posted*, and never *delivered*
//!
//! `CGEventPost` returns `void`. There is no status, no error, and no way to ask
//! afterwards whether anything received the event. So `Ok(())` from
//! [`Injector::inject`] means the events were handed to the window server, which
//! is the strongest claim this platform permits, and the doc comment on the trait
//! says so in those words. An implementation that inferred delivery from a
//! successful call would be inventing information.
//!
//! # Secure input is detected and reported rather than fought
//!
//! When a password field has focus, macOS turns on **secure event input**
//! (`EnableSecureEventInput`), and synthetic keyboard events are silently dropped
//! for as long as it is on. That is the operating system protecting the person at
//! the machine from exactly this feature, and it is working correctly.
//!
//! This module therefore *asks* — `IsSecureEventInputEnabled` — and refuses
//! keyboard and text events with [`Refusal::SecureDesktop`] while it is on, so the
//! console can say "the machine is asking for a password; typing is suspended"
//! instead of appearing to type into a void. Pointer events are still injected,
//! because secure input does not affect them and a pointer that freezes at a
//! password prompt looks like a dead session.
//!
//! There is no bypass here and there will not be one. A remote channel that could
//! type into a password field the operating system has deliberately protected would
//! be a credential-capture channel wearing a remote-desktop's clothes.
//!
//! # The other refusal: Accessibility
//!
//! Synthetic events need the Accessibility grant, and a process without it posts
//! events that go nowhere — again silently. The grant is checked before each batch
//! rather than once at construction, because macOS revokes it live from System
//! Settings and a session that started permitted must notice when it stops being
//! so. See [`crate::macos::grant`] for the remediation the console renders.
//!
//! # Everything held is released when this object goes away
//!
//! [`MacInjector`] owns a [`synth::InputState`] recording what it has actually
//! posted, and its [`Drop`] applies the release plan. That is the autonomous
//! `RELEASE_ALL` the plan calls non-negotiable: the case it exists for is a VPN
//! that drops mid-drag, where the client that would have sent `RELEASE_ALL` is the
//! thing that vanished. A modifier left down on a remote machine turns every
//! keystroke by the person sitting at it into a shortcut.

use crate::input::InjectedEvent;
use crate::macos::{grant, sys};
use crate::synth::{self, DisplaySpace, InputState, MacEvent};
use crate::{CaptureError, Fault, InjectError, Injector};
use selfhost_desk::wire::Refusal;
use std::ffi::c_void;

/// `kCGEventSourceStateHIDSystemState`.
///
/// The source state that combines with the real hardware: a synthetic Shift-down
/// posted from this source is seen by the system alongside the keyboard on the
/// desk, which is what makes a remote modifier behave like a local one. The
/// private state would keep our events in their own world, where a real
/// application would never see the modifier at all.
const SOURCE_HID_SYSTEM_STATE: i32 = 1;

/// `kCGHIDEventTap`: post at the lowest tap, where the events look like hardware.
///
/// The session tap would deliver only to this login session's applications and skip
/// anything reading closer to the driver — including the window server's own
/// handling of some system gestures.
const HID_EVENT_TAP: u32 = 0;

/// `kCGScrollEventUnitLine`.
///
/// Lines rather than pixels because the protocol's wheel movement is in notches,
/// and a notch is a line. Pixel units would need a pixels-per-notch figure that
/// only the client's own scrolling behaviour could supply.
const SCROLL_UNIT_LINE: u32 = 1;

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    /// Creates the event source every synthetic event is stamped with.
    fn CGEventSourceCreate(state_id: i32) -> *mut c_void;

    /// A mouse event at a point in the global point space.
    fn CGEventCreateMouseEvent(
        source: *mut c_void,
        event_type: u32,
        position: sys::CGPoint,
        button: u32,
    ) -> *mut c_void;

    /// A keyboard event for a `CGKeyCode`. `key_down` is a C `bool`, one byte.
    fn CGEventCreateKeyboardEvent(
        source: *mut c_void,
        key_code: u16,
        key_down: u8,
    ) -> *mut c_void;

    /// A scroll event. The non-variadic form, so the three wheel axes are ordinary
    /// arguments rather than a C variadic list whose ABI differs by architecture.
    fn CGEventCreateScrollWheelEvent2(
        source: *mut c_void,
        units: u32,
        wheel_count: u32,
        wheel1: i32,
        wheel2: i32,
        wheel3: i32,
    ) -> *mut c_void;

    /// Replaces an event's modifier flags. macOS does **not** derive these from
    /// posted key events, so every event this module posts carries them explicitly.
    fn CGEventSetFlags(event: *mut c_void, flags: u64);

    /// Attaches a UTF-16 string to a keyboard event, which is what makes the
    /// unicode path type a character the remote layout cannot otherwise reach.
    fn CGEventKeyboardSetUnicodeString(event: *mut c_void, length: usize, string: *const u16);

    /// Posts an event. **Returns void**: there is no delivery to report.
    fn CGEventPost(tap: u32, event: *mut c_void);

    /// The pointer's current position, read when a button arrives before any move.
    fn CGEventGetLocation(event: *mut c_void) -> sys::CGPoint;

    /// An event with no source, used only to read the pointer's location.
    fn CGEventCreate(source: *mut c_void) -> *mut c_void;
}

#[link(name = "Carbon", kind = "framework")]
unsafe extern "C" {
    /// Whether the system is in secure event input — a password field has focus and
    /// synthetic keyboard events are being discarded.
    fn IsSecureEventInputEnabled() -> u8;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    /// Releases an event or an event source.
    fn CFRelease(object: *const c_void);
}

/// A Core Foundation object released on drop.
///
/// Every `CGEvent` is created, configured, posted and released, and there are four
/// early-return branches between the first and the last. One owning type is the
/// difference between that and a leak per keystroke in a daemon that runs for
/// months.
#[derive(Debug)]
struct Owned(*mut c_void);

impl Owned {
    /// Takes ownership of a Core Foundation object, refusing null.
    fn new(object: *mut c_void) -> Option<Self> {
        if object.is_null() { None } else { Some(Self(object)) }
    }

    /// The raw pointer, borrowed rather than consumed.
    fn raw(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0.cast_const()) };
    }
}

/// The macOS injector.
pub struct MacInjector {
    /// The event source every event is stamped with, held for the injector's life
    /// because creating one per event would drop the modifier state it accumulates.
    source: Owned,
    /// The displays, in the protocol's own numbering.
    displays: Vec<DisplaySpace>,
    /// What has actually been posted, and therefore what must be released.
    state: InputState,
}

impl MacInjector {
    /// Builds an injector for this machine's displays.
    ///
    /// # Errors
    ///
    /// [`InjectError::PermissionDenied`] when Accessibility has not been granted,
    /// and [`InjectError::Failed`] when Core Graphics will not produce an event
    /// source — which on a machine that passed the grant check means something is
    /// wrong that a retry will not fix.
    pub fn new() -> Result<Self, InjectError> {
        grant::gate_input()?;
        let source = Owned::new(unsafe { CGEventSourceCreate(SOURCE_HID_SYSTEM_STATE) }).ok_or(
            InjectError::Failed(Fault::refused("CGEventSourceCreate", "produced no event source")),
        )?;
        Ok(Self { source, displays: read_displays()?, state: InputState::new() })
    }

    /// Re-reads the display layout.
    ///
    /// Called when the screen source rebuilds: that is exactly when a display was
    /// added, removed, moved or rescaled, and every origin held here became a lie
    /// that would land the pointer on the wrong screen.
    ///
    /// # Errors
    ///
    /// [`InjectError::NoSession`] for a machine with no displays at all.
    pub fn relayout(&mut self) -> Result<(), InjectError> {
        self.displays = read_displays()?;
        Ok(())
    }

    /// Releases everything this injector has left held.
    ///
    /// Idempotent, because it is called both on an explicit `RELEASE_ALL` and again
    /// from [`Drop`]. Errors from individual releases are collected rather than
    /// short-circuited: a key that cannot be released must not stop the next key
    /// from being released.
    ///
    /// # Errors
    ///
    /// The first failure encountered, after every release has been attempted.
    pub fn release_all(&mut self) -> Result<(), InjectError> {
        let plan = self.state.release_plan();
        let mut first: Option<InjectError> = None;
        for event in &plan {
            if let Err(failure) = self.post_one(event) {
                first.get_or_insert(failure);
            }
        }
        match first {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }

    /// Posts the platform events one input event becomes.
    ///
    /// Deliberately does **not** update [`Self::state`]: the caller does that after
    /// the post succeeds, so a failed call cannot leave a key recorded as held that
    /// is not — which would make the release plan press a key nobody touched.
    fn post_one(&mut self, event: &InjectedEvent) -> Result<(), InjectError> {
        let planned = synth::macos_events(event, &self.displays, &mut self.state)
            .map_err(InjectError::Refused)?;
        for step in planned {
            self.post_planned(step)?;
        }
        Ok(())
    }

    /// Builds and posts one planned `CGEvent`.
    fn post_planned(&self, planned: MacEvent) -> Result<(), InjectError> {
        let event = match planned {
            MacEvent::Mouse { event_type, button, point, flags } => {
                let position = match point {
                    Some(point) => sys::CGPoint {
                        // The plan works in whole points; Core Graphics takes
                        // floating point and treats the value as the point's own
                        // coordinate, so the conversion is exact.
                        x: point.x as f64,
                        y: point.y as f64,
                    },
                    // A button before any move: post it where the pointer already
                    // is. Inventing a position here would move the pointer as a side
                    // effect of clicking.
                    None => current_location(),
                };
                let event = Owned::new(unsafe {
                    CGEventCreateMouseEvent(self.source.raw(), event_type, position, button)
                })
                .ok_or(InjectError::Failed(Fault::refused(
                    "CGEventCreateMouseEvent",
                    "produced no event",
                )))?;
                unsafe { CGEventSetFlags(event.raw(), flags) };
                event
            }
            MacEvent::Scroll { lines_y, lines_x, flags } => {
                let event = Owned::new(unsafe {
                    CGEventCreateScrollWheelEvent2(
                        self.source.raw(),
                        SCROLL_UNIT_LINE,
                        2,
                        lines_y,
                        lines_x,
                        0,
                    )
                })
                .ok_or(InjectError::Failed(Fault::refused(
                    "CGEventCreateScrollWheelEvent2",
                    "produced no event",
                )))?;
                unsafe { CGEventSetFlags(event.raw(), flags) };
                event
            }
            MacEvent::Key { key_code, down, flags } => {
                let event = Owned::new(unsafe {
                    CGEventCreateKeyboardEvent(self.source.raw(), key_code, u8::from(down))
                })
                .ok_or(InjectError::Failed(Fault::refused(
                    "CGEventCreateKeyboardEvent",
                    "produced no event",
                )))?;
                unsafe { CGEventSetFlags(event.raw(), flags) };
                event
            }
            MacEvent::Unicode { unit, down } => {
                // Key code zero with a unicode string attached is the documented
                // way to type a character the layout cannot reach. The flags are
                // deliberately left alone: the unicode path ignores modifier state
                // entirely, which is why `crate::input` refuses text while a
                // shortcut modifier is held rather than pretending here.
                let event = Owned::new(unsafe {
                    CGEventCreateKeyboardEvent(self.source.raw(), 0, u8::from(down))
                })
                .ok_or(InjectError::Failed(Fault::refused(
                    "CGEventCreateKeyboardEvent",
                    "produced no event",
                )))?;
                let units = [unit];
                unsafe { CGEventKeyboardSetUnicodeString(event.raw(), units.len(), units.as_ptr()) };
                event
            }
        };
        unsafe { CGEventPost(HID_EVENT_TAP, event.raw()) };
        Ok(())
    }
}

impl Injector for MacInjector {
    /// Injects a batch, in order, refusing what macOS will not deliver.
    ///
    /// # Errors
    ///
    /// [`InjectError::PermissionDenied`] when the Accessibility grant has gone away
    /// since the last batch, and [`InjectError::Refused`] with
    /// [`Refusal::SecureDesktop`] for keyboard input while a password field holds
    /// secure input. Both are **states the console reports**, not faults: the first
    /// ends when the operator grants the permission and the second when they finish
    /// typing their password at the machine.
    fn inject(&mut self, events: &[InjectedEvent]) -> Result<(), InjectError> {
        grant::gate_input()?;
        let secure = secure_input_enabled();
        for event in events {
            if let Some(refusal) = refuse_under_secure_input(event, secure) {
                return Err(InjectError::Refused(refusal));
            }
            self.post_one(event)?;
            // Recorded only once the post has happened, so what the release plan
            // believes is held is what was actually sent.
            self.state.observe(event);
        }
        Ok(())
    }
}

impl Drop for MacInjector {
    /// Applies the release plan, autonomously.
    ///
    /// This is the half of `RELEASE_ALL` that does not depend on the client: the
    /// session that owned this injector has ended, for whatever reason — a clean
    /// close, a dropped tunnel, an agent being torn down — and whatever it left held
    /// comes up now. A failure here cannot be reported anywhere and must not stop
    /// the remaining releases, so each is attempted and the result is discarded.
    fn drop(&mut self) {
        let plan = self.state.release_plan();
        for event in &plan {
            let _ = self.post_one(event);
        }
    }
}

/// Whether an event must be refused because secure input is on.
///
/// Pure, so the policy can be asserted without a password field: keyboard and text
/// are refused, everything else is not. Separating the two matters — a pointer that
/// freezes whenever the machine asks for a password looks like a dead session, and
/// a keyboard that silently types nothing looks like a broken one.
pub fn refuse_under_secure_input(event: &InjectedEvent, secure: bool) -> Option<Refusal> {
    if !secure {
        return None;
    }
    match event {
        InjectedEvent::Key { .. } | InjectedEvent::Text { .. } => Some(Refusal::SecureDesktop),
        InjectedEvent::PointerMove { .. }
        | InjectedEvent::Button { .. }
        | InjectedEvent::Scroll { .. } => None,
    }
}

/// Whether macOS is discarding synthetic keyboard events right now.
pub fn secure_input_enabled() -> bool {
    unsafe { IsSecureEventInputEnabled() != 0 }
}

/// The pointer's current position, for a button that arrives before any move.
///
/// Answers the origin when Core Graphics will not say, which is the only place in
/// this module where a coordinate is invented — and it is invented for a click that
/// would otherwise not happen at all.
fn current_location() -> sys::CGPoint {
    let Some(event) = Owned::new(unsafe { CGEventCreate(std::ptr::null_mut()) }) else {
        return sys::CGPoint { x: 0.0, y: 0.0 };
    };
    unsafe { CGEventGetLocation(event.raw()) }
}

/// This machine's displays, as the injector's coordinate mapping needs them.
fn read_displays() -> Result<Vec<DisplaySpace>, InjectError> {
    let displays = sys::displays().map_err(|condition| match condition {
        CaptureError::NoSession => InjectError::NoSession,
        CaptureError::PermissionDenied(grant) => InjectError::PermissionDenied(grant),
        other => InjectError::Failed(Fault::refused(
            "CGGetActiveDisplayList",
            other.sentence().into_owned(),
        )),
    })?;
    Ok(displays
        .iter()
        .take(selfhost_desk::wire::MAX_MONITORS)
        .enumerate()
        .map(|(index, display)| DisplaySpace {
            monitor: u8::try_from(index).unwrap_or(u8::MAX),
            origin: display.point_origin,
            scale_permille: display.scale_permille(),
            pixel_width: display.pixel_width,
            pixel_height: display.pixel_height,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_desk::keys::Usage;
    use selfhost_desk::wire::Button;

    fn key(code: &str) -> Usage {
        Usage::from_code(code).expect("the vocabulary has this key")
    }

    #[test]
    fn secure_input_stops_the_keyboard_and_leaves_the_pointer_alone() {
        // The console must be able to say "the machine is asking for a password"
        // while the operator can still see the pointer moving.
        assert_eq!(
            refuse_under_secure_input(&InjectedEvent::Key { usage: key("KeyA"), down: true }, true),
            Some(Refusal::SecureDesktop)
        );
        assert_eq!(
            refuse_under_secure_input(&InjectedEvent::Text { unit: 65, down: true }, true),
            Some(Refusal::SecureDesktop)
        );
        assert_eq!(
            refuse_under_secure_input(
                &InjectedEvent::PointerMove { monitor: 0, x: 1, y: 1 },
                true
            ),
            None
        );
        assert_eq!(
            refuse_under_secure_input(
                &InjectedEvent::Button { button: Button::Left, down: true },
                true
            ),
            None
        );
    }

    #[test]
    fn nothing_is_refused_when_secure_input_is_off() {
        for event in [
            InjectedEvent::Key { usage: key("KeyA"), down: true },
            InjectedEvent::Text { unit: 65, down: true },
            InjectedEvent::Scroll { dx: 0, dy: 120 },
        ] {
            assert_eq!(refuse_under_secure_input(&event, false), None);
        }
    }

    #[test]
    fn the_machine_answers_whether_it_is_in_secure_input() {
        // A pure query against the real Carbon symbol: it must not prompt, must not
        // hang, and must answer the same thing twice in a row on an idle machine.
        assert_eq!(secure_input_enabled(), secure_input_enabled());
    }

    #[test]
    fn an_injector_either_builds_or_names_the_grant_it_is_missing() {
        // Against the real machine, and deliberately without injecting anything: a
        // test that moved the developer's pointer would be a test nobody runs twice.
        match MacInjector::new() {
            Ok(injector) => {
                assert!(!injector.displays.is_empty());
                assert!(injector.state.is_idle());
            }
            Err(InjectError::PermissionDenied(grant)) => {
                let sentence = grant::remediation(grant);
                assert!(sentence.contains("Accessibility"), "{sentence}");
            }
            Err(InjectError::NoSession) => {}
            Err(other) => panic!("unexpected refusal: {other}"),
        }
    }

    #[test]
    fn a_sub_notch_scroll_reaches_the_platform_as_nothing_at_all() {
        // The one end-to-end injection this test suite is willing to perform: it
        // runs the whole path — the grant check, the secure-input check, the plan —
        // against the real machine and produces no platform event, because a single
        // 1/120th of a notch is not yet a line. A test that moved the developer's
        // pointer or typed into their editor would be a test nobody runs twice.
        let Ok(mut injector) = MacInjector::new() else {
            return; // no Accessibility grant, or no displays
        };
        let outcome = injector.inject(&[InjectedEvent::Scroll { dx: 0, dy: 1 }]);
        match outcome {
            Ok(()) => {}
            // Secure input is on because a password field has focus somewhere. That
            // refusal applies to the keyboard rather than the wheel, so it should not
            // appear here — but if the machine is in that state, the assertion worth
            // making is that the refusal is named rather than silent.
            Err(InjectError::Refused(reason)) => {
                panic!("a wheel event was refused with {reason:?}");
            }
            Err(other) => panic!("unexpected failure: {other}"),
        }
        assert!(injector.state.is_idle(), "a wheel movement holds nothing down");
    }

    #[test]
    fn a_dropped_injector_has_nothing_left_to_release() {
        // The autonomous `RELEASE_ALL`, asserted at the level a test can reach
        // without a keyboard: the state an injector is dropped with is drained by
        // the same plan `Drop` applies, and draining twice produces nothing.
        let mut state = InputState::new();
        state.observe(&InjectedEvent::Key { usage: key("ControlLeft"), down: true });
        state.observe(&InjectedEvent::Button { button: Button::Left, down: true });
        assert_eq!(state.release_plan().len(), 2);
        assert!(state.release_plan().is_empty());
        assert!(state.is_idle());
    }

    #[test]
    fn the_displays_the_injector_addresses_are_the_ones_the_capture_advertises() {
        // The two must agree or the pointer lands on the wrong screen. Both are
        // built from `sys::displays` in the same order, and this is the assertion
        // that says so on whatever machine this runs on.
        let (Ok(spaces), Ok(monitors)) = (read_displays(), sys::monitors()) else {
            return; // no displays attached
        };
        assert_eq!(spaces.len(), monitors.len());
        for (space, monitor) in spaces.iter().zip(monitors.iter()) {
            assert_eq!(space.monitor, monitor.id);
            assert_eq!(space.pixel_width, monitor.width);
            assert_eq!(space.pixel_height, monitor.height);
            assert_eq!(space.scale_permille, monitor.scale_permille);
        }
    }
}
