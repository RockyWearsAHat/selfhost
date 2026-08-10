//! Windows input injection: `SendInput`, and the refusal it will not admit to.
//!
//! Every decision this file could get wrong has already been made in
//! [`crate::synth`] — which flags an absolute pointer move carries, which virtual
//! key and scancode a HID usage is, which of the thumb buttons travels in
//! `mouseData` — where each is a pure function with a table beside it, tested on a
//! machine that has no `user32.dll`. What is left here is the call, the structure
//! whose size must be exact, and the one thing only this layer can ask about.
//!
//! # A full return count is not success
//!
//! `SendInput` answers the number of events it inserted into the input stream.
//! **That is not the number delivered.** User Interface Privilege Isolation
//! discards synthesised input aimed at any window above the caller's integrity
//! level, after the call has returned, and neither the return value nor
//! `GetLastError` says a word about it. The agent runs as the console user at
//! medium integrity *deliberately* — see [`super::uipi_verdict`] for why running it
//! any higher would turn this feature into a remote privilege-escalation channel —
//! so this is the ordinary case whenever an elevated window has focus, not an
//! exotic one.
//!
//! Therefore: the foreground window's integrity level is read **before** the batch,
//! and input that would be swallowed is refused with
//! [`Refusal::ElevatedWindow`] so the console can say `input-refused (elevated
//! window)`. That is a state to be surfaced, never a bug to be chased. What cannot
//! be detected is not claimed: `Ok(())` means *posted*, which is the strongest
//! claim this platform supports.
//!
//! # The secure desktop is refused before anything else
//!
//! A UAC consent dialog, the lock screen and the credential provider all live on a
//! different desktop, and this session deliberately can neither see nor drive any
//! of them. `SendInput` from the ordinary desktop simply does not reach the secure
//! one, so refusing here changes nothing about what happens — it changes what the
//! console is able to *say* about it.
//!
//! # Everything held is released when this object goes away
//!
//! [`WinInjector`] owns a [`synth::InputState`] recording what it has actually
//! posted, and its [`Drop`] applies the release plan without being asked. The case
//! it exists for is the tunnel dropping mid-drag, where the client that would have
//! sent `RELEASE_ALL` is the thing that vanished — and a left button or an Alt key
//! left down on a remote Windows machine makes the desktop unusable for the person
//! sitting at it.

use super::sys::{self, Handle, OwnedHandle};
use super::{blocked_by_elevation, desktop, identity, uipi_verdict, ForegroundIntegrity, InputDesktop};
use crate::agent::Integrity;
use crate::input::InjectedEvent;
use crate::synth::{self, InputState, WindowsInput};
use crate::{Fault, InjectError, Injector};
use selfhost_desk::wire::{Monitor, Refusal};

/// The Windows injector.
#[derive(Debug)]
pub struct WinInjector {
    /// The displays, as the protocol describes them, for the coordinate mapping.
    monitors: Vec<Monitor>,
    /// What has actually been posted, and therefore what must be released.
    state: InputState,
    /// This process's own integrity level, read once: it cannot change for the life
    /// of a process, and re-reading it per batch would be a token open per
    /// keystroke.
    own: Integrity,
}

impl WinInjector {
    /// Builds an injector for this session's displays.
    ///
    /// # Errors
    ///
    /// [`InjectError::NoSession`] when the session has no displays, which is what a
    /// session that has been switched away from looks like from inside.
    pub fn new() -> Result<Self, InjectError> {
        let monitors = super::gdi::monitors().map_err(|_| InjectError::NoSession)?;
        if monitors.is_empty() {
            return Err(InjectError::NoSession);
        }
        Ok(Self { monitors, state: InputState::new(), own: identity::process_integrity() })
    }

    /// Re-reads the display layout.
    ///
    /// Called when the screen source rebuilds, because that is exactly when a
    /// display was added, removed, moved or rescaled and the normalisation held
    /// here started addressing a virtual desktop that no longer exists.
    ///
    /// # Errors
    ///
    /// [`InjectError::NoSession`] as [`Self::new`].
    pub fn relayout(&mut self) -> Result<(), InjectError> {
        let monitors = super::gdi::monitors().map_err(|_| InjectError::NoSession)?;
        if monitors.is_empty() {
            return Err(InjectError::NoSession);
        }
        self.monitors = monitors;
        Ok(())
    }

    /// This process's integrity level, for the diagnostics plate.
    pub fn integrity(&self) -> Integrity {
        self.own
    }

    /// The displays this injector addresses, for the lowering that validates a
    /// pointer position before it reaches a platform call.
    ///
    /// Borrowed from the injector rather than kept a second time by the caller,
    /// because two copies of a display list are two copies that a topology change
    /// updates at different moments — and the moment they disagree is a pointer
    /// mapped against one desktop and injected into another.
    pub fn monitors(&self) -> &[Monitor] {
        &self.monitors
    }

    /// Releases everything this injector has left held.
    ///
    /// Idempotent, because it is called both for an explicit `RELEASE_ALL` and again
    /// from [`Drop`]. Every release is attempted even after one fails: a key that
    /// cannot be released must not keep the next one held.
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
    /// Deliberately does not update [`Self::state`]: the caller records the event
    /// only after the post has succeeded, so a failed call cannot leave a key
    /// recorded as held that is not — which would make the release plan press a key
    /// nobody touched.
    fn post_one(&mut self, event: &InjectedEvent) -> Result<(), InjectError> {
        let planned = synth::windows_inputs(event, &self.monitors, &mut self.state)
            .map_err(InjectError::Refused)?;
        if planned.is_empty() {
            return Ok(());
        }
        let inputs: Vec<sys::Input> = planned.iter().map(build).collect();
        send(&inputs)
    }
}

/// One planned event as the tagged union `SendInput` takes.
fn build(planned: &WindowsInput) -> sys::Input {
    match planned {
        WindowsInput::Mouse { dx, dy, mouse_data, flags } => sys::Input {
            kind: sys::INPUT_MOUSE,
            event: sys::InputUnion {
                mouse: sys::MouseInput {
                    dx: *dx,
                    dy: *dy,
                    mouse_data: *mouse_data,
                    flags: *flags,
                    // Zero means "now". A timestamp from any other clock makes
                    // events arrive out of order with the machine's own input.
                    time: 0,
                    extra_info: 0,
                },
            },
        },
        WindowsInput::Key { virtual_key, scancode, flags } => sys::Input {
            kind: sys::INPUT_KEYBOARD,
            event: sys::InputUnion {
                keyboard: sys::KeyboardInput {
                    virtual_key: *virtual_key,
                    scancode: *scancode,
                    flags: *flags,
                    time: 0,
                    extra_info: 0,
                },
            },
        },
    }
}

/// Hands a batch to `SendInput`, refusing to read success into a full count.
///
/// # Errors
///
/// [`InjectError::Failed`] when fewer events were inserted than were offered. That
/// is the only failure `SendInput` reports, and it means the input stream rejected
/// the batch — most often because another process is blocking input, occasionally
/// because a structure size disagreed, which the compile-time assertions in
/// [`super::sys`] exist to make impossible.
fn send(inputs: &[sys::Input]) -> Result<(), InjectError> {
    if inputs.is_empty() {
        return Ok(());
    }
    let count = u32::try_from(inputs.len())
        .map_err(|_| InjectError::Failed(Fault::refused("SendInput", "a batch that large")))?;
    let size = i32::try_from(size_of::<sys::Input>())
        .map_err(|_| InjectError::Failed(Fault::refused("SendInput", "an impossible INPUT size")))?;
    let inserted = unsafe { sys::SendInput(count, inputs.as_ptr(), size) };
    if inserted != count {
        return Err(InjectError::Failed(
            Fault::last_os_error("SendInput")
                .noting(format!("inserted {inserted} of {count} events")),
        ));
    }
    // And that is *all* this proves. See the module documentation: UIPI discards
    // what it discards after this returns, and says nothing about it.
    Ok(())
}

/// What can be learned about the window that currently has the focus.
///
/// The three answers are not interchangeable — see [`ForegroundIntegrity`]. In
/// particular `ERROR_ACCESS_DENIED` from either call is **evidence of elevation**
/// rather than an absence of information: Windows grants
/// `PROCESS_QUERY_LIMITED_INFORMATION` against any same-user process at or below
/// the caller's level, so being refused means the target is above it.
pub fn foreground_integrity() -> ForegroundIntegrity {
    let window = unsafe { sys::GetForegroundWindow() };
    if window.is_null() {
        // No window has the focus. Ordinary during a desktop switch, and it says
        // nothing about integrity.
        return ForegroundIntegrity::Unknown;
    }
    let mut process_id: u32 = 0;
    let thread = unsafe { sys::GetWindowThreadProcessId(window, &mut process_id) };
    if thread == 0 || process_id == 0 {
        return ForegroundIntegrity::Unknown;
    }

    let raw = unsafe {
        sys::OpenProcess(sys::PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id)
    };
    let Some(process) = OwnedHandle::new(raw) else {
        return denied_or_unknown();
    };

    let mut token_raw: Handle = std::ptr::null_mut();
    let opened = unsafe { sys::OpenProcessToken(process.raw(), sys::TOKEN_QUERY, &mut token_raw) };
    if opened == 0 {
        return denied_or_unknown();
    }
    let Some(token) = OwnedHandle::new(token_raw) else {
        return ForegroundIntegrity::Unknown;
    };
    match identity::token_integrity(&token) {
        Ok(rid) => ForegroundIntegrity::Known(Integrity::from_rid(rid)),
        // The token opened but its label would not be read. Nothing here says the
        // window is elevated, so nothing is claimed.
        Err(_) => ForegroundIntegrity::Unknown,
    }
}

/// Reads the failure that has just happened as evidence, or as silence.
///
/// `GetLastError` is read immediately — through `std::io::Error`, which reads it on
/// this platform — because any intervening call, including an allocation, may
/// overwrite it.
fn denied_or_unknown() -> ForegroundIntegrity {
    match std::io::Error::last_os_error().raw_os_error() {
        Some(code) if code == sys::ERROR_ACCESS_DENIED => ForegroundIntegrity::Denied,
        _ => ForegroundIntegrity::Unknown,
    }
}

impl Injector for WinInjector {
    /// Injects a batch, in order, refusing what Windows will discard.
    ///
    /// # Errors
    ///
    /// [`InjectError::Refused`] with [`Refusal::SecureDesktop`] while a consent
    /// prompt or the lock screen holds the input desktop, and with
    /// [`Refusal::ElevatedWindow`] when the focused window is above this process —
    /// both **states the console reports**, both ending by themselves. Everything
    /// else is [`InjectError::Failed`].
    fn inject(&mut self, events: &[InjectedEvent]) -> Result<(), InjectError> {
        // The secure desktop first: it is one cheap call and it explains the other
        // refusal when both apply.
        match desktop::input_desktop() {
            Ok(InputDesktop::Default) => {}
            Ok(_) => return Err(InjectError::Refused(Refusal::SecureDesktop)),
            // A desktop that cannot be identified is one we must not type into: an
            // unnamed desktop in front means something else took the input.
            Err(_) => return Err(InjectError::Refused(Refusal::SecureDesktop)),
        }

        // Read once per batch rather than per event: it is a process open and a
        // token read, and the focus does not change inside a batch that takes
        // microseconds.
        let elevation = uipi_verdict(self.own, foreground_integrity());

        for event in events {
            if let Some(refusal) = elevation.filter(|_| blocked_by_elevation(event)) {
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

impl Drop for WinInjector {
    /// Applies the release plan, autonomously.
    ///
    /// This is the half of `RELEASE_ALL` that does not depend on the client. The
    /// session that owned this injector has ended — cleanly, or because a tunnel
    /// dropped mid-drag — and whatever it left held comes up now. A failure here
    /// cannot be reported anywhere and must not stop the remaining releases, so each
    /// is attempted and the result discarded.
    ///
    /// The releases go through [`Self::post_one`] and therefore **skip** the desktop
    /// and elevation checks that [`Injector::inject`] applies to new input. That
    /// asymmetry is deliberate and it is the only safe way round. `SendInput` posts
    /// to the desktop this thread is attached to — `winsta0\default`, where the keys
    /// were pressed — so a consent prompt owning the *input* desktop does not stop
    /// the release from landing where it is needed. And [`InputState::release_plan`]
    /// drains the record before anything is posted, so a refusal here would not be
    /// retried by anybody: this is the last chance to put those keys up, and a check
    /// that turned it into "no chance at all" would leave a modifier held down on a
    /// machine whose remote session has already ended.
    ///
    /// [`InputState::release_plan`]: crate::synth::InputState::release_plan
    fn drop(&mut self) {
        let plan = self.state.release_plan();
        for event in &plan {
            let _ = self.post_one(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_input_structure_is_exactly_the_size_send_input_validates() {
        // The failure this prevents is total and silent: a `cbSize` mismatch makes
        // `SendInput` inject nothing and report a parameter error naming no field.
        assert_eq!(size_of::<sys::Input>(), 40);
        assert_eq!(size_of::<sys::MouseInput>(), 32);
        assert_eq!(size_of::<sys::KeyboardInput>(), 24);
    }

    #[test]
    fn a_planned_event_becomes_the_union_member_its_tag_names() {
        // The one place a mistake would put a mouse event's fields in a keyboard
        // event's union member, which Windows reads as a key with a garbage
        // scancode.
        let mouse = build(&WindowsInput::Mouse {
            dx: 100,
            dy: 200,
            mouse_data: 120,
            flags: synth::MOUSEEVENTF_WHEEL,
        });
        assert_eq!(mouse.kind, sys::INPUT_MOUSE);
        // Sound: the tag says which member was written.
        let written = unsafe { mouse.event.mouse };
        assert_eq!((written.dx, written.dy), (100, 200));
        assert_eq!(written.mouse_data, 120);
        assert_eq!(written.time, 0, "zero means now");

        let key = build(&WindowsInput::Key {
            virtual_key: 0x41,
            scancode: 0x1E,
            flags: synth::KEYEVENTF_KEYUP,
        });
        assert_eq!(key.kind, sys::INPUT_KEYBOARD);
        let written = unsafe { key.event.keyboard };
        assert_eq!(written.virtual_key, 0x41);
        assert_eq!(written.scancode, 0x1E);
        assert_eq!(written.flags, synth::KEYEVENTF_KEYUP);
    }

    #[test]
    fn an_empty_batch_calls_nothing() {
        // `SendInput` with a zero count is documented to fail, and a caller that
        // treated that as an injection failure would report a fault for an input
        // event that lowered to nothing — a sub-notch scroll, for instance.
        assert!(send(&[]).is_ok());
    }
}
