//! Which mechanism a piece of input must use. Pure, and decided exactly once.
//!
//! There are two ways to make a character appear on both of the platforms this
//! project targets, and choosing the wrong one produces a failure with no error
//! message anywhere:
//!
//! - The **scancode path** presses a physical key. Windows takes a virtual-key
//!   code plus a scancode (plus `KEYEVENTF_EXTENDEDKEY` for the E0 keys); macOS
//!   takes a `CGKeyCode`. The operating system then applies the current keyboard
//!   layout and the current modifier state, which is what makes `Ctrl+C` mean
//!   copy.
//! - The **unicode path** hands the character over directly —
//!   `KEYEVENTF_UNICODE` packets on Windows, `CGEventKeyboardSetUnicodeString`
//!   on macOS. It bypasses the layout entirely, which is the only way to type a
//!   character the remote machine's layout cannot reach, and it **ignores
//!   modifier state**: `Ctrl+C` sent as unicode packets does nothing at all. Not
//!   "something unexpected" — nothing, silently, with a success return.
//!
//! The protocol therefore carries two different messages, `Key` and `Text`, and
//! the mapping from message to mechanism is fixed and lives here. It is decided
//! in one pure function so that both platform injectors inherit the same
//! decision, and so the decision is tested once rather than twice and
//! differently.
//!
//! # The held-key set is not bookkeeping, it is the failure mode
//!
//! This link is a tunnel over a VPN. The single most likely real-world failure is
//! that it drops in the middle of a drag or with a modifier down — and a
//! modifier that is never released stays down on the remote machine *forever*,
//! turning every subsequent keystroke by the person sitting at it into a
//! shortcut. So every press and release passes through [`HeldKeys`] here, and
//! [`release_all`] produces the exact release events needed to undo whatever is
//! outstanding. The agent applies it autonomously when the channel closes; the
//! client also sends it on blur and on reconnect. Both, deliberately: the client
//! cannot be trusted to still be running.

use selfhost_desk::keys::{HeldKeys, Modifier, Usage};
use selfhost_desk::wire::{Button, Message, Monitor, Refusal, MAX_TEXT_BYTES};

/// How a piece of input reaches the operating system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// A physical key, with the layout and the modifier state applied by the
    /// operating system.
    Scancode,
    /// A character handed over directly, bypassing the layout and ignoring every
    /// modifier that is held.
    Unicode,
}

/// The largest number of UTF-16 code units one `Text` message may produce.
///
/// Derived from the protocol's own byte cap rather than chosen independently, so
/// the two cannot drift apart: `MAX_TEXT_BYTES` of UTF-8 cannot encode more than
/// that many UTF-16 units, since every unit costs at least one byte.
pub const MAX_TEXT_UNITS: usize = MAX_TEXT_BYTES;

/// One input event, lowered to what a platform injector actually performs.
///
/// Deliberately still platform-neutral: pointer positions stay in the display's
/// own pixel space and are mapped by [`crate::coords`] inside each injector,
/// because the two platforms want different final forms (a 16-bit fraction of the
/// virtual desktop on Windows, a point in the global display space on macOS) and
/// baking either one in here would make this enum a Windows type wearing a
/// neutral name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectedEvent {
    /// A physical key went down or came up.
    Key {
        /// Which key, in the protocol's HID vocabulary.
        usage: Usage,
        /// True for a press.
        down: bool,
    },
    /// One UTF-16 code unit of text, down or up.
    ///
    /// A code *unit*, not a character: a character outside the basic multilingual
    /// plane is a surrogate pair and travels as two of these in order, which is
    /// what both platforms' unicode paths require.
    Text {
        /// The UTF-16 code unit.
        unit: u16,
        /// True for a press. Each unit is pressed and released in turn.
        down: bool,
    },
    /// The pointer moved to an absolute position in a display's pixel space.
    PointerMove {
        /// Which display's pixel space the coordinates are in.
        monitor: u8,
        /// x within that display, in pixels.
        x: i32,
        /// y within that display, in pixels.
        y: i32,
    },
    /// A pointer button went down or came up.
    Button {
        /// Which button.
        button: Button,
        /// True for a press.
        down: bool,
    },
    /// The wheel turned, in 1/120ths of a notch, positive being away from the
    /// user and to the right.
    Scroll {
        /// Horizontal movement.
        dx: i32,
        /// Vertical movement.
        dy: i32,
    },
}

/// The mechanism a protocol message uses, or `None` for one that is not input.
pub fn mechanism(message: &Message) -> Option<Mechanism> {
    match message {
        Message::Key { .. } | Message::ReleaseAll => Some(Mechanism::Scancode),
        Message::Text { .. } => Some(Mechanism::Unicode),
        // Pointer events are neither: they are neither a key nor a character,
        // and answering `Scancode` for them would make the name a lie in the one
        // place somebody might later read it as a promise.
        _ => None,
    }
}

/// The modifier that makes typing text meaningless, if one is held.
///
/// Shift is not one of them: holding Shift while text arrives is what a client
/// does when the operator is typing capitals, and the unicode path already
/// carries the capital itself. Anything else — Control, Alt, or the Windows/
/// Command key — means the remote machine is mid-shortcut, and injecting
/// characters there produces neither the shortcut nor the text.
pub fn blocks_text(held: &HeldKeys) -> Option<Modifier> {
    held.held()
        .filter_map(|key| key.modifier())
        .map(|(modifier, _side)| modifier)
        .find(|modifier| !matches!(modifier, Modifier::Shift))
}

/// Lowers one protocol message into the events a platform injector performs.
///
/// `held` is updated as a side effect, because the held set and the events must
/// agree by construction: a press that is emitted but not recorded is a key that
/// [`release_all`] will never let go of.
///
/// Returns a [`Refusal`] — the protocol's own vocabulary — for input that will
/// not be performed, so the caller can tell the client why its keystroke did
/// nothing instead of dropping it silently.
pub fn lower(
    message: &Message,
    monitors: &[Monitor],
    held: &mut HeldKeys,
) -> Result<Vec<InjectedEvent>, Refusal> {
    match message {
        Message::Key { usage, down } => {
            if *down {
                held.press(*usage);
            } else {
                held.release(*usage);
            }
            Ok(vec![InjectedEvent::Key { usage: *usage, down: *down }])
        }
        Message::Text { text } => {
            if let Some(modifier) = blocks_text(held) {
                // `Unmappable` is the closest word the protocol has, and it is
                // the truthful one: with this modifier down there is no sequence
                // of unicode packets that produces what the client asked for.
                let _ = modifier;
                return Err(Refusal::Unmappable);
            }
            text_events(text)
        }
        Message::PointerMove { monitor, x, y } => {
            // Validated here rather than in the injector so that a hostile
            // coordinate is refused once, in a tested pure function, on both
            // platforms.
            crate::coords::locate(monitors, *monitor, *x, *y).map_err(|_| Refusal::Unmappable)?;
            Ok(vec![InjectedEvent::PointerMove { monitor: *monitor, x: *x, y: *y }])
        }
        Message::Button { button, down } => {
            Ok(vec![InjectedEvent::Button { button: *button, down: *down }])
        }
        Message::Scroll { dx, dy } => Ok(vec![InjectedEvent::Scroll { dx: *dx, dy: *dy }]),
        Message::ReleaseAll => Ok(release_all(held)),
        // Every other message is the agent talking, not the client. A client
        // that sends one is refused rather than ignored, so the console can say
        // so instead of appearing to accept input it never performed.
        _ => Err(Refusal::Unmappable),
    }
}

/// The release events that undo everything currently held.
///
/// Drains the held set, so calling it twice is harmless and the second call
/// produces nothing. Order is the vocabulary's own order rather than the order
/// the keys were pressed; releases are independent of each other, so any order
/// leaves the remote keyboard in the same state.
pub fn release_all(held: &mut HeldKeys) -> Vec<InjectedEvent> {
    held.drain()
        .into_iter()
        .map(|usage| InjectedEvent::Key { usage, down: false })
        .collect()
}

/// Lowers a string to unicode down/up pairs, one per UTF-16 code unit.
///
/// A character outside the basic multilingual plane becomes two units, emitted in
/// order — both platforms require the high surrogate and the low surrogate to
/// arrive as consecutive events, and splitting them across two batches produces a
/// replacement character or nothing at all.
pub fn text_events(text: &str) -> Result<Vec<InjectedEvent>, Refusal> {
    let mut events = Vec::with_capacity(text.len() * 2);
    for unit in text.encode_utf16() {
        if events.len() / 2 >= MAX_TEXT_UNITS {
            return Err(Refusal::Unmappable);
        }
        events.push(InjectedEvent::Text { unit, down: true });
        events.push(InjectedEvent::Text { unit, down: false });
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: &str) -> Usage {
        Usage::from_code(code).expect("the vocabulary has this key")
    }

    fn one_display() -> Vec<Monitor> {
        vec![Monitor {
            id: 0,
            origin_x: 0,
            origin_y: 0,
            width: 1920,
            height: 1080,
            scale_permille: 1000,
            primary: true,
        }]
    }

    #[test]
    fn a_key_message_takes_the_scancode_path_and_text_takes_the_unicode_one() {
        // The whole point of the two-message protocol. If this ever collapses,
        // `Ctrl+C` starts doing nothing with no error anywhere.
        assert_eq!(
            mechanism(&Message::Key { usage: key("KeyC"), down: true }),
            Some(Mechanism::Scancode)
        );
        assert_eq!(
            mechanism(&Message::Text { text: "c".to_owned() }),
            Some(Mechanism::Unicode)
        );
        assert_eq!(mechanism(&Message::ReleaseAll), Some(Mechanism::Scancode));
        assert_eq!(mechanism(&Message::Scroll { dx: 0, dy: 120 }), None);
    }

    #[test]
    fn a_press_is_recorded_and_a_release_clears_it() {
        let mut held = HeldKeys::new();
        let events =
            lower(&Message::Key { usage: key("ShiftLeft"), down: true }, &one_display(), &mut held)
                .unwrap();
        assert_eq!(events, vec![InjectedEvent::Key { usage: key("ShiftLeft"), down: true }]);
        assert!(held.is_held(key("ShiftLeft")));

        lower(&Message::Key { usage: key("ShiftLeft"), down: false }, &one_display(), &mut held)
            .unwrap();
        assert!(!held.is_held(key("ShiftLeft")));
    }

    #[test]
    fn release_all_lets_go_of_everything_that_is_down() {
        // The VPN-drop-mid-drag case: without this, a modifier stays down on the
        // remote machine forever and every later keystroke becomes a shortcut.
        let mut held = HeldKeys::new();
        for code in ["ControlLeft", "AltLeft", "KeyA"] {
            lower(&Message::Key { usage: key(code), down: true }, &one_display(), &mut held)
                .unwrap();
        }
        let releases = release_all(&mut held);
        assert_eq!(releases.len(), 3);
        assert!(releases.iter().all(|event| matches!(
            event,
            InjectedEvent::Key { down: false, .. }
        )));
        assert!(held.is_empty());
    }

    #[test]
    fn release_all_a_second_time_produces_nothing() {
        let mut held = HeldKeys::new();
        lower(&Message::Key { usage: key("KeyA"), down: true }, &one_display(), &mut held).unwrap();
        assert_eq!(release_all(&mut held).len(), 1);
        assert!(release_all(&mut held).is_empty());
    }

    #[test]
    fn the_release_all_message_goes_through_the_same_path() {
        let mut held = HeldKeys::new();
        lower(&Message::Key { usage: key("MetaLeft"), down: true }, &one_display(), &mut held)
            .unwrap();
        let events = lower(&Message::ReleaseAll, &one_display(), &mut held).unwrap();
        assert_eq!(events, vec![InjectedEvent::Key { usage: key("MetaLeft"), down: false }]);
        assert!(held.is_empty());
    }

    #[test]
    fn text_becomes_one_down_and_one_up_per_code_unit() {
        let events = text_events("hi").unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0], InjectedEvent::Text { unit: u16::from(b'h'), down: true });
        assert_eq!(events[1], InjectedEvent::Text { unit: u16::from(b'h'), down: false });
    }

    #[test]
    fn a_character_outside_the_basic_plane_travels_as_its_surrogate_pair_in_order() {
        // Both platforms require the two halves to arrive consecutively; a single
        // event carrying a `char` would have made this impossible to express.
        let events = text_events("\u{1F600}").unwrap();
        assert_eq!(events.len(), 4, "one surrogate pair is two units");
        let units: Vec<u16> = events
            .iter()
            .filter_map(|event| match event {
                InjectedEvent::Text { unit, down: true } => Some(*unit),
                _ => None,
            })
            .collect();
        assert_eq!(units, vec![0xD83D, 0xDE00]);
    }

    #[test]
    fn text_is_refused_while_a_shortcut_modifier_is_held() {
        // Unicode packets ignore modifier state entirely, so injecting here
        // produces neither the shortcut nor the characters. Refusing tells the
        // console; injecting would produce silence.
        for code in ["ControlLeft", "AltRight", "MetaLeft"] {
            let mut held = HeldKeys::new();
            lower(&Message::Key { usage: key(code), down: true }, &one_display(), &mut held)
                .unwrap();
            assert_eq!(
                lower(&Message::Text { text: "c".to_owned() }, &one_display(), &mut held),
                Err(Refusal::Unmappable),
                "text should be refused with {code} held"
            );
        }
    }

    #[test]
    fn text_is_allowed_while_shift_is_held() {
        // A client holds Shift while the operator types capitals, and the
        // capital is already in the text. Refusing here would make shifted
        // typing impossible.
        let mut held = HeldKeys::new();
        lower(&Message::Key { usage: key("ShiftLeft"), down: true }, &one_display(), &mut held)
            .unwrap();
        assert!(blocks_text(&held).is_none());
        assert!(lower(&Message::Text { text: "A".to_owned() }, &one_display(), &mut held).is_ok());
    }

    #[test]
    fn a_pointer_position_outside_the_display_is_refused_before_it_reaches_a_platform() {
        let mut held = HeldKeys::new();
        assert_eq!(
            lower(&Message::PointerMove { monitor: 0, x: 5000, y: 0 }, &one_display(), &mut held),
            Err(Refusal::Unmappable)
        );
        assert_eq!(
            lower(&Message::PointerMove { monitor: 9, x: 0, y: 0 }, &one_display(), &mut held),
            Err(Refusal::Unmappable)
        );
        assert!(
            lower(&Message::PointerMove { monitor: 0, x: 1919, y: 1079 }, &one_display(), &mut held)
                .is_ok()
        );
    }

    #[test]
    fn a_message_the_agent_sends_is_refused_rather_than_ignored() {
        // A client that sends `FrameEnd` is confused or hostile. Ignoring it
        // would make the console believe input was performed.
        let mut held = HeldKeys::new();
        assert_eq!(
            lower(&Message::FrameEnd { sequence: 1 }, &one_display(), &mut held),
            Err(Refusal::Unmappable)
        );
    }

    #[test]
    fn every_key_in_the_vocabulary_lowers_without_refusal() {
        // `Usage::all` is the seam `selfhost-desk` documents for exactly this:
        // it turns "the table is complete" from a claim into an assertion.
        let monitors = one_display();
        for usage in Usage::all() {
            let mut held = HeldKeys::new();
            assert!(
                lower(&Message::Key { usage, down: true }, &monitors, &mut held).is_ok(),
                "{} has no lowering",
                usage.code()
            );
            assert!(held.is_held(usage));
        }
    }
}
