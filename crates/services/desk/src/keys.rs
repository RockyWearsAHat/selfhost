//! The key vocabulary: USB HID usage page 0x07, as a closed table.
//!
//! # Why not the UI toolkit's own key type
//!
//! `rui`'s [`Key`](../../rui/input/enum.Key.html) is a *user-interface* vocabulary
//! and it is the right one for a button that responds to Escape. It is the wrong
//! one for a remote keyboard: it has no function keys, no keypad, no separate
//! left and right modifiers, and its `Character(char)` carries the character the
//! operator's own layout produced, lowercased. Forwarding that to another machine
//! hands it a mangled keyboard — the remote end cannot tell `Numpad4` from `4`,
//! cannot see that the right Alt was the one pressed (which on a European layout
//! is AltGr and composes entirely different characters), and receives `c` where
//! the operator pressed the physical key that their layout calls `c` and the
//! remote layout may not.
//!
//! So the wire speaks *physical* keys. USB HID usage page 0x07 is the natural
//! choice because it is what the hardware itself reports and because every side
//! of this system already speaks it or maps to it in one table:
//!
//! - The browser's `KeyboardEvent.code` is **defined** in terms of these usages,
//!   so the SPA's mapping is a rename, not a translation.
//! - Windows maps by table to a virtual-key code plus a scancode, with
//!   `KEYEVENTF_EXTENDEDKEY` for the keys that live behind an E0 prefix.
//! - macOS maps by table to a `CGKeyCode`.
//!
//! Those two tables live in `selfhost-screen`, because they are platform
//! knowledge. What lives *here* is the vocabulary they map from, and one
//! property of it that matters more than the tables do.
//!
//! # The closed table, and the refusal
//!
//! [`Usage`] can only be constructed from [`KEYS`], and [`KEYS`] contains exactly
//! the usages we have a mapping for on **both** platforms. A usage outside it is
//! a typed refusal — [`KeyError::Unmappable`] — and never a silent drop. That
//! distinction is the whole reason this is a table and not a `u16` newtype with
//! a range check: a key that quietly does nothing is diagnosed as "the remote
//! machine is frozen", while a refusal that reaches the console is diagnosed in
//! one glance. The wire carries the refusal back as
//! [`Refusal::Unmappable`](crate::wire::Refusal::Unmappable).
//!
//! Two families are absent on purpose, and their absence is the mechanism above
//! doing its job rather than a gap to be filled quietly later:
//!
//! - **Media and power keys** (`0x66` Power, `0x7F`–`0x81` volume). Modern macOS
//!   does not deliver these as `CGKeyCode` keyboard events at all — they are
//!   system-defined `NX` events on a different path — so an entry for them would
//!   be a mapping we cannot honour. Refusing is honest; pretending is a bug
//!   report from a person whose volume key does nothing.
//! - **Japanese and Korean IME keys** (`0x87`–`0x91`) and `F21`–`F24`. Neither
//!   has been verified injecting on either platform from this codebase, and
//!   macOS has no `kVK_` constant above `F20`. An unverified entry in a table
//!   whose entire value is that it is trustworthy costs more than the key it
//!   would add. Adding them is a table edit here plus a table edit in each
//!   platform module, and the coverage test in `selfhost-screen` is what will
//!   force the second edit to happen.
//!
//! # Held keys
//!
//! [`HeldKeys`] is here rather than in [`crate::state`] because it is bookkeeping
//! about keys, and because the invariant it protects is a keyboard invariant: a
//! tunnelled link that drops mid-drag leaves whatever was down on the far machine
//! down forever. The agent applies [`HeldKeys::drain`] autonomously whenever the
//! channel closes, so recovery does not depend on the client that vanished
//! sending anything.

use std::fmt;

/// What kind of key a usage is, for the code that has to treat families
/// differently.
///
/// The session policy uses this to decide what may be injected while the far end
/// is in a suspended state, and the platform tables use it to decide which keys
/// need the extended-scancode flag. It is a classification of the *vocabulary*,
/// never of a particular keyboard: `Keypad` means "this usage is a keypad key",
/// not "this machine has a keypad".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyKind {
    /// A key that ordinarily produces a character: letters, digits, punctuation,
    /// space.
    Typing,
    /// One of the eight modifiers. See [`Usage::modifier`].
    Modifier,
    /// `F1`–`F20`.
    Function,
    /// Arrows, Home/End, Page Up/Down, Insert, Delete.
    Navigation,
    /// Anything on the numeric keypad, including its own Enter and separators.
    Keypad,
    /// Caps Lock, Num Lock, Scroll Lock — keys whose effect is a latch.
    Lock,
    /// Print Screen, Pause, Context Menu, Help, and the editing keys that are not
    /// navigation.
    System,
}

/// One of the four modifier roles.
///
/// Deliberately separate from [`Side`]: the difference between the left and the
/// right Alt is not cosmetic — the right one is AltGr on most non-US layouts and
/// composes characters the left one does not — so a session that collapses them
/// silently changes what the operator typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Modifier {
    /// Control.
    Control,
    /// Shift.
    Shift,
    /// Alt (Option on macOS); the right-hand one is AltGr on many layouts.
    Alt,
    /// The Windows key / Command key.
    Meta,
}

/// Which side of the keyboard a modifier sits on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Side {
    /// The left-hand modifier.
    Left,
    /// The right-hand modifier.
    Right,
}

/// One entry of the vocabulary.
///
/// Public so that `selfhost-screen`'s platform tables can iterate [`KEYS`] and
/// prove, in their own tests, that they cover every usage this crate can express.
/// A table that is merely believed to be complete is the failure mode this type
/// exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyDef {
    /// The HID usage id within page 0x07.
    pub usage: u16,
    /// The `KeyboardEvent.code` name for the same physical key. Unique across
    /// the table, which [`Usage::from_code`] relies on.
    pub code: &'static str,
    /// The family this key belongs to.
    pub kind: KeyKind,
    /// The modifier role and side, for the eight modifier usages.
    pub modifier: Option<(Modifier, Side)>,
}

/// The highest usage id defined in HID usage page 0x07.
///
/// Anything above it is not a keyboard usage at all — a peer sending one is
/// speaking a different protocol or probing, and it is worth distinguishing from
/// a real usage we simply do not map. See [`KeyError`].
pub const MAX_PAGE_USAGE: u16 = 0xE7;

/// Shorthand for a table row, so the table below reads as data rather than as a
/// hundred constructor calls.
const fn key(usage: u16, code: &'static str, kind: KeyKind) -> KeyDef {
    KeyDef { usage, code, kind, modifier: None }
}

/// Shorthand for one of the eight modifier rows.
const fn modifier(usage: u16, code: &'static str, role: Modifier, side: Side) -> KeyDef {
    KeyDef { usage, code, kind: KeyKind::Modifier, modifier: Some((role, side)) }
}

/// The whole key vocabulary, sorted by [`KeyDef::usage`].
///
/// Sorted because [`Usage::from_hid`] binary-searches it and because the index of
/// a row is the bit position [`HeldKeys`] uses; a test asserts the ordering rather
/// than trusting the author of the next edit to preserve it.
pub static KEYS: &[KeyDef] = &[
    key(0x04, "KeyA", KeyKind::Typing),
    key(0x05, "KeyB", KeyKind::Typing),
    key(0x06, "KeyC", KeyKind::Typing),
    key(0x07, "KeyD", KeyKind::Typing),
    key(0x08, "KeyE", KeyKind::Typing),
    key(0x09, "KeyF", KeyKind::Typing),
    key(0x0A, "KeyG", KeyKind::Typing),
    key(0x0B, "KeyH", KeyKind::Typing),
    key(0x0C, "KeyI", KeyKind::Typing),
    key(0x0D, "KeyJ", KeyKind::Typing),
    key(0x0E, "KeyK", KeyKind::Typing),
    key(0x0F, "KeyL", KeyKind::Typing),
    key(0x10, "KeyM", KeyKind::Typing),
    key(0x11, "KeyN", KeyKind::Typing),
    key(0x12, "KeyO", KeyKind::Typing),
    key(0x13, "KeyP", KeyKind::Typing),
    key(0x14, "KeyQ", KeyKind::Typing),
    key(0x15, "KeyR", KeyKind::Typing),
    key(0x16, "KeyS", KeyKind::Typing),
    key(0x17, "KeyT", KeyKind::Typing),
    key(0x18, "KeyU", KeyKind::Typing),
    key(0x19, "KeyV", KeyKind::Typing),
    key(0x1A, "KeyW", KeyKind::Typing),
    key(0x1B, "KeyX", KeyKind::Typing),
    key(0x1C, "KeyY", KeyKind::Typing),
    key(0x1D, "KeyZ", KeyKind::Typing),
    key(0x1E, "Digit1", KeyKind::Typing),
    key(0x1F, "Digit2", KeyKind::Typing),
    key(0x20, "Digit3", KeyKind::Typing),
    key(0x21, "Digit4", KeyKind::Typing),
    key(0x22, "Digit5", KeyKind::Typing),
    key(0x23, "Digit6", KeyKind::Typing),
    key(0x24, "Digit7", KeyKind::Typing),
    key(0x25, "Digit8", KeyKind::Typing),
    key(0x26, "Digit9", KeyKind::Typing),
    key(0x27, "Digit0", KeyKind::Typing),
    key(0x28, "Enter", KeyKind::Typing),
    key(0x29, "Escape", KeyKind::System),
    key(0x2A, "Backspace", KeyKind::Typing),
    key(0x2B, "Tab", KeyKind::Typing),
    key(0x2C, "Space", KeyKind::Typing),
    key(0x2D, "Minus", KeyKind::Typing),
    key(0x2E, "Equal", KeyKind::Typing),
    key(0x2F, "BracketLeft", KeyKind::Typing),
    key(0x30, "BracketRight", KeyKind::Typing),
    key(0x31, "Backslash", KeyKind::Typing),
    key(0x33, "Semicolon", KeyKind::Typing),
    key(0x34, "Quote", KeyKind::Typing),
    key(0x35, "Backquote", KeyKind::Typing),
    key(0x36, "Comma", KeyKind::Typing),
    key(0x37, "Period", KeyKind::Typing),
    key(0x38, "Slash", KeyKind::Typing),
    key(0x39, "CapsLock", KeyKind::Lock),
    key(0x3A, "F1", KeyKind::Function),
    key(0x3B, "F2", KeyKind::Function),
    key(0x3C, "F3", KeyKind::Function),
    key(0x3D, "F4", KeyKind::Function),
    key(0x3E, "F5", KeyKind::Function),
    key(0x3F, "F6", KeyKind::Function),
    key(0x40, "F7", KeyKind::Function),
    key(0x41, "F8", KeyKind::Function),
    key(0x42, "F9", KeyKind::Function),
    key(0x43, "F10", KeyKind::Function),
    key(0x44, "F11", KeyKind::Function),
    key(0x45, "F12", KeyKind::Function),
    key(0x46, "PrintScreen", KeyKind::System),
    key(0x47, "ScrollLock", KeyKind::Lock),
    key(0x48, "Pause", KeyKind::System),
    key(0x49, "Insert", KeyKind::Navigation),
    key(0x4A, "Home", KeyKind::Navigation),
    key(0x4B, "PageUp", KeyKind::Navigation),
    key(0x4C, "Delete", KeyKind::Navigation),
    key(0x4D, "End", KeyKind::Navigation),
    key(0x4E, "PageDown", KeyKind::Navigation),
    key(0x4F, "ArrowRight", KeyKind::Navigation),
    key(0x50, "ArrowLeft", KeyKind::Navigation),
    key(0x51, "ArrowDown", KeyKind::Navigation),
    key(0x52, "ArrowUp", KeyKind::Navigation),
    key(0x53, "NumLock", KeyKind::Lock),
    key(0x54, "NumpadDivide", KeyKind::Keypad),
    key(0x55, "NumpadMultiply", KeyKind::Keypad),
    key(0x56, "NumpadSubtract", KeyKind::Keypad),
    key(0x57, "NumpadAdd", KeyKind::Keypad),
    key(0x58, "NumpadEnter", KeyKind::Keypad),
    key(0x59, "Numpad1", KeyKind::Keypad),
    key(0x5A, "Numpad2", KeyKind::Keypad),
    key(0x5B, "Numpad3", KeyKind::Keypad),
    key(0x5C, "Numpad4", KeyKind::Keypad),
    key(0x5D, "Numpad5", KeyKind::Keypad),
    key(0x5E, "Numpad6", KeyKind::Keypad),
    key(0x5F, "Numpad7", KeyKind::Keypad),
    key(0x60, "Numpad8", KeyKind::Keypad),
    key(0x61, "Numpad9", KeyKind::Keypad),
    key(0x62, "Numpad0", KeyKind::Keypad),
    key(0x63, "NumpadDecimal", KeyKind::Keypad),
    key(0x64, "IntlBackslash", KeyKind::Typing),
    key(0x65, "ContextMenu", KeyKind::System),
    key(0x67, "NumpadEqual", KeyKind::Keypad),
    key(0x68, "F13", KeyKind::Function),
    key(0x69, "F14", KeyKind::Function),
    key(0x6A, "F15", KeyKind::Function),
    key(0x6B, "F16", KeyKind::Function),
    key(0x6C, "F17", KeyKind::Function),
    key(0x6D, "F18", KeyKind::Function),
    key(0x6E, "F19", KeyKind::Function),
    key(0x6F, "F20", KeyKind::Function),
    key(0x75, "Help", KeyKind::System),
    key(0x85, "NumpadComma", KeyKind::Keypad),
    modifier(0xE0, "ControlLeft", Modifier::Control, Side::Left),
    modifier(0xE1, "ShiftLeft", Modifier::Shift, Side::Left),
    modifier(0xE2, "AltLeft", Modifier::Alt, Side::Left),
    modifier(0xE3, "MetaLeft", Modifier::Meta, Side::Left),
    modifier(0xE4, "ControlRight", Modifier::Control, Side::Right),
    modifier(0xE5, "ShiftRight", Modifier::Shift, Side::Right),
    modifier(0xE6, "AltRight", Modifier::Alt, Side::Right),
    modifier(0xE7, "MetaRight", Modifier::Meta, Side::Right),
];

/// Why a key could not be admitted to the vocabulary.
///
/// The two failures are kept apart because they mean different things to whoever
/// reads the log. [`KeyError::OutOfPage`] is a peer that is not speaking this
/// protocol; [`KeyError::Unmappable`] is a real keyboard key that this build has
/// no mapping for, which is a gap in [`KEYS`] and is fixed by a table edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// The usage is outside HID usage page 0x07 entirely.
    OutOfPage {
        /// The value that was offered.
        usage: u16,
    },
    /// A usage inside page 0x07 that no platform in this workspace can map. See
    /// the module documentation for which families are deliberately absent.
    Unmappable {
        /// The value that was offered.
        usage: u16,
    },
    /// A `KeyboardEvent.code` name this vocabulary does not carry.
    UnknownCode,
}

impl fmt::Display for KeyError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfPage { usage } => {
                write!(out, "HID usage {usage:#06x} is not on keyboard page 0x07")
            }
            Self::Unmappable { usage } => {
                write!(out, "HID usage {usage:#06x} has no mapping on any supported platform")
            }
            Self::UnknownCode => out.write_str("no key in the vocabulary carries that code name"),
        }
    }
}

impl std::error::Error for KeyError {}

/// One physical key, identified the way the hardware identifies it.
///
/// Constructed only through [`Usage::from_hid`] or [`Usage::from_code`], so a
/// `Usage` in hand is a promise that both platform tables have a row for it. The
/// stored value is the index into [`KEYS`] rather than the HID id, because the
/// index is also the bit position in [`HeldKeys`] and keeping one representation
/// removes the possibility of the two disagreeing.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Usage(u8);

impl Usage {
    /// Admits a HID page 0x07 usage id into the vocabulary.
    ///
    /// Returns [`KeyError::OutOfPage`] for a value that is not a keyboard usage
    /// at all, and [`KeyError::Unmappable`] for one that is but that this build
    /// cannot inject. Never panics and never silently substitutes a nearby key.
    pub fn from_hid(usage: u16) -> Result<Self, KeyError> {
        if usage > MAX_PAGE_USAGE {
            return Err(KeyError::OutOfPage { usage });
        }
        match KEYS.binary_search_by(|entry| entry.usage.cmp(&usage)) {
            // The table is far shorter than `u8::MAX`, which the length test
            // asserts, so this narrowing cannot lose information.
            Ok(index) => Ok(Self(index as u8)),
            Err(_) => Err(KeyError::Unmappable { usage }),
        }
    }

    /// Admits a browser `KeyboardEvent.code` name into the vocabulary.
    ///
    /// A linear scan over a table of about a hundred rows, which costs less than
    /// maintaining a second sorted index that could fall out of step with the
    /// first. Case-sensitive: `KeyboardEvent.code` values are spelled exactly one
    /// way, and accepting variations would let two spellings mean one key.
    pub fn from_code(code: &str) -> Result<Self, KeyError> {
        KEYS.iter()
            .position(|entry| entry.code == code)
            .map(|index| Self(index as u8))
            .ok_or(KeyError::UnknownCode)
    }

    /// The row this usage names.
    pub fn definition(self) -> &'static KeyDef {
        // `self.0` can only have come from an index into `KEYS`, which is
        // `static` and therefore cannot shrink underneath us.
        &KEYS[self.0 as usize]
    }

    /// The HID page 0x07 usage id, as it travels on the wire.
    pub fn hid(self) -> u16 {
        self.definition().usage
    }

    /// The browser's `KeyboardEvent.code` name for the same physical key.
    pub fn code(self) -> &'static str {
        self.definition().code
    }

    /// The family this key belongs to.
    pub fn kind(self) -> KeyKind {
        self.definition().kind
    }

    /// The modifier role and side, for the eight modifier keys; `None` otherwise.
    pub fn modifier(self) -> Option<(Modifier, Side)> {
        self.definition().modifier
    }

    /// Every key in the vocabulary, in usage order.
    ///
    /// This is the seam the platform tables in `selfhost-screen` test against:
    /// iterate it, map each entry, and fail if any entry has no mapping. That
    /// turns "the table is complete" from a claim into an assertion.
    pub fn all() -> impl Iterator<Item = Self> {
        (0..KEYS.len()).map(|index| Self(index as u8))
    }
}

impl fmt::Debug for Usage {
    /// Prints the code name and the usage, because a bare index in a failing
    /// assertion tells the reader nothing about which key it was.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "Usage({}, {:#04x})", self.code(), self.hid())
    }
}

/// How many `u64` words [`HeldKeys`] needs to cover the vocabulary.
const HELD_WORDS: usize = 4;

/// The set of keys currently held down on the far machine.
///
/// A bitset over indices into [`KEYS`], which is why [`Usage`] stores an index:
/// tracking held keys is on the input path, once per event, and a set that
/// allocates would be a heap operation per keystroke.
///
/// # Why this exists at all
///
/// Because a remote keyboard has a failure mode a local one does not: the link
/// can vanish between a key going down and coming up. Over a tunnel that is not
/// a rare event, and the consequence is not subtle — a held Meta or a held mouse
/// button leaves the far machine unusable to the person sitting in front of it,
/// with no indication of why. So both ends carry this set: the client sends
/// `RELEASE_ALL` on blur and on reconnect, and the agent applies [`drain`] itself
/// whenever the channel closes, because recovery must not depend on a message
/// from the peer that just disappeared.
///
/// [`drain`]: HeldKeys::drain
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HeldKeys {
    words: [u64; HELD_WORDS],
}

impl HeldKeys {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Splits a usage into its word and bit position.
    fn position(key: Usage) -> (usize, u64) {
        let index = key.0 as usize;
        (index / 64, 1u64 << (index % 64))
    }

    /// Records a key as held. Idempotent: a key repeat does not double-count,
    /// which matters because the far end sends one release for many repeats.
    pub fn press(&mut self, key: Usage) {
        let (word, bit) = Self::position(key);
        self.words[word] |= bit;
    }

    /// Records a key as released. Returns whether it had been held — a release
    /// for a key that was never pressed is not an error, but it is worth not
    /// forwarding, since some platforms treat a spurious key-up as a key-down.
    pub fn release(&mut self, key: Usage) -> bool {
        let (word, bit) = Self::position(key);
        let was_held = self.words[word] & bit != 0;
        self.words[word] &= !bit;
        was_held
    }

    /// Whether a key is currently held.
    pub fn is_held(&self, key: Usage) -> bool {
        let (word, bit) = Self::position(key);
        self.words[word] & bit != 0
    }

    /// How many keys are held.
    pub fn len(&self) -> usize {
        self.words.iter().map(|word| word.count_ones() as usize).sum()
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    /// Empties the set and returns everything that was held, in usage order.
    ///
    /// The order is deliberate rather than incidental: modifiers sort last (they
    /// occupy `0xE0`–`0xE7`, the top of the page), so a caller that injects the
    /// releases in the order returned lifts the ordinary keys before the
    /// modifiers holding them. Releasing Control before `C` can be observed by
    /// the far machine as a bare `C` arriving in whatever window has focus.
    pub fn drain(&mut self) -> Vec<Usage> {
        let held = self.held().collect();
        self.words = [0; HELD_WORDS];
        held
    }

    /// Every held key, in usage order.
    pub fn held(&self) -> impl Iterator<Item = Usage> + '_ {
        Usage::all().filter(|key| self.is_held(*key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn the_table_is_sorted_and_fits_the_index_type() {
        // `Usage` stores a `u8` index and `HeldKeys` is four 64-bit words, so the
        // table has a hard ceiling. `from_hid` also binary-searches it.
        assert!(KEYS.len() <= HELD_WORDS * 64, "the held-key bitset would overflow");
        assert!(KEYS.len() <= u8::MAX as usize, "the usage index would overflow");
        for pair in KEYS.windows(2) {
            assert!(pair[0].usage < pair[1].usage, "table out of order at {:#04x}", pair[0].usage);
        }
    }

    #[test]
    fn every_code_name_is_unique() {
        // `from_code` returns the first match, so a duplicate would make one of
        // the two keys unreachable from the browser and impossible to diagnose.
        let names: HashSet<&str> = KEYS.iter().map(|entry| entry.code).collect();
        assert_eq!(names.len(), KEYS.len());
    }

    #[test]
    fn every_usage_round_trips_through_both_spellings() {
        for entry in KEYS {
            let by_usage = Usage::from_hid(entry.usage).expect("table entry must be admissible");
            assert_eq!(by_usage.hid(), entry.usage);
            assert_eq!(by_usage.code(), entry.code);

            let by_code = Usage::from_code(entry.code).expect("table entry must be admissible");
            assert_eq!(by_code, by_usage);
            assert_eq!(by_code.hid(), entry.usage);
        }
    }

    #[test]
    fn all_enumerates_the_whole_table_once() {
        let enumerated: Vec<u16> = Usage::all().map(Usage::hid).collect();
        let expected: Vec<u16> = KEYS.iter().map(|entry| entry.usage).collect();
        assert_eq!(enumerated, expected);
    }

    #[test]
    fn a_usage_above_the_page_is_refused_as_off_page() {
        for usage in [0xE8, 0x0100, 0x1234, u16::MAX] {
            assert_eq!(Usage::from_hid(usage), Err(KeyError::OutOfPage { usage }));
        }
    }

    #[test]
    fn the_deliberately_absent_families_are_refused_as_unmappable() {
        // Each of these is a real page-0x07 usage. Refusing them is the module's
        // stated policy, and a future table edit that adds one must also update
        // this test, which is the point: the addition becomes a decision.
        for usage in [
            0x00, // reserved / no event
            0x32, // NonUsHash — would collide with Backslash's code name
            0x66, // Power
            0x70, // F21
            0x73, // F24
            0x7F, // Mute
            0x80, // VolumeUp
            0x88, // KanaMode
        ] {
            assert_eq!(Usage::from_hid(usage), Err(KeyError::Unmappable { usage }), "{usage:#04x}");
        }
    }

    #[test]
    fn an_unknown_code_name_is_refused() {
        for name in ["", "keya", "KeyA ", "Power", "F24", "AudioVolumeMute", "Meta"] {
            assert_eq!(Usage::from_code(name), Err(KeyError::UnknownCode), "{name:?}");
        }
    }

    #[test]
    fn the_eight_modifiers_carry_their_role_and_side_and_nothing_else_does() {
        let expected = [
            ("ControlLeft", Modifier::Control, Side::Left),
            ("ShiftLeft", Modifier::Shift, Side::Left),
            ("AltLeft", Modifier::Alt, Side::Left),
            ("MetaLeft", Modifier::Meta, Side::Left),
            ("ControlRight", Modifier::Control, Side::Right),
            ("ShiftRight", Modifier::Shift, Side::Right),
            ("AltRight", Modifier::Alt, Side::Right),
            ("MetaRight", Modifier::Meta, Side::Right),
        ];
        for (code, role, side) in expected {
            let key = Usage::from_code(code).expect("modifier must be in the table");
            assert_eq!(key.kind(), KeyKind::Modifier);
            assert_eq!(key.modifier(), Some((role, side)));
        }

        let with_modifier = Usage::all().filter(|key| key.modifier().is_some()).count();
        assert_eq!(with_modifier, expected.len());
        // Kind and modifier must agree, or a caller that switches on one and a
        // caller that switches on the other disagree about the same key.
        for key in Usage::all() {
            assert_eq!(key.modifier().is_some(), key.kind() == KeyKind::Modifier, "{key:?}");
        }
    }

    #[test]
    fn a_keypad_digit_is_not_the_same_key_as_the_row_digit() {
        // The whole reason the wire does not speak characters: these two produce
        // the same glyph and are different keys, and applications distinguish
        // them.
        let row = Usage::from_code("Digit4").expect("in table");
        let pad = Usage::from_code("Numpad4").expect("in table");
        assert_ne!(row, pad);
        assert_eq!(row.kind(), KeyKind::Typing);
        assert_eq!(pad.kind(), KeyKind::Keypad);
    }

    #[test]
    fn held_keys_track_presses_and_releases() {
        let control = Usage::from_code("ControlLeft").expect("in table");
        let c = Usage::from_code("KeyC").expect("in table");
        let mut held = HeldKeys::new();
        assert!(held.is_empty());

        held.press(control);
        held.press(c);
        // A key repeat must not double-count, or one release would leave it held.
        held.press(c);
        assert_eq!(held.len(), 2);
        assert!(held.is_held(control) && held.is_held(c));

        assert!(held.release(c));
        assert!(!held.release(c), "a second release reports it was not held");
        assert_eq!(held.len(), 1);
        assert!(!held.is_held(c));
    }

    #[test]
    fn drain_empties_the_set_and_lifts_modifiers_last() {
        let control = Usage::from_code("ControlLeft").expect("in table");
        let shift = Usage::from_code("ShiftRight").expect("in table");
        let c = Usage::from_code("KeyC").expect("in table");
        let f1 = Usage::from_code("F1").expect("in table");

        let mut held = HeldKeys::new();
        for key in [control, c, shift, f1] {
            held.press(key);
        }

        let released = held.drain();
        assert_eq!(released, vec![c, f1, control, shift]);
        assert!(held.is_empty(), "drain must leave nothing behind");
        assert!(held.drain().is_empty(), "draining twice is harmless");
    }

    #[test]
    fn every_key_in_the_vocabulary_can_be_held_and_released() {
        // Guards the bitset arithmetic against a table that grows past a word
        // boundary: pressing the last row must not touch the first.
        let mut held = HeldKeys::new();
        for key in Usage::all() {
            held.press(key);
        }
        assert_eq!(held.len(), KEYS.len());
        for key in Usage::all() {
            assert!(held.release(key), "{key:?} was not held");
        }
        assert!(held.is_empty());
    }
}
