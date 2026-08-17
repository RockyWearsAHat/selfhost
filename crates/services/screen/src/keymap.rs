//! The two platform key tables. Pure, closed, and proven total against the
//! vocabulary they map from.
//!
//! `selfhost_desk::keys` owns the wire vocabulary — USB HID usage page 0x07, the
//! physical namespace the browser's `KeyboardEvent.code` is defined in terms of.
//! What it deliberately does *not* own is what a usage becomes on a machine, and
//! it says so: "those two tables live in `selfhost-screen`, because they are
//! platform knowledge". This is that file, and it holds **both** tables rather
//! than one per platform module for three reasons that all cost real time when
//! they are ignored:
//!
//! 1. **Both tables compile everywhere.** The Windows arm of this crate cannot be
//!    built on the machine this branch is developed on, so a Windows key table
//!    living behind `#[cfg(windows)]` would be a table nobody could test until it
//!    reached the production box. Here, `cargo test` on a Mac proves the Windows
//!    mapping is total and internally consistent.
//! 2. **Totality is an assertion, not a claim.** [`selfhost_desk::keys::Usage::all`]
//!    exists so a consumer can iterate the entire vocabulary; the coverage tests
//!    below do exactly that, so adding a row to `KEYS` without adding both
//!    mappings fails the build rather than producing a key that silently does
//!    nothing on one platform.
//! 3. **The two tables disagree in interesting places**, and the disagreements are
//!    easier to describe — and to test — side by side than a file apart.
//!
//! # Windows: a virtual key *and* a scancode, and why both travel
//!
//! `SendInput` is given `wVk` and `wScan` together and **without**
//! `KEYEVENTF_SCANCODE`, so Windows acts on the virtual key and the scancode only
//! fills the `lParam` bits an application sees if it looks. Games and terminal
//! emulators do look. Sending a zero there is not wrong so much as impoverished,
//! so the real set-1 scancode travels with every row.
//!
//! `KEYEVENTF_EXTENDEDKEY` is the flag that separates the two keys that share a
//! virtual key or a scancode: the keypad Enter from the typewriter Enter, the
//! right Control from the left, the arrow cluster from the keypad digits that
//! carry the same scancodes. Getting it wrong does not fail — it types the wrong
//! key, which is the whole class of bug this table exists to close.
//!
//! Two rows are worth reading before anybody "fixes" them:
//!
//! - **`Pause` and `NumLock` share scancode `0x45`.** That is historically true:
//!   Pause is `E1 1D 45` on the wire and `SendInput` has one scancode field, which
//!   cannot express an `E1` prefix at all. The virtual keys differ
//!   (`VK_PAUSE` 0x13, `VK_NUMLOCK` 0x90) and the virtual key is what Windows acts
//!   on, so the pair works; the scancode collision is a limitation of the API's
//!   shape, stated here rather than discovered later.
//! - **`Enter` and `NumpadEnter` share `VK_RETURN`.** They are distinguished by
//!   the extended flag, exactly as a real keyboard distinguishes them, which is
//!   why the uniqueness test below is over the *pair* `(virtual key, extended)`
//!   rather than over the virtual key alone.
//!
//! # macOS: `CGKeyCode`, and four honest aliases
//!
//! macOS names keys by the position they occupy on an Apple keyboard, and an
//! Apple keyboard has no Print Screen, no Scroll Lock, no Pause, no Insert and no
//! Num Lock. What it has is F13, F14, F15, Help and Clear sitting in exactly those
//! positions, and that is what macOS reports when a PC keyboard's key in that
//! position is pressed. So the table maps them there:
//!
//! | HID key       | `CGKeyCode` | Apple's name for that position |
//! |---------------|-------------|--------------------------------|
//! | `PrintScreen` | `0x69`      | F13                            |
//! | `ScrollLock`  | `0x6B`      | F14                            |
//! | `Pause`       | `0x71`      | F15                            |
//! | `Insert`      | `0x72`      | Help                           |
//! | `NumLock`     | `0x47`      | Clear                          |
//!
//! Four of those five collide with the HID key for the Apple name itself (`F13`,
//! `F14`, `F15`, `Help`), and that collision is *correct*: they are one physical
//! key with two names, and a remote Mac cannot tell which name the operator's
//! keyboard prints on it. [`MACOS_ALIASES`] names the collisions so that a test can
//! assert exactly this set and no other — a new, unintended collision is then a
//! failing test rather than a key that types something else.
//!
//! The alternative was refusing those five keys on macOS. It was rejected because
//! refusing `Insert` on a Mac buys nothing: the physical key exists on the
//! operator's keyboard, macOS has a keycode for the position, and a refusal would
//! be this build inventing a limitation the platform does not have.

use selfhost_desk::keys::Usage;

/// What one HID usage becomes on Windows.
///
/// Carries all three fields together because they are only ever used together: a
/// virtual key without its extended flag is ambiguous, and a scancode without its
/// virtual key is not what `SendInput` is being asked to act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsKey {
    /// The Win32 virtual-key code. This is what Windows acts on, because the
    /// injector does not set `KEYEVENTF_SCANCODE`.
    pub virtual_key: u16,
    /// The set-1 scancode, carried so that an application reading `lParam` sees
    /// the physical key rather than a zero.
    pub scancode: u16,
    /// Whether the key needs `KEYEVENTF_EXTENDEDKEY` — the `E0` prefix that
    /// separates the arrow cluster from the keypad and the right modifiers from
    /// the left.
    pub extended: bool,
}

/// One row of the Windows table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsRow {
    /// The HID usage this row maps, within page 0x07.
    pub usage: u16,
    /// What it becomes.
    pub key: WindowsKey,
}

/// One row of the macOS table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacosRow {
    /// The HID usage this row maps, within page 0x07.
    pub usage: u16,
    /// The `CGKeyCode` for the physical key in that position.
    pub key_code: u16,
}

/// Shorthand so the table below reads as data.
const fn win(usage: u16, virtual_key: u16, scancode: u16, extended: bool) -> WindowsRow {
    WindowsRow { usage, key: WindowsKey { virtual_key, scancode, extended } }
}

/// Shorthand for the macOS table.
const fn mac(usage: u16, key_code: u16) -> MacosRow {
    MacosRow { usage, key_code }
}

/// The HID → Win32 table, sorted by usage.
///
/// Sorted because [`windows_key`] binary-searches it, and a test asserts the
/// ordering rather than trusting the author of the next edit.
pub static WINDOWS_KEYS: &[WindowsRow] = &[
    win(0x04, 0x41, 0x1E, false), // KeyA
    win(0x05, 0x42, 0x30, false), // KeyB
    win(0x06, 0x43, 0x2E, false), // KeyC
    win(0x07, 0x44, 0x20, false), // KeyD
    win(0x08, 0x45, 0x12, false), // KeyE
    win(0x09, 0x46, 0x21, false), // KeyF
    win(0x0A, 0x47, 0x22, false), // KeyG
    win(0x0B, 0x48, 0x23, false), // KeyH
    win(0x0C, 0x49, 0x17, false), // KeyI
    win(0x0D, 0x4A, 0x24, false), // KeyJ
    win(0x0E, 0x4B, 0x25, false), // KeyK
    win(0x0F, 0x4C, 0x26, false), // KeyL
    win(0x10, 0x4D, 0x32, false), // KeyM
    win(0x11, 0x4E, 0x31, false), // KeyN
    win(0x12, 0x4F, 0x18, false), // KeyO
    win(0x13, 0x50, 0x19, false), // KeyP
    win(0x14, 0x51, 0x10, false), // KeyQ
    win(0x15, 0x52, 0x13, false), // KeyR
    win(0x16, 0x53, 0x1F, false), // KeyS
    win(0x17, 0x54, 0x14, false), // KeyT
    win(0x18, 0x55, 0x16, false), // KeyU
    win(0x19, 0x56, 0x2F, false), // KeyV
    win(0x1A, 0x57, 0x11, false), // KeyW
    win(0x1B, 0x58, 0x2D, false), // KeyX
    win(0x1C, 0x59, 0x15, false), // KeyY
    win(0x1D, 0x5A, 0x2C, false), // KeyZ
    win(0x1E, 0x31, 0x02, false), // Digit1
    win(0x1F, 0x32, 0x03, false), // Digit2
    win(0x20, 0x33, 0x04, false), // Digit3
    win(0x21, 0x34, 0x05, false), // Digit4
    win(0x22, 0x35, 0x06, false), // Digit5
    win(0x23, 0x36, 0x07, false), // Digit6
    win(0x24, 0x37, 0x08, false), // Digit7
    win(0x25, 0x38, 0x09, false), // Digit8
    win(0x26, 0x39, 0x0A, false), // Digit9
    win(0x27, 0x30, 0x0B, false), // Digit0
    win(0x28, 0x0D, 0x1C, false), // Enter
    win(0x29, 0x1B, 0x01, false), // Escape
    win(0x2A, 0x08, 0x0E, false), // Backspace
    win(0x2B, 0x09, 0x0F, false), // Tab
    win(0x2C, 0x20, 0x39, false), // Space
    win(0x2D, 0xBD, 0x0C, false), // Minus (VK_OEM_MINUS)
    win(0x2E, 0xBB, 0x0D, false), // Equal (VK_OEM_PLUS)
    win(0x2F, 0xDB, 0x1A, false), // BracketLeft (VK_OEM_4)
    win(0x30, 0xDD, 0x1B, false), // BracketRight (VK_OEM_6)
    win(0x31, 0xDC, 0x2B, false), // Backslash (VK_OEM_5)
    win(0x33, 0xBA, 0x27, false), // Semicolon (VK_OEM_1)
    win(0x34, 0xDE, 0x28, false), // Quote (VK_OEM_7)
    win(0x35, 0xC0, 0x29, false), // Backquote (VK_OEM_3)
    win(0x36, 0xBC, 0x33, false), // Comma (VK_OEM_COMMA)
    win(0x37, 0xBE, 0x34, false), // Period (VK_OEM_PERIOD)
    win(0x38, 0xBF, 0x35, false), // Slash (VK_OEM_2)
    win(0x39, 0x14, 0x3A, false), // CapsLock
    win(0x3A, 0x70, 0x3B, false), // F1
    win(0x3B, 0x71, 0x3C, false), // F2
    win(0x3C, 0x72, 0x3D, false), // F3
    win(0x3D, 0x73, 0x3E, false), // F4
    win(0x3E, 0x74, 0x3F, false), // F5
    win(0x3F, 0x75, 0x40, false), // F6
    win(0x40, 0x76, 0x41, false), // F7
    win(0x41, 0x77, 0x42, false), // F8
    win(0x42, 0x78, 0x43, false), // F9
    win(0x43, 0x79, 0x44, false), // F10
    win(0x44, 0x7A, 0x57, false), // F11
    win(0x45, 0x7B, 0x58, false), // F12
    win(0x46, 0x2C, 0x37, true),  // PrintScreen (VK_SNAPSHOT, E0 37)
    win(0x47, 0x91, 0x46, false), // ScrollLock
    win(0x48, 0x13, 0x45, false), // Pause — see the module note on E1 1D 45
    win(0x49, 0x2D, 0x52, true),  // Insert
    win(0x4A, 0x24, 0x47, true),  // Home
    win(0x4B, 0x21, 0x49, true),  // PageUp
    win(0x4C, 0x2E, 0x53, true),  // Delete
    win(0x4D, 0x23, 0x4F, true),  // End
    win(0x4E, 0x22, 0x51, true),  // PageDown
    win(0x4F, 0x27, 0x4D, true),  // ArrowRight
    win(0x50, 0x25, 0x4B, true),  // ArrowLeft
    win(0x51, 0x28, 0x50, true),  // ArrowDown
    win(0x52, 0x26, 0x48, true),  // ArrowUp
    win(0x53, 0x90, 0x45, false), // NumLock
    win(0x54, 0x6F, 0x35, true),  // NumpadDivide (E0 35)
    win(0x55, 0x6A, 0x37, false), // NumpadMultiply
    win(0x56, 0x6D, 0x4A, false), // NumpadSubtract
    win(0x57, 0x6B, 0x4E, false), // NumpadAdd
    win(0x58, 0x0D, 0x1C, true),  // NumpadEnter — VK_RETURN, extended
    win(0x59, 0x61, 0x4F, false), // Numpad1
    win(0x5A, 0x62, 0x50, false), // Numpad2
    win(0x5B, 0x63, 0x51, false), // Numpad3
    win(0x5C, 0x64, 0x4B, false), // Numpad4
    win(0x5D, 0x65, 0x4C, false), // Numpad5
    win(0x5E, 0x66, 0x4D, false), // Numpad6
    win(0x5F, 0x67, 0x47, false), // Numpad7
    win(0x60, 0x68, 0x48, false), // Numpad8
    win(0x61, 0x69, 0x49, false), // Numpad9
    win(0x62, 0x60, 0x52, false), // Numpad0
    win(0x63, 0x6E, 0x53, false), // NumpadDecimal
    win(0x64, 0xE2, 0x56, false), // IntlBackslash (VK_OEM_102)
    win(0x65, 0x5D, 0x5D, true),  // ContextMenu (VK_APPS)
    win(0x67, 0x92, 0x59, false), // NumpadEqual (VK_OEM_NEC_EQUAL)
    win(0x68, 0x7C, 0x64, false), // F13
    win(0x69, 0x7D, 0x65, false), // F14
    win(0x6A, 0x7E, 0x66, false), // F15
    win(0x6B, 0x7F, 0x67, false), // F16
    win(0x6C, 0x80, 0x68, false), // F17
    win(0x6D, 0x81, 0x69, false), // F18
    win(0x6E, 0x82, 0x6A, false), // F19
    win(0x6F, 0x83, 0x6B, false), // F20
    win(0x75, 0x2F, 0x63, false), // Help (VK_HELP)
    win(0x85, 0x6C, 0x7E, false), // NumpadComma (VK_SEPARATOR)
    win(0xE0, 0xA2, 0x1D, false), // ControlLeft
    win(0xE1, 0xA0, 0x2A, false), // ShiftLeft
    win(0xE2, 0xA4, 0x38, false), // AltLeft
    win(0xE3, 0x5B, 0x5B, true),  // MetaLeft (VK_LWIN)
    win(0xE4, 0xA3, 0x1D, true),  // ControlRight
    win(0xE5, 0xA1, 0x36, false), // ShiftRight
    win(0xE6, 0xA5, 0x38, true),  // AltRight (AltGr)
    win(0xE7, 0x5C, 0x5C, true),  // MetaRight (VK_RWIN)
];

/// The HID → `CGKeyCode` table, sorted by usage.
pub static MACOS_KEYS: &[MacosRow] = &[
    mac(0x04, 0x00), // KeyA
    mac(0x05, 0x0B), // KeyB
    mac(0x06, 0x08), // KeyC
    mac(0x07, 0x02), // KeyD
    mac(0x08, 0x0E), // KeyE
    mac(0x09, 0x03), // KeyF
    mac(0x0A, 0x05), // KeyG
    mac(0x0B, 0x04), // KeyH
    mac(0x0C, 0x22), // KeyI
    mac(0x0D, 0x26), // KeyJ
    mac(0x0E, 0x28), // KeyK
    mac(0x0F, 0x25), // KeyL
    mac(0x10, 0x2E), // KeyM
    mac(0x11, 0x2D), // KeyN
    mac(0x12, 0x1F), // KeyO
    mac(0x13, 0x23), // KeyP
    mac(0x14, 0x0C), // KeyQ
    mac(0x15, 0x0F), // KeyR
    mac(0x16, 0x01), // KeyS
    mac(0x17, 0x11), // KeyT
    mac(0x18, 0x20), // KeyU
    mac(0x19, 0x09), // KeyV
    mac(0x1A, 0x0D), // KeyW
    mac(0x1B, 0x07), // KeyX
    mac(0x1C, 0x10), // KeyY
    mac(0x1D, 0x06), // KeyZ
    mac(0x1E, 0x12), // Digit1
    mac(0x1F, 0x13), // Digit2
    mac(0x20, 0x14), // Digit3
    mac(0x21, 0x15), // Digit4
    mac(0x22, 0x17), // Digit5 — 0x17, not 0x16; Apple's order swaps 5 and 6
    mac(0x23, 0x16), // Digit6
    mac(0x24, 0x1A), // Digit7
    mac(0x25, 0x1C), // Digit8
    mac(0x26, 0x19), // Digit9
    mac(0x27, 0x1D), // Digit0
    mac(0x28, 0x24), // Enter (Return)
    mac(0x29, 0x35), // Escape
    mac(0x2A, 0x33), // Backspace (Delete)
    mac(0x2B, 0x30), // Tab
    mac(0x2C, 0x31), // Space
    mac(0x2D, 0x1B), // Minus
    mac(0x2E, 0x18), // Equal
    mac(0x2F, 0x21), // BracketLeft
    mac(0x30, 0x1E), // BracketRight
    mac(0x31, 0x2A), // Backslash
    mac(0x33, 0x29), // Semicolon
    mac(0x34, 0x27), // Quote
    mac(0x35, 0x32), // Backquote (Grave)
    mac(0x36, 0x2B), // Comma
    mac(0x37, 0x2F), // Period
    mac(0x38, 0x2C), // Slash
    mac(0x39, 0x39), // CapsLock
    mac(0x3A, 0x7A), // F1
    mac(0x3B, 0x78), // F2
    mac(0x3C, 0x63), // F3
    mac(0x3D, 0x76), // F4
    mac(0x3E, 0x60), // F5
    mac(0x3F, 0x61), // F6
    mac(0x40, 0x62), // F7
    mac(0x41, 0x64), // F8
    mac(0x42, 0x65), // F9
    mac(0x43, 0x6D), // F10
    mac(0x44, 0x67), // F11
    mac(0x45, 0x6F), // F12
    mac(0x46, 0x69), // PrintScreen → F13's position
    mac(0x47, 0x6B), // ScrollLock → F14's position
    mac(0x48, 0x71), // Pause → F15's position
    mac(0x49, 0x72), // Insert → Help's position
    mac(0x4A, 0x73), // Home
    mac(0x4B, 0x74), // PageUp
    mac(0x4C, 0x75), // Delete (forward delete)
    mac(0x4D, 0x77), // End
    mac(0x4E, 0x79), // PageDown
    mac(0x4F, 0x7C), // ArrowRight
    mac(0x50, 0x7B), // ArrowLeft
    mac(0x51, 0x7D), // ArrowDown
    mac(0x52, 0x7E), // ArrowUp
    mac(0x53, 0x47), // NumLock → Clear's position
    mac(0x54, 0x4B), // NumpadDivide
    mac(0x55, 0x43), // NumpadMultiply
    mac(0x56, 0x4E), // NumpadSubtract
    mac(0x57, 0x45), // NumpadAdd
    mac(0x58, 0x4C), // NumpadEnter
    mac(0x59, 0x53), // Numpad1
    mac(0x5A, 0x54), // Numpad2
    mac(0x5B, 0x55), // Numpad3
    mac(0x5C, 0x56), // Numpad4
    mac(0x5D, 0x57), // Numpad5
    mac(0x5E, 0x58), // Numpad6
    mac(0x5F, 0x59), // Numpad7
    mac(0x60, 0x5B), // Numpad8
    mac(0x61, 0x5C), // Numpad9
    mac(0x62, 0x52), // Numpad0
    mac(0x63, 0x41), // NumpadDecimal
    mac(0x64, 0x0A), // IntlBackslash (ISO section)
    mac(0x65, 0x6E), // ContextMenu — the keycode macOS reports for a PC menu key
    mac(0x67, 0x51), // NumpadEqual
    mac(0x68, 0x69), // F13
    mac(0x69, 0x6B), // F14
    mac(0x6A, 0x71), // F15
    mac(0x6B, 0x6A), // F16
    mac(0x6C, 0x40), // F17
    mac(0x6D, 0x4F), // F18
    mac(0x6E, 0x50), // F19
    mac(0x6F, 0x5A), // F20
    mac(0x75, 0x72), // Help
    mac(0x85, 0x5F), // NumpadComma (JIS keypad comma)
    mac(0xE0, 0x3B), // ControlLeft
    mac(0xE1, 0x38), // ShiftLeft
    mac(0xE2, 0x3A), // AltLeft (Option)
    mac(0xE3, 0x37), // MetaLeft (Command)
    mac(0xE4, 0x3E), // ControlRight
    mac(0xE5, 0x3C), // ShiftRight
    mac(0xE6, 0x3D), // AltRight (right Option)
    mac(0xE7, 0x36), // MetaRight (right Command)
];

/// The macOS keycodes two HID usages share on purpose, as `(usage, usage)` pairs.
///
/// Each pair is one physical key with two names — a PC keyboard prints one on it
/// and an Apple keyboard prints the other — so both HID usages must reach the same
/// `CGKeyCode`. Listed rather than merely tolerated so the test below can assert
/// *exactly* this set: an accidental collision introduced by a later table edit is
/// then a failing test rather than a key that quietly types something else.
pub static MACOS_ALIASES: &[(&str, &str)] = &[
    ("PrintScreen", "F13"),
    ("ScrollLock", "F14"),
    ("Pause", "F15"),
    ("Insert", "Help"),
];

/// What a HID usage becomes on Windows, or `None` for one this build cannot map.
///
/// `None` is never dropped silently by a caller: the injectors turn it into
/// [`selfhost_desk::wire::Refusal::Unmappable`], which reaches the console. A key
/// that does nothing and says nothing is diagnosed as "the remote machine is
/// frozen", which is the failure this whole vocabulary exists to avoid.
pub fn windows_key(usage: Usage) -> Option<WindowsKey> {
    let hid = usage.hid();
    WINDOWS_KEYS
        .binary_search_by_key(&hid, |row| row.usage)
        .ok()
        .and_then(|index| WINDOWS_KEYS.get(index))
        .map(|row| row.key)
}

/// What a HID usage becomes on macOS, or `None` for one this build cannot map.
pub fn macos_key(usage: Usage) -> Option<u16> {
    let hid = usage.hid();
    MACOS_KEYS
        .binary_search_by_key(&hid, |row| row.usage)
        .ok()
        .and_then(|index| MACOS_KEYS.get(index))
        .map(|row| row.key_code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_desk::keys::KEYS;
    use std::collections::{HashMap, HashSet};

    fn usage(code: &str) -> Usage {
        Usage::from_code(code).expect("the vocabulary has this key")
    }

    #[test]
    fn both_tables_are_sorted_because_both_are_binary_searched() {
        assert!(WINDOWS_KEYS.windows(2).all(|pair| pair[0].usage < pair[1].usage));
        assert!(MACOS_KEYS.windows(2).all(|pair| pair[0].usage < pair[1].usage));
    }

    #[test]
    fn every_key_in_the_vocabulary_maps_on_both_platforms() {
        // The assertion `selfhost_desk::keys` documents `Usage::all` for. Adding a
        // row to `KEYS` without adding both mappings fails here rather than
        // producing a key that does nothing on one of the two machines.
        for key in Usage::all() {
            assert!(windows_key(key).is_some(), "{} has no Windows mapping", key.code());
            assert!(macos_key(key).is_some(), "{} has no macOS mapping", key.code());
        }
        assert_eq!(WINDOWS_KEYS.len(), KEYS.len(), "the Windows table has a row nothing maps to");
        assert_eq!(MACOS_KEYS.len(), KEYS.len(), "the macOS table has a row nothing maps to");
    }

    #[test]
    fn no_windows_virtual_key_and_extended_pair_is_used_twice() {
        // The pair rather than the virtual key alone: `Enter` and `NumpadEnter` are
        // both `VK_RETURN` and are separated by the extended flag, exactly as a
        // real keyboard separates them.
        let mut seen: HashMap<(u16, bool), u16> = HashMap::new();
        for row in WINDOWS_KEYS {
            let previous = seen.insert((row.key.virtual_key, row.key.extended), row.usage);
            assert_eq!(
                previous, None,
                "usage {:#04x} collides with {previous:?} on virtual key {:#04x}",
                row.usage, row.key.virtual_key
            );
        }
    }

    #[test]
    fn the_keypad_and_the_arrow_cluster_are_separated_by_the_extended_flag() {
        // They share scancodes, which is why the flag is the whole answer. Drop it
        // and pressing Left types a 4 whenever Num Lock is on.
        assert_eq!(
            windows_key(usage("ArrowLeft")).unwrap(),
            WindowsKey { virtual_key: 0x25, scancode: 0x4B, extended: true }
        );
        assert_eq!(
            windows_key(usage("Numpad4")).unwrap(),
            WindowsKey { virtual_key: 0x64, scancode: 0x4B, extended: false }
        );
        assert_eq!(
            windows_key(usage("NumpadEnter")).unwrap(),
            WindowsKey { virtual_key: 0x0D, scancode: 0x1C, extended: true }
        );
        assert_eq!(
            windows_key(usage("Enter")).unwrap(),
            WindowsKey { virtual_key: 0x0D, scancode: 0x1C, extended: false }
        );
    }

    #[test]
    fn every_right_hand_modifier_that_needs_the_e0_prefix_has_it() {
        // AltGr is the one that matters: a European layout composes entirely
        // different characters from the right Alt, and without the extended flag
        // Windows is handed the left one.
        for (code, extended) in [
            ("ControlLeft", false),
            ("ControlRight", true),
            ("ShiftLeft", false),
            ("ShiftRight", false),
            ("AltLeft", false),
            ("AltRight", true),
            ("MetaLeft", true),
            ("MetaRight", true),
        ] {
            assert_eq!(
                windows_key(usage(code)).unwrap().extended,
                extended,
                "{code} has the wrong extended flag"
            );
        }
    }

    #[test]
    fn the_macos_table_collides_exactly_where_the_aliases_say_it_does() {
        // An Apple keyboard has one key where a PC keyboard has two names. Any
        // collision *not* in `MACOS_ALIASES` is a table mistake, and this is where
        // it is caught.
        let mut by_code: HashMap<u16, Vec<&'static str>> = HashMap::new();
        for key in Usage::all() {
            let code = macos_key(key).expect("every usage maps");
            by_code.entry(code).or_default().push(key.code());
        }
        let found: HashSet<(&str, &str)> = by_code
            .values()
            .filter(|names| names.len() > 1)
            .map(|names| {
                assert_eq!(names.len(), 2, "three keys share one keycode: {names:?}");
                (names[0], names[1])
            })
            .collect();
        let declared: HashSet<(&str, &str)> = MACOS_ALIASES.iter().copied().collect();
        let normalise = |set: HashSet<(&str, &str)>| -> HashSet<[String; 2]> {
            set.into_iter()
                .map(|(one, two)| {
                    let mut pair = [one.to_owned(), two.to_owned()];
                    pair.sort();
                    pair
                })
                .collect()
        };
        assert_eq!(normalise(found), normalise(declared));
    }

    #[test]
    fn the_keys_an_apple_keyboard_does_not_have_land_on_the_position_they_occupy() {
        assert_eq!(macos_key(usage("PrintScreen")), macos_key(usage("F13")));
        assert_eq!(macos_key(usage("NumLock")), Some(0x47), "Clear sits where Num Lock does");
        assert_eq!(macos_key(usage("Insert")), macos_key(usage("Help")));
    }

    #[test]
    fn the_digits_follow_apples_order_rather_than_the_obvious_one() {
        // 5 and 6 are the pair that is wrong in every table copied by eye: Apple
        // numbers them 0x17 and 0x16, not 0x16 and 0x17.
        assert_eq!(macos_key(usage("Digit5")), Some(0x17));
        assert_eq!(macos_key(usage("Digit6")), Some(0x16));
    }

    #[test]
    fn a_usage_outside_the_vocabulary_cannot_even_be_asked_about() {
        // The vocabulary is closed, so an unmappable key is refused before it
        // reaches either table. This asserts the seam rather than the table.
        assert!(Usage::from_hid(0x66).is_err(), "Power is deliberately absent");
        assert!(Usage::from_hid(0x0100).is_err(), "outside page 0x07 entirely");
    }
}
