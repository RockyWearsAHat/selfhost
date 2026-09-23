//! The window's house style: a quiet, native-feeling dark palette, the one
//! spacing scale every gap on screen is drawn from, and the ground everything
//! sits on.
//!
//! The look is editorial rather than instrumental. Chrome is neutral navy and
//! lifts by lightness, not shadow; there is one accent (a calm blue, for the
//! one action the window is mostly for) and four state hues that belong to
//! the tunnel alone — slate when it is down, amber while it is reaching, cyan
//! once it is up, red when it has broken. The state hue is never the accent:
//! a Connect button is blue in every state, and a status is never dressed as a
//! button. This file owns the palette, hands it to rui once through
//! [`rui::App::theme`], and paints the ground: a plain vertical wash from deep
//! navy to near-black, with nothing drawn on it. The light itself belongs to
//! [`crate::hero`], because its colour is the tunnel's state.

use rui::{Appearance, Canvas, Color, CornerStyle, FontId, Palette, Theme};

// ---- the spacing scale ------------------------------------------------------
//
// Every pad and gap in the window is one of these five, so two blocks can
// never be a unit apart by accident. Four-based, like the toolkit's own.

/// Hairline company: the gap between a label and the value it names.
pub const SPACE_XS: f32 = 4.0;
/// Within a group: between rows of one card, between a control and its note.
pub const SPACE_S: f32 = 8.0;
/// A card's own inset, and the gap between a glyph and its label.
pub const SPACE_M: f32 = 12.0;
/// Between blocks that belong together: a card and the line under it.
pub const SPACE_L: f32 = 16.0;
/// The window's side margin, and the breath between the hero and the rest.
pub const SPACE_XL: f32 = 20.0;

// ---- the palette, as raw colours the drawings paint with --------------------

/// The ground at the top of the window: deep navy.
pub const NIGHT: Color = Color::rgb(0x0b, 0x10, 0x1f);
/// The ground at the foot of the window: nearly black.
pub const ABYSS: Color = Color::rgb(0x04, 0x06, 0x0c);
/// A card's face, one step lighter than the ground — that is its whole
/// elevation.
pub const SURFACE: Color = Color::rgb(0x12, 0x19, 0x2b);
/// The lower edge of a card's face.
pub const SURFACE_DEEP: Color = Color::rgb(0x0f, 0x15, 0x26);
/// A control's face, a step above a card.
pub const RAISED: Color = Color::rgb(0x1b, 0x24, 0x3a);
/// A well: the inside of a field, the track of a switch that is off.
pub const SUNKEN: Color = Color::rgb(0x08, 0x0c, 0x16);
/// The one hairline colour, used sparingly.
pub const BORDER: Color = Color::rgb(0x20, 0x2a, 0x42);
/// The ink readings are set in.
pub const INK: Color = Color::rgb(0xec, 0xf0, 0xf8);
/// Muted ink, for labels, hosts, and explanations.
pub const MUTED: Color = Color::rgb(0x8b, 0x96, 0xac);
/// The accent: a calm blue, for the one action the window is mostly for.
pub const ACCENT: Color = Color::rgb(0x5d, 0x8c, 0xf5);
/// The accent's deep end, for a pressed or tinted control.
pub const ACCENT_DEEP: Color = Color::rgb(0x2f, 0x55, 0xb0);
/// The accent's light end, for a focus ring.
pub const ACCENT_LIGHT: Color = Color::rgb(0xb9, 0xcd, 0xff);
/// Up: the tunnel's own cyan.
pub const CYAN: Color = Color::rgb(0x3c, 0xd9, 0xe6);
/// Reaching: amber, while the tunnel is still dialling.
pub const AMBER: Color = Color::rgb(0xf6, 0xb1, 0x4a);
/// Failed: red, only ever with a reason beside it.
pub const RED: Color = Color::rgb(0xf2, 0x5f, 0x6b);
/// Off: cold slate, when there is no tunnel.
pub const SLATE: Color = Color::rgb(0x6b, 0x78, 0x90);

/// The palette handed to rui, so text, buttons, tags, and lamps share the
/// window's hues.
pub const NATIVE: Palette = Palette {
    background: NIGHT,
    background_deep: ABYSS,
    surface: SURFACE,
    surface_deep: SURFACE_DEEP,
    sheen: Color::rgb(0x24, 0x2f, 0x4a),
    raised: RAISED,
    sunken: SUNKEN,
    border: BORDER,
    border_focus: ACCENT_LIGHT,
    text: INK,
    text_muted: MUTED,
    text_on_accent: Color::rgb(0xf6, 0xf9, 0xff),
    accent: ACCENT,
    accent_deep: ACCENT_DEEP,
    accent_light: ACCENT_LIGHT,
    ok: CYAN,
    ok_tint: Color::rgb(0x0d, 0x2a, 0x33),
    warn: AMBER,
    warn_tint: Color::rgb(0x33, 0x24, 0x0c),
    bad: RED,
    bad_tint: Color::rgb(0x36, 0x12, 0x18),
    idle: SLATE,
    idle_tint: Color::rgb(0x15, 0x1b, 0x2a),
    shadow: Color::rgba(0x00, 0x00, 0x00, 0x40),
};

/// The window's theme: always the dark native palette, rounded corners.
pub fn theme(_appearance: Appearance, ui_font: FontId, mono_font: FontId) -> Theme {
    Theme::new(Appearance::Dark, ui_font, mono_font).with_palette(NATIVE).with_corners(CornerStyle::Round)
}

/// The ground behind everything: a plain wash from navy to near-black.
///
/// Nothing else is drawn here on purpose. The one light in the window is the
/// hero's, and its colour is the tunnel's state — which the ground, painted
/// before the view is described, cannot know.
pub fn ground(canvas: &mut Canvas, _theme: &Theme) {
    canvas.clear_vertical(NIGHT, ABYSS);
}

/// The four state hues the window is ever lit in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Hue {
    /// Connected — cyan.
    Up,
    /// Dialling or authenticating — amber.
    Reaching,
    /// Broken — red.
    Failed,
    /// Down — slate.
    Off,
}

/// The colour of a state hue.
pub fn hue(kind: Hue) -> Color {
    match kind {
        Hue::Up => CYAN,
        Hue::Reaching => AMBER,
        Hue::Failed => RED,
        Hue::Off => SLATE,
    }
}
