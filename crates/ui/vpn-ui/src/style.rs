//! The panel's house style: a precision instrument on a near-black ground.
//!
//! The look is a calm control panel — a high-end audio interface, a camera's
//! menu — rather than a holographic display. There is no decoration behind
//! the controls: no grid, no scanlines, no brackets. One saturated colour, the
//! signature cyan, is spent on exactly two things: the live state and the
//! primary action. Everything else is neutral ink on neutral surfaces, so that
//! when the cyan lights up it means something.
//!
//! This file owns the palette, hands it to rui once through
//! [`rui::App::theme`], owns the spacing scale every layout in the crate
//! draws from, and paints the ground.

use rui::{Appearance, Canvas, Color, CornerStyle, FontId, Palette, Theme};

// ---- the spacing scale ------------------------------------------------------

/// The one 4-based spacing scale the panel is laid out on.
///
/// Every gap and every pad in the crate names one of these rather than a
/// number of its own, so the rhythm down the window is one rhythm. Control
/// heights live beside them for the same reason.
pub mod space {
    /// The tightest gap: between a value and its unit, a word and its dot.
    pub const XS: f32 = 4.0;
    /// The gap between things that belong together: rows of one list.
    pub const S: f32 = 8.0;
    /// A control's inner padding, and the gap between one section and the
    /// next — the whole window has to fit its smallest size with every row
    /// drawn, and this is the step that does.
    pub const M: f32 = 12.0;
    /// The window's margin, and the gap between the ring and its words.
    pub const L: f32 = 16.0;
    /// The height of the one control the window is mostly for.
    pub const PRIMARY_HEIGHT: f32 = 40.0;
    /// The height of a route row: a name, a host, a chevron.
    pub const ROW_HEIGHT: f32 = 32.0;
    /// The height of the readout strip.
    pub const STRIP_HEIGHT: f32 = 40.0;
    /// The height of one labelled field row, as rui's `field_row` reserves it.
    pub const FIELD_HEIGHT: f32 = 20.0;
    /// The height of a single-line footer.
    pub const LINE_HEIGHT: f32 = 16.0;
}

// ---- the palette, as raw colours the instruments paint with ------------------

/// The ground: near black, faintly cool.
pub const VOID: Color = Color::rgb(0x0b, 0x0c, 0x10);
/// The ground at the window's foot, a shade deeper.
pub const VOID_DEEP: Color = Color::rgb(0x08, 0x09, 0x0c);
/// The signature: the one saturated colour, for the live state and the
/// primary action.
pub const CYAN: Color = Color::rgb(0x3a, 0xe1, 0xff);
/// Cyan at its brightest, for a knob or a core.
pub const CYAN_BRIGHT: Color = Color::rgb(0xc4, 0xf3, 0xff);
/// Cyan shaded down, for the bottom of the primary button.
pub const CYAN_DEEP: Color = Color::rgb(0x1c, 0xa8, 0xc8);
/// Reaching amber, while the tunnel is still dialling — with cause only.
pub const AMBER: Color = Color::rgb(0xf2, 0xb0, 0x4f);
/// Fault red, when the tunnel breaks — with cause only.
pub const RED: Color = Color::rgb(0xff, 0x5a, 0x66);
/// Cold slate, when the tunnel is down and a control is unavailable.
pub const SLATE: Color = Color::rgb(0x6a, 0x73, 0x80);
/// The ink readouts are set in.
pub const INK: Color = Color::rgb(0xec, 0xf0, 0xf3);
/// Muted ink, for labels and explanations.
pub const MUTED: Color = Color::rgb(0x8b, 0x93, 0x9e);
/// A surface lying on the ground: a list, a strip.
pub const SURFACE: Color = Color::rgb(0x14, 0x16, 0x1b);
/// The same surface a step up, for a row under the pointer.
pub const RAISED: Color = Color::rgb(0x1c, 0x1f, 0x26);
/// The hairline where two surfaces meet.
pub const BORDER: Color = Color::rgb(0x26, 0x2a, 0x32);

/// The palette handed to rui, so text, tags, and controls share the panel's
/// hues. Chrome is neutral; the accent is the only saturated entry, and `ok`
/// is the same cyan on purpose — "up" is the live state this window exists
/// to show, and it wears the signature.
pub const INSTRUMENT: Palette = Palette {
    background: VOID,
    background_deep: VOID_DEEP,
    surface: SURFACE,
    surface_deep: Color::rgb(0x11, 0x13, 0x18),
    sheen: Color::rgb(0x22, 0x26, 0x2e),
    raised: RAISED,
    sunken: Color::rgb(0x08, 0x09, 0x0c),
    border: BORDER,
    border_focus: CYAN,
    text: INK,
    text_muted: MUTED,
    text_on_accent: Color::rgb(0x05, 0x19, 0x1f),
    accent: CYAN,
    accent_deep: CYAN_DEEP,
    accent_light: CYAN_BRIGHT,
    ok: CYAN,
    ok_tint: Color::rgb(0x0b, 0x2a, 0x33),
    warn: AMBER,
    warn_tint: Color::rgb(0x2b, 0x1f, 0x0c),
    bad: RED,
    bad_tint: Color::rgb(0x2c, 0x10, 0x15),
    idle: SLATE,
    idle_tint: Color::rgb(0x15, 0x18, 0x1d),
    shadow: Color::rgba(0x00, 0x00, 0x00, 0x40),
};

/// The window's theme: always the dark instrument palette, softly rounded.
///
/// Rounded rather than chamfered: a cut corner on every card is the costume
/// this revision takes off, and rui's own note on [`rui::style::Radius::Cut`]
/// says the same.
pub fn theme(_appearance: Appearance, ui_font: FontId, mono_font: FontId) -> Theme {
    Theme::new(Appearance::Dark, ui_font, mono_font).with_palette(INSTRUMENT).with_corners(CornerStyle::Round)
}

/// The ground behind everything: the void, shading a touch deeper toward the
/// foot of the window so the surfaces lying on it read as lit from above.
/// Nothing else — no grid, no bloom, no scanlines.
pub fn ground(canvas: &mut Canvas, _theme: &Theme) {
    canvas.clear_vertical(VOID, VOID_DEEP);
}

/// The signature colour for a given state hue, for the instruments.
pub fn hue(kind: Hue) -> Color {
    match kind {
        Hue::Up => CYAN,
        Hue::Reaching => AMBER,
        Hue::Failed => RED,
        Hue::Off => SLATE,
    }
}

/// The four state hues the panel is ever drawn in.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Hue {
    /// Connected — the signature cyan.
    Up,
    /// Dialling or authenticating — amber.
    Reaching,
    /// Broken — red.
    Failed,
    /// Down — cold slate.
    Off,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_palette_is_legible() {
        // rui's own contrast gate: text ≥ 7, secondary ≥ 4.5 against the
        // ground — asserted here so a palette tweak that dims the labels
        // fails a test rather than a reviewer's eyes.
        INSTRUMENT.assert_legible("instrument");
    }
}
