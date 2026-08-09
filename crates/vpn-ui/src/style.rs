//! The panel's holographic house style: a cyan-on-void HUD, and the atmosphere
//! behind it.
//!
//! The look is sculpted, not assembled from box-flags — the ground and every
//! instrument are signed-distance shapes painted with fields and lit with
//! additive glow (see rui's `sdf` module and `SHAPING.md`). This file owns the
//! palette, hands it to rui once through [`rui::App::theme`], and paints the
//! ground: a deep void, a radial reactor-glow behind the hero, a perspective
//! grid receding to a horizon, and fine scanlines.

use rui::{Appearance, Canvas, Color, CornerStyle, FontId, Palette, Point, Theme};
use rui::{Sculpt, circle, radial};

// ---- the holographic palette, as raw colours the sculptors paint with -------

/// The void the HUD floats on.
pub const VOID: Color = Color::rgb(0x04, 0x07, 0x0d);
/// The deeper void at the window's foot.
pub const VOID_DEEP: Color = Color::rgb(0x01, 0x02, 0x05);
/// The signature: arc-reactor cyan.
pub const CYAN: Color = Color::rgb(0x3a, 0xe1, 0xff);
/// Cyan at its brightest, for cores and surges.
pub const CYAN_BRIGHT: Color = Color::rgb(0xd4, 0xf7, 0xff);
/// Cyan gone deep, for the cold end of a conduit gradient.
pub const CYAN_DEEP: Color = Color::rgb(0x0b, 0x4f, 0x66);
/// Reaching amber, while the tunnel is still dialling.
pub const AMBER: Color = Color::rgb(0xff, 0xb4, 0x54);
/// Fault red, when the tunnel breaks.
pub const RED: Color = Color::rgb(0xff, 0x4d, 0x5a);
/// Cold slate, when the tunnel is down.
pub const SLATE: Color = Color::rgb(0x54, 0x64, 0x72);
/// The ink readouts are set in.
pub const INK: Color = Color::rgb(0xe3, 0xf1, 0xf7);
/// Muted ink, for labels.
pub const MUTED: Color = Color::rgb(0x6d, 0x84, 0x91);
/// The translucent fill of a glass panel.
pub const GLASS: Color = Color::rgba(0x0c, 0x18, 0x22, 0xb0);
/// The edge-light run along a glass panel's frame.
pub const EDGE: Color = Color::rgb(0x49, 0xc7, 0xe6);

/// The palette handed to rui, so text, tags, and lamps share the HUD's hues.
pub const HUD: Palette = Palette {
    background: VOID,
    background_deep: VOID_DEEP,
    surface: Color::rgb(0x0a, 0x14, 0x1d),
    surface_deep: Color::rgb(0x07, 0x0f, 0x16),
    sheen: Color::rgb(0x14, 0x2a, 0x38),
    raised: Color::rgb(0x0f, 0x1e, 0x29),
    sunken: Color::rgb(0x03, 0x08, 0x0d),
    border: Color::rgb(0x1c, 0x3a, 0x49),
    border_focus: CYAN,
    text: INK,
    text_muted: MUTED,
    text_on_accent: Color::rgb(0x03, 0x10, 0x16),
    accent: CYAN,
    accent_deep: CYAN_DEEP,
    accent_light: CYAN_BRIGHT,
    ok: CYAN,
    ok_tint: Color::rgb(0x06, 0x1c, 0x25),
    warn: AMBER,
    warn_tint: Color::rgb(0x24, 0x18, 0x08),
    bad: RED,
    bad_tint: Color::rgb(0x26, 0x0c, 0x11),
    idle: SLATE,
    idle_tint: Color::rgb(0x0b, 0x12, 0x18),
    shadow: Color::rgba(0x00, 0x00, 0x00, 0x40),
};

/// The window's theme: always the dark HUD palette, chamfered corners.
pub fn theme(_appearance: Appearance, ui_font: FontId, mono_font: FontId) -> Theme {
    Theme::new(Appearance::Dark, ui_font, mono_font).with_palette(HUD).with_corners(CornerStyle::Cut)
}

/// The atmosphere behind everything: void wash, a reactor-glow bloom high on the
/// window behind the hero, a perspective grid receding to a horizon, scanlines.
pub fn ground(canvas: &mut Canvas, _theme: &Theme) {
    canvas.clear_vertical(VOID, VOID_DEEP);
    let bounds = canvas.bounds();

    // The reactor-glow: a broad radial bloom seated where the hero sits, so the
    // whole panel reads as lit from its own core.
    let glow_center = Point::new(bounds.center().x, bounds.y + bounds.h * 0.28);
    let bloom = circle(glow_center, bounds.w * 0.62);
    canvas.sculpt(
        &bloom,
        &radial(glow_center, 0.0, bounds.w * 0.62, CYAN.fade(0.16), CYAN.with_alpha(0)),
        Sculpt::Fill,
    );

    // A perspective grid: horizontal rules drawing closer toward a high horizon,
    // and verticals fanning from a vanishing point — faint, cold, receding.
    let horizon = bounds.y + bounds.h * 0.16;
    let grid = CYAN.fade(0.05);
    let vanish = Point::new(bounds.center().x, horizon);
    let floor = bounds.max_y();
    let mut depth = 0.06_f32;
    while depth < 1.0 {
        let y = horizon + (floor - horizon) * depth * depth;
        canvas.line(Point::new(bounds.x, y), Point::new(bounds.max_x(), y), 1.0, grid);
        depth += 0.10;
    }
    for i in -6..=6 {
        let x = bounds.center().x + (bounds.w * 0.5) * (i as f32 / 6.0);
        canvas.line(vanish, Point::new(x, floor), 1.0, grid.fade(0.6));
    }

    // Scanlines: a fine dark comb over the whole ground, the CRT tell.
    let scan = VOID_DEEP.with_alpha(0x22);
    let mut y = bounds.y;
    while y < bounds.max_y() {
        canvas.line(Point::new(bounds.x, y), Point::new(bounds.max_x(), y), 1.0, scan);
        y += 3.0;
    }
}

/// The signature colour for a given state hue, for the sculptors.
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
