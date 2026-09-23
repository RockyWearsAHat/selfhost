//! The panel's small furniture: a route row's chevron, a readout cell, the
//! hairline between cells, and the two-state switch.
//!
//! Each is a few sculpted marks or a few plain elements — no frames, no glow
//! except the switch's knob when it is on. They exist so the view in `app.rs`
//! reads as a description of the window rather than of its pixels.

use crate::style::{INK, SLATE, space};
use rui::{El, Point, Size, Tone, capsule, circle, code, col, draw, heading, solid, spacer};
use rui::{Painter, Sculpt};

/// A small chevron pointing right: the affordance on a route row that says
/// "this opens somewhere". `tone` follows the row — muted when the route is
/// live, idle when it is not.
pub fn chevron<S: 'static>(tone: Tone) -> El<S> {
    const SIZE: f32 = 12.0;
    draw(Size::new(SIZE, SIZE), move |painter, rect| {
        let color = painter.color(tone);
        let c = rect.center();
        let arm = 3.2;
        let tip = Point::new(c.x + arm * 0.5, c.y);
        let upper = Point::new(c.x - arm * 0.5, c.y - arm);
        let lower = Point::new(c.x - arm * 0.5, c.y + arm);
        painter.sculpt(&capsule(upper, tip, 0.8), &solid(color), Sculpt::Fill);
        painter.sculpt(&capsule(tip, lower, 0.8), &solid(color), Sculpt::Fill);
    })
    .w(SIZE)
    .h(SIZE)
}

/// One cell of the readout strip: a small label over a value.
///
/// The value is set in the fixed-width face on purpose — these are the
/// readouts that update in place, and fixed-width digits are what stop
/// "1.2 MB" becoming "1.3 MB" with a sideways shuffle.
pub fn readout<S: 'static>(label: &str, value: impl Into<String>) -> El<S> {
    col((heading(label), code(value).color(Tone::Text)))
        .gap(space::XS)
        .center()
        .grow()
}

/// A one-unit vertical hairline, for the seam between two readout cells.
pub fn seam<S: 'static>() -> El<S> {
    spacer().w(1.0).fill(Tone::Border).role(rui::Role::Separator)
}

/// Sculpts a two-state switch into `rect`: a pill track and a knob.
///
/// Drawn here (not wired) so the app can supply the click handler that flips
/// the real flag; `on` is captured by the caller from the view. Neutral in
/// both positions — the accent is spent on the live state and the primary
/// action, and a rotation policy is neither. On is the knob at the far end
/// on a lit track; off is the knob at the near end on a dim one.
pub fn paint_switch(painter: &mut Painter<'_>, rect: rui::Rect, on: bool) {
    let r = rect.h / 2.0;
    let a = Point::new(rect.x + r, rect.y + r);
    let b = Point::new(rect.max_x() - r, rect.y + r);
    let track = SLATE.fade(if on { 0.95 } else { 0.35 });
    painter.sculpt(&capsule(a, b, rect.h - 1.0), &solid(track), Sculpt::Fill);
    let knob = if on { b } else { a };
    let knob_color = if on { INK } else { INK.fade(0.55) };
    painter.sculpt(&circle(knob, r - 2.5), &solid(knob_color), Sculpt::Fill);
}
