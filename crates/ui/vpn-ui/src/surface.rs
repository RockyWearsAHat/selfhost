//! The window's furniture, drawn: the card everything but the hero sits on,
//! the hairline between a card's rows, the mark a destination row leads with,
//! and the switch.
//!
//! A card here is a step of lightness on the ground and nothing more — no
//! shadow, no frame, one faint hairline round it so it holds its edge against
//! the light. Everything that is a control is a real rui element with a role;
//! what is drawn by hand is only ever a mark inside one.

use crate::style::{ACCENT, BORDER, INK, SLATE, SPACE_M, SPACE_S};
use rui::style::Radius;
use rui::{Children, El, Point, Size, Tone, capsule, circle, col, draw, row, solid, spacer};
use rui::{Painter, Sculpt};

/// A card: the surface tone, rounded, on a hairline.
pub fn card<S: 'static>(children: impl Children<S>) -> El<S> {
    col(children).fill(Tone::Surface).round(Radius::Panel).border(1.0, Tone::Exact(BORDER.fade(0.7)))
}

/// The hairline between two rows of one card, inset so it reads as a rule
/// within the card rather than a cut through it.
pub fn rule<S: 'static>() -> El<S> {
    row(spacer().grow().h(1.0).fill(Tone::Exact(BORDER.fade(0.8)))).pad_x(SPACE_M).h(1.0)
}

/// The mark a destination row leads with: a small lamp, lit in the state's
/// own colour when the destination can be opened and slate when it cannot.
///
/// A mark, not a status: the row it sits in carries the name, so this has no
/// role of its own and reads as decoration to anything that cannot see it.
pub fn lamp<S: 'static>(lit: bool) -> El<S> {
    let size = SPACE_S;
    draw(Size::new(size, size), move |painter, rect| {
        let c = rect.center();
        let color = if lit { crate::style::CYAN } else { SLATE };
        let fade = if painter.visual().disabled { 0.55 } else { 1.0 };
        painter.sculpt(&circle(c, 3.0), &solid(color.fade(fade)), Sculpt::Fill);
        if lit {
            painter.sculpt(&circle(c, 3.0), &solid(color), Sculpt::Glow { radius: 5.0, intensity: 0.5 });
        }
    })
    .w(size)
    .h(size)
}

/// Sculpts a two-state switch into `rect`: a pill track and a knob, in the
/// accent when on and the sunken well when off — the shape a person expects
/// from the system it runs on.
///
/// Drawn here (not wired) so the app can supply the click handler that flips
/// the real flag; `on` is captured by the caller from the view.
pub fn paint_switch(painter: &mut Painter<'_>, rect: rui::Rect, on: bool) {
    let r = rect.h / 2.0;
    let a = Point::new(rect.x + r, rect.y + r);
    let b = Point::new(rect.max_x() - r, rect.y + r);
    let track = if on { ACCENT } else { SLATE.fade(0.45) };
    painter.sculpt(&capsule(a, b, rect.h), &solid(track), Sculpt::Fill);
    let knob = if on { b } else { a };
    painter.sculpt(&circle(knob, r - 2.0), &solid(INK), Sculpt::Fill);
}
