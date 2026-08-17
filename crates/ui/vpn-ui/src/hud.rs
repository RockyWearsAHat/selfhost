//! Reusable HUD furniture, sculpted: the glass panel, its corner brackets and
//! edge-light, and the masthead's mini-reactor mark.
//!
//! A panel here is a translucent slab you can see the grid through, framed by
//! bright brackets at its corners and a sheen along its top — the frame is
//! drawn as sculpted shapes over the slab, so it costs the contents nothing.

use crate::style::{CYAN, CYAN_BRIGHT, EDGE, GLASS};
use rui::style::Radius;
use rui::{Anchor, Children, El, Point, Role, Size, Tone, capsule, circle, col, draw, ring, solid};
use rui::{Painter, Sculpt};

/// A glass HUD panel: a translucent chamfered slab with bracketed corners and a
/// top sheen, holding `children`.
pub fn glass_panel<S: 'static>(children: impl Children<S>) -> El<S> {
    col(children)
        .pad(13.0)
        .fill(Tone::Exact(GLASS))
        .round(Radius::Cut(9.0))
        .border(1.0, Tone::Exact(EDGE.fade(0.25)))
        .add(frame())
}

/// The sculpted frame drawn over a panel: a top sheen and four corner brackets.
fn frame<S: 'static>() -> El<S> {
    draw(Size::new(0.0, 0.0), |painter, rect| {
        // A sheen just inside the top edge — the surface lit from above.
        let sheen = capsule(
            Point::new(rect.x + 8.0, rect.y + 1.5),
            Point::new(rect.max_x() - 8.0, rect.y + 1.5),
            1.0,
        );
        painter.sculpt(&sheen, &solid(CYAN_BRIGHT.fade(0.18)), Sculpt::Fill);

        // Corner brackets: a short L in bright edge-light at each corner.
        let len = 13.0;
        let inset = 3.0;
        let corners = [
            (rect.x + inset, rect.y + inset, 1.0, 1.0),
            (rect.max_x() - inset, rect.y + inset, -1.0, 1.0),
            (rect.x + inset, rect.max_y() - inset, 1.0, -1.0),
            (rect.max_x() - inset, rect.max_y() - inset, -1.0, -1.0),
        ];
        for (cx, cy, sx, sy) in corners {
            let h = capsule(Point::new(cx, cy), Point::new(cx + sx * len, cy), 1.3);
            let v = capsule(Point::new(cx, cy), Point::new(cx, cy + sy * len), 1.3);
            painter.sculpt(&h, &solid(EDGE), Sculpt::Fill);
            painter.sculpt(&v, &solid(EDGE), Sculpt::Fill);
            painter.sculpt(&h, &solid(CYAN), Sculpt::Glow { radius: 4.0, intensity: 0.35 });
            painter.sculpt(&v, &solid(CYAN), Sculpt::Glow { radius: 4.0, intensity: 0.35 });
        }
    })
    .layer(Anchor::Over)
}

/// The masthead mark: a small arc-reactor, so the app wears the instrument it
/// manages.
pub fn mark<S: 'static>() -> El<S> {
    draw(Size::new(22.0, 22.0), |painter, rect| {
        let c = Point::new(rect.x + rect.w / 2.0, rect.y + rect.h / 2.0);
        let r = rect.w * 0.42;
        painter.sculpt(&ring(c, r, 1.4), &solid(CYAN.fade(0.8)), Sculpt::Stroke { width: 1.4 });
        painter.sculpt(&ring(c, r, 1.4), &solid(CYAN), Sculpt::Glow { radius: 4.0, intensity: 0.4 });
        painter.sculpt(&ring(c, r * 0.55, 1.0), &solid(CYAN.fade(0.6)), Sculpt::Stroke { width: 1.0 });
        painter.sculpt(&circle(c, r * 0.28), &solid(CYAN_BRIGHT), Sculpt::Fill);
        painter.sculpt(&circle(c, r * 0.28), &solid(CYAN), Sculpt::Glow { radius: 5.0, intensity: 0.7 });
    })
    .w(22.0)
    .h(22.0)
    .role(Role::Image)
    .label("SelfHost VPN")
}

/// Sculpts a two-state switch into `rect`: a pill track and a glowing knob.
///
/// Drawn here (not wired) so the app can supply the click handler that flips the
/// real flag; `on` is captured by the caller from the view.
pub fn paint_switch(painter: &mut Painter<'_>, rect: rui::Rect, on: bool) {
    let r = rect.h / 2.0;
    let a = Point::new(rect.x + r, rect.y + r);
    let b = Point::new(rect.max_x() - r, rect.y + r);
    let track_color = if on { CYAN } else { crate::style::SLATE };
    painter.sculpt(&capsule(a, b, rect.h - 1.0), &solid(track_color.fade(0.22)), Sculpt::Fill);
    painter.sculpt(&capsule(a, b, rect.h - 1.0), &solid(track_color.fade(0.9)), Sculpt::Stroke { width: 1.0 });
    let knob = if on { b } else { a };
    painter.sculpt(&circle(knob, r - 2.5), &solid(CYAN_BRIGHT), Sculpt::Fill);
    if on {
        painter.sculpt(&circle(knob, r - 2.5), &solid(CYAN), Sculpt::Glow { radius: 6.0, intensity: 0.8 });
    }
}
