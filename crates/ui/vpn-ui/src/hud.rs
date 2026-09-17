//! Reusable HUD furniture, sculpted: the glass panel, its corner brackets and
//! edge-light, the masthead's mini-reactor mark, and the small marks the
//! window's lists are built from — a route's reactor tick, its chevron, a
//! readout cell, the hairline seam between two cells, the two-state switch,
//! and the state word lit like a reactor core.
//!
//! A panel here is a translucent slab you can see the grid through, framed by
//! bright brackets at its corners and a sheen along its top — the frame is
//! drawn as sculpted shapes over the slab, so it costs the contents nothing.

use crate::style::{CYAN, CYAN_BRIGHT, EDGE, GLASS, MUTED, SLATE, space};
use rui::style::Radius;
use rui::{
    Align, Anchor, Children, El, Point, Role, Size, Tone, capsule, circle, code, col, draw, figure, heading, ring,
    row, solid, spacer,
};
use rui::{Painter, Sculpt};

/// A glass HUD panel: a translucent chamfered slab with bracketed corners and a
/// top sheen, holding `children`, framed in the HUD's own cyan edge-light.
pub fn glass_panel<S: 'static>(children: impl Children<S>) -> El<S> {
    glass_panel_lit(children, EDGE)
}

/// A glass panel whose edge-light is `light` — the hero's panel, which takes
/// the tunnel's hue so the frame around the instrument is lit by it.
pub fn glass_panel_lit<S: 'static>(children: impl Children<S>, light: rui::Color) -> El<S> {
    col(children)
        .pad(space::M)
        .fill(Tone::Exact(GLASS))
        .round(Radius::Cut(9.0))
        .border(1.0, Tone::Exact(light.fade(0.25)))
        .add(frame(light))
}

/// The sculpted frame drawn over a panel: a top sheen and four corner brackets.
fn frame<S: 'static>(light: rui::Color) -> El<S> {
    draw(Size::new(0.0, 0.0), move |painter, rect| {
        // A sheen just inside the top edge — the surface lit from above.
        let sheen = capsule(
            Point::new(rect.x + 8.0, rect.y + 1.5),
            Point::new(rect.max_x() - 8.0, rect.y + 1.5),
            1.0,
        );
        painter.sculpt(&sheen, &solid(CYAN_BRIGHT.mix(light, 0.5).fade(0.18)), Sculpt::Fill);

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
            let h = capsule(Point::new(cx, cy), Point::new(cx + sx * len, cy), 1.2);
            let v = capsule(Point::new(cx, cy), Point::new(cx, cy + sy * len), 1.2);
            painter.sculpt(&h, &solid(light), Sculpt::Fill);
            painter.sculpt(&v, &solid(light), Sculpt::Fill);
            painter.sculpt(&h, &solid(light), Sculpt::Glow { radius: 4.0, intensity: 0.32 });
            painter.sculpt(&v, &solid(light), Sculpt::Glow { radius: 4.0, intensity: 0.32 });
        }
    })
    .layer(Anchor::Over)
}

/// A glass row: the same slab and edge-light as a panel, at a row's height and
/// a tighter chamfer, for a list whose rows are each a control.
pub fn glass_row<S: 'static>(children: impl Children<S>) -> El<S> {
    row(children)
        .h(space::ROW_HEIGHT)
        .pad_x(space::M)
        .gap(space::S)
        .align(Align::Center)
        .fill(Tone::Exact(GLASS))
        .round(Radius::Cut(6.0))
        .border(1.0, Tone::Exact(EDGE.fade(0.22)))
        .hover_fill(Tone::Raised)
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

/// How far the ink and marks of a route that cannot be opened are faded — the
/// same reduction rui applies to a disabled control's own ink, so the tick,
/// the words and the chevron all dim as one thing.
const DIMMED: f32 = 0.5;

/// `color` as a tone, faded by [`DIMMED`] unless `lit`.
pub fn ink(color: rui::Color, lit: bool) -> Tone {
    Tone::Exact(if lit { color } else { color.fade(DIMMED) })
}

/// A route row's tick: a miniature reactor — a ring with four collar ticks and
/// a core — lit in the tunnel's cyan when the route can be opened, cold slate
/// when it cannot. A mark, not a status of its own: the row carries the name
/// and the disabled flag, so it has no role.
pub fn reactor_tick<S: 'static>(lit: bool) -> El<S> {
    const SIZE: f32 = 14.0;
    draw(Size::new(SIZE, SIZE), move |painter, rect| {
        let c = rect.center();
        let r = SIZE * 0.36;
        let color = if lit { CYAN } else { SLATE.fade(0.7) };
        painter.sculpt(&ring(c, r, 1.0), &solid(color.fade(0.85)), Sculpt::Stroke { width: 1.0 });
        for i in 0..4 {
            let ang = (i as f32) * std::f32::consts::FRAC_PI_2 + std::f32::consts::FRAC_PI_4;
            let (dx, dy) = (ang.cos(), ang.sin());
            let a = Point::new(c.x + dx * (r + 1.0), c.y + dy * (r + 1.0));
            let b = Point::new(c.x + dx * (r + 2.6), c.y + dy * (r + 2.6));
            painter.sculpt(&capsule(a, b, 0.7), &solid(color.fade(0.7)), Sculpt::Fill);
        }
        if lit {
            painter.sculpt(&circle(c, 1.7), &solid(CYAN_BRIGHT), Sculpt::Fill);
            painter.sculpt(&circle(c, 1.7), &solid(CYAN), Sculpt::Glow { radius: 5.0, intensity: 0.7 });
            painter.sculpt(&ring(c, r, 1.0), &solid(CYAN), Sculpt::Glow { radius: 3.0, intensity: 0.3 });
        } else {
            painter.sculpt(&circle(c, 1.5), &solid(color), Sculpt::Fill);
        }
    })
    .w(SIZE)
    .h(SIZE)
}

/// A small chevron pointing right: the affordance on a route row that says
/// "this opens somewhere". Dimmed with the rest of the row when it does not.
pub fn chevron<S: 'static>(lit: bool) -> El<S> {
    const SIZE: f32 = 12.0;
    draw(Size::new(SIZE, SIZE), move |painter, rect| {
        let color = if lit { EDGE } else { MUTED.fade(DIMMED) };
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
    col((heading(label).tracking(1.4), code(value).color(Tone::Text)))
        .gap(space::XS)
        .center()
        .grow()
}

/// A one-unit vertical hairline in edge-light, for the seam between two
/// readout cells.
pub fn seam<S: 'static>() -> El<S> {
    spacer().w(1.0).fill(Tone::Exact(EDGE.fade(0.22))).role(Role::Separator)
}

/// The size the state word is set at.
pub const WORD_SIZE: f32 = 21.0;

/// The state word, set large in the state's own hue. Plain, crisp text — no
/// glow layer behind it. A word this size in a solid, saturated colour
/// already reads as lit against the panel's dark glass; a glow added on top
/// only softened the letterforms. `lit` is kept so callers can still ask for
/// the dim ink Off uses instead of the hue.
pub fn state_word<S: 'static>(word: &'static str, color: rui::Color, lit: bool) -> El<S> {
    let _ = lit;
    row(figure(word).text_size(WORD_SIZE).bold().tracking(0.6).color(Tone::Exact(color)))
}

/// Sculpts a two-state switch into `rect`: a pill track and a glowing knob.
///
/// Drawn here (not wired) so the app can supply the click handler that flips the
/// real flag; `on` is captured by the caller from the view.
pub fn paint_switch(painter: &mut Painter<'_>, rect: rui::Rect, on: bool) {
    let r = rect.h / 2.0;
    let a = Point::new(rect.x + r, rect.y + r);
    let b = Point::new(rect.max_x() - r, rect.y + r);
    let track_color = if on { CYAN } else { SLATE };
    painter.sculpt(&capsule(a, b, rect.h - 1.0), &solid(track_color.fade(0.22)), Sculpt::Fill);
    painter.sculpt(&capsule(a, b, rect.h - 1.0), &solid(track_color.fade(0.9)), Sculpt::Stroke { width: 1.0 });
    let knob = if on { b } else { a };
    painter.sculpt(&circle(knob, r - 2.5), &solid(CYAN_BRIGHT), Sculpt::Fill);
    if on {
        painter.sculpt(&circle(knob, r - 2.5), &solid(CYAN), Sculpt::Glow { radius: 6.0, intensity: 0.8 });
    }
}
