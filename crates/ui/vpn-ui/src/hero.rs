//! The panel's one bold instrument: the tunnel drawn as an energy conduit
//! between two arc-reactor nodes.
//!
//! It is the whole status at a glance and the only thing that moves. Each end is
//! a reactor — concentric rings, a spinning tick collar, a radiant core — and
//! the link between them is a beam that carries luminous packets from this
//! machine to the box. Dormant, the reactors are cold and the beam is dim.
//! Reaching, packets stream amber. Up, everything runs cyan and the cores
//! breathe. Failed, the beam ruptures. Every mark is a sculpted signed-distance
//! shape lit with additive glow — not a box with flags.

use crate::style::{self, CYAN_BRIGHT};
use crate::tunnel::{Link, Phase};
use rui::{
    El, Point, Role, Size, Tone, capsule, circle, col, linear, micro, radial, ring, row, solid,
    spacer,
};
use rui::{Painter, Sculpt};
use std::f32::consts::TAU;

/// The tunnel hero for the given link, sized to fill the width it is given.
pub fn tunnel_hero<S: 'static>(link: &Link) -> El<S> {
    let motion = Motion::from(&link.phase);
    col((
        rui::draw(Size::new(300.0, 92.0), move |painter, rect| paint(painter, rect, motion))
            .h(92.0)
            .w(rui::style::Length::Fill(1.0))
            .role(Role::Image)
            .label(motion.spoken()),
        row((label("THIS MAC"), spacer().grow(), label("THE BOX"))).pad_x(24.0),
    ))
    .gap(4.0)
}

/// A node caption in the muted mono the machine text is set in.
fn label<S: 'static>(text: &str) -> El<S> {
    micro(text).color(Tone::Muted).tracking(1.6)
}

/// The link reduced to what the drawing switches on. `Copy`, so the paint
/// closure can hold it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Motion {
    /// No tunnel — cold reactors, a dim dotted beam.
    Off,
    /// Dialling/authenticating — amber packets seeking the box.
    Reaching,
    /// Up — full cyan flow, cores breathing.
    Up,
    /// Broken — a red, ruptured beam.
    Failed,
}

impl Motion {
    fn from(phase: &Phase) -> Self {
        match phase {
            Phase::Off => Motion::Off,
            Phase::Dialling | Phase::Authenticated => Motion::Reaching,
            Phase::Up => Motion::Up,
            Phase::Failed(_) => Motion::Failed,
        }
    }
    fn spoken(self) -> &'static str {
        match self {
            Motion::Off => "Tunnel down",
            Motion::Reaching => "Tunnel connecting",
            Motion::Up => "Tunnel up",
            Motion::Failed => "Tunnel failed",
        }
    }
    fn hue(self) -> style::Hue {
        match self {
            Motion::Off => style::Hue::Off,
            Motion::Reaching => style::Hue::Reaching,
            Motion::Up => style::Hue::Up,
            Motion::Failed => style::Hue::Failed,
        }
    }
    /// How energised the reactors are, 0..1 — drives glow and core brightness.
    fn charge(self) -> f32 {
        match self {
            Motion::Off => 0.08,
            Motion::Reaching => 0.75,
            Motion::Up => 1.0,
            Motion::Failed => 0.42,
        }
    }
}

/// The whole instrument, on the shared canvas.
fn paint(painter: &mut Painter<'_>, rect: rui::Rect, motion: Motion) {
    let color = style::hue(motion.hue());
    let charge = motion.charge();
    // Up breathes; everything else holds steady. Off asks for no phases at all:
    // a phase requested is a frame requested, and a dormant window draws none.
    //
    // A phase requested is also, on this renderer, a full relayout-and-paint of
    // the whole window every frame for as long as it runs (see Surface::draw
    // in rui's shell/mod.rs) — real, measured CPU. The animation cadence
    // itself is tuned down for exactly that reason (see the App builder in
    // app.rs's Panel::run: animation_interval, idle_timeout), rather than by
    // cutting the motion someone is actually looking at. A window that is not
    // visible does not pay this at all — rui skips the redraw entirely then.
    let breath = if matches!(motion, Motion::Up) { 0.7 + 0.3 * wave(painter.phase("breath", 3.4)) } else { 1.0 };
    let spin = if matches!(motion, Motion::Off) { 0.0 } else { painter.phase("spin", 9.0) };
    let flow = if matches!(motion, Motion::Up | Motion::Reaching) { painter.phase("flow", 1.6) } else { 0.0 };

    let mid = rect.y + rect.h * 0.48;
    let inset = 34.0;
    let r = 15.0;
    let left = Point::new(rect.x + inset, mid);
    let right = Point::new(rect.max_x() - inset, mid);
    let beam_a = Point::new(left.x + r + 3.0, mid);
    let beam_b = Point::new(right.x - r - 3.0, mid);

    conduit(painter, beam_a, beam_b, color, charge * breath, motion, flow);
    reactor(painter, left, r, color, charge * breath, spin, motion);
    reactor(painter, right, r, color, charge * breath, -spin, motion);
}

/// One arc-reactor: an outer halo, an outer ring, a spinning tick collar, an
/// inner ring turning the other way, and a radiant core with a specular
/// glint — all lit additively in proportion to `charge`.
fn reactor(painter: &mut Painter<'_>, c: Point, r: f32, color: rui::Color, charge: f32, spin: f32, motion: Motion) {
    // A faint outer halo of long dashes, contra-rotating slowly at half rate —
    // the "outermost gear" that reads as depth behind the main ring, at the
    // cost of no new phase (it rides the existing `spin`).
    let halo = r * 1.22;
    let halo_ticks = 8;
    for i in 0..halo_ticks {
        let ang = spin * -0.5 * TAU + (i as f32 / halo_ticks as f32) * TAU;
        let (dx, dy) = (ang.cos(), ang.sin());
        let inner = Point::new(c.x + dx * (halo - 2.0), c.y + dy * (halo - 2.0));
        let outer = Point::new(c.x + dx * (halo + 2.0), c.y + dy * (halo + 2.0));
        painter.sculpt(&capsule(inner, outer, 0.9), &solid(color.fade(0.12 + 0.28 * charge)), Sculpt::Fill);
    }

    // Outer ring — always drawn, brighter with charge.
    painter.sculpt(&ring(c, r, 1.4), &solid(color.fade(0.35 + 0.55 * charge)), Sculpt::Stroke { width: 1.4 });
    if charge > 0.2 {
        painter.sculpt(&ring(c, r, 1.4), &solid(color), Sculpt::Glow { radius: 7.0 * charge, intensity: 0.45 * charge });
    }
    // Inner ring.
    painter.sculpt(&ring(c, r * 0.60, 1.0), &solid(color.fade(0.25 + 0.5 * charge)), Sculpt::Stroke { width: 1.0 });

    // Spinning tick collar — twelve short radial bars turning with `spin`,
    // every third one brighter so the collar reads as machined, not uniform.
    let ticks = 12;
    let collar = r * 0.82;
    for i in 0..ticks {
        let ang = spin * TAU + (i as f32 / ticks as f32) * TAU;
        let (dx, dy) = (ang.cos(), ang.sin());
        let accent = i % 3 == 0;
        let len = if accent { 3.2 } else { 2.5 };
        let inner = Point::new(c.x + dx * (collar - len), c.y + dy * (collar - len));
        let outer = Point::new(c.x + dx * (collar + len), c.y + dy * (collar + len));
        let base = if matches!(motion, Motion::Off) { 0.3 } else { 0.4 + 0.6 * charge };
        let lit = if accent { (base * 1.3).min(1.0) } else { base };
        painter.sculpt(&capsule(inner, outer, if accent { 1.3 } else { 1.0 }), &solid(color.fade(lit)), Sculpt::Fill);
    }

    // The core — a radial well from white-hot to the hue, its bloom, and a
    // small off-centre specular glint so it reads as a lit sphere rather
    // than a flat disc. The glint is a fixed offset (no extra phase).
    let core_r = r * 0.34;
    let hot = CYAN_BRIGHT.mix(color, 1.0 - charge);
    painter.sculpt(&circle(c, core_r), &radial(c, 0.0, core_r, hot, color.fade(0.2)), Sculpt::Fill);
    if charge > 0.15 {
        painter.sculpt(&circle(c, core_r * 0.9), &solid(color), Sculpt::Glow { radius: 9.0 * charge, intensity: 0.75 * charge });
    }
    if charge > 0.3 {
        let glint_c = Point::new(c.x - core_r * 0.32, c.y - core_r * 0.38);
        painter.sculpt(&circle(glint_c, core_r * 0.24), &solid(CYAN_BRIGHT.fade(0.6 * charge)), Sculpt::Fill);
    }
}

/// The beam between the reactors: a base capsule with a gradient, a bloom, and
/// packets flowing across — or, when failed, a ruptured beam with a spark.
fn conduit(painter: &mut Painter<'_>, a: Point, b: Point, color: rui::Color, charge: f32, motion: Motion, flow: f32) {
    if matches!(motion, Motion::Failed) {
        let cx = (a.x + b.x) / 2.0;
        let gap = 18.0;
        let l = Point::new(cx - gap, a.y);
        let rr = Point::new(cx + gap, a.y);
        painter.sculpt(&capsule(a, l, 3.0), &linear(a, l, color.fade(0.5), color.fade(0.85)), Sculpt::Fill);
        painter.sculpt(&capsule(rr, b, 3.0), &linear(rr, b, color.fade(0.85), color.fade(0.5)), Sculpt::Fill);
        // Each half-capsule blooms on its own, so the break stays dark and the
        // rupture reads in silhouette, not only in hue.
        painter.sculpt(&capsule(a, l, 3.0), &solid(color), Sculpt::Glow { radius: 5.0, intensity: 0.3 });
        painter.sculpt(&capsule(rr, b, 3.0), &solid(color), Sculpt::Glow { radius: 5.0, intensity: 0.3 });
        // A spark at the break.
        for end in [l, rr] {
            painter.sculpt(&circle(end, 2.2), &solid(CYAN_BRIGHT), Sculpt::Fill);
            painter.sculpt(&circle(end, 2.2), &solid(color), Sculpt::Glow { radius: 6.0, intensity: 0.9 });
        }
        return;
    }

    if matches!(motion, Motion::Off) {
        // A dim dotted run: short capsule segments, unlit.
        let dim = color.fade(0.45);
        let mut x = a.x;
        while x < b.x {
            let seg = (x + 5.0).min(b.x);
            painter.sculpt(&capsule(Point::new(x, a.y), Point::new(seg, a.y), 2.0), &solid(dim), Sculpt::Fill);
            x += 11.0;
        }
        return;
    }

    // Live beam: a slim hot core line under the broad gradient bloom, so the
    // conduit reads as a taut wire of light rather than a soft bar.
    painter.sculpt(&capsule(a, b, 3.0), &linear(a, b, color.fade(0.45), color.fade(0.8)), Sculpt::Fill);
    painter.sculpt(&capsule(a, b, 3.0), &solid(color), Sculpt::Glow { radius: 7.0 * charge, intensity: 0.5 * charge });
    painter.sculpt(&capsule(a, b, 1.0), &solid(CYAN_BRIGHT.fade(0.5 * charge)), Sculpt::Fill);

    // Packets streaming from this machine to the box — four, at varying sizes
    // and phase offsets so the flow reads as irregular traffic rather than a
    // metronome, each dragging a short fading trail. All reuse the single
    // `flow` phase already paid for; no extra animated element is added.
    let span = b.x - a.x;
    let packets: [(f32, f32); 4] = [(0.00, 1.15), (0.27, 0.75), (0.52, 1.5), (0.78, 0.9)];
    for (offset, scale) in packets {
        let t = (flow + offset).fract();
        let x = a.x + span * t;
        let p = Point::new(x, a.y);
        let rad = 2.6 * scale;

        // A short trail behind the packet (toward `a`), fading with distance.
        let trail_len = 9.0 * scale;
        let tail = Point::new((x - trail_len).max(a.x), a.y);
        painter.sculpt(&capsule(tail, p, rad * 0.55), &linear(tail, p, color.with_alpha(0), color.fade(0.55)), Sculpt::Fill);

        painter.sculpt(&circle(p, rad), &solid(CYAN_BRIGHT), Sculpt::Fill);
        painter.sculpt(&circle(p, rad), &solid(color), Sculpt::Glow { radius: 7.0 * scale, intensity: 0.95 });
    }
}

/// A 0..1 breathing curve from a 0..1 looping phase.
fn wave(phase: f32) -> f32 {
    (phase * TAU).sin() * 0.5 + 0.5
}

