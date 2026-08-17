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
            Motion::Off => 0.12,
            Motion::Reaching => 0.7,
            Motion::Up => 1.0,
            Motion::Failed => 0.35,
        }
    }
}

/// The whole instrument, on the shared canvas.
fn paint(painter: &mut Painter<'_>, rect: rui::Rect, motion: Motion) {
    let color = style::hue(motion.hue());
    let charge = motion.charge();
    // Up breathes; everything else holds steady. Off asks for no phases at all:
    // a phase requested is a frame requested, and a dormant window draws none.
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

/// One arc-reactor: outer ring, inner ring, a spinning tick collar, a radiant
/// core, all lit additively in proportion to `charge`.
fn reactor(painter: &mut Painter<'_>, c: Point, r: f32, color: rui::Color, charge: f32, spin: f32, motion: Motion) {
    // Outer ring — always drawn, brighter with charge.
    painter.sculpt(&ring(c, r, 1.4), &solid(color.fade(0.35 + 0.55 * charge)), Sculpt::Stroke { width: 1.4 });
    if charge > 0.2 {
        painter.sculpt(&ring(c, r, 1.4), &solid(color), Sculpt::Glow { radius: 7.0 * charge, intensity: 0.45 * charge });
    }
    // Inner ring.
    painter.sculpt(&ring(c, r * 0.60, 1.0), &solid(color.fade(0.25 + 0.5 * charge)), Sculpt::Stroke { width: 1.0 });

    // Spinning tick collar — twelve short radial bars turning with `spin`.
    let ticks = 12;
    let collar = r * 0.82;
    for i in 0..ticks {
        let ang = spin * TAU + (i as f32 / ticks as f32) * TAU;
        let (dx, dy) = (ang.cos(), ang.sin());
        let inner = Point::new(c.x + dx * (collar - 2.5), c.y + dy * (collar - 2.5));
        let outer = Point::new(c.x + dx * (collar + 2.5), c.y + dy * (collar + 2.5));
        let lit = if matches!(motion, Motion::Off) { 0.3 } else { 0.4 + 0.6 * charge };
        painter.sculpt(&capsule(inner, outer, 1.1), &solid(color.fade(lit)), Sculpt::Fill);
    }

    // The core — a radial well from white-hot to the hue, and its bloom.
    let core_r = r * 0.34;
    let hot = CYAN_BRIGHT.mix(color, 1.0 - charge);
    painter.sculpt(&circle(c, core_r), &radial(c, 0.0, core_r, hot, color.fade(0.2)), Sculpt::Fill);
    if charge > 0.15 {
        painter.sculpt(&circle(c, core_r * 0.9), &solid(color), Sculpt::Glow { radius: 9.0 * charge, intensity: 0.75 * charge });
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

    // Live beam: gradient core + additive bloom.
    painter.sculpt(&capsule(a, b, 3.0), &linear(a, b, color.fade(0.45), color.fade(0.8)), Sculpt::Fill);
    painter.sculpt(&capsule(a, b, 3.0), &solid(color), Sculpt::Glow { radius: 7.0 * charge, intensity: 0.5 * charge });

    // Packets streaming from this machine to the box.
    let span = b.x - a.x;
    for k in 0..3 {
        let t = (flow + k as f32 / 3.0).fract();
        let x = a.x + span * t;
        let p = Point::new(x, a.y);
        painter.sculpt(&circle(p, 2.6), &solid(CYAN_BRIGHT), Sculpt::Fill);
        painter.sculpt(&circle(p, 2.6), &solid(color), Sculpt::Glow { radius: 7.0, intensity: 0.95 });
    }
}

/// A 0..1 breathing curve from a 0..1 looping phase.
fn wave(phase: f32) -> f32 {
    (phase * TAU).sin() * 0.5 + 0.5
}
