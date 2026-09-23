//! The panel's one instrument: a single ring that fills with charge.
//!
//! It sits beside the state word and says the same thing without words. Down,
//! it is an empty track with a cold dot at its centre. Reaching, an amber arc
//! sweeps round the track looking for the far end. Up, the ring is full cyan
//! and breathes. Failed, the ring is red with a gap in it — the circuit is
//! broken, and nothing moves. Every mark is a sculpted signed-distance shape;
//! the only glow is the live ring's, and the only motion is motion with cause.

use crate::style::{self, CYAN_BRIGHT};
use crate::tunnel::{Link, Phase};
use rui::{El, Role, Size, arc, circle, draw, ring, solid};
use rui::{Painter, Sculpt};
use std::f32::consts::TAU;

/// The ring's footprint, in logical units — square, and the height of the
/// status block it anchors.
pub const RING: f32 = 64.0;

/// The track's thickness.
const TRACK: f32 = 3.5;

/// The status ring for the given link.
pub fn status_ring<S: 'static>(link: &Link) -> El<S> {
    let motion = Motion::from(&link.phase);
    draw(Size::new(RING, RING), move |painter, rect| paint(painter, rect, motion))
        .w(RING)
        .h(RING)
        .role(Role::Image)
        .label(motion.spoken())
}

/// The small mark in the masthead: the same ring at wordmark size, in the
/// wordmark's own muted ink — the brand does not get the accent, the live
/// state does.
pub fn mark<S: 'static>() -> El<S> {
    const SIZE: f32 = 14.0;
    draw(Size::new(SIZE, SIZE), |painter, rect| {
        let c = rect.center();
        painter.sculpt(&ring(c, SIZE * 0.36, 1.6), &solid(style::MUTED), Sculpt::Fill);
        painter.sculpt(&circle(c, 1.6), &solid(style::MUTED), Sculpt::Fill);
    })
    .w(SIZE)
    .h(SIZE)
    .role(Role::Image)
    .label("SelfHost VPN")
}

/// The link reduced to what the drawing switches on. `Copy`, so the paint
/// closure can hold it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Motion {
    /// No tunnel — an empty track, a cold centre.
    Off,
    /// Dialling/authenticating — an amber arc sweeping the track.
    Reaching,
    /// Up — the ring full and breathing.
    Up,
    /// Broken — a red ring with a gap, still.
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
}

/// The whole instrument, on the shared canvas.
fn paint(painter: &mut Painter<'_>, rect: rui::Rect, motion: Motion) {
    let color = style::hue(motion.hue());
    let c = rect.center();
    let r = rect.w / 2.0 - TRACK * 2.0;
    // Twelve o'clock, where a sweep starts and a gap opens.
    let top = -TAU / 4.0;

    // The track: always there, always cold, so the ring has a scale to fill.
    painter.sculpt(&ring(c, r, TRACK), &solid(style::SLATE.fade(0.22)), Sculpt::Fill);

    match motion {
        Motion::Off => {
            painter.sculpt(&circle(c, 3.0), &solid(style::SLATE.fade(0.7)), Sculpt::Fill);
        }
        Motion::Reaching => {
            // One phase, one loop: the arc runs the track once every 1.4s for
            // as long as the client is dialling. The only motion in the
            // window while nothing is up, and it stops the moment something is.
            let sweep = painter.phase("sweep", 1.4) * TAU;
            let shape = arc(c, r, TRACK, top + sweep, TAU * 0.28);
            painter.sculpt(&shape, &solid(color), Sculpt::Fill);
            painter.sculpt(&shape, &solid(color), Sculpt::Glow { radius: 4.0, intensity: 0.3 });
            painter.sculpt(&circle(c, 3.0), &solid(color.fade(0.8)), Sculpt::Fill);
        }
        Motion::Up => {
            // The ring breathes: a slow swell in its glow, never in its
            // geometry, so the instrument holds its shape and only its light
            // moves. Up is the one state that earns a standing animation.
            let breath = 0.55 + 0.45 * wave(painter.phase("breath", 3.6));
            let shape = ring(c, r, TRACK);
            painter.sculpt(&shape, &solid(color), Sculpt::Fill);
            painter.sculpt(&shape, &solid(color), Sculpt::Glow { radius: 9.0, intensity: 0.28 * breath });
            painter.sculpt(&circle(c, 4.0), &solid(CYAN_BRIGHT), Sculpt::Fill);
            painter.sculpt(&circle(c, 4.0), &solid(color), Sculpt::Glow { radius: 7.0, intensity: 0.5 * breath });
        }
        Motion::Failed => {
            // Most of a ring, with the gap at the top: a circuit that did not
            // close. Nothing moves — a failure is a fact, not an activity.
            let gap = TAU * 0.12;
            let shape = arc(c, r, TRACK, top + gap / 2.0, TAU - gap);
            painter.sculpt(&shape, &solid(color), Sculpt::Fill);
            painter.sculpt(&circle(c, 3.0), &solid(color), Sculpt::Fill);
        }
    }
}

/// A 0..1 breathing curve from a 0..1 looping phase.
fn wave(phase: f32) -> f32 {
    (phase * TAU).sin() * 0.5 + 0.5
}
