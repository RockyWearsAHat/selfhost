//! The window's one instrument: a soft light whose colour is the tunnel's
//! state, with the state set in words beneath it.
//!
//! There is no diagram. What a person wants from this window at a glance is
//! *are we up*, and a large word in a field of its own colour answers that
//! faster than any picture of a tunnel could. The light is one broad radial
//! bloom falling from above the window's top edge — slate when there is no
//! tunnel, amber while one is being made, cyan once it is up, red when it has
//! failed — and it is the only thing in the window that moves: it breathes
//! slowly while the tunnel is up and drifts side to side while reaching, so
//! that motion always means the tunnel is doing something.
//!
//! The words are painted here rather than laid out as text elements because
//! the light animates. rui replays an animating drawing on its own, restoring
//! what was under it first (see `AnimatedDraw` in rui's `paint`), so anything
//! laid *over* this drawing would vanish on every replayed frame. Keeping the
//! word inside the drawing is what lets it sit in the light at all.

use crate::style::{self, INK, MUTED};
use crate::tunnel::{Link, Phase};
use rui::style::{Face, Ink, Length};
use rui::{Align, El, Point, Rect, Role, Size, Tone, circle, radial};
use rui::{Painter, Sculpt};
use std::f32::consts::TAU;

/// How tall the hero is, in every state. The button under it never moves.
pub const HEIGHT: f32 = 164.0;

/// The size the state word is set at: the largest thing in the window, and
/// the only run at this size.
const WORD_SIZE: f32 = 34.0;

/// Where the word's baseline block sits within the hero.
const WORD_TOP: f32 = 62.0;
/// The word's line box.
const WORD_HEIGHT: f32 = 40.0;
/// Where the endpoint line sits.
const ENDPOINT_TOP: f32 = 110.0;
/// Where the detail line sits.
const DETAIL_TOP: f32 = 130.0;
/// The two small lines' line box.
const LINE_HEIGHT: f32 = 18.0;

/// The hero for the given link, sized to fill the width it is given.
pub fn hero<S: 'static>(link: &Link, endpoint: &str) -> El<S> {
    let scene = Scene::of(link, endpoint);
    let spoken = format!("{}. {}. {}", scene.word, scene.endpoint, scene.detail);
    rui::draw(Size::new(320.0, HEIGHT), move |painter, rect| paint(painter, rect, &scene))
        .h(HEIGHT)
        .w(Length::Fill(1.0))
        .role(Role::Status)
        .label(spoken)
}

/// The link reduced to what the drawing shows: which light, which words.
#[derive(Clone)]
struct Scene {
    motion: Motion,
    word: String,
    endpoint: String,
    detail: String,
    detail_tone: Tone,
}

impl Scene {
    fn of(link: &Link, endpoint: &str) -> Self {
        let motion = Motion::from(&link.phase);
        let (word, detail, detail_tone) = match &link.phase {
            Phase::Off => ("Offline", "Not connected".to_string(), Tone::Muted),
            Phase::Dialling => ("Connecting", "Reaching the box…".to_string(), Tone::Muted),
            Phase::Authenticated => ("Connecting", "Authenticating…".to_string(), Tone::Muted),
            Phase::Up => ("Connected", "Secure tunnel to the box".to_string(), Tone::Muted),
            Phase::Failed(reason) => ("Failed", reason.clone(), Tone::Exact(style::RED)),
        };
        Self { motion, word: word.into(), endpoint: endpoint.into(), detail, detail_tone }
    }
}

/// The link reduced to what the light switches on. `Copy`, so the paint
/// closure can hold it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Motion {
    /// No tunnel — a faint slate light, still.
    Off,
    /// Dialling/authenticating — amber, drifting side to side.
    Reaching,
    /// Up — cyan, breathing.
    Up,
    /// Broken — red, still.
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
    fn hue(self) -> style::Hue {
        match self {
            Motion::Off => style::Hue::Off,
            Motion::Reaching => style::Hue::Reaching,
            Motion::Up => style::Hue::Up,
            Motion::Failed => style::Hue::Failed,
        }
    }
    /// How bright the light is, 0..1.
    fn charge(self) -> f32 {
        match self {
            Motion::Off => 0.7,
            Motion::Reaching => 0.9,
            Motion::Up => 1.0,
            Motion::Failed => 0.85,
        }
    }
}

/// The whole hero: the light, then the words in it.
fn paint(painter: &mut Painter<'_>, rect: Rect, scene: &Scene) {
    let color = style::hue(scene.motion.hue());
    let charge = scene.motion.charge();

    // Up breathes; Reaching drifts. Off and Failed ask for no phase at all: a
    // phase requested is a frame requested, and a window with nothing to
    // report should draw nothing new.
    let breath = match scene.motion {
        Motion::Up => 0.84 + 0.16 * wave(painter.phase("breath", 4.6)),
        _ => 1.0,
    };
    let drift = match scene.motion {
        Motion::Reaching => (painter.phase("drift", 3.6) * TAU).sin() * rect.w * 0.10,
        _ => 0.0,
    };

    // Everything stays inside the hero's own rectangle — the drawing is
    // replayed alone while it animates, and only this rectangle is restored
    // under it first.
    let previous = painter.canvas().push_clip(rect);

    // The light: three blooms on one centre just above the window's top
    // edge, each smaller and a little denser than the last. One linear
    // radial ends in a visible rim where it reaches nothing; three stacked
    // approximate a bell, so the light simply thins out. All of them fall to
    // nothing well inside the rect.
    let center = Point::new(rect.center().x + drift, rect.y - 24.0);
    let bloom = charge * breath;
    for (reach, alpha) in [(rect.h * 1.15, 0.22), (rect.h * 0.82, 0.24), (rect.h * 0.52, 0.26)] {
        painter.sculpt(
            &circle(center, reach),
            &radial(center, 0.0, reach, color.fade(alpha * bloom), color.with_alpha(0)),
            Sculpt::Fill,
        );
    }

    // The words. One size for the state, the toolkit's own two small sizes
    // for the lines under it — hierarchy by weight and ink, not by inventing
    // a fourth size.
    let word = Ink { size: WORD_SIZE, tone: Tone::Exact(INK), face: Face::Ui, tracking: -0.4, bold: true };
    painter.text(Rect::new(rect.x, rect.y + WORD_TOP, rect.w, WORD_HEIGHT), word, Align::Center, &scene.word);

    let endpoint = Ink { size: 11.5, tone: Tone::Exact(MUTED), face: Face::Mono, tracking: 0.0, bold: false };
    painter.text(
        Rect::new(rect.x, rect.y + ENDPOINT_TOP, rect.w, LINE_HEIGHT),
        endpoint,
        Align::Center,
        &scene.endpoint,
    );

    let detail = Ink { size: 12.0, tone: scene.detail_tone, face: Face::Ui, tracking: 0.0, bold: false };
    painter.text(Rect::new(rect.x, rect.y + DETAIL_TOP, rect.w, LINE_HEIGHT), detail, Align::Center, &scene.detail);

    painter.canvas().pop_clip(previous);
}

/// A 0..1 breathing curve from a 0..1 looping phase.
fn wave(phase: f32) -> f32 {
    (phase * TAU).sin() * 0.5 + 0.5
}
