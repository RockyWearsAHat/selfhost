//! The console's house style: the colours it is drawn in, the marks it makes
//! itself, and why they are those shapes.
//!
//! # The console supplies its own colours
//!
//! `rui` builds a [`Theme`] from an appearance and two faces, and it hands an
//! application the seam to replace any part of it: [`App::theme`] takes a
//! *function* of the appearance, and [`Theme::with_palette`] swaps the colours
//! while leaving the metrics, the corner shape and the type scale exactly as the
//! library chose them. So [`THEATRE`] is the one colour decision in the program
//! — an operating theatre's instrument rather than a desktop's paper — and
//! [`theme`] is where it is handed over. Nothing below either of them names a
//! colour.
//!
//! What is *not* supplied is a second set of sizes or a second type scale.
//! Restating those to change the palette is how an application ends up with a
//! theme that disagrees with the library about what a heading is.
//!
//! The console also supplies its own ground, through the seam
//! [`rui::App::ground`] opens for exactly this: [`ground`] rules a fine
//! measurement scale along the window's top edge and leaves the rest black.
//! An earlier design scribed a graticule across the whole ground and framed
//! the window in its own accent, and both went the way every borrowed mark
//! here has: they said *instrument* by drawing a picture of one, and the
//! picture was the costume. One ruler, in the ink the interface reads by, is
//! the only decoration the ground keeps — measurement, stated once, in the
//! margin where nothing reports.
//!
//! [`App::theme`]: rui::App::theme
//! [`Theme`]: rui::Theme
//! [`Theme::with_palette`]: rui::Theme::with_palette
//!
//! # The corner: precision, not costume
//!
//! Two designs stood here before this one. The first rounded everything —
//! the desktop's own answer — and the second chamfered everything, a film's
//! answer, on the argument that a console is an instrument and an instrument
//! is machined. Both spent their energy on the corner, and the corner was
//! never what read as advanced. What reads as advanced is what a clinical
//! instrument actually looks like: true black, structure in hairlines, right
//! angles, and room. So the theme's own [`CornerStyle`] is set to
//! [`CornerStyle::Square`], and one word there squares every plate, button,
//! field and tag in the window. A square corner quotes nothing — it is the
//! shape of a thing that was not decorated — and against that quiet the few
//! marks that still carry character, the ruler and the lamps, are the only
//! voices left. Controls keep the library's sizes, its type scale, its hover
//! and focus behaviour, so they are still unmistakably things to press.
//!
//! [`CornerStyle`]: rui::CornerStyle
//! [`CornerStyle::Square`]: rui::CornerStyle::Square
//!
//! # The accent is light, not a hue
//!
//! `Tone::Accent` is an off-white: the colour of the instrument's own light,
//! not a paint. It is spent on two things and nothing else — the primary
//! action, and which row is chosen — so choosing is *lighting*: the chosen row
//! is held by a white hairline, and the one primary control is a lit face with
//! dark lettering. An interface whose selection is a hue asks the reader to
//! learn what the hue means; one whose selection is light asks nothing.
//!
//! Status hues are spent even more narrowly. Every row used to set its state
//! word in its own hue, which lit a healthy machine up in green — and an
//! interface whose job is to say when something is wrong cannot say it if a
//! working service is also lit. So the *word* is quiet unless it needs
//! attention, and what carries the state at rest is the lamp: a small mark
//! against a quiet ground. See [`state_ink`].
//!
//! [`THEATRE`] is built to keep that true at the level of the palette. Healthy
//! is not a green but a cyan-tinted steel, one step above the ink a label is
//! set in, so a rail of running services is quiet; amber and red are the only
//! saturated colours anywhere on screen, and neither appears without a cause.
//!
//! # Motion, and what is allowed to glow
//!
//! Three kinds of movement, and no others. [`rui::Painter::ease`] carries a
//! value that has changed to where it now is — the gauge's sweep, and the hover
//! every control in the library already eases on. [`rui::Painter::phase`] loops,
//! and a loop is only ever asked for while the thing it reports is *in flux*:
//! the sweep going round while a connection is being made, the pulse under a
//! lamp that wants attention. A frame that asks for a phase asks for another
//! frame, so a window that idles is a window with nothing outstanding — which is
//! the point, and the reason nothing decorative is allowed one.
//!
//! Glow is spent on exactly one thing: the pulse. A lamp that wants attention
//! throws a halo in its own colour as it breathes; everything else on screen
//! is flat, including a lamp that is merely on — a clinical display states
//! light by value, and a bloom on what is healthy is a filter over the window.
//! This is narrower than the design before it, which haloed the chosen row,
//! the sweeping arc and every lit lamp, and read as a hologram for it.

use rui::{
    Align, Anchor, Appearance, Canvas, Color, Corner, CornerStyle, El, FontId, Palette, Point,
    Rect, Role, Size, Status, Theme, Tone, button, col, draw, heading, micro, row, spacer,
    text,
};
use std::f32::consts::{FRAC_PI_2, TAU};

/// The colours the console is drawn in: an operating theatre's instrument,
/// not a desktop's paper and not a film's hologram.
///
/// Near-black neutrals, structure in grey hairlines, and one accent that is
/// not a hue at all: the off-white of the instrument's own light. Everything
/// merely present is a grey; everything chosen or pressed is lit; and the only
/// saturated colours the window can show are amber and red, which is what lets
/// either mean something the moment it appears.
///
/// The ground sits a step off pure black — pure black is a switched-off
/// screen — and carries no cast: a clinical display is neutral, and every hue
/// it is not wearing is contrast handed to the marks that report.
///
/// Healthy is deliberately not a green. It is a cyan-tinted steel, a step above
/// the muted ink and well below the accent, so that a lamp on a running
/// service reads as *lit* without a rail of them lighting up the window.
pub const THEATRE: Palette = Palette {
    background: Color::rgb(0x06, 0x07, 0x08),
    background_deep: Color::rgb(0x02, 0x02, 0x03),
    surface: Color::rgb(0x0d, 0x0e, 0x10),
    surface_deep: Color::rgb(0x09, 0x0a, 0x0c),
    sheen: Color::rgb(0x1c, 0x1e, 0x21),
    raised: Color::rgb(0x15, 0x17, 0x1a),
    sunken: Color::rgb(0x02, 0x03, 0x04),
    // The hairline every panel is outlined in: a neutral grey. Structure is
    // never lit — light is spent on what is chosen, and an edge is not chosen.
    border: Color::rgb(0x24, 0x27, 0x2b),
    // The keyboard's ring, in the deep accent rather than the accent itself:
    // focus and selection are two facts, and a palette that draws both in one
    // light cannot say which row is chosen and which merely holds the
    // keyboard. A step down in value keeps it plainly a ring — still over
    // three times brighter than the surface it rings — while the full accent
    // stays what it was: the mark of what is chosen.
    border_focus: Color::rgb(0xb8, 0xc0, 0xc5),
    text: Color::rgb(0xe9, 0xec, 0xee),
    text_muted: Color::rgb(0x70, 0x78, 0x7e),
    text_on_accent: Color::rgb(0x0a, 0x0b, 0x0d),
    accent: Color::rgb(0xf2, 0xf5, 0xf6),
    accent_deep: Color::rgb(0xb8, 0xc0, 0xc5),
    accent_light: Color::rgb(0xff, 0xff, 0xff),
    ok: Color::rgb(0x7e, 0x96, 0xa0),
    ok_tint: Color::rgb(0x0d, 0x13, 0x17),
    warn: Color::rgb(0xe0, 0xa4, 0x58),
    warn_tint: Color::rgb(0x21, 0x18, 0x0a),
    bad: Color::rgb(0xf2, 0x55, 0x5a),
    bad_tint: Color::rgb(0x26, 0x0f, 0x11),
    idle: Color::rgb(0x4a, 0x51, 0x57),
    idle_tint: Color::rgb(0x0f, 0x11, 0x14),
    shadow: Color::rgba(0x00, 0x00, 0x00, 0x30),
};

/// The theme every frame is drawn with: the library's, in the console's colours
/// and the console's corner.
///
/// A function of the appearance because that is the shape of the seam, and it
/// answers the same palette either way. A display is not a document: the room's
/// lights coming on does not turn an instrument's face white, and a "light"
/// variant of this palette would be a second design to keep in step with the
/// first for the sake of a window nobody would recognise as the same program.
/// [`rui::Theme::is_dark`] reads the palette rather than what it was built with,
/// so everything derived from it is derived correctly under either desktop.
///
/// [`CornerStyle::Square`] is the one other word the console says to the
/// library: every corner in the window is a right angle, the shape of a thing
/// that was not decorated. See the module's own notes on the corner for why
/// the chamfer before it was the costume, not this.
pub fn theme(_appearance: Appearance, ui_font: FontId, mono_font: FontId) -> Theme {
    Theme::new(Appearance::Dark, ui_font, mono_font)
        .with_palette(THEATRE)
        .with_corners(CornerStyle::Square)
}

/// How far apart the ruler's divisions fall along the window's top edge.
const RULER_STEP: f32 = 10.0;

/// Every how many divisions a longer, brighter mark falls.
const RULER_MAJOR_EVERY: u32 = 5;

/// How far a minor division reaches down from the edge.
const RULER_TICK: f32 = 3.0;

/// How far a major one does.
const RULER_TICK_MAJOR: f32 = 7.0;

/// How much of the text's ink a minor division keeps.
///
/// Faint on purpose: the ground is the one mark in the window that reports
/// nothing, so it must sit below the threshold at which it competes with
/// anything that does.
const RULER_ALPHA: f32 = 0.10;

/// How much a major one keeps: a step above the divisions it gathers.
const RULER_ALPHA_MAJOR: f32 = 0.22;

/// The window's ground: black, ruled once along its top edge.
///
/// This is the console's half of the [`rui::App::ground`] seam, and it is
/// nearly nothing on purpose. An earlier design scribed a graticule across the
/// whole window and closed it with a chamfered viewport frame in the accent —
/// a drawing of an instrument, where this program is meant to *be* one. What
/// a clinical instrument's face actually carries is black glass and one scale,
/// so the ground keeps exactly that: the palette's gradient down to true
/// black, and a fine ruler in the margin above the masthead, minor and major
/// divisions in the ink everything else is read by.
///
/// The ruler is the one decoration in the window, and it earns the place by
/// being what the console is for — measurement — rather than a picture of it.
/// It lives in the sixteen units the layout keeps as margin, so it can never
/// sit behind a word.
///
/// It asks for no phase and draws nothing that moves, so it costs the window
/// none of its ability to idle.
pub fn ground(canvas: &mut Canvas, theme: &Theme) {
    canvas.clear_vertical(theme.palette.background, theme.palette.background_deep);
    let bounds = canvas.bounds();

    let minor = theme.palette.text.fade(RULER_ALPHA);
    let major = theme.palette.text.fade(RULER_ALPHA_MAJOR);
    let mut index: u32 = 1;
    let mut x = RULER_STEP;
    while x < bounds.w {
        let (reach, ink) = if index % RULER_MAJOR_EVERY == 0 {
            (RULER_TICK_MAJOR, major)
        } else {
            (RULER_TICK, minor)
        };
        canvas.line(Point::new(x, 0.0), Point::new(x, reach), 1.0, ink);
        index += 1;
        x += RULER_STEP;
    }
}

/// How big the mark beside the wordmark is drawn.
const MARK: f32 = 22.0;

/// How wide a status lamp is.
///
/// # Why the lamp is a slot and not a pip
///
/// A pip at eight or ten units, once it is antialiased at the size a screen
/// actually draws it, is a dot — the mark every desktop tray uses, and a mark
/// with no edges to be square with. A tall slot has edges: five by fourteen at
/// right angles reads as an indicator machined into a panel, most clearly when
/// it is *unlit*, where the outline is plainly a slot and not a pill.
const LAMP_WIDTH: f32 = 5.0;

/// How tall it is; see [`LAMP_WIDTH`].
const LAMP_HEIGHT: f32 = 14.0;

/// How far a pulsing lamp's halo reaches past the slot casting it.
const LAMP_HALO: f32 = 5.0;

/// How much of the lamp's own colour survives into that halo.
const HALO_STRENGTH: f32 = 0.55;

/// How long a lamp that wants attention takes to pulse once, in seconds.
///
/// Slow enough to read as breathing rather than as blinking. A blink is an
/// alarm going off; this is a mark saying it is still waiting.
const PULSE: f32 = 1.2;

/// How far a pulse dims at its lowest, as a share of full strength.
const PULSE_FLOOR: f32 = 0.35;

/// How wide the wedge against the chosen row is.
const WEDGE: f32 = 3.0;

/// How far round a circle a gauge's reading starts.
///
/// Twelve o'clock. A gauge that began anywhere else would be reporting a share
/// of a whole from a place a reader has to find first.
const TOP: f32 = -FRAC_PI_2;

/// How big a ring gauge is drawn.
///
/// Held near the height of the two lines beside it rather than to the strip it
/// sits in. Every unit it takes is a unit off the sentence and the readings on a
/// narrow window, and a larger dial does not report a proportion any better.
///
/// Six units over what the scale and ring alone needed, and they are what the
/// core paid for: a lit centre inside a ring this small either touches the
/// track or does not exist, and the readings beside the gauge still keep the
/// room the sentence needs.
const GAUGE: f32 = 44.0;

/// How wide its band is.
///
/// Thin, so the unlit track reads as a hairline scribed round the dial and not
/// as a second ring competing with the scale outside it.
const GAUGE_BAND: f32 = 2.0;

/// How many marks its scale is divided into.
///
/// Fourteen: enough to read as a scale rather than four ticks a reader could
/// count, and few enough that each is still a mark and not a hair in a ring of
/// them — the defect a scale of twelve fell into once the ticks were drawn as
/// long as the ring's own radius.
const GAUGE_TICKS: u32 = 14;

/// How long each mark on the scale is drawn.
///
/// Short on purpose. A tick that reaches toward the ring is what turned the
/// scale into a sunburst; a mark this short reads as a division on a dial's
/// face because it stops well short of being anything else.
const GAUGE_TICK: f32 = 2.0;

/// How thick each mark is drawn.
const GAUGE_TICK_WEIGHT: f32 = 1.0;

/// How much air separates the scale from the ring it marks.
///
/// The gap that was missing: without it, the ticks' own inner edge and the
/// ring's own outer edge painted over each other the instant either was
/// widened by so much as a unit, which is what made the mark read as one
/// muddled blot instead of two.
const GAUGE_TICK_GAP: f32 = 2.5;

/// How much of the accent a gauge's unlit track keeps.
const TRACK: f32 = 0.16;

/// How big the lit core at the gauge's centre is drawn.
const CORE: f32 = 5.0;

/// How dim the core burns with nothing running, as a share of full brightness.
///
/// Never out, for the lamp's own reason: a centre that vanishes at zero makes
/// the gauge read as broken exactly when it is reporting the worst news it has.
const CORE_FLOOR: f32 = 0.2;

/// How big the sweep that reports a connection being made is drawn.
const SWEEP: f32 = 14.0;

/// How wide its band is.
const SWEEP_BAND: f32 = 1.6;

/// How far round the circle the lit part of it runs.
const SWEEP_ARC: f32 = TAU * 0.3;

/// How long it takes to go round once, in seconds.
///
/// Slow. A radar sweep says *this is under way*; at half this period the same
/// mark says *something is wrong*, which is a different fact and not this one.
const SWEEP_PERIOD: f32 = 2.4;

/// How tall the tick on the end of a hairline rule is.
const RULE_TICK: f32 = 7.0;

/// A framed surface: the rail, the detail pane, the readout bank.
///
/// A square panel one value above the ground, told by a grey hairline and a
/// sheen along its top edge, and by nothing else. No chamfer, no shadow, no
/// corner marks: on a ground this dark a shadow is invisible and a decorated
/// corner is a costume, so what says *this is a surface* is value — the one
/// separation that works in the dark — and the hairline that says where it
/// ends.
pub fn plate<S>(children: impl rui::Children<S>) -> El<S> {
    col(children)
        .gradient(Tone::Surface, Tone::SurfaceDeep)
        .border(1.0, Tone::Border)
        .pad(12.0)
        .add(sheen())
}

/// How much of the light accent a plate's top sheen keeps.
const SHEEN: f32 = 0.14;

/// The highlight along a plate's top edge: what says the surface is lit.
///
/// One hairline in the light accent, run just inside the border. A plate whose
/// gradient merely darkens downward is shaded; one whose top edge also catches
/// the light is *lit from above*, which is the difference between a rectangle
/// in a flat colour and an instrument's surface under the room's light. It is
/// a layer so the highlight costs the contents nothing.
fn sheen<S>() -> El<S> {
    draw(Size::new(0.0, 0.0), |painter, rect| {
        let color = painter.color(Tone::AccentLight).fade(SHEEN);
        painter.canvas().line(
            Point::new(rect.x + 1.0, rect.y + 1.0),
            Point::new(rect.max_x() - 1.0, rect.y + 1.0),
            1.0,
            color,
        );
    })
    .layer(Anchor::Over)
}

/// How big a line that leads its row is set; see [`emphatic`].
const EMPHATIC: f32 = 13.5;

/// How big a state's word is set: the smallest capitals on screen, a step
/// under the caption — quiet type for a fact the lamp beside it already
/// carries. See [`state_word`].
const STATE_WORD: f32 = 10.5;

/// How big a reading's value is set: between the label's micro capitals and
/// the body, so a figure reads as evidence cited under the sentence rather
/// than as a headline of its own. See [`reading`].
const READING_VALUE: f32 = 12.5;

/// A line that leads its row: a half-step above the body, well short of a
/// heading.
///
/// Spent on exactly two lines — a service's name in the rail and the next
/// move's headline — the two places a row's first words have to be found
/// before the quieter type around them. One mark, so the two cannot come to
/// lead at two different sizes.
pub fn emphatic<S>(label: impl Into<String>) -> El<S> {
    text(label).text_size(EMPHATIC)
}

/// The ink a state's own word is set in.
///
/// Muted while there is nothing to report, and the status's own hue once there
/// is. A running service and a stopped one are both *expected*, and colouring
/// them spends the reader's attention on the rows that do not need it — which
/// is attention the two rows that do need it no longer get. The lamp beside the
/// name carries the state at rest; this carries it when it matters.
pub fn state_ink(status: Status) -> Tone {
    match status {
        Status::Ok | Status::Idle => Tone::Muted,
        Status::Warn | Status::Bad => Tone::ink(status),
    }
}

/// A status lamp: a square slot, lit when the service is doing anything at all.
///
/// Filled for [`Status::Ok`], [`Status::Warn`], and [`Status::Bad`], and left
/// as an outline for [`Status::Idle`]. That is the state said twice by two
/// different means — a hue and a shape — so a reader who receives no colour at
/// all still sees which services are running.
///
/// A lamp that is merely on is flat: a clinical display states light by value,
/// and a bloom on what is healthy is a filter over the window. Only the two
/// states that want attention throw a halo, and they throw it breathing, on
/// the one loop this interface allows a mark that is waiting. See [`PULSE`].
///
/// It carries the state's word for anything that cannot see either, so the row
/// it sits in is named after what it shows.
pub fn lamp<S>(status: Status) -> El<S> {
    let tone = Tone::ink(status);
    let lit = !matches!(status, Status::Idle);
    let waiting = matches!(status, Status::Warn | Status::Bad);
    draw(Size::new(LAMP_WIDTH, LAMP_HEIGHT), move |painter, rect| {
        let color = painter.color(tone);
        if !lit {
            painter.canvas().stroke(rect, Corner::Square, 1.0, color);
            return;
        }
        if waiting {
            let strength = pulse(painter.phase("pulse", PULSE));
            let halo = color.fade(HALO_STRENGTH * strength);
            painter.canvas().shadow(rect, Corner::Square, LAMP_HALO, 0.0, halo);
        }
        painter.canvas().fill(rect, Corner::Square, color);
    })
    .w(LAMP_WIDTH)
    .h(LAMP_HEIGHT)
    .align_self(Align::Center)
    .role(Role::Status)
    .label(spoken(status))
}

/// Where a loop that dims and brightens has got to, from its phase.
///
/// Never all the way out. A mark that goes dark at the bottom of its cycle is a
/// mark that is absent for a moment, and the reader who glanced at that moment
/// was told nothing.
fn pulse(phase: f32) -> f32 {
    let wave = (1.0 + (phase * TAU).sin()) / 2.0;
    PULSE_FLOOR + (1.0 - PULSE_FLOOR) * wave
}

/// What share of the outer sweep's radius the counter-arc runs at.
const SWEEP_INNER: f32 = 0.55;

/// A sweep going round: what a connection being made looks like.
///
/// Two arcs on one phase: the outer runs the way a dial reads and an inner,
/// shorter one runs against it at just over half the radius. One arc going
/// round is a wait cursor; two passing each other are a mechanism *turning*,
/// which is the fact this mark exists to state. Both are driven off the same
/// phase, so the pair costs the window exactly the frames one arc did.
///
/// The one mark in the console that moves while nothing has changed, and it is
/// allowed to because what it reports *is* the movement — the console is
/// reaching for something and has not got there. It stops being drawn the frame
/// the link is made, which is what keeps the window able to idle.
pub fn sweep<S>(status: Status) -> El<S> {
    let tone = Tone::ink(status);
    draw(Size::new(SWEEP, SWEEP), move |painter, rect| {
        let color = painter.color(tone);
        let center = Point::new(rect.x + rect.w / 2.0, rect.y + rect.h / 2.0);
        let radius = rect.w.min(rect.h) / 2.0 - SWEEP_BAND;
        let phase = painter.phase("sweep", SWEEP_PERIOD);
        let start = TOP + phase * TAU;
        let counter = TOP - phase * TAU;
        let canvas = painter.canvas();
        canvas.ring(center, radius, SWEEP_BAND, color.fade(TRACK * 1.5));
        canvas.arc(center, radius, SWEEP_BAND, start, SWEEP_ARC, color);
        canvas.arc(
            center,
            radius * SWEEP_INNER,
            SWEEP_BAND,
            counter,
            SWEEP_ARC * 0.6,
            color.fade(0.6),
        );
    })
    .w(SWEEP)
    .h(SWEEP)
    .align_self(Align::Center)
    .role(Role::Status)
    .label(spoken(status))
}

/// The word a status is read aloud as.
///
/// Lower case, because it is read as part of a sentence — "ok, mongod,
/// running" — rather than as a heading. The same four words
/// [`rui::dot`](rui::dot) uses, so a lamp and a dot cannot come to be read
/// differently.
fn spoken(status: Status) -> &'static str {
    match status {
        Status::Ok => "ok",
        Status::Warn => "warning",
        Status::Bad => "failed",
        Status::Idle => "idle",
    }
}

/// A ring reporting a share of a whole: how much of the machine is up.
///
/// Three rings and a core, drawn outside in, each with air between it and its
/// neighbour: a scale of short ticks, then a gap, then a thin low-alpha track,
/// then the lit arc on that same track, and at the centre a small disc whose
/// brightness *is* the reading. The scale and
/// the track used to be drawn back to back with no gap and ticks nearly as
/// long as the track's own radius, which is what made the whole mark read as
/// one spiked blot rather than as three things at three radii — see
/// [`GAUGE_TICK`] and [`GAUGE_TICK_GAP`].
///
/// The core states the same share the arc does, by a means readable at a
/// distance the arc is not: a machine fully up burns bright at the centre of
/// its dial, and a machine down to nothing has gone dark there — though never
/// out; see [`CORE_FLOOR`]. It eases on the arc's own key, so the two cannot
/// disagree mid-motion.
///
/// The track is what states the scale — without it a reader knows how far the
/// arc has got but not how far *all of it* would be — and it is the same
/// argument [`rui::meter`] makes for the bar it draws.
///
/// The arc eases to a new reading rather than jumping to it, on the curve every
/// control in the library hovers on, because a gauge that snapped between two
/// positions would read as a redraw rather than as a machine changing.
///
/// It carries no name of its own for a screen reader. The ratio it draws is set
/// as words immediately beside it, and a mark that says the same thing a third
/// time is a mark that has to be listened past.
pub fn gauge<S>(fraction: f32) -> El<S> {
    let fraction = fraction.clamp(0.0, 1.0);
    draw(Size::new(GAUGE, GAUGE), move |painter, rect| {
        let accent = painter.color(Tone::Accent);
        let center = Point::new(rect.x + rect.w / 2.0, rect.y + rect.h / 2.0);
        // The scale sits just inside the box's own edge, short enough not to
        // reach it; the ring sits far enough inside the scale to leave the
        // gap that tells the two apart. Working in from the outer edge is
        // what keeps that gap true whatever [`GAUGE`] is set to, rather than
        // a second constant somebody has to keep in step with the first.
        let half = rect.w.min(rect.h) / 2.0;
        let tick_outer = half - 1.0;
        let tick_inner = tick_outer - GAUGE_TICK;
        let radius = tick_inner - GAUGE_TICK_GAP - GAUGE_BAND / 2.0;
        let motion = painter.theme().metrics.motion;
        let swept = painter.ease("sweep", fraction, motion) * TAU;

        let canvas = painter.canvas();
        canvas.ticks(
            center,
            tick_inner,
            tick_outer,
            GAUGE_TICK_WEIGHT,
            GAUGE_TICKS,
            TOP,
            accent.fade(TRACK * 1.6),
        );
        canvas.ring(center, radius, GAUGE_BAND, accent.fade(TRACK));
        if swept > 0.0 {
            canvas.arc(center, radius, GAUGE_BAND, TOP, swept, accent);
        }

        // The core: brightness follows the eased share, so the disc and the
        // arc report the same number by two different means. Flat, like every
        // lit thing here — its reading is its value, not a bloom around it.
        let lit = CORE_FLOOR + (1.0 - CORE_FLOOR) * (swept / TAU);
        canvas.ring(center, CORE / 2.0, CORE, accent.fade(lit));
    })
    .w(GAUGE)
    .h(GAUGE)
    .align_self(Align::Center)
}

/// The gauge's face with no reading on it: scale and track, no arc, no core.
///
/// Drawn while the console has not reached the daemon — the machine's share is
/// not nought, it is *unknown*, and the two must not look alike. A zero
/// reading keeps its dimly lit core ([`CORE_FLOOR`]: dark, never out); an
/// instrument that has not measured anything has no reading to state, so its
/// centre is empty and only the face marks the place a reading will appear.
/// The connected-but-empty machine is a third case and stays bare (see
/// `live_share` in view/mod.rs): with nothing installed there is nothing to
/// measure, and a face would promise a reading that can never arrive.
pub fn gauge_unread<S>() -> El<S> {
    draw(Size::new(GAUGE, GAUGE), move |painter, rect| {
        let accent = painter.color(Tone::Accent);
        let center = Point::new(rect.x + rect.w / 2.0, rect.y + rect.h / 2.0);
        // The same radii, worked in from the edge, as [`gauge`] — the face is
        // the one thing the two states share, so it is drawn by the same
        // arithmetic.
        let half = rect.w.min(rect.h) / 2.0;
        let tick_outer = half - 1.0;
        let tick_inner = tick_outer - GAUGE_TICK;
        let radius = tick_inner - GAUGE_TICK_GAP - GAUGE_BAND / 2.0;

        let canvas = painter.canvas();
        canvas.ticks(
            center,
            tick_inner,
            tick_outer,
            GAUGE_TICK_WEIGHT,
            GAUGE_TICKS,
            TOP,
            accent.fade(TRACK * 1.6),
        );
        canvas.ring(center, radius, GAUGE_BAND, accent.fade(TRACK));
    })
    .w(GAUGE)
    .h(GAUGE)
    .align_self(Align::Center)
}

/// How large a reticle is drawn, at most.
const RETICLE: f32 = 200.0;

/// What share of the room it is given the ring takes, before that cap applies.
///
/// A share and not a fixed radius, so the mark still centres itself behind the
/// words on the smallest pane the backend allows instead of overflowing it.
const RETICLE_SHARE: f32 = 0.42;

/// How thin the ring is drawn.
const RETICLE_BAND: f32 = 1.0;

/// How long each tick on it is.
const RETICLE_TICK: f32 = 6.0;

/// How many ticks it carries.
const RETICLE_TICKS: u32 = 8;

/// How much of the hairline's own alpha survives into it.
///
/// [`Tone::Border`] rather than [`Tone::Accent`]: the accent is spent on the
/// primary action and which row is chosen and on nothing else — see the
/// module's own notes on where a hue is allowed to be spent — and a reticle
/// with a judgement behind it is not either of those. The border is cyan
/// already, at just over a third; faded to a fifth of that it lands at
/// roughly six percent, low enough that a reader has to be told this is here
/// before they see it, which is the whole point of drawing an empty pane at
/// all — it is not reporting anything, and a mark drawn to be noticed would be
/// a claim that it was.
const RETICLE_ALPHA: f32 = 0.2;

/// What share of the outer ring's radius the inner ring is drawn at.
const RETICLE_INNER: f32 = 0.62;

/// How long the crosshair stubs reaching out past the outer ring are.
const RETICLE_STUB: f32 = 10.0;

/// How much air a crosshair stub keeps between itself and the ring it leaves.
const RETICLE_STUB_GAP: f32 = 3.0;

/// A faint targeting reticle, centred behind an empty pane's own words.
///
/// Two rings, a scale, four crosshair stubs at the cardinal points, and a
/// centre mark: an instrument's aperture with nothing sighted in it yet. The
/// room a pane's watermark used to sit in was true blank space, and a window
/// that has never had a service chosen read as unfinished rather than as
/// waiting. This is the same argument the sweep and the gauge make at the
/// other end of the window — an instrument's face is marked everywhere, not
/// only where it currently has a reading — carried to the one panel that had
/// been left bare.
///
/// It is a layer, the same device [`brackets`] uses, so it costs the caption
/// beneath it no room and cannot change where that text is centred. It asks
/// for no phase and no glow: nothing here is in flux, so nothing here may
/// move, on the same rule that keeps the rest of the window able to idle. See
/// the module's own notes on what a loop and a halo are for.
pub fn reticle<S>() -> El<S> {
    draw(Size::new(0.0, 0.0), |painter, rect| {
        let color = painter.color(Tone::Border).fade(RETICLE_ALPHA);
        let center = Point::new(rect.x + rect.w / 2.0, rect.y + rect.h / 2.0);
        let radius = (rect.w.min(rect.h) * RETICLE_SHARE).min(RETICLE / 2.0);
        if radius <= RETICLE_TICK {
            return;
        }
        let canvas = painter.canvas();
        canvas.ring(center, radius, RETICLE_BAND, color);
        canvas.ticks(center, radius - RETICLE_TICK, radius, RETICLE_BAND, RETICLE_TICKS, TOP, color);
        canvas.ring(center, radius * RETICLE_INNER, RETICLE_BAND, color);
        // The centre mark: a dot, not a cross, so the words over it are not
        // read through a plus sign.
        canvas.ring(center, 1.0, 2.0, color);
        // The stubs leave a gap before they set off, so the ring stays a ring
        // rather than a wheel with four spokes through it.
        for (dx, dy) in [(1.0, 0.0), (-1.0, 0.0), (0.0, 1.0), (0.0, -1.0f32)] {
            let from = radius + RETICLE_STUB_GAP;
            canvas.line(
                Point::new(center.x + dx * from, center.y + dy * from),
                Point::new(
                    center.x + dx * (from + RETICLE_STUB),
                    center.y + dy * (from + RETICLE_STUB),
                ),
                RETICLE_BAND,
                color,
            );
        }
    })
    .layer(Anchor::Over)
}

/// The bar down the leading edge of a strip that has something to announce.
///
/// A square bar in the status's own hue: a pale tinted rectangle is easy to
/// read past, and these strips appear exactly when something must not be read
/// past.
pub fn flag<S>(status: Status) -> El<S> {
    let tone = Tone::ink(status);
    draw(Size::new(WEDGE, 0.0), move |painter, rect| {
        let color = painter.color(tone);
        painter.canvas().fill_rect(rect, color);
    })
    .w(WEDGE)
}

/// The mark against the chosen row: a lit bar on its leading edge.
///
/// It grows out of the row's own edge rather than sitting inside it, so the eye
/// is carried from the row it left to the row it landed on. It is drawn in the
/// accent — which here is light — so choosing a row reads as switching its
/// edge on rather than as painting it a colour.
pub fn wedge<S>(chosen: bool) -> El<S> {
    draw(Size::new(WEDGE, 0.0), move |painter, rect| {
        if !chosen {
            return;
        }
        let color = painter.color(Tone::Accent);
        painter.canvas().fill_rect(rect, color);
    })
    .w(WEDGE)
    .h(if chosen { rui::Length::Fraction(0.56) } else { rui::Length::Fixed(0.0) })
    .align_self(Align::Center)
}

/// The console's own mark: a lit square tile carrying three rack units.
///
/// Drawn rather than shipped as an image, for the same reason no font is
/// shipped: it costs nothing, it is correct at every size, and it takes its
/// colours from the theme, so a change of palette reaches it instead of leaving
/// one bitmap behind in the colours of the design before it. Under [`THEATRE`]
/// the accent is light, so the tile comes out as a white chip on black glass —
/// the brightest thing in the window, which the thing the window is named
/// after can afford to be.
///
/// The tile is the one place the accent appears without being pressed, and it
/// earns that by being that name.
pub fn mark<S>() -> El<S> {
    draw(Size::new(MARK, MARK), |painter, rect| {
        let (light, deep) = (painter.color(Tone::AccentLight), painter.color(Tone::AccentDeep));
        painter.canvas().fill_vertical(rect, Corner::Square, light, deep);

        // Three slots stacked as a rack reads from the front, each with a lamp
        // at its left end. The lamp is what stops the three bars reading as the
        // three lines of a menu button.
        let margin = rect.w * 0.22;
        let height = rect.h * 0.15;
        let spacing = (rect.h - margin * 2.0 - height) / 2.0;
        let ink = painter.color(Tone::OnAccent).fade(0.92);
        let lamp = painter.color(Tone::AccentLight);

        for index in 0..3 {
            let unit = Rect::new(
                rect.x + margin,
                rect.y + margin + spacing * index as f32,
                rect.w - margin * 2.0,
                height,
            );
            painter.canvas().fill_rect(unit, ink);
            let socket_size = height * 0.42;
            let socket = Rect::new(
                unit.x + socket_size,
                unit.y + unit.h / 2.0 - socket_size / 2.0,
                socket_size,
                socket_size,
            );
            painter.canvas().fill_rect(socket, lamp);
        }
    })
    .align_self(Align::Center)
}

/// How wide a button whose whole face is one mark is drawn.
const ICON_BUTTON: f32 = 26.0;

/// A button carrying a mark instead of a word.
///
/// [`rui::button`] keeps twelve units of padding on each side for a label,
/// which at this width leaves *two* units for the mark — so the cross that
/// dismisses a notice was drawn as an ellipsis, and so was the minus beside
/// every argument. The padding goes and the width stays.
///
/// The name is a parameter and not optional, because a mark has no words to be
/// named after: a screen reader given `\u{00d7}` reads out "multiplication
/// sign", and every remove button would otherwise be called the same thing.
pub fn icon_button<S>(mark: &'static str, name: impl Into<String>) -> El<S> {
    button(mark).ghost().w(ICON_BUTTON).pad_x(0.0).label(name)
}

/// A hairline that takes whatever room is left, ending in a tick.
///
/// The tick is the difference between a rule and a border. A hairline that runs
/// out at the edge of the pane reads as the top of a box that was not finished;
/// the same line stopped by a short upright reads as a measurement — this far,
/// deliberately — which is what every rule in this window is for.
pub fn rule<S>() -> El<S> {
    row((
        spacer().h(1.0).grow().fill(Tone::Border).align_self(Align::Center),
        spacer().w(1.0).h(RULE_TICK).fill(Tone::Border).align_self(Align::Center),
    ))
    .grow()
    .align(Align::Center)
}

/// How tall a rule stood on end is drawn.
///
/// Deliberately short of the strip it divides. A hairline running from edge to
/// edge is the wall of a table cell, and a readout bank ruled into cells is the
/// four-cards defect the bank was restaged to be rid of. Stopped short, the
/// same mark says the two things either side of it are two readings on one
/// instrument.
const STANDING_RULE: f32 = 30.0;

/// A hairline stood on end, dividing a strip into what it reports and what it
/// intends.
///
/// The same mark [`rule`] makes, turned, and made for the same argument: a rule
/// states where one block ends without drawing an outline round either. It
/// takes a stated height rather than the room that is left because what it
/// divides is a strip of a fixed height, and a rule that grew with the strip
/// would become that wall.
pub fn standing_rule<S>() -> El<S> {
    spacer().w(1.0).h(STANDING_RULE).fill(Tone::Border).align_self(Align::Center)
}

/// A block's label, with a ticked rule running from it to the far edge.
///
/// [`rui::section`] with this window's own rule and a little more tracking. The
/// label is the smallest type on screen and it is set in capitals, which pack
/// into a block at that size; opening them up is what makes SERVICES, OUTPUT and
/// DEFINITION read as headings for the machine rather than as a word squeezed
/// against a line.
///
/// `note` is what sits at the far end of the same line — a count, or LIVE — and
/// is set in the fixed-width face, because everything the console puts there is
/// something it read off the machine.
pub fn section_rule<S>(label: &'static str, note: Option<String>) -> El<S> {
    row((heading(label).tracking(1.5), rule(), note.map(micro))).h(14.0).gap(8.0)
}

/// A section rule whose far end carries a control rather than a reading.
///
/// The same mark [`section_rule`] makes, stood a few units taller so the
/// control has a face to press. A control at the end of a rule is about the
/// block the rule introduces — the one place this is spent is DEFINITION's
/// Edit, which opens for editing exactly what that block shows. It does not
/// join the lifecycle well: five buttons cannot keep their words on the
/// narrowest pane, and a definition is not a lifecycle event.
pub fn section_rule_control<S>(label: &'static str, control: El<S>) -> El<S> {
    row((
        heading(label).tracking(1.5).align_self(Align::Center),
        rule(),
        control.align_self(Align::Center),
    ))
    .h(22.0)
    .gap(8.0)
}

/// A machine's state, set as a word beside whatever it is about.
///
/// Small capitals, tracked as [`rui::Theme::state`] tracks them, in the ink
/// [`state_ink`] chose. Bare rather than inside a tag: a tag is chrome around
/// one word, and on a narrow rail that chrome takes the room the service's own
/// name needs — and the name is the part that tells one row from another.
pub fn state_word<S>(status: Status, label: String) -> El<S> {
    text(label).text_size(STATE_WORD).tracking(0.4).color(state_ink(status))
}

/// One count cited under the condition: what is being counted, and the count.
///
/// Set on one line at the size of a label rather than stacked under one, and
/// that is the whole point of the mark. A label above a figure is a *tile* — it
/// claims the count is a headline — and the readout bank's counts are not the
/// headline; they are the evidence for the sentence above them, and evidence is
/// cited inline. What separates one reading from the next is the room between
/// them, because a rule or a middot between three pairs is chrome around
/// something already legible.
///
/// The label is tracked capitals and the value is fixed-width, which is the same
/// division the whole window is built on: what the interface says about itself
/// is set in the desktop's face, and what it read off the machine lines up in
/// columns.
///
/// `alarm` is the one voice a reading may raise, and it is passed rather than
/// worked out here so that the decision about *which* count is allowed to shout
/// stays beside the counting. See the bank's own header for that argument.
pub fn reading<S>(label: &'static str, value: String, alarm: Option<Status>) -> El<S> {
    row((
        micro(label).tracking(1.2),
        text(value)
            .mono()
            .text_size(READING_VALUE)
            .color(alarm.map_or(Tone::Text, Tone::ink)),
    ))
    .gap(6.0)
    .align(Align::Center)
}

/// A lamp and a state's word, as one mark: what a title line ends with.
///
/// Kept together here so the masthead and the detail pane cannot come to state
/// the same thing two different ways.
pub fn state_mark<S>(status: Status, label: String) -> El<S> {
    marked(lamp(status), status, label)
}

/// The same, for a link that is still being made.
///
/// A sweep in place of the lamp while the console is reaching for the daemon or
/// the tunnel is opening, and the lamp itself the moment either arrives. The
/// two are one mark rather than two because they say the same thing about the
/// same subject — one of them says it is still happening.
pub fn link_mark<S>(status: Status, label: String, reaching: bool) -> El<S> {
    let head = if reaching { sweep(status) } else { lamp(status) };
    marked(head, status, label)
}

/// A mark and the word beside it, spaced and aligned the one way.
fn marked<S>(head: El<S>, status: Status, label: String) -> El<S> {
    row((head, state_word(status, label))).gap(6.0).align(Align::Center)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A state for trees that do nothing.
    struct Nothing;

    /// The theme the console actually draws with, with no faces loaded.
    fn theatre() -> Theme {
        theme(Appearance::Dark, FontId::FIRST, FontId::FIRST)
    }

    #[test]
    fn the_console_is_the_same_instrument_under_either_desktop() {
        // The seam is a function of the appearance and this one ignores it on
        // purpose: a display does not turn white because the room's lights came
        // on, and a second palette is a second design to keep in step.
        let light = theme(Appearance::Light, FontId::FIRST, FontId::FIRST);
        assert_eq!(light.palette, theatre().palette);
        assert!(light.is_dark(), "which appearance a theme is follows its palette");
    }

    #[test]
    fn the_console_says_two_words_to_the_library_and_no_more() {
        // The palette and the corner are supplied; the sizes and the type scale
        // are the library's. Restating those to change the look is how a theme
        // comes to disagree with the library about what a heading is.
        let library = Theme::new(Appearance::Dark, FontId::FIRST, FontId::FIRST);
        assert_eq!(theatre().metrics, library.metrics);
        assert_eq!(theatre().corners, CornerStyle::Square, "every corner is a right angle");
    }

    #[test]
    fn the_accent_is_light_and_not_a_hue() {
        // The design's one wager: selection and the primary action are *lit*,
        // not painted, so the accent has to be brighter than every ink and
        // carry no saturation worth the name.
        let accent = THEATRE.accent;
        let spread =
            accent.r.max(accent.g).max(accent.b) - accent.r.min(accent.g).min(accent.b);
        assert!(spread < 8, "an accent with a hue is a paint, not a light");
        assert!(accent.luminance() > THEATRE.text.luminance(), "lit means brighter than ink");
    }

    #[test]
    fn keyboard_focus_and_selection_are_two_facts_with_two_marks() {
        // A focused row and the chosen row can be different rows, and a
        // palette whose ring and selection hairline are one colour cannot say
        // so. The ring is the deep accent — no new colour — and it still has
        // to read as a boundary against the surface it rings.
        assert_ne!(THEATRE.border_focus, THEATRE.accent, "focus must not wear selection's light");
        assert_eq!(THEATRE.border_focus, THEATRE.accent_deep, "the ring is the deep accent");
        assert!(THEATRE.border_focus.contrast_ratio(THEATRE.surface) >= 3.0);
    }

    #[test]
    fn the_palette_holds_the_librarys_own_legibility_law() {
        // The same battery the library runs over its own palettes, so THEATRE
        // cannot silently regress a pairing the library already guards.
        THEATRE.assert_legible("THEATRE");
    }

    #[test]
    fn the_type_marks_are_the_sizes_the_window_was_tuned_at() {
        // The ramp lives here as named marks so a size cannot drift in one
        // place without the others; these hold the marks where they stand.
        let lead: El<Nothing> = emphatic("mongod");
        assert_eq!(lead.style().ink.size, Some(EMPHATIC));

        let word: El<Nothing> = state_word(Status::Ok, "RUNNING".into());
        assert_eq!(word.style().ink.size, Some(STATE_WORD));

        let cited: El<Nothing> = reading("RUNNING", "2/4".into(), None);
        let value = cited.child(1).expect("the value beside the label");
        assert_eq!(value.style().ink.size, Some(READING_VALUE));
    }

    #[test]
    fn healthy_is_a_cyan_tinted_steel_and_never_a_green() {
        // The palette holding up the rule the whole rail depends on. A green ok
        // lights every working service, and an interface that lights what is
        // working cannot say what is not.
        let ok = THEATRE.ok;
        assert!(ok.b > ok.g, "a healthy hue that leans green is the defect");
        assert!(ok.luminance() < THEATRE.accent.luminance(), "quieter than the accent");
        assert!(ok.luminance() > THEATRE.idle.luminance(), "and brighter than idle");
    }

    #[test]
    fn the_ground_is_ruled_along_its_top_edge_and_bare_everywhere_else() {
        // The ruler is the one decoration the window keeps: a division where
        // the scale says one falls, in the margin above the masthead, and the
        // palette's own gradient everywhere else.
        let mut canvas = Canvas::new(100, 100, 1.0);
        ground(&mut canvas, &theatre());
        let at = |x: u32, y: u32| canvas.pixels()[(y * 100 + x) as usize];
        assert_ne!(at(10, 1), at(5, 1), "a division is a step above the ground");
        assert_ne!(at(50, 5), at(10, 5), "a major division reaches further than a minor one");
        assert_eq!(at(5, 50), at(48, 50), "the ground below the ruler is untouched");
    }

    #[test]
    fn text_is_legible_on_every_ground_it_is_set_on() {
        for ground in [THEATRE.background, THEATRE.surface, THEATRE.sunken, THEATRE.raised] {
            assert!(
                THEATRE.text.luminance() - ground.luminance() > 0.5,
                "body text is too close to a ground it is set on"
            );
        }
    }

    #[test]
    fn a_working_service_is_stated_quietly_and_a_broken_one_is_not() {
        // The rule the whole rail depends on: green on every healthy row is
        // exactly what stops a red one being seen.
        assert_eq!(state_ink(Status::Ok), Tone::Muted);
        assert_eq!(state_ink(Status::Idle), Tone::Muted);
        assert_eq!(state_ink(Status::Bad), Tone::Bad);
        assert_eq!(state_ink(Status::Warn), Tone::Warn);
    }

    #[test]
    fn a_lamp_says_what_it_is_for_anything_that_cannot_see_it() {
        let lit: El<Nothing> = lamp(Status::Ok);
        assert_eq!(lit.accessibility_role(), rui::Role::Status);
        assert_eq!(lit.accessible_name(), "ok");
        let unlit: El<Nothing> = lamp(Status::Idle);
        assert_eq!(unlit.accessible_name(), "idle");
    }

    #[test]
    fn a_link_being_made_is_swept_and_a_link_that_is_made_is_lamped() {
        // The sweep is the one loop in the window, so which mark is drawn is
        // what decides whether the console can idle.
        let reaching: El<Nothing> = link_mark(Status::Warn, "CONNECTING".into(), true);
        let head = reaching.child(0).expect("a mark before the word");
        assert_eq!(head.style().width, rui::Length::Fixed(SWEEP));

        let made: El<Nothing> = link_mark(Status::Ok, "CONNECTED".into(), false);
        let head = made.child(0).expect("a mark before the word");
        assert_eq!(head.style().width, rui::Length::Fixed(LAMP_WIDTH));
    }

    #[test]
    fn a_pulse_dims_without_ever_going_out() {
        // A mark that disappears at the bottom of its cycle tells the reader who
        // glanced at that moment nothing at all.
        for step in 0..16 {
            let strength = pulse(step as f32 / 16.0);
            assert!(strength >= PULSE_FLOOR, "a pulse went further out than its floor");
            assert!(strength <= 1.0, "a pulse went brighter than the lamp itself");
        }
    }

    #[test]
    fn a_mark_gets_the_whole_face_of_the_button_carrying_it() {
        // The defect this exists to keep out: a button's twelve units of
        // padding each side, at twenty-six units wide, leaves two units for the
        // mark — and a cross that does not fit is drawn as an ellipsis.
        let dismiss: El<Nothing> = icon_button("\u{00d7}", "Dismiss");
        assert_eq!(dismiss.style().padding.horizontal(), 0.0);
        assert_eq!(dismiss.style().width, rui::Length::Fixed(ICON_BUTTON));
        assert_eq!(dismiss.accessible_name(), "Dismiss");
    }

    #[test]
    fn the_wedge_takes_no_room_when_nothing_is_chosen() {
        // Drawn at zero height rather than omitted, so choosing a row does not
        // change how wide the rest of it is.
        let absent: El<Nothing> = wedge(false);
        assert_eq!(absent.style().height, rui::Length::Fixed(0.0));
        let present: El<Nothing> = wedge(true);
        assert!(matches!(present.style().height, rui::Length::Fraction(_)));
    }
}
