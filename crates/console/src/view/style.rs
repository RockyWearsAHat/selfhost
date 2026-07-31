//! The console's house style: the colours it is drawn in, the marks it makes
//! itself, and why they are those shapes.
//!
//! # The console supplies its own colours
//!
//! `rui` builds a [`Theme`] from an appearance and two faces, and it hands an
//! application the seam to replace any part of it: [`App::theme`] takes a
//! *function* of the appearance, and [`Theme::with_palette`] swaps the colours
//! while leaving the metrics, the corner shape and the type scale exactly as the
//! library chose them. So [`HUD`] is the one colour decision in the program —
//! a lit instrument's display rather than a desktop's paper — and [`theme`] is
//! where it is handed over. Nothing below either of them names a colour.
//!
//! What is *not* supplied is a second set of sizes or a second type scale.
//! Restating those to change the palette is how an application ends up with a
//! theme that disagrees with the library about what a heading is.
//!
//! The console also supplies its own ground, through the seam
//! [`rui::App::ground`] opens for exactly this: [`ground`] scribes a faint
//! graticule under the plates. An earlier design ruled a graph-paper grid
//! *across* the window and it went, rightly, as costume — the difference here
//! is where the mark lives and how loud it is. The plates are opaque, so the
//! graticule exists only in the chassis around and between them, at a
//! twentieth of the accent; it decorates the one part of the window that
//! reports nothing, and it cannot sit behind a single word.
//!
//! [`App::theme`]: rui::App::theme
//! [`Theme`]: rui::Theme
//! [`Theme::with_palette`]: rui::Theme::with_palette
//!
//! # The corner: the desktop owns what you press, the console owns what it
//! reports with
//!
//! `Canvas` draws a rectangle's corners as [`Corner::Round`] or
//! [`Corner::Cut`], for the same money, and says why the choice matters: a
//! rounded corner reads as a card in a document and a cut one reads as a panel
//! bolted into a rack. The library's own theme then rounds *everything*, and
//! its reasoning is worth reading before disagreeing with it — a chamfer
//! repeated on every panel, button, field and tag stopped saying *this program
//! is about a machine* and started saying *this program is pretending to be
//! from a film*.
//!
//! Both arguments are right, about different things, and the line between them
//! is what a mark is *for*:
//!
//! - **Anything the operator presses keeps the desktop's shape.** A button, a
//!   field and a segmented control are things every program on the machine also
//!   has, and there is no credit for disagreeing with the platform about what a
//!   button looks like. Those stay rounded, because the theme rounds them and
//!   the console does not fight it — which is also why the theme's own
//!   [`CornerStyle`] is left alone rather than set to [`CornerStyle::Cut`]:
//!   one word there would chamfer every control in the window.
//! - **Anything the console *reports on* is cut.** The plates, the rail's rows,
//!   the lamp beside a service, the wedge against the chosen row, the bar
//!   against a line of standard error, the mark in the masthead — none of these
//!   is a control, none has an equivalent in the desktop's own vocabulary, and
//!   every one of them exists to state a fact about a machine. A chamfer on
//!   those is not a costume, because there is nothing underneath it pretending
//!   to be something else. A row is on this side of the line even though it can
//!   be chosen: what it is is a readout, and being selectable does not make it a
//!   button.
//!
//! [`CornerStyle`]: rui::CornerStyle
//! [`CornerStyle::Cut`]: rui::CornerStyle::Cut
//!
//! What that buys is the character without the cost: a rack of chamfered plates
//! carrying rounded buttons reads as instrumentation laid on a desktop program,
//! which is exactly what this is. [`brackets`] is the same argument at the
//! corners themselves.
//!
//! # One accent, and status only where there is something to report
//!
//! `Tone::Accent` is spent on two things and nothing else: the primary action,
//! and which row is chosen. It is never a decoration and never a status.
//!
//! Status hues are spent even more narrowly. Every row used to set its state
//! word in its own hue, which lit a healthy machine up in green — and an
//! interface whose job is to say when something is wrong cannot say it if a
//! working service is also lit. So the *word* is quiet unless it needs
//! attention, and what carries the state at rest is the lamp: a small saturated
//! mark against a quiet ground. See [`state_ink`].
//!
//! [`HUD`] is built to keep that true at the level of the palette. Healthy is
//! not a green but a cyan-tinted steel, one step above the ink a label is set
//! in, so a rail of running services is quiet; amber and red are the only
//! saturated hues on screen other than the accent, and neither of them appears
//! without a cause.
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
//! Glow is spent on the same short list. [`rui::El::glow`] and
//! [`rui::Canvas::arc_glow`] say *this is live*: the lamp of a running service,
//! the plate that has been chosen, the arc that is sweeping, the lamp that is
//! pulsing. A halo on one element is a fact about that element; a halo on every
//! element is a filter over the window, and the fact is gone.

use rui::{
    Align, Anchor, Appearance, Canvas, Color, Corner, El, FontId, Palette, Point, Radius, Rect,
    Role, Size, Status, Theme, Tone, button, col, draw, heading, micro, row, spacer, text,
};
use std::f32::consts::{FRAC_PI_2, TAU};

/// The colours the console is drawn in: an instrument's display, not paper.
///
/// A near-black navy ground, one electric cyan, and steel for everything that is
/// merely present. The cyan is the only saturated colour at rest, which is what
/// lets amber and red mean something the moment either appears — see the
/// module's own notes on where a hue is allowed to be spent.
///
/// Healthy is deliberately not a green. It is a cyan-tinted steel, a step above
/// the muted ink and a step below the accent, so that a lamp on a running
/// service reads as *lit* without a rail of them lighting up the window.
pub const HUD: Palette = Palette {
    background: Color::rgb(0x0a, 0x12, 0x20),
    background_deep: Color::rgb(0x05, 0x0a, 0x12),
    surface: Color::rgb(0x0d, 0x18, 0x26),
    surface_deep: Color::rgb(0x0a, 0x14, 0x20),
    sheen: Color::rgb(0x16, 0x2c, 0x40),
    raised: Color::rgb(0x12, 0x22, 0x36),
    sunken: Color::rgb(0x06, 0x0e, 0x18),
    // The hairline every panel is outlined in: the accent at just over a third,
    // so an edge is cyan where it is looked at and grey where it is not.
    border: Color::rgba(0x5f, 0xd9, 0xf2, 0x59),
    border_focus: Color::rgb(0x8f, 0xe9, 0xff),
    text: Color::rgb(0xdf, 0xf6, 0xff),
    text_muted: Color::rgb(0x6e, 0x8c, 0xa0),
    text_on_accent: Color::rgb(0x04, 0x12, 0x1c),
    accent: Color::rgb(0x5f, 0xd9, 0xf2),
    accent_deep: Color::rgb(0x2b, 0x93, 0xb4),
    accent_light: Color::rgb(0x9b, 0xeb, 0xfb),
    ok: Color::rgb(0x6e, 0x9a, 0xac),
    ok_tint: Color::rgb(0x0c, 0x1c, 0x28),
    warn: Color::rgb(0xff, 0xb4, 0x54),
    warn_tint: Color::rgb(0x26, 0x1a, 0x0c),
    bad: Color::rgb(0xff, 0x52, 0x52),
    bad_tint: Color::rgb(0x2a, 0x11, 0x16),
    idle: Color::rgb(0x4c, 0x64, 0x76),
    idle_tint: Color::rgb(0x0c, 0x16, 0x22),
    shadow: Color::rgba(0x00, 0x02, 0x06, 0x4c),
};

/// The theme every frame is drawn with: the library's, in the console's colours.
///
/// A function of the appearance because that is the shape of the seam, and it
/// answers the same palette either way. A display is not a document: the room's
/// lights coming on does not turn an instrument's face white, and a "light"
/// variant of this palette would be a second design to keep in step with the
/// first for the sake of a window nobody would recognise as the same program.
/// [`rui::Theme::is_dark`] reads the palette rather than what it was built with,
/// so everything derived from it is derived correctly under either desktop.
pub fn theme(_appearance: Appearance, ui_font: FontId, mono_font: FontId) -> Theme {
    Theme::new(Appearance::Dark, ui_font, mono_font).with_palette(HUD)
}

/// How far apart the graticule the window's ground is scribed with repeats.
///
/// The plates cover most of the window, so what the graticule actually shows
/// through is the chassis around and between them — the window's margins and
/// gutters. Close enough that even a sixteen-unit margin catches a line or
/// two, which is what makes the gaps read as a surface the plates are mounted
/// on rather than as nothing.
const GRID: f32 = 32.0;

/// How much of the accent a graticule line keeps.
///
/// Faint on purpose: the ground is the one mark in the window that reports
/// nothing, so it must be below the threshold at which it competes with
/// anything that does.
const GRID_LINE: f32 = 0.05;

/// Every how many crossings a registration cross is scribed.
const GRID_CROSS_EVERY: u32 = 4;

/// How long each arm of a registration cross is.
const GRID_CROSS: f32 = 3.5;

/// How much of the accent a cross keeps: a step above the lines it registers.
const GRID_CROSS_ALPHA: f32 = 0.11;

/// The window's ground: the palette's gradient, scribed with a graticule.
///
/// This is the console's half of the [`rui::App::ground`] seam. The library
/// paints a bare window as a flat gradient, which is right for a document and
/// wrong for this program: an instrument's chassis is machined, and the plates
/// the console reports on should read as mounted *on* something rather than
/// floating in a void. A fine grid in the accent at a twentieth of its
/// strength, registered every fourth crossing with a small cross, is that
/// something — visible in the margins and gutters, and covered without
/// ceremony wherever a plate has a reading to make.
///
/// It asks for no phase and draws nothing that moves, so it costs the window
/// none of its ability to idle.
pub fn ground(canvas: &mut Canvas, theme: &Theme) {
    canvas.clear_vertical(theme.palette.background, theme.palette.background_deep);
    let bounds = canvas.bounds();

    let line = theme.palette.accent.fade(GRID_LINE);
    let mut x = GRID;
    while x < bounds.w {
        canvas.line(Point::new(x, 0.0), Point::new(x, bounds.h), 1.0, line);
        x += GRID;
    }
    let mut y = GRID;
    while y < bounds.h {
        canvas.line(Point::new(0.0, y), Point::new(bounds.w, y), 1.0, line);
        y += GRID;
    }

    let cross = theme.palette.accent.fade(GRID_CROSS_ALPHA);
    let step = GRID * GRID_CROSS_EVERY as f32;
    let mut x = step;
    while x < bounds.w {
        let mut y = step;
        while y < bounds.h {
            canvas.line(Point::new(x - GRID_CROSS, y), Point::new(x + GRID_CROSS, y), 1.0, cross);
            canvas.line(Point::new(x, y - GRID_CROSS), Point::new(x, y + GRID_CROSS), 1.0, cross);
            y += step;
        }
        x += step;
    }
}

/// How far a plate's corner is chamfered, in logical units.
///
/// Large enough to be seen as a cut and not as a corner that failed to round.
/// It is also where a corner bracket's elbow sits, so the two marks agree about
/// where the plate's corner actually is; see [`brackets`].
const PLATE_CUT: f32 = 7.0;

/// How far a mark the console draws itself is cut, as a share of its width.
///
/// One number, so the masthead's mark and anything else cut to its own width
/// are visibly the same family rather than two chamfers somebody chose
/// separately.
const CUT: f32 = 0.3;

/// How big the mark beside the wordmark is drawn.
const MARK: f32 = 22.0;

/// How long each arm of a corner bracket is.
const BRACKET_ARM: f32 = 12.0;

/// How thick it is drawn, in logical units.
///
/// Thicker than the hairline it sits on. A bracket in the same weight as the
/// outline is an outline with gaps in it; what says *bracket* is that the corner
/// is drawn heavier than the edge running away from it.
const BRACKET: f32 = 1.8;

/// How far a bracket sits inside the plate's own edge.
const BRACKET_INSET: f32 = 2.5;

/// How wide a status lamp is.
///
/// # Why the lamp is a slot and not a pip
///
/// A chamfer has to be *seen* to mean anything, and at eight or ten units
/// square it is not: cut a tenth of its width off each corner of a ten-unit
/// square and, once it is antialiased at the size a screen actually draws it,
/// what comes out is a circle. Cut it half and what comes out is a diamond,
/// which reads as a warning sign whatever colour it is in. Both were drawn and
/// looked at before this was settled.
///
/// A tall slot has edges long enough to carry the cut. Five by fourteen with
/// two units off each corner reads as an indicator machined into a panel at the
/// size it is drawn — most clearly when it is *unlit*, where the outline is
/// plainly a chamfered slot and not a rounded pill.
const LAMP_WIDTH: f32 = 5.0;

/// How tall it is; see [`LAMP_WIDTH`].
const LAMP_HEIGHT: f32 = 14.0;

/// How far its corners are cut, in logical units.
const LAMP_CUT: f32 = 2.0;

/// How far a lit lamp's halo reaches past the slot casting it.
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
/// Held to the height of the two lines beside it rather than to the strip it
/// sits in. Every unit it takes is a unit off the sentence and the readings on a
/// narrow window, and a larger dial does not report a proportion any better.
///
/// Four units over what first read as a dial: at the original size the scale,
/// the ring and the sweep had no air between them to be told apart in, and
/// widening the strip's tallest mark by four units is still short of the room
/// the sentence beside it needs.
const GAUGE: f32 = 38.0;

/// How wide its band is.
///
/// Thin, so the unlit track reads as a hairline scribed round the dial and not
/// as a second ring competing with the scale outside it.
const GAUGE_BAND: f32 = 2.0;

/// How far its lit arc's halo reaches either side of that band.
///
/// Its own number rather than [`SWEEP`]'s: a glow this size on a band this
/// thin is already a bloom, and the sweep's blur is tuned to a band nearly
/// twice as wide.
const GAUGE_GLOW: f32 = 3.0;

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

/// How big the sweep that reports a connection being made is drawn.
const SWEEP: f32 = 14.0;

/// How wide its band is.
const SWEEP_BAND: f32 = 1.6;

/// How far its lit arc's halo reaches either side of that band.
const SWEEP_GLOW: f32 = 5.0;

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
/// A chamfered plate, outlined in the cyan hairline, shaded down its height and
/// bracketed at its corners. The shadow is what says the surface is lying on the
/// window rather than drawn on it; seven units of blur under a corner this
/// square reads as a plate rather than as a card that has been squared off.
///
/// The brackets are a layer, so they cost the contents nothing: a plate is the
/// same size and holds the same rows whether or not its corners are marked.
pub fn plate<S>(children: impl rui::Children<S>) -> El<S> {
    col(children)
        .gradient(Tone::Surface, Tone::SurfaceDeep)
        .border(1.0, Tone::Border)
        .round(Radius::Cut(PLATE_CUT))
        .shadow(7.0)
        .pad(12.0)
        .add(sheen())
        .add(brackets(Tone::Border))
}

/// How much of the light accent a plate's top sheen keeps.
const SHEEN: f32 = 0.14;

/// The highlight along a plate's top edge: what says the surface is lit.
///
/// One hairline in the light accent, run just inside the border between the
/// chamfers. A plate whose gradient merely darkens downward is shaded; one
/// whose top edge also catches the light is *lit from above*, which is the
/// difference between a rectangle in a flat colour and a machined surface
/// under the room's light. It is a layer for the same reason [`brackets`] is:
/// a highlight costs the contents nothing.
fn sheen<S>() -> El<S> {
    draw(Size::new(0.0, 0.0), |painter, rect| {
        let color = painter.color(Tone::AccentLight).fade(SHEEN);
        painter.canvas().line(
            Point::new(rect.x + PLATE_CUT + 1.0, rect.y + 1.0),
            Point::new(rect.max_x() - PLATE_CUT - 1.0, rect.y + 1.0),
            1.0,
            color,
        );
    })
    .layer(Anchor::Over)
}

/// Four corner brackets, drawn over whatever they are added to.
///
/// The mark that says a rectangle is a *frame around a reading* rather than a
/// box with something in it. Each is two short strokes meeting where the plate's
/// chamfer ends, so the bracket and the cut corner agree about where the corner
/// is instead of crossing each other.
///
/// It is a layer rather than a child, which is the whole reason this can be
/// added to anything: a layer takes no room from its parent and is measured to
/// the parent's own rectangle, so bracketing a strip cannot change what fits
/// inside it.
pub fn brackets<S>(tone: Tone) -> El<S> {
    draw(Size::new(0.0, 0.0), move |painter, rect| {
        let color = painter.color(tone);
        // Held to a third of the shortest side, so a small strip is bracketed
        // rather than outlined by four arms that meet in the middle of an edge.
        let arm = BRACKET_ARM.min(rect.w / 3.0).min(rect.h / 3.0);
        if arm <= 0.0 {
            return;
        }

        let (left, right) = (rect.x + BRACKET_INSET, rect.max_x() - BRACKET_INSET);
        let (top, bottom) = (rect.y + BRACKET_INSET, rect.max_y() - BRACKET_INSET);
        let mut corner = |x: f32, y: f32, along: f32, down: f32| {
            let canvas = painter.canvas();
            canvas.line(
                Point::new(x + along * PLATE_CUT, y),
                Point::new(x + along * (PLATE_CUT + arm), y),
                BRACKET,
                color,
            );
            canvas.line(
                Point::new(x, y + down * PLATE_CUT),
                Point::new(x, y + down * (PLATE_CUT + arm)),
                BRACKET,
                color,
            );
        };
        corner(left, top, 1.0, 1.0);
        corner(right, top, -1.0, 1.0);
        corner(left, bottom, 1.0, -1.0);
        corner(right, bottom, -1.0, -1.0);
    })
    .layer(Anchor::Over)
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

/// A status lamp: a chamfered slot, lit when the service has something to say.
///
/// Filled for [`Status::Ok`], [`Status::Warn`], and [`Status::Bad`], and left
/// as an outline for [`Status::Idle`]. That is the state said twice by two
/// different means — a hue and a shape — so a reader who receives no colour at
/// all still sees which services are running.
///
/// A lit lamp casts a halo in its own colour, because a lamp that is on throws
/// light and one that is off does not; an idle lamp is an outline with nothing
/// around it. The two that want attention pulse instead of burning steady, on
/// the one loop this interface allows a mark that is waiting. See [`PULSE`].
///
/// It carries the state's word for anything that cannot see either, so the row
/// it sits in is named after what it shows.
pub fn lamp<S>(status: Status) -> El<S> {
    let tone = Tone::ink(status);
    let lit = !matches!(status, Status::Idle);
    let waiting = matches!(status, Status::Warn | Status::Bad);
    draw(Size::new(LAMP_WIDTH, LAMP_HEIGHT), move |painter, rect| {
        let corner = Corner::Cut(LAMP_CUT);
        let color = painter.color(tone);
        if !lit {
            painter.canvas().stroke(rect, corner, 1.0, color);
            return;
        }
        let strength = if waiting { pulse(painter.phase("pulse", PULSE)) } else { 1.0 };
        let halo = color.fade(HALO_STRENGTH * strength);
        painter.canvas().shadow(rect, corner, LAMP_HALO, 0.0, halo);
        painter.canvas().fill(rect, corner, color);
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

/// A sweep going round: what a connection being made looks like.
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
        let start = TOP + painter.phase("sweep", SWEEP_PERIOD) * TAU;
        let canvas = painter.canvas();
        canvas.ring(center, radius, SWEEP_BAND, color.fade(TRACK * 1.5));
        canvas.arc_glow(center, radius, SWEEP_BAND, start, SWEEP_ARC, SWEEP_GLOW, color.fade(0.45));
        canvas.arc(center, radius, SWEEP_BAND, start, SWEEP_ARC, color);
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
/// Three rings, drawn outside in, each with air between it and its neighbour:
/// a scale of short ticks, then a gap, then a thin low-alpha track, then the
/// lit arc on that same track with a subtle glow of its own. The scale and the
/// track used to be drawn back to back with no gap and ticks nearly as long as
/// the track's own radius, which is what made the whole mark read as one
/// spiked blot rather than as three things at three radii — see [`GAUGE_TICK`]
/// and [`GAUGE_TICK_GAP`].
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
            canvas.arc_glow(center, radius, GAUGE_BAND, TOP, swept, GAUGE_GLOW, accent.fade(0.4));
            canvas.arc(center, radius, GAUGE_BAND, TOP, swept, accent);
        }
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

/// A faint reticle, centred behind an empty pane's own words.
///
/// The room a pane's watermark used to sit in was true blank space, and a
/// window that has never had a service chosen read as unfinished rather than
/// as waiting. This is the same argument the sweep and the gauge make at the
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
    })
    .layer(Anchor::Over)
}

/// The bar down the leading edge of a strip that has something to announce.
///
/// Cut rather than rounded, for the reason every mark the console reports with
/// is: a pale tinted rectangle is easy to read past, and these strips appear
/// exactly when something must not be read past.
pub fn flag<S>(status: Status) -> El<S> {
    let tone = Tone::ink(status);
    draw(Size::new(WEDGE, 0.0), move |painter, rect| {
        let color = painter.color(tone);
        painter.canvas().fill(rect, Corner::Cut(rect.w * 0.9), color);
    })
    .w(WEDGE)
}

/// The mark against the chosen row: a cut wedge on its leading edge.
///
/// It grows out of the row's own edge rather than sitting inside it, so the eye
/// is carried from the row it left to the row it landed on. Cut on its trailing
/// corners only in effect — the leading pair are flush against the rail's
/// padding — which is what makes it read as a tab machined into the edge rather
/// than as a rounded pill parked beside the name.
pub fn wedge<S>(chosen: bool) -> El<S> {
    draw(Size::new(WEDGE, 0.0), move |painter, rect| {
        if !chosen {
            return;
        }
        let color = painter.color(Tone::Accent);
        painter.canvas().fill(rect, Corner::Cut(rect.w * 0.9), color);
    })
    .w(WEDGE)
    .h(if chosen { rui::Length::Fraction(0.56) } else { rui::Length::Fixed(0.0) })
    .align_self(Align::Center)
}

/// The console's own mark: a chamfered tile carrying three lit rack units.
///
/// Drawn rather than shipped as an image, for the same reason no font is
/// shipped: it costs nothing, it is correct at every size, and it takes its
/// colours from the theme, so a change of palette reaches it instead of leaving
/// one bitmap behind in the colours of the design before it.
///
/// The tile is the one place the accent appears without being pressed, and it
/// earns that by being the thing the window is named after.
pub fn mark<S>() -> El<S> {
    draw(Size::new(MARK, MARK), |painter, rect| {
        let (light, deep) = (painter.color(Tone::AccentLight), painter.color(Tone::AccentDeep));
        painter.canvas().fill_vertical(rect, Corner::Cut(rect.w * CUT), light, deep);

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

/// A machine's state, set as a word beside whatever it is about.
///
/// Small capitals, tracked as [`rui::Theme::state`] tracks them, in the ink
/// [`state_ink`] chose. Bare rather than inside a tag: a tag is chrome around
/// one word, and on a narrow rail that chrome takes the room the service's own
/// name needs — and the name is the part that tells one row from another.
pub fn state_word<S>(status: Status, label: String) -> El<S> {
    text(label).text_size(10.5).tracking(0.4).color(state_ink(status))
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
            .text_size(12.5)
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
    fn hud() -> Theme {
        theme(Appearance::Dark, FontId::FIRST, FontId::FIRST)
    }

    #[test]
    fn the_console_is_the_same_instrument_under_either_desktop() {
        // The seam is a function of the appearance and this one ignores it on
        // purpose: a display does not turn white because the room's lights came
        // on, and a second palette is a second design to keep in step.
        let light = theme(Appearance::Light, FontId::FIRST, FontId::FIRST);
        assert_eq!(light.palette, hud().palette);
        assert!(light.is_dark(), "which appearance a theme is follows its palette");
    }

    #[test]
    fn the_supplied_palette_changes_the_colours_and_nothing_else() {
        // What the seam is for: the console names colours, and leaves the sizes,
        // the type scale and the corner shape to the library that chose them.
        let library = Theme::new(Appearance::Dark, FontId::FIRST, FontId::FIRST);
        assert_eq!(hud().metrics, library.metrics);
        assert_eq!(hud().corners, library.corners, "a control keeps the desktop's shape");
    }

    #[test]
    fn healthy_is_a_cyan_tinted_steel_and_never_a_green() {
        // The palette holding up the rule the whole rail depends on. A green ok
        // lights every working service, and an interface that lights what is
        // working cannot say what is not.
        let ok = HUD.ok;
        assert!(ok.b > ok.g, "a healthy hue that leans green is the defect");
        assert!(ok.luminance() < HUD.accent.luminance(), "quieter than the accent");
        assert!(ok.luminance() > HUD.idle.luminance(), "and brighter than idle");
    }

    #[test]
    fn the_ground_is_scribed_and_the_room_between_the_lines_is_even() {
        // The graticule is the chassis the plates are mounted on: a line where
        // the grid says one goes, and the palette's own gradient everywhere
        // else — a texture over the whole ground would be noise, not a scribe.
        let mut canvas = Canvas::new(100, 100, 1.0);
        ground(&mut canvas, &hud());
        let at = |x: u32, y: u32| canvas.pixels()[(y * 100 + x) as usize];
        assert_ne!(at(32, 10), at(16, 10), "a graticule line is a step above the ground");
        assert_eq!(at(16, 10), at(48, 10), "the ground between lines is untouched");
    }

    #[test]
    fn text_is_legible_on_every_ground_it_is_set_on() {
        for ground in [HUD.background, HUD.surface, HUD.sunken, HUD.raised] {
            assert!(
                HUD.text.luminance() - ground.luminance() > 0.5,
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
    fn a_bracket_takes_no_room_from_what_it_frames() {
        // The whole reason it is a layer: bracketing a strip must not change
        // what fits inside it.
        let frame: El<Nothing> = brackets(Tone::Border);
        assert_eq!(frame.anchor(), Some(Anchor::Over));
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
