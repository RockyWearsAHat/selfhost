//! The console's house style: the marks it makes itself, and why they are those
//! shapes.
//!
//! `rui` supplies the palette, the metrics, and the type scale, and there is no
//! seam through which an application hands it a different [`Theme`] — the theme
//! is built inside `App::draw_into` from an appearance and two faces. So this is
//! not a second theme. It is the small set of marks the console draws with its
//! *own* painter, kept in one place so the whole window's character is decided
//! here rather than separately by each view that happens to draw something.
//!
//! [`Theme`]: rui::Theme
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
//!   field, a segmented control and the plates they sit on are things every
//!   program on the machine also has, and there is no credit for disagreeing
//!   with the platform about what a button looks like. Those stay rounded,
//!   because `rui` rounds them and the console does not fight it.
//! - **Anything the console *reports with* is cut.** The lamp beside a service,
//!   the wedge against the chosen row, the bar against a line of standard
//!   error, the mark in the masthead — none of these is a control, none has an
//!   equivalent in the desktop's own vocabulary, and every one of them exists to
//!   state a fact about a machine. A chamfer on those is not a costume, because
//!   there is nothing underneath it pretending to be something else.
//!
//! What that buys is the character without the cost: a rail of four chamfered
//! lamps against rounded rows reads as instrumentation laid on a desktop
//! program, which is exactly what this is.
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
//! # Motion
//!
//! Every animation on screen is a hover easing on `Metrics::motion`, which the
//! library runs for nothing. A control the console draws itself reads
//! `Visual::lit` — the same eased value every built-in control animates on — so
//! a hand-drawn mark and a button settle on one curve.
//!
//! Nothing else here animates, and not for want of taste: `Memory::ease` is the
//! library's frame-rate-independent easing and `Painter` carries no `Memory`, so
//! an application cannot ease a value of its own. A count that ran up to its new
//! number, or a row that settled into place, needs that seam and is left undone
//! rather than faked with a frame counter.

use rui::{Align, Corner, El, Radius, Rect, Size, Status, Tone, button, col, draw, row, text};

/// How far a plate's corner is rounded, in logical units.
///
/// Three rather than the theme's eight. The shape is still the desktop's — a
/// radius, not a chamfer — but at eight units a large surface reads as a card
/// lying on a page, and at three it reads as a sheet with its edges broken.
/// That is the whole of the difference, and it is the most a framed surface can
/// say about its character without picking a fight with the platform.
const PLATE_CORNER: f32 = 3.0;

/// How far a mark the console draws itself is cut, as a share of its width.
///
/// One number, so the masthead's mark and anything else cut to its own width
/// are visibly the same family rather than two chamfers somebody chose
/// separately.
const CUT: f32 = 0.3;

/// How big the mark beside the wordmark is drawn.
const MARK: f32 = 22.0;

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

/// How wide the wedge against the chosen row is.
const WEDGE: f32 = 3.0;

/// A framed surface: the rail, the detail pane, the readout bank.
///
/// [`rui::panel`] with the console's own corner and a shallower shadow. The
/// shadow is what says the surface is lying on the window rather than drawn on
/// it; nine units of blur under a corner this square reads as a card that has
/// been squared off, and seven reads as a plate.
pub fn plate<S>(children: impl rui::Children<S>) -> El<S> {
    col(children)
        .gradient(Tone::Surface, Tone::SurfaceDeep)
        .border(1.0, Tone::Border)
        .round(Radius::Units(PLATE_CORNER))
        .shadow(7.0)
        .pad(12.0)
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
/// It carries the state's word for anything that cannot see either, so the row
/// it sits in is named after what it shows.
pub fn lamp<S>(status: Status) -> El<S> {
    let tone = Tone::ink(status);
    let lit = !matches!(status, Status::Idle);
    draw(Size::new(LAMP_WIDTH, LAMP_HEIGHT), move |painter, rect| {
        let corner = Corner::Cut(LAMP_CUT);
        let color = painter.color(tone);
        if lit {
            painter.canvas().fill(rect, corner, color);
        } else {
            painter.canvas().stroke(rect, corner, 1.0, color);
        }
    })
    .w(LAMP_WIDTH)
    .h(LAMP_HEIGHT)
    .align_self(Align::Center)
    .role(rui::Role::Status)
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
/// colours from the theme, so it is right in both appearances instead of being
/// one bitmap that suits one of them.
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

/// A hairline that takes whatever room is left between what surrounds it.
pub fn rule<S>() -> El<S> {
    rui::spacer().h(1.0).grow().fill(Tone::Border).align_self(Align::Center)
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

/// A lamp and a state's word, as one mark: what a title line ends with.
///
/// Kept together here so the masthead and the detail pane cannot come to state
/// the same thing two different ways.
pub fn state_mark<S>(status: Status, label: String) -> El<S> {
    row((lamp(status), state_word(status, label))).gap(6.0).align(Align::Center)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A state for trees that do nothing.
    struct Nothing;

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
