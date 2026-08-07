//! The elements an interface is written from.
//!
//! Every one of them is an ordinary [`El`] with a style already set on it, and
//! every one can be adjusted further by the same setters that built it — so a
//! button that needs to be wider is `button("Go").w(120.0)` rather than a
//! variant somebody has to add here first.
//!
//! # The type scale
//!
//! The sizes are named rather than numbered: [`title`], [`heading`], [`text`],
//! [`caption`], [`micro`]. Five is enough for any interface and fewer than any
//! interface ends up with by accident, and naming them is what stops the third
//! screen someone writes from introducing a sixth that is half a unit from one
//! that already exists.
//!
//! # Every one of them states what it is
//!
//! Each constructor here carries its own [`Role`] — the one its kind implies,
//! or a line stating otherwise — so an interface written from these elements is
//! meaningful to a screen reader without a word being added at the call site.
//! A control built instead from [`draw`] states its own with [`El::role`]. See
//! [`accessibility`](crate::accessibility) for why that decision is worth
//! holding, and [`audit`](crate::accessibility::audit) for what holds it.

use crate::accessibility::Role;
use crate::element::{Children, El, Node};
use crate::geom::{Rect, Size};
use crate::paint::Painter;
use crate::style::{Align, Axis, Length, Radius, Tone};
use crate::theme::Status;

/// The size ordinary text is set at.
///
/// Not applied by [`text`], which sets no size at all: the default lives in
/// [`Ink`](crate::Ink) so that a size set on a container reaches everything
/// inside it. This is that same number, named, for a caller sizing something
/// against ordinary text.
pub const BODY_SIZE: f32 = 13.5;

/// The size a pane's name is set at.
pub const TITLE_SIZE: f32 = 15.0;

/// The size a section label is set at.
pub const HEADING_SIZE: f32 = 10.5;

/// The size an aside is set at.
pub const CAPTION_SIZE: f32 = 11.5;

/// The size the smallest annotation is set at.
pub const MICRO_SIZE: f32 = 9.5;

/// The size a figure meant to be read at a glance is set at.
pub const FIGURE_SIZE: f32 = 21.0;

/// The size text the machine produced is set at.
///
/// Smaller than [`BODY_SIZE`], because a fixed-width face at the same size
/// reads larger than a proportional one beside it.
pub const CODE_SIZE: f32 = 11.5;

/// How far a section label's letters are opened up.
///
/// Capitals at ten units pack into a block in a face spaced for lower case.
/// Opening them is what makes a small label legible rather than merely small.
const HEADING_TRACKING: f32 = 0.9;

/// A box that stacks what is in it from top to bottom.
pub fn col<S>(children: impl Children<S>) -> El<S> {
    El::of(Node::Stack).axis(Axis::Column).add(children)
}

/// A box that stacks what is in it from left to right.
///
/// Its children are stretched to its height unless they state one of their own,
/// which is what makes two panels side by side come out the same height without
/// either being told how tall to be. Text is unaffected: a run is drawn on the
/// middle of whatever rectangle it was given, so stretching it changes nothing
/// about where it sits.
pub fn row<S>(children: impl Children<S>) -> El<S> {
    El::of(Node::Stack).axis(Axis::Row).add(children)
}

/// Nothing: a box drawn with no marks at all.
///
/// What space between things is made of, and what a layout under construction is
/// filled with. `spacer().grow()` pushes everything after it to the far end of
/// its row, which is the whole of what a "spacer" ever needs to be.
pub fn spacer<S>() -> El<S> {
    El::of(Node::Stack)
}

/// A run of text.
pub fn text<S>(text: impl Into<String>) -> El<S> {
    El::of(Node::Text(text.into()))
}

/// The name of a window, a pane, or the thing a screen is about.
pub fn title<S>(text: impl Into<String>) -> El<S> {
    El::of(Node::Text(text.into())).text_size(TITLE_SIZE).role(Role::Heading)
}

/// The label that introduces a block: small, muted, opened up.
///
/// Written in capitals by the caller rather than uppercased here, because a
/// heading is sometimes a name, and shouting `MongoDB` back as `MONGODB` is
/// worse than leaving it alone.
pub fn heading<S>(text: impl Into<String>) -> El<S> {
    El::of(Node::Text(text.into()))
        .text_size(HEADING_SIZE)
        .tracking(HEADING_TRACKING)
        .color(Tone::Muted)
        .role(Role::Heading)
}

/// An aside: a unit, an explanation, a timestamp.
pub fn caption<S>(text: impl Into<String>) -> El<S> {
    El::of(Node::Text(text.into())).text_size(CAPTION_SIZE).color(Tone::Muted)
}

/// The smallest annotation there is, set in the fixed-width face.
pub fn micro<S>(text: impl Into<String>) -> El<S> {
    El::of(Node::Text(text.into())).text_size(MICRO_SIZE).color(Tone::Muted).mono()
}

/// A figure worth reading across a room: a count, a total.
pub fn figure<S>(text: impl Into<String>) -> El<S> {
    El::of(Node::Text(text.into())).text_size(FIGURE_SIZE)
}

/// A line of something the machine produced: a path, an address, a log line.
pub fn code<S>(text: impl Into<String>) -> El<S> {
    El::of(Node::Text(text.into())).text_size(CODE_SIZE).mono()
}

/// A paragraph, wrapped to whatever width it is given.
pub fn paragraph<S>(text: impl Into<String>) -> El<S> {
    El::of(Node::Text(text.into())).wrap().w(Length::Fill(1.0))
}

/// A surface lying on the window: outlined, rounded, and lifted by a shadow.
///
/// The three marks are made in the order light would make them — a shadow
/// beneath, a fill shaded very slightly down its height, an outline round it —
/// and none of them is meant to be noticed. What they say together is *this is
/// a thing lying on the window* rather than *this is drawn on the window*.
pub fn panel<S>(children: impl Children<S>) -> El<S> {
    col(children)
        .gradient(Tone::Surface, Tone::SurfaceDeep)
        .border(1.0, Tone::Border)
        .round(Radius::Panel)
        .shadow(9.0)
        .pad(12.0)
}

/// A hairline across whatever contains it.
pub fn divider<S>() -> El<S> {
    El::of(Node::Stack).h(1.0).fill(Tone::Border).role(Role::Separator)
}

/// A button: an outlined surface that lightens under the pointer.
///
/// Its face is a step *above* the surface it sits on — [`Tone::Raised`] shading
/// down to [`Tone::Surface`] — where a panel's own face shades from surface
/// downward. A button drawn in the panel's exact gradient disappears into the
/// panel, leaving a hairline rectangle that reads as a diagram of a button;
/// raising the face is what says *key mounted on a panel*, and it pairs with
/// [`field`], which is sunken for the opposite reason: what is pressed sits
/// proud, what is typed into is a well.
///
/// Ordinary by default. [`El::primary`] fills it with the accent for the one
/// action a screen is mostly for, [`El::danger`] tints it for something
/// destructive, and [`El::ghost`] takes its chrome away entirely for an action
/// that repeats down a list.
pub fn button<S>(label: impl Into<String>) -> El<S> {
    row(text(label).grow().text_align(Align::Center))
        .h(28.0)
        .pad_x(12.0)
        .gradient(Tone::Raised, Tone::Surface)
        .border(1.0, Tone::Border)
        .round(Radius::Control)
        .reactive()
        .role(Role::Button)
}

/// An editable line of text.
///
/// Set in the fixed-width face, because what is typed into a field is nearly
/// always something a machine will read back verbatim — a name, a path, an
/// argument — and it is the face that makes `l` and `1`, or `rn` and `m`, tell
/// each other apart in a string somebody has to check.
pub fn field<S>(value: impl Into<String>) -> El<S> {
    El::of(Node::Field { value: value.into(), placeholder: String::new() })
        .h(28.0)
        .pad_x(8.0)
        .text_size(CODE_SIZE)
        .mono()
        .fill(Tone::Sunken)
        .border(1.0, Tone::Border)
        .round(Radius::Control)
        .focusable()
        .role(Role::Field)
}

/// A tag: a status's own word, on a tint of its own colour.
///
/// The fill carries the colour and the word inside it says which state it is,
/// so nobody has to learn a code. An earlier revision also outlined it and ran a
/// bar of the hue down its leading edge, which made a column of tags read as
/// warning lights before it read as words — and an interface whose job is to say
/// when something is wrong cannot do it if a healthy row is also lit.
pub fn tag<S>(status: Status, label: impl Into<String>) -> El<S> {
    row(text(label))
        .pad_x(8.0)
        .h(18.0)
        .fill(Tone::tint(status))
        .color(Tone::ink(status))
        .text_size(HEADING_SIZE)
        .tracking(0.4)
        .pill()
        .role(Role::Status)
}

/// A dot in a status's own colour.
///
/// What a status looks like where there is no room for its word: down the side
/// of a list, where the same four words on every row say less than four colours
/// do. It still carries the word for anything that cannot see the colour —
/// which is the whole argument for a role being set here rather than left to
/// the caller, since the caller can see it.
pub fn dot<S>(status: Status, radius: f32) -> El<S> {
    let tone = Tone::ink(status);
    draw(Size::new(radius * 2.0, radius * 2.0), move |painter, rect| {
        let color = painter.color(tone);
        let center = rect.center();
        let bounds = Rect::new(center.x - radius, center.y - radius, radius * 2.0, radius * 2.0);
        painter.canvas().fill(bounds, crate::canvas::Corner::Round(radius), color);
    })
    .role(Role::Status)
    .label(word_for(status))
}

/// The word a status is read aloud as.
///
/// Lower case, because it is read as part of a sentence — "mongod, running" —
/// rather than as a heading.
fn word_for(status: Status) -> &'static str {
    match status {
        Status::Ok => "ok",
        Status::Warn => "warning",
        Status::Bad => "failed",
        Status::Idle => "idle",
    }
}

/// A bar filled to `fraction` of its width, on a track.
///
/// The fraction is clamped, so a value derived from a stale total cannot overrun
/// the track. The track is drawn rather than left empty: that is what states the
/// scale, because without it a reader knows how much is filled but not how much
/// filled would be all of it.
pub fn meter<S>(fraction: f32, tone: impl Into<Tone>) -> El<S> {
    let tone = tone.into();
    let fraction = fraction.clamp(0.0, 1.0);
    draw(Size::new(80.0, 6.0), move |painter, rect| {
        let corner = crate::canvas::Corner::Round(rect.h / 2.0);
        let track = painter.color(Tone::Sunken);
        let border = painter.color(Tone::Border);
        painter.canvas().fill(rect, corner, track);
        painter.canvas().stroke(rect, corner, 1.0, border);

        let filled = Rect::new(rect.x, rect.y, rect.w * fraction, rect.h);
        if filled.w > 0.0 {
            let color = painter.color(tone);
            // Shaped to the same corner as the track rather than to its own, so
            // a nearly empty bar is a short rounded stub inside the track and
            // not a circle sitting at its left end.
            let corner = crate::canvas::Corner::Round(filled.w.min(rect.h) / 2.0);
            painter.canvas().fill(filled, corner, color);
        }
    })
    .h(6.0)
    .role(Role::Meter)
    // The scale the track states, stated again for anything that cannot see the
    // track. A percentage rather than the raw fraction, because "sixty-two
    // percent" is what a person would say and "zero point six two" is not.
    .value(format!("{:.0}%", fraction * 100.0))
}

/// Something drawn directly onto the canvas.
///
/// The way out of the widget set, for a sparkline, a logo, or a diagram.
/// `intrinsic` is the size it asks for before the layout has its say.
pub fn draw<S>(
    intrinsic: Size,
    paint: impl Fn(&mut Painter<'_>, Rect) + 'static,
) -> El<S> {
    El::of(Node::Draw { intrinsic, paint: Box::new(paint) })
}

/// A row of tabs, and what to do when one is chosen.
///
/// Each tab is as wide as its own word rather than a share of the row. Dividing
/// the row equally is the obvious thing and it is wrong at any width worth
/// having: three words spread across a wide window sit a hand's breadth apart
/// and read as three unrelated headings rather than as one control.
///
/// What marks the chosen one is a bar under it, on a rule that runs the full
/// width — because what the rule separates is the row from the page, not the
/// tabs from each other.
pub fn tabs<S: 'static>(
    labels: &[&str],
    selected: usize,
    choose: impl Fn(&mut S, usize) + Copy + 'static,
) -> El<S> {
    let tabs: Vec<El<S>> = labels
        .iter()
        .enumerate()
        .map(|(index, label)| {
            let chosen = index == selected;
            col((
                row(text(*label).text_size(12.5)).h(26.0).pad_x(12.0),
                El::of(Node::Stack)
                    .h(2.0)
                    .fill(if chosen { Tone::Accent } else { Tone::Clear }),
            ))
            .key(*label)
            .color(if chosen { Tone::Accent } else { Tone::Muted })
            .hover_color(Tone::Text)
            .role(Role::Tab)
            .selected(chosen)
            .on_click(move |state: &mut S| choose(state, index))
        })
        .collect();

    // The row is the list, which is what gives each tab its place in a set of
    // three without anybody counting: the structure already says it.
    col((row(tabs).role(Role::TabList), divider())).h(28.0)
}

/// A segmented control: several words, one of them chosen.
///
/// For a choice between a handful of named alternatives that all fit on a line —
/// where a menu would hide two of the three answers behind a click.
pub fn segmented<S: 'static>(
    labels: &[&str],
    selected: usize,
    choose: impl Fn(&mut S, usize) + Copy + 'static,
) -> El<S> {
    let cells: Vec<El<S>> = labels
        .iter()
        .enumerate()
        .map(|(index, label)| {
            let chosen = index == selected;
            row(text(*label).grow().text_align(Align::Center).text_size(12.0))
                .key(*label)
                .grow()
                .h(22.0)
                .round(Radius::Units(4.0))
                .fill(if chosen { Tone::Surface } else { Tone::Clear })
                .color(if chosen { Tone::Text } else { Tone::Muted })
                .hover_color(Tone::Text)
                .role(Role::Radio)
                .selected(chosen)
                .on_click(move |state: &mut S| choose(state, index))
        })
        .collect();

    row(cells)
        .h(28.0)
        .pad(3.0)
        .gap(2.0)
        .fill(Tone::Sunken)
        .border(1.0, Tone::Border)
        .round(Radius::Control)
}

impl<S> El<S> {
    /// Fills this button with the accent: the one action a screen is mostly for.
    ///
    /// The fill is the whole of its emphasis. It used to also cast a halo in the
    /// accent, on the argument that the main action should be findable without
    /// reading a label — but a solid block of the only saturated colour on
    /// screen already is, and the halo just made the button look like it was
    /// radiating.
    pub fn primary(self) -> Self {
        self.gradient(Tone::Accent, Tone::AccentDeep)
            .color(Tone::OnAccent)
            .border(0.0, Tone::Clear)
    }

    /// Tints this button for something destructive.
    ///
    /// Tinted rather than filled solid: filled with its own hue it is the
    /// brightest thing on screen and drags the eye to the one control nobody
    /// should reach for by accident — which outshines the primary action, and is
    /// exactly backwards.
    pub fn danger(self) -> Self {
        self.gradient(Tone::BadTint, Tone::BadTint).color(Tone::Bad).border(1.0, Tone::Bad)
    }

    /// Takes this button's chrome away until the pointer is over it.
    ///
    /// For an action that repeats down a list, where a bordered button on every
    /// row would be a column of boxes rather than a column of rows.
    pub fn ghost(self) -> Self {
        self.fill(Tone::Clear).border(0.0, Tone::Clear).hover_fill(Tone::Raised)
    }

    /// What a field shows, dimmed, while it holds nothing.
    ///
    /// Ignored by everything that is not a field, rather than being a separate
    /// type that only fields have: a description reads better when every setter
    /// is available everywhere and the ones that do not apply do nothing.
    pub fn placeholder(mut self, hint: impl Into<String>) -> Self {
        if let Node::Field { placeholder, .. } = &mut self.node {
            *placeholder = hint.into();
        }
        self
    }

    /// Sets this element's own alignment across its parent's axis, overriding
    /// whatever the parent said.
    pub fn align_self(mut self, align: Align) -> Self {
        self.style.self_align = Some(align);
        self
    }

    /// Centres this element's own text within it.
    pub fn center_text(self) -> Self {
        self.text_align(Align::Center)
    }

}

/// A section label with a rule running from it to the far edge.
///
/// A label floating above a block leaves the eye to work out how far down the
/// block extends, and in a window of stacked blocks that guess is wrong as often
/// as it is right. A rule states it: everything under this line belongs to this
/// word. It also does the grouping a box would do, without the cost a box has —
/// which is that ten nested boxes read as a diagram of an interface rather than
/// as one.
pub fn section<S>(label: impl Into<String>, note: Option<String>) -> El<S> {
    row((
        heading(label),
        El::of(Node::Stack).h(1.0).grow().fill(Tone::Border),
        note.map(|note| micro(note)),
    ))
    .h(14.0)
    .gap(8.0)
}

/// A row that names something and shows its value beside it.
///
/// The label column is a fixed width so that values line up down a page without
/// anyone measuring the longest label, but never more than a third of the row —
/// on a narrow pane a fixed column is width taken from the value, and the value
/// is the part worth reading.
///
/// The heading names the value for anything that cannot see the two side by
/// side — this is what `<label for>` is on the web — but only when the value
/// has no words of its own. A field is named "NAME" by the row it sits in; a
/// button is named "Restart" by what it says, and being put in a row does not
/// rename it.
pub fn field_row<S>(label: impl Into<String>, value: El<S>) -> El<S> {
    let label = label.into();
    let value = if value.accessible_name().is_empty() {
        value.label(label.clone())
    } else {
        value
    };
    row((heading(label).w(78.0), value.grow())).gap(8.0).min_h(20.0)
}

/// A row that names a stack of values rather than one line of them.
///
/// [`field_row`] centres its label against the value beside it, which is right
/// for one line and wrong for a stack: centred against four rows, the label
/// floats beside the third and names none of them. Here the label keeps the
/// height of one control and holds the top of the row, so the name sits level
/// with the first entry — where a reader scanning the labels expects the stack
/// to begin. The value keeps its own children's names: a stack's entries name
/// themselves, and renaming the stack after its label would announce every
/// entry identically.
pub fn field_group<S>(label: impl Into<String>, value: El<S>) -> El<S> {
    // The label's box matches a control's height so its word centres on the
    // first entry's own centre line, exactly as `field_row` centres against a
    // single control.
    row((heading(label).w(78.0).h(28.0).align_self(Align::Start), value.grow()))
        .gap(8.0)
        .min_h(20.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A state for trees that do nothing.
    struct Nothing;

    #[test]
    fn a_placeholder_only_attaches_to_a_field() {
        let field: El<Nothing> = field("").placeholder("a name");
        match &field.node {
            Node::Field { placeholder, .. } => assert_eq!(placeholder, "a name"),
            _ => panic!("expected a field"),
        }

        // Set on something that is not a field it does nothing, rather than
        // failing to compile or panicking — the setter is available everywhere.
        let text: El<Nothing> = text("plain").placeholder("ignored");
        assert!(matches!(text.node, Node::Text(_)));
    }

    #[test]
    fn a_button_answers_the_pointer_and_takes_the_keyboard() {
        let button: El<Nothing> = button("Start").on_click(|_| {});
        assert!(button.interactive());
        assert!(button.focusable);
    }

    #[test]
    fn the_emphases_of_a_button_differ_in_their_fill_rather_than_their_shape() {
        let ordinary: El<Nothing> = button("Ordinary");
        let primary: El<Nothing> = button("Primary").primary();
        let ghost: El<Nothing> = button("Quiet").ghost();

        assert_eq!(ordinary.style().radius, primary.style().radius);
        assert_ne!(ordinary.style().fill, primary.style().fill);
        assert_eq!(ghost.style().fill, Some(Tone::Clear));
        assert_eq!(ghost.style().hover.fill, Some(Tone::Raised), "chrome arrives on hover");
    }

    #[test]
    fn a_tag_takes_both_of_a_status_colours_from_the_same_place() {
        let tag: El<Nothing> = tag(Status::Bad, "failed");
        assert_eq!(tag.style().fill, Some(Tone::BadTint));
        assert_eq!(tag.style().ink.tone, Some(Tone::Bad));
    }

    #[test]
    fn tabs_key_themselves_by_their_own_words() {
        let element: El<Nothing> = tabs(&["Services", "Sites"], 0, |_, _| {});
        let row = &element.children[0];
        assert_eq!(row.children[0].key.as_deref(), Some("Services"));
        assert_eq!(row.children[1].key.as_deref(), Some("Sites"));
    }
}
