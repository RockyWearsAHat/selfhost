//! The element: structure, style, and behaviour in one value.
//!
//! An [`El`] is one node of the description of an interface. It is built by
//! calling a constructor — [`col`](crate::col), [`text`](crate::widgets::text),
//! [`button`](crate::button) — and then chaining setters onto it, so the three
//! things a piece of interface has to say are said in one place and in one
//! language:
//!
//! ```ignore
//! row((
//!     text(&service.name).grow(),
//!     button("Restart").on_click(|app: &mut App| app.restart()),
//! ))
//! .pad(12.0)
//! .gap(8.0)
//! .fill(Tone::Surface)
//! .round(Radius::Panel)
//! ```
//!
//! # Behaviour is a function of the state
//!
//! A handler is `Fn(&mut S)`, where `S` is the application's own state — not a
//! closure that captured it. That single decision is what makes this library
//! ordinary Rust rather than a fight with the borrow checker: the description is
//! built from `&S`, so nothing in it borrows the state mutably, and the handlers
//! that will mutate it are run after the frame has been drawn and the
//! description dropped. There is no `Rc`, no `RefCell`, and no interior
//! mutability anywhere in this crate.
//!
//! # Identity
//!
//! Everything a person can interact with needs an identity that is the same from
//! one frame to the next, because that is the key its hover, focus, caret, and
//! scroll position are stored under. It is derived from the element's path
//! through the tree, so nothing has to be named by hand — until a list is
//! reordered, at which point [`El::key`] names the row after the thing it shows
//! and the state follows the row rather than the position.
//!
//! # Meaning
//!
//! An element also carries a [`Role`], defaulted from what kind of element it
//! is and set deliberately by every constructor in
//! [`widgets`](crate::widgets). That is what makes this tree the accessibility
//! tree rather than something a second structure has to be derived from; see
//! [`accessibility`](crate::accessibility) for the whole of that decision.

use crate::accessibility::Role;
use crate::geom::{Insets, Rect, Size};
use crate::input::{Drag, Key, Modifiers};
use crate::memory::Id;
use crate::paint::Painter;
use crate::style::{Align, Anchor, Axis, Face, Hover, Ink, Justify, Length, Radius, Style, Tone};

/// What an interaction does to the application's state.
pub type Action<S> = Box<dyn Fn(&mut S)>;

/// What editing a field does to it, given the text the field now holds.
pub type TextAction<S> = Box<dyn Fn(&mut S, String)>;

/// What dragging does, given where the pointer is within the element.
pub type DragAction<S> = Box<dyn Fn(&mut S, Drag)>;

/// What a keypress does, given which key it was and what was held with it.
pub type KeyAction<S> = Box<dyn Fn(&mut S, Key, Modifiers)>;

/// What the wheel does, given how far it turned across and down.
pub type ScrollAction<S> = Box<dyn Fn(&mut S, f32, f32)>;

/// What the pointer arriving or leaving does, given which of the two it was.
pub type HoverAction<S> = Box<dyn Fn(&mut S, bool)>;

/// An application's own drawing, given the painter and the room it was placed in.
pub type Drawing = Box<dyn Fn(&mut Painter<'_>, Rect)>;

/// What an element actually is, underneath its style.
///
/// Deliberately short. Every widget in the library is one of these four with a
/// style on it and children inside it, which is what keeps the renderer small
/// enough to be read in one sitting and means a widget somebody writes has
/// exactly the same standing as one shipped here.
pub(crate) enum Node {
    /// A box that stacks its children along one axis.
    Stack,
    /// A run of text.
    Text(String),
    /// An editable line of text, and what to show when it is empty.
    Field {
        /// What the field holds, as the state last said.
        value: String,
        /// What is shown, dimmed, while it holds nothing.
        placeholder: String,
    },
    /// Something drawn directly onto the canvas.
    ///
    /// The way out of the widget set: a sparkline, a logo, a diagram. It takes
    /// the rectangle the layout gave it and the same [`Painter`] every widget
    /// here is drawn with, so an application's own drawing is not a second-class
    /// citizen.
    Draw {
        /// What it asks to be, before the layout has its say.
        intrinsic: Size,
        /// The drawing itself.
        paint: Drawing,
    },
}

/// One node of an interface: what it is, what it looks like, and what it does.
pub struct El<S> {
    pub(crate) node: Node,
    pub(crate) style: Style,
    pub(crate) children: Vec<El<S>>,
    /// Names this element, so its interaction state survives its siblings
    /// changing order. See the module's notes on identity.
    pub(crate) key: Option<String>,
    pub(crate) on_click: Option<Action<S>>,
    pub(crate) on_secondary_click: Option<Action<S>>,
    pub(crate) on_input: Option<TextAction<S>>,
    pub(crate) on_submit: Option<Action<S>>,
    pub(crate) on_drag: Option<DragAction<S>>,
    pub(crate) on_key: Option<KeyAction<S>>,
    pub(crate) on_scroll: Option<ScrollAction<S>>,
    pub(crate) on_hover: Option<HoverAction<S>>,
    /// Whether it takes the keyboard, and takes a place in the tab order.
    pub(crate) focusable: bool,
    /// Whether it lightens under the pointer and darkens under a press.
    pub(crate) reactive: bool,
    /// Whether it is drawn dimmed and ignores every event.
    pub(crate) disabled: bool,
    /// Whether its children scroll inside it.
    pub(crate) scrolls: bool,
    /// Where the layout put it, and what identity it was given.
    ///
    /// Written by the layout pass and read by the renderer. They live on the
    /// element rather than in a parallel structure so that the two passes cannot
    /// disagree about which rectangle belongs to which node — the defect that
    /// makes a button draw in one place and respond in another.
    pub(crate) rect: Rect,
    pub(crate) id: Id,
    /// The text properties in force here: this element's own, over its parent's.
    ///
    /// Resolved by the layout, once, rather than by every place that draws text,
    /// because inheritance walked twice is inheritance that can be walked
    /// differently in the two places.
    pub(crate) ink: Ink,
    /// Whether a scrolling area sticks to the end of its content.
    pub(crate) follows: bool,
    /// What this element is, for anything that cannot see it.
    ///
    /// Defaulted from the kind of node and then set by whichever constructor
    /// built it, so meaning arrives with the widget rather than being added
    /// afterwards. See [`accessibility`](crate::accessibility).
    pub(crate) role: Role,
    /// What it is called, when the words inside it will not do.
    pub(crate) label: Option<String>,
    /// What it holds, when that is not its own text.
    pub(crate) value: Option<String>,
    /// Whether it is the chosen one of its group, where that applies.
    pub(crate) selected: Option<bool>,
}

impl<S> El<S> {
    /// An element of the given kind, with nothing set on it.
    ///
    /// Its role is the one its kind implies — a stack groups, a run of text
    /// reads as text, an editable line is a field, and an application's own
    /// drawing is a picture until it says otherwise. Every constructor in
    /// [`widgets`](crate::widgets) then states its own.
    pub(crate) fn of(node: Node) -> Self {
        let role = match &node {
            Node::Stack => Role::Group,
            Node::Text(_) => Role::Text,
            Node::Field { .. } => Role::Field,
            Node::Draw { .. } => Role::Image,
        };
        Self {
            node,
            style: Style::default(),
            children: Vec::new(),
            key: None,
            on_click: None,
            on_secondary_click: None,
            on_input: None,
            on_submit: None,
            on_drag: None,
            on_key: None,
            on_scroll: None,
            on_hover: None,
            focusable: false,
            reactive: false,
            disabled: false,
            scrolls: false,
            rect: Rect::new(0.0, 0.0, 0.0, 0.0),
            id: Id::ROOT,
            ink: Ink::default(),
            follows: false,
            role,
            label: None,
            value: None,
            selected: None,
        }
    }

    /// The style set on this element, for a widget that builds on another.
    pub fn style(&self) -> &Style {
        &self.style
    }

    /// Replaces the style wholesale.
    ///
    /// For a theme or a design system that wants to hand out prepared styles
    /// rather than a chain of setters.
    pub fn with_style(mut self, style: Style) -> Self {
        self.style = style;
        self
    }

    /// Adds children to this element.
    ///
    /// Accepts a single element, a tuple of them, a `Vec`, or an `Option` — see
    /// [`Children`].
    // Deliberately not `std::ops::Add`: that trait takes one operand of one
    // type and answers a sum, and this takes *anything* that can be children —
    // a tuple, a `Vec`, an `Option` — and answers the same element. Naming it
    // `add` is what makes a description read as a sentence.
    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, children: impl Children<S>) -> Self {
        children.extend_into(&mut self.children);
        self
    }

    // ----- room, and how it is divided -------------------------------------

    /// Asks for this much width.
    pub fn w(mut self, width: impl Into<Length>) -> Self {
        self.style.width = width.into();
        self
    }

    /// Asks for this much height.
    pub fn h(mut self, height: impl Into<Length>) -> Self {
        self.style.height = height.into();
        self
    }

    /// Asks for exactly this size, on both axes.
    pub fn size(self, width: f32, height: f32) -> Self {
        self.w(width).h(height)
    }

    /// Takes an equal share of whatever room the parent has spare.
    ///
    /// Along the parent's own direction, whichever that turns out to be — which
    /// is why it is one call rather than a choice between `w` and `h` that has
    /// to be revisited when a row becomes a column.
    pub fn grow(mut self) -> Self {
        self.style.grow = Some(1.0);
        self
    }

    /// The same, asking for `share` times what a plain [`El::grow`] would get.
    pub fn grow_by(mut self, share: f32) -> Self {
        self.style.grow = Some(share.max(0.0));
        self
    }

    /// Grows from what its content needs rather than from nothing.
    ///
    /// [`El::grow`] deals a share of the leftover measured from zero, which is
    /// right for a pane or a spacer — their content is whatever fits. A control
    /// is the other way round: its words come first, and only the room past
    /// them is up for sharing. A row of buttons growing from content toward a
    /// stated maximum are uniform whenever the room allows it, share what there
    /// is when it does not, and no label is squeezed below what it says while a
    /// shorter sibling still has slack to give.
    pub fn grow_from_content(mut self) -> Self {
        self.style.grow = Some(1.0);
        self.style.grow_from_content = true;
        self
    }

    /// Stands whole or is not laid out at all.
    ///
    /// When the container shrinks, an ordinary element gives ground gradually
    /// — its text truncates, its content clips. This one refuses the middle
    /// state: the moment the layout would hand it less than it measured, it
    /// collapses to nothing and the room it held goes to its siblings. Say it
    /// on an element whose meaning is stated elsewhere too, where half the
    /// words are worse than none of them.
    pub fn whole(mut self) -> Self {
        self.style.whole = true;
        self
    }

    /// Refuses to be laid out narrower than this.
    pub fn min_w(mut self, width: f32) -> Self {
        self.style.min_width = width;
        self
    }

    /// Refuses to be laid out shorter than this.
    pub fn min_h(mut self, height: f32) -> Self {
        self.style.min_height = height;
        self
    }

    /// Refuses to be laid out wider than this.
    pub fn max_w(mut self, width: f32) -> Self {
        self.style.max_width = width;
        self
    }

    /// Refuses to be laid out taller than this.
    pub fn max_h(mut self, height: f32) -> Self {
        self.style.max_height = height;
        self
    }

    /// Leaves this much room inside its own edge, all the way round.
    pub fn pad(mut self, amount: f32) -> Self {
        self.style.padding = Insets::uniform(amount);
        self
    }

    /// Leaves room at the left and right only.
    pub fn pad_x(mut self, amount: f32) -> Self {
        self.style.padding.left = amount;
        self.style.padding.right = amount;
        self
    }

    /// Leaves room at the top and bottom only.
    pub fn pad_y(mut self, amount: f32) -> Self {
        self.style.padding.top = amount;
        self.style.padding.bottom = amount;
        self
    }

    /// Leaves a different amount of room on each side.
    pub fn pad_each(mut self, top: f32, right: f32, bottom: f32, left: f32) -> Self {
        self.style.padding = Insets::new(left, top, right, bottom);
        self
    }

    /// Leaves this much room between its children.
    pub fn gap(mut self, amount: f32) -> Self {
        self.style.gap = amount;
        self
    }

    /// Stacks its children along this axis.
    pub fn axis(mut self, axis: Axis) -> Self {
        self.style.axis = axis;
        self
    }

    /// Where its children sit across the direction it stacks them.
    pub fn align(mut self, align: Align) -> Self {
        self.style.align = align;
        self
    }

    /// Where its children sit along that direction, when there is room to spare.
    pub fn justify(mut self, justify: Justify) -> Self {
        self.style.justify = justify;
        self
    }

    /// Centres its children on both axes.
    pub fn center(self) -> Self {
        self.align(Align::Center).justify(Justify::Center)
    }

    // ----- how it looks -----------------------------------------------------

    /// Fills it with a colour, or a role from the theme.
    ///
    /// Replaces a gradient set earlier rather than becoming the top of one: a
    /// widget whose fill is overridden — a button turned into a quiet one — must
    /// end up with the fill it was given, not a fade from it to whatever the
    /// original bottom was.
    pub fn fill(mut self, tone: impl Into<Tone>) -> Self {
        self.style.fill = Some(tone.into());
        self.style.fill_deep = None;
        self
    }

    /// Fills it with a gradient running from `top` to `bottom`.
    ///
    /// Meant to be very slight. What this is for is stopping a large surface
    /// reading as one flat stamp of colour; a fill that is visibly shaded down
    /// its height is a surface wearing a texture.
    pub fn gradient(mut self, top: impl Into<Tone>, bottom: impl Into<Tone>) -> Self {
        self.style.fill = Some(top.into());
        self.style.fill_deep = Some(bottom.into());
        self
    }

    /// Outlines it, `thickness` units wide.
    pub fn border(mut self, thickness: f32, tone: impl Into<Tone>) -> Self {
        self.style.border = Some((thickness, tone.into()));
        self
    }

    /// Rounds its corners.
    pub fn round(mut self, radius: impl Into<Radius>) -> Self {
        self.style.radius = radius.into();
        self
    }

    /// Rounds its corners fully: a capsule, or a circle if it is square.
    pub fn pill(mut self) -> Self {
        self.style.radius = Radius::Pill;
        self
    }

    /// Casts a soft shadow beneath it, blurred this far past its own edge.
    pub fn shadow(mut self, blur: f32) -> Self {
        self.style.shadow = Some(blur);
        self
    }

    /// Casts a halo of `tone` around it, reaching `blur` units past its edge.
    ///
    /// Not a coloured shadow. A shadow is the absence of light: it is the
    /// theme's own black at whatever alpha survives the appearance, and it
    /// falls a little downward because the light comes from above. A glow is
    /// light — it takes a hue, it is cast evenly in every direction, and what
    /// it says is that the thing is *live*: a lamp that is lit, the pane that
    /// has been chosen, a state that wants attention.
    ///
    /// That is also why it is worth spending sparingly. A halo on one element
    /// is a fact about that element; a halo on every element is a filter over
    /// the window, and the fact is gone.
    pub fn glow(mut self, blur: f32, tone: impl Into<Tone>) -> Self {
        self.style.glow = Some((blur, tone.into()));
        self
    }

    /// Confines its own drawing, and its children's, to its rectangle.
    pub fn clip(mut self) -> Self {
        self.style.clip = true;
        self
    }

    /// Runs its children onto further lines when they do not all fit on one.
    ///
    /// A row of tags, a grid of cards, a toolbar that reflows on a narrow
    /// window: the one layout that a strict single-axis stack genuinely cannot
    /// express, because how many lines there are is not known until the
    /// children have been measured.
    ///
    /// Each line is as tall as the tallest thing on it, and the lines are
    /// separated by the same [`El::gap`] as the children. A flowing container
    /// asks for the height its lines came to, so it grows downward as the
    /// window narrows rather than cutting its last line off.
    pub fn flow(mut self) -> Self {
        self.style.flow = true;
        self.style.axis = Axis::Row;
        self
    }

    /// Scrolls its children inside it, and clips them to it.
    ///
    /// Vertical, because that is what a list, a log, and a page of settings all
    /// are. A row that overflows sideways is nearly always a layout that should
    /// have been told to wrap or to shrink.
    pub fn scroll(mut self) -> Self {
        self.scrolls = true;
        self.style.clip = true;
        self
    }

    /// Keeps a scrolling area at the end of its content as that content grows.
    ///
    /// What a log tail is: it follows the newest line until the reader scrolls
    /// back, and follows again once they scroll to the end. A view that yanks
    /// itself to the bottom while somebody is reading further up is the single
    /// most irritating thing an interface can do, and deciding it here — from
    /// whether the reader is at the end — is what stops every application having
    /// to keep that flag itself.
    ///
    /// The end it stops at is the nearest join between two children rather than
    /// the last pixel of the content, so the child at the top of the frame is a
    /// whole one; see `layout::whole_child_at_top` for what that buys and what
    /// it costs.
    pub fn follow(mut self) -> Self {
        self.follows = true;
        self.scroll()
    }

    // ----- text --------------------------------------------------------------

    /// Sets text at this size, here and in everything inside it.
    pub fn text_size(mut self, size: f32) -> Self {
        self.style.ink.size = Some(size);
        self
    }

    /// Sets text in this colour, here and in everything inside it.
    pub fn color(mut self, tone: impl Into<Tone>) -> Self {
        self.style.ink.tone = Some(tone.into());
        self
    }

    /// Sets text in the fixed-width face: anything the machine produced.
    pub fn mono(mut self) -> Self {
        self.style.ink.face = Some(Face::Mono);
        self
    }

    /// Opens the letters up by this much.
    ///
    /// What makes a small capitalised label legible rather than merely small.
    pub fn tracking(mut self, amount: f32) -> Self {
        self.style.ink.tracking = Some(amount);
        self
    }

    /// Draws the text heavier.
    ///
    /// Emboldened by drawing the run twice, a fraction of a unit apart, rather
    /// than by loading a second face. Every desktop ships a bold companion to
    /// its interface face under a different name in a different place, and
    /// hunting for it on three platforms to gain a weight that the eye reads as
    /// *emphasis* either way is not a trade worth making.
    pub fn bold(mut self) -> Self {
        self.style.ink.bold = Some(true);
        self
    }

    /// Where its own text sits within it.
    pub fn text_align(mut self, align: Align) -> Self {
        self.style.text_align = align;
        self
    }

    /// Wraps its text across as many lines as it needs, rather than cutting it
    /// short at the right edge.
    pub fn wrap(mut self) -> Self {
        self.style.wrap = true;
        self
    }

    // ----- what it does ------------------------------------------------------

    /// Runs `action` when it is clicked.
    pub fn on_click(mut self, action: impl Fn(&mut S) + 'static) -> Self {
        self.on_click = Some(Box::new(action));
        self.reactive = true;
        self.focusable = true;
        self
    }

    /// Runs `action` when it is clicked with the secondary button.
    pub fn on_secondary_click(mut self, action: impl Fn(&mut S) + 'static) -> Self {
        self.on_secondary_click = Some(Box::new(action));
        self
    }

    /// Runs `action` with the field's new text every time it is edited.
    pub fn on_input(mut self, action: impl Fn(&mut S, String) + 'static) -> Self {
        self.on_input = Some(Box::new(action));
        self.focusable = true;
        self
    }

    /// Runs `action` when Enter is pressed in it.
    pub fn on_submit(mut self, action: impl Fn(&mut S) + 'static) -> Self {
        self.on_submit = Some(Box::new(action));
        self.focusable = true;
        self
    }

    /// Runs `action` every frame the pointer is held down on it, told where
    /// within it the pointer is.
    ///
    /// The primitive that separates a control you can *build* from one you can
    /// only *use*. A click reports that something happened; a drag reports
    /// where the pointer is, continuously, in the element's own coordinates —
    /// which is a slider, a splitter, a knob, a canvas that pans, and a row
    /// dragged to reorder, all from the same four lines:
    ///
    /// ```ignore
    /// draw(Size::new(160.0, 20.0), track_and_knob)
    ///     .on_drag(|app: &mut App, drag| app.volume = drag.fraction().x)
    /// ```
    ///
    /// It fires on the frame the press begins, on every frame it is held —
    /// wherever the pointer has moved to, including outside the element — and
    /// once more when it is released. See [`Drag::phase`].
    pub fn on_drag(mut self, action: impl Fn(&mut S, Drag) + 'static) -> Self {
        self.on_drag = Some(Box::new(action));
        self.reactive = true;
        self
    }

    /// Runs `action` for every key pressed while it has the keyboard.
    ///
    /// What lets a control this library has never heard of be driven from the
    /// keyboard: a slider that answers the arrow keys, a list that answers Home
    /// and End, a canvas with its own shortcuts. Attaching it puts the element
    /// in the tab order, because a control that takes keys has to be reachable
    /// without a pointer.
    pub fn on_key(mut self, action: impl Fn(&mut S, Key, Modifiers) + 'static) -> Self {
        self.on_key = Some(Box::new(action));
        self.focusable = true;
        self
    }

    /// Runs `action` when the wheel turns over it, told how far across and down.
    ///
    /// For a control that answers the wheel without being a scrolling area — a
    /// number that steps, a zoom, a timeline. [`El::scroll`] remains the way to
    /// make children scroll inside a box; this is the way out for everything
    /// else.
    pub fn on_scroll(mut self, action: impl Fn(&mut S, f32, f32) + 'static) -> Self {
        self.on_scroll = Some(Box::new(action));
        self
    }

    /// Runs `action` when the pointer arrives over it, and again when it leaves.
    ///
    /// Called only when it *changes*, not every frame the pointer is there, so
    /// it can write to the application's own state without turning a resting
    /// pointer into an endless redraw.
    ///
    /// What this is for is interface that is decided by hovering rather than
    /// merely shaded by it — a tooltip, a preview, a row that reveals its
    /// actions. [`El::hover_fill`] and its neighbours cover the shading, which
    /// needs no state at all; this is the way out when what should appear is
    /// something only the application can describe.
    pub fn on_hover(mut self, action: impl Fn(&mut S, bool) + 'static) -> Self {
        self.on_hover = Some(Box::new(action));
        self
    }

    /// Lifts this element out of its parent's stacking and places it against
    /// the parent's edge, drawn above everything else.
    ///
    /// The one exception to *every position is decided by exactly one parent*,
    /// and it exists because the alternative is worse: a menu, a tooltip, and a
    /// dialog are all "this belongs to that, but it is not inside it", and
    /// without somewhere to say so an interface either cannot have them or
    /// fakes them by reserving room that then jumps when they open.
    ///
    /// A layer takes no room from its parent, is held inside the window so it
    /// cannot open off the edge of the screen, escapes any clipping between it
    /// and the window, and is drawn — and answers the pointer — above whatever
    /// it covers.
    ///
    /// ```ignore
    /// button("Sort").on_click(open).add(app.menu_open.then(|| {
    ///     panel(items).layer(Anchor::Below)
    /// }))
    /// ```
    pub fn layer(mut self, anchor: Anchor) -> Self {
        self.style.layer = Some(anchor);
        self
    }

    /// Gives it a place in the tab order even though nothing is attached to it.
    pub fn focusable(mut self) -> Self {
        self.focusable = true;
        self
    }

    /// Lightens it under the pointer and darkens it under a press, without
    /// anything being attached to it.
    pub fn reactive(mut self) -> Self {
        self.reactive = true;
        self
    }

    /// Draws it dimmed and makes it ignore every event.
    ///
    /// Drawn at all, rather than omitted, because a control that vanishes when
    /// it is unavailable makes the row around it jump and leaves the person
    /// unsure whether it was ever there.
    pub fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        if disabled {
            self.focusable = false;
        }
        self
    }

    /// Fills it differently while the pointer is over it.
    pub fn hover_fill(mut self, tone: impl Into<Tone>) -> Self {
        self.style.hover.fill = Some(tone.into());
        self
    }

    /// Colours its text differently while the pointer is over it.
    pub fn hover_color(mut self, tone: impl Into<Tone>) -> Self {
        self.style.hover.ink = Some(tone.into());
        self
    }

    /// Outlines it differently while the pointer is over it.
    pub fn hover_border(mut self, tone: impl Into<Tone>) -> Self {
        self.style.hover.border = Some(tone.into());
        self
    }

    /// Names this element, so its interaction state follows it when its
    /// siblings are added, removed, or reordered.
    pub fn key(mut self, key: impl Into<String>) -> Self {
        self.key = Some(key.into());
        self
    }

    // ----- what it means ------------------------------------------------------

    /// States what this element is, for anything that cannot see it.
    ///
    /// Every constructor in [`widgets`](crate::widgets) already sets one, so
    /// this is the escape for a control hand-built out of
    /// [`draw`](crate::widgets::draw) — a switch, a slider, a row that behaves
    /// as one item of a list. An element a person can interact with may not
    /// keep the default [`Role::Group`]: that is a control nobody has named,
    /// and the enforcement in [`audit`](crate::accessibility::audit) rejects
    /// it.
    ///
    /// ```ignore
    /// draw(Size::new(34.0, 20.0), knob)
    ///     .role(Role::Checkbox)
    ///     .label("Dark appearance")
    ///     .selected(app.dark)
    ///     .on_click(|app: &mut App| app.dark = !app.dark)
    /// ```
    pub fn role(mut self, role: Role) -> Self {
        self.role = role;
        self
    }

    /// Names this element, for a control whose own words will not do.
    ///
    /// Needed only where there are no words to be named after — an icon
    /// button, a switch, a slider. Everything with text inside it is named by
    /// that text already, which is what makes the convention free at nearly
    /// every call site; see [`El::accessible_name`].
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }

    /// States what this element holds, where that is not its own text.
    ///
    /// A field is valued by what is in it and needs none of this. A meter, a
    /// slider, or a stepper is a number that has to be read aloud as something,
    /// and only the author knows as what — "62%" rather than "0.62".
    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }

    /// States whether this is the chosen one of its group.
    ///
    /// Set rather than inferred from the fill, because a colour is not a
    /// semantic: [`Tone::Selection`] is how a chosen row is *drawn*, and a
    /// theme written next year may draw it some other way without the meaning
    /// having changed at all.
    pub fn selected(mut self, selected: bool) -> Self {
        self.selected = Some(selected);
        self
    }

    /// What this element is, for anything that cannot see it.
    pub fn accessibility_role(&self) -> Role {
        self.role
    }

    /// What this element is called.
    ///
    /// [`El::label`] if one was given; otherwise the words of its subtree, run
    /// together — which is HTML's *accessible name computation from contents*,
    /// and is why `button("Restart")` needs nothing written at its call site.
    /// A field is excluded from that rule: its text is its value, so a field
    /// with no label has no name and the enforcement says so.
    ///
    /// Layers are left out. A tooltip hanging off a button is not part of what
    /// the button is called.
    ///
    /// ```ignore
    /// assert_eq!(button("Restart").accessible_name(), "Restart");
    /// ```
    pub fn accessible_name(&self) -> String {
        if let Some(label) = &self.label {
            return label.clone();
        }
        if !self.role.names_from_contents() {
            return String::new();
        }
        let mut name = String::new();
        self.collect_words(&mut name);
        name
    }

    /// Whether this is the chosen one of its group, where that applies at all.
    pub fn is_selected(&self) -> Option<bool> {
        self.selected
    }

    /// Appends this element's own words, and its children's, to `out`.
    fn collect_words(&self, out: &mut String) {
        if let Node::Text(text) = &self.node {
            let text = text.trim();
            if !text.is_empty() {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(text);
            }
        }
        for child in &self.children {
            if child.style.layer.is_none() {
                child.collect_words(out);
            }
        }
    }

    /// What is inside this element.
    ///
    /// A description is a value, so a test can walk it: this is what lets an
    /// interface be asserted on — which button is offered, which is unavailable,
    /// what a row says — without a window, a pointer, or a frame.
    pub fn children(&self) -> &[El<S>] {
        &self.children
    }

    /// The `index`th thing inside it, if it has that many.
    pub fn child(&self, index: usize) -> Option<&El<S>> {
        self.children.get(index)
    }

    /// The text it holds, if it is a run of text or a field.
    pub fn text_content(&self) -> Option<&str> {
        match &self.node {
            Node::Text(text) => Some(text),
            Node::Field { value, .. } => Some(value),
            _ => None,
        }
    }

    /// Whether it is drawn dimmed and ignores every event.
    pub fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// What this element does when it is clicked, if anything.
    ///
    /// The description is an ordinary value and its handlers are ordinary
    /// functions, so what a button *does* can be tested without a window, a
    /// pointer, or a frame: build the element, take its handler, and call it on
    /// a state.
    pub fn click_action(&self) -> Option<&Action<S>> {
        self.on_click.as_ref()
    }

    /// What editing it does, if it is a field with a handler attached.
    pub fn input_action(&self) -> Option<&TextAction<S>> {
        self.on_input.as_ref()
    }

    /// What dragging it does, if anything.
    pub fn drag_action(&self) -> Option<&DragAction<S>> {
        self.on_drag.as_ref()
    }

    /// What a keypress in it does, if anything.
    pub fn key_action(&self) -> Option<&KeyAction<S>> {
        self.on_key.as_ref()
    }

    /// Where this element is anchored, if it was lifted out of the flow by
    /// [`El::layer`].
    pub fn anchor(&self) -> Option<Anchor> {
        self.style.layer
    }

    /// Whether anything about this element depends on the pointer or keyboard.
    pub(crate) fn interactive(&self) -> bool {
        !self.disabled
            && (self.on_click.is_some()
                || self.on_secondary_click.is_some()
                || self.on_input.is_some()
                || self.on_submit.is_some()
                || self.on_drag.is_some()
                || self.on_key.is_some()
                || self.on_scroll.is_some()
                || self.on_hover.is_some()
                || self.focusable
                || self.reactive
                || self.scrolls
                || !self.style.hover.is_empty())
    }

    /// Whether it holds a caret and takes typing.
    pub(crate) fn is_field(&self) -> bool {
        matches!(self.node, Node::Field { .. })
    }

    /// The hover treatment in force, which a disabled element does not have.
    pub(crate) fn hover(&self) -> Hover {
        if self.disabled { Hover::default() } else { self.style.hover }
    }
}

impl From<f32> for Length {
    fn from(units: f32) -> Self {
        Self::Fixed(units)
    }
}

impl From<f32> for Radius {
    fn from(units: f32) -> Self {
        Self::Units(units)
    }
}

/// Whatever can be put inside an element.
///
/// Implemented for a single element, for tuples of up to twelve of them, for a
/// `Vec`, and for an `Option`. Between them those cover how children are
/// actually written: a fixed handful, a list built from data, and something
/// shown only sometimes — the three cases a template language spends `{#each}`
/// and `{#if}` blocks on.
pub trait Children<S> {
    /// Appends these children to `out`, in order.
    fn extend_into(self, out: &mut Vec<El<S>>);
}

impl<S> Children<S> for El<S> {
    fn extend_into(self, out: &mut Vec<El<S>>) {
        out.push(self);
    }
}

impl<S> Children<S> for Vec<El<S>> {
    fn extend_into(self, out: &mut Vec<El<S>>) {
        out.extend(self);
    }
}

impl<S, C: Children<S>> Children<S> for Option<C> {
    fn extend_into(self, out: &mut Vec<El<S>>) {
        if let Some(children) = self {
            children.extend_into(out);
        }
    }
}

impl<S> Children<S> for () {
    fn extend_into(self, _: &mut Vec<El<S>>) {}
}

/// Implements [`Children`] for a tuple of that many elements.
macro_rules! children_tuple {
    ($($name:ident),+) => {
        impl<S, $($name: Children<S>),+> Children<S> for ($($name,)+) {
            #[allow(non_snake_case)]
            fn extend_into(self, out: &mut Vec<El<S>>) {
                let ($($name,)+) = self;
                $($name.extend_into(out);)+
            }
        }
    };
}

children_tuple!(A);
children_tuple!(A, B);
children_tuple!(A, B, C);
children_tuple!(A, B, C, D);
children_tuple!(A, B, C, D, E);
children_tuple!(A, B, C, D, E, F);
children_tuple!(A, B, C, D, E, F, G);
children_tuple!(A, B, C, D, E, F, G, H);
children_tuple!(A, B, C, D, E, F, G, H, I);
children_tuple!(A, B, C, D, E, F, G, H, I, J);
children_tuple!(A, B, C, D, E, F, G, H, I, J, K);
children_tuple!(A, B, C, D, E, F, G, H, I, J, K, L);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{button, col, text};

    /// A state a test can watch being changed.
    #[derive(Default)]
    struct Counter {
        count: i32,
    }

    #[test]
    fn a_tuple_of_children_keeps_its_order() {
        let tree: El<Counter> = col((text("first"), text("second"), text("third")));
        assert_eq!(tree.children.len(), 3);
        let labels: Vec<_> = tree
            .children
            .iter()
            .map(|child| match &child.node {
                Node::Text(text) => text.as_str(),
                _ => "",
            })
            .collect();
        assert_eq!(labels, ["first", "second", "third"]);
    }

    #[test]
    fn a_none_child_contributes_nothing() {
        let absent: Option<El<Counter>> = None;
        let tree = col((text("first"), absent, Some(text("third"))));
        assert_eq!(tree.children.len(), 2);
    }

    #[test]
    fn a_list_built_from_data_is_a_child_like_any_other() {
        let rows: Vec<El<Counter>> = (0..4).map(|index| text(format!("row {index}"))).collect();
        let tree = col((text("heading"), rows));
        assert_eq!(tree.children.len(), 5);
    }

    #[test]
    fn a_handler_changes_the_state_it_is_given() {
        // The whole behaviour model in one assertion: the description borrows
        // nothing, and the handler it carries is an ordinary function of the
        // application's own state.
        let tree: El<Counter> = button("Increment").on_click(|counter: &mut Counter| counter.count += 1);
        let mut counter = Counter::default();
        (tree.on_click.expect("the handler just set"))(&mut counter);
        assert_eq!(counter.count, 1);
    }

    #[test]
    fn attaching_a_handler_makes_an_element_focusable_and_reactive() {
        let plain: El<Counter> = text("nothing attached");
        assert!(!plain.interactive());

        let clickable: El<Counter> = text("attached").on_click(|_| {});
        assert!(clickable.interactive());
        assert!(clickable.focusable, "a clickable thing must be reachable from the keyboard");
    }

    #[test]
    fn a_disabled_element_leaves_the_tab_order_and_takes_no_events() {
        let element: El<Counter> = button("Install").on_click(|_| {}).disabled(true);
        assert!(!element.interactive());
        assert!(!element.focusable);
    }
}
