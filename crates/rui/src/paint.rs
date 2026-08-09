//! Drawing a laid-out description, and working out what it was told.
//!
//! One walk of the tree does both. Each element is asked what the pointer and
//! keyboard did to it, drawn according to that answer, and then its children are
//! walked — so what is on screen and what responded are decided by the same code
//! from the same rectangle, and cannot come to disagree.
//!
//! # Handlers run afterwards
//!
//! Nothing is called while the tree is being drawn. A click puts the handler it
//! is attached to on a list, and the list is run once the frame is finished and
//! the description is about to be dropped. That ordering is what lets a handler
//! take `&mut` of the application's whole state: while the description exists it
//! borrows the state immutably, and by the time a handler runs it does not exist
//! any more.
//!
//! # What an application's own drawing can reach
//!
//! Everything a widget in this library can: the canvas, the faces, the theme,
//! what the pointer and keyboard are doing to it ([`Visual`]), and the easing
//! every built-in animation runs on ([`Painter::ease`]). A control somebody
//! writes is therefore not a picture that happens to be clickable — it moves,
//! lights, and settles exactly as a shipped one does, without this module
//! knowing what it is.

use crate::canvas::{Canvas, Corner};
use crate::color::Color;
use crate::element::{El, Node};
use crate::geom::{Insets, Point, Rect};
use crate::input::{Drag, Input, Key, Phase, PointerButton};
use crate::memory::{Caret, Id, Memory, Response};
use crate::sdf::{Paint, Sculpt, Shape};
use crate::style::{Align, Ink, Radius, Tone};
use crate::text::{Fonts, TextStyle, grapheme};
use crate::theme::Theme;

/// Something an interaction asked to be done to the application's state.
///
/// Borrowed from the tree, so it lives exactly as long as the description that
/// produced it — which is until the end of the frame that drew it.
pub(crate) type Deferred<'tree, S> = Box<dyn FnOnce(&mut S) + 'tree>;

/// What the pointer and keyboard are doing to the element being drawn.
///
/// Handed to an application's own drawing, and the reason [`widgets::draw`] is a
/// way to build a *control* rather than only a picture. A custom knob, tick, or
/// handle sees exactly what a button sees, so it can react exactly as one does —
/// without the library having to know what a knob is.
///
/// [`widgets::draw`]: crate::widgets::draw
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Visual {
    /// The pointer is over it.
    pub hovered: bool,
    /// It is being pressed right now.
    pub held: bool,
    /// It has the keyboard's attention.
    pub focused: bool,
    /// How far its hover has eased in, from zero to one.
    ///
    /// The eased value rather than the boolean, so custom drawing animates on
    /// exactly the curve every other control in the interface animates on.
    pub lit: f32,
    /// It is drawn dimmed and ignores every event.
    pub disabled: bool,
}

/// The canvas, the faces, the theme, and the element's own easing: everything
/// drawing needs.
///
/// Handed to an application's own drawing, so a sparkline or a diagram is drawn
/// with exactly what every widget in the library is drawn with — including
/// [`Painter::ease`], the curve every one of them animates on.
pub struct Painter<'a> {
    canvas: &'a mut Canvas,
    fonts: &'a Fonts,
    theme: &'a Theme,
    visual: Visual,
    /// Whose drawing this is, so an eased value needs no identity of its own.
    id: Id,
    /// Where eased values are kept between frames, or `None` outside a frame.
    ///
    /// The only mutable thing a painter holds. It is an `Option` because a
    /// painter also draws with no frame around it — an icon, a thumbnail — and
    /// there is no state to keep between frames that never happen. See
    /// [`Painter::ease`].
    memory: Option<&'a mut Memory>,
}

impl<'a> Painter<'a> {
    /// A painter that marks `canvas`, for drawing outside a frame.
    ///
    /// What renders an icon, a thumbnail, or anything else an application draws
    /// with no window open: the same marks every widget is made of, on a canvas
    /// the caller owns. Nothing is being pointed at, so [`Painter::visual`]
    /// reports an element at rest, and nothing outlives a single drawing, so
    /// [`Painter::ease`] answers its target at once.
    pub fn new(canvas: &'a mut Canvas, fonts: &'a Fonts, theme: &'a Theme) -> Self {
        Self { canvas, fonts, theme, visual: Visual::default(), id: Id::ROOT, memory: None }
    }

    /// What the pointer and keyboard are doing to the element being drawn.
    pub fn visual(&self) -> Visual {
        self.visual
    }

    /// Eases the value named `key` toward `target`, and answers where it got.
    ///
    /// The curve every control in this library moves on, reachable from drawing
    /// the library has never seen: a value that counts up to its new number, a
    /// bar that sweeps rather than jumps, a row that settles. `seconds` is the
    /// time constant — how long the value takes to close most of the remaining
    /// distance — and [`Metrics::motion`](crate::theme::Metrics::motion) is what
    /// the interface's own animations use, so passing that is how a hand-built
    /// control moves at the same speed as a button.
    ///
    /// # Two eased values in one drawing
    ///
    /// `key` names the value *within* this element, and the element's own
    /// identity is supplied — so `painter.ease("sweep", …)` and
    /// `painter.ease("glow", …)` are two values in every copy of a row, and the
    /// same call in the row below is a third. A caller never invents an
    /// identity, and two values in one drawing cannot silently share one number.
    ///
    /// It is a name and not the order the calls happen to run in, because an
    /// eased value that lives behind an `if` would then take its neighbour's
    /// number on the frame the branch changes — which looks like an animation
    /// leaping and reads, from the code, like nothing at all.
    ///
    /// # What it does not do
    ///
    /// Read a clock. The frame is *told* how long it lasted, exactly as every
    /// built-in animation is, so `harness.frames(60)` is one second of this and
    /// a test can assert where it got to. See [`Memory::ease`].
    ///
    /// Outside a frame — a painter from [`Painter::new`] — there is nothing to
    /// remember a value in, so this answers `target`. That is what a first sight
    /// of a value does inside a frame too, and it is why an icon rendered to a
    /// file draws the interface at rest rather than mid-animation.
    pub fn ease(&mut self, key: &str, target: f32, seconds: f32) -> f32 {
        let id = self.id.with(APPLICATION_EASING).with(key);
        match &mut self.memory {
            Some(memory) => memory.ease(id, target, seconds),
            None => target,
        }
    }

    /// Advances the looping value named `key`, and answers where it is.
    ///
    /// From zero to one and round again every `period` seconds. What
    /// [`Painter::ease`] is to a value going somewhere, this is to one that
    /// repeats: a sweep going round while a connection is being made, a lamp
    /// pulsing while something wants attention. `key` names it within this
    /// element exactly as it does there, so a drawing may have a sweep and a
    /// pulse without the two sharing a number.
    ///
    /// A cycle has nowhere to arrive, so a frame that asks for one asks for
    /// another frame. Ask for it only while the loop is what the interface is
    /// *reporting* — motion that means nothing is a window that never idles.
    ///
    /// Outside a frame — a painter from [`Painter::new`] — there is nothing to
    /// remember a position in, so this answers zero: an icon rendered to a file
    /// is drawn at the start of its loop rather than somewhere in the middle of
    /// one.
    pub fn phase(&mut self, key: &str, period: f32) -> f32 {
        let id = self.id.with(APPLICATION_EASING).with(key);
        match &mut self.memory {
            Some(memory) => memory.phase(id, period),
            None => 0.0,
        }
    }

    /// The pixels being marked.
    pub fn canvas(&mut self) -> &mut Canvas {
        self.canvas
    }

    /// The loaded faces.
    pub fn fonts(&self) -> &'a Fonts {
        self.fonts
    }

    /// The theme in force.
    pub fn theme(&self) -> &'a Theme {
        self.theme
    }

    /// What a role comes to under that theme.
    pub fn color(&self, tone: impl Into<Tone>) -> Color {
        tone.into().resolve(self.theme)
    }

    /// Fills a rectangle.
    pub fn fill(&mut self, rect: Rect, radius: Radius, tone: impl Into<Tone>) {
        let color = self.color(tone);
        let corner = corner_of(radius, rect, self.theme);
        self.canvas.fill(rect, corner, color);
    }

    /// Outlines one.
    pub fn stroke(&mut self, rect: Rect, radius: Radius, thickness: f32, tone: impl Into<Tone>) {
        let color = self.color(tone);
        let corner = corner_of(radius, rect, self.theme);
        self.canvas.stroke(rect, corner, thickness, color);
    }

    /// Draws a composable signed-distance [`Shape`] in `paint`, read as `style`.
    ///
    /// The [`crate::sdf`] algebra reached from an application's own drawing: the
    /// same [`Canvas::sculpt`] every sculpted shape is drawn with, so a hand-shaped
    /// HUD frame animates and lights exactly as a built-in shape does.
    ///
    /// [`Canvas::sculpt`]: crate::canvas::Canvas::sculpt
    pub fn sculpt(&mut self, shape: &Shape, paint: &Paint, style: Sculpt) {
        self.canvas.sculpt(shape, paint, style);
    }

    /// Draws one line of text inside `rect`, cut short if it does not fit.
    pub fn text(&mut self, rect: Rect, ink: Ink, align: Align, text: &str) {
        let style = ink.style(self.theme);
        draw_line(self.canvas, self.fonts, &style, rect, align, text, ink.bold);
    }
}

/// Everything one frame is drawn from.
pub(crate) struct Frame<'a> {
    pub(crate) canvas: &'a mut Canvas,
    pub(crate) fonts: &'a Fonts,
    pub(crate) theme: &'a Theme,
    pub(crate) input: &'a Input,
    pub(crate) memory: &'a mut Memory,
    /// What the pointer is over, decided once for the whole frame.
    pub(crate) hit: Hit,
}

/// What the pointer is actually over, resolved before anything is drawn.
///
/// One answer for the whole frame, because "am I hovered" is a question about
/// the *interface* and not about one element: two boxes that overlap — a menu
/// over the row it opened from, a control inside a clickable row — would
/// otherwise both conclude that they were, and an interface where the thing
/// underneath also lights up is one nobody can aim at.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct Hit {
    /// The topmost element the pointer is over that can answer it at all.
    pub(crate) target: Option<Id>,
    /// The innermost scrolling area under the pointer, which the wheel belongs
    /// to — so a list inside a page scrolls the list, not the page.
    pub(crate) scroll: Option<Id>,
}

/// The name every value an application eases or cycles is kept under.
///
/// One step of its own between an element's identity and the caller's key, so
/// that a drawing which eases something called `hover` cannot land on the value
/// this module eases under that name for the same element.
const APPLICATION_EASING: &str = "draw";

/// How far outside its own edge a focus ring is drawn.
const FOCUS_OFFSET: f32 = 2.0;

/// How thick that ring is.
const FOCUS_THICKNESS: f32 = 2.0;

/// How far a bold run is drawn from itself to thicken it.
///
/// A third of a logical unit: enough that the antialiasing lays down a second,
/// offset edge and the stem reads heavier, and little enough that the letter
/// does not read as doubled.
const BOLD_OFFSET: f32 = 0.35;

/// Draws the whole tree and collects what it was told to do.
pub(crate) fn render<'tree, S>(
    root: &'tree El<S>,
    frame: &mut Frame<'_>,
) -> Vec<Deferred<'tree, S>> {
    // Tab is taken once for the whole frame rather than by whichever field
    // happens to be focused: focus has to move even when what holds it does not
    // handle keys, and only the finished frame knows the full order.
    if frame.input.key_pressed(Key::Tab) {
        frame.memory.step_focus(if frame.input.modifiers().shift { -1 } else { 1 });
    }
    frame.hit = resolve_hit(root, frame.input.pointer(), frame.canvas.bounds());

    let mut actions = Vec::new();
    let mut layers = Vec::new();
    draw(root, frame, &mut actions, &mut layers);

    // Layers last, so they lie over what they were opened from, and from the
    // top of the tree, so they are not clipped by whatever contained them. A
    // layer may open a layer of its own — a submenu — which is why this drains
    // rather than iterating once.
    while !layers.is_empty() {
        for layer in std::mem::take(&mut layers) {
            draw(layer, frame, &mut actions, &mut layers);
        }
    }
    actions
}

/// Works out what the pointer is over, in the order things will be drawn.
///
/// Later wins, which is what makes the topmost element the one that answers:
/// children are drawn over their parents, and layers over everything.
fn resolve_hit<S>(root: &El<S>, pointer: Point, bounds: Rect) -> Hit {
    let mut hit = Hit::default();
    let mut layers = Vec::new();
    probe(root, pointer, bounds, &mut hit, &mut layers);
    while !layers.is_empty() {
        for layer in std::mem::take(&mut layers) {
            probe(layer, pointer, bounds, &mut hit, &mut layers);
        }
    }
    hit
}

/// Notes whether the pointer is over one element, then over its children.
fn probe<'tree, S>(
    el: &'tree El<S>,
    pointer: Point,
    clip: Rect,
    hit: &mut Hit,
    layers: &mut Vec<&'tree El<S>>,
) {
    // Both tests matter: the rectangle says where the element is, and the clip
    // says whether it is on screen at all. A row scrolled out of its container
    // is still at a position; it is just not visible, and it must not be
    // clickable either.
    if clip.contains(pointer) && el.rect.contains(pointer) {
        if el.interactive() {
            hit.target = Some(el.id);
        }
        if el.scrolls {
            hit.scroll = Some(el.id);
        }
    }

    let inner = if el.style.clip { clip.intersect(el.rect) } else { clip };
    for child in &el.children {
        match child.style.layer {
            Some(_) => layers.push(child),
            None => probe(child, pointer, inner, hit, layers),
        }
    }
}

/// Draws one element and everything inside it.
fn draw<'tree, S>(
    el: &'tree El<S>,
    frame: &mut Frame<'_>,
    actions: &mut Vec<Deferred<'tree, S>>,
    layers: &mut Vec<&'tree El<S>>,
) {
    let rect = el.rect;
    let visible = frame.canvas.is_visible(rect.expand(Insets::uniform(FOCUS_OFFSET * 2.0)));

    let response = interact(el, frame);
    let lit = if el.reactive || !el.hover().is_empty() {
        let target = f32::from(u8::from(response.hovered));
        frame.memory.ease(el.id.with("hover"), target, frame.theme.metrics.motion)
    } else {
        0.0
    };

    if visible {
        decorate(el, frame, &response, lit);
        content(el, frame, &response, lit, actions);
    }

    if response.clicked {
        if let Some(action) = &el.on_click {
            actions.push(Box::new(move |state| action(state)));
        }
    }
    if response.secondary_clicked {
        if let Some(action) = &el.on_secondary_click {
            actions.push(Box::new(move |state| action(state)));
        }
    }
    if let (Some(action), Some(drag)) = (&el.on_drag, response.drag) {
        actions.push(Box::new(move |state| action(state, drag)));
    }
    if let Some(action) = &el.on_key {
        if response.focused {
            for &(key, modifiers) in frame.input.keys() {
                actions.push(Box::new(move |state| action(state, key, modifiers)));
            }
        }
    }
    if let Some(action) = &el.on_scroll {
        let (across, down) = frame.input.scroll();
        if response.hovered && (across != 0.0 || down != 0.0) {
            actions.push(Box::new(move |state| action(state, across, down)));
        }
    }
    if let Some(action) = &el.on_hover {
        let hovered = response.hovered;
        if frame.memory.note_hover(el.id, hovered) {
            actions.push(Box::new(move |state| action(state, hovered)));
        }
    }

    if el.children.is_empty() {
        return;
    }
    let previous = el.style.clip.then(|| frame.canvas.push_clip(rect));
    for child in &el.children {
        // A layer belongs to this element but is not inside it: it is put by
        // for the end of the frame, and drawn from the top of the tree.
        match child.style.layer {
            Some(_) => layers.push(child),
            None => draw(child, frame, actions, layers),
        }
    }
    if let Some(previous) = previous {
        frame.canvas.pop_clip(previous);
    }

    if el.scrolls {
        scrollbar(el, frame);
    }
}

/// What the pointer and keyboard did to an element this frame.
///
/// The one place hovering, pressing, clicking, focus, and the wheel are decided,
/// so everything in an interface agrees on what a click is.
fn interact<S>(el: &El<S>, frame: &mut Frame<'_>) -> Response {
    if !el.interactive() {
        return Response::none(el.rect);
    }
    let input = frame.input;
    let pointer = input.pointer();
    // Decided once for the whole frame rather than element by element, so that
    // exactly one thing is hovered however many rectangles the pointer is
    // inside; see [`Hit`].
    let hovered = input.pointer_inside() && frame.hit.target == Some(el.id);

    if el.focusable {
        frame.memory.offer_focus(el.id);
    }
    if hovered && input.pressed(PointerButton::Primary) {
        frame.memory.press(el.id);
    }
    if el.scrolls && frame.hit.scroll == Some(el.id) {
        let (_, wheel) = input.scroll();
        if wheel != 0.0 {
            let offset = (frame.memory.scroll_offset(el.id) - wheel).max(0.0);
            frame.memory.set_scroll_offset(el.id, offset);
            if el.follows {
                // Following again the moment the reader arrives back at the end,
                // rather than needing a separate gesture to re-attach: the way
                // out of a log tail is to scroll up, and the way back in is to
                // scroll down to where it was.
                let end = end_of(frame.memory, el.id, el.rect.h);
                frame.memory.set_following(el.id, offset >= end - 1.0);
            }
            // The offset is applied by the next layout, so this frame is not the
            // one that shows it. Asking for another frame is what turns that
            // into a redraw the reader sees immediately rather than one that
            // waits for whatever wakes the loop next.
            frame.memory.request_frame();
        }
    }

    let pressed_here = frame.memory.active() == Some(el.id);
    let focused = frame.memory.focused() == Some(el.id);
    // A focused control is activated from the keyboard, so an interface is
    // usable without a pointer at all.
    let by_key = focused
        && el.on_click.is_some()
        && !el.is_field()
        && (input.key_pressed(Key::Space) || input.key_pressed(Key::Enter));
    // And an assistive technology's press is the third: a click with no pointer
    // and no key behind it, which names what to activate instead of where. It
    // joins the other two *here*, in the one place a click is decided, so that
    // a screen reader cannot reach a handler by any route a pointer could not.
    // Focus is deliberately not taken — see [`Event::Activated`].
    let by_assistive = el.on_click.is_some() && input.activated(el.id);

    // A drag is reported from where the press *began*, so the pointer leaving
    // the element does not end it — dragging a slider past its own end and back
    // is one gesture, and a control that lost the pointer half way through it
    // would be unusable.
    let drag = (el.on_drag.is_some() && pressed_here).then(|| Drag {
        at: Point::new(pointer.x - el.rect.x, pointer.y - el.rect.y),
        rect: el.rect,
        phase: if input.pressed(PointerButton::Primary) {
            Phase::Began
        } else if input.released(PointerButton::Primary) {
            Phase::Ended
        } else {
            Phase::Moved
        },
    });

    Response {
        rect: el.rect,
        drag,
        hovered,
        held: pressed_here && input.held(PointerButton::Primary),
        clicked: (pressed_here && input.released(PointerButton::Primary) && hovered)
            || by_key
            || by_assistive,
        secondary_clicked: hovered
            && input.released(PointerButton::Secondary)
            && input
                .press_origin(PointerButton::Secondary)
                .is_some_and(|origin| el.rect.contains(origin)),
        focused,
    }
}

/// Draws what lies behind an element's content: its shadow, fill, and outline.
fn decorate<S>(el: &El<S>, frame: &mut Frame<'_>, response: &Response, lit: f32) {
    let style = &el.style;
    let theme = frame.theme;
    let rect = el.rect;
    if !style.has_decoration() {
        return;
    }
    let corner = corner_of(style.radius, rect, theme);

    if let Some(blur) = style.shadow {
        let cast = rect.translate(0.0, theme.metrics.shadow_offset);
        let shadow = Tone::Shadow.resolve(theme);
        frame.canvas.shadow(cast, corner, blur, 0.0, shadow);
    }

    // Over the shadow and under the fill: a halo is light thrown onto what is
    // behind the element, and the element itself is drawn on top of it.
    if let Some((blur, tone)) = style.glow {
        // Cast from where the element is rather than offset downward — an even
        // halo is what separates a glow from a shadow; see [`El::glow`].
        frame.canvas.shadow(rect, corner, blur, 0.0, tone.resolve(theme));
    }

    if let Some(fill) = style.fill {
        let top = surface(fill.resolve(theme), el, response, lit, theme);
        match style.fill_deep {
            Some(deep) => {
                let bottom = surface(deep.resolve(theme), el, response, lit, theme);
                frame.canvas.fill_vertical(rect, corner, top, bottom);
            }
            None => frame.canvas.fill(rect, corner, top),
        }
    }

    if let Some((thickness, tone)) = style.border {
        let mut color = tone.resolve(theme);
        if let Some(hover) = el.hover().border {
            color = color.mix(hover.resolve(theme), lit);
        }
        if el.disabled {
            color = color.fade(0.6);
        }
        frame.canvas.stroke(rect, corner, thickness, color);
    }

    // Only for focus the keyboard put there: a ring around what was just
    // clicked repeats the click back at the person. A field is the exception —
    // its caret earns the ring however focus arrived, and a well being typed
    // into should look held either way.
    if response.focused && el.focusable && (el.is_field() || frame.memory.focus_visible()) {
        let ring = rect.expand(Insets::uniform(FOCUS_OFFSET));
        let color = Tone::Focus.resolve(theme);
        frame.canvas.stroke(ring, corner.grown(FOCUS_OFFSET), FOCUS_THICKNESS, color);
    }
}

/// What an element is actually filled with, once it has answered the pointer.
fn surface<S>(
    base: Color,
    el: &El<S>,
    response: &Response,
    lit: f32,
    theme: &Theme,
) -> Color {
    if el.disabled {
        // Tinted only faintly toward what it would be. A disabled control that
        // keeps most of its colour reads as an enabled one that is merely a bit
        // dark, and the person finds out it is unavailable by clicking it.
        return Tone::SurfaceDeep.resolve(theme).mix(base, 0.10);
    }
    let hovered = match el.hover().fill {
        // A fill named for the hover arrives rather than brightening, which is
        // what a row or a quiet button wants: no chrome at rest, a surface under
        // the pointer.
        Some(tone) => base.mix(tone.resolve(theme), lit),
        None if el.reactive => lift(base, lit, false),
        None => base,
    };
    // A press applies at once rather than easing. The two are deliberately
    // different: a hover is the interface noticing the pointer, which should
    // feel smooth, and a press is the person acting, which must land on the
    // frame they pressed.
    if response.held { lift(hovered, 0.0, true) } else { hovered }
}

/// Draws an element's own content: its text, its field, or its own drawing.
fn content<'tree, S>(
    el: &'tree El<S>,
    frame: &mut Frame<'_>,
    response: &Response,
    lit: f32,
    actions: &mut Vec<Deferred<'tree, S>>,
) {
    let theme = frame.theme;
    let mut ink = el.ink;
    if let Some(hover) = el.hover().ink {
        ink.tone = Tone::Exact(ink.tone.resolve(theme).mix(hover.resolve(theme), lit));
    }
    if el.disabled {
        ink.tone = Tone::Exact(ink.tone.resolve(theme).fade(0.55));
    }
    let inner = el.rect.inset(el.style.padding);

    match &el.node {
        Node::Stack => {}
        Node::Text(text) => {
            let style = ink.style(theme);
            if el.style.wrap {
                draw_wrapped(frame, &style, inner, el.style.text_align, text, ink.bold);
            } else {
                draw_line(
                    frame.canvas,
                    frame.fonts,
                    &style,
                    inner,
                    el.style.text_align,
                    text,
                    ink.bold,
                );
            }
        }
        Node::Field { value, placeholder } => {
            field(el, frame, response, ink, inner, value, placeholder, actions);
        }
        Node::Draw { paint, .. } => {
            // Everything a widget in this library knows about its own state,
            // handed to drawing the library has never seen. That is what makes
            // `draw` a way to build a control rather than only a picture.
            let visual = Visual {
                hovered: response.hovered,
                held: response.held,
                focused: response.focused,
                lit,
                disabled: el.disabled,
            };
            let mut painter = Painter {
                canvas: frame.canvas,
                fonts: frame.fonts,
                theme: frame.theme,
                visual,
                id: el.id,
                // The same store every built-in animation is kept in, reached
                // under the element's own identity — see [`Painter::ease`].
                memory: Some(frame.memory),
            };
            paint(&mut painter, el.rect);
        }
    }
}

/// Draws a field's text and caret, and turns this frame's typing into actions.
#[allow(clippy::too_many_arguments)]
fn field<'tree, S>(
    el: &'tree El<S>,
    frame: &mut Frame<'_>,
    response: &Response,
    ink: Ink,
    inner: Rect,
    value: &str,
    placeholder: &str,
    actions: &mut Vec<Deferred<'tree, S>>,
) {
    let style = ink.style(frame.theme);
    let mut caret = frame.memory.caret(el.id);
    caret.offset = clamp_to_boundary(value, caret.offset);
    caret.anchor = clamp_to_boundary(value, caret.anchor);

    let mut text = value.to_owned();
    let editing = response.focused && !el.disabled;
    if editing {
        let resting = caret;
        aim_caret(frame, &style, &text, &mut caret, response, inner.w);
        let edit = apply_edits(frame.input, frame.memory, &mut text, &mut caret);
        // Any edit or caret move restarts the blink, so the caret holds solid
        // while the person is typing — a mark mid-blink under active typing
        // reads as the field dropping characters.
        if edit.changed
            || caret.offset != resting.offset
            || caret.anchor != resting.anchor
        {
            frame.memory.reset_phase(el.id.with(CARET_BLINK_KEY));
        }
        if edit.changed {
            if let Some(action) = &el.on_input {
                let edited = text.clone();
                actions.push(Box::new(move |state| action(state, edited)));
            }
            // The edit reaches the state after this frame, so the text drawn
            // below is what it was a moment ago. Asking for another frame is
            // what makes typing appear under the caret rather than one wake-up
            // later.
            frame.memory.request_frame();
        }
        if edit.submitted {
            if let Some(action) = &el.on_submit {
                actions.push(Box::new(move |state| action(state)));
            }
        }
    }
    frame.memory.set_caret(el.id, caret);

    if text.is_empty() && !response.focused && frame.input.composition().is_none() {
        // The idle ink, a step dimmer than muted: a placeholder is a hint
        // about what could be typed, not a value that was, and drawn in the
        // ink real text is read by it impersonates one — a blank field has to
        // be unmistakably blank.
        let hint = style.colored(Tone::Idle.resolve(frame.theme));
        draw_line(frame.canvas, frame.fonts, &hint, inner, Align::Start, placeholder, false);
        return;
    }

    // What is drawn is the field's text with any composition inserted at the
    // caret. A composition belongs to the interaction and not to the value —
    // the application never sees it — but the person choosing between 日 and 火
    // has to be able to read what they are choosing, in place.
    let composing = if editing { frame.input.composition() } else { None };
    let (display, preedit) = match composing {
        Some(composition) => {
            let mut display = text;
            display.insert_str(caret.offset, &composition.text);
            let range = caret.offset..caret.offset + composition.text.len();
            (display, Some((range, composition.selection.clone())))
        }
        None => (text, None),
    };

    // Where the caret is drawn: inside the composition while there is one,
    // because that is where the next keystroke goes.
    let caret_offset = match &preedit {
        Some((range, selection)) => range.start + selection.start,
        None => caret.offset,
    };

    // Keep the caret on screen by sliding the text left when it would otherwise
    // sit past the right edge.
    let caret_x = frame.fonts.measure(&style, &display[..caret_offset]);
    let shift = scroll_shift(caret_x, inner.w);
    let metrics = frame.fonts.metrics(&style);
    let line_height = metrics.line_height();
    let top = inner.y + (inner.h - line_height) / 2.0;
    let baseline = top + metrics.ascent;

    let previous = frame.canvas.push_clip(inner);
    let left = inner.x - shift;

    // Behind the text, so the text stays the thing being read.
    let selection = caret.selection();
    if editing && preedit.is_none() && !selection.is_empty() {
        let start = frame.fonts.measure(&style, &display[..selection.start]);
        let end = frame.fonts.measure(&style, &display[..selection.end]);
        let rect = Rect::new(left + start, top, end - start, line_height);
        frame.canvas.fill_rect(rect, Tone::Selection.resolve(frame.theme));
    }

    frame.fonts.draw(frame.canvas, &style, Point::new(left, baseline), &display, style.color);

    if let Some((range, selection)) = &preedit {
        underline_composition(frame, &style, &display, range, selection, left, baseline);
    }
    frame.canvas.pop_clip(previous);

    if response.focused {
        // The blink: lit for just over half of each turn, dark for the rest.
        // The loop runs only while a field is focused — the blink *is* the
        // report that typing has somewhere to land, which is what earns it the
        // frames — and every edit resets it, so it holds solid under typing.
        let lit =
            frame.memory.phase(el.id.with(CARET_BLINK_KEY), CARET_BLINK_PERIOD) < CARET_BLINK_LIT;
        let caret_rect =
            Rect::new(inner.x + caret_x - shift, top, CARET_THICKNESS, line_height);
        if lit {
            frame.canvas.fill_rect(caret_rect, Tone::Accent.resolve(frame.theme));
        }
        // What the platform's input method is told, so that a list of candidate
        // characters opens beside the text being composed. Reported from here
        // because this is the one place that knows where the caret came out —
        // and whether the blink has it lit this frame, because the caret is
        // still *there* while it is dark.
        if editing {
            frame.memory.set_caret_area(caret_rect);
        }
    }
}

/// How wide the caret is drawn, in logical units.
const CARET_THICKNESS: f32 = 1.5;

/// How long one blink takes, lit and dark together, in seconds.
const CARET_BLINK_PERIOD: f32 = 1.1;

/// What share of each blink the caret is lit for.
///
/// Just over half, so the caret is present more than it is absent: the blink
/// exists to catch the eye, not to make the insertion point a thing that has
/// to be waited for.
const CARET_BLINK_LIT: f32 = 0.55;

/// The name the blink's loop is kept under, and reset under on every edit.
const CARET_BLINK_KEY: &str = "caret";

/// How much of a gap is kept between the caret and the right edge.
const CARET_MARGIN: f32 = 2.0;

/// How far below the baseline a composition is underlined.
const UNDERLINE_DROP: f32 = 2.0;

/// How thick that underline is, and how thick the part being edited is.
const UNDERLINE: (f32, f32) = (1.0, 2.0);

/// How far the text is slid left to keep a caret at `caret_x` in view.
fn scroll_shift(caret_x: f32, width: f32) -> f32 {
    (caret_x - width + CARET_MARGIN).max(0.0)
}

/// Underlines the text an input method is still composing.
///
/// Two weights: a hairline under the whole composition, and a thicker one under
/// the part the input method has singled out. That is the convention every
/// platform's own fields use, and it is the only thing on screen that
/// distinguishes text which is merely proposed from text that has been typed.
fn underline_composition(
    frame: &mut Frame<'_>,
    style: &TextStyle,
    display: &str,
    range: &std::ops::Range<usize>,
    selection: &std::ops::Range<usize>,
    left: f32,
    baseline: f32,
) {
    let color = Tone::Accent.resolve(frame.theme);
    let mut rule = |from: usize, to: usize, thickness: f32| {
        let start = frame.fonts.measure(style, &display[..from]);
        let end = frame.fonts.measure(style, &display[..to]);
        if end > start {
            let rect = Rect::new(left + start, baseline + UNDERLINE_DROP, end - start, thickness);
            frame.canvas.fill_rect(rect, color);
        }
    };
    rule(range.start, range.end, UNDERLINE.0);
    rule(range.start + selection.start, range.start + selection.end, UNDERLINE.1);
}

/// Puts the caret where the pointer pressed, and selects where it dragged.
///
/// The pointer is aiming at the text as it was drawn on the *previous* frame,
/// so the amount that frame was scrolled by has to be reconstructed — which it
/// can be exactly, because it was derived from the caret and the caret has not
/// moved yet.
fn aim_caret(
    frame: &mut Frame<'_>,
    style: &TextStyle,
    text: &str,
    caret: &mut Caret,
    response: &Response,
    width: f32,
) {
    let Some(drag) = response.drag else {
        return;
    };
    let drawn_at = frame.fonts.measure(style, &text[..caret.offset]);
    let x = drag.at.x + scroll_shift(drawn_at, width);
    // A press starts a new selection; every frame after it drags the far end.
    move_caret(caret, offset_at(frame.fonts, style, text, x), drag.phase != Phase::Began);
}

/// The cluster boundary in `text` nearest to `x`, measured from its own origin.
///
/// The nearest rather than the one before, because a click on the right-hand
/// half of a letter means the caret goes after it — which is what makes clicking
/// at the end of a word land at the end of the word.
fn offset_at(fonts: &Fonts, style: &TextStyle, text: &str, x: f32) -> usize {
    let mut nearest = 0;
    let mut best = f32::INFINITY;
    for offset in boundaries(text) {
        let distance = (fonts.measure(style, &text[..offset]) - x).abs();
        if distance < best {
            best = distance;
            nearest = offset;
        }
    }
    nearest
}

/// Every place in `text` a caret may sit, in order.
fn boundaries(text: &str) -> impl Iterator<Item = usize> + '_ {
    grapheme::clusters(text).map(|(start, _)| start).chain(std::iter::once(text.len()))
}

/// Moves the caret, dragging the selection with it or collapsing it.
fn move_caret(caret: &mut Caret, to: usize, extend: bool) {
    caret.offset = to;
    if !extend {
        caret.anchor = to;
    }
}

/// Removes what is selected, and answers whether anything was.
fn delete_selection(text: &mut String, caret: &mut Caret) -> bool {
    let selection = caret.selection();
    if selection.is_empty() {
        return false;
    }
    text.replace_range(selection.clone(), "");
    move_caret(caret, selection.start, false);
    true
}

/// Puts `typed` in at the caret, replacing whatever was selected.
fn insert(text: &mut String, caret: &mut Caret, typed: &str) {
    delete_selection(text, caret);
    text.insert_str(caret.offset, typed);
    move_caret(caret, caret.offset + typed.len(), false);
}

/// Text with everything a single-line field cannot show taken out.
///
/// A newline pasted into a field would otherwise be stored and then silently not
/// drawn, so the value would disagree with what is on screen.
fn printable(text: &str) -> String {
    text.chars().filter(|character| !character.is_control()).collect()
}

/// What a frame's typing did to a field.
struct Edit {
    /// Its text changed.
    changed: bool,
    /// Enter was pressed in it.
    submitted: bool,
}

/// Applies this frame's typing to a focused field's text and caret.
///
/// `memory` is here for the clipboard: cutting and copying leave a request on it
/// for the window loop to perform, and pasting reads what the loop left there in
/// answer to the last one. See [`Memory::copy_to_clipboard`].
fn apply_edits(
    input: &Input,
    memory: &mut Memory,
    text: &mut String,
    caret: &mut Caret,
) -> Edit {
    let mut edit = Edit { changed: false, submitted: false };

    for &(key, modifiers) in input.keys() {
        // The accelerator with a letter is a command and never typing, so it is
        // decided before anything else looks at the key.
        if modifiers.command_only() {
            edit.changed |= apply_shortcut(key, memory, text, caret);
            continue;
        }
        let extend = modifiers.shift;
        match key {
            Key::Backspace => {
                if delete_selection(text, caret) {
                    edit.changed = true;
                } else if let Some(previous) = grapheme::before(text, caret.offset) {
                    text.replace_range(previous..caret.offset, "");
                    move_caret(caret, previous, false);
                    edit.changed = true;
                }
            }
            Key::Delete => {
                if delete_selection(text, caret) {
                    edit.changed = true;
                } else if let Some(next) = grapheme::after(text, caret.offset) {
                    text.replace_range(caret.offset..next, "");
                    edit.changed = true;
                }
            }
            // An arrow with a selection and no shift collapses it to the
            // matching end rather than moving from the caret: pressing left
            // over a selection means "go to its start", everywhere.
            Key::Left => {
                let selection = caret.selection();
                match selection.is_empty() || extend {
                    true => move_caret(caret, grapheme::before(text, caret.offset).unwrap_or(0), extend),
                    false => move_caret(caret, selection.start, false),
                }
            }
            Key::Right => {
                let selection = caret.selection();
                match selection.is_empty() || extend {
                    true => move_caret(
                        caret,
                        grapheme::after(text, caret.offset).unwrap_or(text.len()),
                        extend,
                    ),
                    false => move_caret(caret, selection.end, false),
                }
            }
            Key::Home => move_caret(caret, 0, extend),
            Key::End => move_caret(caret, text.len(), extend),
            Key::Enter => edit.submitted = true,
            _ => {}
        }
    }

    // Typed text arrives already resolved by the platform's input method, so it
    // is inserted whole rather than key by key.
    let typed = printable(input.text());
    if !typed.is_empty() {
        insert(text, caret, &typed);
        edit.changed = true;
    }

    // What the clipboard answered the last frame's request with. A frame late by
    // construction — see [`Memory::request_paste`] — and inserted here so that a
    // paste behaves in every other way exactly like typing.
    if let Some(pasted) = memory.take_pasted() {
        let pasted = printable(&pasted);
        if !pasted.is_empty() {
            insert(text, caret, &pasted);
            edit.changed = true;
        }
    }
    edit
}

/// Applies one accelerator shortcut, and answers whether the text changed.
fn apply_shortcut(key: Key, memory: &mut Memory, text: &mut String, caret: &mut Caret) -> bool {
    let selection = caret.selection();
    match key {
        Key::Character('a') => {
            caret.anchor = 0;
            caret.offset = text.len();
            false
        }
        Key::Character('c') => {
            if !selection.is_empty() {
                memory.copy_to_clipboard(text[selection].to_owned());
            }
            false
        }
        Key::Character('x') => {
            if selection.is_empty() {
                return false;
            }
            memory.copy_to_clipboard(text[selection].to_owned());
            delete_selection(text, caret)
        }
        Key::Character('v') => {
            memory.request_paste();
            false
        }
        _ => false,
    }
}

/// Draws the indicator down the edge of a scrolling area.
fn scrollbar<S>(el: &El<S>, frame: &mut Frame<'_>) {
    let rect = el.rect;
    let content = frame.memory.content_height(el.id);
    let overflow = content - rect.h;
    if overflow <= 0.0 {
        return;
    }
    let theme = frame.theme;
    let width = theme.metrics.scrollbar;
    let track = Rect::new(rect.max_x() - width, rect.y, width, rect.h);

    // Proportional, but never so short it cannot be seen.
    let proportion = (rect.h / content).clamp(0.0, 1.0);
    let thumb_height = (track.h * proportion).max(width * 2.0);
    let travel = (track.h - thumb_height).max(0.0);
    let position = frame.memory.scroll_offset(el.id) / overflow;

    // Drawn on its own rail rather than floating on the content. The rail is
    // what says how far there is left to go; a thumb alone only says where you
    // are, and on a log that is still arriving those are different questions.
    let rail = Rect::new(track.x + width * 0.45, track.y, width * 0.1, track.h);
    frame.canvas.fill_rect(rail, Tone::Border.resolve(theme));

    // Grey, dim, and thin. A scroll bar reports where you are in something you
    // are reading; it is never the thing being read.
    let thumb =
        Rect::new(track.x + width * 0.25, track.y + travel * position, width * 0.5, thumb_height);
    let color = Tone::Muted.resolve(theme).fade(0.55);
    frame.canvas.fill(thumb, Corner::Round(thumb.w / 2.0), color);
}

/// Draws one line of text in `rect`, cut short if it does not fit.
///
/// Vertically centred, because every caller wants text centred in the box it was
/// given, and doing it here means none of them computes a baseline.
fn draw_line(
    canvas: &mut Canvas,
    fonts: &Fonts,
    style: &TextStyle,
    rect: Rect,
    align: Align,
    text: &str,
    bold: bool,
) {
    if text.is_empty() || rect.is_empty() {
        return;
    }
    let metrics = fonts.metrics(style);
    let width = fonts.measure(style, text).min(rect.w);
    let baseline = rect.y + (rect.h - metrics.line_height()) / 2.0 + metrics.ascent;
    let origin = Point::new(rect.x + align.offset(rect.w, width), baseline);

    fonts.draw_truncated(canvas, style, origin, text, rect.w, style.color);
    if bold {
        let doubled = Point::new(origin.x + BOLD_OFFSET, origin.y);
        fonts.draw_truncated(canvas, style, doubled, text, rect.w, style.color);
    }
}

/// Draws wrapped text from the top of `rect` down.
fn draw_wrapped(
    frame: &mut Frame<'_>,
    style: &TextStyle,
    rect: Rect,
    align: Align,
    text: &str,
    bold: bool,
) {
    let metrics = frame.fonts.metrics(style);
    let line_height = metrics.line_height();
    let mut y = rect.y;
    for (start, end) in frame.fonts.wrap(style, text, rect.w) {
        if y + line_height > rect.max_y() + 0.5 {
            break;
        }
        let line = &text[start..end];
        let width = frame.fonts.measure(style, line);
        let origin = Point::new(rect.x + align.offset(rect.w, width), y + metrics.ascent);
        frame.fonts.draw(frame.canvas, style, origin, line, style.color);
        if bold {
            let doubled = Point::new(origin.x + BOLD_OFFSET, origin.y);
            frame.fonts.draw(frame.canvas, style, doubled, line, style.color);
        }
        y += line_height;
    }
}

/// The corner shape a radius amounts to on a particular rectangle.
///
/// Four of the six take the theme's own shape and differ only in size, which is
/// what makes one word in the theme change the whole interface. The other two
/// state a shape of their own; see [`Radius`].
fn corner_of(radius: Radius, rect: Rect, theme: &Theme) -> Corner {
    match radius {
        Radius::None => Corner::Square,
        Radius::Panel => theme.corner(),
        Radius::Control => theme.corner_small(),
        Radius::Units(units) => theme.corner().resized(units),
        Radius::Pill => theme.corner().resized(rect.w.min(rect.h) / 2.0),
        Radius::Cut(units) => Corner::Cut(units),
    }
}

/// Lightens or darkens a fill by how far it is hovered, and whether it is held.
///
/// Which direction depends on the colour: darkening an already-dark accent does
/// nothing visible, so the shift is always *away* from the colour's own
/// lightness and therefore always visible.
fn lift(base: Color, lit: f32, held: bool) -> Color {
    let toward = if base.luminance() > 0.5 { Color::BLACK } else { Color::WHITE };
    let amount = 0.12 * lit.clamp(0.0, 1.0) + if held { 0.16 } else { 0.0 };
    if amount <= 0.0 {
        return base;
    }
    base.mix(toward, amount)
}

/// The nearest place a caret may sit at or before `offset`.
///
/// A cluster boundary and not merely a character one: a caret between a letter
/// and the accent that belongs to it draws the accent over the letter after it,
/// and one inside an emoji built from joined parts splits it into its pieces.
/// See [`grapheme`](crate::text::grapheme).
///
/// Applied to a field's value on every frame, because the value comes from the
/// application and may have been replaced by anything at all since the caret was
/// last put somewhere in it.
fn clamp_to_boundary(text: &str, offset: usize) -> usize {
    let offset = offset.min(text.len());
    if grapheme::is_boundary(text, offset) {
        return offset;
    }
    grapheme::before(text, offset).unwrap_or(0)
}

/// Where a scrolling area identified by `id` should sit to show its end.
///
/// Exposed through [`Memory`] rather than computed by an application, because
/// only the layout knows how tall the content came out. See
/// [`Memory::content_height`].
pub(crate) fn end_of(memory: &Memory, id: Id, viewport: f32) -> f32 {
    (memory.content_height(id) - viewport).max(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifting_moves_a_light_colour_darker_and_a_dark_one_lighter() {
        let light = Color::rgb(240, 240, 240);
        let dark = Color::rgb(20, 20, 40);
        assert!(lift(light, 1.0, false).luminance() < light.luminance());
        assert!(lift(dark, 1.0, false).luminance() > dark.luminance());
    }

    #[test]
    fn a_press_lifts_further_than_a_hover() {
        let base = Color::rgb(40, 90, 200);
        assert!(lift(base, 1.0, true).luminance() > lift(base, 1.0, false).luminance());
    }

    #[test]
    fn a_painter_outside_a_frame_answers_an_easing_with_its_target() {
        // An icon drawn to a file has no frames to ease over and nowhere to
        // remember a value between them, so it draws the interface at rest —
        // which is what a first sight of a value does inside a frame too.
        let mut canvas = Canvas::new(16, 16, 1.0);
        let fonts = crate::testing::test_fonts();
        let theme =
            Theme::new(crate::theme::Appearance::Dark, fonts.ui_font, fonts.mono_font);
        let mut painter = Painter::new(&mut canvas, &fonts.fonts, &theme);
        assert_eq!(painter.ease("sweep", 0.75, 0.1), 0.75);
        assert_eq!(painter.ease("sweep", 0.25, 0.1), 0.25, "and it does not accumulate");
    }

    #[test]
    fn a_painter_outside_a_frame_reports_a_loop_at_its_beginning() {
        // An icon written to a file is not a frame of an animation: a loop with
        // nowhere to be remembered is drawn where it starts.
        let mut canvas = Canvas::new(16, 16, 1.0);
        let fonts = crate::testing::test_fonts();
        let theme =
            Theme::new(crate::theme::Appearance::Dark, fonts.ui_font, fonts.mono_font);
        let mut painter = Painter::new(&mut canvas, &fonts.fonts, &theme);
        assert_eq!(painter.phase("sweep", 1.2), 0.0);
    }

    #[test]
    fn an_untouched_colour_is_left_exactly_alone() {
        let base = Color::rgb(1, 2, 3);
        assert_eq!(lift(base, 0.0, false), base);
    }

    #[test]
    fn an_offset_inside_a_cluster_is_pulled_back_to_its_start() {
        assert_eq!(clamp_to_boundary("aé", 2), 1, "the middle of é");
        assert_eq!(clamp_to_boundary("aé", 999), 3);
        // A letter and the accent that belongs to it are one place, not two:
        // a caret between them would draw the accent over the next letter.
        assert_eq!(clamp_to_boundary("e\u{301}f", 1), 0, "between e and its accent");
    }

    use crate::input::{Composition, Event, Modifiers};

    /// One frame's worth of input, with `events` folded into it.
    fn typed(events: impl IntoIterator<Item = Event>) -> Input {
        let mut input = Input::new();
        input.begin_frame();
        for event in events {
            input.apply(event);
        }
        input
    }

    /// The key `character` pressed with the platform accelerator held.
    fn shortcut(character: char) -> Event {
        Event::KeyDown {
            key: Key::Character(character),
            modifiers: Modifiers { command: true, ..Modifiers::NONE },
        }
    }

    /// A key pressed with nothing, or with only shift, held.
    fn press(key: Key, shift: bool) -> Event {
        Event::KeyDown { key, modifiers: Modifiers { shift, ..Modifiers::NONE } }
    }

    /// A caret at `offset` with nothing selected.
    fn at(offset: usize) -> Caret {
        Caret { offset, anchor: offset }
    }

    /// A caret selecting `from..to`, dragged in that direction.
    fn selecting(from: usize, to: usize) -> Caret {
        Caret { offset: to, anchor: from }
    }

    #[test]
    fn typing_inserts_at_the_caret_and_moves_it_along() {
        let mut memory = Memory::new();
        let mut text = "ad".to_owned();
        let mut caret = at(1);
        let edit = apply_edits(&typed([Event::Text("bc".into())]), &mut memory, &mut text, &mut caret);

        assert!(edit.changed);
        assert_eq!(text, "abcd");
        assert_eq!(caret.offset, 3);
    }

    #[test]
    fn backspace_at_the_start_of_a_field_changes_nothing() {
        let mut memory = Memory::new();
        let mut text = "abc".to_owned();
        let mut caret = at(0);
        let input = typed([press(Key::Backspace, false)]);
        assert!(!apply_edits(&input, &mut memory, &mut text, &mut caret).changed);
        assert_eq!(text, "abc");
    }

    #[test]
    fn backspace_removes_a_whole_cluster_and_not_one_character_of_it() {
        // The visible bug this fixes: one press leaving a bare accent behind,
        // or an emoji collapsing into the parts it was joined from.
        let mut memory = Memory::new();
        let mut text = "ae\u{301}".to_owned();
        let mut caret = at(text.len());
        apply_edits(&typed([press(Key::Backspace, false)]), &mut memory, &mut text, &mut caret);
        assert_eq!(text, "a");
    }

    #[test]
    fn shift_and_an_arrow_extend_a_selection_from_where_it_started() {
        let mut memory = Memory::new();
        let mut text = "abcd".to_owned();
        let mut caret = at(1);
        let input = typed([press(Key::Right, true), press(Key::Right, true)]);
        apply_edits(&input, &mut memory, &mut text, &mut caret);

        assert_eq!(caret.selection(), 1..3);
        assert_eq!(&text[caret.selection()], "bc");
    }

    #[test]
    fn an_arrow_without_shift_collapses_a_selection_to_the_end_it_points_at() {
        let mut memory = Memory::new();
        let mut text = "abcd".to_owned();

        let mut caret = selecting(1, 3);
        apply_edits(&typed([press(Key::Left, false)]), &mut memory, &mut text, &mut caret);
        assert_eq!(caret.offset, 1, "left over a selection goes to its start");

        let mut caret = selecting(1, 3);
        apply_edits(&typed([press(Key::Right, false)]), &mut memory, &mut text, &mut caret);
        assert_eq!(caret.offset, 3, "and right to its end");
    }

    #[test]
    fn typing_over_a_selection_replaces_it() {
        let mut memory = Memory::new();
        let mut text = "abcd".to_owned();
        let mut caret = selecting(1, 3);
        apply_edits(&typed([Event::Text("X".into())]), &mut memory, &mut text, &mut caret);

        assert_eq!(text, "aXd");
        assert_eq!(caret.selection(), 2..2, "the selection is gone, not merely moved");
    }

    #[test]
    fn copying_leaves_the_selection_for_the_window_and_the_text_alone() {
        let mut memory = Memory::new();
        let mut text = "selfhost".to_owned();
        let mut caret = selecting(0, 4);
        let edit = apply_edits(&typed([shortcut('c')]), &mut memory, &mut text, &mut caret);

        assert!(!edit.changed, "copying is not an edit");
        assert_eq!(memory.take_clipboard_request().copy.as_deref(), Some("self"));
        assert_eq!(text, "selfhost");
    }

    #[test]
    fn cutting_copies_and_then_removes() {
        let mut memory = Memory::new();
        let mut text = "selfhost".to_owned();
        let mut caret = selecting(0, 4);
        let edit = apply_edits(&typed([shortcut('x')]), &mut memory, &mut text, &mut caret);

        assert!(edit.changed);
        assert_eq!(memory.take_clipboard_request().copy.as_deref(), Some("self"));
        assert_eq!(text, "host");
    }

    #[test]
    fn copying_nothing_asks_the_window_for_nothing() {
        // A field with no selection is not an empty clipboard waiting to happen.
        let mut memory = Memory::new();
        let mut text = "selfhost".to_owned();
        let mut caret = at(4);
        apply_edits(&typed([shortcut('c')]), &mut memory, &mut text, &mut caret);
        assert_eq!(memory.take_clipboard_request().copy, None);
    }

    #[test]
    fn pasting_asks_this_frame_and_inserts_on_the_next() {
        let mut memory = Memory::new();
        let mut text = "ad".to_owned();
        let mut caret = at(1);

        apply_edits(&typed([shortcut('v')]), &mut memory, &mut text, &mut caret);
        assert!(memory.take_clipboard_request().paste, "the window was never asked");
        assert_eq!(text, "ad", "nothing can be pasted before the clipboard has answered");

        // What the window loop does with the answer, and the frame after it.
        memory.deliver_paste("bc".into());
        let edit = apply_edits(&typed([]), &mut memory, &mut text, &mut caret);
        assert!(edit.changed);
        assert_eq!(text, "abcd");
        assert_eq!(caret.offset, 3);
    }

    #[test]
    fn a_pasted_newline_does_not_reach_a_single_line_field() {
        // It would be stored and then not drawn, so the value would disagree
        // with what is on screen.
        let mut memory = Memory::new();
        let mut text = String::new();
        let mut caret = at(0);
        memory.deliver_paste("one\ntwo".into());
        apply_edits(&typed([]), &mut memory, &mut text, &mut caret);
        assert_eq!(text, "onetwo");
    }

    #[test]
    fn select_all_takes_the_whole_field_however_it_is_pressed() {
        let mut memory = Memory::new();
        let mut text = "selfhost".to_owned();
        let mut caret = at(3);
        apply_edits(&typed([shortcut('a')]), &mut memory, &mut text, &mut caret);
        assert_eq!(caret.selection(), 0..text.len());
    }

    #[test]
    fn a_shortcut_is_never_also_typed_into_the_field() {
        // The bug this prevents: Command-V inserting a "v" as well as pasting.
        let mut memory = Memory::new();
        let mut text = String::new();
        let mut caret = at(0);
        apply_edits(&typed([shortcut('v')]), &mut memory, &mut text, &mut caret);
        assert_eq!(text, "");
    }

    #[test]
    fn a_composition_never_reaches_the_field_but_its_commit_does() {
        // The whole of the composition contract: what the input method is still
        // assembling is drawn, and only what it commits is typed.
        let mut memory = Memory::new();
        let mut text = String::new();
        let mut caret = at(0);

        let composing = typed([Event::Composing(Composition {
            text: "にほん".into(),
            selection: 0..9,
        })]);
        let edit = apply_edits(&composing, &mut memory, &mut text, &mut caret);
        assert!(!edit.changed, "a composition is not an edit");
        assert_eq!(text, "");
        assert!(composing.composition().is_some(), "but it is there to be drawn");

        let committed = typed([
            Event::Composing(Composition::default()),
            Event::Text("日本".into()),
        ]);
        assert!(apply_edits(&committed, &mut memory, &mut text, &mut caret).changed);
        assert_eq!(text, "日本");
    }
}
