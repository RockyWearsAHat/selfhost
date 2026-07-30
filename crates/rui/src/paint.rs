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

use crate::canvas::{Canvas, Corner};
use crate::color::Color;
use crate::element::{El, Node};
use crate::geom::{Insets, Point, Rect};
use crate::input::{Drag, Input, Key, Phase, PointerButton};
use crate::memory::{Caret, Id, Memory, Response};
use crate::style::{Align, Ink, Radius, Tone};
use crate::text::{Fonts, TextStyle};
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

/// The canvas, the faces, and the theme: everything drawing needs.
///
/// Handed to an application's own drawing, so a sparkline or a diagram is drawn
/// with exactly what every widget in the library is drawn with.
pub struct Painter<'a> {
    canvas: &'a mut Canvas,
    fonts: &'a Fonts,
    theme: &'a Theme,
    visual: Visual,
}

impl<'a> Painter<'a> {
    /// A painter that marks `canvas`, for drawing outside a frame.
    ///
    /// What renders an icon, a thumbnail, or anything else an application draws
    /// with no window open: the same marks every widget is made of, on a canvas
    /// the caller owns. Nothing is being pointed at, so [`Painter::visual`]
    /// reports an element at rest.
    pub fn new(canvas: &'a mut Canvas, fonts: &'a Fonts, theme: &'a Theme) -> Self {
        Self { canvas, fonts, theme, visual: Visual::default() }
    }

    /// What the pointer and keyboard are doing to the element being drawn.
    pub fn visual(&self) -> Visual {
        self.visual
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
        clicked: (pressed_here && input.released(PointerButton::Primary) && hovered) || by_key,
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

    if response.focused && el.focusable {
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
            let mut painter =
                Painter { canvas: frame.canvas, fonts: frame.fonts, theme: frame.theme, visual };
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

    let mut text = value.to_owned();
    if response.focused && !el.disabled {
        let edit = apply_edits(frame.input, &mut text, &mut caret);
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

    if text.is_empty() && !response.focused {
        let hint = style.colored(Tone::Muted.resolve(frame.theme));
        draw_line(frame.canvas, frame.fonts, &hint, inner, Align::Start, placeholder, false);
        return;
    }

    // Keep the caret on screen by sliding the text left when it would otherwise
    // sit past the right edge.
    let caret_x = frame.fonts.measure(&style, &text[..caret.offset]);
    let shift = (caret_x - inner.w + 2.0).max(0.0);
    let metrics = frame.fonts.metrics(&style);
    let baseline = inner.y + (inner.h - metrics.line_height()) / 2.0 + metrics.ascent;

    let previous = frame.canvas.push_clip(inner);
    let origin = Point::new(inner.x - shift, baseline);
    frame.fonts.draw(frame.canvas, &style, origin, &text, style.color);
    frame.canvas.pop_clip(previous);

    if response.focused {
        let caret_rect = Rect::new(
            inner.x + caret_x - shift,
            inner.y + (inner.h - metrics.line_height()) / 2.0,
            1.5,
            metrics.line_height(),
        );
        frame.canvas.fill_rect(caret_rect, Tone::Accent.resolve(frame.theme));
    }
}

/// What a frame's typing did to a field.
struct Edit {
    /// Its text changed.
    changed: bool,
    /// Enter was pressed in it.
    submitted: bool,
}

/// Applies this frame's typing to a focused field's text and caret.
fn apply_edits(input: &Input, text: &mut String, caret: &mut Caret) -> Edit {
    let mut edit = Edit { changed: false, submitted: false };

    for (key, _) in input.keys() {
        match key {
            Key::Backspace => {
                if let Some(previous) = previous_boundary(text, caret.offset) {
                    text.replace_range(previous..caret.offset, "");
                    caret.offset = previous;
                    edit.changed = true;
                }
            }
            Key::Delete => {
                if let Some(next) = next_boundary(text, caret.offset) {
                    text.replace_range(caret.offset..next, "");
                    edit.changed = true;
                }
            }
            Key::Left => caret.offset = previous_boundary(text, caret.offset).unwrap_or(0),
            Key::Right => caret.offset = next_boundary(text, caret.offset).unwrap_or(text.len()),
            Key::Home => caret.offset = 0,
            Key::End => caret.offset = text.len(),
            Key::Enter => edit.submitted = true,
            _ => {}
        }
    }

    // Typed text arrives already resolved by the platform's input method, so it
    // is inserted whole rather than key by key. Control characters are dropped:
    // a newline pasted into a single-line field would otherwise be stored and
    // then silently not drawn.
    let typed: String = input.text().chars().filter(|character| !character.is_control()).collect();
    if !typed.is_empty() {
        text.insert_str(caret.offset, &typed);
        caret.offset += typed.len();
        edit.changed = true;
    }
    edit
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
fn corner_of(radius: Radius, rect: Rect, theme: &Theme) -> Corner {
    match radius {
        Radius::None => Corner::Square,
        Radius::Panel => theme.corner(),
        Radius::Control => theme.corner_small(),
        Radius::Units(units) => theme.corner().resized(units),
        Radius::Pill => theme.corner().resized(rect.w.min(rect.h) / 2.0),
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

/// The nearest character boundary at or before `offset`.
fn clamp_to_boundary(text: &str, offset: usize) -> usize {
    let mut offset = offset.min(text.len());
    while offset > 0 && !text.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

/// The character boundary before `offset`, or `None` at the start.
fn previous_boundary(text: &str, offset: usize) -> Option<usize> {
    let offset = clamp_to_boundary(text, offset);
    text[..offset].chars().next_back().map(|character| offset - character.len_utf8())
}

/// The character boundary after `offset`, or `None` at the end.
fn next_boundary(text: &str, offset: usize) -> Option<usize> {
    let offset = clamp_to_boundary(text, offset);
    text[offset..].chars().next().map(|character| offset + character.len_utf8())
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
    fn an_untouched_colour_is_left_exactly_alone() {
        let base = Color::rgb(1, 2, 3);
        assert_eq!(lift(base, 0.0, false), base);
    }

    #[test]
    fn caret_movement_lands_on_character_boundaries_in_multibyte_text() {
        let text = "aé漢";
        assert_eq!(next_boundary(text, 0), Some(1));
        assert_eq!(next_boundary(text, 1), Some(3), "é is two bytes");
        assert_eq!(next_boundary(text, 3), Some(6), "漢 is three bytes");
        assert_eq!(next_boundary(text, 6), None);

        assert_eq!(previous_boundary(text, 6), Some(3));
        assert_eq!(previous_boundary(text, 3), Some(1));
        assert_eq!(previous_boundary(text, 0), None);
    }

    #[test]
    fn an_offset_inside_a_character_is_pulled_back_to_its_start() {
        assert_eq!(clamp_to_boundary("aé", 2), 1, "the middle of é");
        assert_eq!(clamp_to_boundary("aé", 999), 3);
    }

    #[test]
    fn typing_inserts_at_the_caret_and_moves_it_along() {
        let mut input = Input::new();
        input.begin_frame();
        input.apply(crate::input::Event::Text("bc".into()));

        let mut text = "ad".to_owned();
        let mut caret = Caret { offset: 1 };
        let edit = apply_edits(&input, &mut text, &mut caret);

        assert!(edit.changed);
        assert_eq!(text, "abcd");
        assert_eq!(caret.offset, 3);
    }

    #[test]
    fn backspace_at_the_start_of_a_field_changes_nothing() {
        let mut input = Input::new();
        input.begin_frame();
        input.apply(crate::input::Event::KeyDown {
            key: Key::Backspace,
            modifiers: crate::input::Modifiers::default(),
        });

        let mut text = "abc".to_owned();
        let mut caret = Caret { offset: 0 };
        assert!(!apply_edits(&input, &mut text, &mut caret).changed);
        assert_eq!(text, "abc");
    }
}
