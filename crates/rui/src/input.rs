//! Input events, and the per-frame view of them the widgets read.
//!
//! A backend reports what happened as [`Event`]s. [`Input`] folds those into the
//! shape an immediate-mode frame actually wants: where the pointer *is*, which
//! buttons went down or up *since the last frame*, and what text was typed. A
//! widget asks "was I clicked", not "walk this event list".
//!
//! The distinction between held and newly-pressed is the whole reason this type
//! exists. A button that fired while the pointer was merely held down would
//! repeat every frame, and one that fired on press would activate under a
//! pointer that arrived already held from somewhere else.
//!
//! # Typing arrives in two forms, and only one of them is finished
//!
//! [`Event::Text`] is text the platform's input method has *decided*: it is
//! inserted and it is done. [`Event::Composing`] is the other half — the
//! [`Composition`] an input method is still assembling, which the person can
//! still change or abandon. Composing "にほん" takes five keystrokes and produces
//! six different in-progress strings before any of it is typed, and pressing
//! Option-E on a US layout leaves an accent waiting for the letter it belongs
//! to.
//!
//! The two are kept apart because they belong to different owners. Committed
//! text belongs to the application's state and goes through the field's input
//! handler; a composition belongs to the *interaction*, lives in [`Input`] until
//! the input method resolves it, and is drawn underlined in place so the person
//! can see what they are still choosing. A composition that reached the
//! application's state would be a value the application had to learn to un-type.
//!
//! # Not every event has a position
//!
//! [`Event::Activated`] names *what* rather than *where*: an assistive
//! technology holds the [`Id`] of a node and asks for it to be activated, with
//! no pointer anywhere near it. It is an event, and not a call from a backend
//! into a handler, for the reason a click is one — so that both arrive at the
//! same frame, are folded into the same [`Input`], and reach the same handler
//! by the same route. See the invariant in
//! [`accessibility`](crate::accessibility).

use crate::geom::{Point, Rect};
use crate::memory::Id;
use std::ops::Range;

/// Which pointer button.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PointerButton {
    /// The one that activates things; the left button, usually.
    Primary,
    /// The one that opens context menus.
    Secondary,
    /// The scroll wheel pressed as a button.
    Middle,
}

impl PointerButton {
    /// Every button, in a fixed order, for indexing.
    const ALL: [Self; 3] = [Self::Primary, Self::Secondary, Self::Middle];

    fn index(self) -> usize {
        match self {
            Self::Primary => 0,
            Self::Secondary => 1,
            Self::Middle => 2,
        }
    }
}

/// Which part of a press one frame of a drag is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// The button went down on the element this frame.
    Began,
    /// It is still down, wherever the pointer has since moved to.
    Moved,
    /// It came up this frame. The last frame of the drag, and the one a
    /// control that only commits at the end acts on.
    Ended,
}

/// Where the pointer is within an element being pressed, and how far through
/// the press this frame is.
///
/// The primitive every continuous control is made of. A click says only *that*
/// something was pressed; this says *where*, every frame, in the element's own
/// coordinates — which is the whole difference between a button and a slider, a
/// splitter, a knob, a canvas that can be panned, or a row dragged to reorder.
///
/// ```ignore
/// draw(Size::new(160.0, 20.0), |painter, rect| { /* the track and the knob */ })
///     .on_drag(|app: &mut App, drag| app.volume = drag.fraction().x)
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Drag {
    /// The pointer, relative to the element's top-left corner.
    ///
    /// Not clamped: a pointer dragged off the end of a slider reports a
    /// position outside the element, because the control — not this type —
    /// decides whether that means "the maximum" or "cancelled".
    pub at: Point,
    /// Where the element was drawn, in window coordinates.
    pub rect: Rect,
    /// Which part of the press this frame is.
    pub phase: Phase,
}

impl Drag {
    /// How far across and down the element the pointer is, from zero to one.
    ///
    /// Clamped, and zero on an axis the element has no extent along, so a
    /// control reading it can never be handed a value outside its own range or
    /// a NaN from dividing by an empty rectangle.
    pub fn fraction(&self) -> Point {
        let across = if self.rect.w > 0.0 { self.at.x / self.rect.w } else { 0.0 };
        let down = if self.rect.h > 0.0 { self.at.y / self.rect.h } else { 0.0 };
        Point::new(across.clamp(0.0, 1.0), down.clamp(0.0, 1.0))
    }

    /// Whether the button came up this frame.
    pub fn ended(&self) -> bool {
        self.phase == Phase::Ended
    }
}

/// Which modifier keys were held.
///
/// `command` is the platform's own accelerator key — Command on macOS, Control
/// elsewhere. Backends map it, so a shortcut is written once and is correct on
/// each platform rather than needing a conditional at every use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Modifiers {
    /// Shift.
    pub shift: bool,
    /// Control, as a key in its own right.
    pub control: bool,
    /// Alt, or Option.
    pub alt: bool,
    /// The platform's accelerator key.
    pub command: bool,
}

impl Modifiers {
    /// No modifiers held.
    pub const NONE: Self = Self { shift: false, control: false, alt: false, command: false };

    /// Whether Control and the accelerator are the same physical key here.
    ///
    /// They are everywhere except macOS, which has both. This is the one fact
    /// about the platform that has to be known *above* the backends, because
    /// only here is the question asked — and getting it wrong is not a cosmetic
    /// difference: a backend that reports Control as the accelerator, as X11
    /// and Windows both must, would otherwise report a modifier that
    /// [`Modifiers::command_only`] then refuses to see past, and no shortcut on
    /// either platform would ever match.
    #[cfg(target_os = "macos")]
    const CONTROL_IS_ACCELERATOR: bool = false;

    /// The same, where Control is the accelerator.
    #[cfg(not(target_os = "macos"))]
    const CONTROL_IS_ACCELERATOR: bool = true;

    /// Whether no modifier at all is held.
    pub fn is_empty(self) -> bool {
        self == Self::NONE
    }

    /// Whether the accelerator, and nothing else, is held.
    ///
    /// Control counts as "something else" only where it is a key in its own
    /// right. On a platform whose accelerator *is* Control, a backend reports
    /// one keypress in both fields, and treating that as two modifiers would
    /// make the accelerator unpressable.
    pub fn command_only(self) -> bool {
        let control_is_extra = self.control && !Self::CONTROL_IS_ACCELERATOR;
        self.command && !self.shift && !self.alt && !control_is_extra
    }
}

/// A key, named by what it does rather than by where it sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Key {
    /// Dismiss, or cancel.
    Escape,
    /// Confirm.
    Enter,
    /// Move focus.
    Tab,
    /// Delete backwards.
    Backspace,
    /// Delete forwards.
    Delete,
    /// Space.
    Space,
    /// Arrow up.
    Up,
    /// Arrow down.
    Down,
    /// Arrow left.
    Left,
    /// Arrow right.
    Right,
    /// Start of line, or of a list.
    Home,
    /// End of line, or of a list.
    End,
    /// A screenful up.
    PageUp,
    /// A screenful down.
    PageDown,
    /// A printable key, given as the lowercase character it bears.
    ///
    /// For shortcuts. Typing is reported as [`Event::Text`] instead, because
    /// what a keypress *inserts* depends on the layout, the modifiers, and any
    /// dead key before it — questions only the platform can answer.
    Character(char),
}

/// Text an input method is still assembling, shown but not yet typed.
///
/// The in-progress half of typing: what a Japanese, Chinese, or Korean input
/// method has been given so far, or the accent a dead key is holding until it
/// learns which letter it belongs to. It is drawn at the caret, underlined, and
/// is replaced wholesale every time the input method changes its mind — never
/// appended to, because backing up over a composition is the input method's
/// business and not the field's.
///
/// It reaches the application only when the input method commits it, as an
/// ordinary [`Event::Text`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Composition {
    /// What is being composed. Empty means the composition was abandoned.
    pub text: String,
    /// The part of `text` the input method has singled out, in byte offsets.
    ///
    /// Where the caret sits within the composition, and — when it covers more
    /// than one character — which clause of a longer phrase is being edited.
    /// Always on character boundaries of `text`, and always within it, so a
    /// field can slice by it without checking.
    pub selection: Range<usize>,
}

impl Composition {
    /// Whether there is nothing being composed.
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
}

/// Something the window told us happened.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// The pointer moved to a position in logical units.
    PointerMoved(Point),
    /// The pointer left the window.
    PointerLeft,
    /// A pointer button went down.
    PointerDown {
        /// Where.
        position: Point,
        /// Which button.
        button: PointerButton,
    },
    /// A pointer button came up.
    PointerUp {
        /// Where.
        position: Point,
        /// Which button.
        button: PointerButton,
    },
    /// Scrolling, in logical units; positive is content moving down and right.
    Scrolled {
        /// Horizontal amount.
        x: f32,
        /// Vertical amount.
        y: f32,
    },
    /// A key went down.
    KeyDown {
        /// Which key.
        key: Key,
        /// What was held with it.
        modifiers: Modifiers,
    },
    /// A key came up.
    KeyUp {
        /// Which key.
        key: Key,
        /// What was held with it.
        modifiers: Modifiers,
    },
    /// Text was typed, and the platform's input method has committed to it.
    Text(String),
    /// What the input method is still composing changed.
    ///
    /// Sent on every keystroke of a composition, carrying the whole of it each
    /// time. An empty [`Composition`] means the composition ended — either
    /// abandoned, or committed, in which case an [`Event::Text`] carrying the
    /// result comes with it.
    Composing(Composition),
    /// An assistive technology asked for something to be activated.
    ///
    /// A screen reader's press, arriving as an event because that is the only
    /// shape that keeps one route from an intent to a handler: it is folded
    /// into the frame the way a click is, and the element it names runs the
    /// same [`El::click_action`](crate::El::click_action) a pointer and the
    /// keyboard run.
    ///
    /// The [`Id`] is the one the platform was handed in
    /// [`AccessNode`](crate::accessibility::AccessNode), which is stable from
    /// frame to frame. An identity that no longer belongs to anything on
    /// screen, or belongs to something that answers no press, does nothing —
    /// an assistive technology holds objects from trees that have since moved
    /// on, and a stale press is a race rather than a failure.
    ///
    /// It does not move the keyboard. A click gives focus to what it pressed
    /// because the pointer went there; an assistive technology keeps a reading
    /// cursor of its own and moves the keyboard when *it* means to, so
    /// activating a button must not take the keyboard away from the field
    /// somebody was filling in.
    Activated(Id),
    /// The user asked to close the window.
    CloseRequested,
}

// A resize is deliberately *not* an event. How big the window is right now is
// state, and a backend can always be asked; delivering it as an event as well
// would mean two sources for one fact, and a frame drawn from the stale one
// whenever they disagree.

/// What the pointer and keyboard are doing this frame.
#[derive(Debug, Clone, Default)]
pub struct Input {
    /// Where the pointer is, in logical units.
    pointer: Point,
    /// Whether the pointer is over the window at all.
    pointer_inside: bool,
    /// Where the pointer was when each button was pressed.
    ///
    /// A drag is judged from where it *began*, so that releasing outside a
    /// widget still counts as a click on it only if the press started there.
    press_origin: [Option<Point>; 3],
    held: [bool; 3],
    pressed: [bool; 3],
    released: [bool; 3],
    scroll: (f32, f32),
    keys: Vec<(Key, Modifiers)>,
    /// What an assistive technology asked to activate this frame.
    ///
    /// A list rather than one identity, because two presses can arrive between
    /// frames the way two keystrokes can, and a frame that dropped one would
    /// lose an activation somebody made.
    activated: Vec<Id>,
    text: String,
    /// What an input method is still assembling.
    ///
    /// Unlike `text`, this survives the frame boundary: a composition is a thing
    /// that *is*, for as long as the input method holds it, rather than a thing
    /// that happened. Clearing it each frame would make it flicker on screen and
    /// vanish for every frame no key was pressed on.
    composition: Composition,
    modifiers: Modifiers,
    close_requested: bool,
}

impl Input {
    /// A pointer nowhere, nothing held, nothing typed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Discards everything that only applied to the frame just drawn.
    ///
    /// What persists is what is still *true* — where the pointer is, what is
    /// held down, what an input method is still composing. What is cleared is
    /// what merely *happened*.
    pub fn begin_frame(&mut self) {
        self.pressed = [false; 3];
        self.released = [false; 3];
        self.scroll = (0.0, 0.0);
        self.keys.clear();
        self.activated.clear();
        self.text.clear();
    }

    /// Folds one event in.
    pub fn apply(&mut self, event: Event) {
        match event {
            Event::PointerMoved(position) => {
                self.pointer = position;
                self.pointer_inside = true;
            }
            Event::PointerLeft => self.pointer_inside = false,
            Event::PointerDown { position, button } => {
                self.pointer = position;
                self.pointer_inside = true;
                self.held[button.index()] = true;
                self.pressed[button.index()] = true;
                self.press_origin[button.index()] = Some(position);
            }
            Event::PointerUp { position, button } => {
                self.pointer = position;
                self.held[button.index()] = false;
                self.released[button.index()] = true;
            }
            Event::Scrolled { x, y } => {
                self.scroll.0 += x;
                self.scroll.1 += y;
            }
            Event::KeyDown { key, modifiers } => {
                self.modifiers = modifiers;
                self.keys.push((key, modifiers));
            }
            Event::KeyUp { modifiers, .. } => self.modifiers = modifiers,
            Event::Text(text) => self.text.push_str(&text),
            Event::Composing(composition) => self.composition = within_bounds(composition),
            Event::Activated(id) => self.activated.push(id),
            Event::CloseRequested => self.close_requested = true,
        }
    }

    /// Where the pointer is, in logical units.
    pub fn pointer(&self) -> Point {
        self.pointer
    }

    /// Whether the pointer is over the window.
    pub fn pointer_inside(&self) -> bool {
        self.pointer_inside
    }

    /// Whether a button is held down right now.
    pub fn held(&self, button: PointerButton) -> bool {
        self.held[button.index()]
    }

    /// Whether a button went down during this frame.
    pub fn pressed(&self, button: PointerButton) -> bool {
        self.pressed[button.index()]
    }

    /// Whether a button came up during this frame.
    pub fn released(&self, button: PointerButton) -> bool {
        self.released[button.index()]
    }

    /// Where the pointer was when a held button went down.
    pub fn press_origin(&self, button: PointerButton) -> Option<Point> {
        self.press_origin[button.index()]
    }

    /// Whether any button is held.
    pub fn any_held(&self) -> bool {
        PointerButton::ALL.iter().any(|&button| self.held(button))
    }

    /// How far this frame scrolled, in logical units.
    pub fn scroll(&self) -> (f32, f32) {
        self.scroll
    }

    /// The keys pressed this frame, in the order they arrived.
    pub fn keys(&self) -> &[(Key, Modifiers)] {
        &self.keys
    }

    /// Whether a key was pressed this frame, whatever was held with it.
    pub fn key_pressed(&self, key: Key) -> bool {
        self.keys.iter().any(|(pressed, _)| *pressed == key)
    }

    /// Whether an assistive technology asked to activate this element.
    ///
    /// What a frame asks in the same breath as "was I clicked": the answer
    /// joins the pointer's and the keyboard's at the one place a click is
    /// decided, so there is nothing here for an interface to handle separately.
    pub fn activated(&self, id: Id) -> bool {
        self.activated.contains(&id)
    }

    /// Whether a key was pressed with exactly the platform accelerator held.
    pub fn shortcut(&self, key: Key) -> bool {
        self.keys
            .iter()
            .any(|(pressed, modifiers)| *pressed == key && modifiers.command_only())
    }

    /// The text typed this frame.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// What an input method is still composing, if it is composing anything.
    ///
    /// Whatever has the keyboard draws this at its caret. Nothing else should
    /// act on it: it is not typed yet, and it may never be.
    pub fn composition(&self) -> Option<&Composition> {
        if self.composition.is_empty() { None } else { Some(&self.composition) }
    }

    /// Which modifiers were last seen held.
    pub fn modifiers(&self) -> Modifiers {
        self.modifiers
    }

    /// Whether the user has asked to close the window.
    pub fn close_requested(&self) -> bool {
        self.close_requested
    }
}

/// A composition whose selection is certainly inside its own text.
///
/// [`Input::apply`] is the one place a composition crosses from a platform into
/// the library, so it is the one place the invariant [`Composition::selection`]
/// promises can be established. A field slices its composition by that range
/// every frame it draws one, and an input method counts in UTF-16 units while a
/// [`String`] is bytes — so a range landing past the end, or halfway through a
/// character, is a mistranslation waiting to panic the interface rather than
/// merely draw it oddly.
fn within_bounds(mut composition: Composition) -> Composition {
    let start = boundary_at_or_before(&composition.text, composition.selection.start);
    let end = boundary_at_or_before(&composition.text, composition.selection.end).max(start);
    composition.selection = start..end;
    composition
}

/// The character boundary of `text` at or before `offset`.
fn boundary_at_or_before(text: &str, offset: usize) -> usize {
    let mut offset = offset.min(text.len());
    while offset > 0 && !text.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(x: f32, y: f32) -> Point {
        Point::new(x, y)
    }

    #[test]
    fn a_press_is_reported_once_however_long_the_button_is_held() {
        let mut input = Input::new();
        input.apply(Event::PointerDown { position: at(1.0, 1.0), button: PointerButton::Primary });
        assert!(input.pressed(PointerButton::Primary));
        assert!(input.held(PointerButton::Primary));

        input.begin_frame();
        assert!(!input.pressed(PointerButton::Primary), "the press repeated");
        assert!(input.held(PointerButton::Primary), "the button is still down");
    }

    #[test]
    fn a_release_clears_the_hold_but_is_itself_reported_once() {
        let mut input = Input::new();
        input.apply(Event::PointerDown { position: at(1.0, 1.0), button: PointerButton::Primary });
        input.begin_frame();
        input.apply(Event::PointerUp { position: at(1.0, 1.0), button: PointerButton::Primary });

        assert!(input.released(PointerButton::Primary));
        assert!(!input.held(PointerButton::Primary));

        input.begin_frame();
        assert!(!input.released(PointerButton::Primary));
    }

    #[test]
    fn buttons_are_tracked_apart_from_one_another() {
        let mut input = Input::new();
        input.apply(Event::PointerDown { position: at(0.0, 0.0), button: PointerButton::Secondary });
        assert!(input.held(PointerButton::Secondary));
        assert!(!input.held(PointerButton::Primary));
        assert!(input.any_held());
    }

    #[test]
    fn where_a_press_began_is_remembered_for_judging_a_drag() {
        let mut input = Input::new();
        input.apply(Event::PointerDown { position: at(5.0, 5.0), button: PointerButton::Primary });
        input.apply(Event::PointerMoved(at(90.0, 90.0)));

        assert_eq!(input.press_origin(PointerButton::Primary), Some(at(5.0, 5.0)));
        assert_eq!(input.pointer(), at(90.0, 90.0));
    }

    #[test]
    fn scrolling_within_one_frame_accumulates() {
        let mut input = Input::new();
        input.apply(Event::Scrolled { x: 1.0, y: 2.0 });
        input.apply(Event::Scrolled { x: 0.5, y: 3.0 });
        assert_eq!(input.scroll(), (1.5, 5.0));

        input.begin_frame();
        assert_eq!(input.scroll(), (0.0, 0.0), "scrolling carried into the next frame");
    }

    #[test]
    fn the_pointer_position_survives_the_frame_boundary() {
        let mut input = Input::new();
        input.apply(Event::PointerMoved(at(3.0, 4.0)));
        input.begin_frame();
        assert_eq!(input.pointer(), at(3.0, 4.0));
        assert!(input.pointer_inside());
    }

    #[test]
    fn the_pointer_leaving_is_remembered_without_moving_it() {
        let mut input = Input::new();
        input.apply(Event::PointerMoved(at(3.0, 4.0)));
        input.apply(Event::PointerLeft);
        assert!(!input.pointer_inside());
        assert_eq!(input.pointer(), at(3.0, 4.0));
    }

    #[test]
    fn typed_text_accumulates_within_a_frame_and_clears_after_it() {
        let mut input = Input::new();
        input.apply(Event::Text("se".into()));
        input.apply(Event::Text("lf".into()));
        assert_eq!(input.text(), "self");

        input.begin_frame();
        assert_eq!(input.text(), "");
    }

    /// The event an input method sends while it is still assembling something.
    fn composing(text: &str, selection: Range<usize>) -> Event {
        Event::Composing(Composition { text: text.to_owned(), selection })
    }

    #[test]
    fn a_composition_replaces_the_last_one_rather_than_adding_to_it() {
        let mut input = Input::new();
        input.apply(composing("に", 0..3));
        input.apply(composing("にほ", 0..6));
        assert_eq!(input.composition().map(|c| c.text.as_str()), Some("にほ"));
    }

    #[test]
    fn a_composition_outlives_the_frame_it_started_on() {
        // Unlike typed text: it is still on screen, and still undecided, on
        // every frame until the input method resolves it.
        let mut input = Input::new();
        input.apply(composing("にほ", 0..6));
        input.begin_frame();
        assert!(input.composition().is_some(), "the composition vanished between frames");
    }

    #[test]
    fn an_empty_composition_is_the_end_of_one_rather_than_a_composition() {
        let mut input = Input::new();
        input.apply(composing("に", 0..3));
        input.apply(composing("", 0..0));
        assert_eq!(input.composition(), None);
    }

    #[test]
    fn committing_a_composition_types_text_and_ends_the_composition() {
        let mut input = Input::new();
        input.apply(composing("にほん", 0..9));
        input.apply(composing("", 0..0));
        input.apply(Event::Text("日本".into()));
        assert_eq!(input.text(), "日本");
        assert_eq!(input.composition(), None);
    }

    #[test]
    fn a_selection_reported_past_the_end_or_mid_character_is_pulled_inside() {
        // What a platform counting UTF-16 units hands over when it is translated
        // carelessly. The field slices by this range, so it has to hold.
        let mut input = Input::new();
        input.apply(composing("é", 1..99));
        let composition = input.composition().expect("the composition should survive clamping");
        assert_eq!(composition.selection, 0..2, "é is one character of two bytes");
    }

    #[test]
    fn a_shortcut_needs_the_accelerator_and_nothing_else() {
        let accelerator = Modifiers { command: true, ..Modifiers::NONE };
        let with_shift = Modifiers { command: true, shift: true, ..Modifiers::NONE };

        let mut input = Input::new();
        input.apply(Event::KeyDown { key: Key::Character('r'), modifiers: accelerator });
        assert!(input.shortcut(Key::Character('r')));
        assert!(!input.shortcut(Key::Character('s')));

        input.begin_frame();
        input.apply(Event::KeyDown { key: Key::Character('r'), modifiers: with_shift });
        assert!(!input.shortcut(Key::Character('r')), "shift should not match a bare shortcut");
        assert!(input.key_pressed(Key::Character('r')), "but the key was still pressed");
    }

    #[test]
    fn a_close_request_persists_until_it_is_acted_on() {
        let mut input = Input::new();
        input.apply(Event::CloseRequested);
        input.begin_frame();
        assert!(input.close_requested());
    }

    #[test]
    fn a_backend_that_reports_control_as_the_accelerator_is_understood() {
        // What X11 and Windows both send for one press of Control. It has to
        // read as a bare accelerator, or a shortcut on either platform is
        // unpressable — which is exactly what it was.
        let both = Modifiers { control: true, command: true, ..Modifiers::NONE };
        assert_eq!(both.command_only(), Modifiers::CONTROL_IS_ACCELERATOR);

        // Control alone, with no accelerator, is never a shortcut anywhere.
        let control = Modifiers { control: true, ..Modifiers::NONE };
        assert!(!control.command_only());
    }

    #[test]
    fn a_second_modifier_still_stops_it_being_a_bare_accelerator() {
        for extra in [
            Modifiers { shift: true, ..Modifiers::NONE },
            Modifiers { alt: true, ..Modifiers::NONE },
        ] {
            let held = Modifiers { command: true, ..extra };
            assert!(!held.command_only(), "{held:?} is the accelerator and something else");
        }
    }

    #[test]
    fn releasing_a_modifier_updates_what_is_held() {
        let mut input = Input::new();
        let shifted = Modifiers { shift: true, ..Modifiers::NONE };
        input.apply(Event::KeyDown { key: Key::Character('a'), modifiers: shifted });
        assert!(input.modifiers().shift);

        input.apply(Event::KeyUp { key: Key::Character('a'), modifiers: Modifiers::NONE });
        assert!(input.modifiers().is_empty());
    }
}
