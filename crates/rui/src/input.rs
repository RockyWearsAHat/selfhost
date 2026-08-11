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
        fraction_within(self.at, self.rect)
    }

    /// Whether the button came up this frame.
    pub fn ended(&self) -> bool {
        self.phase == Phase::Ended
    }
}

/// Where the pointer is over an element it has not pressed.
///
/// What [`Drag`] is to a gesture, this is to a hand simply moving: the same two
/// facts — where within the element, and how big the element is — with no press
/// to be part of. Carried by
/// [`El::on_pointer_move`](crate::El::on_pointer_move).
///
/// The rectangle travels with the position because a position alone cannot be
/// turned into anything: a viewport forwarding a pointer to a far screen, a map
/// reading out coordinates and a picture picking a pixel all need to know what
/// share of the element the pointer is at, and the element is the only thing
/// that knows its own size. Handing over both is what makes [`Pointing::fraction`]
/// answerable here rather than something every caller re-derives from a rectangle
/// it had to store during a draw.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pointing {
    /// The pointer, relative to the element's top-left corner.
    pub at: Point,
    /// Where the element was drawn, in window coordinates.
    pub rect: Rect,
}

impl Pointing {
    /// How far across and down the element the pointer is, from zero to one.
    ///
    /// Clamped and NaN-free, exactly as [`Drag::fraction`] is — the same
    /// computation, so a control driven by both cannot read two different
    /// answers for one position.
    pub fn fraction(&self) -> Point {
        fraction_within(self.at, self.rect)
    }
}

/// Where a point sits within a rectangle, from zero to one on each axis.
///
/// One implementation for [`Drag`] and [`Pointing`]. Clamped, and zero on an
/// axis with no extent, so nothing reading it is handed a value outside its own
/// range or a NaN from dividing by an empty rectangle.
fn fraction_within(at: Point, rect: Rect) -> Point {
    let across = if rect.w > 0.0 { at.x / rect.w } else { 0.0 };
    let down = if rect.h > 0.0 { at.y / rect.h } else { 0.0 };
    Point::new(across.clamp(0.0, 1.0), down.clamp(0.0, 1.0))
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

/// Where a key sits on the keyboard, as the platform numbers it.
///
/// [`Key`] says what a key *means* here: what the layout, the modifiers, and
/// any dead key before it made of the press. This says *which key moved*, and
/// the two are different questions with different right answers.
///
/// # What it is for
///
/// Two things [`Key`] cannot do.
///
/// It names keys this library has no name for — the function row, the keypad,
/// the left and right halves of a modifier pair — because a number needs no
/// vocabulary. An interface that wants F5 or the keypad's Enter can have it
/// without this enum growing a variant per keyboard.
///
/// And it survives being sent somewhere else. Forwarding a keystroke to another
/// machine means telling it which key went down, not which character this
/// machine's layout produced: a Dvorak typist driving a QWERTY machine by
/// characters types gibberish, and a shortcut is a *position* on every platform
/// that defines one. So the physical key is what travels.
///
/// # It is the platform's own numbering, and it does not travel by itself
///
/// A macOS virtual key code, a Win32 virtual-key code, and an X11 keycode are
/// three unrelated numbering schemes: 49 is Space on macOS, `VK_1` on Windows,
/// and `q` under X11. This type carries the number and nothing else, so anything
/// sending one to another machine must send *which scheme it is* alongside it —
/// a translation table belongs to whoever spans two platforms, and putting one
/// here would mean this library deciding what a keyboard is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyCode(u32);

impl KeyCode {
    /// The code the platform gave, whatever its numbering means.
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// That number, for a backend or a forwarder that knows the scheme.
    pub const fn raw(self) -> u32 {
        self.0
    }
}

/// Which way a key moved.
///
/// One enum rather than two handlers, because a key that goes down and is never
/// reported coming up is a key held forever on whatever is listening — a caret
/// that repeats, or, once a keystroke is being forwarded, a modifier stuck down
/// on another person's machine. Making the direction a value the one handler
/// must match on is what stops half of the pair being written and the other
/// half forgotten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyPhase {
    /// The key went down.
    Down,
    /// The key came up.
    Up,
}

/// One movement of one key: which key, what it meant, and which way it went.
///
/// The whole of what a keyboard did, as opposed to the two questions widgets
/// usually ask of it ("was I clicked" and "was this shortcut pressed"). What
/// wants this is anything that has to *reproduce* the keyboard rather than
/// respond to it: a remote session, a key-remapper, a macro recorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyStroke {
    /// Which physical key, when the press came from a keyboard.
    ///
    /// `None` for a keystroke nothing physical produced — one synthesized by a
    /// test, or by an assistive technology. Anything forwarding a keystroke to
    /// another machine sends only the ones that have a code, because a key with
    /// no position is not a key another machine can be told about.
    pub code: Option<KeyCode>,
    /// What the key means here, when this library has a name for it.
    ///
    /// `None` for every key [`Key`] does not name — the function row, the
    /// keypad, the modifiers themselves.
    pub key: Option<Key>,
    /// What was held with it.
    pub modifiers: Modifiers,
    /// Which way it moved.
    pub phase: KeyPhase,
}

impl KeyStroke {
    /// Whether this is a key going down.
    pub fn is_down(&self) -> bool {
        self.phase == KeyPhase::Down
    }

    /// Whether it says anything at all.
    ///
    /// A stroke with neither a position nor a meaning describes no key, and
    /// [`Input::apply`] drops it rather than storing something a handler would
    /// have to check for.
    fn is_meaningful(&self) -> bool {
        self.code.is_some() || self.key.is_some()
    }
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
    ///
    /// Both halves are optional because the two questions a key answers are
    /// independent: F5 has a position and no meaning this library names, and a
    /// keystroke a test or an assistive technology synthesized has a meaning and
    /// no position. An event with neither is dropped by [`Input::apply`].
    KeyDown {
        /// What the key means here, if this library names it.
        key: Option<Key>,
        /// Which physical key, if it came from a keyboard.
        code: Option<KeyCode>,
        /// What was held with it.
        modifiers: Modifiers,
    },
    /// A key came up.
    ///
    /// Reported for the same keys as [`Event::KeyDown`] and never for fewer: a
    /// backend that sends the down and swallows the up leaves the key held on
    /// anything watching. See [`Input::released_keys`].
    KeyUp {
        /// What the key means here, if this library names it.
        key: Option<Key>,
        /// Which physical key, if it came from a keyboard.
        code: Option<KeyCode>,
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
    /// Whether it arrived somewhere new during this frame.
    ///
    /// A thing that *happened*, so it is cleared with the presses and the
    /// keystrokes rather than persisting like the position itself. It is what
    /// separates "the pointer is here" from "the pointer just came here": an
    /// element told the former every frame would forward a position to another
    /// machine for as long as a hand rested over it.
    moved: bool,
    /// Where the pointer was when each button was pressed.
    ///
    /// A drag is judged from where it *began*, so that releasing outside a
    /// widget still counts as a click on it only if the press started there.
    press_origin: [Option<Point>; 3],
    held: [bool; 3],
    pressed: [bool; 3],
    released: [bool; 3],
    scroll: (f32, f32),
    /// Every key that moved this frame, in the order the keys moved.
    ///
    /// One list for both directions, and the only place keyboard movement is
    /// kept: "which keys went down" and "which came up" are *views* of it
    /// ([`Input::keys`], [`Input::released_keys`]) rather than lists of their
    /// own, so the two can never come to disagree about a press one of them
    /// recorded and the other missed — which is exactly how a key gets stuck.
    strokes: Vec<KeyStroke>,
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
        self.moved = false;
        self.pressed = [false; 3];
        self.released = [false; 3];
        self.scroll = (0.0, 0.0);
        self.strokes.clear();
        self.activated.clear();
        self.text.clear();
    }

    /// Folds one event in.
    pub fn apply(&mut self, event: Event) {
        match event {
            Event::PointerMoved(position) => {
                self.place(position);
                self.pointer_inside = true;
            }
            Event::PointerLeft => self.pointer_inside = false,
            Event::PointerDown { position, button } => {
                self.place(position);
                self.pointer_inside = true;
                self.held[button.index()] = true;
                self.pressed[button.index()] = true;
                self.press_origin[button.index()] = Some(position);
            }
            Event::PointerUp { position, button } => {
                self.place(position);
                self.held[button.index()] = false;
                self.released[button.index()] = true;
            }
            Event::Scrolled { x, y } => {
                self.scroll.0 += x;
                self.scroll.1 += y;
            }
            Event::KeyDown { key, code, modifiers } => {
                self.modifiers = modifiers;
                self.take_stroke(KeyStroke { code, key, modifiers, phase: KeyPhase::Down });
            }
            Event::KeyUp { key, code, modifiers } => {
                self.modifiers = modifiers;
                self.take_stroke(KeyStroke { code, key, modifiers, phase: KeyPhase::Up });
            }
            Event::Text(text) => self.text.push_str(&text),
            Event::Composing(composition) => self.composition = within_bounds(composition),
            Event::Activated(id) => self.activated.push(id),
            Event::CloseRequested => self.close_requested = true,
        }
    }

    /// Puts the pointer somewhere, noting whether that is somewhere new.
    ///
    /// One place, because every positioned event moves it and a press that
    /// forgot to say so would be a movement no element could hear.
    fn place(&mut self, position: Point) {
        if position != self.pointer {
            self.moved = true;
        }
        self.pointer = position;
    }

    /// Where the pointer is, in logical units.
    pub fn pointer(&self) -> Point {
        self.pointer
    }

    /// Whether the pointer is over the window.
    pub fn pointer_inside(&self) -> bool {
        self.pointer_inside
    }

    /// Whether the pointer arrived somewhere new during this frame.
    ///
    /// False on a frame drawn for any other reason — an animation, a poll, a
    /// keystroke — which is what lets [`El::on_pointer_move`](crate::El::on_pointer_move)
    /// report movement rather than presence.
    pub fn pointer_moved(&self) -> bool {
        self.moved
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

    /// Every key that moved this frame, both directions, in order.
    ///
    /// What anything reproducing the keyboard reads, rather than responding to
    /// it: a remote session forwarding keystrokes, a macro recorder. Widgets
    /// want [`Input::keys`].
    pub fn strokes(&self) -> &[KeyStroke] {
        &self.strokes
    }

    /// The keys pressed this frame that this library has a name for, in order.
    ///
    /// Keys with no name — the function row, the keypad — are in
    /// [`Input::strokes`] and not here, because a widget asking "was Escape
    /// pressed" has nothing to do with a key it cannot spell.
    pub fn keys(&self) -> impl Iterator<Item = (Key, Modifiers)> + '_ {
        self.named(KeyPhase::Down)
    }

    /// The keys *released* this frame, in the same shape.
    ///
    /// The half that used to be thrown away. A widget that acts while a key is
    /// held — one driving something continuous, or forwarding the keyboard to
    /// another machine — has no way to stop without this, and "no way to stop"
    /// means a key held down forever on whatever was listening.
    pub fn released_keys(&self) -> impl Iterator<Item = (Key, Modifiers)> + '_ {
        self.named(KeyPhase::Up)
    }

    /// Whether a key was pressed this frame, whatever was held with it.
    pub fn key_pressed(&self, key: Key) -> bool {
        self.keys().any(|(pressed, _)| pressed == key)
    }

    /// Whether a key came up this frame, whatever was held with it.
    pub fn key_released(&self, key: Key) -> bool {
        self.released_keys().any(|(released, _)| released == key)
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
        self.keys().any(|(pressed, modifiers)| pressed == key && modifiers.command_only())
    }

    /// The named keys that moved one way this frame.
    ///
    /// The one place [`Input::keys`] and [`Input::released_keys`] differ, so
    /// that the pair cannot be filtered two subtly different ways.
    fn named(&self, phase: KeyPhase) -> impl Iterator<Item = (Key, Modifiers)> + '_ {
        self.strokes
            .iter()
            .filter(move |stroke| stroke.phase == phase)
            .filter_map(|stroke| Some((stroke.key?, stroke.modifiers)))
    }

    /// Records one key's movement, if it describes a key at all.
    fn take_stroke(&mut self, stroke: KeyStroke) {
        if stroke.is_meaningful() {
            self.strokes.push(stroke);
        }
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

    /// A key going down with nothing held, as a platform reports it.
    fn down(key: Key, modifiers: Modifiers) -> Event {
        Event::KeyDown { key: Some(key), code: None, modifiers }
    }

    /// The same key coming up.
    fn up(key: Key, modifiers: Modifiers) -> Event {
        Event::KeyUp { key: Some(key), code: None, modifiers }
    }

    #[test]
    fn a_shortcut_needs_the_accelerator_and_nothing_else() {
        let accelerator = Modifiers { command: true, ..Modifiers::NONE };
        let with_shift = Modifiers { command: true, shift: true, ..Modifiers::NONE };

        let mut input = Input::new();
        input.apply(down(Key::Character('r'), accelerator));
        assert!(input.shortcut(Key::Character('r')));
        assert!(!input.shortcut(Key::Character('s')));

        input.begin_frame();
        input.apply(down(Key::Character('r'), with_shift));
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
        input.apply(down(Key::Character('a'), shifted));
        assert!(input.modifiers().shift);

        input.apply(up(Key::Character('a'), Modifiers::NONE));
        assert!(input.modifiers().is_empty());
    }

    #[test]
    fn a_key_that_went_down_is_reported_coming_up_again() {
        // The half that used to be discarded. Everything that holds state while
        // a key is held — a repeat, a forwarded keystroke — depends on it.
        let mut input = Input::new();
        input.apply(down(Key::Character('a'), Modifiers::NONE));
        assert!(input.key_pressed(Key::Character('a')));
        assert!(!input.key_released(Key::Character('a')), "it has not come up yet");

        input.begin_frame();
        input.apply(up(Key::Character('a'), Modifiers::NONE));
        assert!(input.key_released(Key::Character('a')));
        assert!(!input.key_pressed(Key::Character('a')), "a release is not a press");
    }

    #[test]
    fn a_release_is_reported_once_and_does_not_carry_into_the_next_frame() {
        let mut input = Input::new();
        input.apply(up(Key::Escape, Modifiers::NONE));
        assert!(input.key_released(Key::Escape));

        input.begin_frame();
        assert!(!input.key_released(Key::Escape), "the release repeated");
        assert_eq!(input.strokes().len(), 0);
    }

    #[test]
    fn every_key_that_went_down_can_be_matched_with_the_one_that_came_up() {
        // The stuck-key guarantee, stated as the arithmetic that proves it: over
        // any run of frames, each code that went down comes up exactly once. A
        // remote session that forwards `strokes()` verbatim therefore cannot
        // leave a key held on the far machine unless the far end drops one.
        let mut input = Input::new();
        let mut held: Vec<KeyCode> = Vec::new();
        let codes = [KeyCode::new(0), KeyCode::new(96), KeyCode::new(55)];

        for code in codes {
            input.begin_frame();
            input.apply(Event::KeyDown { key: None, code: Some(code), modifiers: Modifiers::NONE });
            held.extend(down_codes(&input));
        }
        for code in codes.into_iter().rev() {
            input.begin_frame();
            input.apply(Event::KeyUp { key: None, code: Some(code), modifiers: Modifiers::NONE });
            for released in input.strokes().iter().filter(|stroke| !stroke.is_down()) {
                let code = released.code.expect("a physical release carries its code");
                let at = held
                    .iter()
                    .position(|held| *held == code)
                    .unwrap_or_else(|| panic!("{code:?} came up without having gone down"));
                held.remove(at);
            }
        }

        assert!(held.is_empty(), "left held down: {held:?}");
    }

    /// The physical keys that went down this frame.
    fn down_codes(input: &Input) -> Vec<KeyCode> {
        input
            .strokes()
            .iter()
            .filter(|stroke| stroke.is_down())
            .filter_map(|stroke| stroke.code)
            .collect()
    }

    #[test]
    fn a_key_this_library_cannot_name_still_reaches_anything_forwarding_it() {
        // F5, the keypad, the right-hand Shift: no `Key` variant, and no reason
        // a remote session should not be able to send them.
        let mut input = Input::new();
        input.apply(Event::KeyDown {
            key: None,
            code: Some(KeyCode::new(96)),
            modifiers: Modifiers::NONE,
        });

        assert_eq!(input.keys().count(), 0, "it has no name, so no widget sees it");
        assert_eq!(input.strokes().len(), 1);
        assert_eq!(input.strokes()[0].code, Some(KeyCode::new(96)));
        assert!(input.strokes()[0].is_down());
    }

    #[test]
    fn a_keystroke_that_names_no_key_at_all_is_dropped() {
        // Neither a position nor a meaning describes nothing, and storing it
        // would make every reader check for it.
        let mut input = Input::new();
        input.apply(Event::KeyDown { key: None, code: None, modifiers: Modifiers::NONE });
        assert_eq!(input.strokes().len(), 0);
    }

    #[test]
    fn a_named_key_carries_its_position_as_well() {
        // Both halves of the same press: the widget reads the meaning, the
        // remote session reads the key.
        let mut input = Input::new();
        input.apply(Event::KeyDown {
            key: Some(Key::Escape),
            code: Some(KeyCode::new(53)),
            modifiers: Modifiers::NONE,
        });

        assert!(input.key_pressed(Key::Escape));
        assert_eq!(input.strokes()[0].code.map(KeyCode::raw), Some(53));
    }
}
