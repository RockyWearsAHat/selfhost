//! The little that outlives a frame: identity, and interaction state.
//!
//! Every frame is described from scratch out of the application's own data, so
//! nothing about *what is on screen* is stored here. What is stored is the
//! handful of things that belong to the interaction rather than to the data —
//! which element the pointer is over, which is being pressed, which has the
//! keyboard, where a list is scrolled, where a caret sits, and how far each of
//! those has animated toward where it is going.
//!
//! The reason that split is worth keeping strictly is that an interface built
//! from a retained tree of widget objects has to mirror every change in the data
//! into those objects, and every bug in that mirroring is a screen showing
//! something that is no longer true. Rebuilding the description each frame makes
//! that class of bug impossible to write.
//!
//! # Time is given, not read
//!
//! Easing needs to know how long the last frame took, and nothing here reads a
//! clock — [`Memory::begin_frame`] is told. That is what makes an animation
//! assertable in a test: step the clock by a fixed amount and check where the
//! value got to.

use crate::geom::Rect;
use crate::input::{Drag, Input};
use std::collections::{HashMap, HashSet};

/// A stable identifier for something a person can interact with.
///
/// Derived by hashing, so it can be built from whatever actually identifies the
/// thing — a service's name, a tab's title, a position in the tree — rather than
/// from a counter that shifts when the list changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Id(u64);

impl Id {
    /// The identity of the whole interface, which every other one descends from.
    pub const ROOT: Self = Self(FNV_OFFSET);

    /// The identifier for `seed`.
    pub fn new(seed: &str) -> Self {
        Self(fnv1a(FNV_OFFSET, seed.as_bytes()))
    }

    /// A child identifier, distinct from this one and from its siblings.
    pub fn with(self, seed: &str) -> Self {
        Self(fnv1a(self.0, seed.as_bytes()))
    }

    /// A child identifier for the `index`th of something.
    pub fn index(self, index: usize) -> Self {
        Self(fnv1a(self.0, &index.to_le_bytes()))
    }
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// FNV-1a, which is short, has no dependency, and spreads short keys well.
fn fnv1a(seed: u64, bytes: &[u8]) -> u64 {
    let mut hash = seed;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// How the keyboard's attention came to be where it is.
///
/// What decides whether a focus ring is drawn. A pointer press puts focus
/// where the pointer already is, so a ring there tells the person nothing they
/// did not just do — but focus that arrived from the keyboard is invisible
/// without one. See [`Memory::focus_visible`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FocusSource {
    /// A pointer press put focus here.
    #[default]
    Pointer,
    /// Tab, or another key stepping focus, put it here.
    Keyboard,
}

/// What an element's interaction amounted to this frame.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Response {
    /// Where it was drawn.
    pub rect: Rect,
    /// Where the pointer is within it while it is being dragged.
    ///
    /// Present on every frame between the press and the release, including the
    /// frames the pointer has left the element on — see [`Drag`].
    pub drag: Option<Drag>,
    /// The pointer is over it.
    pub hovered: bool,
    /// It is being pressed right now.
    pub held: bool,
    /// It was activated this frame, by whichever of the three routes.
    ///
    /// A press that began on it and ended on it, or Space or Enter while it had
    /// the keyboard, or an assistive technology naming it — one flag for all
    /// three, because an interface must not be able to tell them apart. See the
    /// invariant in [`accessibility`](crate::accessibility).
    pub clicked: bool,
    /// The same, for the secondary button.
    pub secondary_clicked: bool,
    /// It has the keyboard's attention.
    pub focused: bool,
}

impl Response {
    /// Nothing happened to it at all.
    pub(crate) fn none(rect: Rect) -> Self {
        Self {
            rect,
            drag: None,
            hovered: false,
            held: false,
            clicked: false,
            secondary_clicked: false,
            focused: false,
        }
    }
}

/// Where a caret sits in a field being edited, and what it has selected.
///
/// Two offsets rather than a range, because a selection has a direction: the
/// anchor is where the selection began and does not move, and the offset is the
/// end being dragged. Extending a selection leftwards and then rightwards has to
/// come back to where it started, which a sorted pair cannot express.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Caret {
    /// Byte offset within the field's text: where the caret is drawn.
    pub(crate) offset: usize,
    /// Byte offset the selection is anchored at; equal to `offset` when there
    /// is no selection.
    pub(crate) anchor: usize,
}

impl Caret {
    /// What is selected, in byte offsets, low end first.
    ///
    /// Empty when nothing is, which is the case a caller can treat as "act on
    /// the caret" without asking a second question.
    pub(crate) fn selection(self) -> std::ops::Range<usize> {
        self.offset.min(self.anchor)..self.offset.max(self.anchor)
    }
}

/// What a frame asked the window to do with the system clipboard.
///
/// # Why a request and not a call
///
/// A handler is `fn(&mut S)` and captures nothing, and drawing a field has no
/// window in reach either — the whole point of [`crate::shell`] is that nothing
/// above it knows what a window is. So a field leaves its intention here and the
/// window loop performs it once the frame is finished, which is exactly the
/// shape [`Memory::request_frame`] already uses for "do this once I am done".
///
/// It also happens to be the only shape X11 can honour. There is no clipboard
/// buffer to read there: asking for the selection sends a message to whichever
/// client owns it and the answer arrives later, so a `paste()` that returned a
/// string on the spot is not a thing that platform has.
#[derive(Debug, Default)]
pub(crate) struct ClipboardRequest {
    /// Text to be placed on the clipboard.
    pub(crate) copy: Option<String>,
    /// Whether the clipboard's own text was asked for.
    pub(crate) paste: bool,
}

/// How far an eased value has travelled, and when it was last asked for.
#[derive(Debug, Clone, Copy)]
struct Eased {
    value: f32,
    /// The frame it was last asked for, so values nothing draws are dropped.
    seen: u64,
}

/// How far round its period a looping value has got, and when it was last asked
/// for.
#[derive(Debug, Clone, Copy)]
struct Cycle {
    /// From zero to one, wrapping.
    value: f32,
    /// The frame it was last asked for, so cycles nothing draws are dropped.
    seen: u64,
}

/// How close to its target a value has to get before it is called settled.
///
/// Exponential easing approaches its target without ever arriving, so without a
/// threshold the interface would redraw for ever after every hover. Every
/// animated value here is a fraction or a coordinate in logical units, and a
/// thousandth of either is far below what a pixel can show.
const SETTLED: f32 = 0.001;

/// The state that outlives a frame.
#[derive(Debug, Default)]
pub struct Memory {
    active: Option<Id>,
    focus: Option<Id>,
    /// How focus last moved, which is what decides whether it is ringed.
    focus_source: FocusSource,
    scroll: HashMap<Id, f32>,
    content_height: HashMap<Id, f32>,
    carets: HashMap<Id, Caret>,
    /// Every focusable element drawn this frame, in the order it was drawn.
    focus_order: Vec<Id>,
    /// Set when Tab was pressed, resolved once the frame's order is known.
    pending_focus_step: i32,
    /// Where each animated value has got to.
    eased: HashMap<Id, Eased>,
    /// How far round its period each looping value has got.
    cycles: HashMap<Id, Cycle>,
    /// How long the frame being drawn represents, in seconds.
    delta: f32,
    /// Which frame is being drawn, for dropping values nothing draws any more.
    frame: u64,
    /// Whether anything is still short of its target.
    animating: bool,
    /// Which following areas the reader has scrolled away from.
    ///
    /// Absent means still following, so an area that has never been touched
    /// tails its content — which is what a log view is for.
    detached: HashMap<Id, bool>,
    /// What the pointer was over on the frame before this one.
    was_hovered: HashSet<Id>,
    /// What it is over on this one, which becomes the above at the end of it.
    ///
    /// Two sets swapped rather than one map updated, so an element that is no
    /// longer drawn drops out by simply not being added again — hover state for
    /// a row that scrolled away is state that could otherwise only grow.
    hovered: HashSet<Id>,
    /// What the frame being drawn asked of the system clipboard.
    clipboard: ClipboardRequest,
    /// What the window last read back from the clipboard, for whoever asked.
    pasted: Option<String>,
    /// Where the caret of whatever has the keyboard was last drawn.
    ///
    /// Not for drawing — the field draws its own caret. This is what the window
    /// tells the platform's input method, so that a list of candidate characters
    /// opens beside the text being composed rather than in the corner of the
    /// screen.
    caret_area: Option<Rect>,
}

impl Memory {
    /// Nothing hovered, pressed, focused, or scrolled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Which element has the keyboard, if any.
    pub fn focused(&self) -> Option<Id> {
        self.focus
    }

    /// Gives the keyboard to an element, or to nothing.
    pub fn set_focus(&mut self, id: Option<Id>) {
        self.focus = id;
        if let Some(id) = id {
            self.carets.entry(id).or_default();
        }
    }

    /// Which element is being pressed, if any.
    pub(crate) fn active(&self) -> Option<Id> {
        self.active
    }

    /// Notes that an element is being pressed, and gives it the keyboard.
    pub(crate) fn press(&mut self, id: Id) {
        self.active = Some(id);
        self.focus_source = FocusSource::Pointer;
        self.set_focus(Some(id));
    }

    /// Whether what holds the keyboard should wear the focus ring.
    ///
    /// True only when focus last moved by key. A ring around what was just
    /// clicked repeats the click back at the person, while keyboard focus is
    /// invisible without one — so the ring is drawn for the second and not the
    /// first. A field is the one exception, and the drawing makes it: a caret
    /// justifies the ring however focus arrived.
    pub fn focus_visible(&self) -> bool {
        self.focus_source == FocusSource::Keyboard
    }

    /// Enters an element into this frame's tab order.
    pub(crate) fn offer_focus(&mut self, id: Id) {
        self.focus_order.push(id);
    }

    /// Where a caret sits in the field identified by `id`.
    pub(crate) fn caret(&self, id: Id) -> Caret {
        self.carets.get(&id).copied().unwrap_or_default()
    }

    /// Records where that caret has moved to.
    pub(crate) fn set_caret(&mut self, id: Id, caret: Caret) {
        self.carets.insert(id, caret);
    }

    /// How far a scrolling area is scrolled, in logical units.
    pub fn scroll_offset(&self, id: Id) -> f32 {
        self.scroll.get(&id).copied().unwrap_or(0.0)
    }

    /// Scrolls an area to a position, which is clamped when it is next drawn.
    pub fn set_scroll_offset(&mut self, id: Id, offset: f32) {
        self.scroll.insert(id, offset);
    }

    /// How tall a scrolling area's contents were the last time they were laid
    /// out.
    ///
    /// Zero before it has ever been drawn. Exposed so that a view which follows
    /// the end of a growing list — a log tail — can work out where the end is;
    /// that is the one thing a scrolling area cannot decide for itself, because
    /// only the application knows whether the reader has scrolled away on
    /// purpose.
    pub fn content_height(&self, id: Id) -> f32 {
        self.content_height.get(&id).copied().unwrap_or(0.0)
    }

    /// Records how tall those contents came out.
    pub(crate) fn set_content_height(&mut self, id: Id, height: f32) {
        self.content_height.insert(id, height);
    }

    /// Asks for another frame to be drawn as soon as this one is finished.
    ///
    /// For a change made *during* a frame that the frame therefore cannot show:
    /// a wheel that moved a list, a keystroke that has yet to reach the state.
    /// It reuses the same path an animation does, so the loop needs no second
    /// notion of being behind.
    pub fn request_frame(&mut self) {
        self.animating = true;
    }

    /// Asks for `text` to be placed on the system clipboard.
    ///
    /// Performed by the window once this frame is finished, by the loop in
    /// [`shell`](crate::shell) — a field cannot reach a window, so it leaves
    /// its intention here instead. The last request of a frame wins, because two
    /// controls both copying on the same frame is a mistake and the alternative
    /// — concatenating them — would be a stranger one.
    pub fn copy_to_clipboard(&mut self, text: String) {
        self.clipboard.copy = Some(text);
    }

    /// Asks for the system clipboard's text, which arrives on the next frame.
    ///
    /// A frame later rather than at once, because reading a clipboard is asking
    /// another program a question, and on X11 it is literally that. The extra
    /// frame is asked for here, so the paste appears immediately rather than
    /// whenever something else next woke the interface up.
    pub fn request_paste(&mut self) {
        self.clipboard.paste = true;
        self.request_frame();
    }

    /// Takes what this frame asked of the clipboard, for the window to perform.
    pub(crate) fn take_clipboard_request(&mut self) -> ClipboardRequest {
        std::mem::take(&mut self.clipboard)
    }

    /// Hands over what the clipboard answered, for the next frame to read.
    pub(crate) fn deliver_paste(&mut self, text: String) {
        self.pasted = Some(text);
        self.request_frame();
    }

    /// Takes the clipboard's answer, if one is waiting for this frame.
    ///
    /// Consumed rather than read, so it is pasted once and not on every frame
    /// until the next paste.
    pub(crate) fn take_pasted(&mut self) -> Option<String> {
        self.pasted.take()
    }

    /// Notes where the caret of whatever has the keyboard was drawn.
    pub(crate) fn set_caret_area(&mut self, area: Rect) {
        self.caret_area = Some(area);
    }

    /// Where that caret was, if anything drew one this frame.
    pub(crate) fn caret_area(&self) -> Option<Rect> {
        self.caret_area
    }

    /// Whether a following area is still stuck to the end of its content.
    pub(crate) fn is_following(&self, id: Id) -> bool {
        !self.detached.get(&id).copied().unwrap_or(false)
    }

    /// Records whether the reader has scrolled away from that end.
    pub(crate) fn set_following(&mut self, id: Id, following: bool) {
        self.detached.insert(id, !following);
    }

    /// Notes whether the pointer is over an element, and answers whether that
    /// has just changed.
    ///
    /// The change and not the state, because an application told every frame
    /// that the pointer is still where it was would write to its own state
    /// every frame, and an interface that writes every frame is one that
    /// redraws for ever.
    pub(crate) fn note_hover(&mut self, id: Id, hovered: bool) -> bool {
        if hovered {
            self.hovered.insert(id);
        }
        self.was_hovered.contains(&id) != hovered
    }

    /// Begins a frame representing `elapsed` of real time.
    ///
    /// `elapsed` is clamped: a frame that took a long time — the window was
    /// behind another one, or the machine stalled — must not make an animation
    /// leap, and a zero would leave every animation frozen. The worst a stall
    /// can do is take one frame longer to settle.
    pub fn begin_frame(&mut self, elapsed: std::time::Duration) {
        /// Longer than this is a stall rather than a frame, and is treated as one.
        const LONGEST: f32 = 1.0 / 15.0;
        /// Shorter than this cannot move anything and would only lose precision.
        const SHORTEST: f32 = 1.0 / 1000.0;

        self.delta = elapsed.as_secs_f32().clamp(SHORTEST, LONGEST);
        self.frame = self.frame.wrapping_add(1);
        self.animating = false;
        // Where the caret is belongs to the frame that draws it. Kept from the
        // last one, it would go on pointing at a field that has since lost the
        // keyboard or scrolled off the screen.
        self.caret_area = None;
    }

    /// Whether anything is mid-animation and the frame should be drawn again.
    ///
    /// The loop asks this to decide whether to wait for input or to come back
    /// promptly, which is what keeps an idle interface from redrawing at all.
    pub fn is_animating(&self) -> bool {
        self.animating
    }

    /// Eases the value held under `id` toward `target`, and answers where it got.
    ///
    /// `seconds` is the time constant: how long the value takes to close most of
    /// the remaining distance. The step is `1 - e^(-dt/seconds)` rather than a
    /// fixed increment, so the motion is identical whether the frame took four
    /// milliseconds or forty — a fixed increment ties the speed of the interface
    /// to the speed of the machine drawing it.
    ///
    /// A value asked for the first time starts *at* its target rather than at
    /// zero. Otherwise everything would animate in from nothing the first time
    /// it was drawn, so opening a window would play a burst of animation and a
    /// row scrolled into view would fade in as though it had just changed.
    pub fn ease(&mut self, id: Id, target: f32, seconds: f32) -> f32 {
        let frame = self.frame;
        let entry = self.eased.entry(id).or_insert(Eased { value: target, seen: frame });
        entry.seen = frame;

        let step = if seconds > 0.0 { 1.0 - (-self.delta / seconds).exp() } else { 1.0 };
        let value = entry.value + (target - entry.value) * step;

        if (target - value).abs() <= SETTLED {
            entry.value = target;
        } else {
            entry.value = value;
            self.animating = true;
        }
        entry.value
    }

    /// Advances the looping value held under `id`, and answers where it is.
    ///
    /// From zero to one and round again every `period` seconds: what a rotating
    /// sweep, a pulse, or anything else that repeats is driven from. The step is
    /// the frame's own elapsed time over the period, so a loop takes as long on
    /// a slow machine as on a quick one, exactly as [`Memory::ease`] does.
    ///
    /// # It never settles, so ask for it only while it should be moving
    ///
    /// An eased value arrives and the interface goes back to sleep. A cycle has
    /// nowhere to arrive, so every frame that asks for one asks for another
    /// frame — which is right when the loop *is* the report (a sweep saying a
    /// connection is being made, a pulse saying something wants attention) and
    /// is a window that never idles when it is not. Draw it while the state is
    /// in flux and stop asking when it is not.
    ///
    /// A period of zero or less has no length to divide by and holds at zero,
    /// without keeping the loop awake.
    pub fn phase(&mut self, id: Id, period: f32) -> f32 {
        if period <= 0.0 || !period.is_finite() {
            return 0.0;
        }
        let frame = self.frame;
        let cycle = self.cycles.entry(id).or_insert(Cycle { value: 0.0, seen: frame });
        cycle.seen = frame;
        cycle.value = (cycle.value + self.delta / period).fract();
        self.animating = true;
        cycle.value
    }

    /// Restarts the looping value held under `id` from the top of its turn.
    ///
    /// What a caret's blink is reset by on every edit, so the mark holds solid
    /// while the typing it reports is still happening. Forgetting the entry is
    /// enough: the next ask starts a fresh turn at zero, exactly as a loop
    /// being seen for the first time does.
    pub(crate) fn reset_phase(&mut self, id: Id) {
        self.cycles.remove(&id);
    }

    /// Settles the frame's interaction state.
    ///
    /// A press is released here rather than where it was drawn, so that letting
    /// go over something that has since vanished — a row that scrolled away, a
    /// button on a tab that was switched — still ends the press.
    pub fn end_frame(&mut self, input: &Input) {
        if !input.any_held() {
            self.active = None;
        }

        if self.pending_focus_step != 0 && !self.focus_order.is_empty() {
            let position = self.focus.and_then(|id| self.focus_order.iter().position(|&f| f == id));
            let count = self.focus_order.len() as i32;
            let next = match position {
                Some(current) => (current as i32 + self.pending_focus_step).rem_euclid(count),
                // Nothing focused: Tab starts at the beginning and Shift-Tab at
                // the end, which is what every other interface does.
                None if self.pending_focus_step > 0 => 0,
                None => count - 1,
            };
            self.set_focus(Some(self.focus_order[next as usize]));
        }
        self.pending_focus_step = 0;
        self.focus_order.clear();

        // A caret belonging to nothing on screen is state that can only grow.
        if let Some(focus) = self.focus {
            self.carets.retain(|id, _| *id == focus);
        } else {
            self.carets.clear();
        }

        // The same for eased values: anything this frame did not draw is gone
        // from the screen, so its position is not worth remembering. A row
        // scrolled back into view then starts settled rather than animating from
        // where it was when it left.
        let frame = self.frame;
        self.eased.retain(|_, eased| eased.seen == frame);
        // And for looping ones, which is what stops a sweep resuming half way
        // round when whatever it belonged to comes back on screen.
        self.cycles.retain(|_, cycle| cycle.seen == frame);

        // What the pointer was over is now what it *was* over. Anything this
        // frame did not draw is simply not in the new set.
        self.was_hovered = std::mem::take(&mut self.hovered);

        // A paste is delivered *after* this, so anything still here was offered
        // to the frame that asked for it and not taken — the field that wanted
        // it has since lost the keyboard or gone. Pasting it into whatever holds
        // the keyboard next would be text arriving in a place nobody aimed it.
        self.pasted = None;
    }

    /// Notes that Tab was pressed, to be resolved at the end of the frame.
    ///
    /// Taken once per frame rather than by whichever field happens to be
    /// focused: focus must move even when what holds it does not handle keys,
    /// and only the finished frame knows the full order.
    pub(crate) fn step_focus(&mut self, step: i32) {
        self.pending_focus_step = step;
        self.focus_source = FocusSource::Keyboard;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_stable_and_distinct() {
        assert_eq!(Id::new("services"), Id::new("services"));
        assert_ne!(Id::new("services"), Id::new("sites"));
        assert_ne!(Id::new("a").with("b"), Id::new("b").with("a"));
        assert_ne!(Id::ROOT.index(1), Id::ROOT.index(2));
    }

    #[test]
    fn a_child_identifier_differs_from_its_parent() {
        let parent = Id::new("panel");
        assert_ne!(parent, parent.with("button"));
        assert_ne!(parent, parent.index(0));
    }

    #[test]
    fn focus_from_a_press_is_not_ringed_and_focus_from_the_keyboard_is() {
        // The two routes to the keyboard, told apart: a click already showed
        // the person where they aimed, and Tab showed them nothing.
        let mut memory = Memory::new();
        memory.press(Id::new("button"));
        assert!(!memory.focus_visible(), "a click is its own confirmation");

        memory.offer_focus(Id::new("button"));
        memory.step_focus(1);
        memory.end_frame(&Input::new());
        assert!(memory.focus_visible(), "keyboard focus is invisible without the ring");

        memory.press(Id::new("button"));
        assert!(!memory.focus_visible(), "the next click takes the ring back off");
    }

    #[test]
    fn a_reset_loop_starts_its_turn_again_from_the_top() {
        let mut memory = Memory::new();
        let id = Id::new("caret");
        for _ in 0..30 {
            stepped(&mut memory, 1.0 / 60.0);
            memory.phase(id, 1.0);
        }
        assert!(memory.phase(id, 1.0) > 0.3, "the loop has travelled");

        memory.reset_phase(id);
        stepped(&mut memory, 1.0 / 60.0);
        let restarted = memory.phase(id, 1.0);
        assert!(restarted < 0.05, "expected a fresh turn, got {restarted}");
    }

    #[test]
    fn a_press_is_forgotten_when_nothing_is_held_any_more() {
        let mut memory = Memory::new();
        memory.press(Id::new("button"));
        memory.end_frame(&Input::new());
        assert_eq!(memory.active(), None);
    }

    #[test]
    fn tab_moves_focus_through_the_order_the_frame_drew() {
        let mut memory = Memory::new();
        let (first, second) = (Id::new("first"), Id::new("second"));

        for expected in [first, second, first] {
            memory.offer_focus(first);
            memory.offer_focus(second);
            memory.step_focus(1);
            memory.end_frame(&Input::new());
            assert_eq!(memory.focused(), Some(expected), "focus should advance and wrap");
        }
    }

    #[test]
    fn shift_tab_moves_backwards_and_wraps() {
        let mut memory = Memory::new();
        let (first, second) = (Id::new("first"), Id::new("second"));

        for expected in [second, first, second] {
            memory.offer_focus(first);
            memory.offer_focus(second);
            memory.step_focus(-1);
            memory.end_frame(&Input::new());
            assert_eq!(memory.focused(), Some(expected));
        }
    }

    #[test]
    fn tab_with_nothing_focusable_on_screen_changes_nothing() {
        let mut memory = Memory::new();
        memory.step_focus(1);
        memory.end_frame(&Input::new());
        assert_eq!(memory.focused(), None);
    }

    #[test]
    fn carets_of_fields_that_are_gone_do_not_accumulate() {
        let mut memory = Memory::new();
        memory.set_focus(Some(Id::new("field-one")));
        memory.end_frame(&Input::new());
        memory.set_focus(Some(Id::new("field-two")));
        memory.end_frame(&Input::new());
        assert_eq!(memory.carets.len(), 1);
    }

    /// Steps the memory by one frame of the given length.
    fn stepped(memory: &mut Memory, seconds: f32) {
        memory.begin_frame(std::time::Duration::from_secs_f32(seconds));
    }

    #[test]
    fn a_value_seen_for_the_first_time_starts_at_its_target() {
        let mut memory = Memory::new();
        stepped(&mut memory, 1.0 / 60.0);
        assert_eq!(memory.ease(Id::new("hover"), 1.0, 0.1), 1.0);
        assert!(!memory.is_animating(), "nothing should animate on first sight");
    }

    #[test]
    fn a_changed_target_is_approached_rather_than_jumped_to() {
        let mut memory = Memory::new();
        let id = Id::new("hover");
        stepped(&mut memory, 1.0 / 60.0);
        memory.ease(id, 0.0, 0.1);

        stepped(&mut memory, 1.0 / 60.0);
        let first = memory.ease(id, 1.0, 0.1);
        assert!(first > 0.0 && first < 1.0, "expected a step along the way, got {first}");
        assert!(memory.is_animating());

        stepped(&mut memory, 1.0 / 60.0);
        assert!(memory.ease(id, 1.0, 0.1) > first, "it should keep closing on its target");
    }

    #[test]
    fn an_animation_settles_exactly_and_then_stops_asking_for_frames() {
        let mut memory = Memory::new();
        let id = Id::new("hover");
        stepped(&mut memory, 1.0 / 60.0);
        memory.ease(id, 0.0, 0.05);

        // Exponential easing never truly arrives, so this asserts the threshold
        // does its job: without it the interface would redraw for ever.
        for _ in 0..200 {
            stepped(&mut memory, 1.0 / 60.0);
            memory.ease(id, 1.0, 0.05);
        }
        assert_eq!(memory.ease(id, 1.0, 0.05), 1.0);
        assert!(!memory.is_animating(), "a settled animation must not keep the loop awake");
    }

    #[test]
    fn the_same_elapsed_time_moves_a_value_the_same_distance_at_any_frame_rate() {
        // The whole point of easing on elapsed time rather than per frame: a
        // slow machine must not animate more slowly, only less smoothly.
        let travel = |frames: u32, seconds: f32| {
            let mut memory = Memory::new();
            let id = Id::new("hover");
            stepped(&mut memory, seconds);
            memory.ease(id, 0.0, 0.1);
            for _ in 0..frames {
                stepped(&mut memory, seconds);
                memory.ease(id, 1.0, 0.1);
            }
            memory.ease(id, 1.0, 0.1)
        };

        let fast = travel(20, 1.0 / 120.0);
        let slow = travel(10, 1.0 / 60.0);
        assert!((fast - slow).abs() < 0.02, "{fast} and {slow} should agree after equal time");
    }

    #[test]
    fn a_stalled_frame_is_treated_as_a_slow_one_rather_than_a_leap() {
        let mut memory = Memory::new();
        let id = Id::new("hover");
        stepped(&mut memory, 1.0 / 60.0);
        memory.ease(id, 0.0, 0.1);

        memory.begin_frame(std::time::Duration::from_secs(30));
        assert!(
            memory.ease(id, 1.0, 0.1) < 1.0,
            "a thirty-second stall should not finish the animation outright"
        );
    }

    #[test]
    fn eased_values_nothing_draws_any_more_are_forgotten() {
        let mut memory = Memory::new();
        stepped(&mut memory, 1.0 / 60.0);
        memory.ease(Id::new("row-1"), 1.0, 0.1);
        memory.end_frame(&Input::new());
        assert_eq!(memory.eased.len(), 1);

        // A frame that draws something else entirely: the first row has scrolled
        // away, and remembering where its hover got to would only accumulate.
        stepped(&mut memory, 1.0 / 60.0);
        memory.ease(Id::new("row-2"), 1.0, 0.1);
        memory.end_frame(&Input::new());
        assert_eq!(memory.eased.len(), 1);
        assert!(memory.eased.contains_key(&Id::new("row-2")));
    }

    #[test]
    fn a_looping_value_advances_by_the_time_the_frame_took() {
        let mut memory = Memory::new();
        let id = Id::new("sweep");

        // A tenth of a second of a one-second loop is a tenth of the way round.
        for _ in 0..6 {
            stepped(&mut memory, 1.0 / 60.0);
            memory.phase(id, 1.0);
        }
        let after = memory.phase(id, 1.0);
        assert!((after - 0.1).abs() < 0.02, "expected about a tenth round, got {after}");
    }

    #[test]
    fn a_looping_value_wraps_rather_than_running_away() {
        let mut memory = Memory::new();
        let id = Id::new("sweep");
        for _ in 0..300 {
            stepped(&mut memory, 1.0 / 60.0);
            let phase = memory.phase(id, 0.5);
            assert!((0.0..1.0).contains(&phase), "a phase left its own turn: {phase}");
        }
    }

    #[test]
    fn a_loop_takes_as_long_on_a_slow_machine_as_on_a_quick_one() {
        // The same reasoning easing rests on: a machine drawing half as many
        // frames must turn the sweep at the same speed, only less smoothly.
        let travelled = |frames: u32, seconds: f32| {
            let mut memory = Memory::new();
            let id = Id::new("sweep");
            for _ in 0..frames {
                stepped(&mut memory, seconds);
                memory.phase(id, 2.0);
            }
            memory.phase(id, 2.0)
        };

        let fast = travelled(40, 1.0 / 120.0);
        let slow = travelled(20, 1.0 / 60.0);
        assert!((fast - slow).abs() < 0.01, "{fast} and {slow} should agree after equal time");
    }

    #[test]
    fn a_loop_keeps_asking_for_frames_because_it_never_arrives() {
        // The difference from easing, stated: a cycle has nowhere to settle, so
        // drawing one is asking for the next frame — which is why it is only
        // drawn while the loop is what the interface is reporting.
        let mut memory = Memory::new();
        stepped(&mut memory, 1.0 / 60.0);
        memory.phase(Id::new("sweep"), 1.2);
        assert!(memory.is_animating());
    }

    #[test]
    fn a_period_of_nothing_holds_still_and_lets_the_window_sleep() {
        let mut memory = Memory::new();
        stepped(&mut memory, 1.0 / 60.0);
        assert_eq!(memory.phase(Id::new("sweep"), 0.0), 0.0);
        assert!(!memory.is_animating(), "a loop with no period must not spin the loop");
    }

    #[test]
    fn two_loops_run_at_their_own_periods() {
        let mut memory = Memory::new();
        let (sweep, pulse) = (Id::new("sweep"), Id::new("pulse"));
        for _ in 0..20 {
            stepped(&mut memory, 1.0 / 60.0);
            memory.phase(sweep, 1.0);
            memory.phase(pulse, 4.0);
        }
        assert!(
            memory.phase(sweep, 1.0) > memory.phase(pulse, 4.0),
            "the quicker loop should be further round than the slower one"
        );
    }

    #[test]
    fn loops_nothing_draws_any_more_are_forgotten() {
        // So a sweep that scrolled away starts at its beginning when it comes
        // back rather than resuming half way round.
        let mut memory = Memory::new();
        stepped(&mut memory, 1.0 / 60.0);
        memory.phase(Id::new("row-1"), 1.0);
        memory.end_frame(&Input::new());
        assert_eq!(memory.cycles.len(), 1);

        stepped(&mut memory, 1.0 / 60.0);
        memory.phase(Id::new("row-2"), 1.0);
        memory.end_frame(&Input::new());
        assert_eq!(memory.cycles.len(), 1);
        assert!(memory.cycles.contains_key(&Id::new("row-2")));
    }

    #[test]
    fn a_copy_is_queued_for_the_window_and_handed_over_once() {
        let mut memory = Memory::new();
        memory.copy_to_clipboard("selfhost".into());

        let request = memory.take_clipboard_request();
        assert_eq!(request.copy.as_deref(), Some("selfhost"));
        assert!(!request.paste, "copying is not also asking to paste");
        assert_eq!(memory.take_clipboard_request().copy, None, "the copy was performed twice");
    }

    #[test]
    fn asking_to_paste_also_asks_for_the_frame_that_will_show_it() {
        let mut memory = Memory::new();
        stepped(&mut memory, 1.0 / 60.0);
        memory.request_paste();

        assert!(memory.take_clipboard_request().paste);
        assert!(memory.is_animating(), "the paste would not appear until something else woke us");
    }

    #[test]
    fn the_clipboards_answer_is_read_by_the_next_frame_exactly_once() {
        let mut memory = Memory::new();
        memory.deliver_paste("pasted".into());
        assert_eq!(memory.take_pasted().as_deref(), Some("pasted"));
        assert_eq!(memory.take_pasted(), None, "the same paste arrived twice");
    }

    #[test]
    fn an_answer_nobody_took_is_dropped_rather_than_kept_for_later() {
        // The field that asked has lost the keyboard by the time the answer
        // arrives. Holding it would paste it into whatever is focused next.
        let mut memory = Memory::new();
        memory.deliver_paste("pasted".into());
        memory.end_frame(&Input::new());
        assert_eq!(memory.take_pasted(), None);
    }

    #[test]
    fn where_the_caret_is_belongs_to_one_frame_only() {
        let mut memory = Memory::new();
        stepped(&mut memory, 1.0 / 60.0);
        memory.set_caret_area(Rect::new(4.0, 8.0, 2.0, 16.0));
        assert!(memory.caret_area().is_some());

        stepped(&mut memory, 1.0 / 60.0);
        assert_eq!(memory.caret_area(), None, "a frame that drew no caret still reported one");
    }

    #[test]
    fn scroll_offsets_are_remembered_per_area() {
        let mut memory = Memory::new();
        let (logs, services) = (Id::new("logs"), Id::new("services"));
        memory.set_scroll_offset(logs, 42.0);
        assert_eq!(memory.scroll_offset(logs), 42.0);
        assert_eq!(memory.scroll_offset(services), 0.0);
    }
}
