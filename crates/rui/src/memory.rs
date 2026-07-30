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
    /// A press that began on it ended on it, this frame.
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

/// Where a caret sits in a field being edited.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Caret {
    /// Byte offset within the field's text.
    pub(crate) offset: usize,
}

/// How far an eased value has travelled, and when it was last asked for.
#[derive(Debug, Clone, Copy)]
struct Eased {
    value: f32,
    /// The frame it was last asked for, so values nothing draws are dropped.
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
    scroll: HashMap<Id, f32>,
    content_height: HashMap<Id, f32>,
    carets: HashMap<Id, Caret>,
    /// Every focusable element drawn this frame, in the order it was drawn.
    focus_order: Vec<Id>,
    /// Set when Tab was pressed, resolved once the frame's order is known.
    pending_focus_step: i32,
    /// Where each animated value has got to.
    eased: HashMap<Id, Eased>,
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
        self.set_focus(Some(id));
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

        // What the pointer was over is now what it *was* over. Anything this
        // frame did not draw is simply not in the new set.
        self.was_hovered = std::mem::take(&mut self.hovered);
    }

    /// Notes that Tab was pressed, to be resolved at the end of the frame.
    ///
    /// Taken once per frame rather than by whichever field happens to be
    /// focused: focus must move even when what holds it does not handle keys,
    /// and only the finished frame knows the full order.
    pub(crate) fn step_focus(&mut self, step: i32) {
        self.pending_focus_step = step;
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
    fn scroll_offsets_are_remembered_per_area() {
        let mut memory = Memory::new();
        let (logs, services) = (Id::new("logs"), Id::new("services"));
        memory.set_scroll_offset(logs, 42.0);
        assert_eq!(memory.scroll_offset(logs), 42.0);
        assert_eq!(memory.scroll_offset(services), 0.0);
    }
}
