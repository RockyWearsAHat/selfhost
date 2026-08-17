//! The cursor policy: what to send about the pointer, and when.
//!
//! # Why the pointer is not part of the picture
//!
//! It would be simpler to composite the pointer into the captured frame and send
//! one image. It would also make the pointer move at the *capture* rate, which
//! over a tunnel means the pointer lags the operator's hand by a whole round
//! trip plus a frame interval. Nothing else about a remote desktop is as
//! immediately, viscerally wrong as a pointer that trails behind the mouse, and
//! separating it is the single largest perceived-latency win available to this
//! design.
//!
//! So the pointer travels as its own two messages. Its **position** is small and
//! is sent whenever it moves, so the client can move a second canvas by a CSS
//! transform at the browser's own frame rate. Its **shape** is a bitmap and is
//! sent only when it is one the client has not seen — which is what this module
//! decides.
//!
//! # Why the cache is bounded, and why it is LRU
//!
//! A shape id on Windows is an `HCURSOR` value and on macOS a pointer-derived
//! handle. Neither is under our control, and neither is guaranteed not to churn:
//! an application that creates cursors dynamically — an image editor with a
//! brush preview, a terminal with a custom I-beam — produces a new id every
//! time. An unbounded cache would therefore be an unbounded allocation driven by
//! whatever is running on the far machine, in the client's process.
//!
//! Bounded means something must be evicted, and least-recently-used is the right
//! rule here for a reason specific to pointers: a desktop cycles through a small
//! working set — arrow, I-beam, hand, the eight resize handles — and returns to
//! it constantly. LRU keeps exactly that working set and evicts the one-off
//! shapes, which is the behaviour "send the bitmap again" costs least for.
//!
//! An evicted shape is not an error and not a lost frame: the next time it
//! appears, [`ShapeCache::observe`] answers [`ShapeDecision::Fresh`] and the
//! bitmap is sent again. The cost of a cache miss is one small message.

/// A platform shape identifier.
///
/// Opaque on purpose. It is an `HCURSOR` on Windows and a handle-derived value
/// on macOS; this crate never interprets it, and wrapping it stops it being
/// confused with the monitor ids and sequence numbers it shares a message with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShapeId(pub u64);

/// How many distinct shapes a cache holds.
///
/// Thirty-two comfortably covers the working set of every desktop environment
/// tested — arrow, I-beam, wait, hand, help, cross, and the eight resize
/// handles, with room for whatever the focused application adds. It also bounds
/// the client's memory: with the wire's 128-pixel cursor ceiling, thirty-two
/// shapes is at most two mebibytes.
pub const DEFAULT_CAPACITY: usize = 32;

/// What to do about a shape the far end just reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShapeDecision {
    /// The client already holds this shape; send the position only.
    Known(ShapeId),
    /// The client does not hold this shape; send the bitmap with it.
    Fresh(ShapeId),
}

impl ShapeDecision {
    /// The shape either way.
    pub const fn id(self) -> ShapeId {
        match self {
            Self::Known(id) | Self::Fresh(id) => id,
        }
    }

    /// Whether the bitmap must accompany this update.
    pub const fn needs_bitmap(self) -> bool {
        matches!(self, Self::Fresh(_))
    }
}

/// Which shapes the far end has been told about.
///
/// Held by the **sender**, and it models the receiver's memory. The two can only
/// disagree if a message is lost, which the transport underneath does not
/// permit: a WebSocket either delivers in order or closes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeCache {
    /// Most recently used first. A `Vec` rather than a map because the capacity
    /// is thirty-two: a linear scan of thirty-two `u64`s is faster than hashing
    /// one, and this runs once per frame rather than once per pixel.
    recent: Vec<ShapeId>,
    capacity: usize,
}

impl Default for ShapeCache {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl ShapeCache {
    /// A cache holding at most `capacity` shapes.
    ///
    /// A capacity of zero is legal and means every shape is sent every time —
    /// wasteful, but correct, and it makes "the cache is disabled" a
    /// configuration rather than a code path.
    pub fn new(capacity: usize) -> Self {
        Self { recent: Vec::with_capacity(capacity.min(DEFAULT_CAPACITY)), capacity }
    }

    /// How many shapes are held.
    pub fn len(&self) -> usize {
        self.recent.len()
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.recent.is_empty()
    }

    /// Whether a shape is held, without recording a use.
    pub fn contains(&self, id: ShapeId) -> bool {
        self.recent.contains(&id)
    }

    /// Records that a shape is in use, and says whether its bitmap must be sent.
    ///
    /// Moves the shape to the front, so the least recently used sits at the back
    /// and is what gets evicted.
    pub fn observe(&mut self, id: ShapeId) -> ShapeDecision {
        if self.capacity == 0 {
            return ShapeDecision::Fresh(id);
        }
        if let Some(position) = self.recent.iter().position(|held| *held == id) {
            let held = self.recent.remove(position);
            self.recent.insert(0, held);
            return ShapeDecision::Known(id);
        }
        self.recent.insert(0, id);
        self.recent.truncate(self.capacity);
        ShapeDecision::Fresh(id)
    }

    /// Forgets everything.
    ///
    /// Called when a client reconnects: the new client holds no shapes, and a
    /// sender that believes otherwise sends positions for a bitmap the receiver
    /// has never seen, which draws nothing at all.
    pub fn forget_all(&mut self) {
        self.recent.clear();
    }
}

/// Where the pointer is and what it looks like, as the far end reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pointer {
    /// Virtual-desktop x, which is negative on a monitor left of the primary.
    pub x: i32,
    /// Virtual-desktop y, which is negative on a monitor above the primary.
    pub y: i32,
    /// Whether the platform is drawing a pointer at all. Hidden while typing in
    /// most editors, and a client that draws one anyway shows a pointer the
    /// person at the machine cannot see.
    pub visible: bool,
    /// The current shape.
    pub shape: ShapeId,
}

/// What to put on the wire for one pointer observation.
///
/// Both fields may be `None`: a pointer that has not moved and whose shape the
/// client already holds costs nothing at all, which is the common case sixty
/// times a second while the operator reads something.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Emission {
    /// The pointer, if its position or visibility changed.
    pub position: Option<Pointer>,
    /// The shape whose bitmap must be sent with it, if any.
    pub shape: Option<ShapeId>,
}

impl Emission {
    /// Whether nothing at all needs to be sent.
    pub const fn is_empty(&self) -> bool {
        self.position.is_none() && self.shape.is_none()
    }
}

/// The sender's whole cursor policy: the cache plus the last thing sent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CursorPolicy {
    cache: ShapeCache,
    last: Option<Pointer>,
}

impl CursorPolicy {
    /// A policy with a cache of the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self { cache: ShapeCache::new(capacity), last: None }
    }

    /// The shape cache, for the diagnostics plate.
    pub fn cache(&self) -> &ShapeCache {
        &self.cache
    }

    /// Decides what to send about the pointer now.
    ///
    /// A shape the client does not hold forces the position to be sent as well,
    /// even if the pointer has not moved: the bitmap message carries no
    /// position, so a shape change at rest would otherwise leave the client
    /// holding a new bitmap it does not know where to draw.
    pub fn observe(&mut self, current: Pointer) -> Emission {
        let decision = self.cache.observe(current.shape);
        let moved = self.last != Some(current);
        self.last = Some(current);

        Emission {
            position: (moved || decision.needs_bitmap()).then_some(current),
            shape: decision.needs_bitmap().then_some(current.shape),
        }
    }

    /// Forgets the client's state entirely, for a reconnect.
    ///
    /// After this, the next observation sends both the position and the bitmap,
    /// whatever the pointer was doing — which is exactly what a client that has
    /// just attached needs.
    pub fn forget(&mut self) {
        self.cache.forget_all();
        self.last = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(x: i32, y: i32, shape: u64) -> Pointer {
        Pointer { x, y, visible: true, shape: ShapeId(shape) }
    }

    #[test]
    fn a_shape_is_fresh_once_and_known_afterwards() {
        let mut cache = ShapeCache::default();
        assert!(cache.is_empty());
        assert_eq!(cache.observe(ShapeId(7)), ShapeDecision::Fresh(ShapeId(7)));
        for _ in 0..100 {
            assert_eq!(cache.observe(ShapeId(7)), ShapeDecision::Known(ShapeId(7)));
        }
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(ShapeId(7)));
    }

    #[test]
    fn the_cache_never_grows_past_its_capacity() {
        let mut cache = ShapeCache::new(4);
        for id in 0..1000 {
            cache.observe(ShapeId(id));
            assert!(cache.len() <= 4, "cache grew to {}", cache.len());
        }
    }

    #[test]
    fn the_least_recently_used_shape_is_the_one_evicted() {
        let mut cache = ShapeCache::new(3);
        for id in [1, 2, 3] {
            cache.observe(ShapeId(id));
        }
        // Touching 1 makes 2 the oldest, so inserting 4 must evict 2 and not 1.
        assert_eq!(cache.observe(ShapeId(1)), ShapeDecision::Known(ShapeId(1)));
        assert_eq!(cache.observe(ShapeId(4)), ShapeDecision::Fresh(ShapeId(4)));
        assert!(cache.contains(ShapeId(1)));
        assert!(cache.contains(ShapeId(3)));
        assert!(cache.contains(ShapeId(4)));
        assert!(!cache.contains(ShapeId(2)));
    }

    #[test]
    fn an_evicted_shape_is_simply_sent_again() {
        // A cache miss must cost one message, never an error and never a shape
        // the client is left unable to draw.
        let mut cache = ShapeCache::new(2);
        cache.observe(ShapeId(1));
        cache.observe(ShapeId(2));
        cache.observe(ShapeId(3));
        assert_eq!(cache.observe(ShapeId(1)), ShapeDecision::Fresh(ShapeId(1)));
    }

    #[test]
    fn the_working_set_of_a_real_desktop_stays_resident() {
        // Arrow, I-beam and hand alternating for a long session, with the
        // occasional one-off shape from an application. The three must never be
        // evicted by the churn.
        let mut cache = ShapeCache::default();
        let working_set = [ShapeId(1), ShapeId(2), ShapeId(3)];
        for round in 0..10_000u64 {
            cache.observe(working_set[(round % 3) as usize]);
            if round % 7 == 0 {
                cache.observe(ShapeId(1000 + round));
            }
        }
        for shape in working_set {
            assert!(cache.contains(shape), "{shape:?} was evicted by transient shapes");
        }
    }

    #[test]
    fn a_zero_capacity_cache_sends_every_shape_every_time() {
        let mut cache = ShapeCache::new(0);
        for _ in 0..10 {
            assert_eq!(cache.observe(ShapeId(1)), ShapeDecision::Fresh(ShapeId(1)));
        }
        assert!(cache.is_empty());
    }

    #[test]
    fn a_motionless_pointer_with_a_known_shape_costs_nothing() {
        let mut policy = CursorPolicy::default();
        let first = policy.observe(at(10, 20, 1));
        assert_eq!(first.position, Some(at(10, 20, 1)));
        assert_eq!(first.shape, Some(ShapeId(1)));

        for _ in 0..100 {
            let emission = policy.observe(at(10, 20, 1));
            assert!(emission.is_empty(), "a still pointer must cost nothing");
        }
    }

    #[test]
    fn a_moved_pointer_sends_a_position_and_no_bitmap() {
        let mut policy = CursorPolicy::default();
        policy.observe(at(0, 0, 1));
        let emission = policy.observe(at(1, 0, 1));
        assert_eq!(emission.position, Some(at(1, 0, 1)));
        assert_eq!(emission.shape, None);
    }

    #[test]
    fn hiding_the_pointer_is_a_change_worth_sending() {
        let mut policy = CursorPolicy::default();
        policy.observe(at(5, 5, 1));
        let hidden = Pointer { visible: false, ..at(5, 5, 1) };
        let emission = policy.observe(hidden);
        assert_eq!(emission.position, Some(hidden));
        assert_eq!(emission.shape, None);
    }

    #[test]
    fn a_new_shape_at_rest_still_sends_the_position() {
        // The bitmap message carries no coordinates, so a shape change without a
        // position would leave the client holding a picture and no idea where it
        // goes.
        let mut policy = CursorPolicy::default();
        policy.observe(at(9, 9, 1));
        let emission = policy.observe(at(9, 9, 2));
        assert_eq!(emission.shape, Some(ShapeId(2)));
        assert_eq!(emission.position, Some(at(9, 9, 2)));
    }

    #[test]
    fn a_reconnect_forgets_everything_the_old_client_knew() {
        let mut policy = CursorPolicy::default();
        policy.observe(at(3, 4, 1));
        assert!(policy.observe(at(3, 4, 1)).is_empty());

        policy.forget();
        let emission = policy.observe(at(3, 4, 1));
        assert_eq!(emission.position, Some(at(3, 4, 1)));
        assert_eq!(emission.shape, Some(ShapeId(1)), "a fresh client holds no shapes");
        assert!(policy.cache().is_empty() || policy.cache().len() == 1);
    }

    #[test]
    fn a_decision_reports_its_shape_either_way() {
        assert_eq!(ShapeDecision::Known(ShapeId(4)).id(), ShapeId(4));
        assert_eq!(ShapeDecision::Fresh(ShapeId(4)).id(), ShapeId(4));
        assert!(!ShapeDecision::Known(ShapeId(4)).needs_bitmap());
        assert!(ShapeDecision::Fresh(ShapeId(4)).needs_bitmap());
    }
}
