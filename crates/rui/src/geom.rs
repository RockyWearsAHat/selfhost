//! Points, sizes, and rectangles, in logical units.
//!
//! Everything above the canvas works in *logical* coordinates — the units a
//! layout is written in — and only [`crate::canvas::Canvas`] multiplies by the
//! display scale to reach device pixels. Keeping the conversion in exactly one
//! place is what stops a HiDPI screen from needing a second set of numbers
//! threaded through the widgets.
//!
//! The origin is the top left and y grows downward, matching every windowing
//! system this runs on and the memory order of the pixel buffer.

/// A position, in logical units.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Point {
    /// Distance from the left edge.
    pub x: f32,
    /// Distance from the top edge.
    pub y: f32,
}

impl Point {
    /// A point at `(x, y)`.
    pub const fn new(x: f32, y: f32) -> Self {
        Self { x, y }
    }

    /// The origin.
    pub const ZERO: Self = Self { x: 0.0, y: 0.0 };

    /// This point moved by `dx` and `dy`.
    pub fn offset(self, dx: f32, dy: f32) -> Self {
        Self { x: self.x + dx, y: self.y + dy }
    }
}

/// A width and a height, in logical units.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Size {
    /// Horizontal extent.
    pub w: f32,
    /// Vertical extent.
    pub h: f32,
}

impl Size {
    /// A size of `w` by `h`.
    pub const fn new(w: f32, h: f32) -> Self {
        Self { w, h }
    }

    /// Zero by zero.
    pub const ZERO: Self = Self { w: 0.0, h: 0.0 };
}

/// Padding or margin on each of the four edges.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Insets {
    /// Left edge.
    pub left: f32,
    /// Top edge.
    pub top: f32,
    /// Right edge.
    pub right: f32,
    /// Bottom edge.
    pub bottom: f32,
}

impl Insets {
    /// The same inset on all four edges.
    pub const fn uniform(amount: f32) -> Self {
        Self { left: amount, top: amount, right: amount, bottom: amount }
    }

    /// `horizontal` on the left and right, `vertical` on the top and bottom.
    pub const fn symmetric(horizontal: f32, vertical: f32) -> Self {
        Self { left: horizontal, top: vertical, right: horizontal, bottom: vertical }
    }

    /// Insets given edge by edge.
    pub const fn new(left: f32, top: f32, right: f32, bottom: f32) -> Self {
        Self { left, top, right, bottom }
    }

    /// Nothing on any edge.
    pub const ZERO: Self = Self::uniform(0.0);

    /// Total horizontal inset.
    pub fn horizontal(self) -> f32 {
        self.left + self.right
    }

    /// Total vertical inset.
    pub fn vertical(self) -> f32 {
        self.top + self.bottom
    }
}

/// An axis-aligned rectangle, in logical units.
///
/// Stored as an origin plus an extent rather than two corners because that is
/// what layout produces and what drawing consumes; the corner accessors derive
/// the other form. Width and height are never negative — [`Rect::intersect`]
/// answers an empty rectangle rather than an inside-out one, so a clipped-away
/// region reports `is_empty` instead of drawing in reverse.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Rect {
    /// Left edge.
    pub x: f32,
    /// Top edge.
    pub y: f32,
    /// Width; never negative.
    pub w: f32,
    /// Height; never negative.
    pub h: f32,
}

impl Rect {
    /// A rectangle at `(x, y)` measuring `w` by `h`.
    ///
    /// A negative extent is clamped to zero rather than kept, so that every
    /// rectangle in the system satisfies `max >= min`.
    pub fn new(x: f32, y: f32, w: f32, h: f32) -> Self {
        Self { x, y, w: w.max(0.0), h: h.max(0.0) }
    }

    /// A rectangle from its top-left corner and its size.
    pub fn from_origin(origin: Point, size: Size) -> Self {
        Self::new(origin.x, origin.y, size.w, size.h)
    }

    /// A rectangle from two opposite corners, in either order.
    pub fn from_corners(a: Point, b: Point) -> Self {
        Self {
            x: a.x.min(b.x),
            y: a.y.min(b.y),
            w: (a.x - b.x).abs(),
            h: (a.y - b.y).abs(),
        }
    }

    /// The empty rectangle at the origin.
    pub const ZERO: Self = Self { x: 0.0, y: 0.0, w: 0.0, h: 0.0 };

    /// Left edge.
    pub fn min_x(self) -> f32 {
        self.x
    }

    /// Top edge.
    pub fn min_y(self) -> f32 {
        self.y
    }

    /// Right edge.
    pub fn max_x(self) -> f32 {
        self.x + self.w
    }

    /// Bottom edge.
    pub fn max_y(self) -> f32 {
        self.y + self.h
    }

    /// Top-left corner.
    pub fn origin(self) -> Point {
        Point::new(self.x, self.y)
    }

    /// Width and height.
    pub fn size(self) -> Size {
        Size::new(self.w, self.h)
    }

    /// The point at the middle of the rectangle.
    pub fn center(self) -> Point {
        Point::new(self.x + self.w / 2.0, self.y + self.h / 2.0)
    }

    /// Whether the rectangle encloses no area.
    pub fn is_empty(self) -> bool {
        self.w <= 0.0 || self.h <= 0.0
    }

    /// Whether `point` falls inside, counting the left and top edges but not
    /// the right and bottom.
    ///
    /// Half-open on purpose: two rectangles that share an edge must not both
    /// claim a pointer sitting on it, or adjacent buttons would both light up.
    pub fn contains(self, point: Point) -> bool {
        point.x >= self.x && point.x < self.max_x() && point.y >= self.y && point.y < self.max_y()
    }

    /// This rectangle shrunk by `insets`, never smaller than empty.
    pub fn inset(self, insets: Insets) -> Self {
        Self::new(
            self.x + insets.left,
            self.y + insets.top,
            self.w - insets.horizontal(),
            self.h - insets.vertical(),
        )
    }

    /// This rectangle grown by `insets`.
    pub fn expand(self, insets: Insets) -> Self {
        Self::new(
            self.x - insets.left,
            self.y - insets.top,
            self.w + insets.horizontal(),
            self.h + insets.vertical(),
        )
    }

    /// This rectangle moved by `dx` and `dy`.
    pub fn translate(self, dx: f32, dy: f32) -> Self {
        Self { x: self.x + dx, y: self.y + dy, ..self }
    }

    /// The overlap of two rectangles, empty when they do not overlap.
    pub fn intersect(self, other: Self) -> Self {
        let x = self.x.max(other.x);
        let y = self.y.max(other.y);
        let right = self.max_x().min(other.max_x());
        let bottom = self.max_y().min(other.max_y());
        Self::new(x, y, right - x, bottom - y)
    }

    /// The smallest rectangle containing both.
    pub fn union(self, other: Self) -> Self {
        if self.is_empty() {
            return other;
        }
        if other.is_empty() {
            return self;
        }
        Self::from_corners(
            Point::new(self.x.min(other.x), self.y.min(other.y)),
            Point::new(self.max_x().max(other.max_x()), self.max_y().max(other.max_y())),
        )
    }

    /// Cuts `amount` off the top, answering `(top, bottom)`.
    ///
    /// # Why every split answers in spatial order
    ///
    /// All four of these answer their pieces in reading order — top before
    /// bottom, left before right — and the *name* says which piece is the one
    /// given a fixed size. The obvious alternative, `(taken, remainder)`, puts
    /// the pieces in a different order depending on which method was called, so
    /// `split_right` hands back the right-hand piece first. That reads as
    /// correct and is not, it type-checks, and what it produces is a layout with
    /// two elements swapped — which is exactly the bug it caused here before
    /// this was changed.
    ///
    /// Cutting more than there is yields the whole rectangle and an empty
    /// remainder rather than overshooting past the edge.
    pub fn split_top(self, amount: f32) -> (Self, Self) {
        let taken = amount.clamp(0.0, self.h);
        (
            Self::new(self.x, self.y, self.w, taken),
            Self::new(self.x, self.y + taken, self.w, self.h - taken),
        )
    }

    /// Cuts `amount` off the bottom, answering `(top, bottom)`.
    pub fn split_bottom(self, amount: f32) -> (Self, Self) {
        let taken = amount.clamp(0.0, self.h);
        (
            Self::new(self.x, self.y, self.w, self.h - taken),
            Self::new(self.x, self.max_y() - taken, self.w, taken),
        )
    }

    /// Cuts `amount` off the left, answering `(left, right)`.
    pub fn split_left(self, amount: f32) -> (Self, Self) {
        let taken = amount.clamp(0.0, self.w);
        (
            Self::new(self.x, self.y, taken, self.h),
            Self::new(self.x + taken, self.y, self.w - taken, self.h),
        )
    }

    /// Cuts `amount` off the right, answering `(left, right)`.
    pub fn split_right(self, amount: f32) -> (Self, Self) {
        let taken = amount.clamp(0.0, self.w);
        (
            Self::new(self.x, self.y, self.w - taken, self.h),
            Self::new(self.max_x() - taken, self.y, taken, self.h),
        )
    }

    /// A rectangle of `size` centred inside this one.
    pub fn centered(self, size: Size) -> Self {
        Self::new(
            self.x + (self.w - size.w) / 2.0,
            self.y + (self.h - size.h) / 2.0,
            size.w,
            size.h,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_extents_become_empty_rather_than_inside_out() {
        let rect = Rect::new(10.0, 10.0, -5.0, -5.0);
        assert!(rect.is_empty());
        assert_eq!(rect.max_x(), 10.0);
    }

    #[test]
    fn containment_is_half_open_so_neighbours_do_not_both_claim_a_point() {
        let left = Rect::new(0.0, 0.0, 10.0, 10.0);
        let right = Rect::new(10.0, 0.0, 10.0, 10.0);
        let seam = Point::new(10.0, 5.0);
        assert!(!left.contains(seam));
        assert!(right.contains(seam));
    }

    #[test]
    fn disjoint_rectangles_intersect_to_empty() {
        let a = Rect::new(0.0, 0.0, 5.0, 5.0);
        let b = Rect::new(50.0, 50.0, 5.0, 5.0);
        assert!(a.intersect(b).is_empty());
    }

    #[test]
    fn intersection_keeps_the_overlap() {
        let a = Rect::new(0.0, 0.0, 10.0, 10.0);
        let b = Rect::new(5.0, 5.0, 10.0, 10.0);
        assert_eq!(a.intersect(b), Rect::new(5.0, 5.0, 5.0, 5.0));
    }

    #[test]
    fn union_ignores_an_empty_operand() {
        let real = Rect::new(4.0, 4.0, 2.0, 2.0);
        assert_eq!(real.union(Rect::ZERO), real);
        assert_eq!(Rect::ZERO.union(real), real);
    }

    #[test]
    fn splitting_more_than_there_is_takes_everything_and_leaves_nothing() {
        let rect = Rect::new(0.0, 0.0, 10.0, 10.0);
        let (taken, rest) = rect.split_top(999.0);
        assert_eq!(taken, rect);
        assert!(rest.is_empty());
    }

    #[test]
    fn splits_partition_the_rectangle() {
        let rect = Rect::new(2.0, 3.0, 20.0, 30.0);
        let (top, rest) = rect.split_top(12.0);
        assert_eq!(top.h + rest.h, rect.h);
        assert_eq!(top.max_y(), rest.min_y());

        let (left, right) = rect.split_left(7.0);
        assert_eq!(left.w + right.w, rect.w);
        assert_eq!(left.max_x(), right.min_x());
    }

    #[test]
    fn every_split_answers_its_pieces_in_reading_order() {
        let rect = Rect::new(0.0, 0.0, 100.0, 100.0);

        for (top, bottom) in [rect.split_top(30.0), rect.split_bottom(30.0)] {
            assert!(top.min_y() < bottom.min_y(), "the top piece must come first");
            assert_eq!(top.max_y(), bottom.min_y());
            assert_eq!(top.h + bottom.h, rect.h);
        }

        for (left, right) in [rect.split_left(30.0), rect.split_right(30.0)] {
            assert!(left.min_x() < right.min_x(), "the left piece must come first");
            assert_eq!(left.max_x(), right.min_x());
            assert_eq!(left.w + right.w, rect.w);
        }
    }

    #[test]
    fn the_name_says_which_piece_is_the_fixed_one() {
        let rect = Rect::new(0.0, 0.0, 100.0, 100.0);
        assert_eq!(rect.split_top(30.0).0.h, 30.0);
        assert_eq!(rect.split_bottom(30.0).1.h, 30.0);
        assert_eq!(rect.split_left(30.0).0.w, 30.0);
        assert_eq!(rect.split_right(30.0).1.w, 30.0);
    }

    #[test]
    fn inset_then_expand_returns_the_original() {
        let rect = Rect::new(1.0, 2.0, 40.0, 50.0);
        let padding = Insets::symmetric(4.0, 6.0);
        assert_eq!(rect.inset(padding).expand(padding), rect);
    }

    #[test]
    fn centering_leaves_equal_margins() {
        let outer = Rect::new(0.0, 0.0, 100.0, 50.0);
        let inner = outer.centered(Size::new(40.0, 10.0));
        assert_eq!(inner.min_x() - outer.min_x(), outer.max_x() - inner.max_x());
        assert_eq!(inner.min_y() - outer.min_y(), outer.max_y() - inner.max_y());
    }
}
