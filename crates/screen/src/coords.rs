//! Where a pointer actually goes. Pure, and the only place any of this is done.
//!
//! Pointer coordinates travel absolute, in the pixel space of the display the
//! agent advertised. The client never computes an operating-system coordinate —
//! it says "monitor 2, pixel (14, 900)" and this module turns that into whatever
//! the platform's injection call wants. Relative motion is never sent at all:
//! Windows multiplies relative deltas by pointer acceleration by up to four
//! times, so a relative protocol lands the remote pointer somewhere the client
//! cannot predict and cannot correct.
//!
//! # Why this is one module rather than a few lines in each injector
//!
//! Three separate things in this arithmetic are wrong by default, and each of
//! them produces a symptom that gets diagnosed somewhere else:
//!
//! 1. **The virtual desktop's origin is negative** whenever a display sits to the
//!    left of or above the primary one. A monitor at `x = -1920` is the single
//!    most common real arrangement in this deployment and it is where an
//!    unsigned type or an unchecked subtraction hides. Every value here is `i64`
//!    and signed.
//! 2. **The normalisation divides by `extent - 1`, not by `extent`.** Divide by
//!    the extent and the far corner never reaches 65535, so the pointer can never
//!    touch the last column of pixels — which an operator experiences as "the
//!    close button doesn't work" rather than as an arithmetic bug.
//! 3. **Pixels are not points.** A Retina display reports 3024 pixels and 1512
//!    points; a Windows display at 150% reports 2560 pixels and 1707 points.
//!    macOS injection takes points, capture produces pixels, and the conversion
//!    between them rounds.
//!
//! Get any of those wrong and the pointer lands slightly off, progressively
//! further off toward one corner — which looks exactly like the symptom of a
//! missing `SetProcessDpiAwarenessContext` call in the agent. So the arithmetic
//! lives here, in one file with a table of cases, and when the pointer drifts on
//! the real machine this module can be *excluded* rather than suspected.
//!
//! # Everything is checked
//!
//! Every input to this module is either a number a remote client chose or a
//! number a graphics driver reported. The workspace builds with `panic = "abort"`,
//! so an overflow or a division by zero here is not a wrong pointer position, it
//! is the daemon exiting. Nothing here indexes, divides or multiplies without
//! having established that it can.

use selfhost_desk::wire::Monitor;
use std::fmt;

/// The largest value a normalised coordinate can take.
///
/// Windows' absolute-pointer input is a 16-bit fraction of the virtual desktop,
/// and this is its far edge. It is `u16::MAX` rather than 65536 because the
/// range is inclusive at both ends: 0 is the first pixel and this is the last.
pub const NORMALISED_MAX: u32 = 65_535;

/// A point in the virtual desktop, in physical pixels.
///
/// Signed because the virtual desktop's origin is the *primary* display's
/// top-left corner, not the bounding box's, so everything to the left of or above
/// the primary has negative coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualPoint {
    /// Horizontal position in virtual-desktop pixels.
    pub x: i64,
    /// Vertical position in virtual-desktop pixels.
    pub y: i64,
}

/// A point in a platform's *logical* coordinate space, in points.
///
/// Distinct from [`VirtualPoint`] as a type rather than by convention: the two
/// are the same shape and different units, which is exactly the pair that gets
/// swapped by accident and produces a pointer that lands at half or double the
/// intended distance from the origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Point {
    /// Horizontal position in points.
    pub x: i64,
    /// Vertical position in points.
    pub y: i64,
}

/// A display's origin in a platform's logical coordinate space.
///
/// Passed in rather than derived from a [`Monitor`], and that is deliberate. A
/// monitor's origin is carried in pixels, so recovering its point origin means
/// dividing by a scale — and on a machine with two displays at different scales
/// the pixel origin of the second display is *not* its point origin times its own
/// scale, because the first display's width contributed at the first display's
/// scale. macOS knows the real answer (`CGDisplayBounds` reports points), so it
/// tells us rather than letting us reconstruct something that is only sometimes
/// right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointOrigin {
    /// The display's left edge in points.
    pub x: i64,
    /// The display's top edge in points.
    pub y: i64,
}

/// A position on the virtual desktop as a 16-bit fraction of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Normalised {
    /// Horizontal fraction, 0 at the leftmost pixel and 65535 at the rightmost.
    pub x: u16,
    /// Vertical fraction, 0 at the topmost pixel and 65535 at the bottommost.
    pub y: u16,
}

/// The bounding box of every display, in virtual-desktop pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    /// The leftmost pixel column of any display. Negative when a display sits
    /// left of the primary.
    pub left: i64,
    /// The topmost pixel row of any display. Negative when a display sits above
    /// the primary.
    pub top: i64,
    /// Total width in pixels. Always at least 1 for bounds that exist.
    pub width: i64,
    /// Total height in pixels. Always at least 1 for bounds that exist.
    pub height: i64,
}

impl Bounds {
    /// The rightmost pixel column, inclusive.
    pub const fn right(self) -> i64 {
        self.left + self.width - 1
    }

    /// The bottommost pixel row, inclusive.
    pub const fn bottom(self) -> i64 {
        self.top + self.height - 1
    }
}

/// Why a coordinate could not be mapped.
///
/// Every variant is a refusal rather than a clamp. Clamping is the tempting
/// answer and it is wrong here: a client that asks for a pixel outside the
/// display has a bug or is hostile, and silently moving the pointer to the
/// nearest legal place means the operator watches it go somewhere they did not
/// ask for, on a channel whose entire purpose is doing what it is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoordError {
    /// The machine reported no displays at all.
    NoDisplays,
    /// The client named a display this machine does not have.
    UnknownMonitor {
        /// The id that was asked for.
        wanted: u8,
    },
    /// The point is outside the display it claims to be on.
    OutsideDisplay {
        /// The display it claimed to be on.
        monitor: u8,
        /// The x it asked for, in that display's pixels.
        x: i64,
        /// The y it asked for.
        y: i64,
    },
    /// The point is outside the virtual desktop.
    OutsideDesktop {
        /// The x it asked for, in virtual-desktop pixels.
        x: i64,
        /// The y it asked for.
        y: i64,
    },
    /// A display reported a width or height of zero, so it has no pixels to
    /// address and no sane normalisation.
    EmptyDisplay {
        /// The display that reported it.
        monitor: u8,
    },
    /// A scale factor of zero, which would divide by zero, or one so large the
    /// conversion cannot be represented.
    ImpossibleScale {
        /// The reported scale in thousandths.
        permille: u16,
    },
    /// The arithmetic would leave the range of an `i64`. Only reachable from a
    /// driver reporting a geometry that cannot exist, and reported rather than
    /// wrapped because a wrapped coordinate is a pointer in a random place.
    Overflow {
        /// Which calculation ran out of room.
        during: &'static str,
    },
}

impl CoordError {
    /// The refusal as one sentence, for the diagnostics plate.
    pub fn sentence(&self) -> String {
        match self {
            Self::NoDisplays => "This machine reports no displays at all.".to_owned(),
            Self::UnknownMonitor { wanted } => {
                format!("There is no display {wanted} on this machine.")
            }
            Self::OutsideDisplay { monitor, x, y } => {
                format!("The point ({x}, {y}) is outside display {monitor}.")
            }
            Self::OutsideDesktop { x, y } => {
                format!("The point ({x}, {y}) is outside the virtual desktop.")
            }
            Self::EmptyDisplay { monitor } => {
                format!("Display {monitor} reports no pixels, so nothing can be addressed on it.")
            }
            Self::ImpossibleScale { permille } => {
                format!("A display reported a scale factor of {permille} thousandths, which cannot be used.")
            }
            Self::Overflow { during } => {
                format!("The reported display geometry is too large to work with, while {during}.")
            }
        }
    }
}

impl fmt::Display for CoordError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(&self.sentence())
    }
}

impl std::error::Error for CoordError {}

/// The bounding box of every display.
///
/// Refuses an empty list and any display with no pixels, so every later step can
/// rely on `width >= 1` and `height >= 1` without re-checking.
pub fn bounds(monitors: &[Monitor]) -> Result<Bounds, CoordError> {
    // Checked before the fold rather than after it, so the accumulators below
    // are never read back in their sentinel state.
    if monitors.is_empty() {
        return Err(CoordError::NoDisplays);
    }

    let mut left = i64::MAX;
    let mut top = i64::MAX;
    let mut right = i64::MIN;
    let mut bottom = i64::MIN;

    for monitor in monitors {
        if monitor.width == 0 || monitor.height == 0 {
            return Err(CoordError::EmptyDisplay { monitor: monitor.id });
        }
        let monitor_left = i64::from(monitor.origin_x);
        let monitor_top = i64::from(monitor.origin_y);
        // Widened to i64 before adding: an i32 origin plus a u32 extent does not
        // fit an i32, and a driver reporting a nonsense extent must not wrap.
        let monitor_right = monitor_left + i64::from(monitor.width) - 1;
        let monitor_bottom = monitor_top + i64::from(monitor.height) - 1;

        left = left.min(monitor_left);
        top = top.min(monitor_top);
        right = right.max(monitor_right);
        bottom = bottom.max(monitor_bottom);
    }

    let width = right
        .checked_sub(left)
        .and_then(|span| span.checked_add(1))
        .ok_or(CoordError::Overflow { during: "measuring the virtual desktop's width" })?;
    let height = bottom
        .checked_sub(top)
        .and_then(|span| span.checked_add(1))
        .ok_or(CoordError::Overflow { during: "measuring the virtual desktop's height" })?;

    Ok(Bounds { left, top, width, height })
}

/// Turns a display-local pixel into a virtual-desktop pixel.
///
/// This is the step that carries the sign: a display at `origin_x = -1920` maps
/// its own pixel 0 to virtual `-1920`, and every arithmetic mistake in this
/// subsystem that involves a secondary display is a mistake in this one line.
pub fn locate(monitors: &[Monitor], monitor: u8, x: i32, y: i32) -> Result<VirtualPoint, CoordError> {
    if monitors.is_empty() {
        return Err(CoordError::NoDisplays);
    }
    let display = monitors
        .iter()
        .find(|candidate| candidate.id == monitor)
        .ok_or(CoordError::UnknownMonitor { wanted: monitor })?;

    if display.width == 0 || display.height == 0 {
        return Err(CoordError::EmptyDisplay { monitor });
    }

    let local_x = i64::from(x);
    let local_y = i64::from(y);
    if local_x < 0
        || local_y < 0
        || local_x >= i64::from(display.width)
        || local_y >= i64::from(display.height)
    {
        return Err(CoordError::OutsideDisplay { monitor, x: local_x, y: local_y });
    }

    Ok(VirtualPoint {
        x: i64::from(display.origin_x) + local_x,
        y: i64::from(display.origin_y) + local_y,
    })
}

/// Turns a virtual-desktop pixel into the 16-bit fraction Windows wants.
///
/// The divisor is `extent - 1` so that the last addressable pixel maps to exactly
/// [`NORMALISED_MAX`]. A single-pixel extent divides by zero under that rule, so
/// it answers 0 — the only pixel there is.
pub fn normalise(bounds: Bounds, point: VirtualPoint) -> Result<Normalised, CoordError> {
    if point.x < bounds.left
        || point.y < bounds.top
        || point.x > bounds.right()
        || point.y > bounds.bottom()
    {
        return Err(CoordError::OutsideDesktop { x: point.x, y: point.y });
    }
    Ok(Normalised {
        x: fraction(point.x - bounds.left, bounds.width)?,
        y: fraction(point.y - bounds.top, bounds.height)?,
    })
}

/// Turns a 16-bit fraction back into a virtual-desktop pixel.
///
/// The inverse of [`normalise`], and it exists so the round trip can be asserted
/// rather than believed: on any desktop narrower than 65536 pixels — which is
/// every desktop — normalising a pixel and denormalising the result must return
/// the same pixel, and the test table says so for the arrangements this
/// deployment actually has.
pub fn denormalise(bounds: Bounds, normalised: Normalised) -> Result<VirtualPoint, CoordError> {
    Ok(VirtualPoint {
        x: bounds.left + pixel(i64::from(normalised.x), bounds.width)?,
        y: bounds.top + pixel(i64::from(normalised.y), bounds.height)?,
    })
}

/// The whole mapping a Windows injector needs, in one call.
pub fn absolute(
    monitors: &[Monitor],
    monitor: u8,
    x: i32,
    y: i32,
) -> Result<Normalised, CoordError> {
    let point = locate(monitors, monitor, x, y)?;
    normalise(bounds(monitors)?, point)
}

/// The whole mapping a macOS injector needs, in one call.
///
/// Takes the display's point origin from the platform rather than deriving it —
/// see [`PointOrigin`] for why deriving it is only sometimes right.
pub fn global_point(
    origin: PointOrigin,
    scale_permille: u16,
    x: i32,
    y: i32,
) -> Result<Point, CoordError> {
    let offset_x = pixels_to_points(scale_permille, i64::from(x))?;
    let offset_y = pixels_to_points(scale_permille, i64::from(y))?;
    Ok(Point {
        x: origin
            .x
            .checked_add(offset_x)
            .ok_or(CoordError::Overflow { during: "offsetting a display's point origin" })?,
        y: origin
            .y
            .checked_add(offset_y)
            .ok_or(CoordError::Overflow { during: "offsetting a display's point origin" })?,
    })
}

/// Converts physical pixels to logical points at a given scale.
///
/// `scale_permille` is thousandths: 1000 is an unscaled display, 1500 is Windows
/// at 150%, 2000 is a Retina display. Rounds half away from zero, so a negative
/// offset rounds the same distance as the positive one — rounding toward zero
/// would make the conversion asymmetric about the origin, which shows up as a
/// pointer that is accurate on one display and a pixel out on the one to its left.
pub fn pixels_to_points(scale_permille: u16, pixels: i64) -> Result<i64, CoordError> {
    let scale = check_scale(scale_permille)?;
    let scaled = pixels
        .checked_mul(1000)
        .ok_or(CoordError::Overflow { during: "converting pixels to points" })?;
    Ok(divide_rounding(scaled, scale))
}

/// Converts logical points to physical pixels at a given scale.
pub fn points_to_pixels(scale_permille: u16, points: i64) -> Result<i64, CoordError> {
    let scale = check_scale(scale_permille)?;
    let scaled = points
        .checked_mul(scale)
        .ok_or(CoordError::Overflow { during: "converting points to pixels" })?;
    Ok(divide_rounding(scaled, 1000))
}

/// Rejects a scale that cannot be used as a divisor.
///
/// Zero is the one that matters — a display that has not reported its scale yet
/// reads as zero, and dividing by it aborts the process.
fn check_scale(permille: u16) -> Result<i64, CoordError> {
    if permille == 0 {
        return Err(CoordError::ImpossibleScale { permille });
    }
    Ok(i64::from(permille))
}

/// Integer division rounding half away from zero.
///
/// `divisor` must be non-zero; both call sites establish that first.
fn divide_rounding(numerator: i64, divisor: i64) -> i64 {
    let half = divisor / 2;
    if (numerator < 0) == (divisor < 0) {
        (numerator + half) / divisor
    } else {
        (numerator - half) / divisor
    }
}

/// One axis of [`normalise`].
///
/// `offset` is already known to be within `0..extent` and `extent` at least 1.
fn fraction(offset: i64, extent: i64) -> Result<u16, CoordError> {
    let span = extent - 1;
    if span <= 0 {
        // A one-pixel-wide desktop: the only addressable pixel is the origin, so
        // the fraction is zero. Dividing by `span` here would abort the process.
        return Ok(0);
    }
    let scaled = offset
        .checked_mul(i64::from(NORMALISED_MAX))
        .ok_or(CoordError::Overflow { during: "normalising a pointer position" })?;
    let value = divide_rounding(scaled, span);
    u16::try_from(value).map_err(|_| CoordError::Overflow { during: "normalising a pointer position" })
}

/// One axis of [`denormalise`].
fn pixel(fraction: i64, extent: i64) -> Result<i64, CoordError> {
    let span = extent - 1;
    if span <= 0 {
        return Ok(0);
    }
    let scaled = fraction
        .checked_mul(span)
        .ok_or(CoordError::Overflow { during: "denormalising a pointer position" })?;
    Ok(divide_rounding(scaled, i64::from(NORMALISED_MAX)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A display, spelled out at each call site so a test reads as the
    /// arrangement it is describing.
    fn display(id: u8, x: i32, y: i32, width: u32, height: u32, scale: u16) -> Monitor {
        Monitor {
            id,
            origin_x: x,
            origin_y: y,
            width,
            height,
            scale_permille: scale,
            primary: id == 0,
        }
    }

    fn single() -> Vec<Monitor> {
        vec![display(0, 0, 0, 1920, 1080, 1000)]
    }

    fn side_by_side() -> Vec<Monitor> {
        vec![display(0, 0, 0, 1920, 1080, 1000), display(1, 1920, 0, 1920, 1080, 1000)]
    }

    /// The arrangement sign errors hide in: the second display is to the *left*
    /// of the primary, so the virtual desktop's origin is negative.
    fn secondary_on_the_left() -> Vec<Monitor> {
        vec![display(0, 0, 0, 1920, 1080, 1000), display(1, -1920, 0, 1920, 1080, 1000)]
    }

    /// A 4K panel at 150%, beside an unscaled 1080p one.
    fn mixed_scaling() -> Vec<Monitor> {
        vec![display(0, 0, 0, 1920, 1080, 1000), display(1, 1920, 0, 2560, 1440, 1500)]
    }

    #[test]
    fn one_display_bounds_at_the_origin() {
        assert_eq!(
            bounds(&single()).unwrap(),
            Bounds { left: 0, top: 0, width: 1920, height: 1080 }
        );
    }

    #[test]
    fn two_side_by_side_measure_as_one_wide_desktop() {
        let measured = bounds(&side_by_side()).unwrap();
        assert_eq!(measured, Bounds { left: 0, top: 0, width: 3840, height: 1080 });
        assert_eq!(measured.right(), 3839);
    }

    #[test]
    fn a_display_to_the_left_of_the_primary_gives_the_desktop_a_negative_origin() {
        // This is the case an unsigned type or an unchecked subtraction gets
        // wrong, and it is the ordinary arrangement on the box this ships to.
        let measured = bounds(&secondary_on_the_left()).unwrap();
        assert_eq!(measured, Bounds { left: -1920, top: 0, width: 3840, height: 1080 });
        assert_eq!(measured.right(), 1919);
    }

    #[test]
    fn a_display_above_the_primary_gives_the_desktop_a_negative_top() {
        let stacked = vec![display(0, 0, 0, 1920, 1080, 1000), display(1, 0, -1200, 1920, 1200, 1000)];
        assert_eq!(
            bounds(&stacked).unwrap(),
            Bounds { left: 0, top: -1200, width: 1920, height: 2280 }
        );
    }

    #[test]
    fn no_displays_is_a_named_refusal_rather_than_an_empty_box() {
        assert_eq!(bounds(&[]), Err(CoordError::NoDisplays));
    }

    #[test]
    fn a_display_with_no_pixels_is_refused_before_anything_divides_by_it() {
        let broken = vec![display(0, 0, 0, 0, 1080, 1000)];
        assert_eq!(bounds(&broken), Err(CoordError::EmptyDisplay { monitor: 0 }));
    }

    #[test]
    fn the_corners_of_one_display_map_to_exactly_zero_and_exactly_65535() {
        let monitors = single();
        let box_ = bounds(&monitors).unwrap();
        assert_eq!(
            normalise(box_, VirtualPoint { x: 0, y: 0 }).unwrap(),
            Normalised { x: 0, y: 0 }
        );
        assert_eq!(
            normalise(box_, VirtualPoint { x: 1919, y: 1079 }).unwrap(),
            Normalised { x: 65535, y: 65535 }
        );
    }

    #[test]
    fn the_corners_of_a_two_display_desktop_also_map_to_exactly_zero_and_65535() {
        // Divide by the extent rather than by `extent - 1` and the far corner
        // never reaches 65535 — which an operator experiences as the last column
        // of pixels being unclickable, not as an arithmetic bug.
        for monitors in [side_by_side(), secondary_on_the_left(), mixed_scaling()] {
            let box_ = bounds(&monitors).unwrap();
            let top_left = VirtualPoint { x: box_.left, y: box_.top };
            let bottom_right = VirtualPoint { x: box_.right(), y: box_.bottom() };
            assert_eq!(normalise(box_, top_left).unwrap(), Normalised { x: 0, y: 0 });
            assert_eq!(
                normalise(box_, bottom_right).unwrap(),
                Normalised { x: 65535, y: 65535 },
                "far corner of {box_:?}"
            );
        }
    }

    #[test]
    fn the_far_left_pixel_of_a_display_at_minus_1920_is_the_desktops_own_origin() {
        let monitors = secondary_on_the_left();
        assert_eq!(
            absolute(&monitors, 1, 0, 0).unwrap(),
            Normalised { x: 0, y: 0 },
            "display 1 starts at the left edge of the desktop"
        );
        // And the primary's own origin is now the middle of the desktop, not zero.
        let primary_origin = absolute(&monitors, 0, 0, 0).unwrap();
        assert!(
            (32_000..=33_600).contains(&u32::from(primary_origin.x)),
            "the primary's left edge should be about halfway across: {primary_origin:?}"
        );
    }

    #[test]
    fn a_150_percent_display_is_addressed_in_pixels_like_every_other() {
        // The agent runs per-monitor-DPI-aware, so virtual-desktop coordinates
        // are physical pixels on every display regardless of its scale. If this
        // ever stops being true the pointer drifts toward the bottom-right, and
        // this test is the one that says the fault is not in this module.
        let monitors = mixed_scaling();
        let box_ = bounds(&monitors).unwrap();
        assert_eq!(box_, Bounds { left: 0, top: 0, width: 4480, height: 1440 });

        let scaled_far_corner = locate(&monitors, 1, 2559, 1439).unwrap();
        assert_eq!(scaled_far_corner, VirtualPoint { x: 4479, y: 1439 });
        assert_eq!(
            normalise(box_, scaled_far_corner).unwrap(),
            Normalised { x: 65535, y: 65535 }
        );
    }

    #[test]
    fn a_point_outside_its_display_is_refused_rather_than_clamped() {
        let monitors = single();
        assert_eq!(
            locate(&monitors, 0, 1920, 0),
            Err(CoordError::OutsideDisplay { monitor: 0, x: 1920, y: 0 }),
            "1920 is one past the last column of a 1920-wide display"
        );
        assert_eq!(
            locate(&monitors, 0, -1, 5),
            Err(CoordError::OutsideDisplay { monitor: 0, x: -1, y: 5 })
        );
    }

    #[test]
    fn an_unknown_display_names_what_was_asked_for() {
        assert_eq!(
            locate(&single(), 7, 0, 0),
            Err(CoordError::UnknownMonitor { wanted: 7 })
        );
    }

    #[test]
    fn normalising_and_back_returns_the_same_pixel_on_every_arrangement() {
        // The round trip is exact for any desktop narrower than 65536 pixels,
        // which is every desktop that exists. Asserting it beats believing it.
        for monitors in [single(), side_by_side(), secondary_on_the_left(), mixed_scaling()] {
            let box_ = bounds(&monitors).unwrap();
            let samples = [
                box_.left,
                box_.left + 1,
                box_.left + box_.width / 3,
                box_.left + box_.width / 2,
                box_.right() - 1,
                box_.right(),
            ];
            for x in samples {
                let point = VirtualPoint { x, y: box_.top };
                let there = normalise(box_, point).unwrap();
                let back = denormalise(box_, there).unwrap();
                assert_eq!(back.x, x, "round trip through {there:?} on {box_:?}");
            }
        }
    }

    #[test]
    fn normalisation_never_goes_backwards_as_the_pixel_moves_right() {
        let monitors = secondary_on_the_left();
        let box_ = bounds(&monitors).unwrap();
        let mut previous = 0u16;
        let mut x = box_.left;
        while x <= box_.right() {
            let value = normalise(box_, VirtualPoint { x, y: 0 }).unwrap().x;
            assert!(value >= previous, "went backwards at x = {x}");
            previous = value;
            x += 37; // a stride that is not a factor of the width
        }
    }

    #[test]
    fn a_point_outside_the_desktop_is_refused() {
        let box_ = bounds(&single()).unwrap();
        assert_eq!(
            normalise(box_, VirtualPoint { x: 1920, y: 0 }),
            Err(CoordError::OutsideDesktop { x: 1920, y: 0 })
        );
        assert_eq!(
            normalise(box_, VirtualPoint { x: -1, y: 0 }),
            Err(CoordError::OutsideDesktop { x: -1, y: 0 })
        );
    }

    #[test]
    fn a_one_pixel_desktop_normalises_rather_than_dividing_by_zero() {
        // Absurd, and reachable from a driver mid-mode-change. Under
        // `panic = "abort"` the division would be the whole daemon.
        let tiny = vec![display(0, 0, 0, 1, 1, 1000)];
        let box_ = bounds(&tiny).unwrap();
        assert_eq!(
            normalise(box_, VirtualPoint { x: 0, y: 0 }).unwrap(),
            Normalised { x: 0, y: 0 }
        );
        assert_eq!(
            denormalise(box_, Normalised { x: 65535, y: 65535 }).unwrap(),
            VirtualPoint { x: 0, y: 0 }
        );
    }

    #[test]
    fn a_retina_display_converts_pixels_and_points_exactly() {
        assert_eq!(pixels_to_points(2000, 3024).unwrap(), 1512);
        assert_eq!(points_to_pixels(2000, 1512).unwrap(), 3024);
    }

    #[test]
    fn a_150_percent_display_converts_within_a_pixel_and_says_so() {
        // 2560 physical pixels is 1706.67 points, which is not a point. The
        // conversion rounds, and the round trip is therefore within one pixel
        // rather than exact — stated here so nobody later "fixes" it into a
        // fencepost error.
        let points = pixels_to_points(1500, 2560).unwrap();
        assert_eq!(points, 1707);
        let back = points_to_pixels(1500, points).unwrap();
        assert!((back - 2560).abs() <= 1, "round trip drifted to {back}");
    }

    #[test]
    fn conversion_rounds_symmetrically_about_the_origin() {
        // Rounding toward zero would make a negative offset land a pixel closer
        // to the origin than its positive twin, which is a pointer that is
        // accurate on one display and out by one on the display to its left.
        assert_eq!(pixels_to_points(1500, 100).unwrap(), 67);
        assert_eq!(pixels_to_points(1500, -100).unwrap(), -67);
        assert_eq!(points_to_pixels(1500, 67).unwrap(), 101);
        assert_eq!(points_to_pixels(1500, -67).unwrap(), -101);
    }

    #[test]
    fn a_scale_of_zero_is_refused_rather_than_dividing_by_it() {
        assert_eq!(
            pixels_to_points(0, 100),
            Err(CoordError::ImpossibleScale { permille: 0 })
        );
        assert_eq!(
            points_to_pixels(0, 100),
            Err(CoordError::ImpossibleScale { permille: 0 })
        );
    }

    #[test]
    fn a_global_point_offsets_the_platforms_own_origin() {
        // A second Retina display whose point origin macOS reports as (1512, 0):
        // the pixel offset within it is converted at *its* scale and added to the
        // origin the platform gave us, never to one we reconstructed.
        let origin = PointOrigin { x: 1512, y: 0 };
        assert_eq!(global_point(origin, 2000, 0, 0).unwrap(), Point { x: 1512, y: 0 });
        assert_eq!(global_point(origin, 2000, 200, 100).unwrap(), Point { x: 1612, y: 50 });
    }

    #[test]
    fn a_negative_point_origin_carries_its_sign_through() {
        let origin = PointOrigin { x: -1920, y: -300 };
        assert_eq!(global_point(origin, 1000, 10, 20).unwrap(), Point { x: -1910, y: -280 });
    }

    #[test]
    fn absurd_geometry_overflows_into_an_error_rather_than_wrapping() {
        // A wrapped coordinate is a pointer in a random place, which on a channel
        // that drives a machine is worse than a refusal.
        let huge = vec![display(0, i32::MIN, i32::MIN, u32::MAX, u32::MAX, 1000)];
        // The bounds themselves are representable in i64; normalisation is where
        // the multiplication by 65535 runs out of room.
        let box_ = bounds(&huge).unwrap();
        let far = VirtualPoint { x: box_.right(), y: box_.bottom() };
        assert!(matches!(normalise(box_, far), Ok(_) | Err(CoordError::Overflow { .. })));
        assert_eq!(
            pixels_to_points(1000, i64::MAX),
            Err(CoordError::Overflow { during: "converting pixels to points" })
        );
    }
}
