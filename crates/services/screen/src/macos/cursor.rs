//! The pointer on macOS: where it is, and the honest answer about its shape.
//!
//! The pointer is captured separately from the screen on every platform this
//! project targets, and the reason is the same everywhere: a client that is given
//! the pointer's position each frame and its *shape* only when the shape changes
//! can composite the pointer at **its own** frame rate rather than the capture
//! rate. On a tunnelled link that is the single largest perceived-latency win
//! available — the picture may be a frame behind, but the pointer never is.
//!
//! # Position is exact; the shape is not available and this file says so
//!
//! `CGEventGetLocation` on a null-source event answers the pointer's position in
//! the global **point** space, which is exactly what
//! [`crate::macos::sys::Display`] describes its displays in, so the conversion back
//! to the protocol's virtual pixels is arithmetic this crate already owns and
//! tests.
//!
//! The pointer's *bitmap* is a different matter. macOS exposes no C function that
//! answers "what does the pointer look like right now". `NSCursor` knows, and
//! reaching it means Objective-C messaging into AppKit — `objc_msgSend` with a
//! return-by-value ABI that differs by architecture, an `NSImage` to be rendered,
//! a `TIFFRepresentation` to be decoded — for a bitmap that changes when the
//! pointer crosses a text field. The other route is `CGSGetGlobalCursorData`, a
//! *private* SkyLight SPI that is unavailable to anything that hopes to keep
//! working across an operating-system update.
//!
//! So [`MacCursor`] reports position and visibility and answers `None` for the
//! shape, always. The protocol already treats an absent shape as ordinary — it is
//! the common case on every platform, since the shape only travels when it is new —
//! and both consoles draw their own arrow when they have never been given a bitmap.
//! What the operator loses is the I-beam-over-a-text-field cue; what they keep is a
//! pointer that tracks. That trade is stated here rather than left as a mystery,
//! because a `None` with no explanation invites somebody to "fix" it with private
//! SPI.
//!
//! # A pointer outside every display is reported at the edge, not refused
//!
//! macOS lets the pointer sit at coordinates that belong to no display for a moment
//! during a display reconfiguration. [`CursorSource`] has no state for "the pointer
//! is nowhere", and inventing one would mean a console that blanks the pointer
//! every time a monitor is plugged in. The last display it *was* on is used
//! instead, clamped, which is both what the person at the machine sees and what the
//! remote viewer expects.

use crate::coords::VirtualPoint;
use crate::macos::sys::{self, Display};
use crate::{CaptureError, CursorSource, CursorState};
use std::ffi::c_void;

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    /// Creates an event with no source, purely so its location can be read. The
    /// documented way to ask where the pointer is; `CGEventCreate(NULL)` answers a
    /// snapshot rather than a live handle, so nothing is subscribed and nothing has
    /// to be torn down beyond the one release.
    fn CGEventCreate(source: *mut c_void) -> *mut c_void;

    /// The pointer's position in the global point space.
    fn CGEventGetLocation(event: *mut c_void) -> sys::CGPoint;

    /// Whether the pointer is being drawn. Deprecated in the SDK, which is a C
    /// availability attribute Rust does not honour, and still answered correctly by
    /// the framework.
    fn CGCursorIsVisible() -> u8;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    /// Releases the snapshot event.
    fn CFRelease(object: *const c_void);
}

/// The macOS pointer source.
///
/// Holds the display list so that a position can be turned into the protocol's
/// virtual-pixel space without re-enumerating displays sixty times a second; the
/// list is refreshed by [`MacCursor::relayout`] when the capture rebuilds, which is
/// the same moment the monitor ids change.
#[derive(Debug)]
pub struct MacCursor {
    /// The displays, in the same order the protocol numbers them.
    displays: Vec<Display>,
    /// The last position that landed on a display, for the reconfiguration case.
    last: VirtualPoint,
}

impl MacCursor {
    /// Reads the display layout and starts tracking.
    ///
    /// # Errors
    ///
    /// Whatever [`crate::macos::sys::displays`] answers — [`CaptureError::NoSession`]
    /// for a Mac with nothing attached, which is a state rather than a failure.
    pub fn new() -> Result<Self, CaptureError> {
        Ok(Self { displays: sys::displays()?, last: VirtualPoint { x: 0, y: 0 } })
    }

    /// Re-reads the display layout.
    ///
    /// Called when the screen source rebuilds, because that is exactly when a
    /// display was added, removed or moved and every origin this holds became a lie.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    pub fn relayout(&mut self) -> Result<(), CaptureError> {
        self.displays = sys::displays()?;
        Ok(())
    }

    /// The pointer's position in the protocol's virtual-pixel space.
    fn position(&mut self) -> VirtualPoint {
        let event = unsafe { CGEventCreate(std::ptr::null_mut()) };
        if event.is_null() {
            return self.last;
        }
        let location = unsafe { CGEventGetLocation(event) };
        unsafe { CFRelease(event.cast_const()) };
        match locate(&self.displays, location.x, location.y) {
            Some(point) => {
                self.last = point;
                point
            }
            // Mid-reconfiguration, or a coordinate that is not a number. The last
            // known position is a better answer than the origin, which would jump
            // the remote pointer to the top-left corner of the desktop.
            None => self.last,
        }
    }
}

impl CursorSource for MacCursor {
    fn cursor(&mut self) -> Result<CursorState, CaptureError> {
        Ok(CursorState {
            visible: unsafe { CGCursorIsVisible() != 0 },
            position: self.position(),
            // Always. See the module documentation for why, and for why this is a
            // limitation of the public API rather than an unfinished piece of work.
            shape: None,
        })
    }
}

/// Turns a position in the global point space into virtual-desktop pixels.
///
/// Pure, and separated from the two Core Graphics calls above so the arithmetic can
/// be tested against display arrangements that cannot be plugged into a laptop —
/// notably a second display *left of* the primary, where every coordinate on it is
/// negative and every unsigned type or unchecked subtraction is wrong.
///
/// Answers `None` when the point belongs to no display, which happens for a moment
/// during a reconfiguration and must not become an invented coordinate.
pub fn locate(displays: &[Display], point_x: f64, point_y: f64) -> Option<VirtualPoint> {
    // Rounded down rather than to nearest, and once rather than per display: a
    // point is a square of pixels, and its top-left pixel is the one the person at
    // the machine is pointing at.
    let (Some(x), Some(y)) = (whole_point(point_x), whole_point(point_y)) else {
        return None;
    };
    for display in displays {
        let left = display.point_origin.x;
        let top = display.point_origin.y;
        let right = left + i64::from(display.point_width);
        let bottom = top + i64::from(display.point_height);
        if x < left || y < top || x >= right || y >= bottom {
            continue;
        }
        let scale = display.scale_permille();
        // The offset within the display converts at *this* display's scale; the
        // origin is already in this display's pixels, which is how
        // `Display::to_monitor` places it.
        let offset_x = crate::coords::points_to_pixels(scale, x - left).ok()?;
        let offset_y = crate::coords::points_to_pixels(scale, y - top).ok()?;
        let origin_x = crate::coords::points_to_pixels(scale, left).ok()?;
        let origin_y = crate::coords::points_to_pixels(scale, top).ok()?;
        return Some(VirtualPoint {
            x: origin_x.checked_add(offset_x)?,
            y: origin_y.checked_add(offset_y)?,
        });
    }
    None
}

/// A `CGFloat` as the whole point containing it, or `None` for one that is not a
/// number.
///
/// Clamped to a magnitude every display arrangement fits inside long before an
/// `f64` stops representing consecutive integers, so the cast cannot saturate into
/// a coordinate that means something else.
fn whole_point(value: f64) -> Option<i64> {
    if !value.is_finite() {
        return None;
    }
    /// Far outside any display arrangement, and far inside `f64`'s exact-integer
    /// range.
    const LIMIT: f64 = 9.0e15;
    Some(value.floor().clamp(-LIMIT, LIMIT) as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coords::PointOrigin;

    fn display(id: u32, x: i64, y: i64, points: (u32, u32), pixels: (u32, u32)) -> Display {
        Display {
            id,
            point_origin: PointOrigin { x, y },
            point_width: points.0,
            point_height: points.1,
            pixel_width: pixels.0,
            pixel_height: pixels.1,
            primary: id == 1,
        }
    }

    fn retina() -> Display {
        display(1, 0, 0, (1512, 982), (3024, 1964))
    }

    #[test]
    fn a_point_on_a_retina_display_becomes_the_pixel_underneath_it() {
        // 1512 points wide and 3024 pixels wide: a position reported in points and
        // used as pixels would land the remote pointer at half the distance.
        let displays = vec![retina()];
        assert_eq!(locate(&displays, 0.0, 0.0), Some(VirtualPoint { x: 0, y: 0 }));
        assert_eq!(locate(&displays, 100.0, 50.0), Some(VirtualPoint { x: 200, y: 100 }));
        assert_eq!(locate(&displays, 1511.9, 981.9), Some(VirtualPoint { x: 3022, y: 1962 }));
    }

    #[test]
    fn a_display_left_of_the_primary_carries_its_negative_origin_through() {
        // The arrangement that every sign error hides in.
        let displays = vec![retina(), display(2, -1920, 0, (1920, 1080), (1920, 1080))];
        assert_eq!(locate(&displays, -1920.0, 0.0), Some(VirtualPoint { x: -1920, y: 0 }));
        assert_eq!(locate(&displays, -10.0, 5.0), Some(VirtualPoint { x: -10, y: 5 }));
    }

    #[test]
    fn a_point_belonging_to_no_display_is_refused_rather_than_invented() {
        let displays = vec![retina()];
        assert_eq!(locate(&displays, 5000.0, 0.0), None);
        assert_eq!(locate(&displays, -1.0, 0.0), None);
        assert_eq!(locate(&displays, f64::NAN, 0.0), None);
        assert_eq!(locate(&[], 0.0, 0.0), None);
    }

    #[test]
    fn the_last_known_position_survives_a_pointer_that_is_briefly_nowhere() {
        // During a display reconfiguration the pointer can sit at coordinates no
        // display owns. Jumping the remote pointer to the origin there would be a
        // visible glitch every time a monitor is plugged in.
        let mut cursor = MacCursor { displays: vec![retina()], last: VirtualPoint { x: 7, y: 9 } };
        cursor.displays.clear();
        assert_eq!(cursor.position(), VirtualPoint { x: 7, y: 9 });
    }

    #[test]
    fn the_machine_reports_its_own_pointer() {
        // Against the real Core Graphics. A Mac with no display answers `NoSession`
        // from the constructor, which is a state and is accepted here.
        let Ok(mut cursor) = MacCursor::new() else {
            return;
        };
        let state = cursor.cursor().expect("the pointer is always readable");
        assert!(state.shape.is_none(), "the shape is deliberately never sent from macOS");
        // Whatever the arrangement, the position must be inside the desktop the
        // capture layer advertises — this is the real check that the two agree.
        if let Ok(monitors) = sys::monitors() {
            if let Ok(bounds) = crate::coords::bounds(&monitors) {
                assert!(
                    state.position.x >= bounds.left && state.position.x <= bounds.right(),
                    "{state:?} is outside {bounds:?}"
                );
            }
        }
    }
}
