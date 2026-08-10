//! Core Graphics display enumeration and the two consent checks.
//!
//! Raw framework declarations, as everywhere else in this workspace: no crate is
//! linked for a platform API, by policy. Core Graphics is a C API — `extern "C"`,
//! not `extern "system"` — and returns its rectangles by value, which the C ABI
//! handles for a `#[repr(C)]` structure of four `f64`s without any help from us.
//!
//! # Points, pixels, and why both are read
//!
//! `CGDisplayBounds` answers in **points**: a Retina display 3024 pixels wide
//! reports 1512. The capture path needs pixels, the injection path needs points,
//! and the ratio between them is the display's scale — which is genuinely
//! per-display on a machine with a built-in Retina panel and an external monitor.
//! So both are read here, from the display's current mode, and the scale is
//! derived rather than assumed. `crate::coords` then owns every conversion
//! between them.

use crate::coords::PointOrigin;
use crate::{CaptureError, Fault, Grant};
use selfhost_desk::wire::{Monitor, MAX_MONITORS};
use std::ffi::c_void;

/// A Core Graphics point.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CGPoint {
    x: f64,
    y: f64,
}

/// A Core Graphics size.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CGSize {
    width: f64,
    height: f64,
}

/// A Core Graphics rectangle, returned by value from `CGDisplayBounds`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CGRect {
    origin: CGPoint,
    size: CGSize,
}

/// `kCGErrorSuccess`.
const CG_ERROR_SUCCESS: i32 = 0;

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    /// The display the menu bar is on, which is the origin of the global point
    /// space.
    fn CGMainDisplayID() -> u32;

    /// Fills `displays` with the active display ids. Answers
    /// [`CG_ERROR_SUCCESS`] on success; `count` is written even when `max` is
    /// zero, which is how the length is learned.
    fn CGGetActiveDisplayList(max: u32, displays: *mut u32, count: *mut u32) -> i32;

    /// A display's rectangle in the global **point** space, with the origin at
    /// the main display's top-left and y increasing downwards.
    fn CGDisplayBounds(display: u32) -> CGRect;

    /// The display's current mode, or null. Owned by the caller.
    fn CGDisplayCopyDisplayMode(display: u32) -> *mut c_void;

    /// Releases a mode from [`CGDisplayCopyDisplayMode`].
    fn CGDisplayModeRelease(mode: *mut c_void);

    /// The mode's width in points.
    fn CGDisplayModeGetWidth(mode: *mut c_void) -> usize;

    /// The mode's height in points.
    fn CGDisplayModeGetHeight(mode: *mut c_void) -> usize;

    /// The mode's width in physical pixels — 3024 where the point width is 1512.
    fn CGDisplayModeGetPixelWidth(mode: *mut c_void) -> usize;

    /// The mode's height in physical pixels.
    fn CGDisplayModeGetPixelHeight(mode: *mut c_void) -> usize;

    /// Whether this process may capture the screen. Answers without prompting and
    /// without side effects, which is what makes it usable on every poll.
    fn CGPreflightScreenCaptureAccess() -> u8;

    /// Asks for screen-capture consent, prompting the person at the machine once
    /// per process. Never called on a poll; only on an explicit operator action.
    fn CGRequestScreenCaptureAccess() -> u8;
}

#[link(name = "ApplicationServices", kind = "framework")]
unsafe extern "C" {
    /// Whether this process is trusted for accessibility, which is what
    /// synthesised input needs. Answers without prompting.
    fn AXIsProcessTrusted() -> u8;
}

/// One display, as Core Graphics describes it.
///
/// Carries both coordinate spaces because the two consumers want different ones
/// and neither can be reconstructed from the other across a machine with mixed
/// scales — see [`crate::coords::PointOrigin`] for why that reconstruction is
/// only sometimes right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Display {
    /// Core Graphics' own id for the display.
    pub id: u32,
    /// The display's top-left corner in the global point space.
    pub point_origin: PointOrigin,
    /// Width in points.
    pub point_width: u32,
    /// Height in points.
    pub point_height: u32,
    /// Width in physical pixels.
    pub pixel_width: u32,
    /// Height in physical pixels.
    pub pixel_height: u32,
    /// Whether this is the main display — the one the menu bar is on, and the
    /// origin of the point space.
    pub primary: bool,
}

impl Display {
    /// The display's scale in thousandths: 2000 for a Retina panel, 1000 for an
    /// ordinary one.
    ///
    /// Derived from the mode rather than read from a scale API, because the
    /// number that matters is the ratio between the two extents this code
    /// actually uses. A display reporting no point width answers 1000, which is
    /// the identity and cannot make a later conversion divide by zero.
    pub fn scale_permille(&self) -> u16 {
        if self.point_width == 0 {
            return 1000;
        }
        let ratio = u64::from(self.pixel_width) * 1000 / u64::from(self.point_width);
        u16::try_from(ratio).unwrap_or(u16::MAX)
    }

    /// This display as the protocol's [`Monitor`].
    ///
    /// The protocol's origin is in **pixels**, and macOS has no pixel-space
    /// virtual desktop — so the origin is the point origin scaled by *this*
    /// display's own factor. That is exact for the round trip that matters (a
    /// coordinate on this display converts back through the same factor) and is
    /// approximate only for the composite layout the console draws, which is a
    /// picture rather than an input.
    pub fn to_monitor(&self, id: u8) -> Monitor {
        let scale = self.scale_permille();
        let origin_x = crate::coords::points_to_pixels(scale, self.point_origin.x).unwrap_or(0);
        let origin_y = crate::coords::points_to_pixels(scale, self.point_origin.y).unwrap_or(0);
        Monitor {
            id,
            origin_x: i32::try_from(origin_x).unwrap_or(0),
            origin_y: i32::try_from(origin_y).unwrap_or(0),
            width: self.pixel_width,
            height: self.pixel_height,
            scale_permille: scale,
            primary: self.primary,
        }
    }
}

/// Every active display, in Core Graphics' own order with the main display first.
///
/// # Errors
///
/// [`CaptureError::NoSession`] when the machine reports no active displays at
/// all — a Mac with its lid shut and nothing attached, which is a state rather
/// than a failure — and [`CaptureError::Fatal`] when the enumeration itself
/// fails.
pub fn displays() -> Result<Vec<Display>, CaptureError> {
    let mut count: u32 = 0;
    let status = unsafe { CGGetActiveDisplayList(0, std::ptr::null_mut(), &mut count) };
    if status != CG_ERROR_SUCCESS {
        return Err(CaptureError::Fatal(Fault::os("CGGetActiveDisplayList", status)));
    }
    if count == 0 {
        return Err(CaptureError::NoSession);
    }
    // Bounded before allocating: the count comes from the platform, and a
    // ludicrous one should be refused rather than reserved for.
    let wanted = count.min(64);

    let mut ids = vec![0u32; wanted as usize];
    let mut filled: u32 = 0;
    let status = unsafe { CGGetActiveDisplayList(wanted, ids.as_mut_ptr(), &mut filled) };
    if status != CG_ERROR_SUCCESS {
        return Err(CaptureError::Fatal(Fault::os("CGGetActiveDisplayList", status)));
    }
    ids.truncate(filled.min(wanted) as usize);
    if ids.is_empty() {
        return Err(CaptureError::NoSession);
    }

    let main = unsafe { CGMainDisplayID() };
    ids.iter().map(|id| describe(*id, main)).collect()
}

/// Every active display as the protocol's [`Monitor`], numbered from zero.
///
/// Truncated at the protocol's own [`MAX_MONITORS`] rather than refused: a
/// machine with more displays than the wire can name should show the first
/// sixteen, not nothing at all.
pub fn monitors() -> Result<Vec<Monitor>, CaptureError> {
    let found = displays()?;
    Ok(found
        .iter()
        .take(MAX_MONITORS)
        .enumerate()
        .map(|(index, display)| display.to_monitor(u8::try_from(index).unwrap_or(u8::MAX)))
        .collect())
}

/// Reads one display's geometry.
fn describe(id: u32, main: u32) -> Result<Display, CaptureError> {
    let bounds = unsafe { CGDisplayBounds(id) };
    let mode = unsafe { CGDisplayCopyDisplayMode(id) };
    if mode.is_null() {
        // A display that is being reconfigured, asleep, or has just been
        // unplugged. Rebuilding is the right answer, not failing the session.
        return Err(CaptureError::Reinitialise);
    }
    let owned = OwnedMode(mode);

    let point_width = unsafe { CGDisplayModeGetWidth(owned.0) };
    let point_height = unsafe { CGDisplayModeGetHeight(owned.0) };
    let pixel_width = unsafe { CGDisplayModeGetPixelWidth(owned.0) };
    let pixel_height = unsafe { CGDisplayModeGetPixelHeight(owned.0) };

    Ok(Display {
        id,
        point_origin: PointOrigin {
            x: whole(bounds.origin.x),
            y: whole(bounds.origin.y),
        },
        point_width: clamp(point_width),
        point_height: clamp(point_height),
        pixel_width: clamp(pixel_width),
        pixel_height: clamp(pixel_height),
        primary: id == main,
    })
}

/// Whether this process may capture the screen.
///
/// Answers the question the pixels cannot: a process without consent is handed a
/// picture of the wallpaper rather than an error, so inspecting a frame can never
/// be the check.
pub fn screen_recording_allowed() -> bool {
    unsafe { CGPreflightScreenCaptureAccess() != 0 }
}

/// Whether this process may synthesise keyboard and pointer events.
pub fn accessibility_allowed() -> bool {
    unsafe { AXIsProcessTrusted() != 0 }
}

/// Prompts the person at the machine for screen-recording consent.
///
/// Deliberately separate from [`screen_recording_allowed`] and never called on a
/// poll: macOS shows this prompt once per process and ignores it afterwards, so a
/// supervisor that asked on every attempt would burn the one prompt the operator
/// was going to see, on a machine nobody is sitting at.
pub fn request_screen_recording() -> bool {
    unsafe { CGRequestScreenCaptureAccess() != 0 }
}

/// Checks the consents a session needs before it is told anything is wrong.
///
/// `with_input` asks for the accessibility consent as well, so a view-only
/// session is not blocked by a permission it will never use — viewing and driving
/// are separate capabilities everywhere else in this subsystem, and they are
/// separate here too.
pub fn preflight(with_input: bool) -> Result<(), CaptureError> {
    if !screen_recording_allowed() {
        return Err(CaptureError::PermissionDenied(Grant::ScreenRecording));
    }
    if with_input && !accessibility_allowed() {
        return Err(CaptureError::PermissionDenied(Grant::Accessibility));
    }
    Ok(())
}

/// A display mode that releases itself.
#[derive(Debug)]
struct OwnedMode(*mut c_void);

impl Drop for OwnedMode {
    fn drop(&mut self) {
        unsafe { CGDisplayModeRelease(self.0) };
    }
}

/// A `CGFloat` as a whole number of points.
///
/// `as` on a float is a saturating cast in Rust rather than undefined behaviour,
/// but a NaN would become zero silently, so it is named here: a display whose
/// origin is not a number is placed at the origin, which is wrong in a visible
/// way rather than wrong in an arithmetic way.
fn whole(value: f64) -> i64 {
    if value.is_nan() { 0 } else { value.round() as i64 }
}

/// A platform-reported extent as a `u32`.
fn clamp(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_machine_describes_its_own_displays() {
        // Runs against the real Core Graphics on whatever Mac this is built on.
        // A machine with no display attached answers `NoSession`, which is a
        // state and is accepted here — the assertion is that the call is sane,
        // not that a screen exists.
        match displays() {
            Ok(found) => {
                assert!(!found.is_empty());
                for display in &found {
                    assert!(display.pixel_width > 0, "{display:?} has no pixels");
                    assert!(display.pixel_height > 0, "{display:?} has no pixels");
                    assert!(display.point_width > 0, "{display:?} has no points");
                    // Physical pixels are never fewer than points.
                    assert!(display.pixel_width >= display.point_width, "{display:?}");
                    let scale = display.scale_permille();
                    assert!(
                        (1000..=4000).contains(&scale),
                        "{display:?} reports an implausible scale of {scale}"
                    );
                }
                assert_eq!(
                    found.iter().filter(|display| display.primary).count(),
                    1,
                    "exactly one display is the main one"
                );
            }
            Err(CaptureError::NoSession) => {}
            Err(other) => panic!("enumeration failed: {other}"),
        }
    }

    #[test]
    fn a_display_becomes_a_monitor_the_protocol_can_carry() {
        let Ok(found) = monitors() else {
            return; // no displays attached; the test above covers that path
        };
        assert!(found.len() <= MAX_MONITORS);
        for (index, monitor) in found.iter().enumerate() {
            assert_eq!(usize::from(monitor.id), index, "ids are dense and start at zero");
            assert!(monitor.width > 0 && monitor.height > 0);
        }
        // Whatever the arrangement, the coordinate module must be able to measure
        // it — this is the real check that the two crates agree.
        let bounds = crate::coords::bounds(&found).expect("the displays must form a desktop");
        assert!(bounds.width > 0 && bounds.height > 0);
    }

    #[test]
    fn the_permission_preflight_answers_without_prompting() {
        // Both of these are pure queries. If either ever started prompting, a
        // developer running `cargo test` would get a system dialog, which is how
        // this test would notice.
        let screen = screen_recording_allowed();
        let input = accessibility_allowed();
        match preflight(false) {
            Ok(()) => assert!(screen),
            Err(CaptureError::PermissionDenied(Grant::ScreenRecording)) => assert!(!screen),
            Err(other) => panic!("unexpected preflight answer: {other}"),
        }
        if screen && !input {
            assert!(
                matches!(
                    preflight(true),
                    Err(CaptureError::PermissionDenied(Grant::Accessibility))
                ),
                "input consent must be checked separately from screen consent"
            );
        }
    }

    #[test]
    fn a_display_with_no_points_does_not_divide_by_zero() {
        // Reachable from a display mid-reconfiguration. Under `panic = "abort"`
        // the division would be the whole daemon.
        let broken = Display {
            id: 1,
            point_origin: PointOrigin { x: 0, y: 0 },
            point_width: 0,
            point_height: 0,
            pixel_width: 100,
            pixel_height: 100,
            primary: false,
        };
        assert_eq!(broken.scale_permille(), 1000);
        let monitor = broken.to_monitor(0);
        assert_eq!(monitor.scale_permille, 1000);
    }

    #[test]
    fn a_retina_display_reports_its_scale_and_keeps_its_origin() {
        let retina = Display {
            id: 1,
            point_origin: PointOrigin { x: 1512, y: 0 },
            point_width: 1512,
            point_height: 982,
            pixel_width: 3024,
            pixel_height: 1964,
            primary: false,
        };
        assert_eq!(retina.scale_permille(), 2000);
        let monitor = retina.to_monitor(1);
        assert_eq!(monitor.origin_x, 3024, "the origin is carried in pixels");
        assert_eq!(monitor.width, 3024);
    }
}
