//! The pointer, captured apart from the picture — and the GDI handles that costs.
//!
//! # Why the pointer is not in the frame
//!
//! `BitBlt` from the desktop device context does not include the pointer, and this
//! module deliberately does not put it back. A pointer composited into the frame
//! moves at the *capture* rate; over a tunnel that means it trails the operator's
//! hand by a round trip plus a frame interval, and smears visibly at any latency at
//! all. Sent separately it is two small messages the client draws on its own canvas
//! at its own frame rate, which `selfhost_desk::cursor` calls the single largest
//! perceived-latency win available to this design. This module is the half of that
//! which has to talk to Windows.
//!
//! # The `DeleteObject` discipline, which is why this file is shaped as it is
//!
//! `GetIconInfo` **creates two bitmaps per call and gives them to the caller.** It
//! does so every time, including for a cursor whose shape has not changed and whose
//! handle is the one it returned a thousand calls ago; there is no cache and the
//! ownership is not negotiable. The per-process GDI handle quota is 10,000. A
//! cursor poll at twenty frames a second that forgets one of the two bitmaps
//! exhausts that quota in about four minutes, and forgetting both halves it — after
//! which *every* GDI call in the process fails, including the capture's own
//! `CreateDIBSection`, and the remote desktop dies of something that looks nothing
//! like a cursor bug.
//!
//! The plan's acceptance test for this file is accordingly not a picture: it is a
//! **flat GDI handle count after ten minutes of continuous capture**, read from the
//! GDI objects column in Task Manager.
//!
//! Meeting it is structural rather than careful. [`IconBitmaps`] takes ownership of
//! both bitmaps on the line after the call that produced them, with nothing
//! fallible in between, and each is a [`sys::GdiObject`] whose destructor deletes
//! it. There is no `DeleteObject` at the end of any function here, because a call
//! at the end of a function is a call that every `?` above it skips.
//!
//! # Shapes are read once per shape, not once per frame
//!
//! Decoding a cursor costs a `GetIconInfo`, two `GetDIBits` and an allocation, and
//! the shape changes when the pointer crosses a text field — a few times a minute,
//! against thirty position updates a second. So the bitmap is decoded only when the
//! shape id differs from the one already reported, and
//! [`CursorSource::forget_shape`] exists for the case where the *receiver's* bounded
//! cache has dropped a shape this source believes it already sent.
//!
//! # What is pure lives upstairs
//!
//! Every decision about pixels — the shape identity, the alpha rescue, the four
//! monochrome combinations — is a pure function in [`super`], tested on a machine
//! with no Windows anywhere near it. What is left here is the part that can only be
//! written against the operating system: the calls, and the handles they hand over.

use super::sys::{self, Handle};
use super::{alpha_present, force_opaque, mask_alpha, monochrome_bgra, shape_id};
use crate::{CaptureError, CursorImage, CursorSource, CursorState, Fault, VirtualPoint};
use selfhost_desk::wire::MAX_CURSOR_EDGE;

/// The largest cursor bitmap this build will decode, in pixels each way.
///
/// The protocol's own ceiling. A cursor larger than this — Windows will hand back a
/// 256×256 one if an application asks for it — is reported as a position with no
/// shape rather than as a failure: the client keeps drawing the shape it had, which
/// is wrong in a way nobody notices, where a refusal is wrong in a way that stops
/// the session.
const MAX_EDGE: u32 = MAX_CURSOR_EDGE as u32;

/// The pointer as Windows currently has it.
///
/// Holds one piece of state: which shape the caller was last given. That single
/// field is what turns thirty bitmap decodes a second into roughly one an hour on a
/// desktop where nobody is dragging a window edge.
#[derive(Debug, Default)]
pub struct GdiCursor {
    /// The id of the shape the caller was last handed a bitmap for.
    reported: Option<u64>,
}

impl GdiCursor {
    /// A cursor source that has reported nothing yet.
    pub fn new() -> Self {
        Self::default()
    }
}

impl CursorSource for GdiCursor {
    /// The pointer's position, its visibility, and — only when it is new — its
    /// shape.
    ///
    /// # Errors
    ///
    /// [`CaptureError::SecureDesktop`] when `GetCursorInfo` is refused, which is
    /// what a UAC consent dialog and the lock screen both look like to a
    /// medium-integrity process: the secure desktop is not ours to read. Reported
    /// as that state rather than as an access-denied fault, because it is what the
    /// console must display and because it resolves by itself.
    ///
    /// A cursor destroyed between the position query and the shape query costs this
    /// observation its *shape* and never the observation: an application that
    /// creates and destroys cursors is ordinary, and a pointer that stops moving
    /// because one of them went away mid-poll would not be.
    fn cursor(&mut self) -> Result<CursorState, CaptureError> {
        let mut info = sys::CursorInfo {
            // 24, and the call fails outright on any other value.
            cb_size: u32::try_from(size_of::<sys::CursorInfo>()).unwrap_or(24),
            flags: 0,
            cursor: std::ptr::null_mut(),
            screen_pos: sys::Point::default(),
        };
        if unsafe { sys::GetCursorInfo(&mut info) } == 0 {
            let fault = Fault::last_os_error("GetCursorInfo");
            return match fault.code() {
                Some(sys::ERROR_ACCESS_DENIED) => Err(CaptureError::SecureDesktop),
                _ => Err(CaptureError::Fatal(fault)),
            };
        }

        let position =
            VirtualPoint { x: i64::from(info.screen_pos.x), y: i64::from(info.screen_pos.y) };
        // Suppressed is Windows saying the pointer exists but is not drawn, because
        // the person is working by touch. A client that draws it anyway shows a
        // pointer nobody at the machine can see.
        let visible = info.flags & sys::CURSOR_SHOWING != 0
            && info.flags & sys::CURSOR_SUPPRESSED == 0
            && !info.cursor.is_null();

        if info.cursor.is_null() {
            self.reported = None;
            return Ok(CursorState { visible: false, position, shape: None });
        }

        let shape = read_shape(info.cursor, self.reported).unwrap_or(None);
        if let Some(image) = shape.as_ref() {
            self.reported = Some(image.id);
        }
        Ok(CursorState { visible, position, shape })
    }

    /// Forgets which shape the caller holds, so the next observation carries the
    /// bitmap again.
    ///
    /// Called on a reconnect, and whenever the caller's own bounded shape cache has
    /// evicted the shape currently on screen. Without it the two caches drift: this
    /// source would stay silent about a shape the client no longer holds, and the
    /// pointer would be drawn with whatever bitmap the client kept last.
    fn forget_shape(&mut self) {
        self.reported = None;
    }
}

/// Reads a cursor's shape, or `None` when the caller already has it.
///
/// The identity check and the decode share one `ICONINFO` deliberately: asking
/// twice would race an application that swaps its cursor between the two calls, and
/// would cost a second pair of bitmaps to destroy.
fn read_shape(cursor: Handle, reported: Option<u64>) -> Result<Option<CursorImage>, Fault> {
    let bitmaps = IconBitmaps::of(cursor)?;
    let (width, height) = bitmaps.extent()?;
    if width == 0 || height == 0 || width > MAX_EDGE || height > MAX_EDGE {
        return Ok(None);
    }

    let id = shape_id(cursor as usize as u64, width, height, bitmaps.hotspot_x, bitmaps.hotspot_y);
    if reported == Some(id) {
        return Ok(None);
    }

    Ok(Some(CursorImage {
        id,
        width,
        height,
        // Clamped rather than trusted: the hotspot is used by the client as an
        // offset into the bitmap, and a hotspot outside it would draw the pointer
        // an arbitrary distance from where it actually is.
        hotspot_x: bitmaps.hotspot_x.min(width.saturating_sub(1)),
        hotspot_y: bitmaps.hotspot_y.min(height.saturating_sub(1)),
        bgra: bitmaps.decode(width, height)?,
    }))
}

/// The two bitmaps `GetIconInfo` hands over, owned and destroyed on drop.
///
/// This type is the whole answer to the handle quota. Both bitmaps become owned the
/// instant the call returns, before anything that can fail happens, so every error
/// path below — a refused `GetObjectW`, an overflowing size, a `GetDIBits` that
/// copies no scan lines — destroys them on the way out without a line of code saying
/// so.
#[derive(Debug)]
struct IconBitmaps {
    /// The AND mask. Always present; twice the cursor's height when there is no
    /// colour bitmap, because it then holds the AND and XOR masks stacked.
    mask: Option<sys::GdiObject>,
    /// The colour bitmap, absent for a monochrome cursor.
    colour: Option<sys::GdiObject>,
    /// The hotspot's x offset within the bitmap.
    hotspot_x: u32,
    /// The hotspot's y offset within the bitmap.
    hotspot_y: u32,
}

impl IconBitmaps {
    /// Asks Windows for a cursor's bitmaps and takes ownership of them.
    fn of(cursor: Handle) -> Result<Self, Fault> {
        let mut info = sys::IconInfo {
            is_icon: 0,
            hotspot_x: 0,
            hotspot_y: 0,
            mask: std::ptr::null_mut(),
            colour: std::ptr::null_mut(),
        };
        if unsafe { sys::GetIconInfo(cursor, &mut info) } == 0 {
            return Err(Fault::last_os_error("GetIconInfo"));
        }
        Ok(Self {
            mask: sys::GdiObject::new(info.mask),
            colour: sys::GdiObject::new(info.colour),
            hotspot_x: info.hotspot_x,
            hotspot_y: info.hotspot_y,
        })
    }

    /// The cursor's extent in pixels.
    ///
    /// Taken from the colour bitmap where there is one, and from the mask otherwise
    /// — where the mask is **two masks stacked**, so its height is halved. Getting
    /// that halving wrong produces a cursor twice as tall as it should be with its
    /// own AND mask drawn beneath it, which is a recognisable and frequently
    /// shipped bug in remote-desktop implementations.
    fn extent(&self) -> Result<(u32, u32), Fault> {
        if let Some(colour) = self.colour.as_ref() {
            let bitmap = describe(colour.raw())?;
            return Ok((dimension(bitmap.width), dimension(bitmap.height)));
        }
        let mask = self.mask.as_ref().ok_or_else(|| {
            Fault::refused("GetIconInfo", "produced neither a mask nor a colour bitmap")
        })?;
        let bitmap = describe(mask.raw())?;
        Ok((dimension(bitmap.width), dimension(bitmap.height) / 2))
    }

    /// The shape as tight, top-down BGRA.
    fn decode(&self, width: u32, height: u32) -> Result<Vec<u8>, Fault> {
        let Some(colour) = self.colour.as_ref() else {
            // Monochrome: one bitmap holding the AND mask above the XOR mask.
            let mask = self.mask.as_ref().ok_or_else(|| {
                Fault::refused("GetIconInfo", "produced no mask for a monochrome cursor")
            })?;
            let doubled = height.checked_mul(2).ok_or_else(|| {
                Fault::refused("GetIconInfo", "reported a mask taller than a bitmap can be")
            })?;
            return Ok(monochrome_bgra(width, height, &read_bgra(mask.raw(), width, doubled)?));
        };

        let mut bgra = read_bgra(colour.raw(), width, height)?;
        if alpha_present(&bgra) {
            return Ok(bgra);
        }
        match self.mask.as_ref() {
            Some(mask) => mask_alpha(&mut bgra, &read_bgra(mask.raw(), width, height)?),
            // No alpha and no mask: opaque is the only answer that shows a pointer
            // at all.
            None => force_opaque(&mut bgra),
        }
        Ok(bgra)
    }
}

/// A bitmap's descriptor.
fn describe(bitmap: Handle) -> Result<sys::Bitmap, Fault> {
    let mut described = sys::Bitmap::default();
    let size = i32::try_from(size_of::<sys::Bitmap>()).unwrap_or(32);
    let written = unsafe {
        sys::GetObjectW(bitmap, size, std::ptr::from_mut(&mut described).cast::<std::ffi::c_void>())
    };
    if written == 0 {
        return Err(Fault::last_os_error("GetObjectW"));
    }
    Ok(described)
}

/// A bitmap dimension as an unsigned pixel count.
///
/// Windows reports a bitmap's height as a signed value, where a negative one means
/// top-down rather than a bitmap of negative height — so the magnitude is what is
/// wanted either way.
fn dimension(value: i32) -> u32 {
    value.unsigned_abs()
}

/// Reads any bitmap as tight, top-down, 32-bit BGRA.
///
/// `GetDIBits` converts on the way out, which is why a one-bit-per-pixel mask can be
/// read through the same path as a 32-bit colour cursor: black becomes zero and
/// white becomes 0x00FFFFFF, so a mask bit is testable as "is the blue channel
/// non-zero" — which is the polarity [`mask_alpha`] and [`monochrome_bgra`] are
/// written against.
fn read_bgra(bitmap: Handle, width: u32, height: u32) -> Result<Vec<u8>, Fault> {
    let len = (width as usize)
        .checked_mul(height as usize)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(|| {
            Fault::refused("GetDIBits", format!("{width}×{height} overflows a buffer"))
        })?;
    if len == 0 {
        return Err(Fault::refused("GetDIBits", "was asked for an empty bitmap"));
    }

    let screen = sys::ScreenDc::desktop().ok_or_else(|| Fault::last_os_error("GetDC"))?;
    let mut info = sys::BitmapInfo {
        header: sys::BitmapInfoHeader {
            size: u32::try_from(size_of::<sys::BitmapInfoHeader>()).unwrap_or(40),
            width: i32::try_from(width).unwrap_or(i32::MAX),
            // Negative for top-down, exactly as the capture surface asks for.
            height: -i32::try_from(height).unwrap_or(i32::MAX),
            planes: 1,
            bit_count: 32,
            compression: sys::BI_RGB,
            size_image: 0,
            x_pels_per_meter: 0,
            y_pels_per_meter: 0,
            clr_used: 0,
            clr_important: 0,
        },
        colours: [0; 3],
    };

    let mut bgra = vec![0u8; len];
    let copied = unsafe {
        sys::GetDIBits(
            screen.raw(),
            bitmap,
            0,
            height,
            bgra.as_mut_ptr().cast::<std::ffi::c_void>(),
            &mut info,
            sys::DIB_RGB_COLORS,
        )
    };
    if copied == 0 {
        return Err(Fault::last_os_error("GetDIBits"));
    }
    Ok(bgra)
}
