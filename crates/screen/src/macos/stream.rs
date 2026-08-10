//! macOS screen capture: `CGDisplayStream`, one display at a time.
//!
//! # Why this API, given the SDK says it is obsolete
//!
//! `CGDisplayStream` carries `API_DEPRECATED … obsoleted=15.0` in the macOS SDK.
//! That attribute is a **C availability gate**: it makes clang refuse to compile a
//! call, and it has no effect whatsoever on a Rust program, which resolves the
//! symbol from CoreGraphics like any other. The framework still exports it, still
//! starts, and still delivers frames — verified from raw Rust on 15.5 at 101
//! frames in 1.2 seconds with dirty rectangles attached.
//!
//! The alternative, ScreenCaptureKit, is the same [`Capture`] trait with an
//! Objective-C class hierarchy, a delegate object, `CMSampleBuffer`s and an async
//! start behind it. It is a strictly larger amount of runtime surface for the same
//! pixels, and it can be added beside this file later without changing a line
//! above the trait. Shipping the small one first is the same argument GDI won on
//! Windows.
//!
//! # The block struct is written correctly on day one
//!
//! `CGDisplayStreamCreateWithDispatchQueue` takes an **Objective-C block**, and
//! there is no way to construct one from Rust except by laying the structure out
//! by hand. This is the single most dangerous thing in the crate, because getting
//! it wrong does not fail to compile and does not fail at run time either:
//! `CGDisplayStream` is tolerant enough to call a malformed block, and a later
//! ScreenCaptureKit backend on the same wrong shape segfaults *inside libobjc*
//! with a stack that names neither the block nor this file. So the layout is built
//! properly the first time:
//!
//! - `isa` is `&raw const _NSConcreteGlobalBlock`, the runtime's global-block
//!   class. Global is the right class because the runtime never copies or frees a
//!   global block — `Block_copy` returns the same pointer and `Block_release` does
//!   nothing — so the block's lifetime is entirely ours, which is exactly what we
//!   need when it carries a pointer to our own state.
//! - `flags` is `BLOCK_IS_GLOBAL | BLOCK_HAS_SIGNATURE`.
//! - `descriptor` has the three fields that flag combination implies — reserved,
//!   size, signature — and no copy/dispose helpers, because a global block has
//!   nothing to copy.
//! - The signature is a real Objective-C type encoding for the handler, with the
//!   argument offsets a 64-bit ABI produces.
//!
//! # Surfaces come from a pool, so a retain is not enough
//!
//! Frames arrive as `IOSurface`s that `CGDisplayStream` recycles. Holding one with
//! `CFRetain` alone keeps the memory mapped and does **not** stop the stream from
//! drawing the next frame into it while the encoder is reading — which produces a
//! frame that is half of one moment and half of another, intermittently, under
//! load, and looks like a codec bug. `IOSurfaceIncrementUseCount` is what marks a
//! surface as in use, and every retain here is paired with one.
//!
//! # Rows are padded and the padding is not optional
//!
//! `IOSurfaceGetBytesPerRow` is wider than `width * 4` on every real display this
//! has been run against: **12160 bytes for a 3024-pixel surface** where the tight
//! row is 12096, and **6144 for 1512 pixels** where the tight row is 6048.
//! Assuming the tight value does not produce garbage — it produces a *sheared*
//! picture that still looks like a desktop, so it passes a glance and fails in the
//! field. [`Frame::stride`] carries the real number and
//! `selfhost_desk::tiles::unpack` is the one place it is unwound; the tests at the
//! bottom of this file assert both figures end to end.
//!
//! # Permission is a preflight and never an inspection of the frame
//!
//! See [`crate::macos::grant`]. A process without Screen Recording consent is
//! handed a picture of the wallpaper rather than an error, so the check happens
//! before the stream is created and the refusal that comes back is a typed
//! [`CaptureError::PermissionDenied`] carrying the remediation the console
//! renders.

use crate::macos::{grant, sys};
use crate::{Capture, CaptureError, Fault, Frame};
use selfhost_desk::wire::Monitor;
use selfhost_desk::{Damage, Rect};
use std::ffi::c_void;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// `'BGRA'` as a four-character code: the only pixel format this crate reads.
const PIXEL_FORMAT_BGRA: i32 = 0x4247_5241;

/// `kCGDisplayStreamFrameStatusFrameComplete`.
const STATUS_COMPLETE: i32 = 0;
/// `kCGDisplayStreamFrameStatusFrameIdle`: nothing changed. Not an error, and not
/// counted against anything.
const STATUS_IDLE: i32 = 1;
/// `kCGDisplayStreamFrameStatusFrameBlank`: the display has nothing on it.
const STATUS_BLANK: i32 = 2;
/// `kCGDisplayStreamFrameStatusStopped`: the stream will deliver nothing more.
const STATUS_STOPPED: i32 = 3;

/// `kCGDisplayStreamUpdateDirtyRects`.
const UPDATE_DIRTY_RECTS: i32 = 2;
/// `kCGDisplayStreamUpdateMovedRects`. Read and folded into the dirty list rather
/// than carried as moves — see [`collect_damage`].
const UPDATE_MOVED_RECTS: i32 = 1;

/// `kIOSurfaceLockReadOnly`. Read-only matters: a writable lock invalidates the
/// surface's cached contents for the graphics system, which costs a full copy.
const IOSURFACE_LOCK_READ_ONLY: u32 = 0x0000_0001;

/// `BLOCK_IS_GLOBAL`.
const BLOCK_IS_GLOBAL: i32 = 1 << 28;
/// `BLOCK_HAS_SIGNATURE`.
const BLOCK_HAS_SIGNATURE: i32 = 1 << 30;

/// How long a frame handed over by the stream may be held before the encoder is
/// assumed to have gone away. Only used to bound the stop handshake.
const STOP_GRACE: Duration = Duration::from_millis(2000);

/// How often the display layout is re-read while a stream is running.
const TOPOLOGY_POLL: Duration = Duration::from_secs(2);

/// How often the screen-recording consent is re-checked while a stream is running.
///
/// Not per frame: the preflight is an IPC to the TCC daemon, and asking it sixty
/// times a second would cost more than the capture. Two seconds is fast enough
/// that an operator who revokes the grant sees the console say so before they have
/// finished switching windows.
const CONSENT_POLL: Duration = Duration::from_secs(2);

#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {
    /// Creates a display stream that delivers frames to a dispatch queue.
    ///
    /// The dispatch-queue form is chosen over the run-loop form deliberately: the
    /// run-loop form requires the capture thread to own and run a `CFRunLoop`,
    /// which is a second scheduler inside a thread whose only job is to block on a
    /// condition variable.
    fn CGDisplayStreamCreateWithDispatchQueue(
        display: u32,
        output_width: usize,
        output_height: usize,
        pixel_format: i32,
        properties: *const c_void,
        queue: *mut c_void,
        handler: *mut c_void,
    ) -> *mut c_void;

    /// Starts delivery. Answers `kCGErrorSuccess` (0).
    fn CGDisplayStreamStart(stream: *mut c_void) -> i32;

    /// Stops delivery. **Asynchronous**: the handler is still called once more,
    /// with [`STATUS_STOPPED`], and until then the block and everything it points
    /// at must stay alive.
    fn CGDisplayStreamStop(stream: *mut c_void) -> i32;

    /// The rectangles of one kind in an update. The pointer is owned by the update
    /// and is valid only for the duration of the handler call, which is why the
    /// rectangles are copied out inside it.
    fn CGDisplayStreamUpdateGetRects(
        update: *mut c_void,
        rect_type: i32,
        count: *mut usize,
    ) -> *const sys::CGRect;

    /// The key for the "composite the pointer into the frame" property.
    static kCGDisplayStreamShowCursor: *const c_void;
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    /// Retains any Core Foundation object, including an `IOSurface`.
    fn CFRetain(object: *const c_void) -> *const c_void;

    /// Releases one.
    fn CFRelease(object: *const c_void);

    /// Builds the one-entry properties dictionary the stream is created with.
    fn CFDictionaryCreate(
        allocator: *const c_void,
        keys: *const *const c_void,
        values: *const *const c_void,
        count: isize,
        key_callbacks: *const c_void,
        value_callbacks: *const c_void,
    ) -> *const c_void;

    /// `kCFBooleanFalse`.
    static kCFBooleanFalse: *const c_void;

    /// The standard key callbacks. Only its **address** is ever used; the array
    /// type here is a stand-in for an opaque structure, which is sound because
    /// nothing in this crate reads through it.
    static kCFTypeDictionaryKeyCallBacks: [*const c_void; 8];

    /// The standard value callbacks, under the same rule.
    static kCFTypeDictionaryValueCallBacks: [*const c_void; 8];
}

#[link(name = "IOSurface", kind = "framework")]
unsafe extern "C" {
    /// Maps a surface for reading. Answers `kIOReturnSuccess` (0).
    fn IOSurfaceLock(surface: *mut c_void, options: u32, seed: *mut u32) -> i32;

    /// Unmaps it. Every successful lock has exactly one of these.
    fn IOSurfaceUnlock(surface: *mut c_void, options: u32, seed: *mut u32) -> i32;

    /// The mapped bytes, or null when the surface is not locked.
    fn IOSurfaceGetBaseAddress(surface: *mut c_void) -> *mut c_void;

    /// Bytes between the starts of consecutive rows. **Never `width * 4`.**
    fn IOSurfaceGetBytesPerRow(surface: *mut c_void) -> usize;

    /// Width in pixels.
    fn IOSurfaceGetWidth(surface: *mut c_void) -> usize;

    /// Height in pixels.
    fn IOSurfaceGetHeight(surface: *mut c_void) -> usize;

    /// The whole allocation's size, which bounds every read this module makes.
    fn IOSurfaceGetAllocSize(surface: *mut c_void) -> usize;

    /// Marks a surface as in use, so the stream's pool does not draw the next
    /// frame into it while this one is being read.
    fn IOSurfaceIncrementUseCount(surface: *mut c_void);

    /// Releases that mark.
    fn IOSurfaceDecrementUseCount(surface: *mut c_void);
}

unsafe extern "C" {
    /// The global concurrent dispatch queue. Not owned, never released, and there
    /// is exactly one per priority for the whole process — which is why no queue is
    /// created here and none has to be torn down in the right order later.
    fn dispatch_get_global_queue(identifier: isize, flags: usize) -> *mut c_void;

    /// The Objective-C runtime's global-block class.
    ///
    /// Typed as an array purely so that `&raw const` produces the address the `isa`
    /// field needs; the contents are never read by this crate.
    static _NSConcreteGlobalBlock: [*const c_void; 32];
}

/// The descriptor an Objective-C block with a signature and no helpers has.
#[repr(C)]
struct BlockDescriptor {
    /// Reserved; zero.
    reserved: u64,
    /// The size of the block structure itself.
    size: u64,
    /// The handler's Objective-C type encoding.
    signature: *const u8,
}

/// A descriptor that may live in a `static`.
///
/// `BlockDescriptor` holds a raw pointer, which is not `Sync` by default. It is
/// sound here because the pointer is to a `'static` byte string and nothing ever
/// writes through it.
struct StaticDescriptor(BlockDescriptor);

// Safety: the only pointer inside is to a `'static` string literal, read-only.
unsafe impl Sync for StaticDescriptor {}

/// The handler's type encoding: `void (^)(int32_t, uint64_t, IOSurfaceRef,
/// CGDisplayStreamUpdateRef)`.
///
/// The offsets are the ones a 64-bit ABI produces — the block pointer at 0, the
/// status at 8, the display time at 16 after four bytes of padding, and the two
/// pointers at 24 and 32, for 40 bytes in total. Nothing in the ordinary path
/// parses this string; a future ScreenCaptureKit backend on the same block shape
/// does.
static BLOCK_SIGNATURE: &[u8] = b"v40@?0i8Q16^v24^v32\0";

/// The one descriptor every stream's block points at.
static BLOCK_DESCRIPTOR: StaticDescriptor = StaticDescriptor(BlockDescriptor {
    reserved: 0,
    size: size_of::<FrameBlock>() as u64,
    signature: BLOCK_SIGNATURE.as_ptr(),
});

/// The block passed to `CGDisplayStreamCreateWithDispatchQueue`.
///
/// The first five fields are the ABI's; `shared` is this block's one captured
/// variable. A global block is documented as having no captured variables, and
/// carrying one anyway is sound precisely because the runtime never copies a
/// global block: `Block_copy` returns the same pointer, so the captured field is
/// never left behind in a copy that outlives it.
#[repr(C)]
struct FrameBlock {
    /// `&_NSConcreteGlobalBlock`.
    isa: *const c_void,
    /// [`BLOCK_IS_GLOBAL`] | [`BLOCK_HAS_SIGNATURE`].
    flags: i32,
    /// Reserved; zero.
    reserved: i32,
    /// The function the runtime calls.
    invoke: unsafe extern "C" fn(*mut FrameBlock, i32, u64, *mut c_void, *mut c_void),
    /// [`BLOCK_DESCRIPTOR`].
    descriptor: *const BlockDescriptor,
    /// The state the handler delivers into, owned as a raw `Arc`.
    shared: *const Shared,
}

// A layout mistake here is not a compile error and not a run-time error; it is a
// call into libobjc with the wrong shape. Asserted on the only macOS this crate
// targets.
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<FrameBlock>() == 40);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<BlockDescriptor>() == 24);

/// A retained, use-counted `IOSurface`.
///
/// A newtype rather than a bare pointer so that the `Send` promise below is
/// attached to something that documents why it is true.
struct SurfaceRef(*mut c_void);

// Safety: an `IOSurface` is a thread-safe Core Foundation object, and this handle
// is a strong reference to one. It is created on the dispatch queue the stream
// delivers on and consumed on the capture thread, which is precisely the handover
// this promise describes.
unsafe impl Send for SurfaceRef {}

impl Drop for SurfaceRef {
    fn drop(&mut self) {
        // Both halves, in the reverse order of acquisition: the use count first so
        // the pool may recycle the surface, then the retain.
        unsafe {
            IOSurfaceDecrementUseCount(self.0);
            CFRelease(self.0.cast_const());
        }
    }
}

/// One frame the handler has delivered and the capture thread has not taken.
struct Delivered {
    /// The surface itself.
    surface: SurfaceRef,
    /// What the platform said changed, already copied out of the update — the
    /// update reference is valid only inside the handler.
    damage: Damage,
}

/// The handover between the dispatch queue and the capture thread.
#[derive(Default)]
struct Handoff {
    /// The newest frame, if one is waiting. Exactly one is kept: a remote desktop
    /// wants the *latest* picture, and a queue of stale frames is latency wearing
    /// a buffer's clothes.
    frame: Option<Delivered>,
    /// How many frames the stream delivered while the previous one was still being
    /// encoded, and which were therefore replaced rather than queued. Read back
    /// through [`MacCapture::dropped_frames`] for the diagnostics plate: a rising
    /// number is the honest description of a link that cannot keep up, and it is
    /// deliberately not an error — dropping the older frame is the correct answer
    /// for a remote desktop, where the newest picture is the only one worth having.
    dropped: u64,
    /// Set once the stream has acknowledged its stop.
    stopped: bool,
    /// Set when the display reported a blank frame.
    blank: bool,
}

/// The state the handler and the capture thread share.
#[derive(Default)]
struct Shared {
    /// The handover.
    handoff: Mutex<Handoff>,
    /// Signalled on every delivery and on the stop acknowledgement.
    arrival: Condvar,
}

/// The handler the runtime calls, once per frame, on a dispatch queue.
///
/// # Safety
///
/// Called by the Objective-C runtime with the arguments the block signature
/// describes. `block` is the [`FrameBlock`] this crate built, and its `shared`
/// pointer is kept alive until the stop acknowledgement arrives — see
/// [`ActiveStream::drop`], which is the other half of that promise.
unsafe extern "C" fn on_frame(
    block: *mut FrameBlock,
    status: i32,
    _display_time: u64,
    surface: *mut c_void,
    update: *mut c_void,
) {
    if block.is_null() {
        return;
    }
    let shared = unsafe { (*block).shared };
    if shared.is_null() {
        return;
    }
    // Borrowed, never reconstructed into an `Arc`: ownership stays with
    // `ActiveStream`, which is what guarantees this pointer outlives every call.
    let shared: &Shared = unsafe { &*shared };

    match status {
        STATUS_COMPLETE if !surface.is_null() => {
            // Retained and use-counted *before* the lock is taken, so the window in
            // which the pool could recycle it is as short as it can be.
            unsafe {
                CFRetain(surface.cast_const());
                IOSurfaceIncrementUseCount(surface);
            }
            let damage = unsafe { collect_damage(update) };
            let delivered = Delivered { surface: SurfaceRef(surface), damage };
            if let Ok(mut handoff) = shared.handoff.lock() {
                if handoff.frame.is_some() {
                    handoff.dropped = handoff.dropped.saturating_add(1);
                }
                handoff.blank = false;
                handoff.frame = Some(delivered);
                shared.arrival.notify_all();
            }
        }
        STATUS_BLANK => {
            if let Ok(mut handoff) = shared.handoff.lock() {
                handoff.blank = true;
            }
        }
        STATUS_STOPPED => {
            if let Ok(mut handoff) = shared.handoff.lock() {
                handoff.stopped = true;
                shared.arrival.notify_all();
            }
        }
        // A still desktop produces `STATUS_IDLE` for as long as it stays still, and
        // a complete frame with no surface means the same thing. Waking the capture
        // thread for either would replace a still desktop's near-zero cost with a
        // wakeup per frame interval, forever.
        STATUS_IDLE => {}
        // A status this build does not know about. Treated as idle rather than as a
        // failure: an unknown state that stops the session is worse than an unknown
        // state that waits for the next frame.
        _ => {}
    }
}

/// Copies the damage out of an update reference.
///
/// # Moved rectangles are folded into the dirty list
///
/// `CGDisplayStreamUpdate` reports moved content as a set of destination
/// rectangles plus one delta, and reconstructing a [`selfhost_desk::MoveRect`] from
/// them requires knowing the delta's sign convention. That convention could not be
/// established from documentation, and a wrong sign does not cost bandwidth — it
/// **corrupts the picture**, because the client applies moves before dirty
/// rectangles and would blit from the wrong place. Treating a moved region as
/// simply changed is always correct and sometimes wasteful, which is the right side
/// of that trade to be on.
///
/// # Safety
///
/// `update` must be the update reference the runtime passed to the handler, valid
/// for the duration of the call.
unsafe fn collect_damage(update: *mut c_void) -> Damage {
    let mut damage = Damage::default();
    if update.is_null() {
        return damage;
    }
    for kind in [UPDATE_DIRTY_RECTS, UPDATE_MOVED_RECTS] {
        let mut count: usize = 0;
        let rects = unsafe { CGDisplayStreamUpdateGetRects(update, kind, &mut count) };
        if rects.is_null() {
            continue;
        }
        // Bounded before it is trusted: the count comes from the platform, and a
        // ludicrous one would be an unbounded read and an unbounded allocation.
        for index in 0..count.min(MAX_DAMAGE_RECTS) {
            let rect = unsafe { *rects.add(index) };
            if let Some(converted) = convert_rect(rect) {
                damage.dirty.push(converted);
            }
        }
    }
    damage
}

/// The most damage rectangles one frame may describe.
///
/// A frame with more changed regions than this is a frame where redrawing
/// everything is cheaper than describing it, and the encoder above treats an empty
/// or partial damage list as "assume everything is new" anyway.
const MAX_DAMAGE_RECTS: usize = 256;

/// A Core Graphics rectangle as the protocol's integral one.
///
/// Rounds **outward** — the origin down, the far edge up — because a damage
/// rectangle that is a pixel too small leaves a stale line on the client's screen
/// forever, while one that is a pixel too large costs one row of pixels once.
fn convert_rect(rect: sys::CGRect) -> Option<Rect> {
    let (x, y, width, height) =
        (rect.origin.x, rect.origin.y, rect.size.width, rect.size.height);
    if !x.is_finite() || !y.is_finite() || !width.is_finite() || !height.is_finite() {
        return None;
    }
    if width <= 0.0 || height <= 0.0 {
        return None;
    }
    let left = x.floor();
    let top = y.floor();
    let right = (x + width).ceil();
    let bottom = (y + height).ceil();
    // Saturating casts: every one of these came from the platform and none of them
    // may become a wrapped coordinate.
    let left_i = left.max(f64::from(i32::MIN)).min(f64::from(i32::MAX)) as i32;
    let top_i = top.max(f64::from(i32::MIN)).min(f64::from(i32::MAX)) as i32;
    let width_u = (right - left).max(0.0).min(f64::from(u32::MAX)) as u32;
    let height_u = (bottom - top).max(0.0).min(f64::from(u32::MAX)) as u32;
    if width_u == 0 || height_u == 0 {
        return None;
    }
    Some(Rect::new(left_i, top_i, width_u, height_u))
}

/// A surface locked for reading, unlocked and released on drop.
struct LockedSurface {
    /// The retained surface.
    surface: SurfaceRef,
    /// The mapped bytes.
    base: *const u8,
    /// The mapped length, bounded by the surface's own allocation size.
    len: usize,
    /// Bytes per row, which is wider than `width * 4`.
    stride: usize,
    /// Width in pixels.
    width: u32,
    /// Height in pixels.
    height: u32,
    /// What changed, as the platform described it.
    damage: Damage,
}

impl LockedSurface {
    /// Locks a delivered surface and measures it.
    ///
    /// # Errors
    ///
    /// [`CaptureError::Reinitialise`] for a surface that cannot be locked, that
    /// maps to nothing, or whose stride, extent and allocation do not agree — all
    /// three of which are a display mid-reconfiguration rather than a fault, and
    /// all three of which must be refused rather than indexed into.
    fn take(delivered: Delivered) -> Result<Self, CaptureError> {
        let raw = delivered.surface.0;
        let status = unsafe { IOSurfaceLock(raw, IOSURFACE_LOCK_READ_ONLY, std::ptr::null_mut()) };
        if status != 0 {
            return Err(CaptureError::Reinitialise);
        }
        // From here every path must unlock, so the guard is built immediately and
        // the checks happen against it.
        let base = unsafe { IOSurfaceGetBaseAddress(raw) };
        let stride = unsafe { IOSurfaceGetBytesPerRow(raw) };
        let width = unsafe { IOSurfaceGetWidth(raw) };
        let height = unsafe { IOSurfaceGetHeight(raw) };
        let alloc = unsafe { IOSurfaceGetAllocSize(raw) };

        let mut locked = Self {
            surface: delivered.surface,
            base: base.cast_const().cast::<u8>(),
            len: 0,
            stride,
            width: u32::try_from(width).unwrap_or(0),
            height: u32::try_from(height).unwrap_or(0),
            damage: delivered.damage,
        };
        // Every refusal below drops `locked`, which unlocks the surface and hands it
        // back to the pool — which is why the guard is built before the checks
        // rather than after them.
        let Some(len) = readable_len(locked.width, locked.height, stride, alloc) else {
            return Err(CaptureError::Reinitialise);
        };
        if locked.base.is_null() {
            return Err(CaptureError::Reinitialise);
        }
        locked.len = len;
        Ok(locked)
    }

    /// The mapped pixels.
    ///
    /// Sound: the surface is locked for the lifetime of `self`, `base` is the
    /// address the lock produced, and `len` was checked against the surface's own
    /// allocation size before it was stored.
    fn pixels(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.base, self.len) }
    }
}

impl Drop for LockedSurface {
    fn drop(&mut self) {
        unsafe { IOSurfaceUnlock(self.surface.0, IOSURFACE_LOCK_READ_ONLY, std::ptr::null_mut()) };
        // `self.surface` releases and un-counts itself immediately after this,
        // which is the required order: the pool must not have the surface back
        // while it is still locked.
    }
}

/// How many bytes of a surface may be read, or `None` if its numbers disagree.
///
/// Pure, and separated from the FFI so the arithmetic that stands between a
/// correct picture and an out-of-bounds read can be tested with numbers typed by
/// hand. The requirement is the same one `selfhost_desk::tiles::unpack` states: the
/// last row does not need its padding present, so the minimum is
/// `stride * (height - 1) + width * 4` rather than `stride * height`.
pub fn readable_len(width: u32, height: u32, stride: usize, alloc: usize) -> Option<usize> {
    if width == 0 || height == 0 {
        return None;
    }
    let tight_row = (width as usize).checked_mul(4)?;
    if stride < tight_row {
        return None;
    }
    let minimum = stride.checked_mul(height as usize - 1)?.checked_add(tight_row)?;
    if alloc < minimum {
        return None;
    }
    // Exactly one whole picture, and never the final row's padding: the encoder
    // above needs `stride * (height - 1) + width * 4` bytes and reading further
    // would expose bytes the surface has not promised are meaningful.
    Some(minimum)
}

/// A running `CGDisplayStream` and everything that must outlive it.
struct ActiveStream {
    /// The stream itself.
    stream: *mut c_void,
    /// The block, leaked from a `Box` and reclaimed on drop.
    block: *mut FrameBlock,
    /// The shared state, held as an owning `Arc` while the raw pointer inside the
    /// block borrows it.
    shared: Arc<Shared>,
    /// Which Core Graphics display this stream is for.
    display: u32,
}

impl ActiveStream {
    /// Creates and starts a stream for one display.
    ///
    /// # Errors
    ///
    /// [`CaptureError::Fatal`] when Core Graphics refuses to create or start the
    /// stream, which on a machine that passed the consent preflight means something
    /// is wrong that a retry will not fix.
    fn start(display: u32, width: u32, height: u32) -> Result<Self, CaptureError> {
        let shared = Arc::new(Shared::default());
        // The block borrows the shared state rather than owning a clone of the
        // `Arc`: `ActiveStream` holds the only strong reference and outlives the
        // block by construction, because dropping it is what stops the stream.
        let block = Box::new(FrameBlock {
            isa: (&raw const _NSConcreteGlobalBlock).cast(),
            flags: BLOCK_IS_GLOBAL | BLOCK_HAS_SIGNATURE,
            reserved: 0,
            invoke: on_frame,
            descriptor: &raw const BLOCK_DESCRIPTOR.0,
            shared: Arc::as_ptr(&shared),
        });
        let block = Box::into_raw(block);

        let properties = hide_cursor_properties();
        let queue = unsafe { dispatch_get_global_queue(0, 0) };
        let stream = unsafe {
            CGDisplayStreamCreateWithDispatchQueue(
                display,
                width as usize,
                height as usize,
                PIXEL_FORMAT_BGRA,
                properties,
                queue,
                block.cast(),
            )
        };
        if !properties.is_null() {
            unsafe { CFRelease(properties) };
        }
        if stream.is_null() {
            // Nothing was started, so nothing has to be stopped: the block can be
            // reclaimed immediately.
            drop(unsafe { Box::from_raw(block) });
            return Err(CaptureError::Fatal(Fault::refused(
                "CGDisplayStreamCreateWithDispatchQueue",
                "produced no stream for this display",
            )));
        }

        let status = unsafe { CGDisplayStreamStart(stream) };
        if status != 0 {
            unsafe { CFRelease(stream.cast_const()) };
            drop(unsafe { Box::from_raw(block) });
            return Err(CaptureError::Fatal(Fault::os("CGDisplayStreamStart", status)));
        }
        Ok(Self { stream, block, shared, display })
    }

    /// Waits for the next delivered frame.
    ///
    /// `Ok(None)` is the timeout expiring with nothing new, which on a still
    /// desktop is the ordinary answer forever and is never counted against
    /// anything.
    fn next(&self, timeout: Duration) -> Result<Option<Delivered>, CaptureError> {
        let Ok(mut handoff) = self.shared.handoff.lock() else {
            // A poisoned mutex means the handler panicked, which under
            // `panic = "abort"` cannot happen — but the lock is still fallible, and
            // a rebuild is a better answer than an unwrap in a daemon.
            return Err(CaptureError::Reinitialise);
        };
        if handoff.frame.is_none() && !handoff.stopped {
            let (guard, _) = self
                .shared
                .arrival
                .wait_timeout(handoff, timeout)
                .map_err(|_| CaptureError::Reinitialise)?;
            handoff = guard;
        }
        if handoff.stopped {
            return Err(CaptureError::Reinitialise);
        }
        Ok(handoff.frame.take())
    }
}

impl Drop for ActiveStream {
    /// Stops the stream and reclaims the block **only** once the stop has been
    /// acknowledged.
    ///
    /// `CGDisplayStreamStop` is asynchronous: the handler is called once more, with
    /// [`STATUS_STOPPED`], after it returns. Freeing the block or the shared state
    /// before that call is a use-after-free inside a system dispatch queue, which
    /// is neither reproducible nor debuggable from a log. So the stop is waited on,
    /// and if the acknowledgement does not arrive within [`STOP_GRACE`] the block
    /// and the shared state are **deliberately leaked** — a few hundred bytes, once
    /// per stream that misbehaved, against a crash in a daemon that also serves the
    /// machine's mail and certificates.
    fn drop(&mut self) {
        unsafe { CGDisplayStreamStop(self.stream) };

        let deadline = Instant::now() + STOP_GRACE;
        let mut acknowledged = false;
        while let Ok(handoff) = self.shared.handoff.lock() {
            if handoff.stopped {
                acknowledged = true;
                break;
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            if remaining.is_zero() {
                break;
            }
            let Ok((guard, _)) = self.shared.arrival.wait_timeout(handoff, remaining) else {
                break;
            };
            acknowledged = guard.stopped;
            if acknowledged {
                break;
            }
        }

        unsafe { CFRelease(self.stream.cast_const()) };
        if acknowledged {
            drop(unsafe { Box::from_raw(self.block) });
        }
        // Otherwise the block and the `Arc` inside it are left alive on purpose: the
        // stop was never acknowledged, so the system may still call into them. The
        // leak is the point, and it is bounded by the number of streams that
        // misbehaved. See the doc comment above.
    }
}

/// The properties dictionary that keeps the pointer out of the frame.
///
/// The pointer is captured separately and composited by the client at *its* frame
/// rate, which is the single largest perceived-latency win in this subsystem. A
/// stream that also drew the pointer into the pixels would produce two pointers on
/// the console's screen — one live, one a frame or two behind.
///
/// Answers null when the dictionary cannot be built, which is not fatal: the stream
/// is then created with its defaults, and the worst case is the cosmetic double
/// pointer rather than no session.
fn hide_cursor_properties() -> *const c_void {
    let key = unsafe { kCGDisplayStreamShowCursor };
    let value = unsafe { kCFBooleanFalse };
    if key.is_null() || value.is_null() {
        return std::ptr::null();
    }
    let keys = [key];
    let values = [value];
    unsafe {
        CFDictionaryCreate(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            (&raw const kCFTypeDictionaryKeyCallBacks).cast(),
            (&raw const kCFTypeDictionaryValueCallBacks).cast(),
        )
    }
}

/// The macOS screen source.
///
/// Captures **one display at a time**, chosen by [`MacCapture::select`], for the
/// same reason the Windows one does: a viewer looks at one screen, and the bounding
/// box of two displays of different heights contains dead area that would be
/// encoded, sent and diffed forever.
pub struct MacCapture {
    /// Every display, as the protocol describes them.
    monitors: Vec<Monitor>,
    /// Core Graphics' own ids, in the same order as `monitors`.
    displays: Vec<u32>,
    /// Which display is being captured, by [`Monitor::id`].
    target: u8,
    /// The running stream, absent until the first frame and after every rebuild.
    stream: Option<ActiveStream>,
    /// The frame currently handed out, kept alive for exactly as long as the
    /// borrow in [`Frame`] can live.
    current: Option<LockedSurface>,
    /// A monotonically increasing frame number.
    sequence: u64,
    /// When the layout was last re-enumerated.
    enumerated_at: Instant,
    /// When the consent was last confirmed.
    consented_at: Instant,
}

impl MacCapture {
    /// Builds a screen source for this machine's displays.
    ///
    /// # Errors
    ///
    /// [`CaptureError::PermissionDenied`] when Screen Recording has not been
    /// granted — checked **first**, before anything asks for a pixel, because a
    /// denied process is handed a picture of the wallpaper rather than an error.
    /// [`CaptureError::NoSession`] for a Mac with no display attached, which is a
    /// state rather than a failure.
    pub fn new() -> Result<Self, CaptureError> {
        grant::gate(false)?;
        let found = sys::displays()?;
        let monitors = sys::monitors()?;
        let displays: Vec<u32> = found.iter().map(|display| display.id).collect();
        let target = monitors
            .iter()
            .find(|monitor| monitor.primary)
            .or_else(|| monitors.first())
            .map(|monitor| monitor.id)
            .ok_or(CaptureError::NoSession)?;
        let now = Instant::now();
        Ok(Self {
            monitors,
            displays,
            target,
            stream: None,
            current: None,
            sequence: 0,
            enumerated_at: now,
            consented_at: now,
        })
    }

    /// Which display is being captured.
    pub fn target(&self) -> u8 {
        self.target
    }

    /// How many delivered frames have been superseded before they were encoded.
    ///
    /// Zero on a link that keeps up, and rising on one that does not. Never a
    /// failure: see [`Handoff::dropped`].
    pub fn dropped_frames(&self) -> u64 {
        self.stream
            .as_ref()
            .and_then(|stream| stream.shared.handoff.lock().ok().map(|handoff| handoff.dropped))
            .unwrap_or(0)
    }

    /// Captures a different display from the next frame on.
    ///
    /// Answers `false` for a display that does not exist rather than switching to
    /// nothing: a viewer asking for a monitor that has just been unplugged should
    /// keep seeing the one it has.
    pub fn select(&mut self, monitor: u8) -> bool {
        if !self.monitors.iter().any(|candidate| candidate.id == monitor) {
            return false;
        }
        if self.target != monitor {
            self.target = monitor;
            self.current = None;
            self.stream = None;
        }
        true
    }

    /// The display being captured, with its Core Graphics id.
    fn target_display(&self) -> Result<(Monitor, u32), CaptureError> {
        let index = self
            .monitors
            .iter()
            .position(|monitor| monitor.id == self.target)
            .ok_or(CaptureError::Reinitialise)?;
        let monitor = *self.monitors.get(index).ok_or(CaptureError::Reinitialise)?;
        let display = *self.displays.get(index).ok_or(CaptureError::Reinitialise)?;
        Ok((monitor, display))
    }

    /// Re-reads the layout and the consent when either is due.
    ///
    /// Answers `Ok(true)` when the caller must treat the source as rebuilt.
    fn refresh(&mut self, now: Instant) -> Result<bool, CaptureError> {
        if now.saturating_duration_since(self.consented_at) >= CONSENT_POLL {
            self.consented_at = now;
            // A grant revoked while a session is live must reach the console as the
            // remediation sentence, not as a stream that quietly starts returning
            // wallpaper.
            grant::gate(false)?;
        }
        if now.saturating_duration_since(self.enumerated_at) < TOPOLOGY_POLL {
            return Ok(false);
        }
        self.enumerated_at = now;
        let found = sys::displays()?;
        let monitors = sys::monitors()?;
        if monitors == self.monitors {
            return Ok(false);
        }
        self.monitors = monitors;
        self.displays = found.iter().map(|display| display.id).collect();
        self.current = None;
        self.stream = None;
        if !self.monitors.iter().any(|monitor| monitor.id == self.target) {
            self.target = self
                .monitors
                .iter()
                .find(|monitor| monitor.primary)
                .or_else(|| self.monitors.first())
                .map(|monitor| monitor.id)
                .ok_or(CaptureError::NoSession)?;
        }
        Ok(true)
    }
}

impl Capture for MacCapture {
    fn monitors(&self) -> &[Monitor] {
        &self.monitors
    }

    /// The next frame, or the state the source is in instead.
    ///
    /// Waits up to `timeout` on the stream's own delivery rather than polling:
    /// unlike GDI, `CGDisplayStream` genuinely knows when the screen has changed, so
    /// a still desktop costs one blocked thread and no frames at all.
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame<'_>>, CaptureError> {
        // Released before anything else: the previous frame's surface must go back
        // to the pool before the next one is asked for, or the stream runs out of
        // surfaces and starts dropping frames it could have delivered.
        self.current = None;

        if self.refresh(Instant::now())? {
            return Err(CaptureError::Reinitialise);
        }
        let (monitor, display) = self.target_display()?;

        if self.stream.as_ref().is_none_or(|stream| stream.display != display) {
            self.stream = Some(ActiveStream::start(display, monitor.width, monitor.height)?);
        }
        let stream = self.stream.as_ref().ok_or(CaptureError::Reinitialise)?;
        let Some(delivered) = stream.next(timeout)? else {
            return Ok(None);
        };

        let locked = LockedSurface::take(delivered)?;
        // The extent the stream is delivering must still be the extent the protocol
        // advertised, or the client's tile grid describes a different picture than
        // the one arriving.
        if locked.width != monitor.width || locked.height != monitor.height {
            self.stream = None;
            return Err(CaptureError::Reinitialise);
        }
        self.sequence = self.sequence.saturating_add(1);
        self.current = Some(locked);
        let locked = self.current.as_ref().ok_or(CaptureError::Reinitialise)?;
        Ok(Some(Frame {
            monitor: monitor.id,
            sequence: self.sequence,
            width: locked.width,
            height: locked.height,
            stride: locked.stride,
            pixels: locked.pixels(),
            damage: locked.damage.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_desk::tiles;

    #[test]
    fn a_retina_surfaces_padded_rows_unpack_to_the_picture_they_describe() {
        // The measured figures: a 3024-pixel surface reports 12160 bytes per row
        // where the tight row is 12096. Assuming the tight value shears the image
        // in a way that still looks like a desktop.
        let width = 3024u32;
        let height = 4u32;
        let stride = 12_160usize;
        assert_eq!(width as usize * 4, 12_096);

        let mut pixels = vec![0u8; stride * height as usize];
        for row in 0..height as usize {
            for column in 0..width as usize {
                let at = row * stride + column * 4;
                // A value that depends on both axes, so a shear is visible as a
                // mismatch rather than as a plausible-looking picture.
                pixels[at] = (column % 251) as u8;
                pixels[at + 1] = (row % 251) as u8;
                pixels[at + 2] = 0x10;
                pixels[at + 3] = 0xFF;
            }
            // Padding filled with a value that must never appear in the output.
            for byte in pixels.iter_mut().skip(row * stride + width as usize * 4).take(stride - width as usize * 4) {
                *byte = 0xFE;
            }
        }

        let surface = tiles::unpack(width, height, stride, &pixels).expect("the rows unpack");
        // 0xFE cannot appear in the picture: the two varying channels are taken
        // modulo 251 and the other two are fixed, so any 0xFE in the output came
        // from a row's padding and means the stride was ignored.
        assert!(!surface.pixels().contains(&0xFE), "row padding leaked into the picture");
        for row in 0..height as usize {
            let at = (row * width as usize + 7) * 4;
            assert_eq!(surface.pixels()[at], 7);
            assert_eq!(surface.pixels()[at + 1], (row % 251) as u8);
        }
    }

    #[test]
    fn the_other_measured_stride_unpacks_too() {
        // 6144 bytes for a 1512-pixel surface, where the tight row is 6048.
        let (width, height, stride) = (1512u32, 3u32, 6_144usize);
        assert_eq!(width as usize * 4, 6_048);
        let pixels = vec![0x22u8; stride * height as usize];
        let surface = tiles::unpack(width, height, stride, &pixels).expect("the rows unpack");
        assert_eq!(surface.pixels().len(), (width * height * 4) as usize);
    }

    #[test]
    fn a_frame_reads_its_rows_through_the_stride_it_was_given() {
        // The same figures, through `Frame::row`, which is what an encoder that
        // reads row by row uses.
        let (width, height, stride) = (1512u32, 2u32, 6_144usize);
        let pixels = vec![0u8; stride * height as usize];
        let frame = Frame {
            monitor: 0,
            sequence: 1,
            width,
            height,
            stride,
            pixels: &pixels,
            damage: Damage::default(),
        };
        assert_eq!(frame.row(0).map(<[u8]>::len), Some(6_048));
        assert_eq!(frame.row(1).map(<[u8]>::len), Some(6_048));
        assert!(frame.row(2).is_none());
    }

    #[test]
    fn a_surface_whose_numbers_disagree_is_refused_rather_than_read_past() {
        // Every one of these is reachable from a display mid-reconfiguration, and
        // under `panic = "abort"` an out-of-bounds read is the whole daemon.
        assert_eq!(readable_len(0, 10, 4, 400), None, "no pixels");
        assert_eq!(readable_len(10, 0, 40, 400), None, "no rows");
        assert_eq!(readable_len(10, 10, 39, 400), None, "a stride narrower than the row");
        assert_eq!(readable_len(1512, 100, 6_144, 1_000), None, "an allocation that is too small");
        assert_eq!(
            readable_len(1512, 100, 6_144, 6_144 * 100),
            Some(6_144 * 99 + 6_048),
            "the last row does not need its padding"
        );
    }

    #[test]
    fn a_damage_rectangle_rounds_outward_rather_than_inward() {
        // A rectangle a pixel too small leaves a stale line on the client's screen
        // forever; one a pixel too large costs one row of pixels once.
        let rect = convert_rect(sys::CGRect {
            origin: sys::CGPoint { x: 10.4, y: 20.6 },
            size: sys::CGSize { width: 5.2, height: 3.1 },
        })
        .expect("a real rectangle");
        assert_eq!(rect.x, 10);
        assert_eq!(rect.y, 20);
        assert!(rect.right() >= 16, "the far edge covers 15.6");
        assert!(rect.bottom() >= 24, "the far edge covers 23.7");
    }

    #[test]
    fn an_impossible_rectangle_is_dropped_rather_than_wrapped() {
        for (x, y, width, height) in [
            (f64::NAN, 0.0, 4.0, 4.0),
            (0.0, f64::INFINITY, 4.0, 4.0),
            (0.0, 0.0, 0.0, 4.0),
            (0.0, 0.0, 4.0, -1.0),
        ] {
            assert!(
                convert_rect(sys::CGRect {
                    origin: sys::CGPoint { x, y },
                    size: sys::CGSize { width, height },
                })
                .is_none(),
                "({x}, {y}, {width}, {height}) should not have become a rectangle"
            );
        }
    }

    #[test]
    fn the_block_is_laid_out_the_way_the_objective_c_runtime_reads_it() {
        // The check that cannot be made at run time: a wrong layout is a call into
        // libobjc with the wrong shape, which `CGDisplayStream` tolerates and
        // ScreenCaptureKit does not.
        assert_eq!(size_of::<FrameBlock>(), 40);
        assert_eq!(size_of::<BlockDescriptor>(), 24);
        assert_eq!(BLOCK_DESCRIPTOR.0.size, 40);
        assert_eq!(BLOCK_DESCRIPTOR.0.reserved, 0);
        assert_eq!(BLOCK_IS_GLOBAL | BLOCK_HAS_SIGNATURE, 0x5000_0000_u32 as i32);
        assert!(BLOCK_SIGNATURE.ends_with(b"\0"), "a type encoding is a C string");
    }

    #[test]
    fn a_capture_either_starts_or_names_the_state_it_is_in() {
        // Runs against the real machine. Without the Screen Recording grant — which
        // is the expected state right after a rebuild — this must be a *named*
        // refusal carrying the remediation, never a stream of wallpaper.
        match MacCapture::new() {
            Ok(mut capture) => {
                assert!(!capture.monitors().is_empty());
                match capture.next_frame(Duration::from_millis(500)) {
                    Ok(Some(frame)) => {
                        assert!(frame.stride >= frame.width as usize * 4, "the stride is padded");
                        assert!(frame.row(0).is_some());
                    }
                    // A still desktop delivers nothing within the timeout, and a
                    // display being reconfigured asks for a rebuild. Both are
                    // states, and asserting a frame arrives would make this test
                    // fail on an idle machine.
                    Ok(None) | Err(CaptureError::Reinitialise) => {}
                    Err(other) => panic!("capture answered something it should not: {other}"),
                }
            }
            Err(CaptureError::PermissionDenied(grant)) => {
                let sentence = crate::macos::grant::remediation(grant);
                assert!(sentence.contains("System Settings"), "{sentence}");
                assert!(sentence.ends_with('.'));
            }
            Err(CaptureError::NoSession) => {}
            Err(other) => panic!("unexpected refusal: {other}"),
        }
    }
}

