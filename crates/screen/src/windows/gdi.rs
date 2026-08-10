//! GDI screen capture: one reused DIB section, one `BitBlt` per frame.
//!
//! This is the screen source that ships. It is about four hundred lines, uses no
//! COM, and works in desktop configurations that DXGI Desktop Duplication refuses
//! outright — a remote session, a mirrored driver, a machine whose graphics
//! driver has just restarted. Desktop Duplication is faster and reports real
//! dirty rectangles, and the plan is explicit that it is *optional forever*: it is
//! nine hundred lines of hand-bound COM vtables in which a wrong slot index is
//! silent memory corruption rather than a compile error. So the trait is shaped so
//! a second implementation can drop in beside this one ([`crate::Capture`] says
//! nothing about GDI), and until somebody has verified those slot indices against
//! the headers on the machine itself, this is the only implementation there is.
//!
//! # The reuse is the whole performance story
//!
//! The naive version of this file creates a device context, creates a bitmap,
//! blits, reads the bits and destroys all three, once per frame. At 1080p that is
//! an eight-megabyte allocation and two GDI object lifetimes thirty times a
//! second — about a quarter of a gigabyte a second of allocator traffic, plus the
//! kernel's own bookkeeping, to move pixels that could have gone into memory that
//! was already there. It also puts the process's GDI handle count on a sawtooth
//! against a hard per-process quota of 10,000.
//!
//! So the surface is created once and blitted into for as long as it stays valid,
//! and [`Surface`] owns the entire lifetime of the three objects involved. The
//! pixels are handed upward as a borrow of that memory ([`Frame`]), so the encoder
//! reads straight out of the DIB with no copy at all.
//!
//! # What invalidates the surface, and why the answer is always "rebuild"
//!
//! Three things change what a correct frame looks like: the display's resolution,
//! the display topology (a monitor plugged in, unplugged, or rearranged), and the
//! display's DPI. None of them can be handled by continuing to blit into the old
//! surface. The old surface would keep producing frames — the *wrong* frames, at
//! the old size, or of the wrong part of the desktop — and a remote desktop whose
//! picture is quietly stale is a worse failure than one that says it is rebuilding.
//!
//! Every one of them therefore ends in the same place: drop the surface, re-read
//! the layout, and answer [`CaptureError::Reinitialise`], which the session state
//! machine turns into a bounded, backed-off rebuild and a sentence on the console.
//!
//! The check is split in two because the cheap half has to run every frame and the
//! expensive half does not. Four `GetSystemMetrics` calls per frame catch a
//! resolution or topology change immediately; a full re-enumeration — which also
//! re-reads each display's DPI, and which a scale change is otherwise invisible to,
//! because changing 100% to 150% leaves the physical pixel count alone — runs on a
//! timer. See [`TOPOLOGY_POLL`].
//!
//! # States, not errors
//!
//! Before every blit this module asks two questions that have nothing to do with
//! pixels: is the console session still ours, and is the input desktop still the
//! ordinary one. They are asked *first* because the answer when they are not is a
//! **frozen frame** — `BitBlt` against a desktop that is no longer in front
//! succeeds and returns the last thing that was there, or black, and reports
//! nothing. A remote desktop showing a still picture of a screen that has moved on
//! is the single worst failure this subsystem can have, because nothing about it
//! looks like a failure. Naming the state costs one cheap call per frame.

use super::sys::{self, Handle, ScreenDc};
use super::{desktop, InputDesktop};
use crate::{Capture, CaptureError, Fault, Frame};
use selfhost_desk::wire::{Monitor, MAX_MONITORS};
use selfhost_desk::Damage;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// How often the display layout is re-enumerated in full.
///
/// A resolution change is caught within one frame by the cheap metrics check; this
/// timer exists for the changes that leave those metrics identical — most notably
/// a DPI change, which alters what a display should be *labelled* without altering
/// how many pixels it has. Half a second is below the threshold at which an
/// operator would call the console wrong, and is two orders of magnitude less
/// often than a per-frame enumeration would run.
pub const TOPOLOGY_POLL: Duration = Duration::from_millis(500);

/// The largest display edge this build will allocate a surface for.
///
/// Matches `selfhost_desk::tiles::MAX_EDGE`, which is the protocol's own ceiling,
/// so a display bigger than the protocol can describe is refused here rather than
/// producing frames the wire will reject one at a time.
const MAX_EDGE: u32 = 32_768;

/// The cheap per-frame fingerprint of the display layout.
///
/// Four system metrics and a count. Every change that matters to a capture in
/// progress moves at least one of them, except a DPI change — which is what the
/// full re-enumeration on [`TOPOLOGY_POLL`] is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    /// How many displays make up the virtual desktop.
    count: i32,
    /// The virtual desktop's left edge, negative when a display sits left of the
    /// primary.
    x: i32,
    /// Its top edge.
    y: i32,
    /// Its width.
    width: i32,
    /// Its height.
    height: i32,
}

impl Fingerprint {
    /// Reads the current layout fingerprint.
    ///
    /// Never fails: `GetSystemMetrics` has no error channel, and a value we find
    /// implausible is handled where it is used rather than by inventing a fault
    /// this call cannot actually report.
    fn read() -> Self {
        Self {
            count: unsafe { sys::GetSystemMetrics(sys::SM_CMONITORS) },
            x: unsafe { sys::GetSystemMetrics(sys::SM_XVIRTUALSCREEN) },
            y: unsafe { sys::GetSystemMetrics(sys::SM_YVIRTUALSCREEN) },
            width: unsafe { sys::GetSystemMetrics(sys::SM_CXVIRTUALSCREEN) },
            height: unsafe { sys::GetSystemMetrics(sys::SM_CYVIRTUALSCREEN) },
        }
    }
}

/// The reused capture surface: a memory device context with a top-down 32-bit
/// DIB section selected into it.
///
/// The three objects have one owner and one destructor between them, and the
/// destructor's *order* is the reason this is not three separate guard types
/// composed together: a DIB section that is still selected into a device context
/// cannot be deleted, and `DeleteObject` on it fails and leaks rather than
/// complaining. So the bitmap is deselected first, then deleted, then the context
/// is deleted — always, on every path, once.
#[derive(Debug)]
struct Surface {
    /// The memory device context the bitmap is selected into.
    dc: sys::MemoryDc,
    /// The DIB section. Raw rather than a [`sys::GdiObject`] because it must be
    /// deselected before it is destroyed, and the two steps belong together.
    bitmap: Handle,
    /// Whatever the context held before, selected back before the bitmap dies.
    previous: Handle,
    /// The bits, valid until the bitmap is deleted.
    bits: *mut u8,
    /// Width in physical pixels.
    width: u32,
    /// Height in physical pixels.
    height: u32,
}

impl Surface {
    /// Creates a surface for a display of exactly this size.
    ///
    /// # Errors
    ///
    /// A [`Fault`] naming the GDI call that refused. Every one of them is
    /// translated by the caller into [`CaptureError::Reinitialise`] rather than
    /// reported as fatal: the overwhelmingly common cause of a failure here is
    /// that the mode changed again between reading the layout and building the
    /// surface for it, which fixes itself on the next attempt.
    fn create(width: u32, height: u32) -> Result<Self, Fault> {
        // Checked here so that `Surface::pixels` — which builds a slice from this
        // product — can never be handed a length that wrapped.
        usize::try_from(width)
            .ok()
            .and_then(|width| width.checked_mul(usize::try_from(height).ok()?))
            .and_then(|pixels| pixels.checked_mul(4))
            .ok_or_else(|| {
                Fault::refused("CreateDIBSection", format!("{width}×{height} overflows a surface"))
            })?;
        if width == 0 || height == 0 || width > MAX_EDGE || height > MAX_EDGE {
            return Err(Fault::refused(
                "CreateDIBSection",
                format!("{width}×{height} is outside the sizes this build will capture"),
            ));
        }

        let screen = ScreenDc::desktop().ok_or_else(|| Fault::last_os_error("GetDC"))?;
        let dc = sys::MemoryDc::compatible_with(&screen)
            .ok_or_else(|| Fault::last_os_error("CreateCompatibleDC"))?;

        let info = sys::BitmapInfo {
            header: sys::BitmapInfoHeader {
                size: u32::try_from(size_of::<sys::BitmapInfoHeader>()).unwrap_or(40),
                width: i32::try_from(width).unwrap_or(i32::MAX),
                // Negative: top-down. A bottom-up DIB is not an error and is not
                // obviously wrong in a debugger — it is the operator's desktop
                // upside down.
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

        let mut bits: *mut std::ffi::c_void = std::ptr::null_mut();
        let bitmap = unsafe {
            sys::CreateDIBSection(
                screen.raw(),
                &info,
                sys::DIB_RGB_COLORS,
                &mut bits,
                std::ptr::null_mut(),
                0,
            )
        };
        if bitmap.is_null() || bits.is_null() {
            return Err(Fault::last_os_error("CreateDIBSection")
                .noting(format!("{width}×{height}")));
        }

        let previous = unsafe { sys::SelectObject(dc.raw(), bitmap) };
        if previous.is_null() {
            // Nothing owns the bitmap yet, so it is destroyed here rather than by
            // a destructor that would then also try to deselect it.
            unsafe { sys::DeleteObject(bitmap) };
            return Err(Fault::last_os_error("SelectObject"));
        }

        // The kernel promises `width * height * 4` readable bytes behind `bits` for
        // as long as the bitmap lives, which is exactly this value's lifetime.
        Ok(Self { dc, bitmap, previous, bits: bits.cast::<u8>(), width, height })
    }

    /// Whether this surface still describes a display of the given size.
    fn fits(&self, width: u32, height: u32) -> bool {
        self.width == width && self.height == height
    }

    /// Bytes between the starts of consecutive rows.
    ///
    /// Exactly `width * 4` and not an assumption: at 32 bits per pixel every row
    /// is already a whole number of DWORDs, so GDI adds no padding. It is still
    /// carried on the frame rather than recomputed upstream, because the same
    /// [`Frame`] type also describes macOS surfaces where the padding is real.
    fn stride(&self) -> usize {
        self.width as usize * 4
    }

    /// The captured pixels.
    fn pixels(&self) -> &[u8] {
        let len = self.stride() * self.height as usize;
        // Sound: `bits` points at a DIB section of exactly `width * height * 4`
        // bytes that lives as long as `self`, and `&self` excludes a concurrent
        // blit into it because every blit takes `&mut self`.
        unsafe { std::slice::from_raw_parts(self.bits, len) }
    }

    /// Copies the given region of the virtual desktop into this surface.
    ///
    /// `origin` is in virtual-desktop pixels and is signed, because a display left
    /// of or above the primary has a negative origin and the blit reads from the
    /// desktop's own coordinate space.
    fn blit(&mut self, origin: (i32, i32)) -> Result<(), Fault> {
        let screen = ScreenDc::desktop().ok_or_else(|| Fault::last_os_error("GetDC"))?;
        let ok = unsafe {
            sys::BitBlt(
                self.dc.raw(),
                0,
                0,
                i32::try_from(self.width).unwrap_or(i32::MAX),
                i32::try_from(self.height).unwrap_or(i32::MAX),
                screen.raw(),
                origin.0,
                origin.1,
                // CAPTUREBLT or every layered window on the desktop — which on a
                // modern Windows means most of the shell — comes out as a hole.
                sys::SRCCOPY | sys::CAPTUREBLT,
            )
        };
        if ok == 0 {
            return Err(Fault::last_os_error("BitBlt"));
        }
        Ok(())
    }
}

impl Drop for Surface {
    fn drop(&mut self) {
        // Order is load-bearing: a selected DIB section cannot be deleted, and the
        // failure is silent.
        unsafe {
            sys::SelectObject(self.dc.raw(), self.previous);
            sys::DeleteObject(self.bitmap);
        }
        // `self.dc` deletes itself immediately after this, which is the required
        // order and is why it is the only one of the three left to a destructor.
    }
}

/// The GDI screen source.
///
/// Captures **one display at a time**. Multi-monitor is expressed by choosing
/// which display to capture ([`GdiCapture::select`]) rather than by blitting the
/// whole virtual desktop into one surface: a viewer looks at one screen, and the
/// bounding box of two displays that are not the same height contains dead area
/// that would be encoded, sent and diffed forever.
#[derive(Debug)]
pub struct GdiCapture {
    /// Every display, in enumeration order, as the protocol describes them.
    monitors: Vec<Monitor>,
    /// Which of them is being captured, by [`Monitor::id`].
    target: u8,
    /// The reused surface, absent until the first frame and after every rebuild.
    surface: Option<Surface>,
    /// The cheap layout fingerprint, compared every frame.
    fingerprint: Fingerprint,
    /// When the layout was last re-enumerated in full.
    enumerated_at: Instant,
    /// The session this agent belongs to, so that a fast user switch is noticed
    /// from inside the session rather than only by the daemon.
    session: u32,
    /// A monotonically increasing frame number.
    sequence: u64,
    /// The last platform failure, for the diagnostics plate. Kept rather than
    /// returned because the states it accompanies are recoverable and the console
    /// shows the state, not the error number.
    last_fault: Option<Fault>,
}

impl GdiCapture {
    /// Builds a screen source for this session's displays.
    ///
    /// # Errors
    ///
    /// [`CaptureError::SessionDisconnected`] when the session has no displays at
    /// all, which is what a disconnected remote session and a session that has
    /// been switched away from both look like from inside. It is deliberately not
    /// a fault: the session comes back, and the state machine polls a suspension
    /// forever where it gives up on a fault after a bounded number of rebuilds.
    pub fn new() -> Result<Self, CaptureError> {
        let monitors = monitors()?;
        let target = monitors
            .iter()
            .find(|monitor| monitor.primary)
            .or_else(|| monitors.first())
            .map(|monitor| monitor.id)
            .ok_or(CaptureError::SessionDisconnected)?;
        Ok(Self {
            monitors,
            target,
            surface: None,
            fingerprint: Fingerprint::read(),
            enumerated_at: Instant::now(),
            session: current_session().unwrap_or(u32::MAX),
            sequence: 0,
            last_fault: None,
        })
    }

    /// Which display is being captured.
    pub fn target(&self) -> u8 {
        self.target
    }

    /// Captures a different display from the next frame on.
    ///
    /// Answers `false` for a display that does not exist, rather than switching to
    /// nothing: a viewer asking for a monitor that has just been unplugged should
    /// keep seeing the one it has.
    pub fn select(&mut self, monitor: u8) -> bool {
        if !self.monitors.iter().any(|candidate| candidate.id == monitor) {
            return false;
        }
        if self.target != monitor {
            self.target = monitor;
            // The new display is almost certainly a different size, and even when
            // it is not, the old surface holds the old display's pixels.
            self.surface = None;
        }
        true
    }

    /// The last platform failure, for the diagnostics plate.
    pub fn last_fault(&self) -> Option<&Fault> {
        self.last_fault.as_ref()
    }

    /// Answers the state the session is in, when it is not one that can be
    /// captured.
    ///
    /// Asked **before** the blit, every frame, because the failure mode this
    /// prevents is a frozen picture rather than an error: `BitBlt` against a
    /// desktop that is no longer in front succeeds and hands back stale or black
    /// pixels without reporting anything at all.
    fn capturable(&self) -> Result<(), CaptureError> {
        // A fast user switch, or an RDP connection taking the console away. Asked
        // first because it is a single cheap call and it explains the other one.
        if self.session != u32::MAX {
            let console = unsafe { sys::WTSGetActiveConsoleSessionId() };
            if console != sys::NO_ACTIVE_SESSION && console != self.session {
                return Err(CaptureError::SessionDisconnected);
            }
        }
        // The secure desktop: a UAC consent prompt, the lock screen, or the
        // credential provider. All three are the same answer — this session
        // deliberately cannot see or drive any of them — and the console renders
        // the sentence attached to the variant.
        match desktop::input_desktop() {
            Ok(InputDesktop::Default) => Ok(()),
            Ok(InputDesktop::Secure | InputDesktop::ScreenSaver) => Err(CaptureError::SecureDesktop),
            // A desktop we do not recognise is one we must not blit: an unnamed
            // desktop in front means something took over the input, and capturing
            // the one behind it would show a picture of a screen nobody is
            // looking at.
            Ok(InputDesktop::Other(_)) => Err(CaptureError::SecureDesktop),
            Err(fault) => Err(CaptureError::Fatal(fault)),
        }
    }

    /// Re-reads the display layout when anything about it has changed.
    ///
    /// Answers `Ok(true)` when the caller must treat the source as rebuilt.
    fn layout_changed(&mut self, now: Instant) -> Result<bool, CaptureError> {
        let fingerprint = Fingerprint::read();
        let due = now.saturating_duration_since(self.enumerated_at) >= TOPOLOGY_POLL;
        if fingerprint == self.fingerprint && !due {
            return Ok(false);
        }

        self.fingerprint = fingerprint;
        self.enumerated_at = now;
        let refreshed = monitors()?;
        if refreshed == self.monitors {
            return Ok(false);
        }

        // A display was added, removed, moved, resized or rescaled. Everything
        // downstream — the surface, the client's tile grid, the coordinate
        // mapping — is built on the old answer, so the honest response is to
        // rebuild rather than to patch.
        self.monitors = refreshed;
        self.surface = None;
        if !self.monitors.iter().any(|monitor| monitor.id == self.target) {
            self.target = self
                .monitors
                .iter()
                .find(|monitor| monitor.primary)
                .or_else(|| self.monitors.first())
                .map(|monitor| monitor.id)
                .ok_or(CaptureError::SessionDisconnected)?;
        }
        Ok(true)
    }

    /// The display being captured, as the protocol describes it.
    fn target_monitor(&self) -> Result<Monitor, CaptureError> {
        self.monitors
            .iter()
            .find(|monitor| monitor.id == self.target)
            .copied()
            .ok_or(CaptureError::Reinitialise)
    }
}

impl Capture for GdiCapture {
    fn monitors(&self) -> &[Monitor] {
        &self.monitors
    }

    /// The next frame.
    ///
    /// `timeout` is accepted and not waited on, and that is not an oversight: GDI
    /// has no way to block until the screen changes. There is nothing to wait
    /// *for* — every call blits the desktop as it is now — so the pacing belongs
    /// to the caller, which is where the frame-rate ceiling and the credit window
    /// already live. Answering immediately keeps this source honest about what it
    /// can do rather than sleeping to look like one that can.
    ///
    /// The damage is always empty, meaning "assume everything is new". The tile
    /// diff in `selfhost_desk::tiles` recovers the real damage by comparing this
    /// frame with what the client is holding, which is where a still desktop's
    /// near-zero cost comes from.
    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame<'_>>, CaptureError> {
        if self.layout_changed(Instant::now())? {
            return Err(CaptureError::Reinitialise);
        }
        self.capturable()?;

        let monitor = self.target_monitor()?;
        if !self.surface.as_ref().is_some_and(|s| s.fits(monitor.width, monitor.height)) {
            match Surface::create(monitor.width, monitor.height) {
                Ok(surface) => self.surface = Some(surface),
                Err(fault) => {
                    self.last_fault = Some(fault);
                    return Err(CaptureError::Reinitialise);
                }
            }
        }

        let surface = self.surface.as_mut().ok_or(CaptureError::Reinitialise)?;
        if let Err(fault) = surface.blit((monitor.origin_x, monitor.origin_y)) {
            // A blit failure is nearly always a mode or desktop change that
            // happened between the checks above and this call. Rebuilding is both
            // the right answer and a bounded one; the fault is kept for the
            // diagnostics plate so a driver that fails repeatedly is visible.
            self.last_fault = Some(fault);
            self.surface = None;
            return Err(CaptureError::Reinitialise);
        }

        self.sequence = self.sequence.saturating_add(1);
        let surface = self.surface.as_ref().ok_or(CaptureError::Reinitialise)?;
        Ok(Some(Frame {
            monitor: monitor.id,
            sequence: self.sequence,
            width: surface.width,
            height: surface.height,
            stride: surface.stride(),
            pixels: surface.pixels(),
            damage: Damage::default(),
        }))
    }
}

/// This process's session id.
///
/// `None` when Windows will not say, in which case the caller stops comparing
/// rather than guessing: a wrong comparison would suspend a perfectly live
/// session forever, which is worse than not noticing a user switch that the
/// desktop check will notice a moment later anyway.
pub fn current_session() -> Option<u32> {
    let mut session: u32 = 0;
    let ok = unsafe { sys::ProcessIdToSessionId(sys::GetCurrentProcessId(), &mut session) };
    (ok != 0).then_some(session)
}

/// Every display attached to this session, as the protocol describes them.
///
/// Ids are assigned by enumeration order and are stable only for as long as the
/// layout is: plugging a monitor in renumbers them, which is exactly why a layout
/// change is a rebuild and a fresh `HELLO` rather than an update to the old one.
///
/// # Errors
///
/// [`CaptureError::SessionDisconnected`] when there are no displays. That is what
/// a session which has been switched away from, or a disconnected remote session,
/// looks like from inside — and it is a state that ends by itself, so it is
/// reported as one rather than as a failure that burns a rebuild budget.
pub fn monitors() -> Result<Vec<Monitor>, CaptureError> {
    let mut handles: Vec<Handle> = Vec::new();
    let ok = unsafe {
        sys::EnumDisplayMonitors(
            std::ptr::null_mut(),
            std::ptr::null(),
            collect_monitor,
            std::ptr::from_mut(&mut handles) as isize,
        )
    };
    if ok == 0 && handles.is_empty() {
        return Err(CaptureError::Fatal(Fault::last_os_error("EnumDisplayMonitors")));
    }

    let dpi = dpi_query();
    let mut monitors = Vec::with_capacity(handles.len().min(MAX_MONITORS));
    for (index, handle) in handles.into_iter().enumerate() {
        // The protocol addresses displays with a single byte and carries at most
        // sixteen of them. A machine with more is captured on the first sixteen
        // rather than refused: seventeen displays is not a reason to be unable to
        // see the first one.
        let Ok(id) = u8::try_from(index) else { break };
        if monitors.len() >= MAX_MONITORS {
            break;
        }
        if let Some(monitor) = describe(handle, id, dpi) {
            monitors.push(monitor);
        }
    }

    if monitors.is_empty() {
        return Err(CaptureError::SessionDisconnected);
    }
    Ok(monitors)
}

/// The `EnumDisplayMonitors` callback: collects handles and decides nothing.
///
/// # Safety
///
/// Invoked by Windows on our own thread, inside our own call, with `data` being
/// the `&mut Vec<Handle>` that call passed. Kept to a push so that there is no
/// path through it that can fail — a callback that can fail has nowhere to report
/// it, and under `panic = "abort"` a callback that panics ends the process.
unsafe extern "system" fn collect_monitor(
    monitor: Handle,
    _dc: Handle,
    _rect: *mut sys::Rect,
    data: isize,
) -> sys::Bool {
    if data == 0 || monitor.is_null() {
        return 1;
    }
    let handles = unsafe { &mut *(data as *mut Vec<Handle>) };
    if handles.len() < MAX_MONITORS {
        handles.push(monitor);
    }
    1
}

/// Describes one display, or `None` when Windows will not.
///
/// A display that cannot be described is skipped rather than failing the whole
/// enumeration: one unreadable display out of three should cost the operator that
/// display, not the session.
fn describe(handle: Handle, id: u8, dpi: Option<sys::GetDpiForMonitorFn>) -> Option<Monitor> {
    let mut info = sys::MonitorInfoExW {
        cb_size: u32::try_from(size_of::<sys::MonitorInfoExW>()).unwrap_or(104),
        monitor: sys::Rect::default(),
        work: sys::Rect::default(),
        flags: 0,
        device: [0; 32],
    };
    if unsafe { sys::GetMonitorInfoW(handle, &mut info) } == 0 {
        return None;
    }

    let width = u32::try_from(i64::from(info.monitor.right) - i64::from(info.monitor.left)).ok()?;
    let height = u32::try_from(i64::from(info.monitor.bottom) - i64::from(info.monitor.top)).ok()?;
    if width == 0 || height == 0 || width > MAX_EDGE || height > MAX_EDGE {
        return None;
    }

    Some(Monitor {
        id,
        origin_x: info.monitor.left,
        origin_y: info.monitor.top,
        width,
        height,
        scale_permille: scale_permille(handle, dpi),
        primary: info.flags & sys::MONITORINFOF_PRIMARY != 0,
    })
}

/// A display's scale factor in thousandths — 1500 for Windows at 150%.
///
/// Sent so a console can *label* a display, never so it can compute coordinates:
/// every coordinate in this subsystem is a physical pixel, which is the whole
/// reason the agent declares per-monitor DPI awareness before it does anything
/// else. A machine too old to answer the question is reported at 100%, which is
/// what it would have been before per-monitor scaling existed.
fn scale_permille(handle: Handle, dpi: Option<sys::GetDpiForMonitorFn>) -> u16 {
    let Some(query) = dpi else { return 1000 };
    let (mut x, mut y) = (0u32, 0u32);
    let result = unsafe { query(handle, sys::MDT_EFFECTIVE_DPI, &mut x, &mut y) };
    if result != 0 || x == 0 {
        return 1000;
    }
    let permille = u64::from(x) * 1000 / u64::from(sys::USER_DEFAULT_SCREEN_DPI);
    u16::try_from(permille).unwrap_or(u16::MAX)
}

/// `GetDpiForMonitor`, resolved once for the life of the process.
///
/// Resolved rather than imported because `shcore` needs an import library this
/// workspace does not carry, and because a statically imported symbol that is
/// missing stops the process from starting — on Windows 8 that would be an agent
/// that fails to launch with a loader error naming a DPI function.
fn dpi_query() -> Option<sys::GetDpiForMonitorFn> {
    static RESOLVED: OnceLock<Option<sys::GetDpiForMonitorFn>> = OnceLock::new();
    *RESOLVED.get_or_init(|| unsafe {
        sys::optional_export::<sys::GetDpiForMonitorFn>("shcore.dll", b"GetDpiForMonitor\0")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_layout_fingerprint_compares_by_value() {
        // The per-frame change check is an equality test on this structure, so it
        // has to be a value type with no interior state.
        let one = Fingerprint { count: 2, x: -1920, y: 0, width: 3840, height: 1080 };
        let same = Fingerprint { count: 2, x: -1920, y: 0, width: 3840, height: 1080 };
        let moved = Fingerprint { x: 0, ..one };
        assert_eq!(one, same);
        assert_ne!(one, moved);
    }
}
