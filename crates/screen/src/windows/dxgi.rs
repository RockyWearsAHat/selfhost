//! DXGI Desktop Duplication: the screen source that can see a game.
//!
//! # Why this exists, when [`super::gdi`] already worked
//!
//! `BitBlt` reads the desktop through GDI, and a Direct3D application does not
//! draw its pixels there. A full-screen game presents a swap chain straight to the
//! display, so what GDI hands back for that region is **black** — not stale, not
//! an error, not a state anything can report. On ALEX-DESKTOP that was a viewer
//! showing a thin strip of Windows-drawn menu chrome above a black rectangle where
//! the game was, while the stream itself was in perfect health: 707 frames and
//! 28.8 MB across one session, every byte of it a faithful copy of black.
//!
//! Desktop Duplication reads the *composited output* — the same surface the
//! display controller scans out — so it sees whatever the screen shows, including
//! Direct3D, OpenGL and Vulkan. That is the whole reason for this file.
//!
//! # What it costs, and why the GDI source stays
//!
//! Duplication is not available everywhere. A machine with no Direct3D 11, an
//! output already duplicated by another program, a remote session, a mirrored
//! driver — each answers with its own `HRESULT`, and each of them is a machine
//! where the old source works fine. So this is a *second* implementation of
//! [`Capture`], chosen at startup by [`super::capture::WindowsCapture`], and every
//! condition below that means "not on this machine" is reported as such rather
//! than as a failure. Nothing that was working stops working because this file
//! exists.
//!
//! # The frame path, and where the copy is
//!
//! `AcquireNextFrame` hands over a GPU texture. GPU memory is not readable by the
//! CPU, so the frame is copied — on the GPU, by `CopyResource` — into a *staging*
//! texture created with `D3D11_USAGE_STAGING` and `D3D11_CPU_ACCESS_READ`, which is
//! then mapped into this process's address space. That mapping is what the encoder
//! reads, with no second copy: [`Frame::pixels`] borrows the driver's own memory
//! for as long as the borrow of `self` lasts, and the map is released at the top of
//! the *next* call. `row_pitch` is the driver's, not `width * 4`, which is exactly
//! what [`Frame::stride`] exists to carry.
//!
//! # Two answers that are not frames
//!
//! - **A timeout.** `AcquireNextFrame` waits for the desktop to change and answers
//!   `DXGI_ERROR_WAIT_TIMEOUT` when it does not. That is `Ok(None)`, and a still
//!   desktop produces it forever at no cost — the thing GDI could never do, since
//!   GDI has nothing to wait on and re-blits an unchanged screen thirty times a
//!   second.
//! - **A pointer-only update.** An acquire whose `last_present_time` is zero
//!   carries no new desktop image; the pointer moved, and the pointer is captured
//!   separately by [`super::cursor`]. The frame is released and `Ok(None)`
//!   answered, so a moving mouse over a still screen encodes nothing.
//!
//! Both must still `ReleaseFrame`. An acquire that is not released is answered by
//! `DXGI_ERROR_INVALID_CALL` on the next one, forever, which is why the release
//! lives in [`Duplication::release`] and is called on every path out.
//!
//! # What it still cannot see
//!
//! Protected content — a DRM video path — is blacked out of the duplicated frame
//! by the display driver itself, and `protected_content_masked_out` says so. This
//! module reports the fact rather than hiding it, because a black rectangle with no
//! explanation is the failure this whole file was written to end.

use super::sys::{self, Hresult, Unknown};
use crate::fault::Fault;
use crate::{Capture, CaptureError, Frame, Monitor};
use selfhost_desk::tiles::Damage;
use std::ffi::c_void;
use std::time::{Duration, Instant};

use super::InputDesktop;
use super::desktop;
use super::gdi::{TOPOLOGY_POLL, current_session, monitors};

/// An owned COM interface pointer.
///
/// The reference counting is written once, here, rather than at each of the eight
/// places an interface is obtained: every one of them is released exactly once, on
/// drop, in the reverse order of acquisition, because that is what `Drop` gives for
/// free and what hand-written release paths get wrong the moment an early return is
/// added between the acquire and the release.
#[derive(Debug)]
struct Com {
    /// The interface. Never null while this value exists.
    pointer: *mut Unknown,
}

impl Com {
    /// Takes ownership of an interface a call has just produced.
    ///
    /// Answers `None` for null, which several COM calls return alongside `S_OK`
    /// when they have nothing to give.
    fn own(pointer: *mut Unknown) -> Option<Self> {
        if pointer.is_null() { None } else { Some(Self { pointer }) }
    }

    /// The raw pointer, for passing to a method that takes an interface.
    fn as_ptr(&self) -> *mut Unknown {
        self.pointer
    }

    /// The vtable, viewed as the interface this pointer is known to be.
    ///
    /// # Safety
    ///
    /// `V` must be the vtable type of the interface this pointer actually is. Every
    /// caller obtained the pointer from a call whose declared out-parameter is that
    /// interface, or from [`Self::query`] with that interface's own IID.
    unsafe fn vtable<V>(&self) -> &V {
        // The first word of any COM object is its vtable pointer; `Unknown` is
        // declared as exactly that, so this is a read of a field and not a guess.
        unsafe { &*(*self.pointer).vtable.cast::<V>() }
    }

    /// `QueryInterface`, as an owned pointer to the requested interface.
    fn query(&self, iid: &sys::Guid, call: &'static str) -> Result<Self, Fault> {
        let mut out: *mut c_void = std::ptr::null_mut();
        // Sound: `query_interface` is slot 0 of every COM interface there is.
        let result = unsafe {
            let vtable = self.vtable::<sys::UnknownVtbl>();
            (vtable.query_interface)(self.pointer, iid, &raw mut out)
        };
        if result != sys::S_OK {
            return Err(hresult(call, result));
        }
        Com::own(out.cast::<Unknown>())
            .ok_or_else(|| Fault::refused(call, "succeeded and handed back a null interface"))
    }
}

impl Drop for Com {
    fn drop(&mut self) {
        // Sound: `release` is slot 2 of every COM interface, and this type is the
        // only owner of the reference it is giving up.
        unsafe {
            let vtable = self.vtable::<sys::UnknownVtbl>();
            (vtable.release)(self.pointer);
        }
    }
}

/// A `HRESULT` that failed, as a [`Fault`] whose sentence a person can act on.
///
/// The code is rendered as hexadecimal rather than through the operating system's
/// error strings, because a `HRESULT` is not a `GetLastError` value and asking
/// Windows to describe `0x887A0022` as though it were one produces a sentence about
/// a completely different failure.
fn hresult(call: &'static str, code: Hresult) -> Fault {
    let described = match code {
        sys::E_ACCESSDENIED => " (the secure desktop is in front)",
        sys::DXGI_ERROR_INVALID_CALL => " (a frame was acquired without releasing the last one)",
        sys::DXGI_ERROR_UNSUPPORTED => " (this adapter cannot duplicate an output)",
        sys::DXGI_ERROR_DEVICE_REMOVED | sys::DXGI_ERROR_DEVICE_RESET => {
            " (the graphics driver restarted)"
        }
        sys::DXGI_ERROR_NOT_CURRENTLY_AVAILABLE => {
            " (every duplication slot on this output is taken)"
        }
        sys::DXGI_ERROR_ACCESS_LOST => " (the duplication was invalidated)",
        sys::DXGI_ERROR_SESSION_DISCONNECTED => " (this session left the console)",
        _ => "",
    };
    Fault::refused(call, format!("HRESULT 0x{:08x}{described}", code as u32))
}

/// Turns a `HRESULT` into the state it means, for the conditions that are states.
///
/// Written as one function because the same handful of codes arrive from three
/// different calls and must mean the same thing at each: a condition that is a
/// rebuild at `DuplicateOutput` and a fatal fault at `AcquireNextFrame` is how a
/// recoverable machine becomes a session that never comes back.
fn condition(call: &'static str, code: Hresult) -> CaptureError {
    match code {
        // The duplication is void. Every one of these is repaired by building it
        // again, which is what `Reinitialise` asks the state machine to do.
        sys::DXGI_ERROR_ACCESS_LOST
        | sys::DXGI_ERROR_DEVICE_REMOVED
        | sys::DXGI_ERROR_DEVICE_RESET
        | sys::DXGI_ERROR_INVALID_CALL => CaptureError::Reinitialise,
        // Somebody else holds the slot. Recoverable without a restart the moment
        // they let go, and the vocabulary already has a word for it.
        sys::DXGI_ERROR_NOT_CURRENTLY_AVAILABLE => CaptureError::TooManyDuplications,
        // The secure desktop. Never captured, by design rather than by inability.
        sys::E_ACCESSDENIED => CaptureError::SecureDesktop,
        sys::DXGI_ERROR_SESSION_DISCONNECTED => CaptureError::SessionDisconnected,
        other => CaptureError::Fatal(hresult(call, other)),
    }
}

/// The Direct3D device, its immediate context, and the staging texture they fill.
///
/// One object because the three have exactly one lifetime between them: the
/// staging texture belongs to the device, the context is how anything reaches
/// either, and a driver restart takes all three at once.
#[derive(Debug)]
struct Device {
    /// `ID3D11Device`.
    device: Com,
    /// `ID3D11DeviceContext`, the immediate one.
    context: Com,
    /// The CPU-readable copy target, and the size it was made for.
    staging: Option<(Com, u32, u32)>,
}

impl Device {
    /// Creates a hardware Direct3D 11 device, or says why this machine has none.
    fn open() -> Result<Self, CaptureError> {
        // Resolved at run time: a machine with no `d3d11.dll` must keep its GDI
        // capture, not fail to start.
        let create: sys::D3d11CreateDeviceFn =
            // Sound: the signature is the declared `D3d11CreateDeviceFn` and
            // nothing constructed at this call site.
            unsafe { sys::optional_export("d3d11.dll", b"D3D11CreateDevice\0") }.ok_or(
                CaptureError::Unsupported { platform: "windows without Direct3D 11" },
            )?;

        let mut device: *mut Unknown = std::ptr::null_mut();
        let mut context: *mut Unknown = std::ptr::null_mut();
        let mut level: u32 = 0;
        // Sound: every pointer is either null (meaning "the default"), or an
        // out-parameter this stack frame owns for the duration of the call.
        let result = unsafe {
            create(
                // A null adapter takes the default one, which is the adapter the
                // desktop is on for every single-GPU machine. See `duplicate`.
                std::ptr::null_mut(),
                sys::D3D_DRIVER_TYPE_HARDWARE,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
                0,
                sys::D3D11_SDK_VERSION,
                &raw mut device,
                &raw mut level,
                &raw mut context,
            )
        };
        if result != sys::S_OK {
            return Err(match result {
                // No Direct3D 11 hardware at all. A state of the machine, and the
                // reason the GDI source is still in the build.
                sys::DXGI_ERROR_UNSUPPORTED => {
                    CaptureError::Unsupported { platform: "windows without a Direct3D 11 adapter" }
                }
                other => condition("D3D11CreateDevice", other),
            });
        }
        let (Some(device), Some(context)) = (Com::own(device), Com::own(context)) else {
            return Err(CaptureError::Fatal(Fault::refused(
                "D3D11CreateDevice",
                "succeeded without producing a device and a context",
            )));
        };
        Ok(Self { device, context, staging: None })
    }

    /// The staging texture for a display of this size, creating it if needed.
    fn staging(&mut self, width: u32, height: u32) -> Result<&Com, CaptureError> {
        if !matches!(self.staging, Some((_, have_width, have_height))
            if have_width == width && have_height == height)
        {
            let desc = sys::D3d11Texture2dDesc {
                width,
                height,
                mip_levels: 1,
                array_size: 1,
                format: sys::DXGI_FORMAT_B8G8R8A8_UNORM,
                sample_desc: sys::DxgiSampleDesc { count: 1, quality: 0 },
                usage: sys::D3D11_USAGE_STAGING,
                // Never bound to the pipeline: this surface exists to be copied
                // into and read out of, and a bind flag on a staging resource is
                // refused outright.
                bind_flags: 0,
                cpu_access_flags: sys::D3D11_CPU_ACCESS_READ,
                misc_flags: 0,
            };
            let mut texture: *mut Unknown = std::ptr::null_mut();
            // Sound: `create_texture_2d` is slot 5 of `ID3D11Device`, `desc` is a
            // fully initialised structure of the declared type, and the initial
            // data is legitimately absent.
            let result = unsafe {
                let vtable = self.device.vtable::<sys::D3d11DeviceVtbl>();
                (vtable.create_texture_2d)(
                    self.device.as_ptr(),
                    &raw const desc,
                    std::ptr::null(),
                    &raw mut texture,
                )
            };
            if result != sys::S_OK {
                return Err(condition("ID3D11Device::CreateTexture2D", result));
            }
            let texture = Com::own(texture).ok_or_else(|| {
                CaptureError::Fatal(Fault::refused(
                    "ID3D11Device::CreateTexture2D",
                    "succeeded and handed back a null texture",
                ))
            })?;
            self.staging = Some((texture, width, height));
        }
        let (texture, _, _) = self.staging.as_ref().ok_or(CaptureError::Reinitialise)?;
        Ok(texture)
    }
}

/// One output's duplication, and the frame it may currently be holding.
#[derive(Debug)]
struct Duplication {
    /// `IDXGIOutputDuplication`.
    interface: Com,
    /// Whether a frame is acquired and therefore owed a release.
    holding: bool,
}

impl Duplication {
    /// Releases the acquired frame, if there is one.
    ///
    /// Idempotent, and called on every path out of an acquire — including the
    /// failing ones, because a frame that was handed over and not released makes
    /// every later acquire answer `DXGI_ERROR_INVALID_CALL` for as long as the
    /// duplication lives.
    fn release(&mut self) {
        if !self.holding {
            return;
        }
        self.holding = false;
        // Sound: `release_frame` is slot 14 of `IDXGIOutputDuplication`. Its own
        // failure is not actionable — there is nothing to retry and nothing to
        // tell the operator — so the state is cleared either way.
        unsafe {
            let vtable = self.interface.vtable::<sys::DxgiOutputDuplicationVtbl>();
            (vtable.release_frame)(self.interface.as_ptr());
        }
    }
}

impl Drop for Duplication {
    fn drop(&mut self) {
        self.release();
    }
}

/// A screen source that reads the composited output.
///
/// Captures **one display at a time**, for the reason [`super::gdi::GdiCapture`]
/// gives: a viewer looks at one screen, and a duplication is per output anyway.
#[derive(Debug)]
pub struct DxgiCapture {
    /// Every display, in enumeration order, as the protocol describes them.
    monitors: Vec<Monitor>,
    /// Which of them is being captured, by [`Monitor::id`].
    target: u8,
    /// The device, context and staging texture.
    device: Device,
    /// The duplication for [`Self::target`], absent until the first frame.
    duplication: Option<Duplication>,
    /// Whether the staging texture is currently mapped, and must be unmapped
    /// before anything else touches it.
    mapped: bool,
    /// When the display layout was last re-enumerated.
    enumerated_at: Instant,
    /// The session this agent belongs to.
    session: u32,
    /// A monotonically increasing frame number.
    sequence: u64,
    /// The last platform failure, for the diagnostics plate.
    last_fault: Option<Fault>,
}

impl DxgiCapture {
    /// Builds a duplication-backed screen source, or says why this machine cannot
    /// have one.
    ///
    /// # Errors
    ///
    /// [`CaptureError::Unsupported`] when there is no Direct3D 11 to build on, and
    /// [`CaptureError::TooManyDuplications`] when another program holds the output.
    /// Both are answers the caller turns into "use GDI", never into a dead session;
    /// see [`super::capture::WindowsCapture::open`].
    pub fn new() -> Result<Self, CaptureError> {
        let monitors = monitors()?;
        let target = monitors
            .iter()
            .find(|monitor| monitor.primary)
            .or_else(|| monitors.first())
            .map(|monitor| monitor.id)
            .ok_or(CaptureError::SessionDisconnected)?;
        let mut capture = Self {
            monitors,
            target,
            device: Device::open()?,
            duplication: None,
            mapped: false,
            enumerated_at: Instant::now(),
            session: current_session().unwrap_or(u32::MAX),
            sequence: 0,
            last_fault: None,
        };
        // Built here rather than lazily, because "this machine cannot duplicate"
        // must be known while the caller can still choose the other source. A
        // duplication that first fails three frames into a live session is a
        // broken session; one that fails here is a line in the log and a GDI
        // capture.
        capture.duplicate()?;
        Ok(capture)
    }

    /// Which display is being captured.
    pub fn target(&self) -> u8 {
        self.target
    }

    /// Captures a different display from the next frame on.
    ///
    /// Answers `false` for a display that does not exist, matching
    /// [`super::gdi::GdiCapture::select`]: a viewer asking for a monitor that has
    /// just been unplugged keeps seeing the one it has.
    pub fn select(&mut self, monitor: u8) -> bool {
        if !self.monitors.iter().any(|candidate| candidate.id == monitor) {
            return false;
        }
        if self.target != monitor {
            self.target = monitor;
            // A duplication belongs to one output, and the staging texture is
            // almost certainly the wrong size for the new one.
            self.unmap();
            self.duplication = None;
            self.device.staging = None;
        }
        true
    }

    /// The last platform failure, for the diagnostics plate.
    pub fn last_fault(&self) -> Option<&Fault> {
        self.last_fault.as_ref()
    }

    /// Releases the mapping held over the staging texture, if any.
    fn unmap(&mut self) {
        if !self.mapped {
            return;
        }
        self.mapped = false;
        let Some((texture, _, _)) = self.device.staging.as_ref() else {
            return;
        };
        // Sound: `unmap` is slot 15 of `ID3D11DeviceContext`, and the resource is
        // the one this type mapped and has not dropped.
        unsafe {
            let vtable = self.device.context.vtable::<sys::D3d11DeviceContextVtbl>();
            (vtable.unmap)(self.device.context.as_ptr(), texture.as_ptr(), 0);
        }
    }

    /// Finds the DXGI output that covers the display being captured, and starts
    /// duplicating it.
    ///
    /// # How an output is matched to a display
    ///
    /// By its place on the virtual desktop, not by its name or its index. The
    /// enumeration order of `EnumOutputs` and of `EnumDisplayMonitors` are two
    /// independent orderings that agree on most machines and not on all, and a
    /// viewer that silently shows the *other* monitor is a failure nobody reports
    /// as one. `DesktopCoordinates` is the same rectangle
    /// [`super::gdi::monitors`] read, so the comparison is exact.
    fn duplicate(&mut self) -> Result<(), CaptureError> {
        let monitor = self.target_monitor()?;
        let device = self
            .device
            .device
            .query(&sys::IID_IDXGI_DEVICE, "ID3D11Device::QueryInterface(IDXGIDevice)")
            .map_err(CaptureError::Fatal)?;

        let mut adapter: *mut Unknown = std::ptr::null_mut();
        // Sound: `get_adapter` is slot 7 of `IDXGIDevice`.
        let result = unsafe {
            let vtable = device.vtable::<sys::DxgiDeviceVtbl>();
            (vtable.get_adapter)(device.as_ptr(), &raw mut adapter)
        };
        if result != sys::S_OK {
            return Err(condition("IDXGIDevice::GetAdapter", result));
        }
        let adapter = Com::own(adapter).ok_or_else(|| {
            CaptureError::Fatal(Fault::refused(
                "IDXGIDevice::GetAdapter",
                "succeeded and handed back a null adapter",
            ))
        })?;

        for index in 0u32.. {
            let mut output: *mut Unknown = std::ptr::null_mut();
            // Sound: `enum_outputs` is slot 7 of `IDXGIAdapter`.
            let result = unsafe {
                let vtable = adapter.vtable::<sys::DxgiAdapterVtbl>();
                (vtable.enum_outputs)(adapter.as_ptr(), index, &raw mut output)
            };
            if result == sys::DXGI_ERROR_NOT_FOUND {
                break;
            }
            if result != sys::S_OK {
                return Err(condition("IDXGIAdapter::EnumOutputs", result));
            }
            let Some(output) = Com::own(output) else {
                continue;
            };
            let output = output
                .query(&sys::IID_IDXGI_OUTPUT1, "IDXGIOutput::QueryInterface(IDXGIOutput1)")
                .map_err(CaptureError::Fatal)?;

            let mut desc = sys::DxgiOutputDesc {
                device_name: [0; 32],
                desktop_coordinates: sys::Rect::default(),
                attached_to_desktop: 0,
                rotation: 0,
                monitor: std::ptr::null_mut(),
            };
            // Sound: `get_desc` is slot 7 of `IDXGIOutput1`, and `desc` is a fully
            // initialised structure of the declared type.
            let result = unsafe {
                let vtable = output.vtable::<sys::DxgiOutput1Vtbl>();
                (vtable.get_desc)(output.as_ptr(), &raw mut desc)
            };
            if result != sys::S_OK {
                return Err(condition("IDXGIOutput1::GetDesc", result));
            }
            if desc.attached_to_desktop == 0 || !covers(&desc, &monitor) {
                continue;
            }

            let mut duplication: *mut Unknown = std::ptr::null_mut();
            // Sound: `duplicate_output` is slot 22 of `IDXGIOutput1`, and the
            // device passed is the one this duplication will be read through.
            let result = unsafe {
                let vtable = output.vtable::<sys::DxgiOutput1Vtbl>();
                (vtable.duplicate_output)(
                    output.as_ptr(),
                    self.device.device.as_ptr(),
                    &raw mut duplication,
                )
            };
            if result != sys::S_OK {
                let fault = hresult("IDXGIOutput1::DuplicateOutput", result);
                self.last_fault = Some(fault);
                return Err(match result {
                    // No duplication on this adapter, ever. Not a rebuild — a
                    // different source.
                    sys::DXGI_ERROR_UNSUPPORTED => {
                        CaptureError::Unsupported { platform: "windows without output duplication" }
                    }
                    other => condition("IDXGIOutput1::DuplicateOutput", other),
                });
            }
            let interface = Com::own(duplication).ok_or_else(|| {
                CaptureError::Fatal(Fault::refused(
                    "IDXGIOutput1::DuplicateOutput",
                    "succeeded and handed back a null duplication",
                ))
            })?;
            self.duplication = Some(Duplication { interface, holding: false });
            return Ok(());
        }

        // Every output was enumerated and none of them is the display being
        // captured. On a laptop with switchable graphics that means the desktop is
        // on an adapter this device did not open, which is a machine for the GDI
        // source rather than a machine with a fault.
        Err(CaptureError::Unsupported { platform: "windows whose display is on another adapter" })
    }

    /// The display being captured, as the protocol describes it.
    fn target_monitor(&self) -> Result<Monitor, CaptureError> {
        self.monitors
            .iter()
            .find(|monitor| monitor.id == self.target)
            .copied()
            .ok_or(CaptureError::Reinitialise)
    }

    /// Answers the state the session is in, when it is not one that can be
    /// captured.
    ///
    /// The same two questions [`super::gdi::GdiCapture`] asks, and asked for a
    /// sharper reason here: on the secure desktop `AcquireNextFrame` answers
    /// `E_ACCESSDENIED`, which is indistinguishable from a genuine permission
    /// failure unless the desktop was checked first.
    fn capturable(&self) -> Result<(), CaptureError> {
        if self.session != u32::MAX {
            // Sound: a call with no arguments that reads a global.
            let console = unsafe { sys::WTSGetActiveConsoleSessionId() };
            if console != sys::NO_ACTIVE_SESSION && console != self.session {
                return Err(CaptureError::SessionDisconnected);
            }
        }
        match desktop::input_desktop() {
            Ok(InputDesktop::Default) => Ok(()),
            Ok(InputDesktop::Secure | InputDesktop::ScreenSaver) => Err(CaptureError::SecureDesktop),
            Ok(InputDesktop::Other(_)) => Err(CaptureError::SecureDesktop),
            Err(fault) => Err(CaptureError::Fatal(fault)),
        }
    }

    /// Re-reads the display layout when the poll falls due.
    ///
    /// Answers `Ok(true)` when the caller must treat the source as rebuilt. There
    /// is no cheap fingerprint here, unlike the GDI source: a duplication answers
    /// `DXGI_ERROR_ACCESS_LOST` the instant the mode changes, so the layout poll is
    /// a slow backstop for the things that change *without* invalidating it — a
    /// second display appearing, or a DPI change — rather than the primary detector
    /// it has to be over there.
    fn layout_changed(&mut self, now: Instant) -> Result<bool, CaptureError> {
        if now.saturating_duration_since(self.enumerated_at) < TOPOLOGY_POLL {
            return Ok(false);
        }
        self.enumerated_at = now;
        let refreshed = monitors()?;
        if refreshed == self.monitors {
            return Ok(false);
        }
        self.monitors = refreshed;
        self.unmap();
        self.duplication = None;
        self.device.staging = None;
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
}

/// Whether a DXGI output is the display this [`Monitor`] describes.
///
/// The rule itself is [`super::output_covers`], which lives in the pure half of
/// this module so it is tested on a machine with no graphics adapter. This is only
/// the unpacking of the structure the driver filled in.
fn covers(desc: &sys::DxgiOutputDesc, monitor: &Monitor) -> bool {
    let rect = desc.desktop_coordinates;
    super::output_covers(rect.left, rect.top, rect.right, rect.bottom, monitor)
}

impl Capture for DxgiCapture {
    fn monitors(&self) -> &[Monitor] {
        &self.monitors
    }

    /// The next frame, waiting up to `timeout` for the desktop to change.
    ///
    /// Unlike the GDI source this one really does wait, and that is the second
    /// reason to prefer it: a still desktop costs one blocked call rather than
    /// thirty full-screen blits and thirty tile diffs a second.
    ///
    /// The damage is left empty — "assume everything is new" — even though the
    /// duplication reports real dirty rectangles. Reading them is a worthwhile
    /// optimisation and is deliberately *not* taken here: the tile diff in
    /// `selfhost_desk::tiles` already recovers the true damage by comparing this
    /// frame against what the client holds, and a dirty-rectangle path that is
    /// subtly wrong produces a picture with stale patches in it, which is the one
    /// failure this subsystem must never have. See `GetFrameDirtyRects`, slot 9,
    /// declared and unused.
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame<'_>>, CaptureError> {
        // Whatever the last call handed out is no longer borrowed, so the driver's
        // memory is given back before anything else touches the texture.
        self.unmap();

        if self.layout_changed(Instant::now())? {
            return Err(CaptureError::Reinitialise);
        }
        self.capturable()?;

        let monitor = self.target_monitor()?;
        if self.duplication.is_none() {
            self.duplicate()?;
        }

        let milliseconds = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        let mut info = sys::DxgiOutduplFrameInfo::default();
        let mut resource: *mut Unknown = std::ptr::null_mut();
        let duplication = self.duplication.as_mut().ok_or(CaptureError::Reinitialise)?;
        // Sound: `acquire_next_frame` is slot 8 of `IDXGIOutputDuplication`, and
        // both out-parameters are owned by this stack frame.
        let result = unsafe {
            let vtable = duplication.interface.vtable::<sys::DxgiOutputDuplicationVtbl>();
            (vtable.acquire_next_frame)(
                duplication.interface.as_ptr(),
                milliseconds,
                &raw mut info,
                &raw mut resource,
            )
        };
        if result == sys::DXGI_ERROR_WAIT_TIMEOUT {
            // Nothing changed. The cheapest possible frame, and the one a server
            // with nobody at the keyboard produces all day.
            return Ok(None);
        }
        if result != sys::S_OK {
            let fault = hresult("IDXGIOutputDuplication::AcquireNextFrame", result);
            self.last_fault = Some(fault);
            // The duplication is dropped on every failure: each of the conditions
            // that gets here invalidates it, and holding a dead one would answer
            // `INVALID_CALL` for ever.
            self.duplication = None;
            return Err(condition("IDXGIOutputDuplication::AcquireNextFrame", result));
        }
        duplication.holding = true;
        let resource = Com::own(resource);

        // A pointer-only update: the desktop image did not change, and the pointer
        // is captured separately. Released and answered as "nothing yet", which
        // costs no encoding at all for a mouse moved across a still screen.
        if info.last_present_time == 0 || resource.is_none() {
            drop(resource);
            duplication.release();
            return Ok(None);
        }

        let outcome = self.copy_frame(resource, monitor);
        // Owed whatever happened above, and owed *before* the borrow of the
        // staging texture is handed out.
        if let Some(duplication) = self.duplication.as_mut() {
            duplication.release();
        }
        outcome?;

        self.sequence = self.sequence.saturating_add(1);
        let (texture, width, height) = match self.device.staging.as_ref() {
            Some(staging) => staging,
            None => return Err(CaptureError::Reinitialise),
        };
        let (width, height) = (*width, *height);
        let mut mapped = sys::D3d11MappedSubresource {
            data: std::ptr::null_mut(),
            row_pitch: 0,
            depth_pitch: 0,
        };
        // Sound: `map` is slot 14 of `ID3D11DeviceContext`, the resource is this
        // type's own staging texture, and the mapping is released by `unmap` at the
        // top of the next call — before any other use of the texture.
        let result = unsafe {
            let vtable = self.device.context.vtable::<sys::D3d11DeviceContextVtbl>();
            (vtable.map)(
                self.device.context.as_ptr(),
                texture.as_ptr(),
                0,
                sys::D3D11_MAP_READ,
                0,
                &raw mut mapped,
            )
        };
        if result != sys::S_OK {
            return Err(condition("ID3D11DeviceContext::Map", result));
        }
        if mapped.data.is_null() {
            return Err(CaptureError::Fatal(Fault::refused(
                "ID3D11DeviceContext::Map",
                "succeeded and handed back a null pointer",
            )));
        }
        self.mapped = true;

        let stride = mapped.row_pitch as usize;
        let Some(length) = stride.checked_mul(height as usize) else {
            return Err(CaptureError::Fatal(Fault::refused(
                "ID3D11DeviceContext::Map",
                "reported a row pitch that cannot describe this surface",
            )));
        };
        // Sound: the driver guarantees `row_pitch * height` readable bytes at
        // `data`, and the mapping outlives this borrow — it is released at the top
        // of the next `next_frame`, which cannot run while the frame is borrowed.
        let pixels = unsafe { std::slice::from_raw_parts(mapped.data.cast::<u8>(), length) };

        Ok(Some(Frame {
            monitor: monitor.id,
            sequence: self.sequence,
            width,
            height,
            stride,
            pixels,
            damage: Damage::default(),
        }))
    }
}

impl DxgiCapture {
    /// Copies the acquired GPU texture into the CPU-readable staging surface.
    ///
    /// Split out so that the release of the acquired frame in [`Self::next_frame`]
    /// happens on the failing paths too, which a `?` inside that function would
    /// skip.
    fn copy_frame(&mut self, resource: Option<Com>, monitor: Monitor) -> Result<(), CaptureError> {
        let resource = resource.ok_or(CaptureError::Reinitialise)?;
        let texture = resource
            .query(&sys::IID_ID3D11_TEXTURE2D, "IDXGIResource::QueryInterface(ID3D11Texture2D)")
            .map_err(CaptureError::Fatal)?;
        // The pointer is taken out of the borrow before the context is reached
        // for: both live in `self.device`, and holding the texture's borrow across
        // the call below would be a mutable and an immutable borrow of one field.
        let staging = self.device.staging(monitor.width, monitor.height)?.as_ptr();
        // Sound: `copy_resource` is slot 47 of `ID3D11DeviceContext`; both
        // resources are live textures of the same format and size, which is what
        // that call requires and what the staging description above guarantees.
        unsafe {
            let vtable = self.device.context.vtable::<sys::D3d11DeviceContextVtbl>();
            (vtable.copy_resource)(self.device.context.as_ptr(), staging, texture.as_ptr());
        }
        Ok(())
    }
}

impl Drop for DxgiCapture {
    fn drop(&mut self) {
        // Before the texture it points into is released.
        self.unmap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An output covering a rectangle.
    fn output(left: i32, top: i32, right: i32, bottom: i32) -> sys::DxgiOutputDesc {
        sys::DxgiOutputDesc {
            device_name: [0; 32],
            desktop_coordinates: sys::Rect { left, top, right, bottom },
            attached_to_desktop: 1,
            rotation: 0,
            monitor: std::ptr::null_mut(),
        }
    }

    #[test]
    fn a_desc_is_unpacked_into_the_rule_the_right_way_round() {
        // The rule itself is tested in the pure half; what is checked here is that
        // the four edges are handed over in the order the structure declares them,
        // which is the mistake this thin function can still make.
        let monitor =
            Monitor { id: 0, origin_x: 2560, origin_y: 0, width: 1920, height: 1080,
                      scale_permille: 1000, primary: false };
        assert!(covers(&output(2560, 0, 4480, 1080), &monitor));
        assert!(!covers(&output(0, 2560, 1080, 4480), &monitor), "the edges are not swapped");
    }

    #[test]
    fn every_dxgi_condition_that_is_a_state_is_reported_as_that_state() {
        // The distinction the whole file turns on: these are conditions of the
        // machine, and reporting any of them as `Fatal` is how a session that
        // would have recovered never comes back.
        assert!(matches!(
            condition("t", sys::DXGI_ERROR_ACCESS_LOST),
            CaptureError::Reinitialise
        ));
        assert!(matches!(
            condition("t", sys::DXGI_ERROR_DEVICE_REMOVED),
            CaptureError::Reinitialise
        ));
        assert!(matches!(
            condition("t", sys::DXGI_ERROR_NOT_CURRENTLY_AVAILABLE),
            CaptureError::TooManyDuplications
        ));
        assert!(matches!(condition("t", sys::E_ACCESSDENIED), CaptureError::SecureDesktop));
        assert!(matches!(
            condition("t", sys::DXGI_ERROR_SESSION_DISCONNECTED),
            CaptureError::SessionDisconnected
        ));
    }

    #[test]
    fn an_unrecognised_hresult_is_fatal_and_names_the_call_that_produced_it() {
        let CaptureError::Fatal(fault) = condition("IDXGIOutput1::DuplicateOutput", 0x8000_4005u32 as Hresult)
        else {
            panic!("an unknown HRESULT must not be mistaken for a state");
        };
        assert_eq!(fault.call(), "IDXGIOutput1::DuplicateOutput");
    }

    #[test]
    fn a_hresult_is_rendered_as_hexadecimal_and_not_as_an_errno() {
        // `0x887A0022` is not error number 2289434658, and describing it through
        // the operating system's `GetLastError` strings would print a sentence
        // about something else entirely.
        let fault = hresult("IDXGIOutput1::DuplicateOutput", sys::DXGI_ERROR_NOT_CURRENTLY_AVAILABLE);
        let sentence = fault.sentence();
        assert!(sentence.contains("0x887a0022"), "{sentence}");
        assert!(sentence.contains("duplication slot"), "{sentence}");
        assert_eq!(fault.code(), None, "a HRESULT is not an OS error code");
    }
}
