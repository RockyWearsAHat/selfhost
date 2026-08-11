//! The Windows backend: Win32 for the window and input, GDI for the blit.
//!
//! # Events are read from the queue, not from the window procedure
//!
//! The usual shape is a `WndProc` that switches on every message and calls back
//! into the application, which from Rust means a `static` callback reaching
//! state it does not own. This does not do that. Messages are pulled off the
//! queue with `PeekMessageW` and read directly, exactly as the macOS backend
//! reads `NSEvent`s, so the whole translation is ordinary code with the state
//! passed to it.
//!
//! The window procedure that remains is three lines. It exists because two
//! messages must be answered rather than observed: `WM_PAINT` has to validate
//! the update region or Windows re-sends it forever, and `WM_ERASEBKGND` has to
//! be swallowed or the system paints the window grey before every frame and it
//! flickers.
//!
//! # The input method draws nothing
//!
//! `WM_IME_STARTCOMPOSITION`, `WM_IME_COMPOSITION`, and `WM_IME_CHAR` are read
//! off the queue and then swallowed rather than passed to `DefWindowProcW`,
//! because the default handling of them opens the system's own composition
//! window and draws the text being composed into it — over the top of the same
//! text the field is already drawing underlined at its caret. What is kept is
//! the data: the string being composed, the string the input method settled on,
//! and where its caret sits within them.
//!
//! # Blitting
//!
//! `StretchDIBits` onto the window's device context, from a top-down 32-bit
//! `BI_RGB` bitmap — which is blue, green, red, unused per pixel, the same bytes
//! [`Canvas`] already holds.

use crate::accessibility::AccessUpdate;
use crate::input::Composition;
use crate::theme::Appearance;
use crate::{Canvas, Event, Key, KeyCode, Modifiers, Point, PointerButton, Rect};
use std::cell::Cell;
use std::ffi::c_void;
use std::time::Duration;

use crate::shell::{Backend, Error, WindowOptions};

type Handle = *mut c_void;
type WordParameter = usize;
type LongParameter = isize;

#[link(name = "user32")]
unsafe extern "system" {
    fn OpenClipboard(owner: Handle) -> i32;
    fn CloseClipboard() -> i32;
    fn EmptyClipboard() -> i32;
    fn GetClipboardData(format: u32) -> Handle;
    fn SetClipboardData(format: u32, memory: Handle) -> Handle;
    fn IsClipboardFormatAvailable(format: u32) -> i32;
    fn RegisterClassExW(class: *const WindowClass) -> u16;
    fn CreateWindowExW(
        extended_style: u32,
        class_name: *const u16,
        window_name: *const u16,
        style: u32,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        parent: Handle,
        menu: Handle,
        instance: Handle,
        parameter: *mut c_void,
    ) -> Handle;
    fn DefWindowProcW(
        window: Handle,
        message: u32,
        word: WordParameter,
        long: LongParameter,
    ) -> LongParameter;
    fn ShowWindow(window: Handle, command: i32) -> i32;
    fn UpdateWindow(window: Handle) -> i32;
    fn DestroyWindow(window: Handle) -> i32;
    fn PeekMessageW(
        message: *mut Message,
        window: Handle,
        first: u32,
        last: u32,
        remove: u32,
    ) -> i32;
    fn TranslateMessage(message: *const Message) -> i32;
    fn DispatchMessageW(message: *const Message) -> LongParameter;
    fn MsgWaitForMultipleObjects(
        count: u32,
        handles: *const Handle,
        wait_all: i32,
        milliseconds: u32,
        mask: u32,
    ) -> u32;
    fn GetClientRect(window: Handle, rect: *mut WindowRect) -> i32;
    fn GetDC(window: Handle) -> Handle;
    fn ReleaseDC(window: Handle, context: Handle) -> i32;
    fn BeginPaint(window: Handle, paint: *mut PaintStruct) -> Handle;
    fn EndPaint(window: Handle, paint: *const PaintStruct) -> i32;
    fn GetKeyState(key: i32) -> i16;
    fn SetProcessDPIAware() -> i32;
    fn GetDpiForWindow(window: Handle) -> u32;
    fn IsWindow(window: Handle) -> i32;
    fn LoadCursorW(instance: Handle, name: *const u16) -> Handle;
    fn GetWindowRect(window: Handle, rect: *mut WindowRect) -> i32;
    fn GetWindowLongPtrW(window: Handle, index: i32) -> LongParameter;
    fn SetWindowLongPtrW(window: Handle, index: i32, value: LongParameter) -> LongParameter;
    fn SetWindowPos(
        window: Handle,
        insert_after: Handle,
        x: i32,
        y: i32,
        width: i32,
        height: i32,
        flags: u32,
    ) -> i32;
    fn MonitorFromWindow(window: Handle, flags: u32) -> Handle;
    fn GetMonitorInfoW(monitor: Handle, info: *mut MonitorInfo) -> i32;
}

#[link(name = "gdi32")]
unsafe extern "system" {
    fn StretchDIBits(
        context: Handle,
        destination_x: i32,
        destination_y: i32,
        destination_width: i32,
        destination_height: i32,
        source_x: i32,
        source_y: i32,
        source_width: i32,
        source_height: i32,
        bits: *const c_void,
        info: *const BitmapInfo,
        usage: u32,
        operation: u32,
    ) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name: *const u16) -> Handle;
    fn GlobalAlloc(flags: u32, bytes: usize) -> Handle;
    fn GlobalFree(memory: Handle) -> Handle;
    fn GlobalLock(memory: Handle) -> *mut c_void;
    fn GlobalUnlock(memory: Handle) -> i32;
}

#[link(name = "imm32")]
unsafe extern "system" {
    fn ImmGetContext(window: Handle) -> Handle;
    fn ImmReleaseContext(window: Handle, context: Handle) -> i32;
    fn ImmGetCompositionStringW(
        context: Handle,
        index: u32,
        buffer: *mut c_void,
        bytes: u32,
    ) -> i32;
    fn ImmSetCompositionWindow(context: Handle, form: *const CompositionForm) -> i32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegGetValueW(
        key: Handle,
        subkey: *const u16,
        value: *const u16,
        flags: u32,
        kind: *mut u32,
        data: *mut c_void,
        size: *mut u32,
    ) -> i32;
}

#[repr(C)]
struct WindowClass {
    size: u32,
    style: u32,
    procedure: Option<
        unsafe extern "system" fn(Handle, u32, WordParameter, LongParameter) -> LongParameter,
    >,
    class_extra: i32,
    window_extra: i32,
    instance: Handle,
    icon: Handle,
    cursor: Handle,
    background: Handle,
    menu_name: *const u16,
    class_name: *const u16,
    small_icon: Handle,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct WindowPoint {
    x: i32,
    y: i32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct WindowRect {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

/// `MONITORINFO`: where a display is, and which part of it a window may have.
///
/// `monitor` is the whole panel and `work` is what is left once the taskbar has
/// had its share. A full screen wants the first — covering the taskbar is the
/// difference between filling the screen and merely being large.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct MonitorInfo {
    size: u32,
    monitor: WindowRect,
    work: WindowRect,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Message {
    window: Handle,
    message: u32,
    word: WordParameter,
    long: LongParameter,
    time: u32,
    point: WindowPoint,
}

impl Default for Message {
    /// An empty message, for `PeekMessageW` to fill in.
    ///
    /// Written out rather than derived because a handle is a raw pointer, and a
    /// derived `Default` would need one for a type this crate does not own.
    fn default() -> Self {
        Self {
            window: std::ptr::null_mut(),
            message: 0,
            word: 0,
            long: 0,
            time: 0,
            point: WindowPoint::default(),
        }
    }
}

#[repr(C)]
struct PaintStruct {
    context: Handle,
    erase: i32,
    paint: WindowRect,
    restore: i32,
    increment: i32,
    reserved: [u8; 32],
}

#[repr(C)]
struct BitmapHeader {
    size: u32,
    width: i32,
    height: i32,
    planes: u16,
    bit_count: u16,
    compression: u32,
    image_size: u32,
    x_pixels_per_meter: i32,
    y_pixels_per_meter: i32,
    colors_used: u32,
    colors_important: u32,
}

#[repr(C)]
struct BitmapInfo {
    header: BitmapHeader,
    colors: [u32; 3],
}

/// `COMPOSITIONFORM`: where the input method should draw what is being composed.
#[repr(C)]
struct CompositionForm {
    style: u32,
    current_position: WindowPoint,
    area: WindowRect,
}

// Window styles and commands.
const WS_OVERLAPPEDWINDOW: u32 = 0x00CF_0000;
/// `WS_POPUP`: a window with no frame, caption, or border of its own.
const WS_POPUP: u32 = 0x8000_0000;
/// `GWL_STYLE`: the style word, for reading and putting back.
const GWL_STYLE: i32 = -16;
/// `MONITOR_DEFAULTTONEAREST`: the display a window is most on.
const MONITOR_DEFAULTTONEAREST: u32 = 2;
/// `SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED`.
///
/// The frame change is the one that matters: without it the old frame's
/// measurements are kept and the client area comes out the wrong size.
const SWP_FRAME_CHANGED: u32 = 0x0004 | 0x0010 | 0x0020;
const SW_SHOW: i32 = 5;
const CW_USEDEFAULT: i32 = i32::MIN;
const IDC_ARROW: u32 = 32512;
const CS_OWNDC: u32 = 0x0020;

// Messages.
const WM_DESTROY: u32 = 0x0002;
const WM_CLOSE: u32 = 0x0010;
const WM_QUIT: u32 = 0x0012;
const WM_ERASEBKGND: u32 = 0x0014;
const WM_PAINT: u32 = 0x000F;
const WM_KEYDOWN: u32 = 0x0100;
const WM_KEYUP: u32 = 0x0101;
const WM_SYSKEYDOWN: u32 = 0x0104;
const WM_SYSKEYUP: u32 = 0x0105;
const WM_CHAR: u32 = 0x0102;
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_LBUTTONUP: u32 = 0x0202;
const WM_RBUTTONDOWN: u32 = 0x0204;
const WM_RBUTTONUP: u32 = 0x0205;
const WM_MBUTTONDOWN: u32 = 0x0207;
const WM_MBUTTONUP: u32 = 0x0208;
const WM_MOUSEWHEEL: u32 = 0x020A;
const WM_MOUSEHWHEEL: u32 = 0x020E;
const WM_IME_STARTCOMPOSITION: u32 = 0x010D;
const WM_IME_ENDCOMPOSITION: u32 = 0x010E;
const WM_IME_COMPOSITION: u32 = 0x010F;
const WM_IME_CHAR: u32 = 0x0286;

// `ImmGetCompositionStringW` indices.
/// The text being composed.
const GCS_COMPSTR: u32 = 0x0008;
/// Where the caret is within it, counted in UTF-16 units.
const GCS_CURSORPOS: u32 = 0x0080;
/// The text the input method has settled on.
const GCS_RESULTSTR: u32 = 0x0800;

/// `CFS_POINT`: place the composition window at a position we give.
const CFS_POINT: u32 = 0x0002;

/// `CF_UNICODETEXT`: the clipboard format that is not a code page.
const CF_UNICODETEXT: u32 = 13;

/// `GMEM_MOVEABLE`, which is what the clipboard requires of its memory.
const GMEM_MOVEABLE: u32 = 0x0002;

const PM_REMOVE: u32 = 0x0001;
const QS_ALLINPUT: u32 = 0x04FF;

// Virtual key codes.
const VK_BACK: i32 = 0x08;
const VK_TAB: i32 = 0x09;
const VK_RETURN: i32 = 0x0D;
const VK_SHIFT: i32 = 0x10;
const VK_CONTROL: i32 = 0x11;
const VK_MENU: i32 = 0x12;
const VK_ESCAPE: i32 = 0x1B;
const VK_SPACE: i32 = 0x20;
const VK_PRIOR: i32 = 0x21;
const VK_NEXT: i32 = 0x22;
const VK_END: i32 = 0x23;
const VK_HOME: i32 = 0x24;
const VK_LEFT: i32 = 0x25;
const VK_UP: i32 = 0x26;
const VK_RIGHT: i32 = 0x27;
const VK_DOWN: i32 = 0x28;
const VK_DELETE: i32 = 0x2E;

/// `BI_RGB`: uncompressed, and for 32 bits per pixel that is blue, green, red,
/// unused — which is a [`Canvas`] word in memory.
const BI_RGB: u32 = 0;
/// `DIB_RGB_COLORS`.
const DIB_RGB_COLORS: u32 = 0;
/// `SRCCOPY`.
const SRCCOPY: u32 = 0x00CC_0020;

/// One notch of a wheel, as Windows counts it.
const WHEEL_DELTA: f32 = 120.0;

/// How many logical units one notch scrolls.
const WHEEL_STEP: f32 = 48.0;

/// The reference density Windows scales from.
const BASE_DPI: f32 = 96.0;

/// `HKEY_CURRENT_USER`.
const HKEY_CURRENT_USER: Handle = 0x8000_0001usize as Handle;
/// `RRF_RT_REG_DWORD`.
const RRF_RT_REG_DWORD: u32 = 0x0000_0010;

/// A window on Windows.
pub(crate) struct Window {
    handle: Handle,
    open: bool,
    /// Client area in device pixels, as of the last pump.
    size: (u32, u32),
    scale: f32,
    /// The frame and the place to put it back, while the screen is filled.
    ///
    /// `None` means the window is its ordinary self. Windows has no full-screen
    /// mode of its own for a window like this one — what a game or a browser
    /// does here is exactly this: drop the frame and cover the display — so
    /// what was dropped has to be kept somewhere, and this is it. A [`Cell`]
    /// because the seam asks for this through `&self`, in the same way the X11
    /// backend keeps its clipboard text.
    windowed: Cell<Option<(LongParameter, WindowRect)>>,
}

impl Backend for Window {
    fn open(options: &WindowOptions) -> Result<Self, Error> {
        unsafe {
            // Without this the system lies about sizes on a high-density
            // display: it reports a scaled-down client area and then stretches
            // what we draw, which turns crisp text into blurred text.
            SetProcessDPIAware();

            let instance = GetModuleHandleW(std::ptr::null());
            let class_name = wide("rui.window");
            let class = WindowClass {
                size: std::mem::size_of::<WindowClass>() as u32,
                // Its own device context, so presenting a frame does not fetch
                // and release one from a shared pool sixty times a second.
                style: CS_OWNDC,
                procedure: Some(window_procedure),
                class_extra: 0,
                window_extra: 0,
                instance,
                icon: std::ptr::null_mut(),
                cursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW as *const u16),
                // No background brush: we paint every pixel ourselves, and a
                // brush would paint over it first.
                background: std::ptr::null_mut(),
                menu_name: std::ptr::null(),
                class_name: class_name.as_ptr(),
                small_icon: std::ptr::null_mut(),
            };
            // A duplicate registration is not an error here: it means a window
            // was opened before, and the class is still the one we want.
            RegisterClassExW(&class);

            let title = wide(&options.title);
            let handle = CreateWindowExW(
                0,
                class_name.as_ptr(),
                title.as_ptr(),
                WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                options.width as i32,
                options.height as i32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                instance,
                std::ptr::null_mut(),
            );
            if handle.is_null() {
                return Err(Error::Platform("CreateWindowExW failed".into()));
            }

            ShowWindow(handle, SW_SHOW);
            UpdateWindow(handle);

            let mut window =
                Self { handle, open: true, size: (1, 1), scale: 1.0, windowed: Cell::new(None) };
            window.refresh_geometry();
            Ok(window)
        }
    }

    fn pump(
        &mut self,
        timeout: Duration,
        events: &mut Vec<Event>,
        _redraw: &mut dyn FnMut(&Self),
    ) -> Result<(), Error> {
        unsafe {
            // Blocks until something arrives or the timeout runs out, so an idle
            // console costs nothing rather than spinning on PeekMessage.
            let milliseconds = timeout.as_millis().min(u32::MAX as u128 - 1) as u32;
            MsgWaitForMultipleObjects(0, std::ptr::null(), 0, milliseconds, QS_ALLINPUT);

            let mut message = Message::default();
            while PeekMessageW(&mut message, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                if message.message == WM_QUIT {
                    self.open = false;
                    break;
                }
                self.translate(&message, events);
                // Turns a key press into the character it types, according to
                // the layout and any dead key before it — which is a question
                // only the system can answer.
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }

            self.refresh_geometry();
            if IsWindow(self.handle) == 0 {
                self.open = false;
            }
        }
        Ok(())
    }

    fn surface(&self) -> (u32, u32, f32) {
        (self.size.0.max(1), self.size.1.max(1), self.scale)
    }

    fn appearance(&self) -> Appearance {
        // `AppsUseLightTheme` is how Windows records the choice; absent means
        // light, which is what every version that lacks the setting used.
        let subkey = wide(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
        let value = wide("AppsUseLightTheme");
        let mut data: u32 = 1;
        let mut size = std::mem::size_of::<u32>() as u32;
        let result = unsafe {
            RegGetValueW(
                HKEY_CURRENT_USER,
                subkey.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                (&raw mut data).cast::<c_void>(),
                &mut size,
            )
        };
        if result == 0 && data == 0 { Appearance::Dark } else { Appearance::Light }
    }

    fn present(&self, canvas: &Canvas) -> Result<(), Error> {
        let width = canvas.width() as i32;
        let height = canvas.height() as i32;
        if width == 0 || height == 0 {
            return Ok(());
        }

        let info = BitmapInfo {
            header: BitmapHeader {
                size: std::mem::size_of::<BitmapHeader>() as u32,
                width,
                // Negative means the rows run top to bottom, which is the order
                // the canvas stores them; a positive height draws it upside down.
                height: -height,
                planes: 1,
                bit_count: 32,
                compression: BI_RGB,
                image_size: 0,
                x_pixels_per_meter: 0,
                y_pixels_per_meter: 0,
                colors_used: 0,
                colors_important: 0,
            },
            colors: [0; 3],
        };

        unsafe {
            let context = GetDC(self.handle);
            if context.is_null() {
                return Err(Error::Platform("the window has no device context".into()));
            }
            StretchDIBits(
                context,
                0,
                0,
                width,
                height,
                0,
                0,
                width,
                height,
                canvas.pixels().as_ptr().cast::<c_void>(),
                &info,
                DIB_RGB_COLORS,
                SRCCOPY,
            );
            ReleaseDC(self.handle, context);
        }
        Ok(())
    }

    fn is_open(&self) -> bool {
        self.open
    }

    fn is_fullscreen(&self) -> bool {
        // What this backend did, and not a question put to the system: Windows
        // has no notion of a full-screen window to ask about, so the frame this
        // window took off is the whole of the fact. Nothing outside this file
        // can put it back, which is why remembering it here cannot go stale in
        // the way the same trick would on macOS.
        let windowed = self.windowed.take();
        let filling = windowed.is_some();
        self.windowed.set(windowed);
        filling
    }

    fn set_fullscreen(&self, filling: bool) -> Result<(), Error> {
        match (filling, self.windowed.take()) {
            (true, None) => self.fill_screen(),
            (false, Some(windowed)) => self.restore_window(windowed),
            // Already as asked. The `take` above is put back by the arms that
            // change something; this one has nothing to change.
            (true, windowed @ Some(_)) => {
                self.windowed.set(windowed);
                Ok(())
            }
            (false, None) => Ok(()),
        }
    }

    fn clipboard_text(&self) -> Result<Option<String>, Error> {
        unsafe {
            // Asked before the clipboard is opened, because opening it locks
            // every other program out of it for as long as we hold it.
            if IsClipboardFormatAvailable(CF_UNICODETEXT) == 0 {
                return Ok(None);
            }
            if OpenClipboard(self.handle) == 0 {
                return Err(Error::Platform("another program is holding the clipboard".into()));
            }
            let memory = GetClipboardData(CF_UNICODETEXT);
            if memory.is_null() {
                CloseClipboard();
                return Ok(None);
            }
            let text = read_wide(GlobalLock(memory).cast::<u16>());
            GlobalUnlock(memory);
            CloseClipboard();
            Ok(text)
        }
    }

    fn set_clipboard_text(&self, text: &str) -> Result<(), Error> {
        let wide_text = wide(text);
        let bytes = std::mem::size_of_val(wide_text.as_slice());
        unsafe {
            if OpenClipboard(self.handle) == 0 {
                return Err(Error::Platform("another program is holding the clipboard".into()));
            }
            // The clipboard takes ownership of the block handed to it, so it is
            // never freed here once `SetClipboardData` has accepted it — and it
            // has to be freed on every path where it has not.
            let memory = GlobalAlloc(GMEM_MOVEABLE, bytes);
            let destination = if memory.is_null() { std::ptr::null_mut() } else { GlobalLock(memory) };
            if destination.is_null() {
                if !memory.is_null() {
                    GlobalFree(memory);
                }
                CloseClipboard();
                return Err(Error::Platform("there was no memory for the copied text".into()));
            }
            std::ptr::copy_nonoverlapping(
                wide_text.as_ptr(),
                destination.cast::<u16>(),
                wide_text.len(),
            );
            GlobalUnlock(memory);

            // Emptying it is what transfers ownership to this program; a
            // clipboard written to without it keeps the last owner's formats.
            EmptyClipboard();
            let accepted = SetClipboardData(CF_UNICODETEXT, memory);
            CloseClipboard();
            if accepted.is_null() {
                GlobalFree(memory);
                return Err(Error::Platform("the clipboard would not take the text".into()));
            }
        }
        Ok(())
    }

    fn set_composition_area(&self, area: Option<Rect>) -> Result<(), Error> {
        let Some(area) = area else {
            return Ok(());
        };
        unsafe {
            let context = ImmGetContext(self.handle);
            if context.is_null() {
                // No input context means no input method is loaded, which is the
                // ordinary case for a keyboard that needs none.
                return Ok(());
            }
            // The bottom left of the caret, in client pixels: an input method
            // hangs its window below the point it is given.
            let form = CompositionForm {
                style: CFS_POINT,
                current_position: WindowPoint {
                    x: (area.x * self.scale) as i32,
                    y: ((area.y + area.h) * self.scale) as i32,
                },
                area: WindowRect::default(),
            };
            let placed = ImmSetCompositionWindow(context, &form);
            ImmReleaseContext(self.handle, context);
            if placed == 0 {
                return Err(Error::Platform("the input method refused a position".into()));
            }
        }
        Ok(())
    }

    /// Nothing yet: this backend has no UI Automation provider.
    ///
    /// The way to on this platform is to answer `WM_GETOBJECT` with an
    /// `IRawElementProviderSimple` — a COM object, which means a vtable built by
    /// hand here, reference counting, and a fragment provider on top of it to
    /// express the tree at all. It is the next platform to do and it is not done,
    /// so Narrator finds a `rui` window and is told nothing about what is in it.
    ///
    /// Accepting the update rather than refusing it is deliberate: a refusal
    /// would end the frame loop, and a screen reader that is not there must not
    /// stop the program running.
    fn update_accessibility(&self, _update: &AccessUpdate) -> Result<(), Error> {
        Ok(())
    }
}

impl Window {
    /// Takes the frame off and covers the display the window is most on.
    ///
    /// The style and the outer rectangle are written down first, because they
    /// are the only record of what the window was: nothing else on the system
    /// remembers where a window that has been resized used to be.
    fn fill_screen(&self) -> Result<(), Error> {
        unsafe {
            let mut place = WindowRect::default();
            if GetWindowRect(self.handle, &mut place) == 0 {
                return Err(Error::Platform("GetWindowRect failed".into()));
            }
            let monitor = MonitorFromWindow(self.handle, MONITOR_DEFAULTTONEAREST);
            let mut info =
                MonitorInfo { size: std::mem::size_of::<MonitorInfo>() as u32, ..MonitorInfo::default() };
            if GetMonitorInfoW(monitor, &mut info) == 0 {
                return Err(Error::Platform("GetMonitorInfoW failed".into()));
            }
            let style = GetWindowLongPtrW(self.handle, GWL_STYLE);
            // Cast from `u32` rather than through `i32`: `WS_POPUP` has its top
            // bit set, and going by way of a signed 32-bit value would sign-
            // extend it into the high half of the style word.
            let filling =
                (style & !(WS_OVERLAPPEDWINDOW as LongParameter)) | WS_POPUP as LongParameter;
            SetWindowLongPtrW(self.handle, GWL_STYLE, filling);
            let screen = info.monitor;
            SetWindowPos(
                self.handle,
                std::ptr::null_mut(),
                screen.left,
                screen.top,
                screen.right - screen.left,
                screen.bottom - screen.top,
                SWP_FRAME_CHANGED,
            );
            self.windowed.set(Some((style, place)));
        }
        Ok(())
    }

    /// Puts the frame and the place back, exactly as they were.
    fn restore_window(&self, (style, place): (LongParameter, WindowRect)) -> Result<(), Error> {
        unsafe {
            SetWindowLongPtrW(self.handle, GWL_STYLE, style);
            SetWindowPos(
                self.handle,
                std::ptr::null_mut(),
                place.left,
                place.top,
                place.right - place.left,
                place.bottom - place.top,
                SWP_FRAME_CHANGED,
            );
        }
        Ok(())
    }

    /// What the input method has in progress, and where its caret sits in it.
    ///
    /// `index` selects which string to read — the one being composed, or the one
    /// the input method has settled on. Both arrive as UTF-16 and are measured
    /// in bytes, which is why the length is halved before it becomes a buffer.
    fn composition_string(&self, index: u32) -> Option<(String, usize)> {
        unsafe {
            let context = ImmGetContext(self.handle);
            if context.is_null() {
                return None;
            }
            let bytes = ImmGetCompositionStringW(context, index, std::ptr::null_mut(), 0);
            if bytes <= 0 {
                ImmReleaseContext(self.handle, context);
                return None;
            }
            let mut buffer = vec![0u16; bytes as usize / 2];
            ImmGetCompositionStringW(
                context,
                index,
                buffer.as_mut_ptr().cast::<c_void>(),
                bytes as u32,
            );
            // Negative means the input method has no opinion about the caret, in
            // which case the end of the composition is where it goes.
            let caret = ImmGetCompositionStringW(context, GCS_CURSORPOS, std::ptr::null_mut(), 0);
            ImmReleaseContext(self.handle, context);

            let text = String::from_utf16_lossy(&buffer);
            let caret = if caret < 0 { buffer.len() } else { caret as usize };
            Some((text, caret))
        }
    }

    /// Turns one of the input method's messages into the toolkit's events.
    ///
    /// A commit and a change to the composition arrive in the same message, and
    /// in that order: the input method says what it settled on and then shows
    /// what is left being composed.
    fn translate_composition(&self, message: &Message, events: &mut Vec<Event>) {
        let flags = message.long as u32;
        if flags & GCS_RESULTSTR != 0 {
            if let Some((text, _)) = self.composition_string(GCS_RESULTSTR) {
                events.push(Event::Composing(Composition::default()));
                let typed: String = text.chars().filter(|c| !c.is_control()).collect();
                if !typed.is_empty() {
                    events.push(Event::Text(typed));
                }
            }
        }
        if flags & GCS_COMPSTR != 0 {
            match self.composition_string(GCS_COMPSTR) {
                Some((text, caret)) if !text.is_empty() => {
                    let at = utf16_offset(&text, caret);
                    events.push(Event::Composing(Composition { text, selection: at..at }));
                }
                _ => events.push(Event::Composing(Composition::default())),
            }
        }
    }
    /// Re-reads the client area and the display's density.
    fn refresh_geometry(&mut self) {
        unsafe {
            let mut rect = WindowRect::default();
            if GetClientRect(self.handle, &mut rect) != 0 {
                let width = (rect.right - rect.left).max(0) as u32;
                let height = (rect.bottom - rect.top).max(0) as u32;
                if width > 0 && height > 0 {
                    self.size = (width, height);
                }
            }
            let dpi = GetDpiForWindow(self.handle);
            if dpi > 0 {
                self.scale = dpi as f32 / BASE_DPI;
            }
        }
    }

    /// Turns one message into the toolkit's events, if it is one we care about.
    fn translate(&self, message: &Message, events: &mut Vec<Event>) {
        let position = || self.position_of(message.long);
        let modifiers = current_modifiers();

        match message.message {
            WM_CLOSE | WM_DESTROY => events.push(Event::CloseRequested),
            WM_MOUSEMOVE => {
                let at = position();
                let (width, height) = self.logical_size();
                if at.x < 0.0 || at.y < 0.0 || at.x > width || at.y > height {
                    events.push(Event::PointerLeft);
                } else {
                    events.push(Event::PointerMoved(at));
                }
            }
            WM_LBUTTONDOWN => {
                events.push(Event::PointerDown { position: position(), button: PointerButton::Primary })
            }
            WM_LBUTTONUP => {
                events.push(Event::PointerUp { position: position(), button: PointerButton::Primary })
            }
            WM_RBUTTONDOWN => events
                .push(Event::PointerDown { position: position(), button: PointerButton::Secondary }),
            WM_RBUTTONUP => events
                .push(Event::PointerUp { position: position(), button: PointerButton::Secondary }),
            WM_MBUTTONDOWN => {
                events.push(Event::PointerDown { position: position(), button: PointerButton::Middle })
            }
            WM_MBUTTONUP => {
                events.push(Event::PointerUp { position: position(), button: PointerButton::Middle })
            }
            WM_MOUSEWHEEL => {
                events.push(Event::Scrolled { x: 0.0, y: wheel_amount(message.word) })
            }
            WM_MOUSEHWHEEL => {
                events.push(Event::Scrolled { x: wheel_amount(message.word), y: 0.0 })
            }
            // Reported whether or not this library has a name for the key. The
            // virtual-key code is what the function row, the keypad, and the
            // left and right halves of a modifier pair have instead of a name,
            // and it is what anything forwarding a keystroke to another machine
            // sends; `key_for_code` is the meaning, and it is allowed to have
            // none.
            WM_KEYDOWN | WM_SYSKEYDOWN => events.push(Event::KeyDown {
                key: key_for_code(message.word as i32),
                code: Some(KeyCode::new(message.word as u32)),
                modifiers,
            }),
            WM_KEYUP | WM_SYSKEYUP => events.push(Event::KeyUp {
                key: key_for_code(message.word as i32),
                code: Some(KeyCode::new(message.word as u32)),
                modifiers,
            }),
            WM_CHAR => {
                // A key held with the accelerator is a command, not typing.
                if modifiers.command {
                    return;
                }
                if let Some(character) =
                    char::from_u32(message.word as u32).filter(|c| !c.is_control())
                {
                    events.push(Event::Text(character.to_string()));
                }
            }
            WM_IME_COMPOSITION => self.translate_composition(message, events),
            // The composition was abandoned. A commit ends it too, but arrives
            // as a result string on the message above and has already been
            // reported by the time this is sent.
            WM_IME_ENDCOMPOSITION => events.push(Event::Composing(Composition::default())),
            _ => {}
        }
    }

    /// The client size in logical units.
    fn logical_size(&self) -> (f32, f32) {
        (self.size.0 as f32 / self.scale, self.size.1 as f32 / self.scale)
    }

    /// The pointer position a mouse message carries, in logical units.
    fn position_of(&self, long: LongParameter) -> Point {
        // Packed as two signed 16-bit values; taking them unsigned puts the
        // pointer at 65,000 the moment it leaves the window to the left.
        let x = (long & 0xffff) as u16 as i16 as f32;
        let y = ((long >> 16) & 0xffff) as u16 as i16 as f32;
        Point::new(x / self.scale, y / self.scale)
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        unsafe {
            if IsWindow(self.handle) != 0 {
                DestroyWindow(self.handle);
            }
        }
    }
}

/// How far one wheel message scrolls, in logical units.
fn wheel_amount(word: WordParameter) -> f32 {
    let notches = ((word >> 16) & 0xffff) as u16 as i16 as f32 / WHEEL_DELTA;
    notches * WHEEL_STEP
}

/// Which modifiers are held right now.
///
/// Read from the keyboard rather than from the message, because a message
/// carries the key that changed and not the state of the others.
fn current_modifiers() -> Modifiers {
    let held = |key: i32| unsafe { GetKeyState(key) < 0 };
    let control = held(VK_CONTROL);
    Modifiers {
        shift: held(VK_SHIFT),
        control,
        alt: held(VK_MENU),
        // Control is the accelerator on this platform, so a shortcut written
        // once is correct here and on macOS without a conditional at its use.
        command: control,
    }
}

/// The named key a virtual key code stands for, if it is one.
fn key_for_code(code: i32) -> Option<Key> {
    Some(match code {
        VK_RETURN => Key::Enter,
        VK_TAB => Key::Tab,
        VK_SPACE => Key::Space,
        VK_BACK => Key::Backspace,
        VK_DELETE => Key::Delete,
        VK_ESCAPE => Key::Escape,
        VK_HOME => Key::Home,
        VK_END => Key::End,
        VK_PRIOR => Key::PageUp,
        VK_NEXT => Key::PageDown,
        VK_LEFT => Key::Left,
        VK_RIGHT => Key::Right,
        VK_UP => Key::Up,
        VK_DOWN => Key::Down,
        // Letters and digits carry their ASCII code, which is what a shortcut
        // is written against.
        0x30..=0x39 => Key::Character(code as u8 as char),
        0x41..=0x5A => Key::Character((code as u8 as char).to_ascii_lowercase()),
        _ => return None,
    })
}

/// A NUL-terminated UTF-16 string, as every wide Win32 entry point wants.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The text at a NUL-terminated wide pointer, or `None` for a null one.
///
/// Only ever pointed at memory the system locked for us and which stays locked
/// for the length of the call.
unsafe fn read_wide(text: *const u16) -> Option<String> {
    if text.is_null() {
        return None;
    }
    let mut length = 0;
    // SAFETY: the clipboard's own block, which the system guarantees is
    // terminated for the format that was asked for.
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    let units = unsafe { std::slice::from_raw_parts(text, length) };
    Some(String::from_utf16_lossy(units))
}

/// The byte offset in `text` of a position counted in UTF-16 units.
///
/// The input method counts the way the system stores a string; a Rust [`String`]
/// is bytes. Saturates at the end rather than panicking.
fn utf16_offset(text: &str, utf16: usize) -> usize {
    let mut counted = 0;
    for (offset, character) in text.char_indices() {
        if counted >= utf16 {
            return offset;
        }
        counted += character.len_utf16();
    }
    text.len()
}

/// Answers the messages that must be answered rather than merely observed.
///
/// Everything else is read off the queue in [`Window::pump`] and then handed to
/// `DefWindowProcW`, so this stays the whole of the callback.
unsafe extern "system" fn window_procedure(
    window: Handle,
    message: u32,
    word: WordParameter,
    long: LongParameter,
) -> LongParameter {
    match message {
        // Painting is ours. Answering non-zero says the background needs no
        // erasing, which is what stops the window flashing grey between frames.
        WM_ERASEBKGND => 1,
        // So is the composition. `DefWindowProcW` would open the system's own
        // little window and draw the text being composed into it, on top of the
        // one the field is already drawing underlined at the caret. Swallowing
        // these three says "we are drawing it", which is true. The messages are
        // still read off the queue before this is reached, so nothing is lost:
        // `WM_IME_CHAR` in particular would otherwise be turned into a
        // `WM_CHAR` and type the committed text a second time.
        WM_IME_STARTCOMPOSITION | WM_IME_COMPOSITION | WM_IME_CHAR => 0,
        // The update region has to be validated or Windows re-sends this
        // forever. Nothing is drawn here: the frame loop presents whole frames.
        WM_PAINT => unsafe {
            let mut paint: PaintStruct = std::mem::zeroed();
            BeginPaint(window, &mut paint);
            EndPaint(window, &paint);
            0
        },
        _ => unsafe { DefWindowProcW(window, message, word, long) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_keys_come_from_their_virtual_codes() {
        assert_eq!(key_for_code(VK_ESCAPE), Some(Key::Escape));
        assert_eq!(key_for_code(VK_UP), Some(Key::Up));
        assert_eq!(key_for_code(0x41), Some(Key::Character('a')), "letters arrive uppercase");
        assert_eq!(key_for_code(0x35), Some(Key::Character('5')));
        assert_eq!(key_for_code(0xFF), None);
    }

    #[test]
    fn a_wheel_notch_scrolls_one_step_in_the_direction_it_turned() {
        assert_eq!(wheel_amount((120i32 as u32 as usize) << 16), WHEEL_STEP);
        assert_eq!(wheel_amount(((-120i32) as u32 as usize) << 16), -WHEEL_STEP);
    }

    #[test]
    fn a_pointer_left_of_the_window_reads_as_negative_not_as_sixty_five_thousand() {
        let window = Window {
            handle: std::ptr::null_mut(),
            open: true,
            size: (100, 100),
            scale: 1.0,
            windowed: Cell::new(None),
        };
        let packed = (-4i16 as u16 as isize) | ((-9i16 as u16 as isize) << 16);
        assert_eq!(window.position_of(packed), Point::new(-4.0, -9.0));
    }

    #[test]
    fn pointer_positions_are_divided_by_the_display_scale() {
        let window = Window {
            handle: std::ptr::null_mut(),
            open: true,
            size: (200, 200),
            scale: 2.0,
            windowed: Cell::new(None),
        };
        let packed = 40isize | (60isize << 16);
        assert_eq!(window.position_of(packed), Point::new(20.0, 30.0));
    }

    #[test]
    fn wide_strings_are_terminated() {
        assert_eq!(wide("hi"), vec![b'h' as u16, b'i' as u16, 0]);
    }
}
