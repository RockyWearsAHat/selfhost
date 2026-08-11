//! The X11 backend: Xlib for the window and input, `XPutImage` for the blit.
//!
//! # Why Xlib and not Wayland
//!
//! Every Wayland desktop ships XWayland, so an X11 client runs on both; the
//! reverse is not true. One backend against the older protocol therefore covers
//! more machines than one against the newer, and it is the smaller of the two by
//! a wide margin — Wayland has no window decorations, so a client draws its own
//! title bar, its own resize borders, and its own close button before it can
//! show anything.
//!
//! # No compositing, no toolkit
//!
//! `XPutImage` copies our pixel buffer straight to the window. The visual we ask
//! for is `TrueColor` at depth 24 with the channels in the order `0xRRGGBB`,
//! which on a little-endian machine is blue, green, red, unused in memory — the
//! same bytes [`Canvas`] holds, so presenting a frame is a copy.
//!
//! # The clipboard is a conversation, not a buffer
//!
//! X11 has nowhere to put copied text. The server remembers only *which window*
//! owns each selection, and every paste anywhere on the desktop is a message to
//! that window asking it to write the text onto the asker's own. So copying here
//! means claiming ownership and then answering questions for as long as we hold
//! it — [`Window::answer_selection_request`] — and pasting means asking and
//! waiting for a reply that a wedged or departed owner may never send.
//!
//! Two consequences worth knowing before reading the code. A paste has a
//! deadline and can come back empty, which is why [`Backend::clipboard_text`] is
//! allowed to answer `Ok(None)` for reasons other than an empty clipboard. And
//! text copied out of this program disappears from the desktop when it exits,
//! because the thing holding the text was the process — a clipboard manager is a
//! program whose whole job is to take ownership from windows that are about to
//! close.
//!
//! # Two things this backend does not do, stated rather than hidden
//!
//! **No input method.** Composition needs XIM, a protocol spoken over a second
//! connection to a separate input-method server. Typing works for anything
//! `XLookupString` can resolve, which is the Latin layouts, and does not work
//! for the writing systems that need an input method. See
//! [`Backend::set_composition_area`].
//!
//! **No accessibility.** That is AT-SPI over D-Bus, an object model of its own
//! with nothing shared with the other two platforms'. A screen reader on Linux
//! finds a `rui` window and is told nothing about what is inside it. See
//! [`Backend::update_accessibility`].
//!
//! Both are gaps rather than decisions, and both are written down here so that
//! the next person meets them in the module header rather than in a bug report.

use crate::accessibility::AccessUpdate;
use crate::theme::Appearance;
use crate::{Canvas, Event, Key, KeyCode, Modifiers, Point, PointerButton, Rect};
use std::cell::RefCell;
use std::ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_void};
use std::time::Duration;

use crate::shell::{Backend, Error, WindowOptions};

type Display = *mut c_void;
type XWindow = c_ulong;
type Atom = c_ulong;
type Visual = *mut c_void;
type GraphicsContext = *mut c_void;

#[link(name = "X11")]
unsafe extern "C" {
    fn XOpenDisplay(name: *const c_char) -> Display;
    fn XCloseDisplay(display: Display) -> c_int;
    fn XDefaultScreen(display: Display) -> c_int;
    fn XRootWindow(display: Display, screen: c_int) -> XWindow;
    fn XDefaultVisual(display: Display, screen: c_int) -> Visual;
    fn XDefaultDepth(display: Display, screen: c_int) -> c_int;
    fn XDefaultGC(display: Display, screen: c_int) -> GraphicsContext;
    fn XWhitePixel(display: Display, screen: c_int) -> c_ulong;
    fn XDisplayWidth(display: Display, screen: c_int) -> c_int;
    fn XDisplayWidthMM(display: Display, screen: c_int) -> c_int;
    fn XConnectionNumber(display: Display) -> c_int;

    fn XCreateSimpleWindow(
        display: Display,
        parent: XWindow,
        x: c_int,
        y: c_int,
        width: c_uint,
        height: c_uint,
        border_width: c_uint,
        border: c_ulong,
        background: c_ulong,
    ) -> XWindow;
    fn XDestroyWindow(display: Display, window: XWindow) -> c_int;
    fn XSelectInput(display: Display, window: XWindow, mask: c_long) -> c_int;
    fn XMapWindow(display: Display, window: XWindow) -> c_int;
    fn XStoreName(display: Display, window: XWindow, name: *const c_char) -> c_int;
    fn XSetWMProtocols(
        display: Display,
        window: XWindow,
        protocols: *mut Atom,
        count: c_int,
    ) -> c_int;
    fn XInternAtom(display: Display, name: *const c_char, only_if_exists: c_int) -> Atom;
    fn XSetWMNormalHints(display: Display, window: XWindow, hints: *const SizeHints);

    fn XPending(display: Display) -> c_int;
    fn XNextEvent(display: Display, event: *mut XEvent) -> c_int;
    fn XCheckTypedWindowEvent(
        display: Display,
        window: XWindow,
        kind: c_int,
        event: *mut XEvent,
    ) -> c_int;
    fn XSendEvent(
        display: Display,
        window: XWindow,
        propagate: c_int,
        mask: c_long,
        event: *mut XEvent,
    ) -> c_int;
    fn XFlush(display: Display) -> c_int;

    // The selection protocol; see the module header.
    fn XSetSelectionOwner(
        display: Display,
        selection: Atom,
        owner: XWindow,
        time: c_ulong,
    ) -> c_int;
    fn XGetSelectionOwner(display: Display, selection: Atom) -> XWindow;
    fn XConvertSelection(
        display: Display,
        selection: Atom,
        target: Atom,
        property: Atom,
        requestor: XWindow,
        time: c_ulong,
    ) -> c_int;
    fn XChangeProperty(
        display: Display,
        window: XWindow,
        property: Atom,
        kind: Atom,
        format: c_int,
        mode: c_int,
        data: *const u8,
        count: c_int,
    ) -> c_int;
    #[allow(clippy::too_many_arguments)]
    fn XGetWindowProperty(
        display: Display,
        window: XWindow,
        property: Atom,
        offset: c_long,
        length: c_long,
        delete: c_int,
        request_type: Atom,
        actual_type: *mut Atom,
        actual_format: *mut c_int,
        count: *mut c_ulong,
        remaining: *mut c_ulong,
        data: *mut *mut u8,
    ) -> c_int;
    fn XLookupString(
        event: *mut XKeyEvent,
        buffer: *mut c_char,
        count: c_int,
        keysym: *mut c_ulong,
        status: *mut c_void,
    ) -> c_int;
    fn XGetWindowAttributes(
        display: Display,
        window: XWindow,
        attributes: *mut WindowAttributes,
    ) -> c_int;

    fn XCreateImage(
        display: Display,
        visual: Visual,
        depth: c_uint,
        format: c_int,
        offset: c_int,
        data: *mut c_char,
        width: c_uint,
        height: c_uint,
        bitmap_pad: c_int,
        bytes_per_line: c_int,
    ) -> *mut XImage;
    fn XPutImage(
        display: Display,
        drawable: XWindow,
        gc: GraphicsContext,
        image: *mut XImage,
        source_x: c_int,
        source_y: c_int,
        destination_x: c_int,
        destination_y: c_int,
        width: c_uint,
        height: c_uint,
    ) -> c_int;
    fn XFree(data: *mut c_void) -> c_int;
}

#[link(name = "c")]
unsafe extern "C" {
    fn poll(descriptors: *mut PollDescriptor, count: c_ulong, timeout: c_int) -> c_int;
}

#[repr(C)]
struct PollDescriptor {
    descriptor: c_int,
    events: i16,
    returned: i16,
}

/// `POLLIN`.
const POLLIN: i16 = 0x001;

/// Only the fields before `data` are read; the rest is opaque padding.
///
/// An `XEvent` is a union of every event structure, and its size is what matters
/// for the caller-allocated buffer `XNextEvent` fills in.
#[repr(C)]
#[derive(Clone, Copy)]
struct XEvent {
    kind: c_int,
    padding: [c_long; 24],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct XKeyEvent {
    kind: c_int,
    serial: c_ulong,
    send_event: c_int,
    display: Display,
    window: XWindow,
    root: XWindow,
    subwindow: XWindow,
    time: c_ulong,
    x: c_int,
    y: c_int,
    x_root: c_int,
    y_root: c_int,
    state: c_uint,
    keycode: c_uint,
    same_screen: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct XButtonEvent {
    kind: c_int,
    serial: c_ulong,
    send_event: c_int,
    display: Display,
    window: XWindow,
    root: XWindow,
    subwindow: XWindow,
    time: c_ulong,
    x: c_int,
    y: c_int,
    x_root: c_int,
    y_root: c_int,
    state: c_uint,
    button: c_uint,
    same_screen: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct XMotionEvent {
    kind: c_int,
    serial: c_ulong,
    send_event: c_int,
    display: Display,
    window: XWindow,
    root: XWindow,
    subwindow: XWindow,
    time: c_ulong,
    x: c_int,
    y: c_int,
    x_root: c_int,
    y_root: c_int,
    state: c_uint,
    is_hint: c_char,
    same_screen: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct XClientMessageEvent {
    kind: c_int,
    serial: c_ulong,
    send_event: c_int,
    display: Display,
    window: XWindow,
    message_type: Atom,
    format: c_int,
    data: [c_long; 5],
}

/// `XSelectionRequestEvent`: another program is asking for our selection.
#[repr(C)]
#[derive(Clone, Copy)]
struct XSelectionRequestEvent {
    kind: c_int,
    serial: c_ulong,
    send_event: c_int,
    display: Display,
    owner: XWindow,
    requestor: XWindow,
    selection: Atom,
    target: Atom,
    property: Atom,
    time: c_ulong,
}

/// `XSelectionEvent`: the answer to such a request, in either direction.
#[repr(C)]
#[derive(Clone, Copy)]
struct XSelectionEvent {
    kind: c_int,
    serial: c_ulong,
    send_event: c_int,
    display: Display,
    requestor: XWindow,
    selection: Atom,
    target: Atom,
    property: Atom,
    time: c_ulong,
}

/// `XSelectionClearEvent`: something else took the selection from us.
#[repr(C)]
#[derive(Clone, Copy)]
struct XSelectionClearEvent {
    kind: c_int,
    serial: c_ulong,
    send_event: c_int,
    display: Display,
    window: XWindow,
    selection: Atom,
    time: c_ulong,
}

#[repr(C)]
struct WindowAttributes {
    x: c_int,
    y: c_int,
    width: c_int,
    height: c_int,
    border_width: c_int,
    depth: c_int,
    visual: Visual,
    root: XWindow,
    class: c_int,
    bit_gravity: c_int,
    win_gravity: c_int,
    backing_store: c_int,
    backing_planes: c_ulong,
    backing_pixel: c_ulong,
    save_under: c_int,
    colormap: c_ulong,
    map_installed: c_int,
    map_state: c_int,
    all_event_masks: c_long,
    your_event_mask: c_long,
    do_not_propagate_mask: c_long,
    override_redirect: c_int,
    screen: *mut c_void,
}

#[repr(C)]
struct XImage {
    width: c_int,
    height: c_int,
    offset: c_int,
    format: c_int,
    data: *mut c_char,
    byte_order: c_int,
    bitmap_unit: c_int,
    bitmap_bit_order: c_int,
    bitmap_pad: c_int,
    depth: c_int,
    bytes_per_line: c_int,
    bits_per_pixel: c_int,
    red_mask: c_ulong,
    green_mask: c_ulong,
    blue_mask: c_ulong,
    // The rest is the object's private data and its function table.
    opaque: [usize; 16],
}

/// The aspect-ratio pair a size hint carries.
///
/// A named struct rather than a tuple because a tuple's layout is not defined,
/// and this crosses into C.
#[repr(C)]
struct Aspect {
    numerator: c_int,
    denominator: c_int,
}

#[repr(C)]
struct SizeHints {
    flags: c_long,
    x: c_int,
    y: c_int,
    width: c_int,
    height: c_int,
    min_width: c_int,
    min_height: c_int,
    max_width: c_int,
    max_height: c_int,
    width_increment: c_int,
    height_increment: c_int,
    min_aspect: Aspect,
    max_aspect: Aspect,
    base_width: c_int,
    base_height: c_int,
    win_gravity: c_int,
}

// Event kinds.
const KEY_PRESS: c_int = 2;
const KEY_RELEASE: c_int = 3;
const BUTTON_PRESS: c_int = 4;
const BUTTON_RELEASE: c_int = 5;
const MOTION_NOTIFY: c_int = 6;
const LEAVE_NOTIFY: c_int = 8;
const SELECTION_CLEAR: c_int = 29;
const SELECTION_REQUEST: c_int = 30;
const SELECTION_NOTIFY: c_int = 31;
const CLIENT_MESSAGE: c_int = 33;

// Event masks.
const KEY_PRESS_MASK: c_long = 1 << 0;
const KEY_RELEASE_MASK: c_long = 1 << 1;
const BUTTON_PRESS_MASK: c_long = 1 << 2;
const BUTTON_RELEASE_MASK: c_long = 1 << 3;
const ENTER_WINDOW_MASK: c_long = 1 << 4;
const LEAVE_WINDOW_MASK: c_long = 1 << 5;
const POINTER_MOTION_MASK: c_long = 1 << 6;
const EXPOSURE_MASK: c_long = 1 << 15;
const STRUCTURE_NOTIFY_MASK: c_long = 1 << 17;
/// `SubstructureNotifyMask`, one of the two a root-window message is sent with.
const SUBSTRUCTURE_NOTIFY_MASK: c_long = 1 << 19;
/// `SubstructureRedirectMask`, the other; together they are what the window
/// manager is listening for on the root window.
const SUBSTRUCTURE_REDIRECT_MASK: c_long = 1 << 20;

// Modifier bits in an event's `state`.
const SHIFT_MASK: c_uint = 1 << 0;
const CONTROL_MASK: c_uint = 1 << 2;
const ALT_MASK: c_uint = 1 << 3;

/// `ZPixmap`, the only image format worth using here.
const Z_PIXMAP: c_int = 2;
/// `PMinSize` in a size hint's flags.
const P_MIN_SIZE: c_long = 1 << 4;

/// `XA_ATOM`, one of the atoms the protocol defines rather than interns.
const XA_ATOM: Atom = 4;
/// `XA_STRING`, the Latin-1 text every X client has always understood.
const XA_STRING: Atom = 31;
/// `CurrentTime`: let the server date the request itself.
const CURRENT_TIME: c_ulong = 0;
/// `AnyPropertyType`: read a property whatever type it turns out to have.
const ANY_PROPERTY_TYPE: Atom = 0;
/// `PropModeReplace`.
const PROP_MODE_REPLACE: c_int = 0;
/// `Success`, which is what every Xlib call answering a status returns on one.
const SUCCESS: c_int = 0;

/// `_NET_WM_STATE_REMOVE` and `_NET_WM_STATE_ADD`, the first word of the
/// message that asks a window manager to change one of a window's states.
const NET_WM_STATE_REMOVE: c_long = 0;
const NET_WM_STATE_ADD: c_long = 1;

/// How many of a window's states are read at once.
///
/// A window manager keeps a handful — maximised, above, sticky, full screen —
/// and thirty-two is far past any of them while staying a single read.
const WINDOW_STATE_WORDS: c_long = 32;

/// How many words of a selection are read at once.
///
/// A quarter of a million 32-bit words is a megabyte of text — past anything a
/// person pastes into a field, and well under the point where the owner would
/// switch to sending it in pieces. See [`Window::read_selection`].
const SELECTION_WORDS: c_long = 262_144;

/// How many times the clipboard is looked at before giving up on an answer.
///
/// Reading the clipboard on X11 is asking another program a question, and a
/// program that is busy, wedged, or has just exited will not answer at all. The
/// budget is counted in attempts rather than measured against a clock, and the
/// worst case is a fifth of a second of a paste doing nothing.
const SELECTION_ATTEMPTS: usize = 40;

/// How long each of those attempts waits for the socket, in milliseconds.
const SELECTION_WAIT: c_int = 5;

/// How many logical units one press of a wheel button scrolls.
const WHEEL_STEP: f32 = 48.0;

/// The reference density scaling is measured from.
const BASE_DPI: f32 = 96.0;

/// Millimetres per inch, for turning the screen's physical size into a density.
const MM_PER_INCH: f32 = 25.4;

/// The atoms this backend interns, gathered because they travel together.
///
/// Interned once at startup rather than per use: `XInternAtom` is a round trip
/// to the server, and a paste that made four of them before it could ask for the
/// text would be four times slower for no reason.
#[derive(Debug, Clone, Copy)]
struct Atoms {
    /// `WM_DELETE_WINDOW`: the close button, reported rather than fatal.
    delete_window: Atom,
    /// `CLIPBOARD`: the one copy and paste use, as opposed to `PRIMARY`.
    clipboard: Atom,
    /// `UTF8_STRING`: the text encoding to ask for and to offer.
    utf8_string: Atom,
    /// `TARGETS`: the question "what forms can you supply this in?"
    targets: Atom,
    /// `INCR`: an answer too big to send at once, which we decline to assemble.
    incremental: Atom,
    /// The property on our own window that answers are delivered into.
    delivery: Atom,
    /// `_NET_WM_STATE`: the list of states the window manager has this window in.
    window_state: Atom,
    /// `_NET_WM_STATE_FULLSCREEN`: the one of those states this backend asks for.
    state_fullscreen: Atom,
}

/// A window on X11.
pub(crate) struct Window {
    display: Display,
    window: XWindow,
    context: GraphicsContext,
    visual: Visual,
    depth: c_uint,
    atoms: Atoms,
    open: bool,
    size: (u32, u32),
    scale: f32,
    /// The text this window has put on the clipboard, while it still owns it.
    ///
    /// X11 has no clipboard buffer to write into. Copying means telling the
    /// server that this window *is* the clipboard, and then answering, one by
    /// one, every program that asks what it holds — so the text has to stay
    /// here for as long as the answer might be wanted. A [`RefCell`] because
    /// answering happens through `&self`: see [`Backend::set_clipboard_text`].
    owned: RefCell<Option<String>>,
}

impl Backend for Window {
    fn open(options: &WindowOptions) -> Result<Self, Error> {
        unsafe {
            let display = XOpenDisplay(std::ptr::null());
            if display.is_null() {
                return Err(Error::Platform(
                    "cannot open an X display; a console needs a graphical session, so run it \
                     on your own machine and tunnel to the daemon"
                        .into(),
                ));
            }

            let screen = XDefaultScreen(display);
            let root = XRootWindow(display, screen);
            let scale = density_scale(display, screen);

            let width = (options.width * scale) as c_uint;
            let height = (options.height * scale) as c_uint;
            let window = XCreateSimpleWindow(
                display,
                root,
                0,
                0,
                width.max(1),
                height.max(1),
                0,
                0,
                XWhitePixel(display, screen),
            );

            let title = std::ffi::CString::new(options.title.as_str())
                .unwrap_or_else(|_| c"rui".to_owned());
            XStoreName(display, window, title.as_ptr());

            let mut hints: SizeHints = std::mem::zeroed();
            hints.flags = P_MIN_SIZE;
            hints.min_width = (options.min_width * scale) as c_int;
            hints.min_height = (options.min_height * scale) as c_int;
            XSetWMNormalHints(display, window, &hints);

            XSelectInput(
                display,
                window,
                KEY_PRESS_MASK
                    | KEY_RELEASE_MASK
                    | BUTTON_PRESS_MASK
                    | BUTTON_RELEASE_MASK
                    | ENTER_WINDOW_MASK
                    | LEAVE_WINDOW_MASK
                    | POINTER_MOTION_MASK
                    | EXPOSURE_MASK
                    | STRUCTURE_NOTIFY_MASK,
            );

            let atoms = Atoms {
                delete_window: XInternAtom(display, c"WM_DELETE_WINDOW".as_ptr(), 0),
                clipboard: XInternAtom(display, c"CLIPBOARD".as_ptr(), 0),
                utf8_string: XInternAtom(display, c"UTF8_STRING".as_ptr(), 0),
                targets: XInternAtom(display, c"TARGETS".as_ptr(), 0),
                incremental: XInternAtom(display, c"INCR".as_ptr(), 0),
                delivery: XInternAtom(display, c"RUI_SELECTION".as_ptr(), 0),
                window_state: XInternAtom(display, c"_NET_WM_STATE".as_ptr(), 0),
                state_fullscreen: XInternAtom(display, c"_NET_WM_STATE_FULLSCREEN".as_ptr(), 0),
            };

            // Without this the window manager's close button kills the
            // connection outright rather than telling us, and the process dies
            // with a command possibly half-written to the daemon.
            let mut delete_window = atoms.delete_window;
            XSetWMProtocols(display, window, &mut delete_window, 1);

            XMapWindow(display, window);
            XFlush(display);

            let mut window = Self {
                display,
                window,
                context: XDefaultGC(display, screen),
                visual: XDefaultVisual(display, screen),
                depth: XDefaultDepth(display, screen) as c_uint,
                atoms,
                open: true,
                size: (width.max(1), height.max(1)),
                scale,
                owned: RefCell::new(None),
            };
            window.refresh_geometry();
            Ok(window)
        }
    }

    // X11 never takes the loop away: a resize arrives as a `ConfigureNotify`
    // like any other event, so `redraw` has nothing to be called for.
    fn pump(
        &mut self,
        timeout: Duration,
        events: &mut Vec<Event>,
        _redraw: &mut dyn FnMut(&Self),
    ) -> Result<(), Error> {
        unsafe {
            // Xlib buffers events itself, so waiting on the socket is only
            // correct once what has already been read has been drained.
            if XPending(self.display) == 0 {
                let mut descriptor = PollDescriptor {
                    descriptor: XConnectionNumber(self.display),
                    events: POLLIN,
                    returned: 0,
                };
                let milliseconds = timeout.as_millis().min(c_int::MAX as u128) as c_int;
                poll(&mut descriptor, 1, milliseconds);
            }

            while XPending(self.display) > 0 {
                let mut event: XEvent = std::mem::zeroed();
                XNextEvent(self.display, &mut event);
                self.translate(&event, events);
            }

            self.refresh_geometry();
        }
        Ok(())
    }

    fn surface(&self) -> (u32, u32, f32) {
        (self.size.0.max(1), self.size.1.max(1), self.scale)
    }

    fn appearance(&self) -> Appearance {
        // X has no standard place to ask. The desktop environments that do have
        // an answer put it in one of these, so this reads them and otherwise
        // assumes light — the same assumption a missing setting has always meant.
        for variable in ["GTK_THEME", "QT_STYLE_OVERRIDE", "SELFHOST_APPEARANCE"] {
            if let Ok(value) = std::env::var(variable) {
                if value.to_ascii_lowercase().contains("dark") {
                    return Appearance::Dark;
                }
            }
        }
        Appearance::Light
    }

    fn present(&self, canvas: &Canvas) -> Result<(), Error> {
        let width = canvas.width();
        let height = canvas.height();
        if width == 0 || height == 0 {
            return Ok(());
        }

        unsafe {
            let image = XCreateImage(
                self.display,
                self.visual,
                self.depth,
                Z_PIXMAP,
                0,
                canvas.pixels().as_ptr() as *mut c_char,
                width,
                height,
                32,
                (width * 4) as c_int,
            );
            if image.is_null() {
                return Err(Error::Platform("XCreateImage failed".into()));
            }

            XPutImage(
                self.display,
                self.window,
                self.context,
                image,
                0,
                0,
                0,
                0,
                width,
                height,
            );

            // The image borrows the canvas's pixels, which the canvas owns.
            // Detaching them before freeing the image is what stops Xlib from
            // calling `free` on a Rust allocation.
            (*image).data = std::ptr::null_mut();
            XFree(image.cast::<c_void>());
            XFlush(self.display);
        }
        Ok(())
    }

    fn is_open(&self) -> bool {
        self.open
    }

    fn is_fullscreen(&self) -> bool {
        // Read from `_NET_WM_STATE` rather than remembered, because the window
        // manager is the one that decides: it may have declined the request,
        // and the person may have used its own key to do this without us.
        unsafe {
            let mut kind: Atom = 0;
            let mut format: c_int = 0;
            let mut count: c_ulong = 0;
            let mut remaining: c_ulong = 0;
            let mut data: *mut u8 = std::ptr::null_mut();
            let status = XGetWindowProperty(
                self.display,
                self.window,
                self.atoms.window_state,
                0,
                WINDOW_STATE_WORDS,
                0,
                XA_ATOM,
                &mut kind,
                &mut format,
                &mut count,
                &mut remaining,
                &mut data,
            );
            if status != SUCCESS || data.is_null() {
                return false;
            }
            // A property of atoms arrives as an array of `long`, whatever the
            // format says: that is the X client library's own convention for a
            // 32-bit property, and reading it as `u32` would halve it on a
            // 64-bit machine.
            let states = std::slice::from_raw_parts(data.cast::<c_ulong>(), count as usize);
            let filling = states.contains(&self.atoms.state_fullscreen);
            XFree(data.cast::<c_void>());
            filling
        }
    }

    fn set_fullscreen(&self, filling: bool) -> Result<(), Error> {
        // The state of a mapped window is changed by asking the window manager,
        // never by writing the property: a client that sets `_NET_WM_STATE`
        // itself is writing down an answer only the window manager can give,
        // and a manager that honours the specification will overwrite it.
        unsafe {
            let mut event: XEvent = std::mem::zeroed();
            let message = &mut *(&raw mut event).cast::<XClientMessageEvent>();
            message.kind = CLIENT_MESSAGE;
            message.display = self.display;
            message.window = self.window;
            message.message_type = self.atoms.window_state;
            message.format = 32;
            message.data[0] = if filling { NET_WM_STATE_ADD } else { NET_WM_STATE_REMOVE };
            message.data[1] = self.atoms.state_fullscreen as c_long;
            // The second state is none, and the source is a normal application
            // rather than a pager — both are fields of the message the
            // specification defines.
            message.data[3] = 1;
            let root = XRootWindow(self.display, XDefaultScreen(self.display));
            XSendEvent(
                self.display,
                root,
                0,
                SUBSTRUCTURE_NOTIFY_MASK | SUBSTRUCTURE_REDIRECT_MASK,
                &mut event,
            );
            XFlush(self.display);
        }
        Ok(())
    }

    /// Asks whoever owns the clipboard what it holds, and waits for the answer.
    ///
    /// The whole of the difference between X11 and every other platform here:
    /// there is no buffer to read. The server only remembers *which window* owns
    /// the selection, so this sends that window a request and waits for it to
    /// send the text back through a property on ours.
    ///
    /// `Ok(None)` covers every ordinary way that can come to nothing — nobody
    /// owns the clipboard, the owner has no text form of it, the owner declined,
    /// the owner never answered, or the answer was too large to send in one
    /// piece. None of those is a failure of this program, and all of them mean
    /// the same thing to a field: there is nothing to paste.
    fn clipboard_text(&self) -> Result<Option<String>, Error> {
        unsafe {
            if XGetSelectionOwner(self.display, self.atoms.clipboard) == 0 {
                return Ok(None);
            }
            XConvertSelection(
                self.display,
                self.atoms.clipboard,
                self.atoms.utf8_string,
                self.atoms.delivery,
                self.window,
                CURRENT_TIME,
            );
            XFlush(self.display);

            for _ in 0..SELECTION_ATTEMPTS {
                // Requests from other programs — including the one this window
                // sends itself when it owns the clipboard — are answered while
                // waiting. Leaving them for the frame loop would deadlock that
                // one case: the answer we are waiting for is one we owe.
                self.answer_pending_requests();

                let mut event: XEvent = std::mem::zeroed();
                if XCheckTypedWindowEvent(self.display, self.window, SELECTION_NOTIFY, &mut event)
                    != 0
                {
                    let notify = &*(&raw const event).cast::<XSelectionEvent>();
                    // A property of `None` is the owner saying it cannot supply
                    // the selection in the form that was asked for.
                    if notify.property == 0 {
                        return Ok(None);
                    }
                    return Ok(self.read_selection(notify.property));
                }

                let mut descriptor = PollDescriptor {
                    descriptor: XConnectionNumber(self.display),
                    events: POLLIN,
                    returned: 0,
                };
                poll(&mut descriptor, 1, SELECTION_WAIT);
                // Moves whatever arrived on the socket into Xlib's own queue,
                // which is where the check above looks.
                XPending(self.display);
            }
            Ok(None)
        }
    }

    /// Takes ownership of the clipboard and remembers what to answer with.
    ///
    /// Copying on X11 is not writing anywhere. It is telling the server that
    /// this window now *is* the clipboard, after which every program that wants
    /// the text asks this one for it — see [`Window::answer_selection_request`].
    /// The text therefore lives here until something else takes ownership, and
    /// disappears when this program exits, which is why a desktop that keeps a
    /// clipboard after the program that filled it has closed is running a
    /// clipboard manager to do exactly that.
    fn set_clipboard_text(&self, text: &str) -> Result<(), Error> {
        *self.owned.borrow_mut() = Some(text.to_owned());
        unsafe {
            XSetSelectionOwner(self.display, self.atoms.clipboard, self.window, CURRENT_TIME);
            XFlush(self.display);
            if XGetSelectionOwner(self.display, self.atoms.clipboard) != self.window {
                *self.owned.borrow_mut() = None;
                return Err(Error::Platform("the X server would not hand over the clipboard".into()));
            }
        }
        Ok(())
    }

    /// Nothing: this backend has no input method, so there is nothing to place.
    ///
    /// Composing on X11 means XIM — a protocol spoken to a separate input-method
    /// server over its own connection, with its own event filtering and its own
    /// callbacks, which is a backend's worth of work on its own. It is not done
    /// here, and this says so rather than pretending: on this platform a
    /// keystroke is whatever `XLookupString` makes of it, dead keys included if
    /// the layout resolves them itself, and there is no way to type Japanese,
    /// Chinese, or Korean into a `rui` window.
    fn set_composition_area(&self, _area: Option<Rect>) -> Result<(), Error> {
        Ok(())
    }

    /// Nothing: this backend does not speak to an assistive technology.
    ///
    /// The way to on this platform is AT-SPI, which is a D-Bus service with an
    /// object model of its own — a whole second interface to implement and no
    /// part of it shared with the two that are. It is not done, and this says so
    /// rather than leaving a method that looks implemented: a screen reader on
    /// Linux finds a `rui` window and is told nothing about what is in it.
    ///
    /// Accepting the update rather than refusing it is deliberate. A refusal
    /// would end the frame loop, which would mean a platform without a screen
    /// reader could not run a program at all.
    fn update_accessibility(&self, _update: &AccessUpdate) -> Result<(), Error> {
        Ok(())
    }
}

impl Window {
    /// Re-reads the window's size.
    fn refresh_geometry(&mut self) {
        unsafe {
            let mut attributes: WindowAttributes = std::mem::zeroed();
            if XGetWindowAttributes(self.display, self.window, &mut attributes) != 0
                && attributes.width > 0
                && attributes.height > 0
            {
                self.size = (attributes.width as u32, attributes.height as u32);
            }
        }
    }

    /// Reads a delivered selection off our own window, and clears it away.
    ///
    /// The property is deleted as it is read, which is how the owner learns the
    /// transfer finished. Leaving it would also leave the next paste reading the
    /// last one.
    fn read_selection(&self, property: Atom) -> Option<String> {
        unsafe {
            let mut kind: Atom = 0;
            let mut format: c_int = 0;
            let mut count: c_ulong = 0;
            let mut remaining: c_ulong = 0;
            let mut data: *mut u8 = std::ptr::null_mut();
            let status = XGetWindowProperty(
                self.display,
                self.window,
                property,
                0,
                SELECTION_WORDS,
                1,
                ANY_PROPERTY_TYPE,
                &mut kind,
                &mut format,
                &mut count,
                &mut remaining,
                &mut data,
            );
            if status != SUCCESS || data.is_null() {
                return None;
            }

            // `INCR` means the owner wants to send it a piece at a time, which
            // is a conversation of its own — the requestor deletes the property
            // and the owner refills it, over and over, until it sends an empty
            // one. Declining is honest for a field someone is pasting a line
            // into; a megabyte of text is not what that is.
            let text = if kind == self.atoms.incremental || format != 8 {
                None
            } else {
                let bytes = std::slice::from_raw_parts(data, count as usize);
                Some(String::from_utf8_lossy(bytes).into_owned())
            };
            XFree(data.cast::<c_void>());
            text
        }
    }

    /// Answers every selection request already waiting in the queue.
    fn answer_pending_requests(&self) {
        loop {
            let mut event: XEvent = unsafe { std::mem::zeroed() };
            let waiting = unsafe {
                XCheckTypedWindowEvent(self.display, self.window, SELECTION_REQUEST, &mut event)
            };
            if waiting == 0 {
                return;
            }
            // SAFETY: the server filled the union's selection-request arm,
            // which is what asking for that event kind means.
            self.answer_selection_request(unsafe {
                &*(&raw const event).cast::<XSelectionRequestEvent>()
            });
        }
    }

    /// Hands our copied text to a program that has asked for it.
    ///
    /// Every paste anywhere on the desktop, for as long as this window owns the
    /// clipboard, arrives here.
    fn answer_selection_request(&self, request: &XSelectionRequestEvent) {
        // A requestor from before the conventions were written asks for the
        // answer under the target's own name. Honouring it costs one line.
        let property = if request.property == 0 { request.target } else { request.property };
        let supplied = self.supply_selection(request, property);

        unsafe {
            let mut event: XEvent = std::mem::zeroed();
            let notify = &mut *(&raw mut event).cast::<XSelectionEvent>();
            notify.kind = SELECTION_NOTIFY;
            notify.display = self.display;
            notify.requestor = request.requestor;
            notify.selection = request.selection;
            notify.target = request.target;
            // `None` for the property is how a refusal is spelled.
            notify.property = if supplied { property } else { 0 };
            notify.time = request.time;
            XSendEvent(self.display, request.requestor, 0, 0, &mut event);
            XFlush(self.display);
        }
    }

    /// Writes what a requestor asked for onto its window, if we have it.
    ///
    /// Answers whether anything was written, which is what decides between an
    /// answer and a refusal.
    fn supply_selection(&self, request: &XSelectionRequestEvent, property: Atom) -> bool {
        if request.target == self.atoms.targets {
            // The conventional first question: what forms can you supply this
            // in? Answering `TARGETS` is what makes a paste into a program that
            // wants something else fail politely rather than hang.
            let targets = [self.atoms.targets, self.atoms.utf8_string, XA_STRING];
            unsafe {
                XChangeProperty(
                    self.display,
                    request.requestor,
                    property,
                    XA_ATOM,
                    32,
                    PROP_MODE_REPLACE,
                    targets.as_ptr().cast::<u8>(),
                    targets.len() as c_int,
                );
            }
            return true;
        }

        // `STRING` is Latin-1 by the letter of the protocol and UTF-8 by the
        // practice of every program written since; a requestor that wanted the
        // letter of it asks for `TEXT` or a specific encoding, and gets a
        // refusal.
        if request.target != self.atoms.utf8_string && request.target != XA_STRING {
            return false;
        }
        let owned = self.owned.borrow();
        let Some(text) = owned.as_deref() else {
            return false;
        };
        unsafe {
            XChangeProperty(
                self.display,
                request.requestor,
                property,
                request.target,
                8,
                PROP_MODE_REPLACE,
                text.as_ptr(),
                text.len() as c_int,
            );
        }
        true
    }

    /// Turns one X event into the toolkit's events, if it is one we care about.
    fn translate(&mut self, event: &XEvent, events: &mut Vec<Event>) {
        unsafe {
            match event.kind {
                SELECTION_REQUEST => {
                    self.answer_selection_request(
                        &*(event as *const XEvent).cast::<XSelectionRequestEvent>(),
                    );
                }
                SELECTION_CLEAR => {
                    let clear = &*(event as *const XEvent).cast::<XSelectionClearEvent>();
                    // Something else has become the clipboard. What we were
                    // holding to answer with is no longer anybody's business.
                    if clear.selection == self.atoms.clipboard {
                        *self.owned.borrow_mut() = None;
                    }
                }
                MOTION_NOTIFY => {
                    let motion = &*(event as *const XEvent).cast::<XMotionEvent>();
                    events.push(Event::PointerMoved(self.position(motion.x, motion.y)));
                }
                LEAVE_NOTIFY => events.push(Event::PointerLeft),
                BUTTON_PRESS | BUTTON_RELEASE => {
                    let button = &*(event as *const XEvent).cast::<XButtonEvent>();
                    let position = self.position(button.x, button.y);
                    // X reports the wheel as buttons four to seven rather than
                    // as an axis, so scrolling arrives here and not as motion.
                    match button.button {
                        4 => {
                            if event.kind == BUTTON_PRESS {
                                events.push(Event::Scrolled { x: 0.0, y: WHEEL_STEP });
                            }
                        }
                        5 => {
                            if event.kind == BUTTON_PRESS {
                                events.push(Event::Scrolled { x: 0.0, y: -WHEEL_STEP });
                            }
                        }
                        6 => {
                            if event.kind == BUTTON_PRESS {
                                events.push(Event::Scrolled { x: WHEEL_STEP, y: 0.0 });
                            }
                        }
                        7 => {
                            if event.kind == BUTTON_PRESS {
                                events.push(Event::Scrolled { x: -WHEEL_STEP, y: 0.0 });
                            }
                        }
                        other => {
                            let pointer = match other {
                                1 => PointerButton::Primary,
                                2 => PointerButton::Middle,
                                3 => PointerButton::Secondary,
                                _ => return,
                            };
                            events.push(if event.kind == BUTTON_PRESS {
                                Event::PointerDown { position, button: pointer }
                            } else {
                                Event::PointerUp { position, button: pointer }
                            });
                        }
                    }
                }
                KEY_PRESS | KEY_RELEASE => self.translate_key(event, events),
                CLIENT_MESSAGE => {
                    let message = &*(event as *const XEvent).cast::<XClientMessageEvent>();
                    if message.data[0] as Atom == self.atoms.delete_window {
                        events.push(Event::CloseRequested);
                        self.open = false;
                    }
                }
                _ => {}
            }
        }
    }

    /// Turns a key event into a key press and, for a press, any text it typed.
    fn translate_key(&self, event: &XEvent, events: &mut Vec<Event>) {
        unsafe {
            let mut key = *(event as *const XEvent).cast::<XKeyEvent>();
            let modifiers = modifiers_of(key.state);

            let mut buffer = [0u8; 32];
            let mut keysym: c_ulong = 0;
            let written = XLookupString(
                &mut key,
                buffer.as_mut_ptr().cast::<c_char>(),
                buffer.len() as c_int,
                &mut keysym,
                std::ptr::null_mut(),
            );

            // The keysym is what the layout made of the key and the hardware
            // keycode is the key itself, which is exactly the difference between
            // what a widget wants and what a keystroke forwarded to another
            // machine wants. Both go out, and the event is sent even when the
            // keysym names nothing this library has a word for — the function
            // row, the keypad, either half of a modifier pair.
            //
            // An X11 keycode is the evdev scancode plus eight, and means nothing
            // to Windows or macOS; see [`KeyCode`](crate::KeyCode).
            let named = key_for_symbol(keysym);
            let code = Some(KeyCode::new(key.keycode));
            events.push(if event.kind == KEY_PRESS {
                Event::KeyDown { key: named, code, modifiers }
            } else {
                Event::KeyUp { key: named, code, modifiers }
            });

            // A key held with the accelerator is a command, not typing.
            if event.kind != KEY_PRESS || modifiers.command || written <= 0 {
                return;
            }
            let typed: String = String::from_utf8_lossy(&buffer[..written as usize])
                .chars()
                .filter(|character| !character.is_control())
                .collect();
            if !typed.is_empty() {
                events.push(Event::Text(typed));
            }
        }
    }

    /// A position in the window, in logical units.
    fn position(&self, x: c_int, y: c_int) -> Point {
        Point::new(x as f32 / self.scale, y as f32 / self.scale)
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        unsafe {
            XDestroyWindow(self.display, self.window);
            XCloseDisplay(self.display);
        }
    }
}

/// The display's scale factor, worked out from its physical size.
///
/// X has no notion of a backing scale, so it is derived: pixels across divided
/// by inches across gives a density, and that over the traditional ninety-six
/// gives a factor. Rounded to a whole number, because a fractional factor makes
/// every hairline land between pixels, and clamped, because a screen that
/// misreports its physical size — which projectors and virtual displays do —
/// would otherwise produce an interface too large or too small to use.
fn density_scale(display: Display, screen: c_int) -> f32 {
    unsafe {
        let pixels = XDisplayWidth(display, screen) as f32;
        let millimetres = XDisplayWidthMM(display, screen) as f32;
        if pixels <= 0.0 || millimetres <= 0.0 {
            return 1.0;
        }
        let dpi = pixels / (millimetres / MM_PER_INCH);
        (dpi / BASE_DPI).round().clamp(1.0, 3.0)
    }
}

/// The modifiers an event's state word describes.
fn modifiers_of(state: c_uint) -> Modifiers {
    let control = state & CONTROL_MASK != 0;
    Modifiers {
        shift: state & SHIFT_MASK != 0,
        control,
        alt: state & ALT_MASK != 0,
        // Control is the accelerator here, as it is on Windows.
        command: control,
    }
}

/// The named key an X keysym stands for, if it is one.
fn key_for_symbol(keysym: c_ulong) -> Option<Key> {
    Some(match keysym {
        0xff08 => Key::Backspace,
        0xff09 => Key::Tab,
        0xff0d | 0xff8d => Key::Enter,
        0xff1b => Key::Escape,
        0xff50 => Key::Home,
        0xff51 => Key::Left,
        0xff52 => Key::Up,
        0xff53 => Key::Right,
        0xff54 => Key::Down,
        0xff55 => Key::PageUp,
        0xff56 => Key::PageDown,
        0xff57 => Key::End,
        0xffff => Key::Delete,
        0x0020 => Key::Space,
        // Latin-1 covers the ASCII letters and digits, whose keysym is their
        // character code — which is what a shortcut is written against.
        0x0021..=0x00ff => {
            let character = char::from_u32(keysym as u32)?;
            Key::Character(character.to_lowercase().next().unwrap_or(character))
        }
        _ => return None,
    })
}

/// The text of a C string, for error reporting.
#[allow(dead_code)]
fn from_c(text: *const c_char) -> String {
    if text.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(text) }.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_keys_come_from_their_keysyms() {
        assert_eq!(key_for_symbol(0xff1b), Some(Key::Escape));
        assert_eq!(key_for_symbol(0xff52), Some(Key::Up));
        assert_eq!(key_for_symbol(0xff8d), Some(Key::Enter), "the keypad's Enter");
        assert_eq!(key_for_symbol(0x0041), Some(Key::Character('a')));
        assert_eq!(key_for_symbol(0x0035), Some(Key::Character('5')));
        assert_eq!(key_for_symbol(0xdeadbeef), None);
    }

    #[test]
    fn control_is_reported_as_the_accelerator() {
        let modifiers = modifiers_of(CONTROL_MASK);
        assert!(modifiers.control && modifiers.command);
        assert!(modifiers.command_only());
    }

    #[test]
    fn every_modifier_is_recognised_separately() {
        let all = modifiers_of(SHIFT_MASK | CONTROL_MASK | ALT_MASK);
        assert!(all.shift && all.control && all.alt);
        assert!(modifiers_of(0).is_empty());
    }
}
