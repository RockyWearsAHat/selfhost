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

use crate::theme::Appearance;
use crate::{Canvas, Event, Key, Modifiers, Point, PointerButton};
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
    fn XFlush(display: Display) -> c_int;
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

// Modifier bits in an event's `state`.
const SHIFT_MASK: c_uint = 1 << 0;
const CONTROL_MASK: c_uint = 1 << 2;
const ALT_MASK: c_uint = 1 << 3;

/// `ZPixmap`, the only image format worth using here.
const Z_PIXMAP: c_int = 2;
/// `PMinSize` in a size hint's flags.
const P_MIN_SIZE: c_long = 1 << 4;

/// How many logical units one press of a wheel button scrolls.
const WHEEL_STEP: f32 = 48.0;

/// The reference density scaling is measured from.
const BASE_DPI: f32 = 96.0;

/// Millimetres per inch, for turning the screen's physical size into a density.
const MM_PER_INCH: f32 = 25.4;

/// A window on X11.
pub(crate) struct Window {
    display: Display,
    window: XWindow,
    context: GraphicsContext,
    visual: Visual,
    depth: c_uint,
    delete_window: Atom,
    open: bool,
    size: (u32, u32),
    scale: f32,
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

            // Without this the window manager's close button kills the
            // connection outright rather than telling us, and the process dies
            // with a command possibly half-written to the daemon.
            let mut delete_window = XInternAtom(display, c"WM_DELETE_WINDOW".as_ptr(), 0);
            XSetWMProtocols(display, window, &mut delete_window, 1);

            XMapWindow(display, window);
            XFlush(display);

            let mut window = Self {
                display,
                window,
                context: XDefaultGC(display, screen),
                visual: XDefaultVisual(display, screen),
                depth: XDefaultDepth(display, screen) as c_uint,
                delete_window,
                open: true,
                size: (width.max(1), height.max(1)),
                scale,
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

    /// Turns one X event into the toolkit's events, if it is one we care about.
    fn translate(&mut self, event: &XEvent, events: &mut Vec<Event>) {
        unsafe {
            match event.kind {
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
                    if message.data[0] as Atom == self.delete_window {
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

            if let Some(named) = key_for_symbol(keysym) {
                events.push(if event.kind == KEY_PRESS {
                    Event::KeyDown { key: named, modifiers }
                } else {
                    Event::KeyUp { key: named, modifiers }
                });
            }

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
