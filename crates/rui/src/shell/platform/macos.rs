//! The macOS backend: AppKit for the window and input, Core Graphics for the blit.
//!
//! # No Objective-C classes are defined here
//!
//! The usual way to draw with AppKit is to subclass `NSView` and override
//! `drawRect:`, which from Rust means building a class at run time and
//! installing function pointers as methods. This does neither. The window's
//! content view is given a `CALayer`, and each frame's pixels become a
//! `CGImage` that is handed to the layer as its contents — so the compositor
//! does the drawing and there is nothing to subclass.
//!
//! Input is read the same way. Rather than overriding `mouseDown:` and its
//! dozen relatives, the loop pulls events out of the queue itself with
//! `nextEventMatchingMask:untilDate:inMode:dequeue:` and reads them directly.
//! Events that AppKit needs — window dragging, the close button, menu
//! shortcuts — are handed back to it; key presses are not, because forwarding a
//! key nothing handles makes the system beep.
//!
//! What is left is a few hundred lines of message sends and no run-time class
//! machinery at all.

use crate::theme::Appearance;
use crate::{Canvas, Event, Key, Modifiers, Point, PointerButton};
use std::cell::Cell;
use std::ffi::{CStr, c_char, c_void};
use std::time::Duration;

use crate::shell::{Backend, Error, WindowOptions};

/// An Objective-C object.
type Object = *mut c_void;
/// A selector: Objective-C's interned method name.
type Sel = *const c_void;

// SAFETY-relevant note for every declaration below: these are the platform's own
// C and Objective-C entry points, declared with the signatures Apple documents.
unsafe extern "C" {
    fn objc_getClass(name: *const c_char) -> Object;
    fn sel_registerName(name: *const c_char) -> Sel;
    fn objc_autoreleasePoolPush() -> *mut c_void;
    fn objc_autoreleasePoolPop(pool: *mut c_void);

    /// Objective-C's dispatch entry point.
    ///
    /// Declared without arguments and transmuted to the exact signature of each
    /// call. It cannot be declared variadic: on Apple silicon a variadic call
    /// passes arguments differently from a normal one, so a variadic
    /// declaration produces calls the runtime misreads.
    fn objc_msgSend();

    /// The same, for messages returning a struct too large for registers.
    ///
    /// Only x86_64 has this split. On aarch64 every return goes through
    /// `objc_msgSend`.
    #[cfg(target_arch = "x86_64")]
    fn objc_msgSend_stret();

    fn CGColorSpaceCreateDeviceRGB() -> *mut c_void;
    fn CGColorSpaceRelease(space: *mut c_void);
    fn CGDataProviderCreateWithCFData(data: *const c_void) -> *mut c_void;
    fn CGDataProviderRelease(provider: *mut c_void);
    #[allow(clippy::too_many_arguments)]
    fn CGImageCreate(
        width: usize,
        height: usize,
        bits_per_component: usize,
        bits_per_pixel: usize,
        bytes_per_row: usize,
        space: *mut c_void,
        bitmap_info: u32,
        provider: *mut c_void,
        decode: *const f64,
        should_interpolate: bool,
        intent: u32,
    ) -> *mut c_void;
    fn CGImageRelease(image: *mut c_void);
    fn CFDataCreate(allocator: *const c_void, bytes: *const u8, length: isize) -> *const c_void;
    fn CFRelease(object: *const c_void);

    fn CFRunLoopGetCurrent() -> *mut c_void;
    fn CFRunLoopObserverCreate(
        allocator: *const c_void,
        activities: u64,
        repeats: bool,
        order: isize,
        callout: extern "C" fn(*mut c_void, u64, *mut c_void),
        context: *mut ObserverContext,
    ) -> *mut c_void;
    fn CFRunLoopAddObserver(loop_: *mut c_void, observer: *mut c_void, mode: *const c_void);
    /// The set of modes AppKit considers "the loop is running normally".
    ///
    /// It contains event tracking, which is the one that matters here: a live
    /// resize runs the loop in `NSEventTrackingRunLoopMode`, and an observer
    /// registered only for the default mode would not fire once during a drag.
    static kCFRunLoopCommonModes: *const c_void;
}

/// `CFRunLoopObserverContext`: what the run loop hands back to a callback.
///
/// The three function pointers are the memory-management hooks, and all three
/// are null here — the `info` pointer refers to something owned by the window
/// and outliving the observer, so there is nothing for the run loop to retain.
#[repr(C)]
struct ObserverContext {
    version: isize,
    info: *mut c_void,
    retain: *const c_void,
    release: *const c_void,
    copy_description: *const c_void,
}

/// `kCFRunLoopBeforeWaiting`: the loop has run everything and is about to sleep.
///
/// The right moment to put a frame on screen — everything that was going to
/// change this turn has changed, and nothing is waiting behind us.
const RUN_LOOP_BEFORE_WAITING: u64 = 1 << 5;

/// `kCFRunLoopExit`: a nested loop is finishing.
///
/// Included so the last frame of a resize is the one at the final size, rather
/// than whatever the drag happened to be at when the loop last slept.
const RUN_LOOP_EXIT: u64 = 1 << 7;

/// `NSViewLayerContentsRedrawOnSetNeedsDisplay`.
///
/// The default for a layer-backed view is to redraw *during* a resize, which
/// for a view that draws nothing means AppKit scaling the layer's contents to
/// each intermediate size. We present a frame at exactly the new size instead,
/// so the scaling is pure cost and pure blur.
const REDRAW_ON_SET_NEEDS_DISPLAY: i64 = 2;

/// `NSViewLayerContentsPlacementTopLeft`.
///
/// Where a frame sits when it and the view disagree about size, which happens
/// for the instant between the view resizing and the next frame arriving.
/// Pinned to the top left, that instant shows correct pixels in part of the
/// window and background in the rest; scaled — the default — it shows every
/// pixel in the window in the wrong place.
const PLACEMENT_TOP_LEFT: i64 = 11;

// The frameworks the entry points above live in. One empty block each, because
// stacking several `link` attributes on a single block declares the same
// linkage repeatedly rather than four different ones.
#[link(name = "AppKit", kind = "framework")]
unsafe extern "C" {}
#[link(name = "Foundation", kind = "framework")]
unsafe extern "C" {}
#[link(name = "CoreGraphics", kind = "framework")]
unsafe extern "C" {}
#[link(name = "QuartzCore", kind = "framework")]
unsafe extern "C" {}

/// A point or a size in Core Graphics' coordinates.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct CgPoint {
    x: f64,
    y: f64,
}

/// A width and a height in Core Graphics' coordinates.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct CgSize {
    width: f64,
    height: f64,
}

/// A rectangle in Core Graphics' coordinates.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct CgRect {
    origin: CgPoint,
    size: CgSize,
}

/// The class with this name.
fn class(name: &CStr) -> Object {
    unsafe { objc_getClass(name.as_ptr()) }
}

/// The selector with this name.
fn sel(name: &CStr) -> Sel {
    unsafe { sel_registerName(name.as_ptr()) }
}

/// Sends a message taking no arguments.
unsafe fn send<R>(receiver: Object, selector: Sel) -> R {
    let dispatch: unsafe extern "C" fn(Object, Sel) -> R =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { dispatch(receiver, selector) }
}

/// Sends a message taking one argument.
unsafe fn send1<R, A>(receiver: Object, selector: Sel, a: A) -> R {
    let dispatch: unsafe extern "C" fn(Object, Sel, A) -> R =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { dispatch(receiver, selector, a) }
}

/// Sends a message taking three arguments.
unsafe fn send3<R, A, B, C>(receiver: Object, selector: Sel, a: A, b: B, c: C) -> R {
    let dispatch: unsafe extern "C" fn(Object, Sel, A, B, C) -> R =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { dispatch(receiver, selector, a, b, c) }
}

/// Sends a message taking four arguments.
unsafe fn send4<R, A, B, C, D>(receiver: Object, selector: Sel, a: A, b: B, c: C, d: D) -> R {
    let dispatch: unsafe extern "C" fn(Object, Sel, A, B, C, D) -> R =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { dispatch(receiver, selector, a, b, c, d) }
}

/// Sends a message that answers a rectangle.
///
/// Split out because a 32-byte struct return goes through a different dispatch
/// function on x86_64 than on Apple silicon. Getting this wrong does not fail to
/// compile; it returns a rectangle of noise.
unsafe fn send_rect(receiver: Object, selector: Sel) -> CgRect {
    #[cfg(target_arch = "x86_64")]
    {
        let mut out = CgRect::default();
        let dispatch: unsafe extern "C" fn(*mut CgRect, Object, Sel) =
            unsafe { std::mem::transmute(objc_msgSend_stret as *const ()) };
        unsafe { dispatch(&mut out, receiver, selector) };
        out
    }
    #[cfg(not(target_arch = "x86_64"))]
    unsafe {
        send(receiver, selector)
    }
}

/// An `NSString` holding `text`, valid until the pool is popped.
fn ns_string(text: &CStr) -> Object {
    unsafe { send1(class(c"NSString"), sel(c"stringWithUTF8String:"), text.as_ptr()) }
}

/// The Rust string behind an `NSString`, or empty when there is none.
fn from_ns_string(string: Object) -> String {
    if string.is_null() {
        return String::new();
    }
    let utf8: *const c_char = unsafe { send(string, sel(c"UTF8String")) };
    if utf8.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(utf8) }.to_string_lossy().into_owned()
}

// Window style bits, from `NSWindowStyleMask`.
const STYLE_TITLED: u64 = 1;
const STYLE_CLOSABLE: u64 = 1 << 1;
const STYLE_MINIATURIZABLE: u64 = 1 << 2;
const STYLE_RESIZABLE: u64 = 1 << 3;
/// `NSBackingStoreBuffered`.
const BACKING_BUFFERED: u64 = 2;
/// `NSApplicationActivationPolicyRegular`: a normal app with a Dock icon.
const ACTIVATION_REGULAR: i64 = 0;

// `NSEventType` values.
const EVENT_LEFT_DOWN: u64 = 1;
const EVENT_LEFT_UP: u64 = 2;
const EVENT_RIGHT_DOWN: u64 = 3;
const EVENT_RIGHT_UP: u64 = 4;
const EVENT_MOUSE_MOVED: u64 = 5;
const EVENT_LEFT_DRAGGED: u64 = 6;
const EVENT_RIGHT_DRAGGED: u64 = 7;
const EVENT_KEY_DOWN: u64 = 10;
const EVENT_KEY_UP: u64 = 11;
const EVENT_SCROLL: u64 = 22;
const EVENT_OTHER_DOWN: u64 = 25;
const EVENT_OTHER_UP: u64 = 26;
const EVENT_OTHER_DRAGGED: u64 = 27;

// `NSEventModifierFlags`.
const MODIFIER_SHIFT: u64 = 1 << 17;
const MODIFIER_CONTROL: u64 = 1 << 18;
const MODIFIER_OPTION: u64 = 1 << 19;
const MODIFIER_COMMAND: u64 = 1 << 20;

/// `kCGImageAlphaNoneSkipFirst | kCGBitmapByteOrder32Little`.
///
/// Which is to say: four bytes per pixel in the order blue, green, red, ignored
/// — exactly how [`Canvas`] stores them, so presenting a frame is a copy.
const BITMAP_INFO: u32 = 6 | (2 << 12);

/// How many logical units one notch of a coarse scroll wheel moves.
///
/// A trackpad reports precise deltas in points and needs no conversion. An
/// old-fashioned wheel reports whole notches, and a notch that moved one point
/// would be useless.
const WHEEL_NOTCH: f64 = 16.0;

/// A window on macOS.
///
/// # Why the state is in cells
///
/// A frame can be drawn while this window is inside its own `pump` — see
/// [`Backend::pump`] and [`LiveResize`]. There is no `&mut self` to be had at
/// that moment, and inventing one from a raw pointer would be two live
/// `&mut`s to the same window. Everything a frame reads or writes is therefore
/// held in a [`Cell`], which is exactly as much sharing as this needs: the
/// window is only ever touched from the main thread, because AppKit refuses to
/// be touched from any other.
pub(crate) struct Window {
    application: Object,
    window: Object,
    view: Object,
    layer: Object,
    open: Cell<bool>,
    /// Logical size of the content view, as of the last time it was read.
    size: Cell<(f64, f64)>,
    /// Device pixels per logical unit, as of the last time it was read.
    scale: Cell<f64>,
    /// The scale the layer was last told about, so it is set only when it moves.
    presented_scale: Cell<f64>,
    /// What the run-loop observer needs to draw a frame. Boxed so its address
    /// is settled before the observer is given it, and so moving the window out
    /// of `open` does not move it.
    live: Box<LiveResize>,
}

/// What the run-loop observer needs in order to draw a frame mid-gesture.
///
/// # The problem this exists for
///
/// AppKit tracks a live resize in a nested run loop: the mouse-down on the
/// window's edge is handed to `sendEvent:`, and that call does not return until
/// the mouse comes up. Everything above — the frame loop, the application, the
/// toolkit — is stopped inside it for the whole drag, so the only frame on
/// screen is the one from before the gesture started, stretched by the
/// compositor to each new size.
///
/// A run-loop observer is the way back in. It is registered for the common
/// modes, which include the event-tracking mode a resize runs in, so it fires
/// on each turn of AppKit's nested loop as well as our own.
///
/// # Both pointers are set per pump, and cleared after it
///
/// Neither can be set once at construction. The window is returned by value
/// from `open`, so its address then is not its address later; and the closure
/// belongs to one call of `pump`. Leaving either set past the call that
/// established it is the way this would become a dangling read, so `pump`
/// clears both on its way out.
#[derive(Default)]
struct LiveResize {
    /// The window mid-resize, or null between pumps.
    window: Cell<*const Window>,
    /// The current pump's `&mut &mut dyn FnMut(&Window)`, or null between pumps.
    ///
    /// A pointer to the reference rather than the reference itself: a `dyn`
    /// pointer is two words wide and this has to fit through C as one.
    redraw: Cell<*mut c_void>,
    /// Whether a frame is being drawn right now.
    ///
    /// A run loop makes no promise that an observer will not fire again while
    /// the last call is still on the stack. Drawing is not re-entrant — the
    /// closure holds the frame's state — so a second call is skipped rather
    /// than allowed to alias the first.
    drawing: Cell<bool>,
}

/// Draws a frame when the run loop is about to sleep during a live resize.
///
/// Fires on every turn of every loop it is registered for, which includes the
/// wait `pump` does itself. The `inLiveResize` gate is what keeps it to the one
/// case it is for: without it every idle wait would draw a second frame, from
/// inside the call that was only supposed to be collecting events.
extern "C" fn draw_during_live_resize(_observer: *mut c_void, _activity: u64, info: *mut c_void) {
    if info.is_null() {
        return;
    }
    // SAFETY: `info` is the `LiveResize` this window boxed and kept, and the
    // observer is only ever registered on the main run loop, so this runs on
    // the thread that owns the window.
    let live = unsafe { &*info.cast::<LiveResize>() };
    let window = live.window.get();
    let redraw = live.redraw.get();
    if window.is_null() || redraw.is_null() {
        return;
    }
    // SAFETY: both were set by the `pump` call this is running inside, and are
    // cleared before it returns.
    let window = unsafe { &*window };
    if !window.in_live_resize() || live.drawing.get() {
        return;
    }
    window.refresh_geometry();
    live.drawing.set(true);
    // SAFETY: as above; the pointer is to `pump`'s own live reference, and
    // `drawing` guarantees this is the only reference to it on the stack.
    let redraw = unsafe { &mut *redraw.cast::<&mut dyn FnMut(&Window)>() };
    redraw(window);
    live.drawing.set(false);
}

impl Backend for Window {
    fn open(options: &WindowOptions) -> Result<Self, Error> {
        unsafe {
            let pool = objc_autoreleasePoolPush();

            let application: Object = send(class(c"NSApplication"), sel(c"sharedApplication"));
            if application.is_null() {
                objc_autoreleasePoolPop(pool);
                return Err(Error::Platform(
                    "could not reach the window server; a console needs a logged-in desktop \
                     session, so run it on your own machine and tunnel to the daemon"
                        .into(),
                ));
            }
            let _: bool =
                send1(application, sel(c"setActivationPolicy:"), ACTIVATION_REGULAR);

            let content = CgRect {
                origin: CgPoint { x: 0.0, y: 0.0 },
                size: CgSize { width: options.width as f64, height: options.height as f64 },
            };
            let style =
                STYLE_TITLED | STYLE_CLOSABLE | STYLE_MINIATURIZABLE | STYLE_RESIZABLE;

            let window: Object = send(class(c"NSWindow"), sel(c"alloc"));
            let window: Object = send4(
                window,
                sel(c"initWithContentRect:styleMask:backing:defer:"),
                content,
                style,
                BACKING_BUFFERED,
                false,
            );
            if window.is_null() {
                objc_autoreleasePoolPop(pool);
                return Err(Error::Platform("NSWindow could not be created".into()));
            }

            // Without this, closing the window deallocates it and every later
            // message — including the one asking whether it is still open —
            // lands on freed memory.
            let _: () = send1(window, sel(c"setReleasedWhenClosed:"), false);
            let title = std::ffi::CString::new(options.title.as_str())
                .unwrap_or_else(|_| c"rui".to_owned());
            let _: () = send1(window, sel(c"setTitle:"), ns_string(&title));
            let _: () = send1(
                window,
                sel(c"setContentMinSize:"),
                CgSize { width: options.min_width as f64, height: options.min_height as f64 },
            );
            // Mouse movement is not reported unless it is asked for, and hover
            // states are most of what makes an interface feel alive.
            let _: () = send1(window, sel(c"setAcceptsMouseMovedEvents:"), true);

            let view: Object = send(window, sel(c"contentView"));
            let _: () = send1(view, sel(c"setWantsLayer:"), true);
            // Both of these are about what happens between a view resizing and
            // the frame at the new size arriving; see the constants.
            let _: () = send1(
                view,
                sel(c"setLayerContentsRedrawPolicy:"),
                REDRAW_ON_SET_NEEDS_DISPLAY,
            );
            let _: () = send1(view, sel(c"setLayerContentsPlacement:"), PLACEMENT_TOP_LEFT);
            let layer: Object = send(view, sel(c"layer"));
            // A canvas has no alpha — the bitmap format ignores that byte — so
            // saying so lets the compositor skip blending the window with what
            // is behind it, for every pixel, every frame.
            let _: () = send1(layer, sel(c"setOpaque:"), true);
            let _: () = send1(window, sel(c"setOpaque:"), true);

            install_menu(application, &options.title);

            let _: () = send(application, sel(c"finishLaunching"));
            let _: () = send1(window, sel(c"makeKeyAndOrderFront:"), std::ptr::null_mut::<c_void>());
            let _: () = send1(application, sel(c"activateIgnoringOtherApps:"), true);

            objc_autoreleasePoolPop(pool);

            let window = Self {
                application,
                window,
                view,
                layer,
                open: Cell::new(true),
                size: Cell::new((options.width as f64, options.height as f64)),
                scale: Cell::new(1.0),
                presented_scale: Cell::new(0.0),
                live: Box::new(LiveResize::default()),
            };
            window.refresh_geometry();
            window.observe_live_resize();
            Ok(window)
        }
    }

    fn pump(
        &mut self,
        timeout: Duration,
        events: &mut Vec<Event>,
        mut redraw: &mut dyn FnMut(&Self),
    ) -> Result<(), Error> {
        // Lets the observer reach this window and this frame for the duration of
        // the call, and no longer. `sendEvent:` below is where AppKit may not
        // come back until a drag ends, and the observer firing inside it is the
        // only reason the window keeps drawing while that happens.
        self.live.window.set(std::ptr::from_ref(self));
        self.live.redraw.set(std::ptr::from_mut(&mut redraw).cast::<c_void>());
        let result = self.pump_events(timeout, events);
        self.live.window.set(std::ptr::null());
        self.live.redraw.set(std::ptr::null_mut());
        result
    }

    fn surface(&self) -> (u32, u32, f32) {
        let (width, height) = self.size.get();
        let scale = self.scale.get();
        ((width * scale).max(1.0) as u32, (height * scale).max(1.0) as u32, scale as f32)
    }

    fn appearance(&self) -> Appearance {
        unsafe {
            let appearance: Object = send(self.application, sel(c"effectiveAppearance"));
            if appearance.is_null() {
                return Appearance::Light;
            }
            let name: Object = send(appearance, sel(c"name"));
            if from_ns_string(name).contains("Dark") {
                Appearance::Dark
            } else {
                Appearance::Light
            }
        }
    }

    fn present(&self, canvas: &Canvas) -> Result<(), Error> {
        let width = canvas.width() as usize;
        let height = canvas.height() as usize;
        if width == 0 || height == 0 {
            return Ok(());
        }
        let bytes = canvas.pixels().len() * 4;

        unsafe {
            let pool = objc_autoreleasePoolPush();

            // The pixels are copied into a `CFData` rather than handed over as a
            // borrowed pointer. The layer keeps the image after this call
            // returns and reads it whenever it next composites, so a provider
            // pointing at the canvas would be read after the canvas had been
            // redrawn — or resized out from under it.
            let data = CFDataCreate(
                std::ptr::null(),
                canvas.pixels().as_ptr() as *const u8,
                bytes as isize,
            );
            let provider = CGDataProviderCreateWithCFData(data);
            let space = CGColorSpaceCreateDeviceRGB();
            let image = CGImageCreate(
                width,
                height,
                8,
                32,
                width * 4,
                space,
                BITMAP_INFO,
                provider,
                std::ptr::null(),
                false,
                0,
            );

            // Changing a layer's contents is an animatable property, so without
            // this the interface cross-fades between frames — every click
            // arrives a quarter of a second late to the eye.
            let transaction = class(c"CATransaction");
            let _: () = send(transaction, sel(c"begin"));
            let _: () = send1(transaction, sel(c"setDisableActions:"), true);
            // Only when it changes: setting it every frame makes the layer
            // rebuild what it had already prepared.
            let scale = self.scale.get();
            if (self.presented_scale.get() - scale).abs() > f64::EPSILON {
                let _: () = send1(self.layer, sel(c"setContentsScale:"), scale);
                self.presented_scale.set(scale);
            }
            let _: () = send1(self.layer, sel(c"setContents:"), image);
            let _: () = send(transaction, sel(c"commit"));

            CGImageRelease(image);
            CGColorSpaceRelease(space);
            CGDataProviderRelease(provider);
            CFRelease(data);

            objc_autoreleasePoolPop(pool);
        }
        Ok(())
    }

    fn is_open(&self) -> bool {
        self.open.get()
    }
}

impl Window {
    /// Registers the observer that draws while AppKit is tracking a gesture.
    ///
    /// Registered once, for the life of the window. What it does when it fires
    /// is decided entirely by [`LiveResize`], which is empty except during a
    /// `pump` — so an observer that outlives anything is an observer that
    /// returns immediately.
    fn observe_live_resize(&self) {
        unsafe {
            let mut context = ObserverContext {
                version: 0,
                info: std::ptr::from_ref(&*self.live).cast_mut().cast::<c_void>(),
                retain: std::ptr::null(),
                release: std::ptr::null(),
                copy_description: std::ptr::null(),
            };
            let observer = CFRunLoopObserverCreate(
                std::ptr::null(),
                RUN_LOOP_BEFORE_WAITING | RUN_LOOP_EXIT,
                true,
                // After AppKit's own observers, so the frame drawn is the one
                // for the geometry AppKit has just finished settling on.
                isize::MAX,
                draw_during_live_resize,
                &mut context,
            );
            if observer.is_null() {
                return;
            }
            CFRunLoopAddObserver(CFRunLoopGetCurrent(), observer, kCFRunLoopCommonModes);
            // Deliberately not released: the observer lives as long as the
            // window does, and the window lives as long as the process. Giving
            // up our reference here would leave only the run loop's, which is
            // enough, but there is nothing to gain from the extra call and a
            // use-after-free to lose if that ever stopped being true.
        }
    }

    /// Whether AppKit is currently tracking a drag of this window's edge.
    fn in_live_resize(&self) -> bool {
        unsafe { send(self.window, sel(c"inLiveResize")) }
    }

    /// The event half of [`Backend::pump`], with the observer already wired up.
    fn pump_events(&self, timeout: Duration, events: &mut Vec<Event>) -> Result<(), Error> {
        unsafe {
            let pool = objc_autoreleasePoolPush();

            let mode = ns_string(c"kCFRunLoopDefaultMode");
            // The first wait blocks up to the timeout; once anything has
            // arrived, the rest of the queue is drained without waiting, so a
            // burst of movement becomes one frame rather than a dozen.
            let deadline: Object = send1(
                class(c"NSDate"),
                sel(c"dateWithTimeIntervalSinceNow:"),
                timeout.as_secs_f64(),
            );
            let immediate: Object = send(class(c"NSDate"), sel(c"distantPast"));

            let mut received_any = false;
            loop {
                let until = if received_any { immediate } else { deadline };
                let event: Object = send4(
                    self.application,
                    sel(c"nextEventMatchingMask:untilDate:inMode:dequeue:"),
                    u64::MAX,
                    until,
                    mode,
                    true,
                );
                if event.is_null() {
                    break;
                }
                received_any = true;

                let kind: u64 = send(event, sel(c"type"));
                self.translate(event, kind, events);

                // Everything AppKit itself needs to see goes back to it:
                // dragging the title bar, the close button, menu shortcuts. Key
                // presses are withheld — nothing here has a responder that
                // handles them, and an unhandled key makes the system beep.
                let is_key = kind == EVENT_KEY_DOWN || kind == EVENT_KEY_UP;
                let modifiers: u64 = send(event, sel(c"modifierFlags"));
                if !is_key || modifiers & MODIFIER_COMMAND != 0 {
                    let _: () = send1(self.application, sel(c"sendEvent:"), event);
                }
            }

            self.refresh_geometry();
            let visible: bool = send(self.window, sel(c"isVisible"));
            if !visible {
                self.open.set(false);
            }

            objc_autoreleasePoolPop(pool);
        }
        Ok(())
    }

    /// Re-reads the window's size and the display's scale.
    fn refresh_geometry(&self) {
        unsafe {
            let frame = send_rect(self.view, sel(c"frame"));
            if frame.size.width > 0.0 && frame.size.height > 0.0 {
                self.size.set((frame.size.width, frame.size.height));
            }
            let scale: f64 = send(self.window, sel(c"backingScaleFactor"));
            if scale > 0.0 {
                self.scale.set(scale);
            }
        }
    }

    /// Turns one `NSEvent` into the toolkit's events, if it is one we care about.
    fn translate(&self, event: Object, kind: u64, events: &mut Vec<Event>) {
        unsafe {
            match kind {
                EVENT_LEFT_DOWN | EVENT_RIGHT_DOWN | EVENT_OTHER_DOWN => {
                    let position = self.pointer_position(event);
                    events.push(Event::PointerDown { position, button: button_of(kind, event) });
                }
                EVENT_LEFT_UP | EVENT_RIGHT_UP | EVENT_OTHER_UP => {
                    let position = self.pointer_position(event);
                    events.push(Event::PointerUp { position, button: button_of(kind, event) });
                }
                EVENT_MOUSE_MOVED | EVENT_LEFT_DRAGGED | EVENT_RIGHT_DRAGGED
                | EVENT_OTHER_DRAGGED => {
                    let position = self.pointer_position(event);
                    // There is no tracking area, so "the pointer left" is
                    // inferred from where it is rather than reported. That is
                    // enough to drop a hover, and it costs no extra objects.
                    let (width, height) = self.size.get();
                    if position.x < 0.0
                        || position.y < 0.0
                        || position.x > width as f32
                        || position.y > height as f32
                    {
                        events.push(Event::PointerLeft);
                    } else {
                        events.push(Event::PointerMoved(position));
                    }
                }
                EVENT_SCROLL => {
                    let precise: bool = send(event, sel(c"hasPreciseScrollingDeltas"));
                    let factor = if precise { 1.0 } else { WHEEL_NOTCH };
                    let x: f64 = send(event, sel(c"scrollingDeltaX"));
                    let y: f64 = send(event, sel(c"scrollingDeltaY"));
                    events.push(Event::Scrolled {
                        x: (x * factor) as f32,
                        y: (y * factor) as f32,
                    });
                }
                EVENT_KEY_DOWN | EVENT_KEY_UP => self.translate_key(event, kind, events),
                _ => {}
            }
        }
    }

    /// Turns a key event into a key press and, for a key down, any text it typed.
    fn translate_key(&self, event: Object, kind: u64, events: &mut Vec<Event>) {
        unsafe {
            let flags: u64 = send(event, sel(c"modifierFlags"));
            let modifiers = modifiers_of(flags);
            let code: u16 = send(event, sel(c"keyCode"));

            let key = key_for_code(code).or_else(|| {
                let characters: Object = send(event, sel(c"charactersIgnoringModifiers"));
                from_ns_string(characters)
                    .chars()
                    .next()
                    .filter(|character| !is_function_key(*character))
                    .map(|character| {
                        Key::Character(character.to_lowercase().next().unwrap_or(character))
                    })
            });

            if let Some(key) = key {
                events.push(if kind == EVENT_KEY_DOWN {
                    Event::KeyDown { key, modifiers }
                } else {
                    Event::KeyUp { key, modifiers }
                });
            }

            // A key held with the accelerator is a command, not typing. Without
            // this, Command-R would insert an "r" into whatever field had focus
            // as well as doing whatever the shortcut does.
            if kind != EVENT_KEY_DOWN || modifiers.command {
                return;
            }
            let characters: Object = send(event, sel(c"characters"));
            let typed: String = from_ns_string(characters)
                .chars()
                .filter(|character| !character.is_control() && !is_function_key(*character))
                .collect();
            if !typed.is_empty() {
                events.push(Event::Text(typed));
            }
        }
    }

    /// Where an event happened, in logical units from the top left.
    fn pointer_position(&self, event: Object) -> Point {
        let location: CgPoint = unsafe { send(event, sel(c"locationInWindow")) };
        // AppKit measures up from the bottom of the content area; everything
        // above measures down from the top.
        Point::new(location.x as f32, (self.size.get().1 - location.y) as f32)
    }
}

/// Which button an event was about.
fn button_of(kind: u64, event: Object) -> PointerButton {
    match kind {
        EVENT_LEFT_DOWN | EVENT_LEFT_UP => PointerButton::Primary,
        EVENT_RIGHT_DOWN | EVENT_RIGHT_UP => PointerButton::Secondary,
        _ => {
            // "Other" covers the middle button and everything past it; only the
            // middle one has a meaning here.
            let number: u64 = unsafe { send(event, sel(c"buttonNumber")) };
            if number == 2 { PointerButton::Middle } else { PointerButton::Primary }
        }
    }
}

/// The modifiers a flags word describes.
///
/// Command is reported as the accelerator, which is what it is on this platform.
fn modifiers_of(flags: u64) -> Modifiers {
    Modifiers {
        shift: flags & MODIFIER_SHIFT != 0,
        control: flags & MODIFIER_CONTROL != 0,
        alt: flags & MODIFIER_OPTION != 0,
        command: flags & MODIFIER_COMMAND != 0,
    }
}

/// The named key a macOS virtual key code stands for, if it is one.
///
/// Virtual key codes are positional and do not change with the keyboard layout,
/// which is exactly what is wanted for keys that have no character.
fn key_for_code(code: u16) -> Option<Key> {
    Some(match code {
        36 | 76 => Key::Enter,
        48 => Key::Tab,
        49 => Key::Space,
        51 => Key::Backspace,
        53 => Key::Escape,
        115 => Key::Home,
        116 => Key::PageUp,
        117 => Key::Delete,
        119 => Key::End,
        121 => Key::PageDown,
        123 => Key::Left,
        124 => Key::Right,
        125 => Key::Down,
        126 => Key::Up,
        _ => return None,
    })
}

/// Whether a character is one of AppKit's private-use codes for a function key.
///
/// Arrows and the like arrive in `characters` as code points in the private use
/// area. Inserting one would put an invisible, undeletable character into a
/// field.
fn is_function_key(character: char) -> bool {
    ('\u{f700}'..='\u{f8ff}').contains(&character)
}

/// Installs the one menu a window needs, so Command-Q works.
///
/// An application with no main menu still shows a menu bar, and the Quit item
/// people reach for by reflex is simply absent from it.
fn install_menu(application: Object, title: &str) {
    unsafe {
        let bar: Object = send(send(class(c"NSMenu"), sel(c"alloc")), sel(c"init"));
        let item: Object = send(send(class(c"NSMenuItem"), sel(c"alloc")), sel(c"init"));
        let _: () = send1(bar, sel(c"addItem:"), item);

        let submenu: Object = send(send(class(c"NSMenu"), sel(c"alloc")), sel(c"init"));
        let label = std::ffi::CString::new(format!("Quit {title}"))
            .unwrap_or_else(|_| c"Quit".to_owned());
        let quit: Object = send3(
            send(class(c"NSMenuItem"), sel(c"alloc")),
            sel(c"initWithTitle:action:keyEquivalent:"),
            ns_string(&label),
            sel(c"terminate:"),
            ns_string(c"q"),
        );
        let _: () = send1(submenu, sel(c"addItem:"), quit);
        let _: () = send1(item, sel(c"setSubmenu:"), submenu);
        let _: () = send1(application, sel(c"setMainMenu:"), bar);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_keys_come_from_positions_not_characters() {
        assert_eq!(key_for_code(53), Some(Key::Escape));
        assert_eq!(key_for_code(126), Some(Key::Up));
        assert_eq!(key_for_code(76), Some(Key::Enter), "the numeric keypad's Enter");
        assert_eq!(key_for_code(0), None, "an ordinary letter is not a named key");
    }

    #[test]
    fn command_is_reported_as_the_accelerator() {
        let modifiers = modifiers_of(MODIFIER_COMMAND);
        assert!(modifiers.command);
        assert!(modifiers.command_only());
    }

    #[test]
    fn every_modifier_is_recognised_separately() {
        let all = modifiers_of(MODIFIER_SHIFT | MODIFIER_CONTROL | MODIFIER_OPTION | MODIFIER_COMMAND);
        assert!(all.shift && all.control && all.alt && all.command);
        assert!(modifiers_of(0).is_empty());
    }

    #[test]
    fn function_key_code_points_are_not_treated_as_text() {
        assert!(is_function_key('\u{f700}'), "the up arrow's private-use code point");
        assert!(!is_function_key('a'));
        assert!(!is_function_key('é'));
    }

    unsafe extern "C" {
        /// Runs the current run loop for `seconds`, or until a source is handled.
        fn CFRunLoopRunInMode(
            mode: *const c_void,
            seconds: f64,
            return_after_source_handled: bool,
        ) -> i32;
        fn CFAbsoluteTimeGetCurrent() -> f64;
        fn CFRunLoopTimerCreate(
            allocator: *const c_void,
            fire_date: f64,
            interval: f64,
            flags: u64,
            order: isize,
            callout: extern "C" fn(*mut c_void, *mut c_void),
            context: *mut ObserverContext,
        ) -> *mut c_void;
        fn CFRunLoopAddTimer(loop_: *mut c_void, timer: *mut c_void, mode: *const c_void);
        static kCFRunLoopDefaultMode: *const c_void;
    }

    /// A timer that does nothing, so the loop has a reason to sleep.
    ///
    /// A run loop with no sources does not wait — it returns straight away and
    /// never reaches the "about to sleep" activity. That is a property of the
    /// empty loop in this test and not of the window, whose loop always has
    /// AppKit's own sources on it.
    extern "C" fn tick(_timer: *mut c_void, _info: *mut c_void) {}

    /// How many times [`count_a_turn`] has been called.
    static TURNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    extern "C" fn count_a_turn(_observer: *mut c_void, _activity: u64, info: *mut c_void) {
        assert!(!info.is_null(), "the context's info pointer should arrive intact");
        TURNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn an_observer_registered_the_way_the_window_registers_one_actually_fires() {
        // The live-resize fix rests entirely on a run-loop observer firing from
        // inside a loop this program did not start. Every part of that is a C
        // signature that compiles whether or not it is right: a wrong flag word
        // registers for no activity, a wrong mode registers for a loop that
        // never runs, and either failure is silent — the window simply goes on
        // not redrawing during a drag, which is the bug being fixed.
        //
        // So this asserts the plumbing rather than the policy. What it cannot
        // reach is `inLiveResize`, which needs a hand on a mouse.
        let mut marker = 0u8;
        let mut context = ObserverContext {
            version: 0,
            info: std::ptr::from_mut(&mut marker).cast::<c_void>(),
            retain: std::ptr::null(),
            release: std::ptr::null(),
            copy_description: std::ptr::null(),
        };
        let before = TURNS.load(std::sync::atomic::Ordering::Relaxed);
        unsafe {
            let observer = CFRunLoopObserverCreate(
                std::ptr::null(),
                RUN_LOOP_BEFORE_WAITING | RUN_LOOP_EXIT,
                true,
                isize::MAX,
                count_a_turn,
                &mut context,
            );
            assert!(!observer.is_null(), "CFRunLoopObserverCreate refused the arguments");
            CFRunLoopAddObserver(CFRunLoopGetCurrent(), observer, kCFRunLoopCommonModes);

            let timer = CFRunLoopTimerCreate(
                std::ptr::null(),
                CFAbsoluteTimeGetCurrent() + 0.01,
                0.01,
                0,
                0,
                tick,
                &mut context,
            );
            assert!(!timer.is_null(), "CFRunLoopTimerCreate refused the arguments");
            CFRunLoopAddTimer(CFRunLoopGetCurrent(), timer, kCFRunLoopDefaultMode);

            // Long enough for the loop to run out of work and be about to
            // sleep, which is the activity the window asks to hear about.
            CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.2, false);
        }
        assert!(
            TURNS.load(std::sync::atomic::Ordering::Relaxed) > before,
            "the observer never fired: the activity flags or the mode are wrong, and a \
             live resize would draw nothing"
        );
    }

    #[test]
    fn nothing_is_drawn_for_an_observer_that_has_no_window_or_no_frame() {
        // What every firing outside a pump looks like. It must be a return and
        // not a null dereference: the observer outlives every individual pump,
        // and fires on turns of the loop that have nothing to do with a resize.
        let live = LiveResize::default();
        let info = std::ptr::from_ref(&live).cast_mut().cast::<c_void>();
        draw_during_live_resize(std::ptr::null_mut(), RUN_LOOP_BEFORE_WAITING, info);
        draw_during_live_resize(std::ptr::null_mut(), RUN_LOOP_BEFORE_WAITING, std::ptr::null_mut());
        assert!(!live.drawing.get(), "a firing with nothing set should not have drawn");
    }

    #[test]
    fn the_bitmap_format_matches_what_the_canvas_stores() {
        // Alpha ignored and in the first byte, 32-bit words read little-endian:
        // blue, green, red, ignored — which is a canvas word in memory.
        assert_eq!(BITMAP_INFO, 6 | 8192);
    }
}
