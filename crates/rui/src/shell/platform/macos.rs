//! The macOS backend: AppKit for the window and input, Core Graphics for the blit.
//!
//! # Nothing is drawn by subclassing, and nothing is read by overriding
//!
//! The usual way to draw with AppKit is to subclass `NSView` and override
//! `drawRect:`. This does not. The window's content view is given a `CALayer`,
//! and each frame's pixels become a `CGImage` handed to the layer as its
//! contents — so the compositor does the drawing and there is nothing to
//! override.
//!
//! Input is read the same way. Rather than overriding `mouseDown:` and its
//! dozen relatives, the loop pulls events out of the queue itself with
//! `nextEventMatchingMask:untilDate:inMode:dequeue:` and reads them directly.
//! Events that AppKit needs — window dragging, the close button, menu
//! shortcuts — are handed back to it; key presses are not, because forwarding a
//! key nothing handles makes the system beep.
//!
//! # The two classes this does build, and why it has to
//!
//! [`content_view_class`] assembles an `NSView` subclass at run time. It exists
//! for exactly one reason: a program only receives typed text through
//! `NSTextInputClient`, and that is a protocol, so there has to be an object
//! conforming to it. Reading `characters` off a key event instead — which is
//! what this did before — asks the keyboard what was pressed rather than asking
//! the input method what was *meant*. On a US layout with plain ASCII the two
//! answers agree; on every other layout, and for every language whose writing
//! system has more characters than a keyboard has keys, they do not. There is no
//! way to type Japanese, Chinese, or Korean, and no way to type é, without one.
//!
//! So the class is deliberately the smallest thing that can conform: the ten
//! methods of the protocol, `acceptsFirstResponder`, and a single instance
//! variable pointing back at the [`Composer`] that holds what is being composed.
//! Nothing about drawing, geometry, or the mouse goes through it.
//!
//! [`element_class`] assembles the second, an `NSAccessibilityElement`
//! subclass, and exists for the mirror image of that reason: a screen reader
//! presses a control by sending `accessibilityPerformPress` to an *object*, so
//! there has to be an object that answers. See below.
//!
//! # Accessibility is a mirror, and the way back is an event
//!
//! [`Accessibility`] keeps one element per node of the interface and applies
//! each frame's difference to them, because a screen reader is handed those
//! objects and asks them questions at moments of its own choosing — long after
//! the frame that produced them.
//!
//! A press comes the other way, and cannot answer itself. It arrives at an
//! object, not at a frame; there is no `&mut` anything to be had inside it, and
//! reaching a handler from here would be a second dispatch beside the one a
//! click already takes. So it is not answered — it is *reported*, exactly as a
//! click is: [`Activation::press`] resolves the object back to the [`Id`] it
//! stands for and leaves it in the window's [`Inbox`], and [`Window::pump`]
//! drains that into [`Event::Activated`] along with the mouse and the keyboard.
//! The seam did not widen; nothing here reaches an application; and the
//! invariant in [`accessibility`](crate::accessibility) holds because the frame
//! decides what a press means, in the same line that decides what a click does.
//!
//! Two details make that work rather than nearly work.
//!
//! *The press does not arrive when we are looking.* It is delivered on the main
//! thread while the loop is asleep inside
//! `nextEventMatchingMask:untilDate:inMode:dequeue:`, which returns only for an
//! `NSEvent` — and an accessibility message is not one. Left alone, a press
//! would be noticed whenever the window next woke for its own reasons, up to
//! [`App::idle_timeout`](crate::App::idle_timeout) later, which for a window
//! that has chosen a long idle is indistinguishable from a dead button. So
//! [`wake`] posts an application-defined `NSEvent` the queue *does* return, and
//! the press lands on the very next frame.
//!
//! *Not everything can be pressed.* AppKit advertises an action for every
//! `accessibilityPerform…` a class implements, so implementing it once on the
//! class would offer "press" on every heading and every rule in the window.
//! [`is_selector_allowed`] answers that question per element from what the node
//! actually carries, and defers to the superclass for every other selector
//! rather than claiming to know.
//!
//! # What each fact of a node comes to, exhaustively
//!
//! [`attributes_of`] is the whole of the mapping, and it destructures
//! [`AccessNode`] and [`AccessState`] without a rest pattern — so a field added
//! to either stops this file compiling until somebody decides what macOS should
//! do with it. That is the guarantee, rather than a test: a test can only check
//! the fields whoever wrote it knew about.
//!
//! | fact | what it becomes here |
//! |---|---|
//! | `id` | the element object itself; AppKit has no attribute for identity |
//! | `parent` | `AXParent` and `AXChildren`, rebuilt wholesale by [`relink`] |
//! | `role` | `AXRole`, through [`ax_role`] |
//! | `name` | `AXDescription`, via `setAccessibilityLabel:` |
//! | `value` | `AXValue`, as a string |
//! | `state.disabled` | `AXEnabled`, inverted |
//! | `state.focusable` | *nothing* — see below |
//! | `state.focused` | `AXFocused` |
//! | `state.selected` | `AXValue` as a number on a checkbox, radio, or tab; `AXSelected` on a row |
//! | `bounds` | `AXFrame`, converted to screen coordinates by [`on_screen`] |
//! | `position_in_set` | the order of the parent's `AXChildren`; see below |
//! | `set_size` | how many those children are; see below |
//! | `actions.press` | `accessibilityPerformPress`, offered per element |
//! | `actions.set_value` | *nothing* — see below |
//! | `actions.keys` | *nothing* — a key reaches a focused element by being typed |
//! | `actions.drag` | *nothing* — see below |
//!
//! Selection is two attributes and not one because AppKit makes it two:
//! VoiceOver reads a checkbox and a radio button as "checked" or "selected"
//! from the *number* in `AXValue`, and reads a row from the boolean in
//! `AXSelected`. A checkbox given `AXSelected` is announced as neither.
//!
//! A position in a set has no per-element attribute on macOS and does not need
//! one: an assistive technology counts a set by walking the parent's children,
//! and [`relink`] already sorts those into set order. `AXIndex` exists, and
//! means a row's index in a *table* — using it for a list would say something
//! AppKit does not mean by it.
//!
//! `focusable`, `set_value`, and `drag` are the honest gaps, and they are all
//! the same gap: this backend can say what is true, and cannot yet be *told*
//! anything but a press. So the writes that would carry those — setting a
//! value, moving focus, choosing a row — are refused rather than accepted and
//! dropped; see [`UNROUTED_WRITES`]. Each closes the way the press did.

use crate::accessibility::{AccessNode, AccessState, AccessUpdate, Role};
use crate::input::Composition;
use crate::memory::Id;
use crate::theme::Appearance;
use crate::{Canvas, Event, Key, KeyCode, Modifiers, Point, PointerButton, Rect};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
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

    // Building a class at run time, for the one class this backend defines;
    // see the module header and [`content_view_class`].
    fn objc_allocateClassPair(superclass: Object, name: *const c_char, extra: usize) -> Object;
    fn objc_registerClassPair(class: Object);
    fn class_addMethod(
        class: Object,
        selector: Sel,
        implementation: *const c_void,
        types: *const c_char,
    ) -> bool;
    fn class_addIvar(
        class: Object,
        name: *const c_char,
        size: usize,
        alignment: u8,
        types: *const c_char,
    ) -> bool;
    fn class_addProtocol(class: Object, protocol: *const c_void) -> bool;
    fn objc_getProtocol(name: *const c_char) -> *const c_void;
    fn object_setInstanceVariable(
        object: Object,
        name: *const c_char,
        value: *mut c_void,
    ) -> *const c_void;
    fn object_getInstanceVariable(
        object: Object,
        name: *const c_char,
        value: *mut *mut c_void,
    ) -> *const c_void;

    /// Objective-C's dispatch entry point.
    ///
    /// Declared without arguments and transmuted to the exact signature of each
    /// call. It cannot be declared variadic: on Apple silicon a variadic call
    /// passes arguments differently from a normal one, so a variadic
    /// declaration produces calls the runtime misreads.
    fn objc_msgSend();

    /// The same, for a message sent to the superclass's implementation.
    ///
    /// Declared and transmuted for the same reasons as [`objc_msgSend`]. The
    /// receiver is an [`ObjcSuper`] rather than the object, which is the whole
    /// of the difference: it names where to *start* looking for the method.
    fn objc_msgSendSuper();

    /// The same, for messages returning a struct too large for registers.
    ///
    /// Only x86_64 has this split. On aarch64 every return goes through
    /// `objc_msgSend`.
    #[cfg(target_arch = "x86_64")]
    fn objc_msgSend_stret();

    /// Tells whatever assistive technology is listening that something moved.
    ///
    /// The notification name is an `NSString`; the constants AppKit exports for
    /// them are the plain strings used at the call sites below.
    fn NSAccessibilityPostNotification(element: Object, notification: Object);

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

/// `NSRange`: a position and a length, counted in UTF-16 units.
///
/// Every range crossing the text-input protocol is in those units, because that
/// is how the platform stores a string. A Rust [`String`] is bytes, and the two
/// agree only while the text is ASCII — which for a composition is precisely the
/// case that never arises. See [`byte_offset`].
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NsRange {
    location: usize,
    length: usize,
}

/// `NSNotFound`, which in an `NSRange` means "there is no such range".
const NOT_FOUND: usize = isize::MAX as usize;

impl NsRange {
    /// The range that is not one.
    const NONE: Self = Self { location: NOT_FOUND, length: 0 };

    /// A range starting at nothing and covering nothing.
    const EMPTY: Self = Self { location: 0, length: 0 };
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

/// Sends a message taking two arguments.
unsafe fn send2<R, A, B>(receiver: Object, selector: Sel, a: A, b: B) -> R {
    let dispatch: unsafe extern "C" fn(Object, Sel, A, B) -> R =
        unsafe { std::mem::transmute(objc_msgSend as *const ()) };
    unsafe { dispatch(receiver, selector, a, b) }
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

/// `struct objc_super`: an object, and where in its ancestry to start dispatch.
#[repr(C)]
struct ObjcSuper {
    receiver: Object,
    superclass: Object,
}

/// Sends a message to the superclass's implementation, taking one argument.
///
/// What `[super …]` compiles to. Needed once here, in
/// [`is_selector_allowed`]: overriding a question the framework already
/// answers means answering the one case that is ours and handing back every
/// other, and there is no way to hand one back but to ask the class we
/// inherited it from.
unsafe fn send1_super<R, A>(receiver: Object, superclass: Object, selector: Sel, a: A) -> R {
    let mut owner = ObjcSuper { receiver, superclass };
    let dispatch: unsafe extern "C" fn(*mut ObjcSuper, Sel, A) -> R =
        unsafe { std::mem::transmute(objc_msgSendSuper as *const ()) };
    unsafe { dispatch(&mut owner, selector, a) }
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

/// Sends a message taking a rectangle and answering one.
///
/// A second rectangle-shaped dispatch for the same reason [`send_rect`] exists:
/// on x86_64 a 32-byte return goes through a different entry point, and getting
/// it wrong compiles and returns noise.
unsafe fn send1_rect(receiver: Object, selector: Sel, rect: CgRect) -> CgRect {
    #[cfg(target_arch = "x86_64")]
    {
        let mut out = CgRect::default();
        let dispatch: unsafe extern "C" fn(*mut CgRect, Object, Sel, CgRect) =
            unsafe { std::mem::transmute(objc_msgSend_stret as *const ()) };
        unsafe { dispatch(&mut out, receiver, selector, rect) };
        out
    }
    #[cfg(not(target_arch = "x86_64"))]
    unsafe {
        send1(receiver, selector, rect)
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
/// `NSWindowStyleMaskFullScreen`, which AppKit sets on a window it has taken to
/// a space of its own. It is how the window answers the question rather than
/// something to open a window with.
const STYLE_FULLSCREEN: u64 = 1 << 14;
/// `NSWindowCollectionBehaviorFullScreenPrimary`: this window may become a full
/// screen on its own space.
///
/// Set explicitly rather than left to AppKit's default. Without it the green
/// button zooms — grows the window to fit the desktop, title bar, menu bar and
/// all — which is a different thing from the one a person asking for a full
/// screen wants, and there is no way to ask for the real one afterwards.
const COLLECTION_FULLSCREEN_PRIMARY: u64 = 1 << 7;
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
/// `NSEventTypeApplicationDefined`: an event the program invented for itself.
///
/// Nothing reads it. It exists to be *delivered*, which is the only thing that
/// ends a wait inside `nextEventMatchingMask:untilDate:inMode:dequeue:` before
/// its deadline; see [`wake`].
const EVENT_APPLICATION_DEFINED: u64 = 15;

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

/// `NSPasteboardTypeString`: the uniform type of plain, UTF-8 text.
///
/// Spelled out rather than read from the framework's own symbol, which would
/// mean a second linkage for a constant that has not changed since the type was
/// introduced.
const PASTEBOARD_TYPE_STRING: &CStr = c"public.utf8-plain-text";

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
    /// What the input method is composing. Boxed for the same reason: the view
    /// holds its address.
    composer: Box<Composer>,
    /// The interface as an assistive technology sees it.
    accessibility: Accessibility,
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
        // Before anything is allocated, because a window whose nodes could not
        // be built is one an assistive technology cannot use, and that is worth
        // refusing to open rather than discovering a frame later.
        let elements = element_class()?;
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
            // What makes the green button, the menu item below, and
            // `Backend::set_fullscreen` all mean the same thing; see the
            // constant.
            let _: () = send1(
                window,
                sel(c"setCollectionBehavior:"),
                COLLECTION_FULLSCREEN_PRIMARY,
            );

            // A view of our own, for the one reason given in the module header:
            // typed text arrives through a protocol, and a protocol needs an
            // object to conform to it. Everything else about the view — the
            // layer, the geometry, the mouse — is what the stock content view
            // would have done.
            let composer = Box::new(Composer::default());
            let view: Object = match content_view_class() {
                Ok(built) => {
                    let view: Object = send(built, sel(c"alloc"));
                    let view: Object = send1(view, sel(c"initWithFrame:"), content);
                    object_setInstanceVariable(
                        view,
                        COMPOSER_IVAR.as_ptr(),
                        std::ptr::from_ref(&*composer).cast_mut().cast::<c_void>(),
                    );
                    let _: () = send1(window, sel(c"setContentView:"), view);
                    // Only the first responder has an input context, so without
                    // this the view conforms to the protocol and is never asked.
                    let _: bool = send1(window, sel(c"makeFirstResponder:"), view);
                    view
                }
                Err(error) => {
                    objc_autoreleasePoolPop(pool);
                    return Err(error);
                }
            };
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
            // Before the window is shown, so a Quit pressed the instant it
            // appears is already an orderly one. A failure here is not fatal
            // and is not reported: the window works, Quit simply goes back to
            // being AppKit's abrupt one.
            if let Ok(delegate) = application_delegate() {
                let _: () = send1(application, sel(c"setDelegate:"), delegate);
            }

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
                composer,
                accessibility: Accessibility::new(elements),
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

    fn is_fullscreen(&self) -> bool {
        // AppKit's own answer, read from the style mask it maintains, rather
        // than a flag this program keeps: the person can leave a full screen
        // with the green button or with Escape, and neither goes through here.
        let mask: u64 = unsafe { send(self.window, sel(c"styleMask")) };
        mask & STYLE_FULLSCREEN != 0
    }

    fn set_fullscreen(&self, filling: bool) -> Result<(), Error> {
        // `toggleFullScreen:` is the only way in, and it is a toggle, so asking
        // for the state it is already in would leave it in the other one.
        if self.is_fullscreen() == filling {
            return Ok(());
        }
        unsafe {
            let _: () =
                send1(self.window, sel(c"toggleFullScreen:"), std::ptr::null_mut::<c_void>());
        }
        Ok(())
    }

    fn clipboard_text(&self) -> Result<Option<String>, Error> {
        unsafe {
            let pool = objc_autoreleasePoolPush();
            let pasteboard: Object = send(class(c"NSPasteboard"), sel(c"generalPasteboard"));
            if pasteboard.is_null() {
                objc_autoreleasePoolPop(pool);
                return Err(Error::Platform("there is no general pasteboard".into()));
            }
            let string: Object =
                send1(pasteboard, sel(c"stringForType:"), ns_string(PASTEBOARD_TYPE_STRING));
            // Null is a pasteboard holding an image, a file, or nothing — all of
            // which are "there is no text to paste" rather than a failure.
            let text = if string.is_null() { None } else { Some(from_ns_string(string)) };
            objc_autoreleasePoolPop(pool);
            Ok(text)
        }
    }

    fn set_clipboard_text(&self, text: &str) -> Result<(), Error> {
        // An `NSString` is built from a C string, so an interior NUL would cut
        // the text short without saying so. Dropping the NULs is the only
        // outcome that is neither a lie nor a refusal to copy.
        let text = std::ffi::CString::new(text.replace('\0', ""))
            .map_err(|_| Error::Platform("the text could not be copied".into()))?;
        unsafe {
            let pool = objc_autoreleasePoolPush();
            let pasteboard: Object = send(class(c"NSPasteboard"), sel(c"generalPasteboard"));
            if pasteboard.is_null() {
                objc_autoreleasePoolPop(pool);
                return Err(Error::Platform("there is no general pasteboard".into()));
            }
            // Ownership is claimed by clearing: a pasteboard written to without
            // this keeps whatever the last program declared it held.
            let _: isize = send(pasteboard, sel(c"clearContents"));
            let written: bool = send2(
                pasteboard,
                sel(c"setString:forType:"),
                ns_string(&text),
                ns_string(PASTEBOARD_TYPE_STRING),
            );
            objc_autoreleasePoolPop(pool);
            if written {
                Ok(())
            } else {
                Err(Error::Platform("the pasteboard would not take the text".into()))
            }
        }
    }

    fn update_accessibility(&self, update: &AccessUpdate) -> Result<(), Error> {
        unsafe {
            // Every element and array built below is autoreleased, and this is
            // called once a frame; without a pool of its own the whole tree
            // would accumulate until the loop next went round.
            let pool = objc_autoreleasePoolPush();
            self.accessibility.apply(self.view, update);
            objc_autoreleasePoolPop(pool);
        }
        Ok(())
    }

    fn set_composition_area(&self, area: Option<Rect>) -> Result<(), Error> {
        self.composer.caret.set(area);
        unsafe {
            let context: Object = send(self.view, sel(c"inputContext"));
            if !context.is_null() {
                // The input method asks for the position when it needs it, and
                // caches the answer; this is what tells it the answer changed.
                let _: () = send(context, sel(c"invalidateCharacterCoordinates"));
            }
        }
        Ok(())
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

            // The other half of the two-way accessibility seam, and the only
            // half that is not a `pump` of AppKit's queue: a press arrives at
            // an element rather than in that queue, so it waits in an inbox of
            // its own and joins the frame here. After the drain above, so that
            // a press delivered during this very wait is not held over to the
            // next one; see [`Activation::press`] and [`wake`].
            self.accessibility.inbox.drain(events);

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
    ///
    /// The input method sees the key first. What it makes of the keystroke —
    /// committed text, a changed composition, or nothing at all — arrives
    /// through the callbacks on the view and is already in `events` by the time
    /// this decides what else to report.
    fn translate_key(&self, event: Object, kind: u64, events: &mut Vec<Event>) {
        unsafe {
            let flags: u64 = send(event, sel(c"modifierFlags"));
            let modifiers = modifiers_of(flags);
            let code: u16 = send(event, sel(c"keyCode"));

            let was_composing = self.composer.is_composing();
            // A key held with the accelerator is a command, not typing: Command-R
            // must not also insert an "r" into whatever field has the keyboard.
            let offered = kind == EVENT_KEY_DOWN && !modifiers.command && self.interpret(event, events);

            // While a composition is in progress the keyboard belongs to the
            // input method: an arrow key is moving through its candidate list and
            // Return is choosing one. Reporting those as well would move a caret
            // and submit a form behind the list the person is still reading.
            if was_composing || self.composer.is_composing() {
                return;
            }

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

            // Reported whether or not this library has a name for the key: the
            // virtual key code is what the function row, the keypad, and the
            // two halves of a modifier pair have instead of a name, and it is
            // what anything forwarding a keystroke to another machine sends.
            // `key_for_code` is the meaning; `keyCode` is the key.
            let code = Some(KeyCode::new(u32::from(code)));
            events.push(if kind == EVENT_KEY_DOWN {
                Event::KeyDown { key, code, modifiers }
            } else {
                Event::KeyUp { key, code, modifiers }
            });

            // What is left is the case where there is no input method to ask —
            // an older system, or a view that failed to become the first
            // responder. Reading the characters off the event is what this did
            // before input methods were wired up, and it is right for a US
            // layout typing ASCII, which is the only thing it can still be
            // asked to do.
            if offered || kind != EVENT_KEY_DOWN || modifiers.command {
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

    /// Hands a key event to the input method, and says whether there was one.
    ///
    /// `events` is lent to the composer for the duration of the call and taken
    /// back afterwards, because the input method answers by calling back on the
    /// view — which is a C function that can carry no borrow of its own.
    fn interpret(&self, event: Object, events: &mut Vec<Event>) -> bool {
        let context: Object = unsafe { send(self.view, sel(c"inputContext")) };
        if context.is_null() {
            return false;
        }
        self.composer.events.set(std::ptr::from_mut(events));
        let _: bool = unsafe { send1(context, sel(c"handleEvent:"), event) };
        self.composer.events.set(std::ptr::null_mut());
        true
    }

    /// Where an event happened, in logical units from the top left.
    fn pointer_position(&self, event: Object) -> Point {
        let location: CgPoint = unsafe { send(event, sel(c"locationInWindow")) };
        // AppKit measures up from the bottom of the content area; everything
        // above measures down from the top.
        Point::new(location.x as f32, (self.size.get().1 - location.y) as f32)
    }
}

/// What the platform's input method is assembling, and where to put it.
///
/// # Why the state is here rather than in the window
///
/// The input method calls back on the *view*, and a view is an Objective-C
/// object with no room in it for a Rust structure. It gets one pointer-sized
/// instance variable instead, pointing at this — which the window owns, boxes so
/// that it never moves, and outlives every call that can reach it, because the
/// input method only ever answers a message this backend has just sent it.
#[derive(Default)]
struct Composer {
    /// What is being composed. Empty means nothing is.
    marked: RefCell<Composition>,
    /// The event list the call in progress is filling, or null between calls.
    ///
    /// The same shape, and for the same reason, as [`LiveResize::redraw`]: the
    /// callbacks are C functions and cannot carry a borrow, so the borrow is
    /// lent to them for exactly the duration of the call that provoked them.
    events: Cell<*mut Vec<Event>>,
    /// Where the caret is in the view, for the candidate window to sit beside.
    caret: Cell<Option<Rect>>,
}

impl Composer {
    /// Whether the input method has something in progress.
    fn is_composing(&self) -> bool {
        !self.marked.borrow().is_empty()
    }

    /// Takes a new composition from the input method and reports it.
    fn compose(&self, composition: Composition) {
        self.push(Event::Composing(composition.clone()));
        *self.marked.borrow_mut() = composition;
    }

    /// Ends the composition, if there is one, and reports that it ended.
    ///
    /// Silent when there was none, so committing ordinary typed text — which is
    /// most of what an input method does — does not announce the end of a
    /// composition that never began.
    fn finish(&self) {
        if !self.is_composing() {
            return;
        }
        *self.marked.borrow_mut() = Composition::default();
        self.push(Event::Composing(Composition::default()));
    }

    /// Adds an event to the list the call in progress is filling.
    ///
    /// Dropped when there is no such call. That is not a lost keystroke: the
    /// pointer is set around every message this backend sends the input method,
    /// so the only calls without one are ones nothing asked for.
    fn push(&self, event: Event) {
        let events = self.events.get();
        if events.is_null() {
            return;
        }
        // SAFETY: set by `Window::interpret` for the duration of one call into
        // the input method, and cleared before that call returns.
        unsafe { (*events).push(event) };
    }
}

/// Where a press waits between the object that received it and the next frame.
///
/// Filled from an accessibility callback and drained by [`Window::pump_events`],
/// which is the whole of the two-way traffic. A list, not a flag: a screen
/// reader can press twice between frames the way a finger can.
///
/// Owned by the window, in a box, so that its address survives the window being
/// moved — the same arrangement, for the same reason, as [`Composer`].
#[derive(Default)]
struct Inbox {
    presses: RefCell<Vec<Id>>,
}

impl Inbox {
    /// Notes that something was pressed.
    fn push(&self, id: Id) {
        self.presses.borrow_mut().push(id);
    }

    /// Takes everything waiting, as the events a frame reads.
    fn drain(&self, events: &mut Vec<Event>) {
        events.extend(self.presses.borrow_mut().drain(..).map(Event::Activated));
    }
}

/// What one accessibility object needs in order to report a press.
///
/// Boxed per element and pointed at by the element's instance variable, because
/// a press arrives at the object and the object is an Objective-C one with no
/// room for a Rust structure in it.
struct Activation {
    /// The node this object stands for.
    id: Id,
    /// Whether that node answers a press at all, as of the last frame.
    ///
    /// A cell because the answer changes without the object doing so: a button
    /// that has just been disabled is the same element and no longer presses.
    pressable: Cell<bool>,
    /// Where to leave a press. Null once the window that owned the inbox has
    /// gone, which is the one thing that can outlive it.
    inbox: Cell<*const Inbox>,
}

impl Activation {
    /// Reports a press, and says whether there was one to report.
    ///
    /// False is not a failure: it is an element whose node no longer answers a
    /// press, or one belonging to a window that has closed. Either way nothing
    /// was queued, and saying so is what stops an assistive technology
    /// announcing that something happened when nothing did.
    fn press(&self) -> bool {
        let inbox = self.inbox.get();
        if !self.pressable.get() || inbox.is_null() {
            return false;
        }
        // SAFETY: the pointer is the address of the window's own boxed `Inbox`,
        // written when this element was built and cleared before the window
        // lets the element go; see [`Accessibility::forget`].
        unsafe { &*inbox }.push(self.id);
        true
    }
}

/// One node of the interface, as the platform's own accessibility object.
struct Mirror {
    /// The `NSAccessibilityElement` standing for it, retained by us.
    element: Object,
    /// What that element reads to answer a press, and what it points at.
    ///
    /// Boxed so its address is settled before the element is given it, and so
    /// that moving the mirror does not move it.
    activation: Box<Activation>,
    /// What holds it, or `None` for a node hanging off the view itself.
    parent: Option<Id>,
    /// Which of its containing set it is, when it is one of a set.
    position: Option<usize>,
    /// How many nodes had been seen when this one first appeared.
    ///
    /// The order to read children in, for children that are not a numbered set.
    /// The tree arrives as a difference and a difference does not carry the
    /// order of the nodes that did not change, so first-seen is the best
    /// available answer — and is the right one for every interface whose rows
    /// are added at the end, which is what a log and a service list are.
    seen: usize,
}

/// The interface as an assistive technology sees it.
///
/// # Why a mirror rather than an answer
///
/// The other seams here are questions the platform asks and this backend
/// answers. Accessibility is not: AppKit hands a screen reader *objects* and
/// lets it ask them things directly, at moments of its own choosing, long after
/// any frame has been drawn. So the tree has to exist as platform objects that
/// outlive the frame, and what arrives from above — a difference — is applied to
/// them rather than answered from.
///
/// A press is the one thing that travels the other way, and it does not travel
/// far: it is left in [`Accessibility::inbox`] for the next pump to report. See
/// the module header for why that is an event and not a call.
struct Accessibility {
    /// One mirror per node of the interface, by the identity it keeps.
    nodes: RefCell<HashMap<Id, Mirror>>,
    /// How many nodes have ever been seen, for ordering new ones.
    seen: Cell<usize>,
    /// Presses waiting to be reported as events.
    ///
    /// Boxed because every element built here is given its address, and the
    /// window this belongs to is returned by value from [`Backend::open`].
    inbox: Box<Inbox>,
    /// The class every one of those elements is built from.
    ///
    /// Held rather than looked up each time: it is settled once for the process
    /// by [`element_class`], and a window that could not build it never opened.
    elements: Object,
}

impl Accessibility {
    /// An empty mirror, whose elements will be of `elements`.
    fn new(elements: Object) -> Self {
        Self { nodes: RefCell::default(), seen: Cell::default(), inbox: Box::default(), elements }
    }

    /// Applies one frame's difference to the mirror.
    fn apply(&self, view: Object, update: &AccessUpdate) {
        let mut nodes = self.nodes.borrow_mut();
        for id in &update.removed {
            if let Some(mirror) = nodes.remove(id) {
                forget(&mirror);
                // Ours since it was created; nothing else holds it once the
                // parent's children are rebuilt below.
                let _: () = unsafe { send(mirror.element, sel(c"release")) };
            }
        }
        for node in &update.changed {
            let seen = self.seen.get();
            let mirror = nodes.entry(node.id).or_insert_with(|| {
                self.seen.set(seen + 1);
                let activation = Box::new(Activation {
                    id: node.id,
                    pressable: Cell::new(false),
                    inbox: Cell::new(std::ptr::from_ref(&*self.inbox)),
                });
                let element = new_element(self.elements, &activation);
                Mirror { element, activation, parent: node.parent, position: None, seen }
            });
            mirror.parent = node.parent;
            mirror.position = node.position_in_set;
            // A disabled control does not answer a press, so neither does its
            // object: what a person is offered has to be what would happen.
            mirror.activation.pressable.set(node.actions.press && !node.state.disabled);
            describe(mirror.element, node, view);
        }
        relink(view, &nodes);
        drop(nodes);

        self.announce(view, update);
    }

    /// Tells the assistive technology what changed beyond the nodes themselves.
    ///
    /// Only notifications. Which element *is* focused was already applied by
    /// [`describe`], from the node's own [`AccessState::focused`] — a node whose
    /// focus changed is by definition a node that differs from the last frame,
    /// so the diff carries it here without this having to work it out a second
    /// time. What the diff cannot carry is the announcement, which is an event
    /// rather than a fact and is the whole of what is left to do.
    fn announce(&self, view: Object, update: &AccessUpdate) {
        let nodes = self.nodes.borrow();
        if update.focus_moved {
            let focused = update
                .focused
                .and_then(|id| nodes.get(&id))
                .map_or(view, |mirror| mirror.element);
            unsafe {
                NSAccessibilityPostNotification(focused, ns_string(c"AXFocusedUIElementChanged"));
            }
        }
        if update.structure_changed {
            // An object model built from the previous shape is now wrong, and
            // this is the only way to say so.
            unsafe { NSAccessibilityPostNotification(view, ns_string(c"AXLayoutChanged")) };
        }
    }
}

impl Drop for Accessibility {
    /// Lets go of every element, and cuts each one loose from this window first.
    ///
    /// An assistive technology may still hold one: the objects are handed out,
    /// and nothing obliges it to give them back before the window closes. An
    /// element cut loose answers no press and reads nothing — which is the only
    /// safe thing it can be once the inbox it pointed at has gone.
    fn drop(&mut self) {
        for mirror in self.nodes.borrow().values() {
            forget(mirror);
            let _: () = unsafe { send(mirror.element, sel(c"release")) };
        }
    }
}

/// Cuts an element loose from the window it was reporting to.
///
/// Both halves matter and both are here so they cannot be done singly: the
/// element stops reading the [`Activation`] that is about to be dropped, and
/// the activation stops pointing at an inbox it may outlive.
fn forget(mirror: &Mirror) {
    mirror.activation.inbox.set(std::ptr::null());
    unsafe {
        object_setInstanceVariable(mirror.element, ACTIVATION_IVAR.as_ptr(), std::ptr::null_mut())
    };
}

/// A fresh, empty accessibility element that reports to `activation`, retained.
///
/// Built from [`element_class`] rather than from `NSAccessibilityElement`
/// itself, which is the subclass's only reason to exist: AppKit's own class is
/// everything a node needs to be *read*, and cannot be pressed.
fn new_element(elements: Object, activation: &Activation) -> Object {
    unsafe {
        let element: Object = send(elements, sel(c"alloc"));
        let element: Object = send(element, sel(c"init"));
        object_setInstanceVariable(
            element,
            ACTIVATION_IVAR.as_ptr(),
            std::ptr::from_ref(activation).cast_mut().cast::<c_void>(),
        );
        element
    }
}

/// What a node holds, in whichever of AppKit's two vocabularies fits its role.
///
/// A checked checkbox and a chosen row are the same fact in this library —
/// [`AccessState::selected`] — and two different attributes on macOS. Keeping
/// that as a decision with a name, rather than an `if` inside the setters,
/// is what lets [`attributes_of`] be tested without a window.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    /// Nothing to say. The attribute is cleared rather than set to an empty
    /// string, which a screen reader would announce as "blank".
    None,
    /// Words: a field's text, or whatever [`El::value`](crate::El::value) said.
    Words(String),
    /// On or off, as `AXValue`'s number — how AppKit reports a checkbox, a
    /// radio button, and a tab, and what VoiceOver reads as "checked" or
    /// "selected" for them.
    Toggle(bool),
}

/// Every attribute one node comes to, worked out before anything is sent.
///
/// Plain data on purpose. The mapping from this library's vocabulary to
/// AppKit's is the part that can be got wrong and the part worth testing, and
/// it needs no window, no view, and no Objective-C to check — see the tests at
/// the foot of this file.
#[derive(Debug, Clone, PartialEq)]
struct Attributes {
    /// `AXRole`.
    role: &'static CStr,
    /// `AXDescription`, which is what `setAccessibilityLabel:` sets.
    label: String,
    /// `AXValue`, in whichever form the role calls for.
    value: Value,
    /// `AXEnabled`.
    enabled: bool,
    /// `AXFocused`.
    focused: bool,
    /// `AXSelected`, for the roles that are chosen rather than switched on.
    ///
    /// `None` leaves the attribute alone: selection means nothing to a heading,
    /// and a checkbox says the same thing through [`Value::Toggle`] instead.
    selected: Option<bool>,
}

/// Whether this role reports being chosen as its *value* rather than as
/// `AXSelected`.
///
/// AppKit's own division, and not a preference: VoiceOver reads a checkbox and
/// a radio button as "checked" or "selected" from the number in `AXValue`, and
/// reads a row or a menu item from the boolean in `AXSelected`. A checkbox
/// given `AXSelected` and no value is announced as neither.
fn selection_is_value(role: Role) -> bool {
    matches!(role, Role::Checkbox | Role::Radio | Role::Tab)
}

/// What one node comes to in AppKit's vocabulary.
///
/// Every field of [`AccessNode`] and [`AccessState`] is destructured here
/// without a rest pattern, so a field added to either stops this compiling
/// until somebody decides what the platform should do with it. That is the
/// guarantee that this mapping cannot quietly fall behind the tree — a test
/// can only check the fields it was written to know about.
fn attributes_of(node: &AccessNode) -> Attributes {
    let AccessNode {
        // The object standing for the node *is* its identity here; AppKit has
        // no attribute for one. `AXIdentifier` would want the author's own
        // `El::key`, which does not reach this far.
        id: _,
        // Applied by `relink` as `AXParent` and `AXChildren`, not here: a link
        // is a fact about two elements and is rebuilt from all of them at once.
        parent: _,
        role,
        name,
        value,
        state,
        bounds: _,
        // Both are carried by the *order* of the children `relink` builds, which
        // is how an assistive technology counts a set on macOS — it walks the
        // parent. There is no per-element attribute for either, and inventing
        // `AXIndex` for a list that is not a table would say something AppKit
        // does not mean by it.
        position_in_set: _,
        set_size: _,
        // `press` is answered by `accessibilityPerformPress` and offered by
        // `is_selector_allowed`; the other three deliberately have no route,
        // for the reasons in `accessibility`'s invariant.
        actions: _,
    } = node;
    let AccessState { disabled, focusable: _, focused, selected } = state;

    let chosen = *selected;
    Attributes {
        role: ax_role(*role),
        label: name.clone(),
        value: match (chosen, selection_is_value(*role), value) {
            // A checked checkbox's value is its state, in AppKit's vocabulary
            // as in this one — and it wins over words, because a checkbox
            // announced by a string is a checkbox whose state is never read.
            (Some(on), true, _) => Value::Toggle(on),
            (_, _, Some(words)) => Value::Words(words.clone()),
            _ => Value::None,
        },
        enabled: !*disabled,
        focused: *focused,
        selected: chosen.filter(|_| !selection_is_value(*role)),
    }
}

/// Fills an element in from the node it stands for.
///
/// Every decision was made in [`attributes_of`]; this only sends them. `bounds`
/// is the one thing it works out for itself, because turning a rectangle in the
/// window into one on the screen needs the view.
fn describe(element: Object, node: &AccessNode, view: Object) {
    let attributes = attributes_of(node);
    unsafe {
        let _: () = send1(element, sel(c"setAccessibilityRole:"), ns_string(attributes.role));
        let _: () = send1(element, sel(c"setAccessibilityLabel:"), text(&attributes.label));
        let value: Object = match &attributes.value {
            Value::None => std::ptr::null_mut(),
            Value::Words(words) => text(words),
            Value::Toggle(on) => send1(class(c"NSNumber"), sel(c"numberWithBool:"), *on),
        };
        let _: () = send1(element, sel(c"setAccessibilityValue:"), value);
        let _: () = send1(element, sel(c"setAccessibilityEnabled:"), attributes.enabled);
        // Set from the node rather than only when focus moves, so that the one
        // walk of the frame is the only thing this reads: a fact applied in two
        // places is a fact that can be applied in one of them and not the other.
        let _: () = send1(element, sel(c"setAccessibilityFocused:"), attributes.focused);
        // Sent even when selection means nothing here, which collapses `None`
        // and `Some(false)` — `AXSelected` is a boolean and has no third state
        // to collapse them into anything else. Writing it unconditionally is
        // what stops a stale one surviving: a row that stops being one, or an
        // element that changes role, would otherwise keep the last answer it
        // was given. Every attribute above is written every time for the same
        // reason.
        let _: () = send1(
            element,
            sel(c"setAccessibilitySelected:"),
            attributes.selected.unwrap_or(false),
        );
        let _: () = send1(element, sel(c"setAccessibilityFrame:"), on_screen(view, node.bounds));
    }
}

/// An `NSString` holding `words`, or nothing if they cannot be one.
///
/// A Rust string may hold a NUL and a C string may not. Answering null rather
/// than a string cut short at the NUL is the honest outcome: a name that
/// silently loses its second half is worse than one that is missing, because
/// only the second is obviously wrong.
fn text(words: &str) -> Object {
    match std::ffi::CString::new(words) {
        Ok(words) => ns_string(&words),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Rebuilds every parent and child link from the mirror's own records.
///
/// Wholesale rather than patched, for the reason a frame is compared rather than
/// tracked: an interface has tens of nodes, and a set of links rebuilt from the
/// parent each node carries cannot drift out of step with them.
fn relink(view: Object, nodes: &HashMap<Id, Mirror>) {
    let mut children: HashMap<Option<Id>, Vec<&Mirror>> = HashMap::new();
    for mirror in nodes.values() {
        children.entry(mirror.parent).or_default().push(mirror);
    }

    for (parent, mut group) in children {
        // A numbered set reads in its own order; everything else reads in the
        // order it first appeared. See [`Mirror::seen`].
        group.sort_by_key(|mirror| (mirror.position.unwrap_or(usize::MAX), mirror.seen));

        let owner = parent.and_then(|id| nodes.get(&id)).map_or(view, |mirror| mirror.element);
        unsafe {
            let list: Object = send(class(c"NSMutableArray"), sel(c"array"));
            for mirror in group {
                let _: () = send1(list, sel(c"addObject:"), mirror.element);
                let _: () = send1(mirror.element, sel(c"setAccessibilityParent:"), owner);
            }
            let _: () = send1(owner, sel(c"setAccessibilityChildren:"), list);
        }
    }
}

/// What a role is called in the platform's own vocabulary.
///
/// Every one of these is a role AppKit already knows, so a screen reader
/// describes a `rui` control in the same words it describes the rest of the
/// desktop. Where this library draws a distinction the platform does not — a
/// status, a meter — the nearest true thing is used rather than a role invented
/// here, which no assistive technology would recognise.
fn ax_role(role: Role) -> &'static CStr {
    match role {
        Role::Group | Role::Dialog => c"AXGroup",
        Role::Text | Role::Label | Role::Status => c"AXStaticText",
        Role::Heading => c"AXHeading",
        Role::Button => c"AXButton",
        Role::Field => c"AXTextField",
        Role::List => c"AXList",
        Role::ListItem => c"AXRow",
        Role::TabList => c"AXTabGroup",
        Role::Tab => c"AXRadioButton",
        Role::Meter => c"AXProgressIndicator",
        Role::Separator => c"AXSplitter",
        Role::Menu => c"AXMenu",
        Role::MenuItem => c"AXMenuItem",
        Role::Image => c"AXImage",
        Role::Checkbox => c"AXCheckBox",
        Role::Radio => c"AXRadioButton",
        Role::Slider => c"AXSlider",
    }
}

/// The name of the content-view class this backend builds at run time.
const VIEW_CLASS: &CStr = c"RuiContentView";

/// The instance variable pointing a view back at its [`Composer`].
const COMPOSER_IVAR: &CStr = c"rui_composer";

/// How the content-view class is named in a failure to build it.
const VIEW_OWNER: &str = "content view";

/// The `NSView` subclass that can receive text, built once per process.
///
/// A second window finds the class the first one built rather than failing on
/// the duplicate name — the same judgement the Windows backend makes about
/// registering its window class twice.
fn content_view_class() -> Result<Object, Error> {
    let existing = class(VIEW_CLASS);
    if !existing.is_null() {
        return Ok(existing);
    }

    let superclass = class(c"NSView");
    if superclass.is_null() {
        return Err(Error::Platform("AppKit is not loaded: there is no NSView".into()));
    }
    let built = unsafe { objc_allocateClassPair(superclass, VIEW_CLASS.as_ptr(), 0) };
    if built.is_null() {
        return Err(Error::Platform("a content view class could not be created".into()));
    }

    let pointer_size = std::mem::size_of::<*mut c_void>();
    let added = unsafe {
        class_addIvar(
            built,
            COMPOSER_IVAR.as_ptr(),
            pointer_size,
            pointer_size.trailing_zeros() as u8,
            c"^v".as_ptr(),
        )
    };
    if !added {
        return Err(Error::Platform("the content view would not take its instance variable".into()));
    }

    // The ten methods of `NSTextInputClient`, plus the one that lets the view
    // hold the keyboard at all. The type strings describe each signature to the
    // runtime; `Q` is an unsigned word, `@` an object, `:` a selector, `B` a
    // boolean, and `{...}` a struct passed by value.
    add_method(
        built,
        VIEW_OWNER,
        c"acceptsFirstResponder",
        accepts_first_responder as *const c_void,
        c"B@:",
    )?;
    add_method(
        built,
        VIEW_OWNER,
        c"insertText:replacementRange:",
        insert_text as *const c_void,
        c"v@:@{_NSRange=QQ}",
    )?;
    add_method(
        built,
        VIEW_OWNER,
        c"doCommandBySelector:",
        do_command_by_selector as *const c_void,
        c"v@::",
    )?;
    add_method(
        built,
        VIEW_OWNER,
        c"setMarkedText:selectedRange:replacementRange:",
        set_marked_text as *const c_void,
        c"v@:@{_NSRange=QQ}{_NSRange=QQ}",
    )?;
    add_method(built, VIEW_OWNER, c"unmarkText", unmark_text as *const c_void, c"v@:")?;
    add_method(built, VIEW_OWNER, c"hasMarkedText", has_marked_text as *const c_void, c"B@:")?;
    add_method(
        built,
        VIEW_OWNER,
        c"markedRange",
        marked_range as *const c_void,
        c"{_NSRange=QQ}@:",
    )?;
    add_method(
        built,
        VIEW_OWNER,
        c"selectedRange",
        selected_range as *const c_void,
        c"{_NSRange=QQ}@:",
    )?;
    add_method(
        built,
        VIEW_OWNER,
        c"validAttributesForMarkedText",
        valid_attributes_for_marked_text as *const c_void,
        c"@@:",
    )?;
    add_method(
        built,
        VIEW_OWNER,
        c"attributedSubstringForProposedRange:actualRange:",
        attributed_substring as *const c_void,
        c"@@:{_NSRange=QQ}^{_NSRange=QQ}",
    )?;
    add_method(
        built,
        VIEW_OWNER,
        c"firstRectForCharacterRange:actualRange:",
        first_rect_for_character_range as *const c_void,
        c"{CGRect={CGPoint=dd}{CGSize=dd}}@:{_NSRange=QQ}^{_NSRange=QQ}",
    )?;
    add_method(
        built,
        VIEW_OWNER,
        c"characterIndexForPoint:",
        character_index_for_point as *const c_void,
        c"Q@:{CGPoint=dd}",
    )?;

    // Declaring conformance is not a formality: `[view inputContext]` answers
    // nil for a view that does not conform, and a nil input context is a window
    // that can never be typed into in any language but this one.
    let protocol = unsafe { objc_getProtocol(c"NSTextInputClient".as_ptr()) };
    if protocol.is_null() || !unsafe { class_addProtocol(built, protocol) } {
        return Err(Error::Platform("the content view could not be made an input client".into()));
    }

    unsafe { objc_registerClassPair(built) };
    Ok(built)
}

/// Installs one method on the class being built.
///
/// `owner` names that class in the failure, because two of them are built here
/// and "a method would not go on" is not a message anybody can act on.
fn add_method(
    class: Object,
    owner: &str,
    name: &CStr,
    implementation: *const c_void,
    types: &CStr,
) -> Result<(), Error> {
    if unsafe { class_addMethod(class, sel(name), implementation, types.as_ptr()) } {
        return Ok(());
    }
    Err(Error::Platform(format!("the {owner} would not take {}", name.to_string_lossy())))
}

/// The name of the accessibility-element class this backend builds at run time.
const ELEMENT_CLASS: &CStr = c"RuiAccessibleElement";

/// The instance variable pointing an element back at its [`Activation`].
const ACTIVATION_IVAR: &CStr = c"rui_activation";

/// How the element class is named in a failure to build it.
const ELEMENT_OWNER: &str = "accessibility element";

/// The `NSAccessibilityElement` subclass that can be pressed, built once per
/// process.
///
/// AppKit's own class is everything a node needs in order to be read, and
/// nothing it needs in order to be *used*: a press is delivered as
/// `accessibilityPerformPress` to the object itself, so answering one means
/// having a class of our own. It adds exactly two methods and one instance
/// variable, and nothing about how a node is described goes through it.
///
/// Found rather than rebuilt for a second window, as [`content_view_class`] is.
fn element_class() -> Result<Object, Error> {
    let existing = class(ELEMENT_CLASS);
    if !existing.is_null() {
        return Ok(existing);
    }

    let superclass = class(c"NSAccessibilityElement");
    if superclass.is_null() {
        return Err(Error::Platform(
            "AppKit is not loaded: there is no NSAccessibilityElement".into(),
        ));
    }
    let built = unsafe { objc_allocateClassPair(superclass, ELEMENT_CLASS.as_ptr(), 0) };
    if built.is_null() {
        return Err(Error::Platform("an accessibility element class could not be created".into()));
    }

    let pointer_size = std::mem::size_of::<*mut c_void>();
    let added = unsafe {
        class_addIvar(
            built,
            ACTIVATION_IVAR.as_ptr(),
            pointer_size,
            pointer_size.trailing_zeros() as u8,
            c"^v".as_ptr(),
        )
    };
    if !added {
        return Err(Error::Platform(
            "the accessibility element would not take its instance variable".into(),
        ));
    }

    add_method(
        built,
        ELEMENT_OWNER,
        c"accessibilityPerformPress",
        perform_press as *const c_void,
        c"B@:",
    )?;
    add_method(
        built,
        ELEMENT_OWNER,
        c"isAccessibilitySelectorAllowed:",
        is_selector_allowed as *const c_void,
        c"B@::",
    )?;

    unsafe { objc_registerClassPair(built) };
    Ok(built)
}

/// The activation an element was built with, or `None` for one cut loose.
///
/// The reference is described as `'static` for the reason
/// [`composer_of`]'s is: the pointer is the address of a box the window owns,
/// and the one thing that can outlive it — an element an assistive technology
/// kept hold of — has had the variable cleared by then. See [`forget`].
fn activation_of(element: Object) -> Option<&'static Activation> {
    if element.is_null() {
        return None;
    }
    let mut pointer: *mut c_void = std::ptr::null_mut();
    unsafe { object_getInstanceVariable(element, ACTIVATION_IVAR.as_ptr(), &mut pointer) };
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the only thing ever written to that variable is the address of
    // the boxed `Activation` the element's own `Mirror` holds.
    Some(unsafe { &*pointer.cast::<Activation>() })
}

/// `-accessibilityPerformPress`: a screen reader activated this node.
///
/// It does not run anything. The press is reported, the loop is woken so that
/// it is reported *now*, and the next frame decides what it means — which is
/// the same frame, and the same line of it, that decides what a click means.
extern "C" fn perform_press(element: Object, _selector: Sel) -> bool {
    let Some(activation) = activation_of(element) else {
        return false;
    };
    if !activation.press() {
        return false;
    }
    wake();
    true
}

/// Ends the loop's wait, so that something just reported is acted on now.
///
/// The wait in [`Window::pump_events`] is
/// `nextEventMatchingMask:untilDate:inMode:dequeue:`, which comes back for an
/// `NSEvent` and for nothing else. An accessibility message is not one: it is
/// delivered to the main thread by the same run loop, from inside that call,
/// and leaves it none the wiser. So one event is posted purely to be returned.
/// Nothing reads it — [`Window::translate`] has no case for its type — and the
/// pump it interrupts goes on to drain the inbox as it always does.
///
/// Without this a press would be noticed whenever the window next woke for its
/// own reasons, which is up to [`App::idle_timeout`](crate::App::idle_timeout)
/// and by default a quarter of a second. A window that has chosen a long idle
/// because it shows something slow would have a button that looks broken.
fn wake() {
    unsafe {
        let pool = objc_autoreleasePoolPush();
        let application: Object = send(class(c"NSApplication"), sel(c"sharedApplication"));
        if !application.is_null() {
            // The one message here with more arguments than [`send4`] takes,
            // and the only one that will ever need this many: an `NSEvent` has
            // no shorter constructor. The signature is Apple's, spelled out so
            // that each argument goes where the ABI puts it.
            let build: unsafe extern "C" fn(
                Object,
                Sel,
                u64,
                CgPoint,
                u64,
                f64,
                isize,
                Object,
                i16,
                isize,
                isize,
            ) -> Object = std::mem::transmute(objc_msgSend as *const ());
            let event = build(
                class(c"NSEvent"),
                sel(
                    c"otherEventWithType:location:modifierFlags:timestamp:\
                       windowNumber:context:subtype:data1:data2:",
                ),
                EVENT_APPLICATION_DEFINED,
                CgPoint::default(),
                0,
                0.0,
                0,
                std::ptr::null_mut(),
                0,
                0,
                0,
            );
            if !event.is_null() {
                // At the front of the queue: the point is to be seen at once,
                // and there is nothing behind it this should wait for.
                let _: () = send2(application, sel(c"postEvent:atStart:"), event, true);
            }
        }
        objc_autoreleasePoolPop(pool);
    }
}

/// Everything an assistive technology may *write* that nothing here reads.
///
/// `NSAccessibilityElement` implements all three, so its own answer to
/// [`is_selector_allowed`] is yes for every one of them — which would offer a
/// person a value they can type into a field that will not take it, a focus
/// they can move that the keyboard will not follow, and a row they can select
/// that the interface will not show as selected. All three would be accepted
/// and silently do nothing.
///
/// They are refused instead. Each is a gap of exactly the shape the press had
/// before it was given an event, and each closes the same way — see the module
/// header. A refusal is a gap somebody can find; an accepted write that does
/// nothing is a bug report from a person who thought their screen reader was
/// broken.
const UNROUTED_WRITES: [&CStr; 3] =
    [c"setAccessibilityValue:", c"setAccessibilityFocused:", c"setAccessibilitySelected:"];

/// `-isAccessibilitySelectorAllowed:`: whether this element answers that.
///
/// Asked before an attribute is offered as writable or an action as available.
/// Two answers are ours: the press, which a node without an `on_click` must not
/// be offered, and the writes in [`UNROUTED_WRITES`], which nothing here reads.
/// Everything else is the superclass's own question about attributes this
/// backend sets through the ordinary setters, and is handed straight back.
///
/// Reading is unaffected. `AXValue`, `AXFocused`, and `AXSelected` are all
/// still reported — [`describe`] sets them every frame from the node. It is
/// only *setting them from outside* that is refused.
extern "C" fn is_selector_allowed(element: Object, _selector: Sel, asked: Sel) -> bool {
    if asked == sel(c"accessibilityPerformPress") {
        return activation_of(element).is_some_and(|activation| activation.pressable.get());
    }
    if UNROUTED_WRITES.iter().any(|name| asked == sel(name)) {
        return false;
    }
    // `NSAccessibilityElement` and not `RuiAccessibleElement`: dispatch starts
    // *above* the override, and starting at the class that defines it would be
    // this function calling itself.
    unsafe {
        send1_super(
            element,
            class(c"NSAccessibilityElement"),
            sel(c"isAccessibilitySelectorAllowed:"),
            asked,
        )
    }
}

/// The composer a view was built with, or `None` for a view built elsewhere.
///
/// The reference is described as `'static` because there is no shorter lifetime
/// to give it: the pointer was written by [`Backend::open`] and refers to a box
/// the window owns for as long as the process has a window at all. See
/// [`Composer`] for why that holds.
fn composer_of(view: Object) -> Option<&'static Composer> {
    if view.is_null() {
        return None;
    }
    let mut pointer: *mut c_void = std::ptr::null_mut();
    unsafe { object_getInstanceVariable(view, COMPOSER_IVAR.as_ptr(), &mut pointer) };
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the only thing ever written to that variable is the address of
    // the window's own boxed `Composer`.
    Some(unsafe { &*pointer.cast::<Composer>() })
}

/// `-acceptsFirstResponder`: yes, or the view is never offered the keyboard.
extern "C" fn accepts_first_responder(_view: Object, _selector: Sel) -> bool {
    true
}

/// `-insertText:replacementRange:`: the input method settled on some text.
///
/// The end of the story for a keystroke: whatever composition was in progress is
/// over, and this is what it came to.
extern "C" fn insert_text(view: Object, _selector: Sel, string: Object, _replacement: NsRange) {
    let Some(composer) = composer_of(view) else {
        return;
    };
    composer.finish();
    let typed: String = text_of(string)
        .chars()
        .filter(|character| !character.is_control() && !is_function_key(*character))
        .collect();
    if !typed.is_empty() {
        composer.push(Event::Text(typed));
    }
}

/// `-setMarkedText:selectedRange:replacementRange:`: the composition changed.
extern "C" fn set_marked_text(
    view: Object,
    _selector: Sel,
    string: Object,
    selected: NsRange,
    _replacement: NsRange,
) {
    let Some(composer) = composer_of(view) else {
        return;
    };
    let text = text_of(string);
    let selection = if selected.location == NOT_FOUND {
        // No selection of its own: the caret belongs at the end, which is where
        // the next keystroke will land.
        text.len()..text.len()
    } else {
        let start = byte_offset(&text, selected.location);
        let end = byte_offset(&text, selected.location.saturating_add(selected.length));
        start..end
    };
    composer.compose(Composition { text, selection });
}

/// `-unmarkText`: the composition was abandoned or has just been committed.
extern "C" fn unmark_text(view: Object, _selector: Sel) {
    if let Some(composer) = composer_of(view) {
        composer.finish();
    }
}

/// `-hasMarkedText`: whether something is being composed.
extern "C" fn has_marked_text(view: Object, _selector: Sel) -> bool {
    composer_of(view).is_some_and(Composer::is_composing)
}

/// `-markedRange`: where the composition sits in the text we are showing.
///
/// The input method is shown the composition and nothing else, so the answer is
/// always the whole of it starting at zero.
extern "C" fn marked_range(view: Object, _selector: Sel) -> NsRange {
    match composer_of(view) {
        Some(composer) if composer.is_composing() => {
            NsRange { location: 0, length: utf16_len(&composer.marked.borrow().text) }
        }
        _ => NsRange::NONE,
    }
}

/// `-selectedRange`: which part of that composition is being edited.
extern "C" fn selected_range(view: Object, _selector: Sel) -> NsRange {
    let Some(composer) = composer_of(view) else {
        return NsRange::EMPTY;
    };
    let marked = composer.marked.borrow();
    let start = utf16_len(&marked.text[..marked.selection.start]);
    let length = utf16_len(&marked.text[marked.selection.clone()]);
    NsRange { location: start, length }
}

/// `-validAttributesForMarkedText`: none — a composition is drawn our way.
///
/// An empty array rather than nil, which some input methods take as an answer
/// they may dereference.
extern "C" fn valid_attributes_for_marked_text(_view: Object, _selector: Sel) -> Object {
    unsafe { send(class(c"NSArray"), sel(c"array")) }
}

/// `-attributedSubstringForProposedRange:actualRange:`: nothing to hand back.
///
/// Answering this properly means handing the input method the surrounding
/// document, which is the application's state and not the window's. Input
/// methods treat nil as "that text is not available", which is true.
extern "C" fn attributed_substring(
    _view: Object,
    _selector: Sel,
    _range: NsRange,
    actual: *mut NsRange,
) -> Object {
    if !actual.is_null() {
        // SAFETY: an out-parameter the caller allocated, or null.
        unsafe { *actual = NsRange::EMPTY };
    }
    std::ptr::null_mut()
}

/// `-firstRectForCharacterRange:actualRange:`: where to put the candidate window.
///
/// In screen coordinates, from the caret the last frame reported. Answered from
/// the view rather than from the window because this is called back on the view
/// and the two share a coordinate space.
extern "C" fn first_rect_for_character_range(
    view: Object,
    _selector: Sel,
    _range: NsRange,
    actual: *mut NsRange,
) -> CgRect {
    if !actual.is_null() {
        // SAFETY: an out-parameter the caller allocated, or null.
        unsafe { *actual = NsRange::EMPTY };
    }
    match composer_of(view).and_then(|composer| composer.caret.get()) {
        Some(caret) => on_screen(view, caret),
        None => CgRect::default(),
    }
}

/// Where a rectangle of the interface is on the screen.
///
/// Two changes of frame in one: AppKit measures a view up from its bottom edge
/// while everything above this file measures down from the top, and the window
/// is somewhere on a desktop that neither of them knows about.
fn on_screen(view: Object, area: Rect) -> CgRect {
    let frame = unsafe { send_rect(view, sel(c"frame")) };
    let in_view = CgRect {
        origin: CgPoint {
            x: f64::from(area.x),
            y: frame.size.height - f64::from(area.y + area.h),
        },
        size: CgSize { width: f64::from(area.w), height: f64::from(area.h) },
    };

    let window: Object = unsafe { send(view, sel(c"window")) };
    if window.is_null() {
        return in_view;
    }
    unsafe { send1_rect(window, sel(c"convertRectToScreen:"), in_view) }
}

/// `-characterIndexForPoint:`: which character is under a screen position.
///
/// Used to drag a selection out of the candidate list into the document, which
/// needs the document this does not hand over. `NSNotFound` is the answer for a
/// position over no text.
extern "C" fn character_index_for_point(_view: Object, _selector: Sel, _point: CgPoint) -> usize {
    NOT_FOUND
}

/// `-doCommandBySelector:`: a key the input method decided was not text.
///
/// Deliberately nothing. Arrow keys, Return, and Tab arrive here having already
/// been reported as [`Event::KeyDown`] from their key codes, and acting on them
/// twice would move a caret two characters for one press. Implementing it at all
/// is what stops AppKit passing the key up the responder chain and beeping.
extern "C" fn do_command_by_selector(_view: Object, _selector: Sel, _command: Sel) {}

/// The text of an `NSString`, or of an `NSAttributedString`.
///
/// The input method sends either, depending on whether it has anything to say
/// about how the text should look. It has, and we ignore it: a composition is
/// drawn underlined by the field, in the interface's own type and colours.
fn text_of(string: Object) -> String {
    if string.is_null() {
        return String::new();
    }
    let attributed: bool = unsafe { send1(string, sel(c"respondsToSelector:"), sel(c"string")) };
    let plain: Object = if attributed { unsafe { send(string, sel(c"string")) } } else { string };
    from_ns_string(plain)
}

/// The byte offset in `text` of a position counted in UTF-16 units.
///
/// Saturates at the end rather than panicking: a position past the end is the
/// input method describing a string it thinks it has and we do not.
fn byte_offset(text: &str, utf16: usize) -> usize {
    let mut counted = 0;
    for (offset, character) in text.char_indices() {
        if counted >= utf16 {
            return offset;
        }
        counted += character.len_utf16();
    }
    text.len()
}

/// How long `text` is in UTF-16 units, which is how the platform counts it.
fn utf16_len(text: &str) -> usize {
    text.chars().map(char::len_utf16).sum()
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

/// The name of the application-delegate class this backend builds at run time.
const DELEGATE_CLASS: &CStr = c"RuiAppDelegate";

/// How that class is named in a failure to build it.
const DELEGATE_OWNER: &str = "application delegate";

/// `NSTerminateCancel`: the application is not to be torn down after all.
const TERMINATE_CANCEL: usize = 0;

/// The delegate that turns Quit into an orderly close, built once per process.
///
/// # The defect this exists for
///
/// AppKit's `terminate:` — which is Command-Q, the Quit item, the Dock's own
/// Quit and the AppleEvent `osascript` sends — tears the process down from
/// inside the run loop. [`Backend::run`](crate::shell::Backend) never returns,
/// so **nothing an application put on the stack is ever dropped**: no
/// destructor, no flush, no child process reaped. The selfhost console found it
/// the hard way — quitting left the `ssh -L` it had spawned holding port 9191
/// for ever, so the next launch reported a tunnel it could not open while
/// talking happily through the orphan.
///
/// Closing the window with the red button has never had this problem, because
/// that path is a fact the loop reads: the window stops being visible, the loop
/// ends, `run` returns, and everything unwinds. So the fix is to make Quit take
/// exactly that path — close the windows, refuse the termination, and let the
/// loop notice — rather than to invent a second shutdown that would then have
/// to be kept in step with the first.
fn application_delegate() -> Result<Object, Error> {
    let class_object = match class(DELEGATE_CLASS) {
        existing if !existing.is_null() => existing,
        _ => {
            let superclass = class(c"NSObject");
            if superclass.is_null() {
                return Err(Error::Platform("the Objective-C runtime has no NSObject".into()));
            }
            let built = unsafe { objc_allocateClassPair(superclass, DELEGATE_CLASS.as_ptr(), 0) };
            if built.is_null() {
                return Err(Error::Platform("a delegate class could not be created".into()));
            }
            // `Q@:@` — returns an unsigned word, takes the receiver, the
            // selector, and the application asking.
            add_method(
                built,
                DELEGATE_OWNER,
                c"applicationShouldTerminate:",
                should_terminate as *const c_void,
                c"Q@:@",
            )?;
            unsafe { objc_registerClassPair(built) };
            built
        }
    };

    let delegate: Object = unsafe { send(send(class_object, sel(c"alloc")), sel(c"init")) };
    if delegate.is_null() {
        return Err(Error::Platform("a delegate could not be created".into()));
    }
    Ok(delegate)
}

/// Answers a Quit by closing every window and refusing to terminate.
///
/// The loop is watching each window's visibility, so this *is* the shutdown:
/// the frame after this one finds nothing visible, ends, and lets the
/// application's own destructors run. See [`application_delegate`].
///
/// # Safety
///
/// Called by the Objective-C runtime with an `NSApplication` as `application`.
unsafe extern "C" fn should_terminate(
    _self: Object,
    _selector: Sel,
    application: Object,
) -> usize {
    unsafe {
        let windows: Object = send(application, sel(c"windows"));
        let count: usize = send(windows, sel(c"count"));
        for index in 0..count {
            let window: Object = send1(windows, sel(c"objectAtIndex:"), index);
            if !window.is_null() {
                let _: () = send1(window, sel(c"close"), std::ptr::null_mut::<c_void>());
            }
        }
    }
    TERMINATE_CANCEL
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

        // A View menu with one item, for the shortcut it carries. Control-
        // Command-F is where every Mac application puts this, and a menu is the
        // only place a Mac keyboard shortcut can live: an application with no
        // menu item for it has no shortcut for it, however willing its window.
        // The item has no target, so it travels the responder chain and reaches
        // whichever window is key — which is how AppKit's own is written.
        let view_item: Object = send(send(class(c"NSMenuItem"), sel(c"alloc")), sel(c"init"));
        let _: () = send1(bar, sel(c"addItem:"), view_item);
        let view_menu: Object =
            send1(send(class(c"NSMenu"), sel(c"alloc")), sel(c"initWithTitle:"), ns_string(c"View"));
        let full_screen: Object = send3(
            send(class(c"NSMenuItem"), sel(c"alloc")),
            sel(c"initWithTitle:action:keyEquivalent:"),
            ns_string(c"Enter Full Screen"),
            sel(c"toggleFullScreen:"),
            ns_string(c"f"),
        );
        let _: () = send1(
            full_screen,
            sel(c"setKeyEquivalentModifierMask:"),
            MODIFIER_CONTROL | MODIFIER_COMMAND,
        );
        let _: () = send1(view_menu, sel(c"addItem:"), full_screen);
        let _: () = send1(view_item, sel(c"setSubmenu:"), view_menu);
        let _: () = send1(application, sel(c"setMainMenu:"), bar);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accessibility::AccessActions;

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

    /// A node carrying one fact, so a test can say which fact it is asserting.
    ///
    /// Every field is named, and none is defaulted away, for the reason
    /// [`attributes_of`] destructures rather than reads: a field added to
    /// [`AccessNode`] has to be answered for here too.
    fn node(role: Role) -> AccessNode {
        AccessNode {
            id: Id::new("a node"),
            parent: None,
            role,
            name: "Notify on failure".into(),
            value: None,
            state: AccessState {
                disabled: false,
                focusable: false,
                focused: false,
                selected: None,
            },
            bounds: Rect::new(0.0, 0.0, 10.0, 10.0),
            position_in_set: None,
            set_size: None,
            actions: AccessActions::default(),
        }
    }

    #[test]
    fn a_checked_box_is_reported_as_a_number_because_that_is_what_voiceover_reads() {
        // The division AppKit makes and this library does not: a checkbox, a
        // radio button, and a tab report being chosen as their *value*. Given
        // `AXSelected` instead, VoiceOver announces neither state.
        for role in [Role::Checkbox, Role::Radio, Role::Tab] {
            let mut checked = node(role);
            checked.state.selected = Some(true);
            let attributes = attributes_of(&checked);
            assert_eq!(attributes.value, Value::Toggle(true), "{role:?} reports its state");
            assert_eq!(attributes.selected, None, "{role:?} does not also claim AXSelected");

            let mut unchecked = node(role);
            unchecked.state.selected = Some(false);
            assert_eq!(attributes_of(&unchecked).value, Value::Toggle(false));
        }
    }

    #[test]
    fn a_chosen_row_is_reported_as_selected_because_that_is_what_a_row_is() {
        for role in [Role::ListItem, Role::MenuItem] {
            let mut chosen = node(role);
            chosen.state.selected = Some(true);
            let attributes = attributes_of(&chosen);
            assert_eq!(attributes.selected, Some(true), "{role:?} reports AXSelected");
            assert_eq!(attributes.value, Value::None, "{role:?} does not also claim a value");
        }
    }

    #[test]
    fn a_node_that_selection_means_nothing_to_claims_neither() {
        // The reason `selected` is an `Option`: a heading is not unselected, it
        // is a heading. Reporting `false` would have a screen reader offer a
        // distinction the interface never drew.
        let attributes = attributes_of(&node(Role::Heading));
        assert_eq!(attributes.selected, None);
        assert_eq!(attributes.value, Value::None);
    }

    #[test]
    fn a_fields_words_are_its_value() {
        let mut field = node(Role::Field);
        field.value = Some("mongod".into());
        assert_eq!(attributes_of(&field).value, Value::Words("mongod".into()));
    }

    #[test]
    fn a_checkboxs_state_wins_over_words_it_was_also_given() {
        // Both cannot be `AXValue`, and a checkbox announced by a string is one
        // whose checked state is never read out at all.
        let mut both = node(Role::Checkbox);
        both.value = Some("on".into());
        both.state.selected = Some(true);
        assert_eq!(attributes_of(&both).value, Value::Toggle(true));
    }

    #[test]
    fn every_other_fact_of_a_node_reaches_the_attribute_it_belongs_to() {
        let mut every = node(Role::Button);
        every.state.disabled = true;
        every.state.focused = true;
        let attributes = attributes_of(&every);

        assert_eq!(attributes.role, c"AXButton");
        assert_eq!(attributes.label, "Notify on failure");
        assert!(!attributes.enabled, "AXEnabled is the inverse of disabled");
        assert!(attributes.focused, "AXFocused comes from the node, not from the diff");
    }

    #[test]
    fn a_name_that_cannot_be_a_c_string_is_absent_rather_than_cut_short() {
        // A name losing its second half at a NUL is worse than one that is
        // missing: only the second is obviously wrong to whoever hears it.
        assert!(text("Notify\0on failure").is_null());
        assert!(!text("Notify on failure").is_null());
    }

    #[test]
    fn nothing_a_screen_reader_writes_is_accepted_and_dropped() {
        // Each of these is a fact this backend can report and cannot be told.
        // Accepting the write would be worse than refusing it; see
        // `UNROUTED_WRITES`.
        for name in UNROUTED_WRITES {
            assert!(
                !is_selector_allowed(std::ptr::null_mut(), std::ptr::null(), sel(name)),
                "{name:?} must not be offered as writable"
            );
        }
    }

    #[test]
    fn the_bitmap_format_matches_what_the_canvas_stores() {
        // Alpha ignored and in the first byte, 32-bit words read little-endian:
        // blue, green, red, ignored — which is a canvas word in memory.
        assert_eq!(BITMAP_INFO, 6 | 8192);
    }
}
