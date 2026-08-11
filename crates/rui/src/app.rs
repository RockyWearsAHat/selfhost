//! Running an interface: the loop, and the one call that starts it.
//!
//! ```ignore
//! struct Counter { count: i32 }
//!
//! fn view(counter: &Counter) -> El<Counter> {
//!     col((
//!         title(format!("Count: {}", counter.count)),
//!         button("Increment").on_click(|counter: &mut Counter| counter.count += 1),
//!     ))
//!     .gap(12.0)
//!     .pad(24.0)
//!     .center()
//! }
//!
//! fn main() -> Result<(), rui::Error> {
//!     rui::run("Counter", Counter { count: 0 }, view)
//! }
//! ```
//!
//! # What a frame is
//!
//! Describe, lay out, draw, then run whatever was clicked. Four steps in that
//! order, every frame, with no state carried between them but the interaction
//! state in [`Memory`] — which is why an interface written with this library
//! cannot show something its data no longer says.
//!
//! Each of those frames is drawn from a [`Theme`], derived from whether the
//! desktop is light or dark. An application supplies its own with
//! [`App::theme`]; one that says nothing is drawn with [`Theme::new`].
//!
//! # What else a frame produces
//!
//! The same walk of the finished tree that hands a test its probes builds the
//! accessibility tree and compares it with the last frame's, so what an
//! assistive technology is told is a difference rather than a repetition. See
//! [`App::accessibility_update`] and [`accessibility`](crate::accessibility).
//!
//! # Reloading it while it runs
//!
//! Built with `--features reload`, a window notices that the file it is running
//! from has been rebuilt, saves what it is showing, and starts the new build in
//! its place. Off by default and absent from a release build entirely — see
//! `App::reloadable` and the `reload` module, neither of which exists in a
//! build without the feature, which is why neither is linked here.

use crate::accessibility::{AccessTree, AccessUpdate};
use crate::canvas::Canvas;
use crate::element::El;
use crate::input::Input;
use crate::layout::{self, Ctx};
use crate::memory::{Id, Memory};
use crate::paint::{self, Frame};
use crate::shell::{self, Error, LoadedFonts, WindowOptions};
use crate::text::{FontId, Fonts};
use crate::theme::{Appearance, Theme};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

/// What running an application in a window amounts to.
///
/// Ordinarily the window loop and nothing else. With developer reload compiled
/// in it is that same loop, wrapped: the executable is watched while the window
/// is up, and the program starts its successor once the window has closed. The
/// two have the same signature on purpose, so there is one call site rather
/// than a branch in [`App::run_with_fonts`].
#[cfg(not(feature = "reload"))]
use crate::shell::run as run_windowed;
#[cfg(feature = "reload")]
use crate::reload::run as run_windowed;

/// An application: some state, and a function from that state to a description.
///
/// Built with [`App::new`], adjusted with the setters, and started with
/// [`App::run`]. [`run`] is the same thing in one call, for the common case
/// where the defaults will do.
pub struct App<S> {
    state: S,
    view: View<S>,
    options: WindowOptions,
    idle: Duration,
    running: Condition<S>,
    /// What the interface is drawn from, given the desktop's appearance.
    theme: ThemeFor,
    /// How the bare window is painted before anything is laid on it.
    ///
    /// `None` for the library's own ground — the palette's vertical gradient —
    /// which is what nearly every application wants. See [`App::ground`].
    ground: Option<Ground>,
    /// Whether the window should fill the screen, and how to say it changed.
    ///
    /// `None` for an application that never asked, which is every one that does
    /// not draw something worth a whole screen: nothing is read from the window
    /// and nothing is ever asked of it. See [`App::fullscreen`].
    fullscreen: Option<(Condition<S>, Report<S>)>,
    /// What another thread has asked the loop for.
    ///
    /// Always present, and free while nobody holds a clone: an unrequested
    /// window reads two atomics per frame and waits exactly as it always did.
    /// See [`Redraw`].
    redraw: Redraw,
    /// What the last frame amounted to, for anything that cannot see it.
    access: AccessTree,
    /// How that differed from the frame before, which is what gets pushed.
    access_update: AccessUpdate,
    /// How to save this and start the new build, once asked for.
    ///
    /// `None` until [`App::reloadable`], which an application only calls in a
    /// build that wants it. Reached from [`crate::reload`], which owns
    /// everything the field means.
    #[cfg(feature = "reload")]
    pub(crate) reload: Option<crate::reload::Reload<S>>,
}

/// What describes the interface: a function from the state to a description.
type View<S> = Box<dyn Fn(&S) -> El<S>>;

/// Something the application is asked about its own state each frame.
type Condition<S> = Box<dyn Fn(&S) -> bool>;

/// How a change the platform made on its own is written into the state.
type Report<S> = Box<dyn Fn(&mut S, bool)>;

/// What the interface is drawn from, derived once a frame from the appearance.
///
/// A function of the appearance and the two faces rather than a stored value,
/// because none of the three is known when an application is built: the desktop
/// can turn the lights out under a running window, and the faces are found on
/// the machine the program is running on. See [`App::theme`].
type ThemeFor = Box<dyn Fn(Appearance, FontId, FontId) -> Theme>;

/// How an application paints the bare window under its interface.
///
/// Handed the whole canvas and the theme in force, before layout has its say;
/// it is responsible for covering every pixel, gradient and all, because it
/// *replaces* the library's clear rather than following it.
type Ground = Box<dyn Fn(&mut Canvas, &Theme)>;

/// A way to ask for a frame from a thread that is not drawing one.
///
/// Everything else in this library is driven by the person using it: a key, a
/// click, an animation the interface itself started. This is for the case that
/// is not — a picture arriving on a socket, a job finishing, a log line read on
/// a worker thread. Without it, such a program shows its news at
/// [`App::idle_timeout`]: four times a second by default, and twice a second in
/// a console that lengthened the timeout to keep an idle window free.
///
/// It is [`Send`] and [`Sync`] and holds no part of the interface, so it can be
/// cloned into any thread or task. Nothing it does can run application code,
/// draw, or touch the state — it says *when*, and never *what*.
///
/// ```ignore
/// let app = App::new("Console", state, view);
/// let redraw = app.redraw();
/// redraw.within(Duration::from_millis(16));      // while a stream is live
/// std::thread::spawn(move || {
///     while let Some(frame) = stream.next() {
///         // ... put the frame where the view can see it ...
///         redraw.request();
///     }
/// });
/// app.run()
/// ```
///
/// # Why it is a bound on latency and not a wake-up
///
/// A request does not interrupt the window: the loop is inside the platform's
/// own event wait, and prising it out of there means one primitive per backend —
/// a run-loop source, a posted message, a pipe an X connection selects on —
/// which is three implementations of the hardest thing to test in the library
/// for a saving of at most one wait.
///
/// So instead a request *shortens* the wait: [`Redraw::within`] says how long a
/// frame may be left waiting, and the loop asks the platform for input for no
/// longer than that. A live stream sets it to a frame's worth of time and gets
/// frames at that pace; nothing else pays anything, because a window with no
/// handle in another thread never lowers the bound and waits exactly as it did.
/// The trade is stated here rather than hidden: this buys bounded latency, not
/// zero latency, and it is the [`Backend`](crate::shell) seam staying at the
/// size it is.
#[derive(Debug, Clone)]
pub struct Redraw(Arc<Pending>);

/// What a [`Redraw`] and the loop share.
#[derive(Debug, Default)]
struct Pending {
    /// Whether a frame has been asked for since the last one was drawn.
    wanted: AtomicBool,
    /// The longest a request may be left waiting, in milliseconds.
    ///
    /// Zero — the state a window starts in and returns to — means the loop
    /// waits [`App::idle_timeout`] as it always did.
    latency: AtomicU32,
}

impl Redraw {
    /// Asks for a frame to be drawn.
    ///
    /// Cheap enough to call per arriving item and idempotent: ten requests
    /// between two frames are one frame, because what is being asked for is
    /// that the screen catch up with the state, not that a frame happen ten
    /// times. Ordering is `Release`/`Acquire` against the loop's own read, so
    /// whatever was written before the request is visible to the frame that
    /// answers it.
    pub fn request(&self) {
        self.0.wanted.store(true, Ordering::Release);
    }

    /// How long a request may be left waiting before the loop answers it.
    ///
    /// The pace at which the interface can keep up with something arriving from
    /// outside: sixteen milliseconds for a video-rate stream, a second for a
    /// log. It is a ceiling and not a frame rate — nothing is drawn unless a
    /// request or an event asks for it.
    ///
    /// [`Duration::ZERO`] puts the window back to sleep, and is what to call
    /// when whatever was arriving has stopped. Leaving a short bound set with
    /// nothing to draw does not spin — an unrequested wake draws nothing — but
    /// it does wake a sleeping laptop's core sixty times a second for no reason.
    pub fn within(&self, latency: Duration) {
        let bounded = latency.as_millis().try_into().unwrap_or(u32::MAX);
        self.0.latency.store(bounded, Ordering::Release);
    }

    /// Whether a frame has been asked for, clearing the request.
    fn take(&self) -> bool {
        self.0.wanted.swap(false, Ordering::Acquire)
    }

    /// The longest the loop may wait, or `None` for as long as it likes.
    fn bound(&self) -> Option<Duration> {
        match self.0.latency.load(Ordering::Acquire) {
            0 => None,
            milliseconds => Some(Duration::from_millis(u64::from(milliseconds))),
        }
    }
}

/// How long the loop waits for input before drawing again anyway.
///
/// A quarter of a second by default: enough that an interface showing something
/// which changes on its own — a service that crashed, a log that grew — keeps up
/// without anyone touching it, and rare enough that an idle window costs
/// nothing, since a frame identical to the one on screen is never presented.
const DEFAULT_IDLE: Duration = Duration::from_millis(250);

impl<S> App<S> {
    /// An application showing `state`, described by `view`.
    pub fn new(
        title: impl Into<String>,
        state: S,
        view: impl Fn(&S) -> El<S> + 'static,
    ) -> Self {
        Self {
            state,
            view: Box::new(view),
            options: WindowOptions { title: title.into(), ..WindowOptions::default() },
            idle: DEFAULT_IDLE,
            running: Box::new(|_| true),
            theme: Box::new(Theme::new),
            ground: None,
            fullscreen: None,
            redraw: Redraw(Arc::new(Pending::default())),
            access: AccessTree::new(),
            access_update: AccessUpdate::default(),
            #[cfg(feature = "reload")]
            reload: None,
        }
    }

    /// Lets a developer's rebuild replace this program without losing what is
    /// on screen.
    ///
    /// Only compiled with `--features reload`, which an application turns on
    /// for its own development and never for a release. `save` writes the state
    /// down and `restore` reads it back; between them this library never learns
    /// what `S` is, which is why it needs no serialisation library to do this.
    /// Neither is called unless a rebuild actually happens.
    ///
    /// ```ignore
    /// let app = App::new("Counter", Counter { count: 0 }, view);
    /// #[cfg(feature = "reload")]
    /// let app = app.reloadable(
    ///     |counter: &Counter| counter.count.to_string().into_bytes(),
    ///     |saved: &[u8]| {
    ///         let text = std::str::from_utf8(saved).map_err(|e| e.to_string())?;
    ///         let count = text.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
    ///         Ok(Counter { count })
    ///     },
    /// )?;
    /// app.run()
    /// ```
    ///
    /// Called once, before [`App::run`]. If this process *is* a restart, the
    /// previous run's state is read here and replaces the one this was built
    /// with — so the state passed to [`App::new`] is what a first run shows and
    /// what a broken handoff never silently falls back to. The message in
    /// `restore`'s `Err` is what the developer is shown; nothing else reads it.
    ///
    /// See [`reload`](crate::reload) for what does and does not survive a
    /// restart. It is a restart, not hot module replacement.
    #[cfg(feature = "reload")]
    pub fn reloadable(
        mut self,
        save: impl Fn(&S) -> Vec<u8> + 'static,
        restore: impl Fn(&[u8]) -> Result<S, String> + 'static,
    ) -> Result<Self, Error> {
        let (reload, restored) = crate::reload::begin(Box::new(save), &restore)?;
        if let Some(state) = restored {
            self.state = state;
        }
        self.reload = Some(reload);
        Ok(self)
    }

    /// How big the window opens.
    pub fn size(mut self, width: f32, height: f32) -> Self {
        self.options.width = width;
        self.options.height = height;
        self
    }

    /// The smallest the window may be dragged to.
    ///
    /// Worth setting: a layout has a size below which it stops being readable,
    /// and refusing to go there is better than drawing an unusable interface.
    pub fn min_size(mut self, width: f32, height: f32) -> Self {
        self.options.min_width = width;
        self.options.min_height = height;
        self
    }

    /// How long the loop may wait for input before drawing again.
    ///
    /// Shorter keeps up better with a machine that changes on its own; longer
    /// costs less while nothing is happening. It never delays input, which ends
    /// the wait the moment it arrives.
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle = timeout;
        self
    }

    /// What the interface is drawn from: its colours, sizes, corners, and type.
    ///
    /// The library's own is [`Theme::new`], and an application that says nothing
    /// gets exactly that. Supplying one reaches every widget at once, because
    /// none of them names a colour or a corner for itself:
    ///
    /// ```ignore
    /// use rui::{App, CornerStyle, Theme};
    ///
    /// App::new("Console", state, view)
    ///     .theme(|appearance, ui, mono| {
    ///         Theme::new(appearance, ui, mono).with_corners(CornerStyle::Cut)
    ///     })
    ///     .run()
    /// ```
    ///
    /// A function rather than a value, and called once a frame, because the
    /// appearance is not knowable in advance: a desktop can turn the lights out
    /// under a running window, and a theme is derived from that rather than
    /// fixed against it. The faces are handed over for the same reason — they
    /// are found on the machine the program is running on. Anything else the
    /// theme depends on is the closure's own business, so long as it does not
    /// read a clock; see [`Memory::begin_frame`](crate::Memory::begin_frame).
    ///
    /// [`App::render`] and [`Harness`](crate::testing::Harness) honour it as a
    /// window does, so a screenshot, a test, and the running program cannot
    /// disagree about what the interface looks like.
    pub fn theme(
        mut self,
        theme: impl Fn(Appearance, FontId, FontId) -> Theme + 'static,
    ) -> Self {
        self.set_theme(Box::new(theme));
        self
    }

    /// The same, on an application that is already built.
    ///
    /// For [`Harness`](crate::testing::Harness), which holds one rather than
    /// building it; the builder above is what an application uses.
    pub(crate) fn set_theme(&mut self, theme: ThemeFor) {
        self.theme = theme;
    }

    /// How the bare window is painted, when the palette's gradient is not it.
    ///
    /// The same seam [`App::theme`] is: the library owns what a frame *is*, and
    /// the application owns what it looks like. A ground replaces the clear
    /// entirely — it is handed the whole canvas first thing each frame and must
    /// cover every pixel — so an instrument can scribe a graticule under its
    /// panels without the library growing an opinion about graticules.
    ///
    /// It is drawing, not layout: nothing behind it is measured, hit, or read
    /// by accessibility, which is what makes it safe for decoration and wrong
    /// for anything a person is meant to notice.
    pub fn ground(mut self, ground: impl Fn(&mut Canvas, &Theme) + 'static) -> Self {
        self.ground = Some(Box::new(ground));
        self
    }

    /// Paints the bare window: the application's ground, or the library's.
    ///
    /// Called by whatever is about to draw a frame — a window, a test, or
    /// [`App::render`] — so the three cannot come to disagree about what an
    /// empty window looks like.
    pub(crate) fn paint_ground(&self, canvas: &mut Canvas, theme: &Theme) {
        match &self.ground {
            Some(ground) => ground(canvas, theme),
            None => {
                canvas.clear_vertical(theme.palette.background, theme.palette.background_deep);
            }
        }
    }

    /// The theme this application draws with, under `appearance`.
    ///
    /// Asked once a frame by whatever is about to draw one — a window, a test,
    /// or [`App::render`] — so there is one answer and not three.
    pub(crate) fn theme_for(
        &self,
        appearance: Appearance,
        ui_font: FontId,
        mono_font: FontId,
    ) -> Theme {
        (self.theme)(appearance, ui_font, mono_font)
    }

    /// Whether the window should be filling the screen, and where to write it
    /// down when the platform changes that on its own.
    ///
    /// Two closures and not one, because both ends can change this. `wanted` is
    /// asked every turn of the loop and is what a control in the interface
    /// toggles; `changed` is called when the person used the platform's own way
    /// in — the green button on macOS, a window manager's key — so that the
    /// state a frame is drawn from cannot come to disagree with the window it
    /// is drawn into.
    ///
    /// ```ignore
    /// App::new("Console", console, view)
    ///     .fullscreen(|console: &Console| console.filling_screen, |console, on| {
    ///         console.filling_screen = on;
    ///     })
    ///     .run()
    /// ```
    ///
    /// An application that never calls this is never asked and never asks:
    /// its window is whatever the person dragged it to, exactly as before.
    pub fn fullscreen(
        mut self,
        wanted: impl Fn(&S) -> bool + 'static,
        changed: impl Fn(&mut S, bool) + 'static,
    ) -> Self {
        self.fullscreen = Some((Box::new(wanted), Box::new(changed)));
        self
    }

    /// Whether the interface wants the window to fill the screen.
    ///
    /// `None` from an application that never bound it, which is the answer the
    /// loop reads as "ask the window nothing".
    pub(crate) fn wants_fullscreen(&self) -> Option<bool> {
        self.fullscreen.as_ref().map(|(wanted, _)| wanted(&self.state))
    }

    /// Writes down that the window is, or is no longer, filling the screen.
    pub(crate) fn report_fullscreen(&mut self, filling: bool) {
        if let Some((_, changed)) = &self.fullscreen {
            changed(&mut self.state, filling);
        }
    }

    /// When the application should close its own window.
    ///
    /// Checked each frame, so a program can end after a fatal error rather than
    /// only the person using it being able to close it.
    pub fn while_running(mut self, running: impl Fn(&S) -> bool + 'static) -> Self {
        self.running = Box::new(running);
        self
    }

    /// The state, for a caller that kept a handle on the application.
    pub fn state(&self) -> &S {
        &self.state
    }

    /// The same, to be changed by whoever holds the application.
    ///
    /// The interface changes its own state through handlers, and that is what
    /// nearly everything should use. This is for the case a handler cannot
    /// reach: something that arrived from outside — a frame off a socket, a job
    /// that finished — put into the state by whoever owns the application
    /// before the next frame is drawn. Pair it with [`Redraw::request`] so the
    /// screen catches up without waiting for the idle timeout.
    pub fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }

    /// What the last frame amounted to, for anything that cannot see it.
    ///
    /// Built from the description that was just drawn, so it cannot disagree
    /// with what is on screen. Empty before the first frame.
    pub fn accessibility(&self) -> &AccessTree {
        &self.access
    }

    /// How that differed from the frame before it.
    ///
    /// What a platform hands to its assistive technology, and nothing else: an
    /// interface spends most of its life unchanged, and this is empty on every
    /// frame that changed nothing. The same reasoning as presenting a frame
    /// only when its pixels differ.
    pub fn accessibility_update(&self) -> &AccessUpdate {
        &self.access_update
    }

    /// Opens a window and runs until it is closed.
    ///
    /// Fonts are found on this machine rather than shipped, so an interface
    /// looks like the desktop it is running on.
    pub fn run(self) -> Result<(), Error> {
        let fonts = shell::load_system_fonts()?;
        self.run_with_fonts(fonts)
    }

    /// The same, with the faces supplied rather than searched for.
    pub fn run_with_fonts(self, fonts: LoadedFonts) -> Result<(), Error> {
        run_windowed(self.options.clone(), fonts, self)
    }

    /// Draws one frame with no window at all, and answers the pixels.
    ///
    /// What makes an interface written with this library testable, and what a
    /// packaging step draws a screenshot with. It is the same code path a window
    /// uses — there is no second renderer that might disagree with the real one.
    pub fn render(
        &mut self,
        width: u32,
        height: u32,
        scale: f32,
        appearance: Appearance,
        fonts: &mut LoadedFonts,
    ) -> Canvas {
        let mut canvas =
            Canvas::new((width as f32 * scale) as u32, (height as f32 * scale) as u32, scale);
        let mut memory = Memory::new();
        self.draw_into(&mut canvas, fonts, appearance, &mut memory);
        canvas
    }

    /// Draws one frame into a canvas that already exists.
    ///
    /// What [`App::render`] does without allocating a surface or forgetting
    /// where everything was scrolled to — which is what the window's own loop
    /// does, and therefore what a measurement of a frame should measure. It is
    /// also the way in for an application that owns its own surface and wants
    /// this library to draw part of it.
    pub fn draw_into(
        &mut self,
        canvas: &mut Canvas,
        fonts: &mut LoadedFonts,
        appearance: Appearance,
        memory: &mut Memory,
    ) {
        let input = Input::new();
        fonts.fonts.set_scale(canvas.scale());

        let theme = self.theme_for(appearance, fonts.ui_font, fonts.mono_font);
        self.paint_ground(canvas, &theme);
        memory.begin_frame(std::time::Duration::from_millis(16));
        self.frame(canvas, &fonts.fonts, &input, memory, &theme);
        memory.end_frame(&input);
    }

    /// Describes, lays out, draws, and then applies whatever was interacted
    /// with.
    pub(crate) fn frame(
        &mut self,
        canvas: &mut Canvas,
        fonts: &Fonts,
        input: &Input,
        memory: &mut Memory,
        theme: &Theme,
    ) {
        // The one place a developer reload does anything, and only once a
        // window has armed it. A test drives [`App::frame_observed`] directly
        // and [`App::render`] never arms anything, so neither can tell whether
        // the feature is compiled in at all.
        #[cfg(feature = "reload")]
        if self.reload.as_ref().is_some_and(|reload| reload.is_armed()) {
            let mut order = Vec::new();
            self.frame_observed(canvas, fonts, input, memory, theme, &mut |el, _| {
                order.push(el.id);
            });
            if let Some(reload) = self.reload.as_mut() {
                reload.after_frame(&self.state, memory, &order);
            }
            return;
        }
        self.frame_observed(canvas, fonts, input, memory, theme, &mut |_, _| {});
    }

    /// The same, handing every laid-out element and its parent to `observe`
    /// before the description is dropped.
    ///
    /// What [`crate::testing::Harness`] is built on. It exists so that testing
    /// an interface goes through the *real* frame rather than a second, simpler
    /// path that could come to disagree with it — the window's loop calls
    /// [`App::frame`], which is this with an observer that does nothing, so
    /// there is exactly one implementation of what a frame is.
    ///
    /// The accessibility tree is built on the same walk, for the same reason:
    /// one traversal of the finished frame, from which everything that has to
    /// know what came out reads its answer.
    pub(crate) fn frame_observed(
        &mut self,
        canvas: &mut Canvas,
        fonts: &Fonts,
        input: &Input,
        memory: &mut Memory,
        theme: &Theme,
        observe: &mut dyn FnMut(&El<S>, Option<Id>),
    ) {
        let mut tree = (self.view)(&self.state);
        let ctx = Ctx { fonts, theme, bounds: canvas.bounds() };
        layout::solve(&mut tree, canvas.bounds(), &ctx, memory);

        let mut frame = Frame { canvas, fonts, theme, input, memory, hit: paint::Hit::default() };
        let actions = paint::render(&tree, &mut frame);

        let mut access = AccessTree::new();
        visit(&tree, None, &mut |el, parent| {
            access.push(el, parent);
            observe(el, parent);
        });
        access.finish(memory.focused());
        self.access_update = access.diff(&self.access);
        self.access = access;

        // Nothing has been called yet. Every handler the frame collected runs
        // here, with the description still alive but no longer being read, which
        // is what lets a handler take the state mutably.
        if !actions.is_empty() {
            for action in actions {
                action(&mut self.state);
            }
            // What was just changed is not what was just drawn, so the frame on
            // screen is one behind. Asking for another one is what makes a click
            // land visibly at once rather than at the next wake-up.
            memory.request_frame();
        }
    }

    /// A handle another thread can ask for a frame with.
    ///
    /// Taken before [`App::run`] and cloned into whatever produces news from
    /// outside the interface. See [`Redraw`] for what it does and does not
    /// promise.
    pub fn redraw(&self) -> Redraw {
        self.redraw.clone()
    }

    /// How long the loop may go without drawing at all.
    ///
    /// The application's own [`App::idle_timeout`], and deliberately not the
    /// shortened wait below: the timeout is how stale the screen may get, which
    /// is the application's decision, while the wait is only how long the loop
    /// may sleep at a stretch.
    pub(crate) fn idle(&self) -> Duration {
        self.idle
    }

    /// How long the loop may wait for input in one go.
    ///
    /// Whichever is shorter: the idle timeout, or the latency another thread
    /// asked [`Redraw::within`] for. A window nobody has asked anything of
    /// waits exactly the timeout, as it always did.
    pub(crate) fn wait(&self) -> Duration {
        match self.redraw.bound() {
            Some(bound) => self.idle.min(bound),
            None => self.idle,
        }
    }

    /// Whether another thread has asked for a frame, clearing the request.
    ///
    /// Asked once per turn of the loop, by the loop, which is what makes
    /// "ten requests are one frame" true.
    pub(crate) fn take_redraw_request(&self) -> bool {
        self.redraw.take()
    }

    /// Whether the loop should keep going.
    pub(crate) fn is_running(&self) -> bool {
        // A reload stops the loop the ordinary way rather than ending the
        // process where it stands, so the window is taken down properly and the
        // new build is started from outside the loop that drew the last frame.
        #[cfg(feature = "reload")]
        if self.reload.as_ref().is_some_and(|reload| reload.is_restarting()) {
            return false;
        }
        (self.running)(&self.state)
    }
}

/// Hands every element of a laid-out tree, and what holds it, to `observe`.
///
/// Parents before their children, so anything rebuilding the tree from this can
/// do it in one pass.
fn visit<S>(
    el: &El<S>,
    parent: Option<Id>,
    observe: &mut dyn FnMut(&El<S>, Option<Id>),
) {
    observe(el, parent);
    for child in el.children() {
        visit(child, Some(el.id), observe);
    }
}

/// Opens a window showing `state`, described by `view`, and runs until it is
/// closed.
///
/// The whole of the setup for an ordinary program. [`App`] is the same thing
/// with the window's size, the idle timeout, and the closing condition open to
/// being changed.
pub fn run<S: 'static>(
    title: impl Into<String>,
    state: S,
    view: impl Fn(&S) -> El<S> + 'static,
) -> Result<(), Error> {
    App::new(title, state, view).run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::widgets::text;

    /// An application with nothing in it, for exercising the loop's decisions.
    fn quiet() -> App<()> {
        App::new("test", (), |_: &()| text("still"))
    }

    #[test]
    fn a_window_nobody_has_asked_anything_of_waits_exactly_its_timeout() {
        // The whole promise of the redraw handle costing nothing: an
        // application that never takes one behaves as it did before there was
        // one to take.
        let app = quiet().idle_timeout(Duration::from_millis(500));
        assert_eq!(app.wait(), Duration::from_millis(500));
        assert!(!app.take_redraw_request());
    }

    #[test]
    fn a_shorter_latency_shortens_the_wait_without_shortening_the_timeout() {
        // Two different questions: how long the loop may sleep at a stretch, and
        // how stale the screen may get. Confusing them would make a live stream
        // redraw the whole interface at the stream's pace whether or not a frame
        // had arrived.
        let app = quiet().idle_timeout(Duration::from_millis(500));
        let redraw = app.redraw();

        redraw.within(Duration::from_millis(16));
        assert_eq!(app.wait(), Duration::from_millis(16));
        assert_eq!(app.idle(), Duration::from_millis(500), "the timeout is the application's");

        redraw.within(Duration::ZERO);
        assert_eq!(app.wait(), Duration::from_millis(500), "the window went back to sleep");
    }

    #[test]
    fn a_latency_longer_than_the_timeout_does_not_slow_the_window_down() {
        let app = quiet().idle_timeout(Duration::from_millis(250));
        app.redraw().within(Duration::from_secs(10));
        assert_eq!(app.wait(), Duration::from_millis(250));
    }

    #[test]
    fn many_requests_between_two_frames_are_one_frame() {
        // What makes it safe to call per arriving item: the loop asks once a
        // turn, and what is being asked for is that the screen catch up.
        let app = quiet();
        let redraw = app.redraw();

        redraw.request();
        redraw.request();
        redraw.request();
        assert!(app.take_redraw_request());
        assert!(!app.take_redraw_request(), "the request outlived the frame that answered it");
    }

    #[test]
    fn a_request_can_be_made_from_another_thread() {
        // The reason the type exists. `App` is not `Send` and never will be —
        // the handle is, and carries nothing of the interface with it.
        let app = quiet();
        let redraw = app.redraw();
        let worker = std::thread::spawn(move || {
            redraw.within(Duration::from_millis(16));
            redraw.request();
        });
        worker.join().expect("the worker thread panicked");

        assert!(app.take_redraw_request());
        assert_eq!(app.wait(), Duration::from_millis(16));
    }

    #[test]
    fn an_absurd_latency_is_carried_rather_than_wrapping_round() {
        // A duration in years does not become a millisecond. It is clamped at
        // the widest bound the counter holds, which is longer than any timeout
        // an application would set and so has no effect on the wait.
        let app = quiet().idle_timeout(Duration::from_millis(250));
        app.redraw().within(Duration::from_secs(60 * 60 * 24 * 365));
        assert_eq!(app.wait(), Duration::from_millis(250));
    }
}
