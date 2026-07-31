//! The window: the only part of the library that talks to an operating system.
//!
//! Deliberately the smallest part. A backend opens a window, says how big it is
//! and whether the desktop is light or dark, hands over the events it received,
//! copies a buffer of pixels onto the screen, carries text to and from the
//! system clipboard, tells the platform's input method where the text being
//! composed is on screen, and hands the platform's assistive technology what
//! the interface now means. Everything else is decided above it, identically
//! everywhere, which is why porting to a new platform is a few hundred lines
//! against that surface and why a defect in a widget can never be a platform
//! defect.
//!
//! # What belongs on that list is a choice, not a fixed number
//!
//! The list grows when something *can only* be answered by the operating
//! system. A clipboard is the clear case: it is not a buffer this library could
//! keep for itself, because the entire point of it is that other programs can
//! read it. Composition is the same — which characters a keystroke produces is a
//! question about the person's chosen input method, not about this program.
//!
//! Everything else stays out, and the cost of each addition is what keeps that
//! honest: one method here is three implementations and a documented gap on any
//! platform that cannot honour it. A capability that a widget could compute for
//! itself, or that one platform has and the others do not, is not one to widen
//! the seam for.
//!
//! # The loop
//!
//! Wait for input, fold it into the frame's [`Input`], draw the whole interface,
//! and present it if it came out different from the last one.
//!
//! There is no partial redraw and no dirty tracking. A system that works out
//! *which region* to repaint is a system that can work it out wrongly, and the
//! symptom is a stale pixel still showing a service as running after it has
//! died. Comparing the finished frame with the previous one has the same effect
//! on cost with none of that risk: it cannot conclude that something changed
//! when it did not, or the reverse. This matters because sending a frame to the
//! compositor costs several times what drawing it does, and most interfaces
//! spend nearly all of their life displaying the same picture.
//!
//! # Two speeds, chosen by whether anything is moving
//!
//! While anything is mid-animation — a hover fading in, a list settling after a
//! click — the loop comes back within `FRAME`. Once everything has settled it
//! goes back to waiting [`App::idle_timeout`], and a window nobody is touching
//! costs what it always did. Nothing here knows what is animating or why: the
//! interface answers [`Memory::is_animating`] and the loop believes it.
//!
//! # When the platform takes the loop away
//!
//! A window system may run a loop of its own that does not return until a
//! gesture ends. macOS resizes a window that way, and a program that only draws
//! from its own loop draws nothing for the whole drag — the compositor stretches
//! the last frame to each new size, so the window smears. So drawing a frame is
//! not something only this loop can do: `Backend::pump` is handed a way to
//! draw one, for a backend to call when the platform has taken over.

pub mod fonts;
mod platform;

use crate::accessibility::AccessUpdate;
use crate::app::App;
use crate::canvas::Canvas;
use crate::geom::Rect;
use crate::input::{Event, Input};
use crate::memory::Memory;
use crate::font::FontError;
use crate::text::{FontId, Fonts};
use crate::theme::Appearance;
use std::time::{Duration, Instant};

pub use fonts::{LoadedFonts, load_system_fonts};

/// How long the loop waits between frames while something is animating.
///
/// A hundred and twenty a second rather than sixty: the wait is an upper bound
/// on latency and not a frame rate, so asking to come back more often costs
/// nothing when nothing is moving, and halves the worst case when something is.
const FRAME: Duration = Duration::from_millis(8);

/// How a window should be opened.
#[derive(Debug, Clone)]
pub struct WindowOptions {
    /// The title bar's text.
    pub title: String,
    /// Initial width, in logical units.
    pub width: f32,
    /// Initial height, in logical units.
    pub height: f32,
    /// The smallest width the window may be dragged to.
    pub min_width: f32,
    /// The smallest height.
    pub min_height: f32,
}

impl Default for WindowOptions {
    fn default() -> Self {
        Self { title: "rui".into(), width: 960.0, height: 640.0, min_width: 420.0, min_height: 320.0 }
    }
}

/// Why a window could not be opened or drawn.
#[derive(Debug)]
pub enum Error {
    /// No usable font was found on this machine.
    NoFont {
        /// The files that were looked for.
        searched: Vec<String>,
    },
    /// A font file was found but could not be parsed.
    Font(FontError),
    /// A file could not be read.
    Io(std::io::Error),
    /// The windowing system refused, or is not there.
    Platform(String),
    /// This platform has no backend compiled in.
    Unsupported,
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoFont { searched } => {
                write!(formatter, "no usable font found; looked for {}", searched.join(", "))
            }
            Self::Font(error) => write!(formatter, "the font could not be read: {error}"),
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Platform(message) => write!(formatter, "{message}"),
            Self::Unsupported => write!(
                formatter,
                "this platform has no window backend; macOS, Windows, and X11 are supported"
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<FontError> for Error {
    fn from(error: FontError) -> Self {
        Self::Font(error)
    }
}

/// What a backend must be able to do.
///
/// Every method is about the platform rather than about the interface. Anything
/// a backend could decide for itself — what a click means, where an element is —
/// is decided above it.
trait Backend: Sized {
    /// Opens the window.
    fn open(options: &WindowOptions) -> Result<Self, Error>;

    /// Collects pending events, waiting up to `timeout` for the first.
    ///
    /// Not only the ones the window system queued. An assistive technology
    /// activates a control by messaging an object the backend handed it, at a
    /// moment of its own choosing, and the answer is to report that here as an
    /// [`Event::Activated`] rather than to act on it — which is why this seam
    /// did not have to grow a method for it, and why a screen reader reaches a
    /// handler by the route a click already takes. See
    /// [`accessibility`](crate::accessibility) for the invariant that rests on
    /// it.
    ///
    /// `redraw` draws and presents one frame immediately, for a backend to call
    /// when the platform has taken the loop away and will not give it back until
    /// a gesture ends. It takes `&Self` and not `&mut Self` because the backend
    /// is inside `pump` when it calls it.
    fn pump(
        &mut self,
        timeout: Duration,
        events: &mut Vec<Event>,
        redraw: &mut dyn FnMut(&Self),
    ) -> Result<(), Error>;

    /// The drawable size in device pixels, and the display's scale factor.
    fn surface(&self) -> (u32, u32, f32);

    /// Whether the desktop is currently light or dark.
    fn appearance(&self) -> Appearance;

    /// Copies a frame onto the screen.
    fn present(&self, canvas: &Canvas) -> Result<(), Error>;

    /// Whether the window is still on screen.
    fn is_open(&self) -> bool;

    /// The plain text on the system clipboard, if it holds any.
    ///
    /// `Ok(None)` is a clipboard holding something that is not text, or nothing
    /// at all, or — on X11, where reading it means asking whichever program owns
    /// it — an owner that did not answer. All three are the same to a field
    /// pasting: there is nothing to paste. An `Err` is the platform refusing.
    fn clipboard_text(&self) -> Result<Option<String>, Error>;

    /// Puts `text` on the system clipboard, replacing whatever was there.
    fn set_clipboard_text(&self, text: &str) -> Result<(), Error>;

    /// Says where the text being composed is, in the same logical units from
    /// the top left of the window that an element is drawn in.
    ///
    /// An input method draws its own window — the list of candidate characters
    /// for a syllable, the accent a dead key is holding — and needs to put it
    /// beside the text it belongs to. `None` means nothing has the keyboard, so
    /// there is nowhere for it to be.
    ///
    /// Told only when it moves, so a platform is free to make this an expensive
    /// call.
    fn set_composition_area(&self, area: Option<Rect>) -> Result<(), Error>;

    /// Hands the platform the accessibility nodes that changed since the last
    /// frame.
    ///
    /// A diff and not the whole tree, for the reason [`Backend::present`] sends
    /// a frame only when it differs: an interface spends most of its life
    /// unchanged, and pushing an identical tree every frame costs the assistive
    /// technology, not us.
    fn update_accessibility(&self, update: &AccessUpdate) -> Result<(), Error>;
}

/// Everything one frame is drawn from, apart from the window and the program.
///
/// Held together because a frame is drawn from two places — the loop below, and
/// the backend itself while the platform has taken the loop away.
struct Surface {
    /// The frame being drawn.
    drawn: Canvas,
    /// The frame on screen, so an identical one is not sent again.
    ///
    /// A second canvas rather than a saved copy of the first: presenting swaps
    /// the two, so recognising an unchanged frame costs one comparison and never
    /// a copy of the surface.
    presented: Canvas,
    input: Input,
    memory: Memory,
    /// When the previous frame was drawn, so animation advances by elapsed time
    /// rather than by a count of frames.
    drawn_at: Instant,
    ui_font: FontId,
    mono_font: FontId,
    /// A failure from a frame drawn inside the platform's own loop.
    ///
    /// There is nothing to return it to from in there, and dropping it would
    /// turn a window that can no longer present into one that silently freezes.
    failed: Option<Error>,
    /// The caret position the input method was last told about.
    ///
    /// Kept so it is told only when the answer changes, for the same reason a
    /// frame is presented only when it differs from the one on screen.
    composition_area: Option<Rect>,
}

impl Surface {
    /// Folds `events` in, draws the whole interface, and presents it if it came
    /// out different from what is already on screen.
    fn draw<B: Backend, S>(
        &mut self,
        window: &B,
        fonts: &mut Fonts,
        app: &mut App<S>,
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        let now = Instant::now();
        self.memory.begin_frame(now.saturating_duration_since(self.drawn_at));
        self.drawn_at = now;

        self.input.begin_frame();
        for event in events.drain(..) {
            self.input.apply(event);
        }

        let (width, height, scale) = window.surface();
        if width != self.drawn.width() || height != self.drawn.height() || scale != self.drawn.scale()
        {
            self.drawn.resize(width, height, scale);
        }
        fonts.set_scale(scale);

        // The application's own, if it supplied one — asked here rather than
        // built here, so a window and a test cannot come to disagree about what
        // the interface looks like. See [`App::theme`].
        let theme = app.theme_for(window.appearance(), self.ui_font, self.mono_font);
        app.paint_ground(&mut self.drawn, &theme);
        app.frame(&mut self.drawn, fonts, &self.input, &mut self.memory, &theme);
        self.memory.end_frame(&self.input);
        self.serve_requests(window)?;

        // The same idea as the comparison below, applied to what the interface
        // *means* rather than to what it looks like: work out the difference
        // from the finished result, and send nothing when there is none. Both
        // are here, next to each other, because they are one principle —
        // compare the outcome, do not track what you believe is dirty.
        let update = app.accessibility_update();
        if !update.is_empty() {
            window.update_accessibility(update)?;
        }

        if self.drawn.pixels() != self.presented.pixels() {
            window.present(&self.drawn)?;
            std::mem::swap(&mut self.drawn, &mut self.presented);
        }
        Ok(())
    }

    /// Does what the finished frame asked of the operating system.
    ///
    /// The other half of [`crate::memory::ClipboardRequest`]: a field cannot
    /// reach a window, because the description it is drawn from borrows the
    /// application's state and knows nothing about one. It leaves its intention
    /// in [`Memory`] and this performs it, one frame's worth at a time, in the
    /// one place that holds both.
    ///
    /// After the frame rather than before it, so that a copy carries what the
    /// field decided *this* frame rather than what it held on the last one.
    fn serve_requests<B: Backend>(&mut self, window: &B) -> Result<(), Error> {
        let request = self.memory.take_clipboard_request();
        if let Some(text) = request.copy {
            window.set_clipboard_text(&text)?;
        }
        if request.paste {
            if let Some(text) = window.clipboard_text()? {
                self.memory.deliver_paste(text);
            }
        }

        let area = self.memory.caret_area();
        if area != self.composition_area {
            window.set_composition_area(area)?;
            self.composition_area = area;
        }
        Ok(())
    }
}

/// Opens a window and runs `app` in it until it is closed.
pub(crate) fn run<S>(
    options: WindowOptions,
    loaded: LoadedFonts,
    mut app: App<S>,
) -> Result<(), Error> {
    let LoadedFonts { mut fonts, ui_font, mono_font } = loaded;
    let mut window = platform::Window::open(&options)?;

    let (width, height, scale) = window.surface();
    let mut surface = Surface {
        drawn: Canvas::new(width, height, scale),
        // Deliberately empty rather than the surface's size: nothing has been
        // presented yet, and an empty canvas differs from every frame, so the
        // first one is sent instead of being mistaken for a repeat.
        presented: Canvas::new(0, 0, scale),
        input: Input::new(),
        memory: Memory::new(),
        drawn_at: Instant::now(),
        ui_font,
        mono_font,
        failed: None,
        composition_area: None,
    };
    let mut events = Vec::new();

    while window.is_open() && app.is_running() {
        events.clear();
        let wait = if surface.memory.is_animating() { FRAME } else { app.idle() };

        {
            // What the backend calls when the platform has taken the loop away.
            // It draws with no events of its own: a gesture the platform is
            // tracking is not one this program is being told about, and folding
            // the same click in twice would fire whatever it landed on twice.
            let mut redraw = |window: &platform::Window| {
                if let Err(error) = surface.draw(window, &mut fonts, &mut app, &mut Vec::new()) {
                    surface.failed = Some(error);
                }
            };
            window.pump(wait, &mut events, &mut redraw)?;
        }
        if let Some(error) = surface.failed.take() {
            return Err(error);
        }

        surface.draw(&window, &mut fonts, &mut app, &mut events)?;
        if surface.input.close_requested() {
            break;
        }
    }
    Ok(())
}
