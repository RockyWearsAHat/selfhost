//! The window: the only part of the library that talks to an operating system.
//!
//! Deliberately the smallest part. A backend does five things — open a window,
//! say how big it is and whether the desktop is light or dark, hand over the
//! events it received, and copy a buffer of pixels onto the screen. Everything
//! else is decided above it, identically everywhere, which is why porting to a
//! new platform is a few hundred lines against that surface and why a defect in
//! a widget can never be a platform defect.
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

use crate::app::App;
use crate::canvas::Canvas;
use crate::input::{Event, Input};
use crate::memory::Memory;
use crate::font::FontError;
use crate::text::{FontId, Fonts};
use crate::theme::{Appearance, Theme};
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

        let theme = Theme::new(window.appearance(), self.ui_font, self.mono_font);
        self.drawn.clear_vertical(theme.palette.background, theme.palette.background_deep);
        app.frame(&mut self.drawn, fonts, &self.input, &mut self.memory, &theme);
        self.memory.end_frame(&self.input);

        if self.drawn.pixels() != self.presented.pixels() {
            window.present(&self.drawn)?;
            std::mem::swap(&mut self.drawn, &mut self.presented);
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
