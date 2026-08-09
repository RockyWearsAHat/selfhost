//! Driving an interface with no window, no pointer, and no display.
//!
//! An interface is only as good as the confidence that it does what it looks
//! like it does, and that confidence has to be cheap or nobody buys any. So the
//! test story here is not a second, simplified rendering path that might
//! disagree with the real one — it is *the* path: [`Harness::frame`] describes,
//! lays out, draws, and applies exactly what a window does, into a buffer
//! instead of onto a screen.
//!
//! ```
//! use rui::testing::Harness;
//! use rui::{El, button, col, text};
//!
//! struct Counter {
//!     count: i32,
//! }
//!
//! fn view(counter: &Counter) -> El<Counter> {
//!     col((
//!         text(format!("{}", counter.count)),
//!         button("Increment").on_click(|counter: &mut Counter| counter.count += 1),
//!     ))
//! }
//!
//! let mut harness = Harness::new(Counter { count: 0 }, view);
//!
//! harness.click_text("Increment");
//! assert_eq!(harness.state().count, 1);
//! assert!(harness.frame().shows("1"));
//! ```
//!
//! That runs as written, with no window and no display — it is one of this
//! crate's own tests.
//!
//! # What makes this possible
//!
//! Three decisions elsewhere in the library, none of them made for testing:
//!
//! - **A view is a function of state**, so there is nothing to set up but the
//!   state itself.
//! - **Nothing reads a clock.** [`Memory`] is *told* how long a frame took, so
//!   an animation is stepped rather than waited for.
//! - **Everything is drawn here**, so a frame can be produced with no display
//!   attached and the pixels are the same pixels a screen would show.
//!
//! The one thing the library does not carry is a font, because a program should
//! use the desktop's. A test cannot: the numbers would depend on which machine
//! ran it. So [`font::test_font`] builds one, with a round half-em advance —
//! see that module for what it measures.
//!
//! # What a test can ask
//!
//! Where things came out ([`Harness::rect_of`], [`Harness::probes`]), what the
//! interface says ([`Harness::shows`], [`Harness::text`]), what it did
//! ([`Harness::state`]), and what it actually drew ([`Harness::pixel`],
//! [`Harness::save_png`]).

pub mod font;

use crate::accessibility::{AccessTree, AccessUpdate, audit};
use crate::app::App;
use crate::canvas::Canvas;
use crate::color::Color;
use crate::element::El;
use crate::geom::{Point, Rect};
use crate::input::{Event, Input, Key, Modifiers, PointerButton};
use crate::accessibility::Role;
use crate::memory::{Id, Memory};
use crate::shell::LoadedFonts;
use crate::text::{FontId, Fonts};
use crate::theme::{Appearance, Theme};
use std::collections::HashSet;
use std::time::Duration;

/// How big a harness draws before it is told otherwise, in logical units.
const DEFAULT_SIZE: (f32, f32) = (800.0, 600.0);

/// How long each frame is taken to have lasted.
///
/// A sixtieth of a second: the pace an animation would settle at on a screen,
/// so a test that steps ten frames has stepped a sixth of a second of easing
/// and can say so.
pub const FRAME: Duration = Duration::from_nanos(16_666_667);

/// What one element came out as, once the frame that drew it was finished.
///
/// A flat record rather than a borrowed tree, because the description is built
/// and dropped inside a frame — by the time a test asks, the elements are gone
/// and only what they *did* is worth keeping.
#[derive(Debug, Clone, PartialEq)]
pub struct Probe {
    /// Its identity, which is what its scroll, focus, and hover are stored under.
    pub id: Id,
    /// What holds it, or `None` for the root of the frame.
    pub parent: Option<Id>,
    /// What it was named with [`El::key`](crate::El::key), if anything.
    pub key: Option<String>,
    /// What it is, for anything that cannot see it.
    ///
    /// The computed name and the state that goes with it live on
    /// [`AccessNode`](crate::accessibility::AccessNode), reached through
    /// [`Harness::accessibility`], because a name is a property of a subtree
    /// rather than of one element.
    pub role: Role,
    /// The text it holds, if it is a run of text or a field.
    pub text: Option<String>,
    /// Where the layout put it, in logical units.
    pub rect: Rect,
    /// Whether it was drawn dimmed and ignoring events.
    pub disabled: bool,
    /// Whether clicking it does anything.
    pub clickable: bool,
    /// Whether it takes the keyboard, and a place in the tab order.
    pub focusable: bool,
    /// Whether it was lifted out of the flow by [`El::layer`](crate::El::layer).
    pub layered: bool,
}

/// An application being driven with no window.
///
/// Built with [`Harness::new`], adjusted with the setters, and then driven: the
/// pointer and keyboard methods each deliver their events and draw one frame,
/// which is the frame the handlers they trigger run at the end of. So the state
/// is current the moment a method returns, and what is *drawn* catches up on
/// the next [`Harness::frame`] — the same one-frame lag a window has, made
/// visible rather than hidden, because a test that could not see it could not
/// assert on it either.
pub struct Harness<S> {
    app: App<S>,
    fonts: LoadedFonts,
    canvas: Canvas,
    memory: Memory,
    input: Input,
    appearance: Appearance,
    elapsed: Duration,
    pending: Vec<Event>,
    probes: Vec<Probe>,
}

impl<S: 'static> Harness<S> {
    /// An application showing `state`, described by `view`, ready to be driven.
    ///
    /// Eight hundred by six hundred logical units at a scale of one, in the
    /// dark appearance, drawn with the face from [`font`].
    pub fn new(state: S, view: impl Fn(&S) -> El<S> + 'static) -> Self {
        Self::with_app(App::new("test", state, view))
    }

    /// The same, around an application that has already been configured.
    ///
    /// For a test of something that is started with [`App`] rather than
    /// [`run`](crate::run) — a window size, a closing condition — which is worth
    /// exercising through the type the program actually uses.
    pub fn with_app(app: App<S>) -> Self {
        let (width, height) = DEFAULT_SIZE;
        Self {
            app,
            fonts: test_fonts(),
            canvas: Canvas::new(width as u32, height as u32, 1.0),
            memory: Memory::new(),
            input: Input::new(),
            appearance: Appearance::Dark,
            elapsed: FRAME,
            pending: Vec::new(),
            probes: Vec::new(),
        }
    }

    // ----- how it is set up ---------------------------------------------------

    /// Draws at this size, in logical units.
    pub fn size(mut self, width: f32, height: f32) -> Self {
        let scale = self.canvas.scale();
        self.canvas.resize((width * scale) as u32, (height * scale) as u32, scale);
        self
    }

    /// Draws at this device pixel density.
    ///
    /// Worth setting in at least one test of anything that draws: a layout is
    /// written in logical units and rasterised in device pixels, and the two
    /// only stay in step because exactly one place multiplies.
    pub fn scale(mut self, scale: f32) -> Self {
        let bounds = self.canvas.bounds();
        self.canvas.resize((bounds.w * scale) as u32, (bounds.h * scale) as u32, scale);
        self
    }

    /// Draws as though the desktop were light, or dark.
    pub fn appearance(mut self, appearance: Appearance) -> Self {
        self.appearance = appearance;
        self
    }

    /// Draws with this theme rather than the library's own.
    ///
    /// The same call as [`App::theme`], on an application the harness built.
    /// One that was built by hand and handed to [`Harness::with_app`] carries
    /// its own theme in already, which is the point: a test drives the theme the
    /// program actually runs with, so a window and a test cannot disagree about
    /// what the interface looks like.
    pub fn theme(
        mut self,
        theme: impl Fn(Appearance, FontId, FontId) -> Theme + 'static,
    ) -> Self {
        self.app.set_theme(Box::new(theme));
        self
    }

    /// Takes every frame to have lasted this long.
    ///
    /// What makes an animation assertable: nothing here reads a clock, so a
    /// test steps time rather than waiting for it.
    pub fn frame_time(mut self, elapsed: Duration) -> Self {
        self.elapsed = elapsed;
        self
    }

    // ----- driving it ---------------------------------------------------------

    /// Draws one whole frame, and runs whatever it was told to do.
    ///
    /// The same four steps a window takes, in the same order, through the same
    /// code: describe, lay out, draw, then apply.
    pub fn frame(&mut self) -> &mut Self {
        self.input.begin_frame();
        for event in self.pending.drain(..) {
            self.input.apply(event);
        }

        self.fonts.fonts.set_scale(self.canvas.scale());
        let theme = self.theme_in_force();
        self.app.paint_ground(&mut self.canvas, &theme);

        self.memory.begin_frame(self.elapsed);
        let mut probes = Vec::new();
        self.app.frame_observed(
            &mut self.canvas,
            &self.fonts.fonts,
            &self.input,
            &mut self.memory,
            &theme,
            &mut |el, parent| probes.push(probe(el, parent)),
        );
        self.memory.end_frame(&self.input);
        self.probes = probes;
        self
    }

    /// Draws `count` further frames, for an animation to settle over.
    pub fn frames(&mut self, count: usize) -> &mut Self {
        for _ in 0..count {
            self.frame();
        }
        self
    }

    /// Queues one event for the next frame.
    ///
    /// The way in for anything the helpers below do not cover; they are all
    /// written in terms of this.
    pub fn event(&mut self, event: Event) -> &mut Self {
        self.pending.push(event);
        self
    }

    /// Moves the pointer, and draws the frame that notices.
    pub fn move_pointer(&mut self, to: Point) -> &mut Self {
        self.event(Event::PointerMoved(to)).frame()
    }

    /// Takes the pointer out of the window.
    pub fn leave(&mut self) -> &mut Self {
        self.event(Event::PointerLeft).frame()
    }

    /// Presses and releases at a point, and draws the frame that answers.
    pub fn click(&mut self, at: Point) -> &mut Self {
        self.event(Event::PointerDown { position: at, button: PointerButton::Primary })
            .event(Event::PointerUp { position: at, button: PointerButton::Primary })
            .frame()
    }

    /// The same with the secondary button.
    pub fn secondary_click(&mut self, at: Point) -> &mut Self {
        self.event(Event::PointerDown { position: at, button: PointerButton::Secondary })
            .event(Event::PointerUp { position: at, button: PointerButton::Secondary })
            .frame()
    }

    /// Presses the pointer down and holds it, without releasing.
    pub fn press(&mut self, at: Point) -> &mut Self {
        self.event(Event::PointerDown { position: at, button: PointerButton::Primary }).frame()
    }

    /// Moves the pointer while it is held down: one frame of a drag.
    pub fn drag_to(&mut self, to: Point) -> &mut Self {
        self.event(Event::PointerMoved(to)).frame()
    }

    /// Lets go where the pointer now is.
    pub fn release(&mut self) -> &mut Self {
        let at = self.input.pointer();
        self.event(Event::PointerUp { position: at, button: PointerButton::Primary }).frame()
    }

    /// A whole drag: press at `from`, move to `to`, and let go.
    ///
    /// Three frames, because that is what it is — a press, a move, and a
    /// release cannot arrive in one, and a control that only works when they do
    /// is a control that does not work.
    pub fn drag(&mut self, from: Point, to: Point) -> &mut Self {
        self.press(from).drag_to(to).release()
    }

    /// Turns the wheel by `down` logical units, and draws the frame.
    pub fn scroll(&mut self, down: f32) -> &mut Self {
        self.event(Event::Scrolled { x: 0.0, y: down }).frame()
    }

    /// Presses a key, with nothing held with it.
    pub fn key(&mut self, key: Key) -> &mut Self {
        self.key_with(key, Modifiers::NONE)
    }

    /// Presses a key with modifiers held.
    pub fn key_with(&mut self, key: Key, modifiers: Modifiers) -> &mut Self {
        self.event(Event::KeyDown { key, modifiers }).frame()
    }

    /// Moves the keyboard on to the next thing that can take it.
    pub fn tab(&mut self) -> &mut Self {
        self.key(Key::Tab)
    }

    /// Types text into whatever holds the keyboard.
    ///
    /// Delivered as text already resolved by an input method, which is how a
    /// platform reports typing — a keystroke's *meaning* depends on the layout,
    /// the modifiers, and any dead key before it, so no test should be spelling
    /// that out.
    pub fn type_text(&mut self, text: &str) -> &mut Self {
        self.event(Event::Text(text.to_owned())).frame()
    }

    // ----- aiming at things by name -------------------------------------------

    /// Clicks the middle of whatever shows this text.
    ///
    /// How a test should nearly always aim: at the word a person would click,
    /// not at a coordinate that changes the moment anything above it does.
    ///
    /// # Panics
    ///
    /// If nothing on screen shows that text, naming what is there instead —
    /// a test that silently clicked nothing would pass for the wrong reason.
    pub fn click_text(&mut self, text: &str) -> &mut Self {
        let at = self.require(text).center();
        self.click(at)
    }

    /// Puts the pointer over the middle of whatever shows this text.
    ///
    /// # Panics
    ///
    /// If nothing on screen shows it; see [`Harness::click_text`].
    pub fn hover_text(&mut self, text: &str) -> &mut Self {
        let at = self.require(text).center();
        self.move_pointer(at)
    }

    /// Activates an element the way an assistive technology does, by identity.
    ///
    /// The other route into a handler, with no pointer and no key involved: a
    /// screen reader holds the [`Id`] of a node and asks for it. It reaches the
    /// same `on_click` a click reaches, which is the whole point of it and what
    /// `tests/accessibility.rs` asserts.
    ///
    /// An identity that belongs to nothing on screen, or to something that
    /// answers no press, draws a frame and changes nothing — the same as a
    /// click on empty space, and for the same reason.
    pub fn activate(&mut self, id: Id) -> &mut Self {
        self.event(Event::Activated(id)).frame()
    }

    /// The same, aimed at whatever an assistive technology would *call* this.
    ///
    /// How a test of the accessible route should nearly always aim: at the name
    /// a screen reader would read out, which is what a person using one has to
    /// go on. That name is computed from the subtree, so this finds
    /// `button("Restart")` as "Restart" with nothing written to make it so.
    ///
    /// # Panics
    ///
    /// If no node is named that, listing the names that are there — a test that
    /// silently activated nothing would pass for the wrong reason.
    pub fn activate_named(&mut self, name: &str) -> &mut Self {
        let found =
            self.accessibility().nodes().iter().find(|node| node.name == name).map(|node| node.id);
        match found {
            Some(id) => self.activate(id),
            None => panic!(
                "nothing on screen is named {name:?}; what is named is {:?}",
                self.accessible_names()
            ),
        }
    }

    /// Every name an assistive technology would have to choose between.
    ///
    /// Only the nodes that carry one, because a group that holds other things
    /// has no name of its own and listing empty strings would bury the answer.
    pub fn accessible_names(&mut self) -> Vec<String> {
        self.accessibility()
            .nodes()
            .iter()
            .filter(|node| !node.name.is_empty())
            .map(|node| node.name.clone())
            .collect()
    }

    /// Where whatever shows this text was drawn.
    ///
    /// Answers the first match in drawing order, which is the topmost thing a
    /// person would take it to mean.
    pub fn rect_of(&mut self, text: &str) -> Option<Rect> {
        self.find(text).map(|probe| probe.rect)
    }

    /// The whole record of whatever shows this text.
    pub fn find(&mut self, text: &str) -> Option<Probe> {
        self.ensure_drawn();
        self.probes.iter().find(|probe| probe.text.as_deref() == Some(text)).cloned()
    }

    /// The record of whatever was named with this key.
    pub fn find_key(&mut self, key: &str) -> Option<Probe> {
        self.ensure_drawn();
        self.probes.iter().find(|probe| probe.key.as_deref() == Some(key)).cloned()
    }

    /// Whether anything on screen shows this text.
    pub fn shows(&mut self, text: &str) -> bool {
        self.find(text).is_some()
    }

    /// Every run of text the last frame drew, in the order it was drawn.
    ///
    /// What an interface *says*, which is most of what is worth asserting about
    /// one: that a failure is reported, that a count is right, that a name
    /// which should not be there is not.
    pub fn text(&mut self) -> Vec<String> {
        self.ensure_drawn();
        self.probes.iter().filter_map(|probe| probe.text.clone()).collect()
    }

    /// Every element the last frame drew, in the order it drew them.
    pub fn probes(&mut self) -> &[Probe] {
        self.ensure_drawn();
        &self.probes
    }

    // ----- what it means ------------------------------------------------------

    /// What the last frame amounted to, for anything that cannot see it.
    ///
    /// Built on the same walk of the finished frame that produced the probes,
    /// so it cannot describe an interface other than the one that was drawn.
    pub fn accessibility(&mut self) -> &AccessTree {
        self.ensure_drawn();
        self.app.accessibility()
    }

    /// How that differed from the frame before it — what a platform would push.
    pub fn accessibility_update(&mut self) -> &AccessUpdate {
        self.ensure_drawn();
        self.app.accessibility_update()
    }

    /// Fails unless the interface on screen keeps the accessibility
    /// convention.
    ///
    /// One call, added to any test that already drives an interface, and the
    /// convention is enforced rather than promised: every clickable or
    /// focusable node has a role of its own, every interactive node has a name,
    /// a tab sits inside a tab list, and no two siblings share an identity. See
    /// [`audit`] for what each failure means.
    ///
    /// # Panics
    ///
    /// Naming every violation, because a test that reported only the first
    /// would be run once per defect.
    pub fn assert_accessible(&mut self) {
        let violations = audit(self.accessibility());
        assert!(
            violations.is_empty(),
            "the interface breaks the accessibility convention in {} place(s):\n{}",
            violations.len(),
            violations
                .iter()
                .map(|violation| format!("  - {violation}"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// Fails unless Tab walks forward through the interface.
    ///
    /// Every focusable element is reached exactly once before any is reached
    /// twice, and those in the ordinary flow are reached in the order they are
    /// written — a person tabbing through an interface should travel the way
    /// they read it. Anything lifted out of the flow by
    /// [`El::layer`](crate::El::layer) comes after all of it, because that is
    /// the order it is drawn in and the two must not disagree.
    ///
    /// It drives frames and leaves the keyboard wherever the walk ended, so
    /// call it at the end of a test rather than in the middle of one.
    ///
    /// # Panics
    ///
    /// If the walk skips something, repeats something, or runs backwards.
    pub fn assert_tab_order(&mut self) {
        let probes = self.probes().to_vec();
        let layered = layered_subtrees(&probes);
        let expected: Vec<Id> = probes
            .iter()
            .filter(|probe| probe.focusable && !layered.contains(&probe.id))
            .map(|probe| probe.id)
            .collect();
        let out_of_flow: HashSet<Id> = probes
            .iter()
            .filter(|probe| probe.focusable && layered.contains(&probe.id))
            .map(|probe| probe.id)
            .collect();
        let total = expected.len() + out_of_flow.len();
        if total == 0 {
            return;
        }

        self.memory.set_focus(None);
        let mut walked = Vec::new();
        for _ in 0..total {
            self.tab();
            match self.focused() {
                Some(id) => walked.push(id),
                None => panic!("Tab reached nothing, with {total} focusable element(s) on screen"),
            }
        }

        let seen: HashSet<Id> = walked.iter().copied().collect();
        assert_eq!(
            seen.len(),
            total,
            "Tab visited {} of {total} focusable elements before repeating itself",
            seen.len()
        );

        let in_flow: Vec<Id> = walked.iter().copied().filter(|id| !out_of_flow.contains(id)).collect();
        assert_eq!(in_flow, expected, "Tab did not travel the order the interface is written in");

        let first_layer = walked.iter().position(|id| out_of_flow.contains(id));
        if let Some(first_layer) = first_layer {
            assert_eq!(
                first_layer,
                expected.len(),
                "what is lifted out of the flow is drawn last and must be tabbed to last"
            );
        }
    }

    // ----- what came of it ----------------------------------------------------

    /// The application's own state.
    pub fn state(&self) -> &S {
        self.app.state()
    }

    /// The pixels of the last frame.
    pub fn canvas(&self) -> &Canvas {
        &self.canvas
    }

    /// The colour of one device pixel, or `None` outside the surface.
    ///
    /// In *device* pixels, not logical units: this is a question about what was
    /// rasterised, and at a scale of two there are four of these to a unit.
    pub fn pixel(&self, x: u32, y: u32) -> Option<Color> {
        if x >= self.canvas.width() || y >= self.canvas.height() {
            return None;
        }
        let index = (y * self.canvas.width() + x) as usize;
        self.canvas.pixels().get(index).map(|&word| Color::from_argb(word))
    }

    /// Whether anything was drawn inside a rectangle, over the window's own
    /// ground.
    ///
    /// The blunt question a snapshot answers, without a snapshot to keep in
    /// step: *is there something there*. It is asked against the ground as it
    /// would have been drawn at that height rather than against one flat
    /// colour, because the window is filled with a slight vertical gradient and
    /// no two rows of it are the same.
    pub fn marked(&self, rect: Rect) -> bool {
        let ground = self.ground();
        let scale = self.canvas.scale();
        let device = Rect::new(rect.x * scale, rect.y * scale, rect.w * scale, rect.h * scale);

        for y in device.y.max(0.0) as u32..(device.max_y() as u32).min(self.canvas.height()) {
            for x in device.x.max(0.0) as u32..(device.max_x() as u32).min(self.canvas.width()) {
                let index = (y * self.canvas.width() + x) as usize;
                match self.canvas.pixels().get(index) {
                    Some(&drawn) if drawn != ground[y as usize] => return true,
                    _ => {}
                }
            }
        }
        false
    }

    /// The colour the bare window is at each device row.
    ///
    /// A one-pixel-wide surface cleared exactly as a frame is, so what counts
    /// as "nothing was drawn here" comes from the same code that draws nothing
    /// rather than from a guess about what it would have produced.
    fn ground(&self) -> Vec<u32> {
        let theme = self.theme_in_force();
        let mut strip = Canvas::new(1, self.canvas.height(), self.canvas.scale());
        self.app.paint_ground(&mut strip, &theme);
        strip.pixels().to_vec()
    }

    /// Writes the last frame out as a PNG.
    ///
    /// For looking at what a test drew, and for the screenshots a project keeps
    /// beside its documentation — which are then made by the same code that
    /// draws the real window, and cannot fall out of date with it.
    ///
    /// # Errors
    ///
    /// If the file cannot be written, or the canvas cannot be encoded.
    pub fn save_png(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        let bytes = crate::image::png(
            self.canvas.width(),
            self.canvas.height(),
            &crate::image::rgba(&self.canvas),
        )
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "the frame could not be encoded")
        })?;
        std::fs::write(path, bytes)
    }

    /// What has the keyboard, if anything.
    pub fn focused(&self) -> Option<Id> {
        self.memory.focused()
    }

    /// How far a scrolling area has been scrolled.
    pub fn scroll_offset(&self, id: Id) -> f32 {
        self.memory.scroll_offset(id)
    }

    /// Whether anything is still mid-animation.
    ///
    /// What the loop asks to decide whether to come back promptly, and what a
    /// test asserts to pin that an interface actually settles — one that never
    /// stops animating never stops drawing.
    pub fn is_animating(&self) -> bool {
        self.memory.is_animating()
    }

    /// The theme this harness draws with, at its appearance and faces.
    ///
    /// Asked of the application rather than built here, so that what a test
    /// measures against — the ground [`Harness::marked`] compares to — is the
    /// same theme the frame was drawn from.
    fn theme_in_force(&self) -> Theme {
        self.app.theme_for(self.appearance, self.fonts.ui_font, self.fonts.mono_font)
    }

    /// Draws a frame if nothing has been drawn yet.
    ///
    /// So that a test can ask what is on screen without first remembering to
    /// draw it, which is a step that only ever gets left out.
    fn ensure_drawn(&mut self) {
        if self.probes.is_empty() {
            self.frame();
        }
    }

    /// Where the thing showing `text` is, or a failure naming what is there.
    fn require(&mut self, text: &str) -> Rect {
        match self.rect_of(text) {
            Some(rect) => rect,
            None => panic!(
                "nothing on screen shows {text:?}; what is there is {:?}",
                self.text()
            ),
        }
    }
}

/// Everything drawn out of the ordinary flow, and everything inside it.
///
/// A layer is drawn after the whole of the flow, so the keyboard reaches it
/// after the whole of the flow too. Its children are not marked themselves —
/// only the layer's own root is — so this walks down from each of them.
fn layered_subtrees(probes: &[Probe]) -> HashSet<Id> {
    let mut inside = HashSet::new();
    // Parents come before their children, so one pass settles the whole tree.
    for probe in probes {
        let under_a_layer = probe.parent.is_some_and(|parent| inside.contains(&parent));
        if probe.layered || under_a_layer {
            inside.insert(probe.id);
        }
    }
    inside
}

/// What one element came out as, and what held it.
fn probe<S>(el: &El<S>, parent: Option<Id>) -> Probe {
    Probe {
        id: el.id,
        parent,
        key: el.key.clone(),
        role: el.accessibility_role(),
        text: el.text_content().map(str::to_owned),
        rect: el.rect,
        disabled: el.is_disabled(),
        clickable: el.click_action().is_some(),
        focusable: el.focusable,
        layered: el.anchor().is_some(),
    }
}

/// The faces a harness draws with: the built one, as both the proportional and
/// the fixed-width face.
///
/// One face standing in for both, because what the two are *for* is telling a
/// reader that a string came from the machine rather than from the interface —
/// which is a question about a real desktop's fonts and not one a test can
/// answer by loading a second copy of the same box.
pub fn test_fonts() -> LoadedFonts {
    let mut fonts = Fonts::new();
    let ui_font = fonts.add(font::test_font());
    let mono_font = fonts.add(font::test_font());
    LoadedFonts { fonts, ui_font, mono_font }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{button, col, text};

    /// Something to watch being changed.
    #[derive(Default)]
    struct Counter {
        count: i32,
    }

    fn counter(state: &Counter) -> El<Counter> {
        col((
            text(format!("{}", state.count)),
            button("Increment").on_click(|counter: &mut Counter| counter.count += 1),
        ))
    }

    #[test]
    fn a_harness_draws_without_a_window_and_answers_what_it_drew() {
        let mut harness = Harness::new(Counter::default(), counter);
        assert!(harness.shows("0"));
        assert!(harness.shows("Increment"));
    }

    #[test]
    fn clicking_by_name_runs_the_handler_and_the_next_frame_shows_it() {
        let mut harness = Harness::new(Counter::default(), counter);
        harness.click_text("Increment");
        assert_eq!(harness.state().count, 1, "the handler runs within the frame that delivered it");
        assert!(harness.frame().shows("1"), "and the next frame draws what it changed");
    }

    #[test]
    fn aiming_at_something_that_is_not_there_fails_loudly() {
        let mut harness = Harness::new(Counter::default(), counter);
        let missing = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            harness.click_text("Decrement");
        }));
        assert!(missing.is_err(), "clicking nothing must not quietly pass");
    }

    /// The strip a focus ring would cross, just above an element's own edge.
    ///
    /// The ring is stroked two units outside the rect and two thick, so its
    /// band lies wholly above the top edge; a short strip over the middle of
    /// that edge — clear of the corners and of the element's own border — is
    /// marked exactly when the ring is drawn.
    fn ring_strip(rect: Rect) -> Rect {
        Rect::new(rect.x + rect.w / 2.0 - 5.0, rect.y - 4.0, 10.0, 2.0)
    }

    #[test]
    fn the_focus_ring_marks_keyboard_focus_and_never_a_click() {
        let mut harness = Harness::new(Counter::default(), |_: &Counter| {
            crate::col(crate::button("Start").key("go").on_click(|_: &mut Counter| {}))
                .pad(20.0)
        });
        let rect = harness.find_key("go").expect("the button is on screen").rect;

        harness.click(rect.center());
        assert_eq!(harness.focused(), Some(harness.find_key("go").unwrap().id));
        assert!(
            !harness.marked(ring_strip(rect)),
            "a click already showed the person where they aimed; no ring"
        );

        harness.tab();
        assert!(harness.marked(ring_strip(rect)), "keyboard focus is invisible without the ring");

        harness.click(rect.center());
        assert!(!harness.marked(ring_strip(rect)), "the next click takes the ring back off");
    }

    #[test]
    fn a_field_wears_the_ring_however_focus_arrived() {
        // The one exception to keyboard-only: a caret justifies the ring, so a
        // clicked field looks held exactly as a tabbed-to one does.
        let mut harness = Harness::new(Counter::default(), |_: &Counter| {
            crate::col(crate::field("").key("name")).pad(20.0)
        });
        let rect = harness.find_key("name").expect("the field is on screen").rect;

        harness.click(rect.center());
        assert!(harness.marked(ring_strip(rect)), "a clicked field is still ringed");
    }

    /// A line being typed into, for the caret tests.
    #[derive(Default)]
    struct Typing {
        text: String,
    }

    #[test]
    fn the_caret_blinks_at_rest_and_holds_solid_under_typing() {
        let mut harness = Harness::new(Typing::default(), |app: &Typing| {
            crate::col(
                crate::field(app.text.clone())
                    .key("name")
                    .on_input(|app: &mut Typing, text: String| app.text = text),
            )
            .pad(20.0)
        })
        .frame_time(Duration::from_millis(66));
        let rect = harness.find_key("name").expect("the field is on screen").rect;

        // A device pixel inside the caret's column: eight units of the field's
        // own padding in, at its vertical middle. Its resting colour is the
        // field's well, read before anything has focus.
        let (x, y) = ((rect.x + 8.0) as u32, rect.center().y as u32);
        let well = harness.pixel(x, y).expect("the field is on the canvas");

        harness.click(rect.center());
        let (mut lit, mut dark) = (false, false);
        for _ in 0..30 {
            harness.frame();
            match harness.pixel(x, y) == Some(well) {
                true => dark = true,
                false => lit = true,
            }
        }
        assert!(lit && dark, "two seconds of a focused caret must both show and hide it");
        assert!(harness.is_animating(), "the blink is a live loop while the field is focused");

        // Step to a frame where the caret is dark, then type: the keystroke
        // resets the blink, so the caret is solid at its new place from the
        // frame the character lands, not whenever the old blink comes round.
        for _ in 0..30 {
            if harness.pixel(x, y) == Some(well) {
                break;
            }
            harness.frame();
        }
        harness.type_text("x");
        // One glyph along: the test face advances half an em of the field's
        // code size, so the caret's column now starts 5.75 units in and the
        // device pixel one unit further sits wholly inside it.
        let after = (rect.x + 8.0 + 6.0) as u32;
        for _ in 0..4 {
            assert_ne!(
                harness.pixel(after, y),
                Some(well),
                "typing must hold the caret solid, not mid-blink"
            );
            harness.frame();
        }
    }

    #[test]
    fn the_face_it_draws_with_measures_in_round_numbers() {
        // Aligned to the start, so the run is laid out to the width it asked
        // for rather than stretched across the window it was given.
        let mut harness = Harness::new(Counter::default(), |_: &Counter| {
            col(text("12345").text_size(20.0)).align(crate::Align::Start)
        });
        let rect = harness.rect_of("12345").expect("the text is on screen");
        assert_eq!(rect.w, 50.0, "five characters at half of twenty units each");
        assert_eq!(rect.h, 20.0, "one line is one em");
    }
}
