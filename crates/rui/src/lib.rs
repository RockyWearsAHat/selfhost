//! A declarative interface library for Rust.
//!
//! `rui` takes the three things the web splits across three languages — the
//! structure of a page, how it looks, and what it does — and makes them one Rust
//! expression:
//!
//! ```ignore
//! use rui::{El, button, col, title};
//!
//! struct Counter {
//!     count: i32,
//! }
//!
//! fn view(counter: &Counter) -> El<Counter> {
//!     col((
//!         title(format!("{}", counter.count)),
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
//! That is the whole model. `col` and `row` are the structure, the chained
//! setters are the style, `on_click` is the behaviour, and `view` is a plain
//! function from the application's state to a description of what should be on
//! screen — called again whenever anything might have changed.
//!
//! # Why it is shaped this way
//!
//! **The description is rebuilt, not mutated.** There is no retained tree of
//! widget objects to keep in step with the data. An interface that mirrors
//! changes into widget objects has, for every change, a way of mirroring it
//! wrongly, and the symptom is a screen showing something that is no longer
//! true. Rebuilding from the data makes that class of defect impossible to
//! write.
//!
//! **Handlers are functions of the state, not closures over it.** An
//! `on_click(|app: &mut App| …)` takes the application's own state as an
//! argument. The description therefore borrows nothing mutably, the handlers run
//! after the frame has been drawn, and there is no `Rc`, no `RefCell`, and no
//! interior mutability anywhere in this library. That is the piece most Rust
//! interface libraries pay for in ceremony, and here it costs nothing.
//!
//! **Colours are roles, not values.** A style names [`Tone::Surface`] or
//! [`Tone::Muted`] rather than a particular grey, so one description of an
//! interface is correct on a light desktop and on a dark one.
//!
//! **Everything is drawn here.** The rasteriser, the TrueType parser, the text
//! layout, the antialiasing, and the platform windows are all in this crate,
//! which has no dependencies at all. An interface renders identically on every
//! platform, and can be drawn with no display attached — see [`App::render`],
//! which is how this library's own appearance is tested.
//!
//! # Foundations, not a catalogue
//!
//! There is no `checkbox`, no `toggle`, and no `slider` here, because a library
//! that ships one has decided what a checkbox *is* — and the first time yours
//! needs to be a shade smaller or answer the right-hand button, the catalogue
//! turns out to be a list of the things you are allowed to want.
//!
//! What is here instead is enough to write any of them:
//!
//! - [`widgets::draw`] — a rectangle and the same [`Painter`] every element in
//!   this crate is made of.
//! - [`Painter::visual`] — whether it is hovered, held, focused, or disabled,
//!   and how far its hover has eased, so custom drawing reacts exactly as a
//!   button does.
//! - [`El::on_drag`] — where the pointer is *within* it, every frame it is
//!   held. The difference between a button and a slider, a splitter, a knob, or
//!   a canvas that pans.
//! - [`El::on_key`], [`El::on_scroll`], [`El::on_hover`], and [`El::layer`] —
//!   the keyboard, the wheel, the pointer arriving, and somewhere to put what
//!   opens.
//!
//! The elements that *are* here are recipes of that kind, kept because an
//! interface needs a house style more than it needs a hundred choices. See the
//! `controls` example for a checkbox, a switch, a slider, a radio group, a
//! stepper, and a tooltip written from the primitives above.
//!
//! # The pieces
//!
//! - [`El`] and the constructors in [`widgets`] — the structure.
//! - [`style`] — the look: lengths, roles, alignment, radii, inheritance.
//! - [`accessibility`] — what the structure *means*: a [`Role`] on every
//!   element, a name computed from the words inside it, and a frame-to-frame
//!   diff of the whole for the platform to push.
//! - [`App`] and [`run`] — the loop.
//! - [`Memory`] — the little that outlives a frame.
//! - [`canvas`], [`font`], [`text`](mod@text), [`image`] — the renderer underneath, which
//!   an application reaches directly through [`Painter`] and [`widgets::draw`].
//! - [`testing`] — driving the whole of it with no window: the real frame, into
//!   a buffer, with a font built rather than borrowed so that a width in a test
//!   is a round number.
//!
//! # Where the state lives
//!
//! In the application's own type, and nowhere else. What this library keeps
//! between frames is only what belongs to the *interaction* — what the pointer
//! is over, what has the keyboard, where a list is scrolled, where a caret sits
//! — all of it in [`Memory`], under an identity derived from the element's path
//! through the tree.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod accessibility;
pub mod app;
pub mod canvas;
pub mod color;
pub mod element;
pub mod font;
pub mod geom;
pub mod image;
pub mod input;
mod layout;
pub mod memory;
pub mod paint;
pub mod shell;
pub mod style;
pub mod testing;
pub mod text;
pub mod theme;
pub mod widgets;

pub use accessibility::{AccessNode, AccessTree, AccessUpdate, Role};
pub use app::{App, run};
pub use canvas::{Canvas, Corner, Mask};
pub use color::Color;
pub use element::{Children, El};
pub use font::{Font, FontError};
pub use geom::{Insets, Point, Rect, Size};
pub use input::{Composition, Drag, Event, Input, Key, Modifiers, Phase, PointerButton};
pub use memory::{Id, Memory, Response};
pub use paint::{Painter, Visual};
pub use shell::{Error, LoadedFonts, WindowOptions};
pub use style::{Align, Anchor, Axis, Face, Ink, Justify, Length, Radius, Style, Tone};
pub use text::{FontId, Fonts, TextStyle};
pub use theme::{Appearance, Palette, Status, Theme};
pub use widgets::{
    button, caption, code, col, divider, dot, draw, field, field_row, figure, heading, meter,
    micro, panel, paragraph, row, section, segmented, spacer, tabs, tag, text, title,
};

/// A run of text, formatted.
///
/// `text!("{} of {}", running, total)` rather than
/// `text(format!("{} of {}", running, total))`. Interfaces are mostly made of
/// sentences with values in them, and the two extra calls per label add up to a
/// description that reads as string handling rather than as an interface.
#[macro_export]
macro_rules! text {
    ($($argument:tt)*) => {
        $crate::text(::std::format!($($argument)*))
    };
}

/// A line of something the machine produced, formatted; see [`text!`].
#[macro_export]
macro_rules! code {
    ($($argument:tt)*) => {
        $crate::code(::std::format!($($argument)*))
    };
}
