//! Every control a toolkit usually ships, written here instead — from the
//! primitives, in a few lines each.
//!
//! Run it with `cargo run -p rui --example controls`, or write it to a pair of
//! PNGs with `cargo run -p rui --example controls -- <directory>`.
//!
//! # Why this is an example and not a module
//!
//! A library that ships `checkbox()` has decided what a checkbox is. The moment
//! you want yours a shade smaller, with a different tick, or answering the
//! right-hand button as well, you are either sending a patch upstream or
//! writing it from scratch anyway — and the catalogue you were given turns out
//! to be a list of the things you are allowed to want.
//!
//! So the library's job is to make sure the *foundation* can express any of
//! them. That is what everything below is: not the library's controls, but a
//! demonstration that the primitives are complete enough to build them, in
//! code you would be happy to paste into your own project and change.
//!
//! Each one uses the same four things any control needs, and which are what the
//! library actually provides:
//!
//! | primitive | what it gives |
//! |---|---|
//! | [`draw`] | a rectangle and a painter |
//! | [`Painter::visual`] | whether it is hovered, held, focused, or disabled |
//! | [`El::on_drag`] | where the pointer is, continuously, while held |
//! | [`El::on_key`], [`El::on_hover`], [`El::layer`] | the keyboard, the pointer arriving, and somewhere to put what opens |
//!
//! # And one more line each
//!
//! A control the library has never heard of still has to say what it *is*, or
//! it exists only for people who can see it. So each one below carries a
//! [`Role`] and, where it has no words of its own, a name — two setters, next
//! to the drawing they describe. `tests/accessibility.rs` drives this example
//! and fails if either is missing, which is how the convention is held rather
//! than merely stated.
//!
//! The state and the view are public so that test can drive this exact
//! interface rather than a copy of it.

use rui::style::{Align, Anchor, Radius};
use rui::{
    App, Appearance, Drag, El, Key, Modifiers, Painter, Rect, Role, Size, Tone, caption, code, col,
    draw, heading, panel, row, text,
};

// ---------------------------------------------------------------------------
// The controls
// ---------------------------------------------------------------------------

/// A checkbox: a box that answers the pointer, and a word beside it.
///
/// The whole control is one `draw` for the box, one `text` for the label, and
/// one handler on the row that holds them — which is what makes the label
/// clickable too, without either half knowing about the other.
fn checkbox<S: 'static>(
    label: &str,
    checked: bool,
    toggle: impl Fn(&mut S) + 'static,
) -> El<S> {
    row((
        draw(Size::new(15.0, 15.0), move |painter: &mut Painter<'_>, rect: Rect| {
            let lit = painter.visual().lit;
            let fill = if checked { Tone::Accent } else { Tone::Sunken };
            painter.fill(rect, Radius::Units(4.0), fill);
            painter.stroke(rect, Radius::Units(4.0), 1.0, Tone::Border);
            if checked {
                painter.fill(tick(rect), Radius::Units(1.0), Tone::OnAccent);
            }
            // The eased hover, so this animates on the same curve everything
            // else in the interface does.
            if lit > 0.0 {
                painter.stroke(rect, Radius::Units(4.0), 1.0, Tone::Focus);
            }
        })
        .size(15.0, 15.0),
        text(label),
    ))
    .gap(8.0)
    .h(22.0)
    .align(Align::Center)
    // What it is, and whether it is on. The name needs saying nowhere: the word
    // beside the box is inside the row, so the row is named after it.
    .role(Role::Checkbox)
    .selected(checked)
    .on_click(move |state: &mut S| toggle(state))
}

/// The mark inside a ticked box.
fn tick(box_rect: Rect) -> Rect {
    let inset = box_rect.w * 0.28;
    Rect::new(
        box_rect.x + inset,
        box_rect.y + inset,
        box_rect.w - inset * 2.0,
        box_rect.h - inset * 2.0,
    )
}

/// A switch: a track, and a knob that slides along it.
fn switch<S: 'static>(on: bool, flip: impl Fn(&mut S) + 'static) -> El<S> {
    draw(Size::new(34.0, 20.0), move |painter: &mut Painter<'_>, rect: Rect| {
        painter.fill(rect, Radius::Pill, if on { Tone::Accent } else { Tone::Sunken });
        painter.stroke(rect, Radius::Pill, 1.0, Tone::Border);

        let knob = rect.h - 6.0;
        let x = if on { rect.max_x() - knob - 3.0 } else { rect.x + 3.0 };
        painter.fill(Rect::new(x, rect.y + 3.0, knob, knob), Radius::Pill, Tone::Surface);
    })
    .size(34.0, 20.0)
    // A switch is a checkbox that is drawn differently, and has no words of its
    // own — so the one thing it cannot work out for itself is its name, which
    // its caller supplies with `.label`.
    .role(Role::Checkbox)
    .selected(on)
    .on_click(move |state: &mut S| flip(state))
}

/// A slider: a track that reports where along it the pointer is.
///
/// The one control that cannot be built from clicks alone, and therefore the
/// one that says most about whether a foundation is finished. It answers the
/// arrow keys as well, which is [`El::on_key`] and four more lines.
fn slider<S: 'static>(value: f32, set: impl Fn(&mut S, f32) + Copy + 'static) -> El<S> {
    /// How far an arrow key moves it.
    const STEP: f32 = 0.05;

    let value = value.clamp(0.0, 1.0);
    draw(Size::new(160.0, 18.0), move |painter: &mut Painter<'_>, rect: Rect| {
        let track = Rect::new(rect.x, rect.center().y - 3.0, rect.w, 6.0);
        painter.fill(track, Radius::Pill, Tone::Sunken);
        painter.fill(Rect::new(track.x, track.y, track.w * value, track.h), Radius::Pill, Tone::Accent);

        let knob = rect.h;
        let x = rect.x + (rect.w - knob) * value;
        painter.fill(Rect::new(x, rect.y, knob, knob), Radius::Pill, Tone::Surface);
        let edge = if painter.visual().focused { Tone::Focus } else { Tone::Border };
        painter.stroke(Rect::new(x, rect.y, knob, knob), Radius::Pill, 1.0, edge);
    })
    .h(18.0)
    .w(160.0)
    .role(Role::Slider)
    .value(format!("{:.0}%", value * 100.0))
    .on_drag(move |state: &mut S, drag: Drag| set(state, drag.fraction().x))
    .on_key(move |state: &mut S, key: Key, _: Modifiers| match key {
        Key::Left => set(state, (value - STEP).max(0.0)),
        Key::Right => set(state, (value + STEP).min(1.0)),
        Key::Home => set(state, 0.0),
        Key::End => set(state, 1.0),
        _ => {}
    })
}

/// A group of choices, one of them taken.
fn radio_group<S: 'static>(
    labels: &[&str],
    chosen: usize,
    choose: impl Fn(&mut S, usize) + Copy + 'static,
) -> El<S> {
    col(labels
        .iter()
        .enumerate()
        .map(|(index, label)| {
            let taken = index == chosen;
            row((
                draw(Size::new(15.0, 15.0), move |painter: &mut Painter<'_>, rect: Rect| {
                    painter.fill(rect, Radius::Pill, Tone::Sunken);
                    painter.stroke(rect, Radius::Pill, 1.0, Tone::Border);
                    if taken {
                        let inset = rect.w * 0.27;
                        let dot = rect.inset(rui::Insets::uniform(inset));
                        painter.fill(dot, Radius::Pill, Tone::Accent);
                    }
                })
                .size(15.0, 15.0),
                text(*label),
            ))
            .key(*label)
            .gap(8.0)
            .h(22.0)
            .align(Align::Center)
            .role(Role::Radio)
            .selected(taken)
            .on_click(move |state: &mut S| choose(state, index))
        })
        .collect::<Vec<_>>())
    .gap(2.0)
}

/// A number the wheel can turn.
fn stepper<S: 'static>(value: i32, step: impl Fn(&mut S, i32) + Copy + 'static) -> El<S> {
    row(code(format!("{value:>4}")))
        .w(64.0)
        .h(24.0)
        .pad_x(8.0)
        .fill(Tone::Sunken)
        .border(1.0, Tone::Border)
        .round(Radius::Control)
        .align(Align::Center)
        // A number that is nudged rather than typed, which is what a slider is;
        // the digits inside it are its value, so its caller names it.
        .role(Role::Slider)
        .value(value.to_string())
        .on_scroll(move |state: &mut S, _, down: f32| step(state, down.signum() as i32))
        .on_key(move |state: &mut S, key: Key, _| match key {
            Key::Up => step(state, 1),
            Key::Down => step(state, -1),
            _ => {}
        })
}

/// Something with a note that appears beside it when the pointer arrives.
///
/// The note is a layer, so it is drawn over whatever it covers and is held
/// inside the window rather than opening off the edge of it.
fn with_tip<S: 'static>(
    anchor: El<S>,
    note: &str,
    showing: bool,
    hover: impl Fn(&mut S, bool) + 'static,
) -> El<S> {
    anchor.on_hover(hover).add(showing.then(|| {
        panel(caption(note)).pad(8.0).layer(Anchor::Below)
    }))
}

// ---------------------------------------------------------------------------
// A window that shows them
// ---------------------------------------------------------------------------

/// What the controls above are wired to.
pub struct Panel {
    notify: bool,
    dark: bool,
    volume: f32,
    format: usize,
    workers: i32,
    tip: bool,
}

/// What the example opens showing.
pub fn demo() -> Panel {
    Panel { notify: true, dark: true, volume: 0.62, format: 1, workers: 8, tip: false }
}

/// The whole example, as one description.
pub fn view(panel_state: &Panel) -> El<Panel> {
    col((
        heading("CONTROLS THIS LIBRARY DOES NOT SHIP"),
        panel(col((
            labelled(
                "Checkbox",
                checkbox("Notify on failure", panel_state.notify, |panel: &mut Panel| {
                    panel.notify = !panel.notify
                }),
            ),
            labelled(
                "Switch",
                switch(panel_state.dark, |panel: &mut Panel| panel.dark = !panel.dark)
                    .label("Dark appearance"),
            ),
            labelled(
                "Slider",
                row((
                    slider(panel_state.volume, |panel: &mut Panel, value| panel.volume = value)
                        .label("Volume"),
                    caption(format!("{:.0}%", panel_state.volume * 100.0)),
                ))
                .gap(12.0)
                .align(Align::Center),
            ),
            labelled(
                "Radio",
                radio_group(&["Plain", "JSON", "Binary"], panel_state.format, |panel: &mut Panel, index| {
                    panel.format = index
                }),
            ),
            labelled(
                "Stepper",
                with_tip(
                    stepper(panel_state.workers, |panel: &mut Panel, by| {
                        panel.workers = (panel.workers + by).clamp(1, 64)
                    })
                    .label("Workers"),
                    "The wheel turns it, and so do the arrow keys.",
                    panel_state.tip,
                    |panel: &mut Panel, over| panel.tip = over,
                ),
            ),
        ))
        .gap(14.0)),
        caption("Every one of them is a `draw` and a handler. None of them is a widget."),
    ))
    .pad(20.0)
    .gap(14.0)
}

/// A row that names a control and puts it beside its name.
fn labelled(name: &str, control: El<Panel>) -> El<Panel> {
    row((heading(name).w(84.0), control)).gap(12.0).align(Align::Center).min_h(24.0)
}

fn main() -> Result<(), rui::Error> {
    let state = demo();

    // With a directory, this draws itself and stops — the same frame a window
    // would show, on a machine that may not have one.
    if let Some(directory) = std::env::args().nth(1) {
        let mut fonts = rui::shell::load_system_fonts()?;
        let mut app = App::new("Controls", state, view).size(520.0, 460.0);
        for (appearance, name) in
            [(Appearance::Light, "controls-light.png"), (Appearance::Dark, "controls-dark.png")]
        {
            let canvas = app.render(520, 460, 2.0, appearance, &mut fonts);
            let bytes = rui::image::png(canvas.width(), canvas.height(), &rui::image::rgba(&canvas))
                .expect("the frame should encode");
            std::fs::write(std::path::Path::new(&directory).join(name), bytes)?;
        }
        return Ok(());
    }

    App::new("Controls", state, view).size(520.0, 460.0).run()
}
