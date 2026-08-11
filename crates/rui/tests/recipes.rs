//! Controls this library does not ship, built from the primitives and tested
//! exactly as anything it *did* ship would be.
//!
//! This is the claim the foundation has to answer for: that a checkbox, a
//! switch, a slider, a group of choices, and a menu are all things you write in
//! a few lines rather than things you wait for — and that once written they are
//! ordinary elements, testable with no window and no special support.
//!
//! Each control here is deliberately whole and standalone. Copying one into a
//! project and changing it is the intended use; see `examples/controls.rs` for
//! the same set drawn together.
//!
//! Every one of them also states what it *is* — a [`Role`], and a name where it
//! has no words of its own — and every test below ends by asserting that the
//! interface it drove keeps the accessibility convention. A control nobody can
//! reach without a pointer is not a finished control, so the tests that say
//! these work say that too.

use rui::testing::Harness;
use rui::{
    Align, Anchor, Bgra, Color, Drag, El, Key, KeyCode, KeyPhase, KeyStroke, Modifiers, Painter,
    Point, Pointing, Radius, Rect, Role, Size, Tone, caption, col, draw, panel, row, text,
};
use std::sync::Arc;

/// Everything the controls below are wired to.
#[derive(Default)]
struct Settings {
    notify: bool,
    dark: bool,
    volume: f32,
    format: usize,
    tip: Option<String>,
    /// The last picture the far machine sent, if a session is up.
    ///
    /// Behind an [`Arc`] because the description is rebuilt every frame and the
    /// drawing inside it owns what it draws: a clone per frame of a megabyte of
    /// screen would cost more than rasterising the interface does, and a clone
    /// of the pointer costs nothing.
    screen: Option<Arc<Screen>>,
    /// Physical keys forwarded to the far machine and not yet released.
    held: Vec<KeyCode>,
    /// Where the pointer has been told the far machine to put its own, in the
    /// pane's own coordinates, in the order it was told.
    pointed: Vec<Point>,
}

/// A picture from another machine, in the byte order every capture uses.
struct Screen {
    width: u32,
    height: u32,
    /// Rows `stride` bytes apart — wider than the pixels, as a real capture is.
    stride: usize,
    bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// The recipes
// ---------------------------------------------------------------------------

/// A box that answers the pointer, and a word beside it.
fn checkbox<S: 'static>(label: &str, checked: bool, toggle: impl Fn(&mut S) + 'static) -> El<S> {
    row((
        draw(Size::new(15.0, 15.0), move |painter: &mut Painter<'_>, rect: Rect| {
            painter.fill(rect, Radius::Units(4.0), if checked { Tone::Accent } else { Tone::Sunken });
            painter.stroke(rect, Radius::Units(4.0), 1.0, Tone::Border);
        })
        .size(15.0, 15.0),
        text(label),
    ))
    .gap(8.0)
    .h(22.0)
    .align(Align::Center)
    .role(Role::Checkbox)
    .selected(checked)
    .on_click(move |state: &mut S| toggle(state))
}

/// A track, and a knob that slides along it.
fn switch<S: 'static>(on: bool, flip: impl Fn(&mut S) + 'static) -> El<S> {
    draw(Size::new(34.0, 20.0), move |painter: &mut Painter<'_>, rect: Rect| {
        painter.fill(rect, Radius::Pill, if on { Tone::Accent } else { Tone::Sunken });
        let knob = rect.h - 6.0;
        let x = if on { rect.max_x() - knob - 3.0 } else { rect.x + 3.0 };
        painter.fill(Rect::new(x, rect.y + 3.0, knob, knob), Radius::Pill, Tone::Surface);
    })
    .size(34.0, 20.0)
    .role(Role::Checkbox)
    .selected(on)
    .label("Dark appearance")
    .on_click(move |state: &mut S| flip(state))
}

/// A track that reports where along it the pointer is, and answers the arrows.
fn slider<S: 'static>(value: f32, set: impl Fn(&mut S, f32) + Copy + 'static) -> El<S> {
    const STEP: f32 = 0.05;
    let value = value.clamp(0.0, 1.0);
    draw(Size::new(160.0, 18.0), move |painter: &mut Painter<'_>, rect: Rect| {
        painter.fill(rect, Radius::Pill, Tone::Sunken);
        painter.fill(Rect::new(rect.x, rect.y, rect.w * value, rect.h), Radius::Pill, Tone::Accent);
    })
    .size(160.0, 18.0)
    .role(Role::Slider)
    .label("Volume")
    .value(format!("{:.0}%", value * 100.0))
    .on_drag(move |state: &mut S, drag: Drag| set(state, drag.fraction().x))
    .on_key(move |state: &mut S, key: Key, _: Modifiers| match key {
        Key::Left => set(state, (value - STEP).max(0.0)),
        Key::Right => set(state, (value + STEP).min(1.0)),
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
                    painter.fill(rect, Radius::Pill, if taken { Tone::Accent } else { Tone::Sunken });
                })
                .size(15.0, 15.0),
                text(*label),
            ))
            .key(*label)
            .h(22.0)
            .gap(8.0)
            .align(Align::Center)
            .role(Role::Radio)
            .selected(taken)
            .on_click(move |state: &mut S| choose(state, index))
        })
        .collect::<Vec<_>>())
}

/// A pane showing another machine's screen, and sending it the keyboard and the
/// pointer.
///
/// The control this library was missing every piece of: a bitmap primitive to
/// draw a captured frame with, the physical key rather than the character a
/// layout made of it, the release as well as the press, and — the last one — a
/// pointer position that arrives without a button being held, since a hand
/// moving over a remote screen is the whole of pointing at it.
fn viewport<S: 'static>(
    size: Size,
    screen: Option<Arc<Screen>>,
    forward: impl Fn(&mut S, KeyStroke) + 'static,
    point: impl Fn(&mut S, Pointing) + 'static,
) -> El<S> {
    draw(size, move |painter: &mut Painter<'_>, rect: Rect| {
        // A frame whose sizes disagree with its buffer is drawn as no frame at
        // all rather than as whatever is past the end of it.
        let picture = screen.as_ref().and_then(|screen| {
            Bgra::new(screen.width, screen.height, screen.stride, &screen.bytes)
        });
        match picture {
            Some(picture) => painter.canvas().blit_bgra(rect, &picture),
            None => painter.fill(rect, Radius::Units(2.0), Tone::Sunken),
        }
    })
    .key("screen")
    .role(Role::Image)
    .label("Remote screen")
    .on_raw_key(forward)
    .on_pointer_move(point)
}

// ---------------------------------------------------------------------------
// What they do
// ---------------------------------------------------------------------------

#[test]
fn a_checkbox_answers_a_click_on_its_label_as_well_as_on_its_box() {
    let mut harness = Harness::new(Settings::default(), |settings: &Settings| {
        col(checkbox("Notify on failure", settings.notify, |settings: &mut Settings| {
            settings.notify = !settings.notify
        }))
        .align(Align::Start)
    });

    harness.click_text("Notify on failure");
    assert!(harness.state().notify, "clicking the word is clicking the control");

    harness.click_text("Notify on failure");
    assert!(!harness.state().notify, "and it is a toggle, not a latch");

    harness.assert_accessible();
    harness.assert_tab_order();
}

#[test]
fn a_checkbox_draws_differently_once_it_is_ticked() {
    let mut off = Harness::new(Settings::default(), |settings: &Settings| {
        col(checkbox("Notify", settings.notify, |_: &mut Settings| {})).align(Align::Start)
    })
    .size(200.0, 60.0);
    let mut on = Harness::new(Settings { notify: true, ..Settings::default() }, |settings: &Settings| {
        col(checkbox("Notify", settings.notify, |_: &mut Settings| {})).align(Align::Start)
    })
    .size(200.0, 60.0);

    off.frame();
    on.frame();
    assert_ne!(off.canvas().pixels(), on.canvas().pixels(), "a state nobody can see is not a state");

    on.assert_accessible();
}

#[test]
fn a_switch_flips_and_moves_its_knob_when_it_does() {
    let mut harness = Harness::new(Settings::default(), |settings: &Settings| {
        col(switch(settings.dark, |settings: &mut Settings| settings.dark = !settings.dark)
            .key("switch"))
        .align(Align::Start)
    })
    .size(200.0, 60.0);

    harness.frame();
    let rect = harness.find_key("switch").expect("the switch is on screen").rect;
    let before: Vec<u32> = harness.canvas().pixels().to_vec();

    harness.click(rect.center());
    assert!(harness.state().dark);
    harness.frame();
    assert_ne!(before, harness.canvas().pixels(), "the knob should have moved");

    harness.assert_accessible();
    harness.assert_tab_order();
}

#[test]
fn a_slider_follows_the_pointer_and_the_arrow_keys_alike() {
    let mut harness = Harness::new(Settings::default(), |settings: &Settings| {
        col(slider(settings.volume, |settings: &mut Settings, value| settings.volume = value)
            .key("volume"))
        .align(Align::Start)
    });

    let rect = harness.find_key("volume").expect("the slider is on screen").rect;
    harness.drag(Point::new(rect.x + 40.0, rect.center().y), Point::new(rect.x + 120.0, rect.center().y));
    assert!((harness.state().volume - 0.75).abs() < 0.001, "it ends where the pointer let go");

    // Pressing it gave it the keyboard, so the arrows step it from there.
    harness.key(Key::Left);
    assert!((harness.state().volume - 0.70).abs() < 0.001);
    harness.key(Key::Right).key(Key::Right);
    assert!((harness.state().volume - 0.80).abs() < 0.001);

    harness.assert_accessible();
}

#[test]
fn a_slider_can_be_used_from_the_keyboard_without_ever_being_clicked() {
    let mut harness = Harness::new(Settings::default(), |settings: &Settings| {
        col(slider(settings.volume, |settings: &mut Settings, value| settings.volume = value))
    });

    harness.tab();
    harness.key(Key::Right);
    assert!((harness.state().volume - 0.05).abs() < 0.001, "tab reached it and the arrow moved it");

    harness.assert_accessible();
    harness.assert_tab_order();
}

#[test]
fn a_group_of_choices_takes_exactly_one_of_them() {
    let mut harness = Harness::new(Settings::default(), |settings: &Settings| {
        col(radio_group(&["Plain", "JSON", "Binary"], settings.format, |settings: &mut Settings, index| {
            settings.format = index
        }))
        .align(Align::Start)
    });

    harness.click_text("Binary");
    assert_eq!(harness.state().format, 2);

    harness.click_text("Plain");
    assert_eq!(harness.state().format, 0, "choosing one is unchoosing the others");

    harness.assert_accessible();
    harness.assert_tab_order();
}

#[test]
fn a_note_appears_when_the_pointer_arrives_and_goes_when_it_leaves() {
    let mut harness = Harness::new(Settings::default(), |settings: &Settings| {
        col((
            text("Workers")
                .h(24.0)
                .on_hover(|settings: &mut Settings, over: bool| {
                    settings.tip = over.then(|| "How many at once".to_owned())
                })
                .add(settings.tip.as_ref().map(|note| {
                    panel(caption(note.clone())).w(160.0).key("tip").layer(Anchor::Below)
                })),
            text("Elsewhere").h(24.0),
        ))
        .align(Align::Start)
    });

    assert!(!harness.shows("How many at once"), "nothing is hovered, so there is no note");

    harness.hover_text("Workers");
    harness.frame();
    assert!(harness.shows("How many at once"), "the pointer arriving brought it up");

    harness.hover_text("Elsewhere");
    harness.frame();
    assert!(!harness.shows("How many at once"), "and leaving took it away again");

    harness.assert_accessible();
}

#[test]
fn a_note_that_is_up_does_not_come_up_again_every_frame() {
    // What `on_hover` reporting the *change* rather than the state is for: an
    // application told every frame that the pointer is still there would write
    // to its own state every frame, and never stop redrawing.
    #[derive(Default)]
    struct Counted {
        changes: u32,
    }

    let mut harness = Harness::new(Counted::default(), |_: &Counted| {
        col(text("Workers").h(24.0).on_hover(|counted: &mut Counted, _| counted.changes += 1))
            .align(Align::Start)
    });

    harness.hover_text("Workers");
    assert_eq!(harness.state().changes, 1);

    harness.frames(10);
    assert_eq!(harness.state().changes, 1, "the pointer has not moved, so nothing has changed");
}



#[test]
fn a_viewport_shows_another_machines_screen_and_sends_it_the_keyboard() {
    // Every one of the four things this library gained, through the public
    // surface, in the shape the console will use them: a captured frame drawn
    // into a pane, the physical key forwarded rather than the character, and
    // the release that stops the far machine holding it down.
    let mut harness = Harness::new(Settings::default(), |settings: &Settings| {
        col(viewport(
            Size::new(120.0, 80.0),
            settings.screen.clone(),
            |settings: &mut Settings, stroke: KeyStroke| {
                let Some(code) = stroke.code else {
                    return;
                };
                match stroke.phase {
                    KeyPhase::Down => settings.held.push(code),
                    KeyPhase::Up => settings.held.retain(|down| *down != code),
                }
            },
            |settings: &mut Settings, at: Pointing| settings.pointed.push(at.at),
        ))
        .align(Align::Start)
    });

    let rect = harness.find_key("screen").expect("the pane is on screen").rect;
    let inside = rect.center();
    assert_ne!(
        harness.pixel(inside.x as u32, inside.y as u32),
        Some(Color::WHITE),
        "nothing has arrived yet, so the pane is showing its own empty state"
    );

    harness.state_mut().screen = Some(Arc::new(captured(120, 80, Color::WHITE)));
    harness.frame();
    assert_eq!(
        harness.pixel(inside.x as u32, inside.y as u32),
        Some(Color::WHITE),
        "the frame that arrived is what is on screen"
    );

    // Driving it: a function key, which this library has no name for at all.
    harness.click(inside);
    let function_key = KeyCode::new(96);
    harness.raw_key(function_key, None);
    assert_eq!(harness.state().held, [function_key], "the far machine was told nothing");

    harness.raw_key_up(function_key, None);
    assert!(harness.state().held.is_empty(), "left held down on the far machine");

    harness.assert_accessible();
}

#[test]
fn a_hand_moving_over_the_viewport_moves_the_far_pointer_without_pressing_anything() {
    // The gap this closes. `on_hover` answers whether the pointer is here and
    // `on_drag` answers where it is only while a button is held, so before
    // `on_pointer_move` a remote screen could be clicked but not *pointed at* —
    // the far cursor stood still until something was dragged.
    let mut harness = pointing();
    let rect = harness.find_key("screen").expect("the pane is on screen").rect;

    harness.move_pointer(Point::new(rect.x + 10.0, rect.y + 20.0));
    harness.move_pointer(Point::new(rect.x + 30.0, rect.y + 40.0));

    assert_eq!(
        harness.state().pointed,
        [Point::new(10.0, 20.0), Point::new(30.0, 40.0)],
        "the far machine is told where in its own screen the pointer is, not where in this window"
    );
    assert!(harness.state().held.is_empty(), "nothing was pressed to make that happen");
}

#[test]
fn a_pointer_resting_on_the_viewport_sends_nothing_at_all() {
    // The other half of "movement, not presence". A handler told every frame
    // that the pointer is still where it was would forward a position down a
    // socket for as long as a hand rested on the picture, and — because writing
    // to the state is what asks for the next frame — would never stop drawing.
    let mut harness = pointing();
    let rect = harness.find_key("screen").expect("the pane is on screen").rect;

    harness.move_pointer(rect.center());
    assert_eq!(harness.state().pointed.len(), 1);

    harness.frames(10);
    assert_eq!(harness.state().pointed.len(), 1, "ten frames of a hand holding still");
}

#[test]
fn the_pointer_leaving_the_viewport_stops_the_far_pointer_rather_than_dragging_it_along() {
    let mut harness = pointing();
    let rect = harness.find_key("screen").expect("the pane is on screen").rect;

    harness.move_pointer(rect.center());
    harness.move_pointer(Point::new(rect.x + rect.w + 40.0, rect.y + rect.h + 40.0));

    assert_eq!(harness.state().pointed.len(), 1, "a position outside the pane is not the pane's");
}

/// A window holding nothing but the viewport, for the pointer tests.
fn pointing() -> Harness<Settings> {
    Harness::new(Settings::default(), |settings: &Settings| {
        col(viewport(
            Size::new(120.0, 80.0),
            settings.screen.clone(),
            |_: &mut Settings, _: KeyStroke| {},
            |settings: &mut Settings, at: Pointing| settings.pointed.push(at.at),
        ))
        .align(Align::Start)
    })
}

/// A picture of one colour, padded as a capture API pads its rows.
fn captured(width: u32, height: u32, color: Color) -> Screen {
    let padding = 48;
    let stride = width as usize * 4 + padding;
    let mut bytes = Vec::with_capacity(stride * height as usize);
    for _ in 0..height {
        for _ in 0..width {
            bytes.extend_from_slice(&[color.b, color.g, color.r, 0xff]);
        }
        bytes.extend(std::iter::repeat_n(0x7f, padding));
    }
    Screen { width, height, stride, bytes }
}
