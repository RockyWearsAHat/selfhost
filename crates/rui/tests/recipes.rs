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
    Align, Anchor, Drag, El, Key, Modifiers, Painter, Point, Radius, Rect, Role, Size, Tone,
    caption, col, draw, panel, row, text,
};

/// Everything the controls below are wired to.
#[derive(Default)]
struct Settings {
    notify: bool,
    dark: bool,
    volume: f32,
    format: usize,
    tip: Option<String>,
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


