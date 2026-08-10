//! What an interface *does* when it is used.
//!
//! Every one of these drives the real frame — describe, lay out, draw, apply —
//! through [`Harness`], with no window and no display. They are written against
//! the public surface only, so a thing these cannot say is a thing an
//! application cannot say either.

use rui::testing::Harness;
use rui::{
    Align, Anchor, Drag, El, Key, KeyCode, KeyPhase, Modifiers, Point, Size, Tone, button, col,
    draw, field, panel, row, text,
};

/// A state with somewhere to record everything these tests provoke.
#[derive(Default)]
struct App {
    count: i32,
    volume: f32,
    typed: String,
    keys: Vec<Key>,
    /// Keys a handler was told went down and has not been told came up.
    held: Vec<Key>,
    /// Keys a handler was told came up, in order.
    released: Vec<Key>,
    /// Physical keys a handler was told went down and not up.
    codes: Vec<Option<KeyCode>>,
    wheel: f32,
    menu_open: bool,
    chosen: Option<String>,
}

#[test]
fn a_click_runs_the_handler_it_was_attached_to() {
    let mut harness = Harness::new(App::default(), |_: &App| {
        col(button("Increment").on_click(|app: &mut App| app.count += 1))
    });

    harness.click_text("Increment");
    assert_eq!(harness.state().count, 1);

    harness.click_text("Increment");
    assert_eq!(harness.state().count, 2, "a second click is a second call");
}

#[test]
fn holding_the_button_down_does_not_repeat_the_click() {
    // The distinction the input layer exists for: a control that fired while
    // the pointer was merely held would run once per frame.
    let mut harness = Harness::new(App::default(), |_: &App| {
        col(button("Fire").on_click(|app: &mut App| app.count += 1))
    });

    let at = harness.rect_of("Fire").expect("the button is on screen").center();
    harness.press(at).frames(5);
    assert_eq!(harness.state().count, 0, "a press alone is not a click");

    harness.release();
    assert_eq!(harness.state().count, 1, "the release is what completes it");
}

#[test]
fn a_press_that_wanders_off_the_control_does_not_activate_it() {
    let mut harness = Harness::new(App::default(), |_: &App| {
        col(button("Delete").on_click(|app: &mut App| app.count += 1))
    });

    let at = harness.rect_of("Delete").expect("the button is on screen").center();
    harness.press(at).drag_to(Point::new(at.x, at.y + 300.0)).release();
    assert_eq!(harness.state().count, 0, "letting go elsewhere is how a click is cancelled");
}

#[test]
fn a_disabled_control_ignores_the_pointer_entirely() {
    let mut harness = Harness::new(App::default(), |_: &App| {
        col(button("Start").on_click(|app: &mut App| app.count += 1).disabled(true))
    });

    harness.click_text("Start");
    assert_eq!(harness.state().count, 0);

    let probe = harness.find("Start").expect("it is still drawn, dimmed, rather than removed");
    assert!(probe.rect.w > 0.0, "a control that vanishes makes the row around it jump");
}

#[test]
fn only_the_topmost_thing_under_the_pointer_answers_it() {
    // A row that is itself clickable, holding a button that is too. Clicking
    // the button must not also click the row underneath it.
    let mut harness = Harness::new(App::default(), |_: &App| {
        col(row((text("Row"), button("Open").on_click(|app: &mut App| app.count += 1)))
            .h(40.0)
            .on_click(|app: &mut App| app.count += 100))
    });

    harness.click_text("Open");
    assert_eq!(harness.state().count, 1, "the row underneath must not fire as well");
}

#[test]
fn a_drag_reports_where_the_pointer_is_for_as_long_as_it_is_held() {
    // A slider, built from the primitives rather than taken off a shelf: a
    // rectangle that draws itself and a handler that reads a fraction.
    let mut harness = Harness::new(App::default(), |app: &App| {
        let volume = app.volume;
        col(draw(Size::new(200.0, 20.0), move |painter, rect| {
            painter.fill(rect, rui::Radius::Pill, Tone::Sunken);
            let filled = rui::Rect::new(rect.x, rect.y, rect.w * volume, rect.h);
            painter.fill(filled, rui::Radius::Pill, Tone::Accent);
        })
        .key("volume")
        .w(200.0)
        .on_drag(|app: &mut App, drag: Drag| app.volume = drag.fraction().x))
        .align(Align::Start)
    });

    let rect = harness.find_key("volume").expect("the slider is on screen").rect;
    assert_eq!(rect.w, 200.0);

    harness.press(Point::new(rect.x + 50.0, rect.center().y));
    assert!((harness.state().volume - 0.25).abs() < 0.001, "the press itself sets a value");

    harness.drag_to(Point::new(rect.x + 150.0, rect.center().y));
    assert!((harness.state().volume - 0.75).abs() < 0.001, "and it follows the pointer");

    // Past its own end, and still held: the fraction is clamped rather than
    // running away, and the drag is not cancelled by leaving the rectangle.
    harness.drag_to(Point::new(rect.x + 900.0, rect.center().y));
    assert_eq!(harness.state().volume, 1.0);

    harness.release();
    assert_eq!(harness.state().volume, 1.0, "letting go leaves it where it was put");
}

#[test]
fn a_drag_ends_where_it_is_released_and_not_before() {
    let mut harness = Harness::new(App::default(), |_: &App| {
        col(draw(Size::new(100.0, 20.0), |_, _| {})
            .key("track")
            .on_drag(|app: &mut App, drag: Drag| {
                if drag.ended() {
                    app.count += 1;
                }
            }))
    });

    let rect = harness.find_key("track").expect("the track is on screen").rect;
    harness.press(rect.center()).drag_to(Point::new(rect.x + 5.0, rect.y + 5.0));
    assert_eq!(harness.state().count, 0, "nothing has ended yet");

    harness.release();
    assert_eq!(harness.state().count, 1, "exactly once, on the frame it was let go");
}

#[test]
fn a_focused_control_takes_keys_of_its_own() {
    let mut harness = Harness::new(App::default(), |_: &App| {
        col(button("Stepper")
            .on_click(|_: &mut App| {})
            .on_key(|app: &mut App, key: Key, _: Modifiers| app.keys.push(key)))
    });

    harness.click_text("Stepper");
    harness.key(Key::Up).key(Key::Down);
    assert_eq!(harness.state().keys, [Key::Up, Key::Down]);
}

#[test]
fn a_key_that_went_down_comes_up_again_on_the_control_that_took_it() {
    // The round trip, and the reason it has to exist: a control that starts
    // something on a press and is never told about the release holds it for as
    // long as the program runs. When the control is a remote desktop, "holds
    // it" means a key held down on somebody else's machine.
    let mut harness = Harness::new(App::default(), |_: &App| {
        col(button("Stepper")
            .on_click(|_: &mut App| {})
            .on_key(|app: &mut App, key: Key, _: Modifiers| app.held.push(key))
            .on_key_up(|app: &mut App, key: Key, _: Modifiers| {
                app.held.retain(|down| *down != key);
                app.released.push(key);
            }))
    });

    harness.click_text("Stepper");
    harness.key(Key::Down).key(Key::Right);
    assert_eq!(harness.state().held, [Key::Down, Key::Right], "both are down");

    harness.key_up(Key::Down).key_up(Key::Right);
    assert_eq!(harness.state().released, [Key::Down, Key::Right]);
    assert!(harness.state().held.is_empty(), "left held down: {:?}", harness.state().held);
}

#[test]
fn a_whole_keystroke_leaves_nothing_held_however_many_are_typed() {
    // The same guarantee stated over a run rather than a pair: press and release
    // twenty keys and the tally must come back to nothing. A dispatch that ran
    // the presses and dropped the releases — the state before `on_key_up`
    // existed — fails this by exactly the number of keys typed.
    let mut harness = Harness::new(App::default(), |_: &App| {
        col(button("Viewport")
            .on_click(|_: &mut App| {})
            .on_key(|app: &mut App, key, _| app.held.push(key))
            .on_key_up(|app: &mut App, key, _| app.held.retain(|down| *down != key)))
    });

    harness.click_text("Viewport");
    for key in [Key::Up, Key::Down, Key::Left, Key::Right, Key::Home] {
        harness.key_stroke(key);
    }
    for letter in "abcdefghijklmno".chars() {
        harness.key_stroke(Key::Character(letter));
    }
    assert!(harness.state().held.is_empty(), "left held down: {:?}", harness.state().held);
}

#[test]
fn a_physical_key_reaches_a_handler_even_where_the_library_has_no_name_for_it() {
    // What forwarding a keystroke to another machine needs: the key that moved,
    // not the character this machine's layout made of it. F5 and the keypad have
    // no `Key` variant and must still arrive.
    let mut harness = Harness::new(App::default(), |_: &App| {
        col(button("Viewport").on_click(|_: &mut App| {}).on_raw_key(|app: &mut App, stroke| {
            match stroke.phase {
                KeyPhase::Down => app.codes.push(stroke.code),
                KeyPhase::Up => app.codes.retain(|down| *down != stroke.code),
            }
        }))
    });

    let function_key = KeyCode::new(96);
    harness.click_text("Viewport");
    harness.raw_key(function_key, None);
    assert_eq!(harness.state().codes, [Some(function_key)], "a key with no name still arrived");

    harness.raw_key_up(function_key, None);
    assert!(harness.state().codes.is_empty(), "the unnamed key was left held down");
}

#[test]
fn a_named_key_reaches_the_raw_handler_carrying_its_position_too() {
    // Both handlers see the same press: the widget reads the meaning, the thing
    // forwarding it reads the key.
    let mut harness = Harness::new(App::default(), |_: &App| {
        col(button("Viewport")
            .on_click(|_: &mut App| {})
            .on_raw_key(|app: &mut App, stroke| {
                app.codes.push(stroke.code);
                app.keys.extend(stroke.key);
            }))
    });

    harness.click_text("Viewport");
    harness.raw_key(KeyCode::new(53), Some(Key::Escape));
    assert_eq!(harness.state().keys, [Key::Escape]);
    assert_eq!(harness.state().codes, [Some(KeyCode::new(53))]);
}

#[test]
fn keys_reach_only_what_holds_the_keyboard() {
    let mut harness = Harness::new(App::default(), |_: &App| {
        col((
            button("First").on_click(|_: &mut App| {}).on_key(|app: &mut App, key, _| {
                app.keys.push(key)
            }),
            button("Second").on_click(|_: &mut App| {}).on_key(|app: &mut App, _, _| {
                app.count += 1
            }),
        ))
    });

    harness.click_text("First");
    harness.key(Key::Home);
    assert_eq!(harness.state().keys, [Key::Home]);
    assert_eq!(harness.state().count, 0, "the unfocused control heard nothing");
}

#[test]
fn the_keyboard_can_reach_and_activate_a_control_with_no_pointer_at_all() {
    let mut harness = Harness::new(App::default(), |_: &App| {
        col((
            button("First").on_click(|app: &mut App| app.count += 1),
            button("Second").on_click(|app: &mut App| app.count += 10),
        ))
    });

    harness.tab();
    harness.key(Key::Enter);
    assert_eq!(harness.state().count, 1, "tab reaches the first control and Enter presses it");

    harness.tab();
    harness.key(Key::Space);
    assert_eq!(harness.state().count, 11, "and tab moves on to the second");

    harness.tab();
    harness.key(Key::Space);
    assert_eq!(harness.state().count, 12, "and wraps back to the first");
}

#[test]
fn the_wheel_reaches_a_control_that_asked_for_it() {
    let mut harness = Harness::new(App::default(), |_: &App| {
        col(text("Zoom").h(40.0).on_scroll(|app: &mut App, _, down| app.wheel += down))
    });

    harness.hover_text("Zoom");
    harness.scroll(3.0);
    assert_eq!(harness.state().wheel, 3.0);

    harness.scroll(-1.0);
    assert_eq!(harness.state().wheel, 2.0);
}

#[test]
fn the_wheel_goes_to_the_innermost_list_rather_than_the_page_around_it() {
    let mut harness = Harness::new(App::default(), |_: &App| {
        col(col((0..40).map(|index| text(format!("row {index}")).h(20.0)).collect::<Vec<_>>())
            .key("inner")
            .h(100.0)
            .scroll())
        .key("outer")
        .scroll()
    });

    let inner = harness.find_key("inner").expect("the list is on screen");
    harness.move_pointer(inner.rect.center()).scroll(-30.0);

    assert_eq!(harness.scroll_offset(inner.id), 30.0, "the list under the pointer scrolled");
    let outer = harness.find_key("outer").expect("the page is on screen");
    assert_eq!(harness.scroll_offset(outer.id), 0.0, "and the page around it did not");
}

#[test]
fn typing_into_a_field_reports_the_text_it_now_holds() {
    let mut harness = Harness::new(App::default(), |app: &App| {
        col(field(app.typed.clone())
            .key("name")
            .placeholder("a name")
            .on_input(|app: &mut App, text: String| app.typed = text))
    });

    let at = harness.find_key("name").expect("the field is on screen").rect.center();
    harness.click(at);
    harness.type_text("mongod");
    assert_eq!(harness.state().typed, "mongod");

    harness.key(Key::Backspace);
    assert_eq!(harness.state().typed, "mongo", "the caret is where the typing left it");
}

#[test]
fn an_unfocused_field_takes_no_typing() {
    let mut harness = Harness::new(App::default(), |app: &App| {
        col(field(app.typed.clone()).on_input(|app: &mut App, text: String| app.typed = text))
    });

    harness.type_text("stray");
    assert_eq!(harness.state().typed, "", "typing goes where the keyboard is, and nowhere else");
}

#[test]
fn a_layer_is_drawn_over_what_it_was_opened_from_and_answers_the_pointer_first() {
    // A menu: a layer hanging under the button that opened it, over a row that
    // is itself clickable. What is on top is what gets clicked.
    let mut harness = Harness::new(App::default(), |app: &App| {
        col((
            button("Sort").on_click(|app: &mut App| app.menu_open = true).add(
                app.menu_open.then(|| {
                    panel(col((
                        text("By name")
                            .h(24.0)
                            .on_click(|app: &mut App| app.chosen = Some("By name".into())),
                        text("By size")
                            .h(24.0)
                            .on_click(|app: &mut App| app.chosen = Some("By size".into())),
                    )))
                    .w(160.0)
                    .layer(Anchor::Below)
                }),
            ),
            text("Underneath").h(60.0).on_click(|app: &mut App| app.count += 100),
        ))
    });

    assert!(!harness.shows("By name"), "a menu that is not open is not drawn");

    harness.click_text("Sort");
    harness.frame();
    assert!(harness.shows("By name"), "opening it draws it");

    let menu = harness.find("By name").expect("the menu is open");
    let under = harness.find("Underneath").expect("the row is there");
    assert!(
        menu.rect.y >= harness.rect_of("Sort").expect("the button").max_y() - 0.5,
        "the menu hangs below the button it belongs to"
    );
    assert!(menu.rect.intersect(under.rect).w > 0.0, "and it genuinely covers the row");

    harness.click_text("By name");
    assert_eq!(harness.state().chosen.as_deref(), Some("By name"));
    assert_eq!(harness.state().count, 0, "the row underneath was covered, so it heard nothing");
}

#[test]
fn a_row_scrolled_out_of_its_list_cannot_be_clicked() {
    // A heading above the list, so that a row scrolled off the top of the list
    // ends up somewhere still inside the *window* — which is the case that
    // actually distinguishes "clipped away" from "off the screen".
    let mut harness = Harness::new(App::default(), |_: &App| {
        col((
            text("SERVICES").h(40.0),
            col((0..40)
                .map(|index| {
                    text(format!("row {index}"))
                        .h(20.0)
                        .on_click(move |app: &mut App| app.count = index + 1)
                })
                .collect::<Vec<_>>())
            .key("list")
            .h(100.0)
            .scroll(),
        ))
    });

    let list = harness.find_key("list").expect("the list is on screen");
    harness.move_pointer(list.rect.center()).scroll(-30.0);
    harness.frame();

    let first = harness.rect_of("row 0").expect("the first row still has a position");
    assert!(first.max_y() <= list.rect.y, "it has been scrolled up out of its list");
    assert!(first.y > 0.0, "and up into the heading, which is still inside the window");

    harness.click(first.center());
    assert_eq!(harness.state().count, 0, "a row that scrolled away must not stay clickable");
}

#[test]
fn what_a_view_offers_can_be_asserted_without_drawing_anything_at_all() {
    // The other half of the story: a description is an ordinary value, so what
    // an interface offers and what it does are assertable from the tree, with
    // no harness, no frame, and no pixels.
    fn actions(running: bool) -> El<App> {
        row((
            button("Start").on_click(|app: &mut App| app.count += 1).disabled(running),
            button("Stop").on_click(|app: &mut App| app.count -= 1).disabled(!running),
        ))
    }

    let stopped = actions(false);
    assert!(!stopped.child(0).expect("Start").is_disabled(), "Start is offered when it is stopped");
    assert!(stopped.child(1).expect("Stop").is_disabled());

    let mut app = App::default();
    (stopped.child(0).expect("Start").click_action().expect("a handler"))(&mut app);
    assert_eq!(app.count, 1);
}
