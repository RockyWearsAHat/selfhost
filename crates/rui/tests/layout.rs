//! Where things come out.
//!
//! These assert exact numbers, which they can only do because the face the
//! harness draws with is built rather than borrowed: every character is half
//! the text size wide and a line is exactly one em, so a width in these tests
//! is arithmetic and not a measurement pasted back from a run.

use rui::testing::Harness;
use rui::{Align, Anchor, Justify, Length, El, col, panel, row, spacer, text};

/// Nothing to hold: these are about rectangles, not behaviour.
#[derive(Default)]
struct Nothing;

/// The text size these use throughout, at which one character is five units.
const SIZE: f32 = 10.0;

/// A harness the given size, showing `view`.
fn showing(
    width: f32,
    height: f32,
    view: impl Fn(&Nothing) -> El<Nothing> + 'static,
) -> Harness<Nothing> {
    Harness::new(Nothing, view).size(width, height)
}

#[test]
fn a_run_of_text_is_as_wide_as_its_characters() {
    let mut harness = showing(400.0, 200.0, |_| {
        col(text("abcd").text_size(SIZE)).align(Align::Start)
    });
    let rect = harness.rect_of("abcd").expect("the run is on screen");
    assert_eq!(rect.w, 20.0, "four characters at five units each");
    assert_eq!(rect.h, SIZE, "one line is one em");
}

#[test]
fn text_at_a_larger_size_is_larger_in_both_directions() {
    let mut harness = showing(400.0, 200.0, |_| {
        col((text("ab").text_size(SIZE).key("small"), text("ab").text_size(SIZE * 2.0).key("big")))
            .align(Align::Start)
    });
    let small = harness.find_key("small").expect("the small run").rect;
    let big = harness.find_key("big").expect("the large run").rect;
    assert_eq!(big.w, small.w * 2.0);
    assert_eq!(big.h, small.h * 2.0);
}

#[test]
fn a_size_set_on_a_container_reaches_the_text_inside_it() {
    let mut harness = showing(400.0, 200.0, |_| {
        col(col(text("abcd")).align(Align::Start)).text_size(SIZE * 2.0).align(Align::Start)
    });
    assert_eq!(
        harness.rect_of("abcd").expect("the run is on screen").w,
        40.0,
        "the run should be set at the size its container asked for"
    );
}

#[test]
fn a_paragraph_wraps_to_the_width_it_was_given() {
    // Twelve characters at five units each is sixty; a hundred units of width
    // fits twenty characters, so this falls onto three lines.
    // Nested one level: the root is always the size of the window, so a width
    // is only a width when something above it hands the room out.
    let mut harness = showing(400.0, 200.0, |_| {
        col(col(text("aaaa bbbb cccc dddd eeee ffff gggg").wrap().text_size(SIZE)).w(100.0))
            .align(Align::Start)
    });
    let rect = harness.rect_of("aaaa bbbb cccc dddd eeee ffff gggg").expect("the paragraph");
    assert!(rect.w <= 100.0, "it must not overrun the width it was given");
    assert_eq!(rect.h, SIZE * 2.0, "thirty-four characters wrap onto two lines of twenty");
}

#[test]
fn a_run_too_long_for_its_box_is_cut_short_rather_than_overrunning_it() {
    let mut harness = showing(400.0, 200.0, |_| {
        col(col(text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").text_size(SIZE)).w(50.0).align(Align::Start))
            .align(Align::Start)
    });
    let rect = harness.rect_of("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").expect("the run");
    assert!(rect.w <= 50.0, "a label must never be laid out wider than the box it was fitted to");
}

#[test]
fn the_room_left_over_is_divided_between_the_things_that_asked_for_it() {
    let mut harness = showing(240.0, 100.0, |_| {
        row((
            spacer().w(40.0).key("fixed"),
            spacer().grow().key("one"),
            spacer().grow_by(3.0).key("three"),
        ))
    });
    assert_eq!(harness.find_key("one").expect("one").rect.w, 50.0);
    assert_eq!(harness.find_key("three").expect("three").rect.w, 150.0);
    assert_eq!(harness.find_key("three").expect("three").rect.max_x(), 240.0);
}

#[test]
fn a_fraction_is_a_share_of_what_the_parent_offered() {
    let mut harness = showing(400.0, 100.0, |_| {
        row(spacer().w(Length::Fraction(0.25)).key("quarter"))
    });
    assert_eq!(harness.find_key("quarter").expect("the quarter").rect.w, 100.0);
}

#[test]
fn room_that_runs_short_is_taken_off_what_was_sized_to_its_content() {
    // A control that asked for a height in units asked for it because that is
    // how tall it has to be; what gives way is the thing that was going to be
    // scrolled or wrapped anyway.
    let mut harness = showing(200.0, 100.0, |_| {
        col((
            text("a").text_size(SIZE).h(200.0).key("stated"),
            col(text("b")).key("content"),
        ))
    });
    assert_eq!(
        harness.find_key("stated").expect("the stated height").rect.h,
        200.0,
        "a stated height is not what gives way"
    );
}

#[test]
fn a_flow_runs_onto_further_lines_when_its_children_do_not_fit() {
    // Six boxes of forty units on a row a hundred wide: two to a line, three
    // lines, and the container as tall as they came to.
    let mut harness = showing(100.0, 200.0, |_| {
        col(row((0..6)
            .map(|index| spacer().size(40.0, 10.0).key(format!("box {index}")))
            .collect::<Vec<_>>())
        .flow()
        .key("bar"))
    });

    let first = harness.find_key("box 0").expect("the first box").rect;
    let second = harness.find_key("box 1").expect("the second box").rect;
    let third = harness.find_key("box 2").expect("the third box").rect;

    assert_eq!(first.y, second.y, "two fit on the first line");
    assert!(third.y > first.y, "and the third runs onto the next");
    assert_eq!(third.x, first.x, "which starts back at the left");
    assert_eq!(harness.find_key("bar").expect("the flow").rect.h, 30.0, "three lines of ten");
}

#[test]
fn a_flow_that_fits_on_one_line_is_one_line() {
    let mut harness = showing(400.0, 200.0, |_| {
        col(row((0..3)
            .map(|index| spacer().size(40.0, 10.0).key(format!("box {index}")))
            .collect::<Vec<_>>())
        .flow()
        .gap(8.0)
        .key("bar"))
    });
    assert_eq!(harness.find_key("bar").expect("the flow").rect.h, 10.0);
    assert_eq!(
        harness.find_key("box 1").expect("the second box").rect.x,
        48.0,
        "the gap falls between them"
    );
}

#[test]
fn a_flow_makes_every_line_as_tall_as_the_tallest_thing_on_it() {
    let mut harness = showing(100.0, 200.0, |_| {
        col(row((
            spacer().size(40.0, 10.0).key("short"),
            spacer().size(40.0, 30.0).key("tall"),
            spacer().size(40.0, 10.0).key("next line"),
        ))
        .flow()
        .key("bar"))
    });
    assert_eq!(harness.find_key("tall").expect("the tall one").rect.h, 30.0);
    assert_eq!(
        harness.find_key("next line").expect("the third").rect.y,
        30.0,
        "the second line starts below the tallest thing on the first"
    );
}

#[test]
fn a_layer_hangs_off_its_anchor_and_takes_no_room_from_it() {
    let mut harness = showing(400.0, 300.0, |_| {
        col((
            col(text("Sort").h(24.0)).key("button").add(
                panel(text("By name")).w(120.0).h(60.0).key("menu").layer(Anchor::Below),
            ),
            spacer().h(20.0).key("after"),
        ))
    });

    let button = harness.find_key("button").expect("the button").rect;
    let menu = harness.find_key("menu").expect("the menu").rect;
    let after = harness.find_key("after").expect("what follows").rect;

    assert_eq!(menu.y, button.max_y(), "it hangs off the bottom edge");
    assert_eq!(menu.x, button.x, "with their left edges in line");
    assert_eq!(menu.w, 120.0, "and it is the width it asked for, not its anchor's");
    assert_eq!(after.y, button.max_y(), "the layer took no room, so nothing moved for it");
}

#[test]
fn a_layer_is_held_inside_the_window_rather_than_opening_off_the_edge() {
    let mut harness = showing(200.0, 200.0, |_| {
        row((
            spacer().grow(),
            col(text("Sort").h(20.0))
                .w(40.0)
                .key("button")
                .add(panel(text("By name")).w(120.0).h(60.0).key("menu").layer(Anchor::Below)),
        ))
    });

    let menu = harness.find_key("menu").expect("the menu").rect;
    assert!(menu.max_x() <= 200.0, "a menu near the right edge must not open past it");
    assert_eq!(menu.max_x(), 200.0, "it is pushed back exactly as far as it had to be");
}

#[test]
fn a_layer_anchored_over_its_parent_covers_it_exactly() {
    let mut harness = showing(300.0, 200.0, |_| {
        col(col(text("Contents")).h(80.0).key("pane").add(
            col(text("Loading")).key("veil").layer(Anchor::Over),
        ))
    });
    let pane = harness.find_key("pane").expect("the pane").rect;
    assert_eq!(harness.find_key("veil").expect("the veil").rect, pane);
}

#[test]
fn a_dialog_is_centred_on_the_window_and_not_on_whatever_opened_it() {
    let mut harness = showing(400.0, 300.0, |_| {
        col(col(text("Delete")).h(20.0).key("button").add(
            panel(text("Are you sure")).size(200.0, 100.0).key("dialog").layer(Anchor::Center),
        ))
    });
    let dialog = harness.find_key("dialog").expect("the dialog").rect;
    assert_eq!(dialog.x, 100.0);
    assert_eq!(dialog.y, 100.0);
}

#[test]
fn padding_is_taken_off_before_anything_is_placed_inside() {
    let mut harness = showing(100.0, 100.0, |_| col(spacer().grow().key("inside")).pad(12.0));
    let inside = harness.find_key("inside").expect("what is inside").rect;
    assert_eq!(inside, rui::Rect::new(12.0, 12.0, 76.0, 76.0));
}

#[test]
fn spare_room_is_spread_between_children_rather_than_around_them() {
    let mut harness = showing(120.0, 40.0, |_| {
        row((
            spacer().w(20.0).key("first"),
            spacer().w(20.0).key("second"),
            spacer().w(20.0).key("third"),
        ))
        .justify(Justify::Between)
    });
    assert_eq!(harness.find_key("first").expect("first").rect.x, 0.0);
    assert_eq!(harness.find_key("second").expect("second").rect.x, 50.0);
    assert_eq!(harness.find_key("third").expect("third").rect.max_x(), 120.0);
}

#[test]
fn identity_follows_a_key_rather_than_a_position() {
    let mut ordered = showing(200.0, 200.0, |_| {
        col((text("alpha").key("a"), text("beta").key("b")))
    });
    let mut swapped = showing(200.0, 200.0, |_| {
        col((text("beta").key("b"), text("alpha").key("a")))
    });

    assert_eq!(
        ordered.find_key("a").expect("alpha").id,
        swapped.find_key("a").expect("alpha").id,
        "a keyed row keeps its identity when its siblings move"
    );
}

#[test]
fn a_layout_holds_up_at_a_higher_pixel_density() {
    // Logical units are what a layout is written in; the scale only reaches the
    // canvas. A rectangle must therefore be the same at any density.
    let plain = showing(200.0, 100.0, |_| col(text("abcd").text_size(SIZE)).align(Align::Start))
        .rect_of("abcd")
        .expect("the run");
    let dense = showing(200.0, 100.0, |_| col(text("abcd").text_size(SIZE)).align(Align::Start))
        .scale(2.0)
        .rect_of("abcd")
        .expect("the run");
    assert_eq!(plain, dense);
}

#[test]
fn a_whole_element_stands_entire_or_is_not_laid_out_at_all() {
    // Room for everything: the whole word stands at its measured width.
    let mut roomy = showing(200.0, 40.0, |_| {
        row((
            text("name").text_size(SIZE).grow_from_content().key("name"),
            text("STATE").text_size(SIZE).whole().key("state"),
        ))
    });
    assert_eq!(roomy.rect_of("STATE").expect("the word stands").w, 25.0, "whole, at five units a character");

    // Room short by any amount: the word yields everything rather than an
    // ellipsis, and the room it held goes to the grower beside it.
    let mut short = showing(60.0, 40.0, |_| {
        row((
            text("a-much-longer-name").text_size(SIZE).grow_from_content().key("name"),
            text("STATE").text_size(SIZE).whole().key("state"),
        ))
    });
    let state = short.find_key("state").expect("the element still exists").rect;
    assert_eq!(state.w, 0.0, "never squeezed, only surrendered");
    let name = short.find_key("name").expect("the name").rect;
    assert_eq!(name.w, 60.0, "the surrendered room reaches the name");
}
