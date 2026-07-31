//! What actually reaches the pixels.
//!
//! The other suites assert about rectangles and state, which a renderer could
//! satisfy while drawing nothing at all. These assert on the buffer: that marks
//! are made where they were meant to be, that the same description twice is the
//! same picture, and that an animation both moves and then stops.

use rui::testing::{Harness, test_fonts};
use rui::{
    Align, App, Appearance, Color, CornerStyle, El, FontId, Radius, Rect, Size, Theme, Tone, button,
    col, draw, row, spacer, text,
};

/// Nothing to hold: these are about pixels.
#[derive(Default)]
struct Nothing;

/// A state a hover test can watch.
#[derive(Default)]
struct Watched {
    clicks: u32,
}

/// A harness showing `view`, at a size these tests can reason about.
fn showing(view: impl Fn(&Nothing) -> El<Nothing> + 'static) -> Harness<Nothing> {
    Harness::new(Nothing, view).size(200.0, 100.0)
}

#[test]
fn a_window_is_drawn_in_the_ground_of_whichever_appearance_is_in_force() {
    let mut dark = showing(|_| col(())).appearance(Appearance::Dark);
    let mut light = showing(|_| col(())).appearance(Appearance::Light);
    dark.frame();
    light.frame();

    let dark_ground = dark.pixel(100, 50).expect("inside the window");
    let light_ground = light.pixel(100, 50).expect("inside the window");
    assert_ne!(dark_ground, light_ground, "one description, two appearances");
    assert!(light_ground.luminance() > dark_ground.luminance(), "and the light one is lighter");
}

#[test]
fn text_makes_marks_where_the_layout_put_it() {
    let mut harness = showing(|_| col(text("abc").text_size(20.0)).align(Align::Start));
    harness.frame();

    let rect = harness.rect_of("abc").expect("the run is on screen");
    assert!(harness.marked(rect), "the run should have drawn something");
    assert!(
        !harness.marked(rui::Rect::new(rect.max_x() + 20.0, rect.y, 40.0, rect.h)),
        "and nothing beyond its own end"
    );
}

#[test]
fn an_empty_window_is_marked_nowhere() {
    let mut harness = showing(|_| col(()));
    harness.frame();
    assert!(!harness.marked(rui::Rect::new(0.0, 0.0, 200.0, 100.0)));
}

#[test]
fn an_application_may_paint_the_ground_its_interface_sits_on() {
    // The seam: the application's ground replaces the library's clear, through
    // the same frame a window draws — see [`App::ground`].
    let claret = Color::rgb(0x20, 0x08, 0x08);
    let app = App::new("grounded", Nothing, |_: &Nothing| col(()))
        .ground(move |canvas, _| canvas.clear(claret));
    let mut harness = Harness::with_app(app).size(200.0, 100.0);
    harness.frame();

    assert_eq!(harness.pixel(100, 50), Some(claret), "the ground is the application's");
    // What `marked` calls "nothing was drawn here" comes from the same ground,
    // so an empty window over a custom ground still counts as empty.
    assert!(!harness.marked(rui::Rect::new(0.0, 0.0, 200.0, 100.0)));
}

#[test]
fn the_same_description_twice_is_the_same_picture() {
    // What the loop relies on to decide it has nothing to present: a frame that
    // came out identical is one the screen already shows. A renderer with any
    // state carried between frames would fail this.
    let mut harness = showing(|_| {
        col((text("Services").text_size(14.0), button("Restart"), spacer().h(10.0))).pad(8.0)
    });
    harness.frame();
    let first: Vec<u32> = harness.canvas().pixels().to_vec();

    harness.frame();
    assert_eq!(first, harness.canvas().pixels(), "an unchanged interface must redraw identically");
}

#[test]
fn two_different_words_are_two_different_pictures() {
    let mut one = showing(|_| col(text("aaaa").text_size(20.0)).align(Align::Start));
    let mut other = showing(|_| col(text("bbbb").text_size(20.0)).align(Align::Start));
    one.frame();
    other.frame();
    assert_ne!(one.canvas().pixels(), other.canvas().pixels());
}

#[test]
fn a_hover_eases_in_over_several_frames_and_then_settles() {
    let mut harness = Harness::new(Watched::default(), |_: &Watched| {
        col(button("Restart").on_click(|watched: &mut Watched| watched.clicks += 1))
    })
    .size(200.0, 100.0);

    harness.frame();
    assert!(!harness.is_animating(), "an interface nobody is touching must not keep drawing");
    let at_rest: Vec<u32> = harness.canvas().pixels().to_vec();

    harness.hover_text("Restart");
    assert!(harness.is_animating(), "the pointer arriving starts the hover moving");
    let part_way: Vec<u32> = harness.canvas().pixels().to_vec();
    assert_ne!(at_rest, part_way, "and it is visibly under way");

    // Time is given, not read, so an animation is stepped rather than waited
    // for. A second is far past any hover the theme allows itself.
    harness.frames(60);
    assert!(!harness.is_animating(), "an animation that never settles never stops drawing");
    let settled: Vec<u32> = harness.canvas().pixels().to_vec();
    assert_ne!(part_way, settled, "it got further than where it was part way");

    harness.frame();
    assert_eq!(settled, harness.canvas().pixels(), "and having settled, it stays");
}

#[test]
fn a_disabled_control_is_drawn_differently_from_an_available_one() {
    let mut available = showing(|_| col(button("Start").on_click(|_: &mut Nothing| {})));
    let mut unavailable =
        showing(|_| col(button("Start").on_click(|_: &mut Nothing| {}).disabled(true)));
    available.frame();
    unavailable.frame();
    assert_ne!(
        available.canvas().pixels(),
        unavailable.canvas().pixels(),
        "a control nobody can use has to look like one"
    );
}

#[test]
fn an_applications_own_drawing_sees_what_a_button_sees() {
    // The whole point of the escape hatch: a control the library has never
    // heard of reacts exactly as one it ships does, because it is handed the
    // same answer about the pointer.
    let mut harness = Harness::new(Watched::default(), |_: &Watched| {
        col(draw(Size::new(60.0, 30.0), |painter, rect| {
            let tone = if painter.visual().hovered { Tone::Ok } else { Tone::Bad };
            painter.fill(rect, Radius::None, tone);
        })
        .key("custom")
        .on_click(|watched: &mut Watched| watched.clicks += 1))
    })
    .size(200.0, 100.0);

    harness.frame();
    let rect = harness.find_key("custom").expect("the control is on screen").rect;
    let at_rest = harness.pixel(rect.center().x as u32, rect.center().y as u32).expect("a pixel");

    harness.move_pointer(rect.center());
    let hovered = harness.pixel(rect.center().x as u32, rect.center().y as u32).expect("a pixel");
    assert_ne!(at_rest, hovered, "custom drawing must be able to answer the pointer");
}

#[test]
fn a_higher_pixel_density_draws_more_pixels_of_the_same_picture() {
    let mut plain = showing(|_| col(text("abc").text_size(20.0)));
    let mut dense = showing(|_| col(text("abc").text_size(20.0))).scale(2.0);
    plain.frame();
    dense.frame();

    assert_eq!(plain.canvas().width(), 200);
    assert_eq!(dense.canvas().width(), 400, "twice the density is twice the pixels across");
    assert_eq!(dense.canvas().pixels().len(), plain.canvas().pixels().len() * 4);
}

#[test]
fn a_layer_is_drawn_over_what_it_covers() {
    let mut harness = showing(|_| {
        col(row(text("underneath")).h(40.0).fill(Tone::Bad).key("under").add(
            col(()).size(200.0, 40.0).fill(Tone::Ok).key("over").layer(rui::Anchor::Over),
        ))
    });
    harness.frame();

    let under = harness.find_key("under").expect("the pane").rect;
    let drawn = harness.pixel(under.center().x as u32, under.center().y as u32).expect("a pixel");
    let mut alone = showing(|_| col(row(()).h(40.0).fill(Tone::Ok)));
    alone.frame();
    let expected = alone.pixel(under.center().x as u32, under.center().y as u32).expect("a pixel");

    assert_eq!(drawn, expected, "the layer, not what it covers, is what is on top");
}

// ----- what the application supplies --------------------------------------

/// A panel filling most of a small window, so its corners are easy to find.
fn plate(radius: Radius) -> El<Nothing> {
    col(col(()).grow().fill(Tone::Surface).round(radius)).pad(10.0)
}

/// How many device pixels of `rect` were marked over the window's own ground.
///
/// A count rather than [`Harness::marked`]'s yes-or-no, because the question a
/// corner asks is *how much* of it was cut away.
fn covered(harness: &Harness<Nothing>, rect: Rect) -> usize {
    let mut marked = 0;
    for y in rect.y as u32..rect.max_y() as u32 {
        for x in rect.x as u32..rect.max_x() as u32 {
            if harness.marked(Rect::new(x as f32, y as f32, 1.0, 1.0)) {
                marked += 1;
            }
        }
    }
    marked
}

#[test]
fn an_application_that_supplies_no_theme_is_drawn_with_the_librarys_own() {
    // The promise the default rests on: `App::theme` is a way in, not a change.
    // Supplying `Theme::new` and supplying nothing must be the same picture.
    let mut silent = showing(|_| plate(Radius::Panel));
    let mut explicit = showing(|_| plate(Radius::Panel)).theme(Theme::new);
    silent.frame();
    explicit.frame();
    assert_eq!(
        silent.canvas().pixels(),
        explicit.canvas().pixels(),
        "the default theme is no longer what an application gets for free"
    );
}

#[test]
fn a_supplied_corner_shape_reaches_a_panel_nobody_told_about_it() {
    // One word in the theme, and every framed thing in the interface follows —
    // which is the whole reason the shape lives there rather than on a widget.
    let mut round = showing(|_| plate(Radius::Panel));
    let mut cut = showing(|_| plate(Radius::Panel))
        .theme(|appearance, ui, mono| {
            Theme::new(appearance, ui, mono).with_corners(CornerStyle::Cut)
        });
    round.frame();
    cut.frame();

    // A chamfer takes away more of a corner than a quarter-circle of the same
    // size does, so the panel covers strictly less of the square its corner
    // sits in. Anything else — the same count, or more — means the shape never
    // reached the panel.
    let corner = Rect::new(10.0, 10.0, 8.0, 8.0);
    let (rounded, chamfered) = (covered(&round, corner), covered(&cut, corner));
    assert!(chamfered > 0, "the panel was not drawn at all");
    assert!(
        chamfered < rounded,
        "a cut corner should give up more of its square than a rounded one: {chamfered} against {rounded}"
    );
}

#[test]
fn one_element_can_be_cut_while_the_interface_around_it_is_not() {
    // The other half: an application that means the chamfer for one plate and
    // not for the program says so on that element, and nothing else moves.
    let mut rounded = showing(|_| plate(Radius::Panel));
    let mut chamfered = showing(|_| plate(Radius::Cut(8.0)));
    rounded.frame();
    chamfered.frame();

    let corner = Rect::new(10.0, 10.0, 8.0, 8.0);
    assert!(covered(&chamfered, corner) < covered(&rounded, corner));
    let middle = Rect::new(60.0, 40.0, 40.0, 20.0);
    assert_eq!(
        covered(&chamfered, middle),
        covered(&rounded, middle),
        "a corner treatment must not change anything but the corners"
    );
}

#[test]
fn a_rendered_frame_and_a_driven_one_are_the_same_frame() {
    // Why `Harness` drives the real frame, stated as an assertion: a screenshot
    // and a test must not be able to disagree about what the interface looks
    // like, and a theme the application supplied reaches both or neither.
    let theme = |appearance: Appearance, ui: FontId, mono: FontId| {
        Theme::new(appearance, ui, mono).with_corners(CornerStyle::Cut)
    };
    let view = |_: &Nothing| plate(Radius::Panel);

    let mut harness =
        Harness::new(Nothing, view).size(200.0, 100.0).appearance(Appearance::Light).theme(theme);
    harness.frame();

    let mut app = App::new("rendered", Nothing, view).theme(theme);
    let rendered = app.render(200, 100, 1.0, Appearance::Light, &mut test_fonts());

    assert_eq!(
        harness.canvas().pixels(),
        rendered.pixels(),
        "the drawn frame and the rendered one came out different"
    );
}

// ----- an application's own easing ----------------------------------------

/// Where the gauge below is heading.
#[derive(Default)]
struct Gauge {
    target: f32,
}

/// A gauge that reports where its easing got to, as a grey.
///
/// The eased value *is* the pixel, so a test reads the animation off the buffer
/// exactly rather than inferring it from something moving.
fn gauge(state: &Gauge) -> El<Gauge> {
    let target = state.target;
    col(draw(Size::new(60.0, 30.0), move |painter, rect| {
        let eased = painter.ease("sweep", target, 0.1);
        let level = (eased * 255.0).round() as u8;
        painter.fill(rect, Radius::None, Color::rgb(level, level, level));
    })
    .key("gauge")
    .on_click(|gauge: &mut Gauge| gauge.target = 1.0)
    .label("Gauge"))
}

/// What the gauge above is reading, from zero to two hundred and fifty-five.
fn reading(harness: &mut Harness<Gauge>) -> u8 {
    let rect = harness.find_key("gauge").expect("the gauge is on screen").rect;
    harness.pixel(rect.center().x as u32, rect.center().y as u32).expect("a pixel").r
}

#[test]
fn an_applications_own_easing_moves_over_frames_and_then_settles() {
    let mut harness = Harness::new(Gauge::default(), gauge).size(200.0, 100.0);
    harness.frame();
    assert_eq!(reading(&mut harness), 0, "a value first seen starts at its target, not at zero");
    assert!(!harness.is_animating(), "and nothing is moving yet");

    // The click sets the target; the frame that delivered it drew the old one.
    harness.activate_named("Gauge");
    harness.frame();
    let part_way = reading(&mut harness);
    assert!(part_way > 0 && part_way < 255, "expected a step along the way, got {part_way}");
    assert!(harness.is_animating(), "a value short of its target must keep the loop awake");

    // A second of it, stepped rather than waited for: nothing reads a clock.
    harness.frames(60);
    assert_eq!(reading(&mut harness), 255, "a second is far past a tenth-of-a-second constant");
    assert!(!harness.is_animating(), "an animation that never settles never stops drawing");
}

#[test]
fn the_same_frames_ease_the_same_distance_every_time() {
    // Determinism, which is what makes the whole thing assertable: two runs of
    // the same steps have to arrive at the same pixel.
    let travel = || {
        let mut harness = Harness::new(Gauge::default(), gauge).size(200.0, 100.0);
        harness.activate_named("Gauge");
        harness.frames(5);
        reading(&mut harness)
    };
    assert_eq!(travel(), travel());
}

/// Two eased values in one drawing, and a hover the library eases beside them.
#[derive(Default)]
struct Pair {
    started: bool,
}

#[test]
fn two_eased_values_in_one_drawing_do_not_share_a_number() {
    // The failure this rules out: one stored value serving two animations, so
    // the second reads the first's number and the pair drift together.
    let mut harness = Harness::new(Pair::default(), |pair: &Pair| {
        let started = pair.started;
        col(draw(Size::new(60.0, 30.0), move |painter, rect| {
            let up = painter.ease("up", if started { 1.0 } else { 0.0 }, 0.1);
            let down = painter.ease("down", 0.0, 0.1);
            let half = Rect::new(rect.x, rect.y, rect.w / 2.0, rect.h);
            painter.fill(half, Radius::None, grey(up));
            painter.fill(
                Rect::new(half.max_x(), rect.y, rect.w / 2.0, rect.h),
                Radius::None,
                grey(down),
            );
        })
        .key("pair")
        .on_click(|pair: &mut Pair| pair.started = true)
        .label("Pair"))
    })
    .size(200.0, 100.0);

    harness.activate_named("Pair");
    harness.frames(60);

    let rect = harness.find_key("pair").expect("on screen").rect;
    let left = harness.pixel((rect.x + 5.0) as u32, rect.center().y as u32).expect("a pixel").r;
    let right = harness.pixel((rect.max_x() - 5.0) as u32, rect.center().y as u32).expect("a pixel").r;
    assert_eq!(left, 255, "the value that was sent up should have arrived");
    assert_eq!(right, 0, "and the one that was left alone should not have moved with it");
}

#[test]
fn an_easing_an_application_names_hover_is_not_the_hover_the_library_eases() {
    // Both are kept under the same element's identity, so the names have to be
    // held apart — or a drawing that happens to call its value `hover` fights
    // the pointer for one number and neither ever settles.
    let mut harness = Harness::new(Nothing, |_: &Nothing| {
        col(draw(Size::new(60.0, 30.0), |painter, rect| {
            let mine = painter.ease("hover", 1.0, 0.1);
            painter.fill(rect, Radius::None, grey(mine));
        })
        .key("named")
        .reactive()
        .label("Named"))
    })
    .size(200.0, 100.0);

    harness.frames(60);
    let rect = harness.find_key("named").expect("on screen").rect;
    let drawn = harness.pixel(rect.center().x as u32, rect.center().y as u32).expect("a pixel").r;
    assert_eq!(drawn, 255, "the drawing's own value was pulled about by the pointer's");
    assert!(!harness.is_animating(), "two values sharing one number never settle");
}

/// The grey a value from zero to one comes to.
fn grey(value: f32) -> Color {
    let level = (value.clamp(0.0, 1.0) * 255.0).round() as u8;
    Color::rgb(level, level, level)
}

// ----- the light an element casts ------------------------------------------

/// A plate of a known size, with `decorate` applied to it.
fn lit(decorate: fn(El<Nothing>) -> El<Nothing>) -> El<Nothing> {
    col(decorate(col(()).size(60.0, 30.0).fill(Tone::Surface).key("plate")))
        .pad(20.0)
        .align(Align::Start)
}

#[test]
fn a_glow_carries_a_hue_where_a_shadow_stays_the_absence_of_light() {
    // The two are deliberately different things. A shadow says a panel is lying
    // on the window; a glow says the thing is live — so one is the theme's own
    // black and the other is whatever colour it was asked for.
    let mut plain = showing(|_| lit(|el| el));
    let mut glowing = showing(|_| lit(|el| el.glow(8.0, Color::rgb(255, 40, 40))));
    let mut shadowed = showing(|_| lit(|el| el.shadow(8.0)));
    plain.frame();
    glowing.frame();
    shadowed.frame();

    let plate = plain.find_key("plate").expect("the plate is on screen").rect;
    let (x, y) = ((plate.x - 3.0) as u32, plate.center().y as u32);
    let ground = plain.pixel(x, y).expect("a pixel");
    let halo = glowing.pixel(x, y).expect("a pixel");
    let shade = shadowed.pixel(x, y).expect("a pixel");

    let hue = |color: Color| color.r as i32 - color.b as i32;
    assert_ne!(halo, ground, "the halo never reached outside the element");
    assert!(hue(halo) > hue(ground), "a glow should carry the colour it was given");
    assert!((hue(shade) - hue(ground)).abs() <= 1, "a shadow must never take a hue");
    assert!(shade.luminance() < ground.luminance(), "and it darkens what it falls on");
}

#[test]
fn a_glow_is_cast_evenly_where_a_shadow_falls_downward() {
    // What says a panel is *lying* on the window is that the light comes from
    // above. A halo has no light to come from anywhere: it is the light.
    let mut glowing = showing(|_| lit(|el| el.glow(8.0, Color::rgb(255, 40, 40))));
    let mut shadowed = showing(|_| lit(|el| el.shadow(8.0)));
    glowing.frame();
    shadowed.frame();

    let plate = glowing.find_key("plate").expect("on screen").rect;
    let x = plate.center().x as u32;
    let read = |harness: &Harness<Nothing>, y: f32| {
        harness.pixel(x, y as u32).expect("a pixel").luminance()
    };
    let ground = read(&glowing, plate.y - 12.0);

    assert!(read(&glowing, plate.y - 3.0) > ground, "a halo reaches above what casts it");
    assert!(
        read(&shadowed, plate.y - 3.0) >= read(&shadowed, plate.max_y() + 3.0),
        "a shadow should be deeper below the panel than above it"
    );
}

// ----- an application's own loop -------------------------------------------

/// A sweep reporting where its loop has got to, as a grey.
///
/// The phase *is* the pixel, so a test reads the loop off the buffer exactly
/// rather than inferring it from something moving.
fn sweep(_: &Nothing) -> El<Nothing> {
    col(draw(Size::new(60.0, 30.0), |painter, rect| {
        let phase = painter.phase("sweep", 1.0);
        painter.fill(rect, Radius::None, grey(phase));
    })
    .key("sweep")
    .label("Sweep"))
}

#[test]
fn an_applications_own_loop_comes_round_and_keeps_the_window_awake() {
    let mut harness = Harness::new(Nothing, sweep).size(200.0, 100.0);
    let read = |harness: &mut Harness<Nothing>| {
        let rect = harness.find_key("sweep").expect("the sweep is on screen").rect;
        harness.pixel(rect.center().x as u32, rect.center().y as u32).expect("a pixel").r
    };

    harness.frame();
    let started = read(&mut harness);
    assert!(harness.is_animating(), "a loop that never arrives has to keep drawing");

    // A quarter of a second of a one-second loop, stepped rather than waited
    // for: nothing here reads a clock either.
    harness.frames(15);
    let quarter = read(&mut harness);
    assert!(quarter > started, "the loop should have moved on: {started} then {quarter}");

    // And past the end of it, where a value that merely counted up would not go.
    harness.frames(45);
    let round = read(&mut harness);
    assert!(round < quarter, "the loop should have come back round, and stopped at {round}");
    assert!(harness.is_animating(), "a loop does not settle");
}

#[test]
fn a_frame_can_be_written_out_as_a_png() {
    // What a project's screenshots should be made with: the same code that
    // draws the real window, so they cannot fall out of date with it.
    let mut harness = showing(|_| col(text("Services").text_size(14.0)).pad(8.0));
    harness.frame();

    let path = std::env::temp_dir().join("rui-rendering-test.png");
    harness.save_png(&path).expect("the frame should be writable");

    let written = std::fs::read(&path).expect("the file should be there");
    assert_eq!(&written[..8], b"\x89PNG\r\n\x1a\n", "and be a PNG");
    std::fs::remove_file(&path).ok();
}
