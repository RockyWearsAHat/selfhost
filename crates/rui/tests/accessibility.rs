//! The convention, expressed as a test rather than as a promise.
//!
//! Every element carries a [`Role`], every interactive one has a name computed
//! from what is inside it, and the structure an assistive technology reads is
//! the structure the layout already built. That decision is only worth making
//! if it is held, and a convention that lives in a document rots the first time
//! somebody adds a widget in a hurry.
//!
//! So it lives here instead. This file drives the library's own widget set,
//! both examples that describe an interface, and — through the same
//! [`Harness::assert_accessible`] call added to each of them — every recipe in
//! `tests/recipes.rs`. It fails the moment a clickable thing has no role, an
//! interactive thing has no name, a tab appears outside a tab list, two
//! siblings collide on an identity, or the tab order stops being a forward walk
//! of the tree.
//!
//! It holds the other half of the decision too — that there is one path from an
//! intent to a handler — by driving the same interface twice from the same
//! state, once with a click and once with the activation an assistive
//! technology sends, and comparing what each leaves behind. A second dispatch
//! is not something a reviewer has to notice; it is a failing test.
//!
//! The examples are included as modules rather than copied, so what is checked
//! is the code that actually runs.

use rui::accessibility::{Role, audit};
use rui::testing::Harness;
use rui::{
    Align, El, Status, Tone, button, caption, code, col, divider, dot, draw, field, field_row,
    figure, heading, meter, micro, panel, paragraph, row, section, segmented, spacer, tabs, tag,
    text, title,
};
use rui::Size;

#[path = "../examples/controls.rs"]
#[allow(dead_code)]
mod controls_example;

#[path = "../examples/counter.rs"]
#[allow(dead_code)]
mod counter_example;

#[path = "../examples/gallery.rs"]
#[allow(dead_code)]
mod gallery_example;

// ---------------------------------------------------------------------------
// The examples
// ---------------------------------------------------------------------------

#[test]
fn the_counter_example_is_reachable_named_and_ordered() {
    let mut harness = Harness::new(counter_example::demo(), counter_example::view);
    harness.assert_accessible();
    harness.assert_tab_order();
}

#[test]
fn the_controls_example_is_reachable_named_and_ordered() {
    let mut harness = Harness::new(controls_example::demo(), controls_example::view);
    harness.assert_accessible();
    harness.assert_tab_order();
}

#[test]
fn the_gallery_example_is_reachable_named_and_ordered() {
    let mut harness = Harness::new(gallery_example::demo(), gallery_example::view)
        .size(1000.0, 640.0);
    harness.assert_accessible();
    harness.assert_tab_order();
}

// ---------------------------------------------------------------------------
// The whole widget set at once
// ---------------------------------------------------------------------------

/// Enough state for every widget in the library to have something to say.
#[derive(Default)]
struct Everything {
    tab: usize,
    mode: usize,
    name: String,
}

/// One of each element the library ships.
fn everything(state: &Everything) -> El<Everything> {
    col((words(), marks(), controls(state)))
        .pad(12.0)
        .gap(8.0)
}

/// Everything on the type scale.
fn words() -> El<Everything> {
    col((
        title("Title"),
        heading("HEADING"),
        text("Text"),
        caption("Caption"),
        micro("micro"),
        figure("42"),
        code("code"),
        paragraph("A paragraph of prose."),
    ))
    .gap(4.0)
}

/// Everything that is a mark rather than a word.
fn marks() -> El<Everything> {
    col((
        divider(),
        section("SECTION", Some("note".into())),
        row((dot(Status::Ok, 3.0), tag(Status::Bad, "failed"), spacer().grow())).gap(6.0),
        field_row("MEMORY", meter(0.62, Tone::Accent)),
    ))
    .gap(4.0)
}

/// Everything a person can reach.
fn controls(state: &Everything) -> El<Everything> {
    col((
        field_row(
            "NAME",
            field(&state.name)
                .placeholder("a service's name")
                .on_input(|state: &mut Everything, name| state.name = name),
        ),
        tabs(&["Overview", "Output"], state.tab, |state: &mut Everything, tab| state.tab = tab),
        segmented(&["Manual", "At boot"], state.mode, |state: &mut Everything, mode| {
            state.mode = mode
        }),
        panel(row((
            button("Start").primary().on_click(|_| {}),
            button("Unavailable").disabled(true),
        ))
        .gap(6.0)),
    ))
    .gap(6.0)
}

#[test]
fn every_widget_the_library_ships_carries_its_own_role() {
    let mut harness = Harness::new(Everything::default(), everything);
    harness.assert_accessible();
    harness.assert_tab_order();

    let roles: Vec<Role> = harness.accessibility().nodes().iter().map(|node| node.role).collect();
    for expected in [
        Role::Heading,
        Role::Text,
        Role::Separator,
        Role::Status,
        Role::Meter,
        Role::Field,
        Role::TabList,
        Role::Tab,
        Role::Radio,
        Role::Button,
    ] {
        assert!(roles.contains(&expected), "nothing in the widget set is a {expected:?}");
    }
}

// ---------------------------------------------------------------------------
// The name comes from the hierarchy
// ---------------------------------------------------------------------------

/// A state nothing writes to.
struct Nothing;

#[test]
fn a_control_is_named_by_the_words_inside_it() {
    let button: El<Nothing> = button("Restart").on_click(|_| {});
    assert_eq!(button.accessible_name(), "Restart", "no author effort at the call site");

    let compound: El<Nothing> =
        row((dot(Status::Ok, 3.0), text("mongod"), text("running"))).on_click(|_| {});
    assert_eq!(
        compound.role(Role::Button).accessible_name(),
        "mongod running",
        "the subtree's words, in order, as HTML names from contents"
    );
}

#[test]
fn a_control_with_no_words_is_named_by_its_label() {
    let unnamed: El<Nothing> = draw(Size::new(16.0, 16.0), |_, _| {}).on_click(|_| {});
    assert_eq!(unnamed.accessible_name(), "", "nothing inside it, so nothing to be named after");

    let named: El<Nothing> =
        draw(Size::new(16.0, 16.0), |_, _| {}).role(Role::Checkbox).label("Notify").on_click(|_| {});
    assert_eq!(named.accessible_name(), "Notify");
}

#[test]
fn a_label_overrides_the_words_inside() {
    let element: El<Nothing> = button("OK").label("Confirm the upgrade").on_click(|_| {});
    assert_eq!(element.accessible_name(), "Confirm the upgrade");
}

#[test]
fn a_field_is_named_by_its_row_and_valued_by_its_text() {
    let mut harness = Harness::new(Nothing, |_: &Nothing| {
        col(field_row("NAME", field("mongod").on_input(|_: &mut Nothing, _| {}))).align(Align::Start)
    });
    harness.frame();

    let node = harness
        .accessibility()
        .nodes()
        .iter()
        .find(|node| node.role == Role::Field)
        .expect("the field is on screen")
        .clone();
    assert_eq!(node.name, "NAME", "the row that names it is what names it");
    assert_eq!(node.value.as_deref(), Some("mongod"), "and what it holds is its value");
}

#[test]
fn a_row_does_not_rename_a_value_that_already_says_what_it_is() {
    let element: El<Nothing> = field_row("ACTION", button("Restart").on_click(|_| {}));
    let button = element.child(1).expect("the value sits beside the label");
    assert_eq!(button.accessible_name(), "Restart", "its own words outrank the row's heading");
}

// ---------------------------------------------------------------------------
// The structure comes from role containment
// ---------------------------------------------------------------------------

#[test]
fn a_tab_list_gives_its_tabs_their_place_without_being_told() {
    let mut harness = Harness::new(0usize, |tab: &usize| {
        col(tabs(&["Overview", "Definition", "Output"], *tab, |tab: &mut usize, chosen| {
            *tab = chosen
        }))
    });
    harness.frame();

    let tabs: Vec<_> = harness
        .accessibility()
        .nodes()
        .iter()
        .filter(|node| node.role == Role::Tab)
        .cloned()
        .collect();
    assert_eq!(tabs.len(), 3);
    for (index, tab) in tabs.iter().enumerate() {
        assert_eq!(tab.set_size, Some(3), "the parent already knows how many there are");
        assert_eq!(tab.position_in_set, Some(index + 1));
    }
    assert_eq!(tabs[0].state.selected, Some(true), "which one is chosen is state, not colour");
    assert_eq!(tabs[1].state.selected, Some(false));
}

#[test]
fn a_chosen_row_of_a_list_says_so_and_an_unchosen_one_says_so_too() {
    // What a list of services amounts to, and the fact a platform layer has to
    // be handed if a screen reader is ever to say which row is the one. The
    // three answers are distinct on purpose: chosen, not chosen, and *the
    // question does not apply* — a heading is not an unselected heading.
    fn view(chosen: &usize) -> El<usize> {
        let rows: Vec<El<usize>> = ["mongod", "caddy", "postgres"]
            .iter()
            .enumerate()
            .map(|(index, name)| {
                text(*name)
                    .key(*name)
                    .role(Role::ListItem)
                    .selected(index == *chosen)
                    .on_click(move |chosen: &mut usize| *chosen = index)
            })
            .collect();
        col(rows).role(Role::List).align(Align::Start)
    }

    let mut harness = Harness::new(1usize, view);
    let rows: Vec<_> = harness
        .accessibility()
        .nodes()
        .iter()
        .filter(|node| node.role == Role::ListItem)
        .cloned()
        .collect();

    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].state.selected, Some(false), "a row nobody chose says it was not chosen");
    assert_eq!(rows[1].state.selected, Some(true), "and the chosen one says it was");
    assert!(
        harness
            .accessibility()
            .nodes()
            .iter()
            .filter(|node| node.role == Role::Heading || node.role == Role::Group)
            .all(|node| node.state.selected.is_none()),
        "selection is not a question anyone asks of a heading or a box"
    );

    // The click's frame is the one the handler runs at the *end* of, so the
    // tree built during it still describes the interface as it was. One more
    // frame is what a window does too; see `Harness`.
    harness.click_text("postgres");
    harness.frame();
    let rows: Vec<_> = harness
        .accessibility()
        .nodes()
        .iter()
        .filter(|node| node.role == Role::ListItem)
        .cloned()
        .collect();
    assert_eq!(rows[1].state.selected, Some(false), "and it moves when the interface says so");
    assert_eq!(rows[2].state.selected, Some(true));
}

#[test]
fn a_tab_outside_a_tab_list_is_a_failure() {
    let mut harness = Harness::new(Nothing, |_: &Nothing| {
        col(text("Overview").role(Role::Tab).on_click(|_: &mut Nothing| {}))
    });
    harness.frame();

    let violations = audit(harness.accessibility());
    assert!(
        violations.iter().any(|violation| violation.to_string().contains("TabList")),
        "a tab with no tab list around it must be reported, got {violations:?}"
    );
}

#[test]
fn a_list_item_outside_a_list_is_a_failure() {
    let mut harness = Harness::new(Nothing, |_: &Nothing| {
        col(text("mongod").role(Role::ListItem).on_click(|_: &mut Nothing| {}))
    });
    harness.frame();

    let violations = audit(harness.accessibility());
    assert!(
        violations.iter().any(|violation| violation.to_string().contains("List")),
        "a list item with no list around it must be reported, got {violations:?}"
    );
}

// ---------------------------------------------------------------------------
// What the enforcement actually catches
// ---------------------------------------------------------------------------

#[test]
fn a_clickable_thing_with_no_role_is_a_failure() {
    let mut harness = Harness::new(Nothing, |_: &Nothing| {
        col(row(text("Restart")).on_click(|_: &mut Nothing| {}))
    });
    harness.frame();

    let violations = audit(harness.accessibility());
    assert!(
        !violations.is_empty(),
        "a bare clickable group is precisely the widget this test exists to reject"
    );
}

#[test]
fn an_interactive_thing_with_no_name_is_a_failure() {
    let mut harness = Harness::new(Nothing, |_: &Nothing| {
        col(draw(Size::new(16.0, 16.0), |_, _| {}).role(Role::Checkbox).on_click(|_: &mut Nothing| {}))
    });
    harness.frame();

    let violations = audit(harness.accessibility());
    assert!(!violations.is_empty(), "an unnamed control is unusable without sight of it");
}

#[test]
fn two_siblings_sharing_a_key_are_a_failure() {
    let mut harness = Harness::new(Nothing, |_: &Nothing| {
        col((
            button("Restart").key("action").on_click(|_: &mut Nothing| {}),
            button("Stop").key("action").on_click(|_: &mut Nothing| {}),
        ))
    });
    harness.frame();

    let violations = audit(harness.accessibility());
    assert!(
        !violations.is_empty(),
        "two siblings with one identity share a hover, a focus, and a caret"
    );
}

// ---------------------------------------------------------------------------
// One path from intent to handler
// ---------------------------------------------------------------------------

/// What a route into the interface is asked to change.
///
/// Two counts and not one, so that a test can tell "the same handler ran twice"
/// from "each route found a handler of its own".
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
struct Counted {
    presses: u32,
    dismissals: u32,
}

fn counted(_: &Counted) -> El<Counted> {
    col((
        button("Restart").on_click(|counted: &mut Counted| counted.presses += 1),
        button("Dismiss").on_click(|counted: &mut Counted| counted.dismissals += 1),
    ))
    .align(Align::Start)
}

#[test]
fn an_assistive_activation_runs_the_same_handler_a_click_would() {
    // The invariant as an assertion: the two routes are driven from the same
    // starting state, and what each leaves behind is compared whole. Anything
    // an activation did differently — a handler of its own, a handler missed,
    // the wrong element — shows up as a difference here.
    let mut clicked = Harness::new(Counted::default(), counted);
    clicked.click_text("Restart");

    let mut activated = Harness::new(Counted::default(), counted);
    activated.activate_named("Restart");

    assert_eq!(
        *activated.state(),
        *clicked.state(),
        "a screen reader's press and a click must leave the interface in one state"
    );
    assert_eq!(clicked.state().presses, 1, "and it must be the state the handler produces");
}

#[test]
fn an_assistive_activation_reaches_the_element_it_names() {
    let mut harness = Harness::new(Counted::default(), counted);
    harness.activate_named("Dismiss");
    assert_eq!(
        *harness.state(),
        Counted { presses: 0, dismissals: 1 },
        "an activation is aimed by identity, and must reach nothing else"
    );
}

#[test]
fn an_assistive_activation_says_so_before_it_is_offered() {
    // What a platform reads to decide whether to offer a press at all. The two
    // have to agree: an action advertised on something that answers none is a
    // command a person is offered and then let down by.
    let mut harness = Harness::new(Counted::default(), counted);
    let nodes = harness.accessibility().nodes().to_vec();

    let button = nodes.iter().find(|node| node.name == "Restart").expect("the button is drawn");
    assert_eq!(button.role, Role::Button);
    assert!(button.actions.press, "a button says it can be pressed");

    assert!(
        nodes.iter().filter(|node| node.role == Role::Text).all(|node| !node.actions.press),
        "a run of words answers no press, and must not claim to"
    );
}

#[test]
fn an_assistive_activation_of_something_that_is_gone_does_nothing() {
    // An assistive technology holds objects from trees that have since moved
    // on, so a stale press is a race and not a failure. It must not panic, and
    // it must not land on whatever happens to be there now.
    let mut harness = Harness::new(Counted::default(), counted);
    harness.frame();

    harness.activate(rui::Id::new("nothing has ever been called this"));
    assert_eq!(*harness.state(), Counted::default(), "an identity nobody has is a no-op");
}

#[test]
fn an_assistive_activation_leaves_the_keyboard_where_it_was() {
    // A click gives focus to what it pressed, because the pointer went there.
    // An activation must not: an assistive technology moves the keyboard when
    // it means to, and pressing a button while somebody is filling in a field
    // must not take the field away from them.
    let mut harness = Harness::new(Counted::default(), counted);
    harness.tab();
    let focused = harness.focused();
    assert!(focused.is_some(), "Tab reached the first button");

    harness.activate_named("Dismiss");
    assert_eq!(harness.state().dismissals, 1, "the handler still ran");
    assert_eq!(harness.focused(), focused, "and the keyboard did not move");
}

#[test]
fn an_assistive_activation_of_a_disabled_control_does_nothing() {
    fn view(counted: &Counted) -> El<Counted> {
        col(button("Restart")
            .on_click(|counted: &mut Counted| counted.presses += 1)
            .disabled(counted.presses == 0))
        .align(Align::Start)
    }

    let mut harness = Harness::new(Counted::default(), view);
    let id = harness
        .accessibility()
        .nodes()
        .iter()
        .find(|node| node.name == "Restart")
        .expect("the button is drawn")
        .id;

    harness.activate(id);
    assert_eq!(
        harness.state().presses,
        0,
        "a disabled control ignores every route, or the two disagree about what disabled means"
    );
}

#[test]
fn a_screen_carrying_a_greyed_control_still_passes_the_tab_audit() {
    // The defect this holds shut, and it was in the audit rather than in the
    // interface: `assert_tab_order` counted a disabled element as one Tab
    // should reach while `rui`'s own walk stepped over it, so any screen
    // honestly greying a control it cannot offer failed for the wrong reason —
    // and the way to pass was to draw fewer facts.
    fn view(_: &Counted) -> El<Counted> {
        col((
            button("Start").on_click(|counted: &mut Counted| counted.presses += 1),
            // Both orders, because the audit and the walk must agree about the
            // same greyed button however it was written.
            button("Restart").on_click(|_: &mut Counted| {}).disabled(true),
            button("Uninstall").disabled(true).on_click(|_: &mut Counted| {}),
        ))
        .gap(6.0)
        .align(Align::Start)
    }

    let mut harness = Harness::new(Counted::default(), view);
    harness.assert_tab_order();

    harness.tab();
    let focused = harness.focused();
    harness.tab();
    assert_eq!(harness.focused(), focused, "Tab found somewhere else to go among two greyed keys");
}

// ---------------------------------------------------------------------------
// Emission is a diff
// ---------------------------------------------------------------------------

#[test]
fn a_frame_that_changed_nothing_emits_nothing() {
    let mut harness = Harness::new(0usize, |count: &usize| {
        col(text(format!("{count}"))).align(Align::Start)
    });

    harness.frame();
    harness.frame();
    assert!(
        harness.accessibility_update().is_empty(),
        "an interface spends most of its life unchanged, and so should its a11y traffic"
    );
}

#[test]
fn the_node_that_lost_the_keyboard_is_in_the_difference_too() {
    // What a platform layer is entitled to assume, and the reason the macOS
    // backend applies focus from the node rather than working out for itself
    // which element used to have it: a node whose focus changed *is* a node
    // that differs, so the diff carries both ends of the move. A backend that
    // had to remember the previous holder would be a second place the truth
    // lived, and the symptom is two elements both claiming the keyboard.
    fn view(_: &Nothing) -> El<Nothing> {
        col((
            button("First").on_click(|_: &mut Nothing| {}),
            button("Second").on_click(|_: &mut Nothing| {}),
        ))
        .align(Align::Start)
    }

    let mut harness = Harness::new(Nothing, view);
    harness.tab();
    let first = harness.focused().expect("Tab reached the first button");

    harness.tab();
    let second = harness.focused().expect("Tab reached the second");
    assert_ne!(first, second, "Tab moved the keyboard");

    // Tab is taken by the frame it arrives on and settled at the end of it, so
    // the tree that frame built still describes where the keyboard *was*. The
    // frame after is the one that says it moved — the same one-frame lag a
    // click has, and the one a window shows too.
    harness.frame();
    let update = harness.accessibility_update().clone();
    assert!(update.focus_moved, "the move itself is announced");
    let lost = update.changed.iter().find(|node| node.id == first);
    let gained = update.changed.iter().find(|node| node.id == second);
    assert_eq!(
        lost.map(|node| node.state.focused),
        Some(false),
        "the node that lost the keyboard is in the difference, saying it no longer has it"
    );
    assert_eq!(gained.map(|node| node.state.focused), Some(true));
}

#[test]
fn only_what_changed_is_emitted() {
    fn view(count: &usize) -> El<usize> {
        col((
            text("Unchanging"),
            text(format!("{count}")),
            button("Increment").on_click(|count: &mut usize| *count += 1),
        ))
        .align(Align::Start)
    }

    let mut harness = Harness::new(0usize, view);
    harness.frame();
    harness.click_text("Increment");
    harness.frame();

    let update = harness.accessibility_update().clone();
    assert!(!update.is_empty(), "the number changed, so something must be said about it");
    assert!(
        update.changed.iter().all(|node| node.name != "Unchanging"),
        "what did not change is not worth the assistive technology's time, got {update:?}"
    );
}
