//! The whole of a `rui` program, in a screenful.
//!
//! `cargo run -p rui --example counter` opens it.
//!
//! The state and the view are public only so that `tests/accessibility.rs` can
//! drive this exact interface rather than a copy of it that could drift from
//! it. Nothing else about the program needs them to be.

use rui::{El, button, col, row, title};

/// Everything this program knows.
pub struct Counter {
    count: i32,
}

/// What this program starts as.
pub fn demo() -> Counter {
    Counter { count: 0 }
}

/// What should be on screen, given that.
pub fn view(counter: &Counter) -> El<Counter> {
    col((
        title(format!("{}", counter.count)).text_size(56.0).bold().center_text(),
        row((
            button("−").w(56.0).on_click(|counter: &mut Counter| counter.count -= 1),
            button("Reset").w(80.0).on_click(|counter: &mut Counter| counter.count = 0),
            button("+").primary().w(56.0).on_click(|counter: &mut Counter| counter.count += 1),
        ))
        .gap(8.0),
    ))
    .gap(20.0)
    .pad(32.0)
    .center()
}

fn main() -> Result<(), rui::Error> {
    rui::run("Counter", demo(), view)
}
