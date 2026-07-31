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

/// Everything this program would hate to lose across a developer reload.
///
/// A count is one number, so it is one number written down. A real application
/// writes whatever its own format is here — this library never looks inside it.
#[cfg(feature = "reload")]
fn save(counter: &Counter) -> Vec<u8> {
    counter.count.to_string().into_bytes()
}

/// The state those bytes came from, or why they could not be read.
#[cfg(feature = "reload")]
fn restore(saved: &[u8]) -> Result<Counter, String> {
    let text = std::str::from_utf8(saved).map_err(|error| error.to_string())?;
    let count = text.trim().parse().map_err(|error: std::num::ParseIntError| error.to_string())?;
    Ok(Counter { count })
}

fn main() -> Result<(), rui::Error> {
    let app = rui::App::new("Counter", demo(), view);

    // Developer reload, and the whole of what it costs at the call site. Off
    // unless this crate is built with the feature, so an ordinary
    // `cargo run --example counter` compiles none of it:
    //
    //     cargo run -p rui --features reload --example counter
    //
    // Then count up to something, edit this file, and in another terminal run
    // `cargo build -p rui --features reload --example counter`. The window
    // comes back as the new build, still showing the number.
    #[cfg(feature = "reload")]
    let app = app.reloadable(save, restore)?;

    app.run()
}
