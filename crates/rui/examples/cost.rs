//! What a frame costs, and what putting a moving picture in one adds to it.
//!
//! Run with `cargo run -p rui --release --example cost`. A debug build measures
//! the compiler rather than the renderer, so it says so and stops.
//!
//! # Why this is a program and not a test
//!
//! A timing assertion on a shared machine is a test that fails for reasons that
//! have nothing to do with the code. What is wanted from a measurement is a
//! number to put in a document and to re-take when something changes, which is
//! this: it prints a table, and a person decides what it means.
//!
//! # What it measures, and why those things
//!
//! [`Canvas::blit_bgra`] is the whole of a video viewport's drawing, so its cost
//! at a window's own size is the cost of turning that window into one.
//!
//! The comparison against the frame on screen is measured twice, because a
//! viewport changes which case the loop is in. `shell` presents a frame only
//! when it differs from the last one — a comparison that exists to *avoid*
//! presenting, and which a moving picture makes always-miss. Whether that
//! matters is arithmetic rather than opinion: a miss stops at the first differing
//! word, so it is the *hit* that scans the surface, and a viewport turns the
//! expensive case into the cheap one. What a viewport does add is the present
//! itself, on every frame instead of hardly ever — so the copy a present makes
//! is measured too.

use rui::canvas::Bgra;
use rui::{Canvas, Color, Rect};
use std::time::{Duration, Instant};

/// The window sizes the console's own frame-cost table is quoted at, in device
/// pixels — a logical size at the scale it is usually shown at.
const WINDOWS: [(&str, u32, u32); 3] =
    [("560 × 420", 1120, 840), ("980 × 680", 1960, 1360), ("1180 × 760", 2360, 1520)];

/// How many times each measurement is repeated.
///
/// The median of these is reported rather than the mean: one sample landing in
/// a scheduler's lap should not move the number a document quotes.
const RUNS: usize = 33;

fn main() {
    if cfg!(debug_assertions) {
        eprintln!("build this with --release; a debug build measures the compiler");
        return;
    }

    println!("| window | pixels | blit a full-window frame | compare (same) | compare (differs) | copy the surface |");
    println!("|---|---|---|---|---|---|");
    for (name, width, height) in WINDOWS {
        let pixels = (width as usize) * (height as usize);
        let source = capture(width, height);
        let frame = Bgra::packed(width, height, &source).expect("the buffer describes the picture");

        let mut canvas = Canvas::new(width, height, 2.0);
        let bounds = canvas.bounds();
        let blit = median(|| canvas.blit_bgra(bounds, &frame));

        // Two surfaces to compare, exactly as the loop holds them: one that came
        // out identical, and one differing in its first row — which is what a
        // viewport at the top of a window produces.
        let same = Canvas::new(width, height, 2.0);
        let mut differs = Canvas::new(width, height, 2.0);
        differs.fill_rect(Rect::new(0.0, 0.0, 4.0, 4.0), Color::WHITE);
        let unchanged = Canvas::new(width, height, 2.0);

        let hit = median(|| assert!(unchanged.pixels() == same.pixels()));
        let miss = median(|| assert!(unchanged.pixels() != differs.pixels()));
        let mut copy = vec![0u32; pixels];
        let present = median(|| copy.copy_from_slice(unchanged.pixels()));

        println!(
            "| {name} | {:.1} M | **{}** | {} | {} | {} |",
            pixels as f32 / 1_000_000.0,
            milliseconds(blit),
            milliseconds(hit),
            milliseconds(miss),
            milliseconds(present),
        );
    }

    println!();
    println!("A remote screen larger than the pane showing it, cropped rather than scaled:");
    let source = capture(1920, 1080);
    let frame = Bgra::packed(1920, 1080, &source).expect("the buffer describes the picture");
    let mut canvas = Canvas::new(2360, 1520, 2.0);
    let pane = Rect::new(20.0, 20.0, 560.0, 320.0);
    let cropped = median(|| canvas.blit_bgra(pane, &frame));
    println!("  1920 × 1080 into a 560 × 320 logical pane at 2×: {}", milliseconds(cropped));
}

/// A picture with something different in every pixel, as a capture would be.
///
/// Not one flat colour: a compiler is entitled to notice that a constant buffer
/// is a constant, and a measurement of that is a measurement of nothing.
fn capture(width: u32, height: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity((width as usize) * (height as usize) * 4);
    for y in 0..height {
        for x in 0..width {
            bytes.extend_from_slice(&[(x ^ y) as u8, (x >> 3) as u8, (y >> 3) as u8, 0xff]);
        }
    }
    bytes
}

/// How long `work` takes, as the median of [`RUNS`] goes at it.
fn median(mut work: impl FnMut()) -> Duration {
    let mut taken = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let started = Instant::now();
        work();
        taken.push(started.elapsed());
    }
    taken.sort_unstable();
    taken.get(RUNS / 2).copied().unwrap_or_default()
}

/// A duration as the milliseconds a frame budget is counted in.
fn milliseconds(taken: Duration) -> String {
    format!("{:.2} ms", taken.as_secs_f64() * 1000.0)
}
