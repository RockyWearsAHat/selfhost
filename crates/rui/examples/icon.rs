//! Draws the application icon at every size macOS asks for.
//!
//! `cargo run -p rui --example icon -- --out <directory>` writes an `.iconset`
//! that `iconutil` turns into an `.icns`. `scripts/macos-app.sh` runs it as part
//! of building the bundle.
//!
//! The icon is *drawn* rather than stored, for the same reason no font is
//! shipped: it is correct at every size instead of being one bitmap resampled to
//! the rest, it costs nothing in the repository, and a change to the mark is a
//! change to code that can be reviewed.

use rui::style::Radius;
use rui::{Appearance, Canvas, Color, Corner, Painter, Rect, Theme, Tone, image};

/// The sizes an `.iconset` holds, and the name each must be filed under.
///
/// macOS asks for every size at one and two times, and names the file after the
/// *logical* size. A missing entry is not an error — the icon simply looks
/// resampled wherever that size is used.
const SIZES: [(u32, u32); 10] = [
    (16, 1),
    (16, 2),
    (32, 1),
    (32, 2),
    (128, 1),
    (128, 2),
    (256, 1),
    (256, 2),
    (512, 1),
    (512, 2),
];

/// How much of the tile the mark is inset by.
///
/// macOS icons are drawn on a rounded square that does not reach the edge of its
/// own box; every application on the Dock leaves this margin, and one that does
/// not looks a size larger than its neighbours.
const MARGIN: f32 = 0.09;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let mut directory = String::from("iconset");
    while let Some(argument) = arguments.next() {
        if argument == "--out" {
            directory = arguments.next().ok_or("--out needs a directory")?;
        }
    }
    std::fs::create_dir_all(&directory)?;

    for (size, scale) in SIZES {
        let pixels = size * scale;
        let mut canvas = Canvas::new(pixels, pixels, scale as f32);
        canvas.clear(Color::TRANSPARENT);
        draw_icon(&mut canvas, size as f32);

        let rgba = image::rgba(&canvas);
        let png = image::png(pixels, pixels, &rgba).ok_or("the icon could not be encoded")?;
        let suffix = if scale == 2 { "@2x" } else { "" };
        let path = format!("{directory}/icon_{size}x{size}{suffix}.png");
        std::fs::write(&path, png)?;
        println!("wrote {path}");
    }
    Ok(())
}

/// Draws the mark filling a `size`-unit tile.
///
/// The same three rack units the console's own header draws, at the same
/// proportions — one mark, in one place, so the icon on the Dock and the mark in
/// the window cannot come to differ.
fn draw_icon(canvas: &mut Canvas, size: f32) {
    let fonts = rui::Fonts::new();
    let theme = Theme::new(Appearance::Dark, rui::FontId::FIRST, rui::FontId::FIRST);
    let mut painter = Painter::new(canvas, &fonts, &theme);

    let margin = size * MARGIN;
    let tile = Rect::new(margin, margin, size - margin * 2.0, size - margin * 2.0);
    let corner = Corner::Round(tile.w * 0.22);
    let (light, deep) = (painter.color(Tone::AccentLight), painter.color(Tone::AccentDeep));
    painter.canvas().fill_vertical(tile, corner, light, deep);

    let inset = tile.w * 0.20;
    let height = tile.h * 0.17;
    let spacing = (tile.h - inset * 2.0 - height) / 2.0;
    let ink = painter.color(Tone::OnAccent).fade(0.92);
    let lamp_color = painter.color(Tone::AccentLight);

    for index in 0..3 {
        let unit = Rect::new(
            tile.x + inset,
            tile.y + inset + spacing * index as f32,
            tile.w - inset * 2.0,
            height,
        );
        painter.fill(unit, Radius::Units(height * 0.2), Tone::Exact(ink));

        let lamp = height * 0.34;
        let socket = Rect::new(unit.x + lamp, unit.y + unit.h / 2.0 - lamp / 2.0, lamp, lamp);
        painter.canvas().fill(socket, Corner::Round(lamp / 2.0), lamp_color);
    }
}
