//! Every element in the library, drawn to a PNG with no window open.
//!
//! Run with `cargo run -p rui --example gallery -- <directory>`. It writes
//! `gallery-light.png`, `gallery-dark.png`, and `gallery-cut.png`, which is how
//! this library's own appearance is reviewed: the renderer is pure, so a frame
//! drawn with no display is the same frame a window would show.
//!
//! The third of those is the same interface under a theme the application
//! supplied — one word different, and every framed thing in the window follows.
//!
//! The state and the view are public so that `tests/accessibility.rs` can hold
//! this exact interface — every element the library ships, in one place — to the
//! accessibility convention.

use rui::style::{Align, Justify, Length, Radius};
use rui::{
    App, Appearance, CornerStyle, El, Size, Status, Theme, Tone, button, caption, code, col,
    divider, dot, draw, field, field_row, figure, heading, image, meter, micro, panel, paragraph,
    row, section, segmented, spacer, tabs, tag, title,
};

/// What the gallery is showing, so the interactive parts have something to say.
pub struct Gallery {
    tab: usize,
    mode: usize,
    name: String,
}

/// What the gallery opens showing.
pub fn demo() -> Gallery {
    Gallery { tab: 0, mode: 1, name: "mongod".into() }
}

/// The whole gallery, as one description.
pub fn view(gallery: &Gallery) -> El<Gallery> {
    col((
        masthead(),
        tabs(&["Overview", "Definition", "Output"], gallery.tab, |gallery: &mut Gallery, tab| {
            gallery.tab = tab
        }),
        row((counts(), states(), readout(gallery))).gap(12.0),
        row((controls(gallery), form(gallery))).gap(12.0).grow(),
    ))
    .pad(16.0)
    .gap(12.0)
}

/// The bar across the top: the mark, the name, and where it is connected.
fn masthead() -> El<Gallery> {
    row((
        draw(Size::new(24.0, 24.0), |painter, rect| {
            // An application's own drawing, on the same canvas every widget
            // here uses: three rack units, each with its lamp lit.
            let corner = rui::Corner::Round(rect.w * 0.24);
            let (light, deep) = (painter.color(Tone::AccentLight), painter.color(Tone::AccentDeep));
            painter.canvas().fill_vertical(rect, corner, light, deep);

            let margin = rect.w * 0.2;
            let height = rect.h * 0.17;
            let spacing = (rect.h - margin * 2.0 - height) / 2.0;
            let ink = painter.color(Tone::OnAccent).fade(0.92);
            let lamp_color = painter.color(Tone::AccentLight);
            for index in 0..3 {
                let unit = rui::Rect::new(
                    rect.x + margin,
                    rect.y + margin + spacing * index as f32,
                    rect.w - margin * 2.0,
                    height,
                );
                painter.canvas().fill_rect(unit, ink);
                let lamp = height * 0.34;
                let socket = rui::Rect::new(
                    unit.x + lamp,
                    unit.y + unit.h / 2.0 - lamp / 2.0,
                    lamp,
                    lamp,
                );
                painter.canvas().fill(socket, rui::Corner::Round(lamp / 2.0), lamp_color);
            }
        }),
        title("rui").bold(),
        caption("a declarative interface library"),
        spacer().grow(),
        dot(Status::Ok, 4.0),
        micro("127.0.0.1:9191"),
    ))
    .gap(8.0)
    .h(28.0)
}

/// A ribbon of figures, which is what a strip of counts is.
fn counts() -> El<Gallery> {
    panel(row((
        count("RUNNING", "6", Status::Ok),
        divider().w(1.0).h(Length::Fill(1.0)),
        count("STOPPED", "1", Status::Idle),
        divider().w(1.0).h(Length::Fill(1.0)),
        count("FAILED", "2", Status::Bad),
    ))
    .gap(16.0)
    .h(46.0))
    .grow()
}

/// One figure with its name under it.
fn count(label: &str, value: &str, status: Status) -> El<Gallery> {
    col((row((figure(value).bold(), dot(status, 3.5))).gap(6.0), heading(label)))
        .gap(2.0)
        .grow()
        .justify(Justify::Center)
}

/// The four statuses, as tags and as a meter.
fn states() -> El<Gallery> {
    panel(col((
        section("STATES", Some("four".into())),
        row((
            tag(Status::Ok, "running"),
            tag(Status::Warn, "restarting"),
            tag(Status::Bad, "failed"),
            tag(Status::Idle, "stopped"),
        ))
        .gap(6.0),
        field_row("MEMORY", row((meter(0.62, Tone::Accent).grow(), caption("62%"))).gap(8.0)),
        field_row("DISK", row((meter(0.91, Tone::Bad).grow(), caption("91%"))).gap(8.0)),
    ))
    .gap(8.0))
    .grow()
}

/// A chamfered plate holding a gauge that sweeps to its reading.
///
/// The two things an application reaches past the widget set for, together:
///
/// - `Radius::Cut` gives *this* container a machined corner while the panels
///   beside it keep the theme's own. A whole interface of them is asked for
///   from the theme instead — see `main`, which renders exactly that.
/// - `Painter::ease` moves the needle on the same curve every button in this
///   window lights on, so a control the library has never seen does not have to
///   choose between jumping and inventing its own timing. Choosing a tab above
///   moves the reading, and the sweep is what carries it there.
fn readout(gallery: &Gallery) -> El<Gallery> {
    // Something on screen that changes, so the sweep has somewhere to go.
    let reading = [0.28, 0.64, 0.93][gallery.tab.min(2)];
    col((
        section("READOUT", Some("eased".into())),
        row((
            draw(Size::new(120.0, 10.0), move |painter, rect| {
                // The interface's own motion constant, so this moves at the
                // pace the rest of the window does.
                let swept = painter.ease("needle", reading, painter.theme().metrics.motion);
                painter.fill(rect, Radius::Cut(3.0), Tone::Sunken);
                painter.stroke(rect, Radius::Cut(3.0), 1.0, Tone::Border);

                let filled = rui::Rect::new(rect.x, rect.y, (rect.w * swept).max(1.0), rect.h);
                painter.fill(filled, Radius::Cut(3.0), Tone::Accent);
            })
            .grow()
            .h(10.0)
            .role(rui::Role::Meter)
            .label("Load")
            .value(format!("{:.0}%", reading * 100.0)),
            caption(format!("{:.0}%", reading * 100.0)),
        ))
        .gap(8.0)
        .align(Align::Center),
        micro("Cut corners, an eased sweep."),
        spacer().grow(),
    ))
    .gap(8.0)
    .w(200.0)
    .pad(12.0)
    .gradient(Tone::Surface, Tone::SurfaceDeep)
    .border(1.0, Tone::Border)
    .round(Radius::Cut(10.0))
    .shadow(9.0)
}

/// Every emphasis a button has, and a paragraph of prose.
fn controls(gallery: &Gallery) -> El<Gallery> {
    panel(col((
        section("CONTROLS", None),
        row((
            button("Start").primary().on_click(|_| {}),
            button("Restart").on_click(|_| {}),
            button("Uninstall").danger().on_click(|_| {}),
            button("Logs").ghost().on_click(|_| {}),
        ))
        .gap(6.0),
        row((button("Unavailable").disabled(true), caption("disabled, and still drawn"))).gap(8.0),
        divider(),
        segmented(&["Manual", "At boot", "On demand"], gallery.mode, |gallery: &mut Gallery, mode| {
            gallery.mode = mode
        }),
        paragraph(
            "Text wraps to whatever width it is given, and inherits its size and \
             colour from whatever contains it — which is the whole of the styling \
             model: roles rather than values, inherited rather than repeated.",
        )
        .color(Tone::Muted)
        .text_size(12.0),
    ))
    .gap(10.0))
    .grow()
}

/// A form, and a scrolling log: the two things every console has.
fn form(gallery: &Gallery) -> El<Gallery> {
    panel(col((
        section("DEFINITION", None),
        field_row(
            "NAME",
            field(&gallery.name)
                .placeholder("a service's name")
                .on_input(|gallery: &mut Gallery, name| gallery.name = name),
        ),
        field_row("PROGRAM", field("/usr/local/bin/mongod").placeholder("a program to run")),
        section("OUTPUT", Some("live".into())),
        col((0..14)
            .map(|line| {
                code(format!("[{line:02}:14:0{}] listening on 127.0.0.1:27017", line % 10))
                    .color(if line % 5 == 0 { Tone::Warn } else { Tone::Muted })
            })
            .collect::<Vec<_>>())
        .gap(2.0)
        .grow()
        .scroll()
        .fill(Tone::Sunken)
        .round(Radius::Control)
        .border(1.0, Tone::Border)
        .pad(8.0),
        row((
            spacer().grow(),
            button("Cancel").on_click(|_| {}),
            button("Install").primary().on_click(|_| {}),
        ))
        .gap(6.0),
    ))
    .gap(10.0))
    .grow()
    .align(Align::Stretch)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    let mut fonts = rui::shell::load_system_fonts()?;

    // The same description, drawn three times. The third supplies a theme of
    // its own, and one word in it turns every panel, button, field, and tag in
    // the window from a card into a machined plate — with not one of them
    // touched, because none of them names a corner shape for itself.
    let renders: [(&str, Appearance, Option<CornerStyle>); 3] = [
        ("light", Appearance::Light, None),
        ("dark", Appearance::Dark, None),
        ("cut", Appearance::Dark, Some(CornerStyle::Cut)),
    ];

    for (name, appearance, corners) in renders {
        let mut app = App::new("Gallery", demo(), view);
        if let Some(corners) = corners {
            app = app.theme(move |appearance, ui, mono| {
                Theme::new(appearance, ui, mono).with_corners(corners)
            });
        }
        let canvas = app.render(1000, 640, 2.0, appearance, &mut fonts);
        let pixels = image::rgba(&canvas);
        let png = image::png(canvas.width(), canvas.height(), &pixels)
            .ok_or("the frame could not be encoded")?;
        let path = format!("{directory}/gallery-{name}.png");
        std::fs::write(&path, png)?;
        println!("wrote {path}");
    }
    Ok(())
}
