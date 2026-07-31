# rui

A declarative interface library for Rust, with no dependencies at all.

It takes the three things the web splits across three languages — the structure
of a page, how it looks, and what it does — and makes them one Rust expression.

```rust
use rui::{El, button, col, title};

struct Counter {
    count: i32,
}

fn view(counter: &Counter) -> El<Counter> {
    col((
        title(format!("{}", counter.count)).text_size(56.0).bold(),
        button("Increment").on_click(|counter: &mut Counter| counter.count += 1),
    ))
    .gap(16.0)
    .pad(32.0)
    .center()
}

fn main() -> Result<(), rui::Error> {
    rui::run("Counter", Counter { count: 0 }, view)
}
```

That is a complete program: it opens a window, finds the desktop's own fonts,
rasterises every pixel itself, and runs until the window is closed.

```
cargo run -p rui --example counter    # the program above
cargo run -p rui --example controls   # controls built from the primitives
cargo run -p rui --example gallery -- .   # every element, to a PNG, with no window
```

## The model

**A view is a function of state.** `view` is called whenever anything might have
changed, and it describes the whole interface from the application's own data.
There is no retained tree of widget objects to keep in step, so an interface can
never show something the data no longer says.

**A handler is a function of state, not a closure over it.**
`on_click(|app: &mut App| …)` takes the application's state as an argument. The
description therefore borrows nothing mutably; handlers run after the frame has
been drawn, on a description that is about to be dropped. There is no `Rc`, no
`RefCell`, and no interior mutability anywhere in the library — the piece most
Rust interface libraries pay for in ceremony costs nothing here.

**A colour is a role, not a value.** A style names `Tone::Surface` or
`Tone::Muted`, resolved against whichever theme is in force, so one description
of an interface is right on a light desktop and on a dark one.

**Structure, style, and behaviour are one chain.** There is no stylesheet to
match against, and no selector: what a thing looks like is written where the
thing is.

```rust
row((
    dot(Status::Ok, 3.0),
    text(&service.name).grow(),
    button("Restart").on_click(|app: &mut App| app.restart()),
))
.key(&service.name)
.pad_x(8.0)
.h(42.0)
.round(Radius::Control)
.hover_fill(Tone::Raised)
```

## Foundations, not a catalogue

This library ships no checkbox, no toggle, no slider, and no menu — on purpose.

A library that ships `checkbox()` has decided what a checkbox is. The moment you
want yours a shade smaller, with a different tick, or answering the right-hand
button as well, you are either sending a patch upstream or writing it from
scratch anyway, and the catalogue you were handed turns out to be a list of the
things you are allowed to want.

What a foundation owes you instead is that any of them can be *written*. Four
primitives cover it:

| primitive | what it gives you |
|---|---|
| `draw(size, \|painter, rect\|)` | a rectangle and the same painter every element here is made of |
| `painter.visual()` | whether it is hovered, held, focused, disabled, and how far its hover has eased |
| `.on_drag(\|state, drag\|)` | where the pointer is *within it*, every frame it is held — clamped by `drag.fraction()` |
| `.on_key`, `.on_scroll`, `.on_hover`, `.layer` | the keyboard, the wheel, the pointer arriving, and somewhere to put what opens |

A slider is then four lines, and is a real control — it animates on the same
curve, answers the keyboard, and is reachable by Tab, because it is made of the
same parts a button is:

```rust
draw(Size::new(160.0, 18.0), move |painter, rect| {
    let (filled, _) = rect.split_left(rect.w * value);
    painter.fill(rect, Radius::Pill, Tone::Sunken);
    painter.fill(filled, Radius::Pill, Tone::Accent);
})
.on_drag(|app: &mut App, drag| app.volume = drag.fraction().x)
.on_key(|app: &mut App, key, _| app.nudge(key))
```

`examples/controls.rs` builds a checkbox, a switch, a slider, a radio group, a
stepper driven by the wheel, and a tooltip this way. `tests/recipes.rs` tests
all of them. Copy either into your project and change it — that is the intended
use, and it needs no permission from this repository.

The elements that *are* here — `col`, `row`, `text`, `title`, `heading`,
`caption`, `micro`, `figure`, `code`, `paragraph`, `panel`, `divider`,
`section`, `field_row`, `button`, `field`, `tag`, `dot`, `meter`, `tabs`,
`segmented`, `spacer`, `draw` — are recipes of exactly that kind, kept because
an interface needs a house style more than it needs a hundred choices. Every one
of them is an ordinary `El` with a style already on it, so a button that needs to
be wider is `button("Go").w(120.0)` rather than a variant somebody has to add
here first.

## Structure

Children are written as a tuple, a `Vec`, or an `Option` — which covers a fixed
handful, a list built from data, and something shown only sometimes: the three
cases a template language spends `{#each}` and `{#if}` blocks on.

```rust
col((
    heading("SERVICES"),                                  // one
    services.iter().map(row_for).collect::<Vec<_>>(),     // many
    error.map(|message| banner(message)),                 // sometimes
))
```

## Layout

The useful half of flexbox, and nothing else. A container stacks its children
along one axis; each asks for a `Length` along it:

| length | means |
|---|---|
| `Auto` (the default) | what its content needs |
| `.w(120.0)` / `.h(28.0)` | exactly that |
| `.grow()` | a share of what is left over |
| `Length::Fraction(0.28)` | that share of what the parent offered |

Room left over is divided between the growing children in proportion to what
they asked for. Room that runs *short* is taken back off the children sized to
their content — never off one that asked for a height in units, because a
control asked for its height because that is how tall it has to be. Across the
other axis a child is stretched unless it states a size or an `align_self`, and
is never laid out wider than the box that owns it.

`.flow()` runs children onto further lines when they do not fit — a row of tags,
a grid of cards, a toolbar that reflows on a narrow window. It is the one layout
a strict single-axis stack cannot express, because how many lines there are is
not known until the children have been measured.

`.scroll()` makes a container show part of its children; `.follow()` keeps it at
the end of them until the reader scrolls back, and follows again once they
scroll to the end — which is what a log tail is, decided from where the reader
actually is rather than from a flag the application has to keep.

`.layer(Anchor::Below)` lifts an element out of its parent's stacking and hangs
it off the parent's edge: a menu, a tooltip, a dialog. A layer takes no room, is
held inside the window so it cannot open off the edge of the screen, escapes any
clipping between it and the window, and is drawn — and answers the pointer —
above whatever it covers.

Otherwise, every position is decided by exactly one parent, so drawing and hit
testing cannot come to disagree about where something is. There is one answer per
frame to *what is the pointer over*, so two overlapping things can never both
believe they are hovered.

## Style, and what inherits

Text properties — size, colour, face, tracking, weight — are inherited by
children that do not set their own, exactly as they are on the web. That is what
lets a whole block be quietened with one call on the container rather than the
same call on nine labels. Nothing else inherits: a box that silently took its
parent's padding would be the most confusing thing a layout engine can do.

Everything else is a chained setter: `.pad`, `.gap`, `.fill`, `.gradient`,
`.border`, `.round`, `.pill`, `.shadow`, `.clip`, `.align`, `.justify`,
`.center`, `.hover_fill`, `.hover_color`, `.disabled`.

## Identity, and the state that outlives a frame

Anything a person can interact with needs an identity that is the same from one
frame to the next, because that is the key its hover, focus, caret, and scroll
position are stored under. It is derived from the element's path through the
tree, so nothing has to be named — until a list is reordered, at which point
`.key(&service.name)` names the row after the thing it shows, and its state
follows the row rather than the position.

`Memory` holds that state and nothing else. No copy of the application's data
lives in this library.

## What it means, for anyone who cannot see it

**Every element carries a `Role`, and the tree of elements *is* the
accessibility tree.** There is no parallel structure to keep in step and nothing
to annotate afterwards — the same description that is laid out and drawn is the
one a screen reader is told about.

That makes the convention nearly free at the call site, because every fact an
assistive technology wants is already somewhere:

| fact | where it already was |
|---|---|
| identity | the `Id` derived from the element's path, named by `.key()` |
| role | set by every constructor here; `.role(Role::Slider)` for anything you build |
| name | the words inside it, exactly as HTML names a control from its contents |
| value | a field's own text, or whatever `.value("62%")` was told |
| state | `.disabled()`, the tab order, and `.selected(true)` |
| structure | which roles contain which — a `Role::Tab` inside a `Role::TabList` |

`button("Restart")` is a button named "Restart" with nothing written to make it
so. A row of a dot, a service's name, and its state is named after the words it
shows. `.label("…")` is needed only where there are no words at all — an icon
button, a switch, a slider drawn with `draw()`:

```rust
draw(Size::new(34.0, 20.0), knob)
    .role(Role::Checkbox)
    .label("Dark appearance")
    .selected(app.dark)
    .on_click(|app: &mut App| app.dark = !app.dark)
```

Structure comes from containment rather than from declaration: `tabs()` builds a
`TabList` of `Tab`s, so each one knows it is the second of three without anyone
counting. Selection is stated with `.selected(true)` and never inferred from a
colour, because a colour is not a semantic.

**One path from intent to handler.** An activation from an assistive technology
resolves an `Id` to a node and runs the same `on_click` a mouse would; there is
no second dispatch, so an interface cannot behave one way for a screen reader
and another for a pointer.

**What is pushed to the platform is a difference, not a tree.** Each frame's
nodes are compared with the last frame's and only what changed is sent — the
same decision as presenting a frame only when its pixels differ, for the same
reason: compare the finished result rather than tracking what you think is
dirty.

And it is enforced rather than promised. `harness.assert_accessible()` fails on
a clickable element with no role, an interactive one with no name, a tab outside
a tab list, or two siblings sharing an identity; `assert_tab_order()` fails if
Tab stops walking the interface the way it is written.
`tests/accessibility.rs` runs both over every example, and `tests/recipes.rs`
runs them over every hand-built control, so the convention breaks the build the
moment somebody adds a widget in a hurry.

## Testing an interface

An interface is only as good as the confidence that it does what it looks like
it does, and that confidence has to be cheap or nobody buys any.

`rui::testing::Harness` drives the *real* frame — describe, lay out, draw, apply
— into a buffer instead of onto a screen. It is not a second, simpler path that
could come to disagree with the window's; the window's loop and the harness call
the same function.

```rust
use rui::testing::Harness;

let mut harness = Harness::new(Counter { count: 0 }, view);

harness.click_text("Increment");
assert_eq!(harness.state().count, 1);
assert!(harness.frame().shows("1"));
```

It can aim at what a person would aim at (`click_text`, `hover_text`), drive
anything else (`drag`, `key`, `type_text`, `scroll`, `tab`), ask where things
came out (`rect_of`, `probes`), ask what the interface says (`text`, `shows`),
and ask what was actually drawn (`pixel`, `marked`, `save_png`).

Two decisions elsewhere make this work. Nothing reads a clock — `Memory` is
*told* how long a frame took — so an animation is stepped rather than waited
for, and `harness.frames(60)` is a second of easing. And everything is drawn
here, so a frame needs no display.

The library deliberately carries no font, because a program should use the
desktop's. A test cannot: its numbers would depend on which machine ran it. So
`rui::testing::font` **builds** one — a real TrueType file, assembled a table at
a time and read back by the same parser that reads one off the disk. Every glyph
is half an em wide and a line is exactly one em, so a width in a test is
arithmetic rather than a number pasted back from a run:

```rust
assert_eq!(harness.rect_of("abcd").unwrap().w, 20.0);   // four characters at ten units
```

And a description is a value whose handlers are ordinary functions, so what an
interface *offers* is assertable with no frame at all:

```rust
let element = actions("mongod", &ServiceState::Stopped);
assert!(!element.child(0).unwrap().is_disabled());
(element.child(0).unwrap().click_action().unwrap())(&mut app);
assert_eq!(app.commands, [Command::Start("mongod".into())]);
```

## What is underneath

Everything, and nothing else. The crate has no dependencies: the TrueType
parser, the glyph rasteriser, the antialiasing, the text layout, the PNG writer,
and the platform windows are all here. An interface renders identically on macOS,
Windows, and X11 because the same code drew it.

| module | what |
|---|---|
| `element`, `widgets` | the description |
| `style` | lengths, roles, alignment, radii |
| `accessibility` | what the description means, and the diff the platform is pushed |
| `layout` | how room is divided |
| `paint` | drawing it, and working out what it was told |
| `canvas`, `font`, `text`, `color`, `geom` | the renderer |
| `image` | writing a frame out as a PNG |
| `shell` | the window, and the loop |
| `testing` | driving all of it with no window |

### Text, and where it stops

Every path through text — measuring, fitting, wrapping, drawing — walks one
advance function, so a run can never be fitted to one width and drawn at
another. Tab stops, tracking, and **pair kerning** all live in that one place;
the adjustments come from a face's `kern` table or its `GPOS` `kern` feature,
so `AV` closes up the way the face's designer intended.

Anywhere text is *cut* — a caret, a wrapped line, an ellipsis — the unit is a
**grapheme cluster** rather than a `char`, so a caret steps over a letter and
its accent together and a line never breaks a flag in half. The cluster rules
are a stated subset of UAX #29: combining marks, joined emoji, regional
indicator pairs, and variation selectors, written out by hand because this
crate carries no data it did not write. Brahmic scripts and Hangul spelled out
as separate jamo are **not** covered and will cluster wrongly;
`src/text/grapheme.rs` says exactly what is in and what is out.

What is genuinely missing is shaping. One character still becomes one glyph, so
there are no ligatures, no bidirectional reordering, and no Arabic or
Devanagari. That is a HarfBuzz-sized body of work, and the limit is stated here
rather than approximated in the renderer.

`unsafe` is confined to `shell/platform/`, one file per platform, each of which
does five things: open a window, say how big it is, say whether the desktop is
light or dark, hand over events, and copy a buffer of pixels onto the screen.
Nothing above that line contains any.

## The loop

Wait for input, draw the whole interface, and present it only if it came out
different from the last frame — a comparison rather than a dirty-region scheme,
because a system that works out which region to repaint can work it out wrongly,
and the symptom is a stale pixel still showing something that is no longer true.

While anything is animating the loop comes back within 8 ms; once everything has
settled it waits `App::idle_timeout`, and a window nobody is touching costs
nothing. Animation advances by *elapsed time*, and the library reads no clock —
it is told how long the last frame took, which is what makes an animation
assertable in a test.

## Using it

```toml
[dependencies]
rui = { git = "https://github.com/RockyWearsAHat/rui" }
```

Rust 1.85 or later, for the 2024 edition. macOS, Windows, and X11.

## Licence

MIT.
