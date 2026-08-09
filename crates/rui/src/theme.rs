//! The colours, spacing, and type sizes everything is drawn from.
//!
//! Nothing below this module chooses a colour or a size for itself. A widget
//! that hard-codes a grey is one the appearance cannot be changed under, and
//! the console has to look right in both a light and a dark desktop.
//!
//! The palette is deliberately small. Every surface is one of three greys, every
//! piece of text is one of three inks, and status is one of four hues with a
//! matching tint behind it. A larger palette does not make an interface look
//! better; it makes two parts of it disagree about what "the border colour" is.
//!
//! # An application supplies its own
//!
//! [`Theme::new`] is the one this library would choose, not the only one there
//! is. An application hands its own to [`App::theme`](crate::App::theme) — a
//! function of the appearance rather than a value, because the desktop can turn
//! the lights out under a running window and a theme is *derived* from that.
//! Everything below reads whatever comes back, so a supplied palette, a supplied
//! set of metrics, and a supplied [`CornerStyle`] reach every widget without one
//! of them being touched.

use crate::canvas::Corner;
use crate::color::Color;
use crate::text::{FontId, TextStyle};

/// Whether the desktop is light or dark.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Appearance {
    /// Dark text on light surfaces.
    Light,
    /// Light text on dark surfaces.
    Dark,
}

/// The colours of one appearance.
///
/// Each status hue comes in a pair: the saturated one is for text and icons, and
/// the `_tint` behind it is what a tag or a banner is filled with. Keeping them
/// together is what stops a green being paired with the wrong green.
///
/// # Surfaces are a pair, not a colour
///
/// [`Palette::surface`] is the *top* of a panel and [`Palette::surface_deep`] is
/// its bottom. The shift between them is very small — a couple of values, not a
/// visible gradient. It is there so a large panel does not read as one flat
/// stamp of colour, and it is kept subtle because a panel that is visibly
/// shaded down its height is a panel wearing a texture.
///
/// The two are kept side by side here so no view can pick a top without the
/// bottom that belongs to it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Palette {
    /// The window's own background, behind every panel.
    pub background: Color,
    /// The background at the bottom of the window; see the type's own notes.
    pub background_deep: Color,
    /// The top edge of a panel, card, or row that sits on the background.
    pub surface: Color,
    /// The bottom edge of that panel.
    pub surface_deep: Color,
    /// The hairline along a panel's top edge that catches the light.
    ///
    /// One line, one value lighter than the surface under it. It is what makes
    /// an edge read as an edge rather than as where a fill happens to stop.
    pub sheen: Color,
    /// A surface lifted above another one — a hovered row, a raised control.
    pub raised: Color,
    /// A surface pushed in — a pressed control, a text field's well.
    pub sunken: Color,
    /// Hairlines and panel outlines.
    pub border: Color,
    /// A border that has the keyboard's attention.
    pub border_focus: Color,
    /// Primary text.
    pub text: Color,
    /// Secondary text: labels, units, explanations.
    pub text_muted: Color,
    /// Text on top of [`Palette::accent`].
    pub text_on_accent: Color,
    /// The one saturated colour, for the primary action and for selection.
    pub accent: Color,
    /// The accent's darker end, for shading a filled control down its height.
    pub accent_deep: Color,
    /// The accent's lighter end, for the top of the same shading.
    ///
    /// Held separately rather than derived by lightening the accent, because the
    /// two appearances need it at different strengths: a light theme's accent is
    /// already dark enough that a small lift shows, and a dark theme's is not.
    pub accent_light: Color,
    /// Healthy.
    pub ok: Color,
    /// Healthy, as a fill.
    pub ok_tint: Color,
    /// Needs attention, but is not broken.
    pub warn: Color,
    /// Needs attention, as a fill.
    pub warn_tint: Color,
    /// Broken.
    pub bad: Color,
    /// Broken, as a fill.
    pub bad_tint: Color,
    /// Not running, and not expected to be.
    pub idle: Color,
    /// Not running, as a fill.
    pub idle_tint: Color,
    /// What a panel's shadow is cast in.
    ///
    /// Always a black at low alpha — a shadow is the absence of light, so it is
    /// never a hue. It is a palette entry rather than a constant because how
    /// much of it survives differs by appearance: on a white ground a soft grey
    /// shadow is what lifts a panel, and on a dark one the same alpha is a
    /// smudge, so the dark theme casts a fainter one.
    pub shadow: Color,
}

impl Palette {
    /// The light palette.
    ///
    /// Near-neutral greys, barely cooled, on which the accent is the only
    /// saturated thing. A white panel on a light grey window, separated by a
    /// hairline and a soft shadow — which is what every desktop the console runs
    /// on already looks like, and looking like the desktop is the point.
    pub const LIGHT: Self = Self {
        background: Color::rgb(0xf2, 0xf3, 0xf5),
        background_deep: Color::rgb(0xea, 0xeb, 0xee),
        surface: Color::rgb(0xff, 0xff, 0xff),
        surface_deep: Color::rgb(0xfa, 0xfb, 0xfc),
        sheen: Color::rgb(0xff, 0xff, 0xff),
        raised: Color::rgb(0xf0, 0xf1, 0xf4),
        sunken: Color::rgb(0xf4, 0xf5, 0xf7),
        border: Color::rgb(0xd8, 0xda, 0xde),
        border_focus: Color::rgb(0x25, 0x63, 0xd4),
        text: Color::rgb(0x1a, 0x1c, 0x1f),
        text_muted: Color::rgb(0x61, 0x65, 0x6b),
        text_on_accent: Color::rgb(0xff, 0xff, 0xff),
        accent: Color::rgb(0x25, 0x63, 0xd4),
        accent_deep: Color::rgb(0x1a, 0x4f, 0xb0),
        accent_light: Color::rgb(0x5b, 0x8e, 0xf0),
        ok: Color::rgb(0x12, 0x7a, 0x45),
        ok_tint: Color::rgb(0xe3, 0xf5, 0xea),
        warn: Color::rgb(0x8a, 0x5a, 0x00),
        warn_tint: Color::rgb(0xfd, 0xf0, 0xd8),
        bad: Color::rgb(0xb3, 0x24, 0x3f),
        bad_tint: Color::rgb(0xfc, 0xe7, 0xea),
        idle: Color::rgb(0x61, 0x65, 0x6b),
        idle_tint: Color::rgb(0xec, 0xee, 0xf1),
        shadow: Color::rgba(0x0a, 0x0c, 0x10, 0x1f),
    };

    /// The dark palette.
    ///
    /// # What the values are chosen against
    ///
    /// The same interface with the lights off, not a second design. The greys
    /// are near-neutral with the faintest cool cast, and a panel sits a clear
    /// step *above* the window rather than a hair above it — in the dark, value
    /// is the only separation that works, and a panel distinguished from its
    /// background by an outline alone is a rectangle someone drew.
    ///
    /// The accent is a blue. It is the one hue none of the four status colours
    /// is near, so the primary action can never be mistaken for a health signal,
    /// and it is the colour a desktop's own selection is in.
    pub const DARK: Self = Self {
        background: Color::rgb(0x17, 0x18, 0x1a),
        background_deep: Color::rgb(0x13, 0x14, 0x16),
        surface: Color::rgb(0x22, 0x24, 0x27),
        surface_deep: Color::rgb(0x1e, 0x20, 0x23),
        sheen: Color::rgb(0x2e, 0x31, 0x34),
        raised: Color::rgb(0x2b, 0x2e, 0x32),
        sunken: Color::rgb(0x13, 0x14, 0x16),
        border: Color::rgb(0x34, 0x38, 0x3d),
        border_focus: Color::rgb(0x4f, 0x8f, 0xf7),
        text: Color::rgb(0xe8, 0xea, 0xed),
        text_muted: Color::rgb(0x9a, 0xa0, 0xa6),
        text_on_accent: Color::rgb(0xff, 0xff, 0xff),
        accent: Color::rgb(0x4f, 0x8f, 0xf7),
        accent_deep: Color::rgb(0x3a, 0x6f, 0xd0),
        accent_light: Color::rgb(0x7a, 0xa9, 0xfa),
        ok: Color::rgb(0x3f, 0xb7, 0x65),
        ok_tint: Color::rgb(0x16, 0x28, 0x1c),
        warn: Color::rgb(0xe8, 0xa3, 0x3d),
        warn_tint: Color::rgb(0x2e, 0x23, 0x13),
        bad: Color::rgb(0xf0, 0x59, 0x6e),
        bad_tint: Color::rgb(0x2f, 0x15, 0x19),
        idle: Color::rgb(0x9a, 0xa0, 0xa6),
        idle_tint: Color::rgb(0x26, 0x28, 0x2b),
        shadow: Color::rgba(0x00, 0x00, 0x00, 0x38),
    };

    /// Fails unless every pairing this palette puts on screen is legible.
    ///
    /// The contrast law, asserted as real WCAG ratios through
    /// [`Color::contrast_ratio`] rather than as channel deltas: primary text
    /// carries at least 7:1 against the window, secondary text at least 4.45:1,
    /// each status ink at least 4.5:1 on its own tint (idle at least 2.3:1),
    /// and the focus ring at least 3:1 against the surface it rings. A dark
    /// palette must also stack its surfaces in ascending value —
    /// `background_deep`, `background`, `surface`, `raised` — because in the
    /// dark, value is the only separation that works.
    ///
    /// `name` names the palette in the failure, so a battery run over several
    /// palettes says which one regressed.
    ///
    /// Two thresholds are tuned to the palettes this workspace ships rather
    /// than to the WCAG figures they started from — the palettes are the law
    /// here, and the thresholds hold the line exactly where they stand:
    /// secondary text at 4.45 because the console's THEATRE palette lands its
    /// muted ink at 4.49, and idle at 2.3 because idle is the one status that
    /// reports nothing and is quiet on purpose — THEATRE holds it at 2.35, and
    /// demanding more would light every stopped service.
    ///
    /// Public so an application that supplies its own palette through
    /// [`Theme::with_palette`] can hold it to the same law from its own tests.
    pub fn assert_legible(&self, name: &str) {
        /// Primary text against the window: WCAG AAA for body text.
        const TEXT: f32 = 7.0;
        /// Secondary text against the window; see the tuning note above.
        const MUTED: f32 = 4.45;
        /// A status ink on its own tint: WCAG AA for its small capitals.
        const STATUS: f32 = 4.5;
        /// The idle ink on its tint; see the tuning note above.
        const IDLE: f32 = 2.3;
        /// The focus ring against a surface: WCAG's floor for a UI boundary.
        const FOCUS: f32 = 3.0;

        let holds = |ink: Color, ground: Color, floor: f32, what: &str| {
            let ratio = ink.contrast_ratio(ground);
            assert!(ratio >= floor, "{name}: {what} carries {ratio:.2}:1 and needs {floor}:1");
        };
        holds(self.text, self.background, TEXT, "primary text on the window");
        holds(self.text_muted, self.background, MUTED, "secondary text on the window");
        holds(self.ok, self.ok_tint, STATUS, "the ok ink on its own tint");
        holds(self.warn, self.warn_tint, STATUS, "the warn ink on its own tint");
        holds(self.bad, self.bad_tint, STATUS, "the bad ink on its own tint");
        holds(self.idle, self.idle_tint, IDLE, "the idle ink on its own tint");
        holds(self.border_focus, self.surface, FOCUS, "the focus ring on a surface");

        if self.background.luminance() < 0.5 {
            let ladder = [
                (self.background_deep, self.background, "the background is not above its deep end"),
                (self.background, self.surface, "a surface is not above the background"),
                (self.surface, self.raised, "raised is not above the surface it lifts from"),
            ];
            for (below, above, what) in ladder {
                assert!(below.luminance() < above.luminance(), "{name}: {what}");
            }
        }
    }
}

/// The sizes the layout is built from, in logical units.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Metrics {
    /// The gap between related things.
    pub gap_small: f32,
    /// The gap between things in a list.
    pub gap: f32,
    /// The gap between sections.
    pub gap_large: f32,
    /// Padding inside a panel.
    pub padding: f32,
    /// How far a panel's corner treatment runs along each edge it meets.
    ///
    /// A size, not a shape: which shape it is belongs to [`Theme::corner`], so
    /// that the whole interface's character is one word in one place.
    pub corner: f32,
    /// The same, for a control.
    pub corner_small: f32,
    /// Height of a button or a text field.
    pub control_height: f32,
    /// Height of one row in a list or table.
    pub row_height: f32,
    /// Thickness of a hairline, in logical units.
    ///
    /// Not one pixel: on a HiDPI display a one-pixel line is invisibly thin, and
    /// on an ordinary one this rounds to the single pixel it should be.
    pub hairline: f32,
    /// Width of a scroll bar.
    pub scrollbar: f32,
    /// How far a panel's shadow is blurred beyond the panel casting it.
    pub shadow: f32,
    /// How far that shadow is offset downward.
    ///
    /// Non-zero, and small. A shadow cast evenly in every direction is a glow;
    /// what says a panel is lying on the window rather than hovering over it is
    /// that the light comes from above, so there is more shadow below than above.
    pub shadow_offset: f32,
    /// How long an eased value takes to close most of its remaining distance.
    ///
    /// One number for the whole interface. Long enough to be seen as motion
    /// rather than as a flicker, short enough that a control still feels
    /// attached to the pointer — past about a fifth of a second a hover starts
    /// to feel like lag rather than like polish.
    pub motion: f32,
}

impl Metrics {
    /// The one set of measurements the console is drawn with.
    ///
    /// # Why these are tight
    ///
    /// This is an instrument panel, not a document. The operator is comparing
    /// several services at once and reading a log while they do it, so what the
    /// spacing has to buy is *how much is on screen together* — a fact that has
    /// scrolled away is a fact nobody is comparing. Generous padding reads as
    /// considered on one card and as a waste of the window on twenty rows of
    /// them, and it is the reason the smallest window the backend allows used to
    /// push the whole log pane off the bottom edge.
    pub const DEFAULT: Self = Self {
        gap_small: 4.0,
        gap: 8.0,
        gap_large: 16.0,
        padding: 12.0,
        corner: 8.0,
        corner_small: 5.0,
        control_height: 28.0,
        row_height: 22.0,
        hairline: 1.0,
        scrollbar: 8.0,
        shadow: 9.0,
        shadow_offset: 1.5,
        motion: 0.09,
    };
}

/// Which shape every framed thing's corners take.
///
/// The whole interface's character in one word. A rounded corner is the corner
/// of a card, and a card is a piece of paper; a corner cut at forty-five degrees
/// is what a panel bolted into a rack looks like. [`Canvas`](crate::Canvas)
/// draws the two for the same cost, so which one an interface is made of is a
/// decision and never a limitation — see that module's notes.
///
/// Held apart from [`Metrics`], which says how *far* a corner treatment runs
/// along the edges it meets. A size is not a shape, and keeping them separate is
/// what lets a panel and a control share one character at two sizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CornerStyle {
    /// A quarter-circle: a card, a document, the desktop's own look.
    Round,
    /// A forty-five degree chamfer: an instrument, a machined panel.
    Cut,
    /// A right angle, at any size.
    Square,
}

impl CornerStyle {
    /// This shape, running `size` units along each edge it meets.
    pub fn at(self, size: f32) -> Corner {
        match self {
            Self::Round => Corner::Round(size),
            Self::Cut => Corner::Cut(size),
            Self::Square => Corner::Square,
        }
    }
}

/// A palette, a set of measurements, a corner shape, and the faces text is
/// drawn in.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    /// The colours.
    pub palette: Palette,
    /// The sizes.
    pub metrics: Metrics,
    /// What shape every framed thing's corners take; see [`Theme::corner`].
    pub corners: CornerStyle,
    /// The proportional face, for prose and labels.
    pub ui_font: FontId,
    /// The fixed-width face, for anything the machine produced.
    pub mono_font: FontId,
}

impl Theme {
    /// The theme for an appearance, drawn with these two faces.
    ///
    /// What an application gets when it supplies none, and the ground an
    /// application that supplies one usually starts from — see
    /// [`Theme::with_corners`] and [`App::theme`](crate::App::theme).
    pub fn new(appearance: Appearance, ui_font: FontId, mono_font: FontId) -> Self {
        Self {
            palette: match appearance {
                Appearance::Light => Palette::LIGHT,
                Appearance::Dark => Palette::DARK,
            },
            metrics: Metrics::DEFAULT,
            corners: CornerStyle::Round,
            ui_font,
            mono_font,
        }
    }

    /// The same theme, with every framed thing's corners taking `corners`.
    ///
    /// The one call that changes what the interface *is*, from the one place
    /// that decides it:
    ///
    /// ```ignore
    /// App::new("Console", state, view)
    ///     .theme(|appearance, ui, mono| {
    ///         Theme::new(appearance, ui, mono).with_corners(CornerStyle::Cut)
    ///     })
    /// ```
    ///
    /// Every panel, button, field, and tag follows, because all of them take
    /// their shape from [`Theme::corner`] and none of them names one.
    pub fn with_corners(mut self, corners: CornerStyle) -> Self {
        self.corners = corners;
        self
    }

    /// The same theme, drawn in `palette`.
    ///
    /// The other half of what [`App::theme`](crate::App::theme) is for: a
    /// program whose subject wants a character of its own supplies the colours
    /// and keeps everything else this theme decided — the metrics, the corner
    /// shape, and the type scale — rather than restating them to change one.
    ///
    /// ```ignore
    /// App::new("Console", state, view)
    ///     .theme(|appearance, ui, mono| {
    ///         Theme::new(appearance, ui, mono).with_palette(HUD)
    ///     })
    /// ```
    ///
    /// Which appearance the result *is* follows from the palette rather than
    /// from what it was built with; see [`Theme::is_dark`].
    pub fn with_palette(mut self, palette: Palette) -> Self {
        self.palette = palette;
        self
    }

    /// Whether this theme is the dark one.
    ///
    /// Asked from the palette rather than stored, so a hand-built palette
    /// answers correctly instead of according to a flag nobody updated.
    pub fn is_dark(&self) -> bool {
        self.palette.background.luminance() < 0.5
    }

    /// The shape every panel, pane, and framed region's corners take.
    ///
    /// [`Theme::corners`] at the panel size, and this is the one place that
    /// decides it. It is [`CornerStyle::Round`] by default. An earlier revision
    /// cut the corners at forty-five degrees on the argument that a console is
    /// an instrument rather than a document, and a chamfered panel is the corner
    /// of something bolted into a rack. The argument was sound and the result
    /// was not: a chamfer is a costume. Repeated on every panel, button, field,
    /// and tag it stops reading as *this program is about a machine* and starts
    /// reading as *this program is pretending to be from a film*, which is the
    /// one thing a tool somebody uses every day must never look like.
    ///
    /// A radius is what the desktop underneath already uses, on all three
    /// platforms, and there is no credit for disagreeing with it. That is a
    /// default and not a law: a program whose whole subject *is* a machine may
    /// mean the chamfer, and says so once with [`Theme::with_corners`] rather
    /// than widget by widget. Every framed thing takes its shape from here
    /// either way, so the interface's character stays one word in one place.
    pub fn corner(&self) -> Corner {
        self.corners.at(self.metrics.corner)
    }

    /// The same, for a control: a button, a field, a tag.
    ///
    /// Smaller rather than a different shape, because a control whose corners
    /// disagree with the panel around it reads as borrowed from another program.
    pub fn corner_small(&self) -> Corner {
        self.corners.at(self.metrics.corner_small)
    }

    /// The window's title, and the name of whatever a pane is about.
    ///
    /// Set in the proportional face, solid. An earlier revision set it in the
    /// fixed-width one and opened it up, so that a title read as a *designation*
    /// rather than as an application's name. What it actually read as was a
    /// terminal, and once the title, the tabs, the headings, and the figures
    /// were all monospaced the whole window did — which is a costume, not a
    /// character. The fixed-width face is now reserved for what it is genuinely
    /// for: text the machine produced, where a column has to line up and `l` has
    /// to tell itself from `1`.
    ///
    /// Not uppercased, and not asking callers to uppercase: a title here is
    /// often a service's own name, and shouting `MongoDB` back as `MONGODB` is
    /// worse than leaving it alone.
    pub fn title(&self) -> TextStyle {
        TextStyle::new(self.ui_font, 15.0, self.palette.text)
    }

    /// A section heading: small capitals, opened up slightly.
    ///
    /// Small and muted because a heading labels the block under it — OUTPUT,
    /// DEFINITION, SERVICES — and should sit behind the values it introduces
    /// rather than compete with them. Capitals at this size pack into a block in
    /// a face spaced for lower case, so they are tracked open a little; that is
    /// what makes a small label legible rather than merely small.
    ///
    /// Callers pass the text already in capitals rather than this uppercasing
    /// it, because a heading is sometimes a name — and lower-casing a service
    /// called `MongoDB` to shout it back is worse than leaving it alone.
    pub fn heading(&self) -> TextStyle {
        TextStyle::new(self.ui_font, 10.5, self.palette.text_muted).tracked(0.9)
    }

    /// Ordinary text.
    pub fn body(&self) -> TextStyle {
        TextStyle::new(self.ui_font, 13.0, self.palette.text)
    }

    /// Ordinary text, emphasised by being the primary ink at a larger size.
    pub fn body_strong(&self) -> TextStyle {
        TextStyle::new(self.ui_font, 13.5, self.palette.text)
    }

    /// Secondary text: units, explanations, timestamps.
    pub fn caption(&self) -> TextStyle {
        TextStyle::new(self.ui_font, 11.5, self.palette.text_muted)
    }

    /// The reading a summary strip is making: a count, or the line of words
    /// that is the whole report.
    ///
    /// The largest size in the scale, and what that size is *for* is the one
    /// thing on a strip that the rest of the strip explains. Usually that is a
    /// number; it is as readily a sentence, and a strip whose sentence were set
    /// smaller than the figures under it would be reporting its evidence louder
    /// than its finding.
    ///
    /// Proportional and solid. Monospaced digits are worth their awkwardness in
    /// a *column* of numbers, where a count crossing from nine to ten would
    /// otherwise shuffle the rows sideways. A reading in a strip lines up with
    /// nothing — so all the fixed-width face bought here was the look of a
    /// terminal readout.
    pub fn figure(&self) -> TextStyle {
        TextStyle::new(self.ui_font, 21.0, self.palette.text)
    }

    /// Anything the machine produced: addresses, paths, log output.
    pub fn mono(&self) -> TextStyle {
        TextStyle::new(self.mono_font, 11.5, self.palette.text)
    }

    /// A machine's state, set as a word: `RUNNING`, `BACKOFF`, `CANNOT START`.
    ///
    /// The one style for a state wherever it appears — inside a [`tag`](crate::widgets::tag), or
    /// bare at the end of a row where a tag's chrome would cost more width than
    /// the row can spare. Callers colour it with the status's own hue and pass
    /// the text already capitalised.
    ///
    /// Tracked, but less than [`Theme::heading`] is. Both are small capitals,
    /// and the difference is what they are competing with: a heading sits alone
    /// on its rule and can afford the room, while a state sits at the end of a
    /// line whose *other* half is a service's name — and every unit spent
    /// opening this out is a unit taken off the name, which is the part that
    /// tells one row from another.
    pub fn state(&self) -> TextStyle {
        TextStyle::new(self.ui_font, 10.5, self.palette.text_muted).tracked(0.4)
    }

    /// The smallest readable mark: a gutter number, a unit, a tick's label.
    ///
    /// Distinct from [`Theme::caption`] rather than a smaller copy of it, so the
    /// two cannot drift: a caption is a sentence a person reads, and this is a
    /// figure they scan past. It is fixed-width because everything it is used
    /// for is a number that should line up down a column.
    pub fn micro(&self) -> TextStyle {
        TextStyle::new(self.mono_font, 9.5, self.palette.text_muted)
    }

    /// The ink and the fill a status is drawn with: a tag, a tick, a strip.
    pub fn status(&self, status: Status) -> (Color, Color) {
        match status {
            Status::Ok => (self.palette.ok, self.palette.ok_tint),
            Status::Warn => (self.palette.warn, self.palette.warn_tint),
            Status::Bad => (self.palette.bad, self.palette.bad_tint),
            Status::Idle => (self.palette.idle, self.palette.idle_tint),
        }
    }
}

/// How something is doing, in the four ways the palette can show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// Working.
    Ok,
    /// Working, but something wants looking at.
    Warn,
    /// Not working.
    Bad,
    /// Not running, and not meant to be.
    Idle,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A theme with no faces loaded: what is asserted here is colour and size,
    /// neither of which needs a font to be present.
    fn theme(appearance: Appearance) -> Theme {
        Theme::new(appearance, FontId::FIRST, FontId::FIRST)
    }

    #[test]
    fn the_dark_theme_knows_it_is_dark() {
        assert!(theme(Appearance::Dark).is_dark());
        assert!(!theme(Appearance::Light).is_dark());
    }

    #[test]
    fn both_built_in_palettes_pass_the_contrast_law() {
        // The whole battery — text at 7:1, secondary at 4.45:1, status inks on
        // their tints, the focus ring at 3:1, and the dark surface ladder — as
        // real WCAG ratios rather than the channel deltas that stood here
        // before. The same call an application runs over its own palette.
        Palette::LIGHT.assert_legible("LIGHT");
        Palette::DARK.assert_legible("DARK");
    }

    #[test]
    fn every_status_ink_clears_wcag_on_its_own_tint() {
        // Stated by ratio as well as by the battery, so a loosened battery
        // threshold cannot quietly take this with it: the three states that
        // report something clear 4.5:1 in both appearances.
        for appearance in [Appearance::Light, Appearance::Dark] {
            let theme = theme(appearance);
            for status in [Status::Ok, Status::Warn, Status::Bad] {
                let (ink, fill) = theme.status(status);
                let ratio = ink.contrast_ratio(fill);
                assert!(ratio >= 4.5, "{appearance:?} {status:?} is {ratio:.2}:1 on its tint");
            }
        }
    }

    #[test]
    fn the_dark_surfaces_climb_from_the_window_floor_to_what_is_raised() {
        // Radix's ordering rule, asserted directly: in the dark, elevation is
        // lightness, so the four grounds must ascend or a raised row would sink.
        let palette = Palette::DARK;
        assert!(palette.background_deep.luminance() < palette.background.luminance());
        assert!(palette.background.luminance() < palette.surface.luminance());
        assert!(palette.surface.luminance() < palette.raised.luminance());
    }

    #[test]
    fn the_battery_rejects_an_illegible_palette() {
        // The law only guards anything if breaking it fails: a palette whose
        // muted ink is its own background must not pass.
        let broken = Palette { text_muted: Palette::DARK.background, ..Palette::DARK };
        let failed = std::panic::catch_unwind(|| broken.assert_legible("broken"));
        assert!(failed.is_err(), "an illegible palette passed the battery");
    }

    #[test]
    fn accent_text_is_legible_on_the_accent() {
        for appearance in [Appearance::Light, Appearance::Dark] {
            let palette = theme(appearance).palette;
            let contrast =
                (palette.text_on_accent.luminance() - palette.accent.luminance()).abs();
            assert!(contrast > 0.3, "{appearance:?} accent text is illegible");
        }
    }

    #[test]
    fn a_surface_shades_away_from_the_light_in_both_appearances() {
        // Light comes from above, so a surface is lighter at its top than at its
        // bottom whichever appearance is in force. Getting this backwards in one
        // of the two is what makes a panel look pressed into the window instead
        // of laid on it.
        for appearance in [Appearance::Light, Appearance::Dark] {
            let palette = theme(appearance).palette;
            assert!(
                palette.surface.luminance() > palette.surface_deep.luminance(),
                "{appearance:?} shades its surfaces the wrong way up"
            );
            assert!(
                palette.background.luminance() > palette.background_deep.luminance(),
                "{appearance:?} shades its background the wrong way up"
            );
        }
    }

    #[test]
    fn a_surface_is_shaded_subtly_rather_than_visibly_striped() {
        // Enough to read as material, little enough that nobody sees a gradient.
        for appearance in [Appearance::Light, Appearance::Dark] {
            let palette = theme(appearance).palette;
            let shift = palette.surface.luminance() - palette.surface_deep.luminance();
            assert!(shift < 0.06, "{appearance:?} surfaces are visibly striped");
        }
    }

    #[test]
    fn the_accent_shades_from_light_to_deep() {
        // Light comes from above for the accent as much as for a grey surface,
        // so a filled control's three values have to run in that order.
        for appearance in [Appearance::Light, Appearance::Dark] {
            let palette = theme(appearance).palette;
            assert!(
                palette.accent_light.luminance() > palette.accent.luminance(),
                "{appearance:?} lightens its accent the wrong way"
            );
            assert!(
                palette.accent.luminance() > palette.accent_deep.luminance(),
                "{appearance:?} shades a filled control the wrong way up"
            );
        }
    }

    #[test]
    fn a_shadow_is_black_and_barely_there() {
        // A shadow is the absence of light. Given a hue it reads as a coloured
        // haze around the panel — which is the glow this design was rid of, back
        // under another name.
        for appearance in [Appearance::Light, Appearance::Dark] {
            let shadow = theme(appearance).palette.shadow;
            assert!(
                shadow.luminance() < 0.1,
                "{appearance:?} casts a shadow that is not a black"
            );
            assert!(shadow.a < 0x60, "{appearance:?} casts a shadow hard enough to be seen as one");
        }
    }

    #[test]
    fn the_accent_is_not_near_any_status_colour() {
        // The primary action must never be mistakable for a health signal, which
        // is the whole reason the accent is a cyan.
        let palette = theme(Appearance::Dark).palette;
        let distance = |a: Color, b: Color| {
            let channel = |x: u8, y: u8| (x as f32 - y as f32).powi(2);
            (channel(a.r, b.r) + channel(a.g, b.g) + channel(a.b, b.b)).sqrt()
        };
        for status in [palette.ok, palette.warn, palette.bad] {
            assert!(
                distance(palette.accent, status) > 90.0,
                "the accent is too close to a status colour to be told apart"
            );
        }
    }

    #[test]
    fn motion_is_quick_enough_to_feel_attached_to_the_pointer() {
        let metrics = Metrics::DEFAULT;
        assert!(metrics.motion > 0.0, "a zero would make every animation a jump");
        assert!(metrics.motion < 0.2, "past a fifth of a second a hover reads as lag");
    }

    #[test]
    fn the_type_scale_ascends() {
        let theme = theme(Appearance::Light);
        assert!(theme.micro().size < theme.caption().size);
        assert!(theme.caption().size < theme.body().size);
        assert!(theme.body().size < theme.body_strong().size);
        assert!(theme.body_strong().size < theme.title().size);
        assert!(theme.title().size < theme.figure().size);
    }

    #[test]
    fn the_fixed_width_face_is_reserved_for_what_the_machine_produced() {
        // The rule that keeps the console from reading as a terminal. Only text
        // the machine wrote — a path, a log line, a gutter number — is set in
        // the face that lines up down a column. Everything the *interface* says
        // about itself is set in the desktop's own face; a monospaced title,
        // heading, and figure together are what made this look like a costume.
        let theme = theme(Appearance::Light);
        for style in [theme.mono(), theme.micro()] {
            assert_eq!(style.font, theme.mono_font);
        }
        for style in [theme.title(), theme.heading(), theme.figure(), theme.state()] {
            assert_eq!(style.font, theme.ui_font, "interface chrome is not machine output");
        }
        assert_eq!(theme.body().font, theme.ui_font);
    }

    #[test]
    fn only_small_capitals_are_opened_up() {
        // Tracking exists here for one thing: capitals at ten pixels in a face
        // spaced for lower case, which pack into a block without it. Everything
        // else is set solid. Applied to mixed case it reads as a title sequence,
        // and that — spread across the title, the tabs, and the figures — was
        // half of what made this interface look like a prop.
        let theme = theme(Appearance::Dark);
        for style in [theme.heading(), theme.state()] {
            assert!(style.tracking > 0.0, "small capitals pack without it");
        }
        for style in
            [theme.title(), theme.figure(), theme.body(), theme.body_strong(), theme.caption(), theme.mono()]
        {
            assert_eq!(style.tracking, 0.0, "mixed case and running text are set solid");
        }
        assert!(
            theme.heading().tracking > theme.state().tracking,
            "a heading sits alone on its rule and can afford more room than a state at the end of a line"
        );
    }

    #[test]
    fn every_framed_thing_takes_the_same_corner_shape() {
        // The interface's whole character. A control whose corners disagree with
        // the panel around it reads as borrowed from another program, so the two
        // sizes must never disagree about which shape they are.
        let theme = theme(Appearance::Dark);
        assert!(matches!(theme.corner(), Corner::Round(_)));
        assert!(matches!(theme.corner_small(), Corner::Round(_)));
        assert!(
            theme.corner_small().size() < theme.corner().size(),
            "a control's corner should be the smaller of the two"
        );
    }

    #[test]
    fn a_supplied_corner_shape_reaches_both_sizes_and_nothing_else() {
        // The whole point of the shape living on the theme: one word changes
        // what the interface is, and changes nothing about what it says.
        let round = theme(Appearance::Dark);
        let cut = round.with_corners(CornerStyle::Cut);
        assert_eq!(cut.corner(), Corner::Cut(round.metrics.corner));
        assert_eq!(cut.corner_small(), Corner::Cut(round.metrics.corner_small));
        assert_eq!(cut.palette, round.palette, "a corner shape is not a colour");
        assert_eq!(cut.metrics, round.metrics, "nor a size");
    }

    #[test]
    fn a_supplied_palette_reaches_the_theme_and_changes_nothing_else() {
        // The seam an application with a character of its own comes through:
        // the colours are its, and the sizes, the corner shape, and the faces
        // are still the ones it did not restate.
        let library = theme(Appearance::Dark);
        let own = Palette { accent: Color::rgb(0x5f, 0xd9, 0xf2), ..Palette::DARK };
        let supplied = library.with_palette(own);

        assert_eq!(supplied.palette.accent, own.accent);
        assert_eq!(supplied.metrics, library.metrics, "a palette is not a size");
        assert_eq!(supplied.corners, library.corners, "nor a shape");
        assert_eq!(supplied.mono_font, library.mono_font, "nor a face");
    }

    #[test]
    fn which_appearance_a_theme_is_follows_its_palette_and_not_its_maker() {
        // A hand-built palette has to answer for itself, or a light theme
        // supplied to a dark window draws every derived colour the wrong way.
        let dark = theme(Appearance::Light).with_palette(Palette::DARK);
        assert!(dark.is_dark());
    }

    #[test]
    fn a_square_theme_is_square_at_every_size() {
        // The third shape has no size to take, so it must not quietly become a
        // radius of zero that something later grows into a curve.
        let square = theme(Appearance::Light).with_corners(CornerStyle::Square);
        assert_eq!(square.corner(), Corner::Square);
        assert_eq!(square.corner().grown(4.0), Corner::Square);
    }

    #[test]
    fn a_theme_that_says_nothing_about_its_corners_is_the_rounded_one() {
        // The default is a promise: an application that supplies no theme, and
        // one that supplies `Theme::new`, must draw the identical interface.
        assert_eq!(theme(Appearance::Light).corners, CornerStyle::Round);
    }

    #[test]
    fn a_panel_is_separated_from_the_window_by_value_as_well_as_by_its_outline() {
        // An outline alone is a rectangle somebody drew. What says a panel is a
        // panel is that it is a different value from the window behind it, and
        // that its border is a different value again from both.
        for appearance in [Appearance::Light, Appearance::Dark] {
            let palette = theme(appearance).palette;
            let step = (palette.surface.luminance() - palette.background.luminance()).abs();
            assert!(step > 0.02, "{appearance:?} lays its panels on an identical ground");
            let outline =
                (palette.border.luminance() - palette.surface.luminance()).abs();
            assert!(outline > 0.02, "{appearance:?} outlines its panels in their own fill");
        }
    }
}
