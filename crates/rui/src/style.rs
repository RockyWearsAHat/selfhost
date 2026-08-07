//! What an element looks like and how it takes up room: the style half of the
//! language.
//!
//! A [`Style`] is the same idea as a rule in a stylesheet, with two differences
//! that matter. It is attached to the element rather than matched to it by a
//! selector, so what a thing looks like is readable at the place it is written;
//! and every value in it is either a number or a *role*, never a raw colour, so
//! an interface is right in a light desktop and a dark one without being written
//! twice.
//!
//! The same holds for shape. A [`Radius`] names the size of a corner and leaves
//! which shape it is to [`Theme::corner`], so an application that hands the
//! library a theme with a different [`CornerStyle`](crate::CornerStyle) changes
//! every panel, button, field, and tag without touching one of them. There are
//! two ways out of that — [`Radius::Cut`] and [`Radius::None`] — for the single
//! element that is genuinely not what the rest of the interface is, and they
//! carry the same warning [`Tone::Exact`] does.
//!
//! # Inheritance
//!
//! Text properties — the size, the ink, the face, the tracking — are inherited
//! by children that do not set their own, exactly as they are on the web. That
//! is what lets a whole block be quietened with one call on the container rather
//! than the same call on nine labels, and it is the only inheritance there is:
//! nothing about layout or background passes down, because a box that silently
//! inherits its parent's padding is the single most confusing thing a layout
//! engine can do.

use crate::color::Color;
use crate::geom::Insets;
use crate::text::{FontId, TextStyle};
use crate::theme::{Status, Theme};

/// A colour named by the part it plays, resolved against the theme in force.
///
/// Naming the role rather than the colour is what makes one description of an
/// interface correct in both appearances. [`Tone::Exact`] is the way out for the
/// rare thing that genuinely is one colour — a brand mark, a graph series — and
/// a [`Color`] converts into it, so `.fill(Color::rgb(..))` also just works.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tone {
    /// Primary text.
    Text,
    /// Secondary text: labels, units, explanations.
    Muted,
    /// The one saturated colour: the primary action, and selection.
    Accent,
    /// The accent's darker end, for shading a filled control down its height.
    AccentDeep,
    /// The accent's lighter end.
    AccentLight,
    /// Text drawn on top of the accent.
    OnAccent,
    /// The window's own ground.
    Background,
    /// A surface lying on that ground.
    Surface,
    /// The bottom edge of such a surface, for shading it down its height.
    SurfaceDeep,
    /// A surface lifted above another: a hovered row.
    Raised,
    /// A surface pushed in: a field's well, a meter's track.
    Sunken,
    /// Hairlines and outlines.
    Border,
    /// A surface that has been chosen: a selected row, a current tab's ground.
    ///
    /// Derived from the accent rather than named in the palette, because what a
    /// selection is *made of* is the same statement in both appearances — a wash
    /// of the one saturated colour over the surface under it — and a palette
    /// entry per appearance is two chances to make it a different wash.
    Selection,
    /// The outline of whatever has the keyboard.
    Focus,
    /// Healthy.
    Ok,
    /// Needs attention, but is not broken.
    Warn,
    /// Broken.
    Bad,
    /// Not running, and not expected to be.
    Idle,
    /// Healthy, as a fill behind text.
    OkTint,
    /// Needs attention, as a fill.
    WarnTint,
    /// Broken, as a fill.
    BadTint,
    /// Not running, as a fill.
    IdleTint,
    /// What a shadow is cast in.
    Shadow,
    /// Nothing at all.
    Clear,
    /// This exact colour, whatever the theme says.
    Exact(Color),
}

/// How much of the accent a selected surface is washed with.
///
/// Enough that a chosen row is unmistakably the chosen one beside a hovered
/// neighbour, and little enough that the text on it is still read as text on a
/// surface rather than as text on a colour.
const SELECTION_WASH: f32 = 0.14;

impl Tone {
    /// The colour this role takes under `theme`.
    pub fn resolve(self, theme: &Theme) -> Color {
        let palette = theme.palette;
        match self {
            Self::Text => palette.text,
            Self::Muted => palette.text_muted,
            Self::Accent => palette.accent,
            Self::AccentDeep => palette.accent_deep,
            Self::AccentLight => palette.accent_light,
            Self::OnAccent => palette.text_on_accent,
            Self::Background => palette.background,
            Self::Surface => palette.surface,
            Self::SurfaceDeep => palette.surface_deep,
            Self::Raised => palette.raised,
            Self::Sunken => palette.sunken,
            Self::Border => palette.border,
            Self::Selection => palette.surface.mix(palette.accent, SELECTION_WASH),
            Self::Focus => palette.border_focus,
            Self::Ok => palette.ok,
            Self::Warn => palette.warn,
            Self::Bad => palette.bad,
            Self::Idle => palette.idle,
            Self::OkTint => palette.ok_tint,
            Self::WarnTint => palette.warn_tint,
            Self::BadTint => palette.bad_tint,
            Self::IdleTint => palette.idle_tint,
            Self::Shadow => palette.shadow,
            Self::Clear => Color::TRANSPARENT,
            Self::Exact(color) => color,
        }
    }

    /// The saturated colour a status is drawn in.
    pub fn ink(status: Status) -> Self {
        match status {
            Status::Ok => Self::Ok,
            Status::Warn => Self::Warn,
            Status::Bad => Self::Bad,
            Status::Idle => Self::Idle,
        }
    }

    /// The fill that belongs behind [`Tone::ink`] of the same status.
    pub fn tint(status: Status) -> Self {
        match status {
            Status::Ok => Self::OkTint,
            Status::Warn => Self::WarnTint,
            Status::Bad => Self::BadTint,
            Status::Idle => Self::IdleTint,
        }
    }
}

impl From<Color> for Tone {
    fn from(color: Color) -> Self {
        Self::Exact(color)
    }
}

/// How much of an axis an element asks for.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Length {
    /// As much as the content needs, and no more.
    Auto,
    /// Exactly this many logical units.
    Fixed(f32),
    /// A share of what is left over after the fixed and automatic ones are
    /// served, in proportion to every other filling sibling's share.
    Fill(f32),
    /// This fraction of what the parent offered.
    Fraction(f32),
}

impl Length {
    /// The share of leftover space this asks for, or zero.
    pub(crate) fn grow(self) -> f32 {
        match self {
            Self::Fill(share) => share.max(0.0),
            _ => 0.0,
        }
    }
}

/// Which way a container stacks what is in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Axis {
    /// Left to right.
    Row,
    /// Top to bottom.
    Column,
}

/// Where things sit on the axis a container does *not* stack along.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Align {
    /// Left, or top.
    Start,
    /// Centred.
    Center,
    /// Right, or bottom.
    End,
    /// Stretched to the full width, or height, of the container.
    Stretch,
}

impl Align {
    /// Where a run of `content` starts within `available`.
    pub(crate) fn offset(self, available: f32, content: f32) -> f32 {
        match self {
            Self::Start | Self::Stretch => 0.0,
            Self::Center => ((available - content) / 2.0).max(0.0),
            Self::End => (available - content).max(0.0),
        }
    }
}

/// Where things sit on the axis a container *does* stack along, once everything
/// has been given the room it asked for and some is still spare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Justify {
    /// Packed at the start; the spare room falls at the end.
    Start,
    /// Packed in the middle.
    Center,
    /// Packed at the end.
    End,
    /// Spread out, with the spare room divided between them.
    Between,
}

/// Where an element lifted out of the flow by [`El::layer`](crate::El::layer)
/// sits relative to the thing it belongs to.
///
/// Named against the *anchor* rather than against the window — `Below` a
/// button, not "at 240, 380" — because what a menu or a tooltip is actually
/// about is the control it came from, and a position in window coordinates
/// stops being right the moment anything above it changes size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchor {
    /// Covering the anchor exactly: a badge, an overlay, a spinner over a pane.
    Over,
    /// Hanging under its bottom edge, left edges aligned: a dropdown, a menu.
    Below,
    /// Sitting on its top edge: a tooltip above a control near the bottom.
    Above,
    /// Beside its right edge, top edges aligned: a submenu.
    After,
    /// Beside its left edge.
    Before,
    /// Centred in the window rather than on the anchor: a dialog.
    ///
    /// The one anchor that ignores where its parent is, because a dialog is
    /// about the *window* and merely happens to have been opened by something.
    Center,
}

/// How the corners of a filled or outlined element are treated.
///
/// Four of these name a *size* and take their shape from
/// [`Theme::corner`](crate::Theme::corner), so that changing the theme's
/// [`CornerStyle`](crate::CornerStyle) changes the whole interface at once. The
/// other two — [`Radius::Cut`] and [`Radius::None`] — name a shape outright, for
/// the one element that genuinely is not what the rest of the interface is.
/// Reach for them the way you reach for [`Tone::Exact`]: rarely, and knowing
/// that a theme will no longer be able to move this corner.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Radius {
    /// The theme's own corner for a panel.
    Panel,
    /// The theme's own corner for a control.
    Control,
    /// The theme's own shape, this many logical units along each edge.
    Units(f32),
    /// Fully round: a capsule, or a circle if it is square.
    Pill,
    /// A forty-five degree chamfer this many units along each edge, whatever
    /// shape the theme takes.
    ///
    /// The one element that is a machined plate in an interface made of cards:
    /// a nameplate, a readout, a region that reports on hardware. A whole
    /// interface of them is a costume, and is asked for from the theme instead.
    Cut(f32),
    /// Square corners, whatever shape the theme takes.
    None,
}

/// Which face a run of text is set in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Face {
    /// The proportional face: everything the interface itself says.
    Ui,
    /// The fixed-width face: everything the machine produced.
    Mono,
}

/// The text properties an element passes down to its children.
///
/// Held apart from the rest of [`Style`] because these are the ones that
/// inherit, and keeping them in their own type is what makes that true by
/// construction rather than by a list of field names somewhere in the layout.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Ink {
    /// The size text is set at, in logical units.
    pub size: f32,
    /// Its colour.
    pub tone: Tone,
    /// Its face.
    pub face: Face,
    /// Extra space added between letters.
    pub tracking: f32,
    /// Whether the run is drawn heavier; see [`El::bold`](crate::El::bold).
    pub bold: bool,
}

impl Default for Ink {
    fn default() -> Self {
        Self { size: crate::widgets::BODY_SIZE, tone: Tone::Text, face: Face::Ui, tracking: 0.0, bold: false }
    }
}

impl Ink {
    /// The drawing style this amounts to under `theme`.
    pub fn style(self, theme: &Theme) -> TextStyle {
        let font: FontId = match self.face {
            Face::Ui => theme.ui_font,
            Face::Mono => theme.mono_font,
        };
        TextStyle::new(font, self.size, self.tone.resolve(theme))
            .tracked(self.tracking)
    }
}

/// How a fill answers the pointer.
///
/// Two colours rather than a whole second style: what changes when a pointer
/// crosses a control is its surface and its ink, and an interface where hovering
/// also moves things is one nobody can click.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Hover {
    /// What it is filled with while the pointer is over it.
    pub fill: Option<Tone>,
    /// What its text turns to.
    pub ink: Option<Tone>,
    /// What its outline turns to.
    pub border: Option<Tone>,
}

impl Hover {
    /// Whether hovering changes anything at all.
    pub(crate) fn is_empty(self) -> bool {
        self.fill.is_none() && self.ink.is_none() && self.border.is_none()
    }
}

/// Everything about an element that is not its content or its children.
///
/// Constructed by the chained setters on [`El`](crate::El) rather than by naming
/// fields, so a description reads as one sentence per element.
#[derive(Debug, Clone, PartialEq)]
pub struct Style {
    /// How much width to ask for.
    pub width: Length,
    /// How much height to ask for.
    pub height: Length,
    /// A share of the parent's spare room along whichever axis it stacks.
    ///
    /// Separate from [`Style::width`] and [`Style::height`] because it is asked
    /// for without knowing which of the two it will turn out to be — `grow()`
    /// keeps meaning "take the rest of the room" when a row is later rewritten
    /// as a column, which the axis-specific lengths cannot.
    pub grow: Option<f32>,
    /// Whether growing starts from what the content needs rather than from
    /// nothing.
    ///
    /// A pane or a spacer grows from zero — its content is whatever fits. A
    /// control is the other way round: its words come first, and only the room
    /// past them is up for sharing. See [`El::grow_from_content`](crate::El::grow_from_content).
    pub grow_from_content: bool,
    /// Whether it stands whole or is not laid out at all.
    ///
    /// A squeezed element normally gives ground gradually — text truncates to
    /// an ellipsis, a pane loses rows. An element that says `whole` refuses
    /// the middle state: when a shrinking container would cut into what it
    /// measured, it collapses to nothing and its room goes to its siblings.
    /// For a mark whose meaning is carried elsewhere too — a state word beside
    /// a lamp — half the word is worse than none of it. See
    /// [`El::whole`](crate::El::whole).
    pub whole: bool,
    /// The narrowest it may be laid out.
    pub min_width: f32,
    /// The shortest it may be laid out.
    pub min_height: f32,
    /// The widest.
    pub max_width: f32,
    /// The tallest.
    pub max_height: f32,
    /// Room left inside its own edge, before its children.
    pub padding: Insets,
    /// Room left between its children.
    pub gap: f32,
    /// Which way its children stack.
    pub axis: Axis,
    /// Where its children sit across that direction.
    pub align: Align,
    /// Where *this* element sits across its parent's direction, if it insists.
    ///
    /// The one thing a child may say about its own placement. Everything else is
    /// the parent's to decide, which is what keeps a rectangle the business of
    /// exactly one box.
    pub self_align: Option<Align>,
    /// Where they sit along it.
    pub justify: Justify,
    /// What it is filled with.
    pub fill: Option<Tone>,
    /// The bottom of that fill, when it is a gradient.
    pub fill_deep: Option<Tone>,
    /// Its outline: how thick, and in what.
    pub border: Option<(f32, Tone)>,
    /// How its corners are treated.
    pub radius: Radius,
    /// How far a shadow beneath it is blurred, if it casts one.
    pub shadow: Option<f32>,
    /// How far a halo around it reaches, and what colour it is.
    ///
    /// Held apart from [`Style::shadow`] rather than being a colour on it,
    /// because the two say opposite things: a shadow is the absence of light,
    /// is always the theme's own black, and falls downward; a glow is light,
    /// takes a hue, and is cast evenly. See [`El::glow`](crate::El::glow).
    pub glow: Option<(f32, Tone)>,
    /// The text properties it sets, and passes to its children.
    pub ink: InkOverride,
    /// Where its own text sits within it.
    pub text_align: Align,
    /// Whether that text wraps rather than being cut short.
    pub wrap: bool,
    /// Whether drawing is confined to its rectangle.
    pub clip: bool,
    /// Whether its children run onto further lines when they do not fit.
    pub flow: bool,
    /// Where it sits, if it was lifted out of its parent's stacking.
    pub layer: Option<Anchor>,
    /// What changes while the pointer is over it.
    pub hover: Hover,
}

/// The text properties an element sets, each one optional.
///
/// A `None` means *whatever my parent said*, which is what makes inheritance
/// work; there is no sentinel value standing in for "unset".
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct InkOverride {
    /// The size, if this element sets one.
    pub size: Option<f32>,
    /// The colour, if it sets one.
    pub tone: Option<Tone>,
    /// The face, if it sets one.
    pub face: Option<Face>,
    /// The tracking, if it sets one.
    pub tracking: Option<f32>,
    /// Whether it is drawn heavier, if it says.
    pub bold: Option<bool>,
}

impl InkOverride {
    /// `inherited`, with whatever this element said applied on top.
    pub fn over(self, inherited: Ink) -> Ink {
        Ink {
            size: self.size.unwrap_or(inherited.size),
            tone: self.tone.unwrap_or(inherited.tone),
            face: self.face.unwrap_or(inherited.face),
            tracking: self.tracking.unwrap_or(inherited.tracking),
            bold: self.bold.unwrap_or(inherited.bold),
        }
    }
}

impl Default for Style {
    fn default() -> Self {
        Self {
            width: Length::Auto,
            height: Length::Auto,
            grow: None,
            grow_from_content: false,
            whole: false,
            min_width: 0.0,
            min_height: 0.0,
            max_width: f32::INFINITY,
            max_height: f32::INFINITY,
            padding: Insets::uniform(0.0),
            gap: 0.0,
            axis: Axis::Column,
            align: Align::Stretch,
            self_align: None,
            justify: Justify::Start,
            fill: None,
            fill_deep: None,
            border: None,
            radius: Radius::None,
            shadow: None,
            glow: None,
            ink: InkOverride::default(),
            text_align: Align::Start,
            wrap: false,
            clip: false,
            flow: false,
            layer: None,
            hover: Hover::default(),
        }
    }
}

impl Style {
    /// Whether anything about this element has to be drawn behind its content.
    pub(crate) fn has_decoration(&self) -> bool {
        self.fill.is_some()
            || self.border.is_some()
            || self.shadow.is_some()
            || self.glow.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_role_resolves_differently_in_the_two_appearances() {
        use crate::text::FontId;
        let font = FontId::FIRST;
        let light = Theme::new(crate::theme::Appearance::Light, font, font);
        let dark = Theme::new(crate::theme::Appearance::Dark, font, font);
        assert_ne!(Tone::Surface.resolve(&light), Tone::Surface.resolve(&dark));
    }

    #[test]
    fn an_exact_colour_ignores_the_theme() {
        use crate::text::FontId;
        let font = FontId::FIRST;
        let brand = Color::rgb(0x7c, 0x3a, 0xed);
        for appearance in [crate::theme::Appearance::Light, crate::theme::Appearance::Dark] {
            let theme = Theme::new(appearance, font, font);
            assert_eq!(Tone::Exact(brand).resolve(&theme), brand);
        }
    }

    #[test]
    fn unset_text_properties_come_from_the_parent() {
        let inherited = Ink { size: 20.0, tone: Tone::Muted, ..Ink::default() };
        let child = InkOverride { tone: Some(Tone::Accent), ..InkOverride::default() };
        let resolved = child.over(inherited);
        assert_eq!(resolved.size, 20.0, "the size was not overridden, so it should carry down");
        assert_eq!(resolved.tone, Tone::Accent);
    }

    #[test]
    fn only_a_filling_length_asks_for_leftover_space() {
        assert_eq!(Length::Fill(2.0).grow(), 2.0);
        assert_eq!(Length::Fixed(40.0).grow(), 0.0);
        assert_eq!(Length::Auto.grow(), 0.0);
    }
}
