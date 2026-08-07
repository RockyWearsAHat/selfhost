//! Laying out and drawing runs of text.
//!
//! [`Fonts`] holds the loaded faces and the cache of rendered glyphs, and is the
//! only thing that turns a `&str` into marks on a [`Canvas`]. Measuring and
//! drawing go through the same code path, so a string can never be laid out to
//! one width and then drawn at another — the bug that makes labels overrun the
//! boxes they were fitted to.
//!
//! # One advance, and everything walks it
//!
//! `Fonts::advance_of` is that path. Measuring, fitting, wrapping, and drawing
//! each walk a string through it and sum what it answers, so anything that
//! changes how wide text is — tab stops, tracking, and now kerning — is added
//! there and nowhere else. A second place would be a second answer, and the two
//! would drift the first time one of them was edited.
//!
//! Kerning makes that rule load-bearing rather than tidy, because it is the
//! first thing here that depends on the character *before* the one being
//! measured. So the advance is asked for a pair, and it answers two numbers:
//! how far the pen moves before the glyph is drawn, and how far after. Drawing
//! uses both in order; every other path only needs their sum.
//!
//! # Clusters, not characters
//!
//! Anything a person can land on or break at is a grapheme cluster: [`fit`]
//! answers a cluster boundary, [`wrap`] breaks at one, and [`grapheme`] is what
//! a caret should step by. A `char` is the wrong unit — it would put a caret
//! between a letter and its accent, and cut a flag in half. See [`grapheme`]
//! for exactly which of UAX #29 is implemented and which of it is not.
//!
//! Measuring and drawing still walk `char`s, because a cluster's width is the
//! sum of its characters' advances either way — a combining mark advances the
//! pen by nothing and draws over its base. The unit only matters where the run
//! is *cut*.
//!
//! [`fit`]: Fonts::fit
//! [`wrap`]: Fonts::wrap
//!
//! # Subpixel positioning
//!
//! A glyph is rendered at the fractional offset the pen actually sits at, in one
//! of [`SUBPIXEL_PHASES`] steps, rather than the pen being rounded to a whole
//! pixel before each glyph. Rounding is cheaper and needs no phases, but it
//! moves each letter by up to half a pixel, and in a word those errors are
//! visible as uneven spacing. Four phases put the worst error at an eighth of a
//! pixel, which is below what the antialiasing can show.
//!
//! # Sizes are quantised
//!
//! Glyphs are cached against the size they were rendered at, so a size that
//! varies continuously would fill the cache with near-duplicates. Sizes round to
//! [`SIZE_QUANTUM`] of a pixel before rendering *and* before measuring, which
//! keeps the two consistent.

pub mod grapheme;

use crate::canvas::Canvas;
use crate::color::Color;
use crate::font::{Font, GlyphId, LineMetrics, RenderedGlyph};
use crate::geom::Point;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

/// How many horizontal subpixel positions a glyph may be rendered at.
pub const SUBPIXEL_PHASES: u32 = 4;

/// The fraction of a pixel that text sizes are rounded to.
pub const SIZE_QUANTUM: f32 = 0.25;

/// How many rendered glyphs are kept before the cache is emptied.
///
/// Emptied wholesale rather than evicted least-recently-used: the console draws
/// a handful of sizes, so the cap is only ever reached by something unusual, and
/// a rebuild costs one frame's worth of rasterising rather than a bookkeeping
/// structure on every lookup.
const MAX_CACHED_GLYPHS: usize = 4096;

/// How many spaces a tab is worth.
const TAB_WIDTH: usize = 4;

/// The character shown where text was cut short.
const ELLIPSIS: char = '…';

/// Which loaded face to draw with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct FontId(usize);

impl FontId {
    /// The first face loaded.
    ///
    /// Also what [`FontId::default`] answers, so a theme can be built before any
    /// face exists — it draws nothing until one does, rather than failing.
    pub const FIRST: Self = Self(0);
}

/// A face, a size, the colour to draw in, and how far apart to set the letters.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TextStyle {
    /// Which face.
    pub font: FontId,
    /// Size in logical units.
    pub size: f32,
    /// Colour.
    pub color: Color,
    /// Extra space after every letter, in logical units; see [`TextStyle::tracked`].
    pub tracking: f32,
}

impl TextStyle {
    /// A style, in the given face, size, and colour, set solid.
    pub const fn new(font: FontId, size: f32, color: Color) -> Self {
        Self { font, size, color, tracking: 0.0 }
    }

    /// The same style in a different colour.
    pub const fn colored(self, color: Color) -> Self {
        Self { color, ..self }
    }

    /// The same style at a different size.
    pub const fn sized(self, size: f32) -> Self {
        Self { size, ..self }
    }

    /// The same style with `tracking` logical units added after every letter.
    ///
    /// This exists for one job: small capitals. A face's spacing is designed for
    /// lower case at a reading size, and setting the same metrics in capitals at
    /// ten pixels packs the letters until the word reads as a block rather than
    /// as letters. Opening them up is what makes a small uppercase label legible
    /// instead of merely small.
    ///
    /// The space is added after the *last* letter as well, so a tracked run
    /// measures one tracking wider than the marks it makes. Every path —
    /// measuring, fitting, wrapping, drawing — agrees on that, which is what
    /// matters: a run can never be fitted to one width and drawn at another. The
    /// cost is a fraction of a pixel of slack at the right of a right-aligned
    /// tracked label, which is below what the antialiasing can show.
    pub const fn tracked(self, tracking: f32) -> Self {
        Self { tracking, ..self }
    }
}

/// What identifies a rendered glyph in the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct GlyphKey {
    glyph: GlyphId,
    /// Device pixel size, in units of [`SIZE_QUANTUM`].
    size: u32,
    /// Which of [`SUBPIXEL_PHASES`] horizontal offsets.
    phase: u32,
}

/// What one character does to the pen, in device pixels.
///
/// Two numbers rather than one because kerning moves the pen *before* the glyph
/// is drawn and the advance moves it after. Every path that only wants a width
/// adds them; drawing is the one that needs them apart.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Advance {
    /// Movement before the glyph: how much this pair closes up.
    kern: f32,
    /// Movement after it: the glyph's own advance, and any tracking.
    width: f32,
}

impl Advance {
    /// What a character that marks nothing and moves nothing contributes.
    const NOTHING: Self = Self { kern: 0.0, width: 0.0 };
}

/// A pen walking one line of text.
///
/// Holds the character before, because kerning belongs to the pair rather than
/// to either glyph, and the size to render at, so that every path walking a run
/// asks [`Fonts::advance_of`] exactly the same question. Copied rather than
/// borrowed so that [`Fonts::fit`] can measure a cluster speculatively and keep
/// the result only if the whole of it fits.
#[derive(Debug, Clone, Copy)]
struct Run {
    /// How far the pen has moved from the start of the line, in device pixels.
    pen: f32,
    /// The character just set, or `None` at the start of the line.
    previous: Option<char>,
    /// The size glyphs are rendered at, in quantised device pixels.
    device_size: f32,
}

impl Run {
    /// A pen at the start of a line to be set at `device_size`.
    fn new(device_size: f32) -> Self {
        Self { pen: 0.0, previous: None, device_size }
    }

    /// Moves the pen over one character, answering where its glyph belongs.
    ///
    /// That is the pen position *after* the pair's kerning and before the
    /// glyph's own advance — which is why drawing calls this rather than
    /// summing widths itself.
    fn add(&mut self, fonts: &Fonts, style: &TextStyle, character: char) -> f32 {
        let advance =
            fonts.advance_of(style, self.previous, character, self.device_size, self.pen);
        self.pen += advance.kern;
        let at = self.pen;
        self.pen += advance.width;
        self.previous = Some(character);
        at
    }
}

/// One loaded face and the glyphs rendered from it so far.
struct Face {
    font: Font,
    rendered: RefCell<HashMap<GlyphKey, Rc<RenderedGlyph>>>,
}

/// The loaded faces, the glyph cache, and the text layout.
pub struct Fonts {
    faces: Vec<Face>,
    scale: f32,
}

impl Fonts {
    /// A set of fonts with nothing loaded, at a scale of one.
    pub fn new() -> Self {
        Self { faces: Vec::new(), scale: 1.0 }
    }

    /// Adds a face and answers the handle that selects it.
    pub fn add(&mut self, font: Font) -> FontId {
        self.faces.push(Face { font, rendered: RefCell::new(HashMap::new()) });
        FontId(self.faces.len() - 1)
    }

    /// How many faces are loaded.
    pub fn len(&self) -> usize {
        self.faces.len()
    }

    /// Whether no face is loaded, in which case nothing will draw.
    pub fn is_empty(&self) -> bool {
        self.faces.is_empty()
    }

    /// Sets the device pixel density text will be rendered for.
    ///
    /// Every cached glyph was rendered for the old scale, so the cache is
    /// dropped: keeping it would draw a window moved to a different monitor at
    /// the wrong resolution until each glyph happened to be re-rendered.
    pub fn set_scale(&mut self, scale: f32) {
        if (self.scale - scale).abs() > f32::EPSILON {
            self.scale = scale;
            for face in &self.faces {
                face.rendered.borrow_mut().clear();
            }
        }
    }

    /// The face a handle refers to, if it is still loaded.
    pub fn font(&self, id: FontId) -> Option<&Font> {
        self.faces.get(id.0).map(|face| &face.font)
    }

    /// The vertical measurements of a line in this style, in logical units.
    pub fn metrics(&self, style: &TextStyle) -> LineMetrics {
        match self.faces.get(style.font.0) {
            Some(face) => face.font.metrics(quantise(style.size)),
            None => LineMetrics { ascent: 0.0, descent: 0.0, line_gap: 0.0 },
        }
    }

    /// The width one line of text will occupy, in logical units.
    ///
    /// Exactly the width [`Fonts::draw`] will advance by, because both walk the
    /// string through one advance, `Fonts::advance_of`.
    pub fn measure(&self, style: &TextStyle, text: &str) -> f32 {
        let device = self.device_size(style);
        let mut run = Run::new(device);
        for character in text.chars() {
            run.add(self, style, character);
        }
        run.pen / self.scale
    }

    /// How many bytes of `text` fit within `max_width` logical units.
    ///
    /// Answers a byte count on a grapheme cluster boundary, so the prefix it
    /// describes is a valid string *and* a whole one: a letter is never left
    /// without its accent, nor a flag without its other half.
    pub fn fit(&self, style: &TextStyle, text: &str, max_width: f32) -> usize {
        let device = self.device_size(style);
        let limit = max_width * self.scale;
        let mut run = Run::new(device);
        for (offset, cluster) in grapheme::clusters(text) {
            // A cluster is all or nothing, so it is measured on a copy of the
            // pen and only committed once it is known to fit.
            let mut attempt = run;
            for character in cluster.chars() {
                attempt.add(self, style, character);
            }
            if attempt.pen > limit {
                return offset;
            }
            run = attempt;
        }
        text.len()
    }

    /// Splits `text` into lines that each fit within `max_width`.
    ///
    /// Breaks at spaces where it can and inside a word where it cannot, so a
    /// single unbroken token — a path, a URL — is chopped rather than allowed to
    /// overrun. Answers byte ranges into `text` rather than owned strings, so
    /// wrapping a paragraph every frame allocates one vector and no copies.
    pub fn wrap(&self, style: &TextStyle, text: &str, max_width: f32) -> Vec<(usize, usize)> {
        let mut lines = Vec::new();
        for paragraph in split_lines(text) {
            self.wrap_paragraph(style, text, paragraph, max_width, &mut lines);
        }
        lines
    }

    /// Draws one line of text with its baseline left end at `origin`.
    ///
    /// Answers how far the pen advanced, in logical units.
    pub fn draw(
        &self,
        canvas: &mut Canvas,
        style: &TextStyle,
        origin: Point,
        text: &str,
        color: Color,
    ) -> f32 {
        let device = self.device_size(style);
        let baseline_x = origin.x * self.scale;
        let baseline_y = (origin.y * self.scale).round() as i32;

        let mut run = Run::new(device);
        for character in text.chars() {
            let at = run.add(self, style, character);
            if let Some(glyph) = self.rendered_glyph(style, character, device, baseline_x + at) {
                let left = (baseline_x + at).floor() as i32 + glyph.left;
                canvas.fill_mask(left, baseline_y + glyph.top, &glyph.mask, color);
            }
        }
        run.pen / self.scale
    }

    /// Draws one line, cut short with an ellipsis if it will not fit.
    ///
    /// Answers how far the pen advanced, which is at most `max_width`.
    pub fn draw_truncated(
        &self,
        canvas: &mut Canvas,
        style: &TextStyle,
        origin: Point,
        text: &str,
        max_width: f32,
        color: Color,
    ) -> f32 {
        if self.measure(style, text) <= max_width {
            return self.draw(canvas, style, origin, text, color);
        }

        // The ellipsis has to fit too, so the text is fitted to what is left
        // after reserving room for it rather than to the full width. Room for
        // not even the ellipsis draws nothing at all: a lone "…" overflowing
        // a collapsed rectangle reports nothing and litters the pixels beside
        // it.
        let ellipsis = self.measure(style, "…");
        if max_width < ellipsis {
            return 0.0;
        }
        let kept = self.fit(style, text, (max_width - ellipsis).max(0.0));
        let advance = self.draw(canvas, style, origin, &text[..kept], color);
        advance
            + self.draw(canvas, style, origin.offset(advance, 0.0), &ELLIPSIS.to_string(), color)
    }

    /// The size glyphs are rendered at, in quantised device pixels.
    fn device_size(&self, style: &TextStyle) -> f32 {
        quantise(quantise(style.size) * self.scale)
    }

    /// The pen movement for one character, in device pixels.
    ///
    /// `previous` is the character before it, which kerning needs because the
    /// adjustment belongs to the pair and not to either glyph. `pen` is where
    /// the pen already is, which a tab needs in order to reach the next stop
    /// rather than simply being some fixed width.
    ///
    /// The one place any of this is decided: every path walks a string through
    /// here, so measuring, fitting, wrapping, and drawing cannot disagree about
    /// how wide a run is.
    fn advance_of(
        &self,
        style: &TextStyle,
        previous: Option<char>,
        character: char,
        device_size: f32,
        pen: f32,
    ) -> Advance {
        let Some((face, glyph)) = self.resolve(style, character) else {
            return Advance::NOTHING;
        };
        if character == '\t' {
            let stop = self.faces[face].font.advance(glyph_of(&self.faces[face].font, ' '), device_size)
                * TAB_WIDTH as f32;
            if stop > 0.0 {
                // A tab reaches an absolute stop, so nothing before it can
                // move it: no kerning, whatever the pair.
                return Advance { kern: 0.0, width: stop - pen.rem_euclid(stop) };
            }
        }
        Advance {
            kern: self.kerning_before(style, previous, face, glyph, device_size),
            // Tracking is added here, in the one place every path already goes
            // through, so measuring and drawing cannot disagree about how wide
            // a tracked run is. It is a logical measurement like the size, so
            // it is scaled to device pixels the same way.
            width: self.faces[face].font.advance(glyph, device_size)
                + style.tracking * self.scale,
        }
    }

    /// How much the pair `previous`–`glyph` closes up, in device pixels.
    ///
    /// Zero unless both glyphs came from the same face: an adjustment states
    /// how two of *one* font's letterforms fit together, and carrying it across
    /// a fallback would be applying one face's opinion to another's shapes.
    fn kerning_before(
        &self,
        style: &TextStyle,
        previous: Option<char>,
        face: usize,
        glyph: GlyphId,
        device_size: f32,
    ) -> f32 {
        let font = &self.faces[face].font;
        if !font.has_kerning() {
            return 0.0;
        }
        match previous.and_then(|character| self.resolve(style, character)) {
            Some((before, left)) if before == face => font.kerning(left, glyph, device_size),
            _ => 0.0,
        }
    }

    /// The glyph image for a character at the pen position, if it marks anything.
    fn rendered_glyph(
        &self,
        style: &TextStyle,
        character: char,
        device_size: f32,
        pen_x: f32,
    ) -> Option<Rc<RenderedGlyph>> {
        let (face_index, glyph) = self.resolve(style, character)?;
        let face = &self.faces[face_index];

        let phase = ((pen_x.rem_euclid(1.0)) * SUBPIXEL_PHASES as f32) as u32 % SUBPIXEL_PHASES;
        let key = GlyphKey {
            glyph,
            size: (device_size / SIZE_QUANTUM).round() as u32,
            phase,
        };

        let mut cache = face.rendered.borrow_mut();
        if cache.len() >= MAX_CACHED_GLYPHS {
            cache.clear();
        }
        let rendered = cache.entry(key).or_insert_with(|| {
            Rc::new(face.font.render(
                glyph,
                device_size,
                phase as f32 / SUBPIXEL_PHASES as f32,
            ))
        });
        (!rendered.mask.is_empty()).then(|| Rc::clone(rendered))
    }

    /// Picks the face and glyph to draw a character with.
    ///
    /// The style's own face wins when it has the character. Otherwise any other
    /// loaded face that does is used, so a monospace face missing a symbol
    /// borrows one rather than showing an empty box — which in a console would
    /// silently mangle a service's own output.
    fn resolve(&self, style: &TextStyle, character: char) -> Option<(usize, GlyphId)> {
        if character.is_control() && character != '\t' {
            return None;
        }
        let requested = self.faces.get(style.font.0)?;
        if requested.font.has_glyph(character) {
            return Some((style.font.0, requested.font.glyph_for(character)));
        }
        for (index, face) in self.faces.iter().enumerate() {
            if face.font.has_glyph(character) {
                return Some((index, face.font.glyph_for(character)));
            }
        }
        Some((style.font.0, requested.font.glyph_for(character)))
    }

    /// Wraps one hard-broken paragraph, appending the lines it becomes.
    fn wrap_paragraph(
        &self,
        style: &TextStyle,
        text: &str,
        paragraph: (usize, usize),
        max_width: f32,
        lines: &mut Vec<(usize, usize)>,
    ) {
        let (start, end) = paragraph;
        let mut line_start = start;

        while line_start < end {
            let remaining = &text[line_start..end];
            let fits = self.fit(style, remaining, max_width);
            if fits >= remaining.len() {
                lines.push((line_start, end));
                return;
            }

            // Prefer the last space that still fits, counting one that starts
            // exactly at the limit: it would otherwise begin the next line as a
            // leading space nobody asked for.
            let break_at = last_break(remaining, fits)
                // Nowhere to break: cut inside the word, but never to nothing,
                // or a single too-wide cluster would loop forever.
                .unwrap_or_else(|| fits.max(grapheme::first_cluster_len(remaining)));

            lines.push((line_start, line_start + break_at));
            line_start += break_at;
            // Leading space on the next line is an artefact of the break.
            while line_start < end && text[line_start..].starts_with(' ') {
                line_start += 1;
            }
        }

        if lines.is_empty() {
            lines.push((start, end));
        }
    }
}

impl Default for Fonts {
    fn default() -> Self {
        Self::new()
    }
}

/// Rounds a size to [`SIZE_QUANTUM`].
fn quantise(size: f32) -> f32 {
    (size / SIZE_QUANTUM).round() * SIZE_QUANTUM
}

/// The glyph a font uses for a character.
fn glyph_of(font: &Font, character: char) -> GlyphId {
    font.glyph_for(character)
}

/// Where to break after the last space or hyphen starting at or before `fits`.
///
/// Answers the byte just past that character, which is where the next line
/// begins. `None` when the text has neither, which is a word too long to break
/// politely.
///
/// A hyphen is a break opportunity because the names machines wear —
/// `levelup-api`, `a-service-with-a-long-name`, a flag, a path — are single
/// spaceless tokens joined by them, and a token that only breaks at spaces
/// breaks in the middle of a word instead of at one of its own joints. The
/// hyphen stays on the line it ends, exactly as a hyphenated line of prose
/// would carry it.
///
/// Walks forwards and keeps the last match rather than searching backwards from
/// `fits`, because `fits` is a cluster boundary and the byte after it need not
/// be a character boundary at all — slicing there would panic.
fn last_break(text: &str, fits: usize) -> Option<usize> {
    text.char_indices()
        .take_while(|(offset, _)| *offset <= fits)
        .filter_map(|(offset, character)| {
            let past = offset + character.len_utf8();
            if character.is_whitespace() {
                // A space at the limit still breaks: it would otherwise open
                // the next line, and it draws nothing where it is.
                Some(past)
            } else if character == '-' && past <= fits {
                // A hyphen is ink, so it breaks only when the whole of it fits.
                Some(past)
            } else {
                None
            }
        })
        .last()
}

/// The byte ranges of the hard lines in `text`, excluding their terminators.
fn split_lines(text: &str) -> Vec<(usize, usize)> {
    let mut lines = Vec::new();
    let mut start = 0;
    for (offset, character) in text.char_indices() {
        if character == '\n' {
            let end = if text[..offset].ends_with('\r') { offset - 1 } else { offset };
            lines.push((start, end));
            start = offset + 1;
        }
    }
    lines.push((start, text.len()));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_round_to_the_quantum() {
        assert_eq!(quantise(13.0), 13.0);
        assert_eq!(quantise(13.1), 13.0);
        assert_eq!(quantise(13.2), 13.25);
    }

    #[test]
    fn a_style_can_be_recoloured_and_resized_without_losing_its_face() {
        let style = TextStyle::new(FontId(2), 13.0, Color::WHITE);
        assert_eq!(style.colored(Color::BLACK).font, FontId(2));
        assert_eq!(style.sized(20.0).color, Color::WHITE);
    }

    #[test]
    fn a_style_is_set_solid_until_it_is_tracked() {
        let style = TextStyle::new(FontId::FIRST, 10.0, Color::WHITE);
        assert_eq!(style.tracking, 0.0);
        assert_eq!(style.tracked(0.8).tracking, 0.8);
        assert_eq!(style.tracked(0.8).size, 10.0, "tracking must not disturb the size");
    }

    #[test]
    fn tracking_reaches_every_path_by_going_through_the_one_advance() {
        // Measuring, fitting, wrapping, and drawing all walk a string through
        // `advance_of`, so adding tracking there is what makes them agree. There
        // is no assertion of the *width* here because this crate ships no face
        // to measure against — with none loaded every glyph resolves to nothing
        // and a width test would pass on an empty advance. It is asserted
        // against a real face by `selfhost-window`, which is what loads one.
        let solid = TextStyle::new(FontId::FIRST, 10.0, Color::WHITE);
        assert_eq!(solid.tracking, 0.0);
        assert_eq!(solid.tracked(0.8).tracking, 0.8);
    }

    #[test]
    fn hard_line_breaks_are_found_without_their_terminators() {
        assert_eq!(split_lines("a\nbb\nccc"), vec![(0, 1), (2, 4), (5, 8)]);
    }

    #[test]
    fn carriage_returns_are_not_part_of_the_line() {
        let text = "a\r\nb";
        let lines = split_lines(text);
        assert_eq!(&text[lines[0].0..lines[0].1], "a");
        assert_eq!(&text[lines[1].0..lines[1].1], "b");
    }

    #[test]
    fn a_trailing_newline_leaves_an_empty_last_line() {
        assert_eq!(split_lines("a\n"), vec![(0, 1), (2, 2)]);
    }

    #[test]
    fn text_with_no_fonts_loaded_measures_to_nothing_rather_than_panicking() {
        let fonts = Fonts::new();
        let style = TextStyle::new(FontId(0), 13.0, Color::WHITE);
        assert_eq!(fonts.measure(&style, "anything"), 0.0);
        assert_eq!(fonts.fit(&style, "anything", 100.0), "anything".len());
        assert!(fonts.is_empty());
    }

    #[test]
    fn drawing_with_no_fonts_loaded_marks_nothing() {
        let fonts = Fonts::new();
        let mut canvas = Canvas::new(20, 20, 1.0);
        canvas.clear(Color::BLACK);
        let style = TextStyle::new(FontId(0), 13.0, Color::WHITE);
        fonts.draw(&mut canvas, &style, Point::new(0.0, 10.0), "hello", Color::WHITE);
        assert!(canvas.pixels().iter().all(|&word| word == 0xff00_0000));
    }

    #[test]
    fn a_line_breaks_after_the_last_space_that_fits() {
        assert_eq!(last_break("one two three", 7), Some(8), "a space at the limit still breaks");
        assert_eq!(last_break("one two three", 6), Some(4));
        assert_eq!(last_break("unbreakable", 5), None);
        // A space that is more than one byte still leaves the break on a
        // character boundary.
        assert_eq!(last_break("a\u{a0}b", 1), Some(3));
    }

    /// The synthetic face, at a size where a character is ten units wide and
    /// the one kerned pair closes up by two.
    fn loaded() -> (Fonts, TextStyle) {
        let mut fonts = Fonts::new();
        let face = fonts.add(crate::testing::font::test_font());
        (fonts, TextStyle::new(face, 20.0, Color::WHITE))
    }

    #[test]
    fn a_kerned_pair_sets_narrower_than_an_unkerned_one() {
        let (fonts, style) = loaded();
        assert_eq!(fonts.measure(&style, "AA"), 20.0);
        assert_eq!(fonts.measure(&style, "AV"), 18.0, "the pair the face kerns");
        assert_eq!(fonts.measure(&style, "VA"), 20.0, "kerning is not symmetric");
        assert_eq!(fonts.measure(&style, "AVA"), 28.0, "one pair in a longer run");
    }

    #[test]
    fn drawing_a_kerned_run_advances_exactly_as_far_as_measuring_it_said() {
        // The invariant the whole module exists to hold, at the point kerning
        // is most likely to break it: drawing applies the adjustment before the
        // glyph and measuring only ever sees a sum.
        let (fonts, style) = loaded();
        let mut canvas = Canvas::new(200, 40, 1.0);
        for run in ["AV", "AVAV", "A V", "\tAV", "AVé…"] {
            let drawn = fonts.draw(&mut canvas, &style, Point::new(0.0, 30.0), run, Color::WHITE);
            assert_eq!(drawn, fonts.measure(&style, run), "{run:?}");
        }
    }

    #[test]
    fn kerning_reaches_fitting_as_well_as_measuring() {
        let (fonts, style) = loaded();
        // Nineteen units is not enough for two characters, but is enough for
        // two that kern.
        assert_eq!(fonts.fit(&style, "AV", 19.0), 2);
        assert_eq!(fonts.fit(&style, "AA", 19.0), 1);
    }

    #[test]
    fn a_run_is_cut_between_clusters_and_never_inside_one() {
        let (fonts, style) = loaded();
        // `e` and a combining acute: one cluster, and in this face two
        // characters wide because the mark falls back to `.notdef`.
        let text = "e\u{301}x";
        assert_eq!(fonts.fit(&style, text, 15.0), 0, "half a cluster is no cluster");
        assert_eq!(fonts.fit(&style, text, 20.0), 3, "the whole of it fits");
        for width in [0.0, 5.0, 12.0, 19.0, 25.0, 40.0] {
            let fits = fonts.fit(&style, text, width);
            assert!(grapheme::is_boundary(text, fits), "cut at {fits} for width {width}");
        }
    }

    #[test]
    fn wrapping_breaks_on_cluster_boundaries_even_with_nowhere_to_break() {
        let (fonts, style) = loaded();
        // No spaces, so every break is a cut inside the word.
        let text = "e\u{301}e\u{301}e\u{301}";
        for (start, end) in fonts.wrap(&style, text, 25.0) {
            assert!(grapheme::is_boundary(text, start), "line starts at {start}");
            assert!(grapheme::is_boundary(text, end), "line ends at {end}");
        }
        assert_eq!(fonts.wrap(&style, text, 25.0).len(), 3, "one cluster to a line");
    }

    #[test]
    fn a_hyphenated_name_breaks_at_its_own_joints_rather_than_mid_word() {
        let (fonts, style) = loaded();
        // Ten characters to a line at this width. Broken blindly that is
        // "levelup-ap" + "i"; broken at the joint the name carries, the hyphen
        // ends the first line and the word after it starts the next whole.
        let text = "levelup-api";
        let lines: Vec<&str> =
            fonts.wrap(&style, text, 100.0).into_iter().map(|(a, b)| &text[a..b]).collect();
        assert_eq!(lines, vec!["levelup-", "api"]);
    }

    #[test]
    fn a_hyphen_that_does_not_fully_fit_is_not_hung_past_the_limit() {
        let (fonts, style) = loaded();
        // Seven characters fit and the hyphen is the eighth. A space there
        // would break — it draws nothing — but a hyphen is ink, so with no
        // joint that fits the break falls back to the plain cut.
        let text = "levelup-api";
        let lines: Vec<&str> =
            fonts.wrap(&style, text, 70.0).into_iter().map(|(a, b)| &text[a..b]).collect();
        assert_eq!(lines, vec!["levelup", "-api"], "the hyphen is not hung past the limit");
    }

    #[test]
    fn a_face_with_no_kerning_measures_exactly_as_it_did_before() {
        // Everything else in the crate asserts widths as a count of characters
        // times half the size; kerning must not have quietly changed that for
        // the pairs the face says nothing about.
        let (fonts, style) = loaded();
        for word in ["abcd", "Increment", "one two three"] {
            assert_eq!(fonts.measure(&style, word), word.chars().count() as f32 * 10.0);
        }
    }
}
