//! A TrueType font, and the glyph images it can be asked for.
//!
//! # Why this is written here
//!
//! The alternative was to let each platform rasterise text with its own stack —
//! Core Text, DirectWrite, Xft. That gets complex-script shaping for free, and
//! costs three separate bodies of foreign-function code, a link-time dependency
//! on Linux, a text path that cannot be tested without a window, and glyphs that
//! come out differently on every operating system. Owning the rasteriser makes
//! the console render identically everywhere and testable with no display at
//! all, which is the same trade the rest of this project makes about protocols.
//!
//! # What it does not do
//!
//! - **No complex-script shaping.** One character becomes one glyph. Scripts
//!   whose letters join or reorder — Arabic, Devanagari — will not render
//!   correctly. Latin, Greek, Cyrillic, numerals, and punctuation will.
//! - **No ligatures or substitutions.** `GSUB` is not read, so `fi` sets as two
//!   letters. Pair kerning *is* read, from both the `kern` table and `GPOS`,
//!   because it is a table lookup rather than the reordering engine a
//!   substitution needs; the `kern` module states exactly how much of each
//!   format that covers.
//! - **No hinting.** The bytecode exists to snap stems to a coarse pixel grid,
//!   a problem that HiDPI displays largely removed, and interpreting it would
//!   mean implementing and sandboxing a second language.
//! - **No PostScript outlines.** Fonts whose glyphs live in a `CFF ` table
//!   rather than `glyf` are refused by name, so the failure is actionable.
//!
//! These are limits of the *font engine*, not of the toolkit: [`Font::parse`]
//! takes bytes, so a face with the coverage a deployment needs is a matter of
//! which file gets loaded.

mod kern;
mod outline;
mod raster;
mod sfnt;

use crate::canvas::Mask;
use kern::Kerning;
use outline::{Edges, Transform};
use raster::Rasteriser;
use sfnt::{CharMap, Directory, Reader, Table};

/// The largest glyph image that will be rendered, per side, in pixels.
///
/// A bound on what one glyph can allocate. Text this size is a display banner,
/// far past anything the console draws.
const MAX_GLYPH_PIXELS: i32 = 2048;

/// Why a font file could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FontError {
    /// The bytes are not a font, or not one whose container we recognise.
    NotAFont,
    /// The face index asked for is past the end of a font collection.
    NoSuchFace {
        /// The index that was asked for.
        wanted: usize,
        /// How many faces the file actually holds.
        available: usize,
    },
    /// The font's glyphs are PostScript outlines, which this engine cannot draw.
    PostScriptOutlines,
    /// A table the engine needs is missing.
    MissingTable(&'static str),
    /// A table is present but could not be read.
    MalformedTable(&'static str),
}

impl std::fmt::Display for FontError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAFont => write!(formatter, "not a TrueType or OpenType font"),
            Self::NoSuchFace { wanted, available } => write!(
                formatter,
                "asked for face {wanted} of a collection that holds {available}"
            ),
            Self::PostScriptOutlines => write!(
                formatter,
                "this font stores its glyphs as PostScript outlines (a `CFF ` table); \
                 only TrueType outlines are supported"
            ),
            Self::MissingTable(tag) => write!(formatter, "the font has no `{tag}` table"),
            Self::MalformedTable(tag) => write!(formatter, "the font's `{tag}` table is malformed"),
        }
    }
}

impl std::error::Error for FontError {}

/// A glyph's index within its font.
///
/// Zero is `.notdef`, the box or blank a font shows for a character it has no
/// glyph for. It is a real glyph and draws normally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GlyphId(pub u16);

/// The vertical measurements of a line of text, in pixels at some size.
///
/// `ascent` and `descent` are both positive distances from the baseline, up and
/// down respectively — the sign convention of the font file, where descent is
/// negative, is normalised away here so that no caller has to remember it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LineMetrics {
    /// How far the tallest letters rise above the baseline.
    pub ascent: f32,
    /// How far the deepest letters fall below it.
    pub descent: f32,
    /// The font's recommended extra space between lines.
    pub line_gap: f32,
}

impl LineMetrics {
    /// Baseline-to-baseline distance for consecutive lines.
    pub fn line_height(&self) -> f32 {
        self.ascent + self.descent + self.line_gap
    }
}

/// One glyph rendered at a particular size and subpixel offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderedGlyph {
    /// The coverage image; empty for a glyph that marks nothing, like a space.
    pub mask: Mask,
    /// Device pixels from the pen position to the mask's left edge.
    pub left: i32,
    /// Device pixels from the baseline to the mask's top edge; negative for the
    /// part of a glyph that rises above the baseline, which is most of it.
    pub top: i32,
}

/// A parsed TrueType font.
pub struct Font {
    data: Vec<u8>,
    units_per_em: f32,
    ascent: f32,
    descent: f32,
    line_gap: f32,
    glyph_count: u16,
    long_glyph_offsets: bool,
    glyf: Table,
    loca: Table,
    hmtx: Table,
    horizontal_metric_count: u16,
    character_map: CharMap,
    kerning: Kerning,
}

impl Font {
    /// How many faces a font file holds; one, unless it is a collection.
    pub fn face_count(data: &[u8]) -> usize {
        sfnt::face_offsets(data).map_or(0, |offsets| offsets.len())
    }

    /// Parses the first face in `data`.
    pub fn parse(data: Vec<u8>) -> Result<Self, FontError> {
        Self::parse_face(data, 0)
    }

    /// Parses one face of a font file, by index.
    ///
    /// Most of the fonts shipped with macOS are collections holding a whole
    /// family, so which face is wanted is a real question rather than always
    /// zero.
    pub fn parse_face(data: Vec<u8>, index: usize) -> Result<Self, FontError> {
        let offsets = sfnt::face_offsets(&data).ok_or(FontError::NotAFont)?;
        let offset = *offsets
            .get(index)
            .ok_or(FontError::NoSuchFace { wanted: index, available: offsets.len() })?;

        let directory = Directory::read(&data, offset).ok_or(FontError::NotAFont)?;
        if directory.find(b"glyf").is_none() && directory.find(b"CFF ").is_some() {
            return Err(FontError::PostScriptOutlines);
        }

        let table = |tag: &'static [u8; 4]| {
            directory.find(tag).ok_or(FontError::MissingTable(
                std::str::from_utf8(tag).unwrap_or("????"),
            ))
        };
        let head = table(b"head")?;
        let hhea = table(b"hhea")?;
        let maxp = table(b"maxp")?;
        let glyf = table(b"glyf")?;
        let loca = table(b"loca")?;
        let hmtx = table(b"hmtx")?;
        let cmap = table(b"cmap")?;

        let mut reader = Reader::at(&data, head.offset + 18);
        let units_per_em = reader.u16().ok_or(FontError::MalformedTable("head"))? as f32;
        // A zero would divide by zero on every glyph; the specification requires
        // 16 to 16384, so anything outside that is a corrupt table rather than
        // an unusual font.
        if !(16.0..=16384.0).contains(&units_per_em) {
            return Err(FontError::MalformedTable("head"));
        }
        let mut reader = Reader::at(&data, head.offset + 50);
        let long_glyph_offsets = match reader.i16().ok_or(FontError::MalformedTable("head"))? {
            0 => false,
            1 => true,
            _ => return Err(FontError::MalformedTable("head")),
        };

        let mut reader = Reader::at(&data, hhea.offset + 4);
        let ascent = reader.i16().ok_or(FontError::MalformedTable("hhea"))? as f32;
        let descent = reader.i16().ok_or(FontError::MalformedTable("hhea"))? as f32;
        let line_gap = reader.i16().ok_or(FontError::MalformedTable("hhea"))? as f32;
        let mut reader = Reader::at(&data, hhea.offset + 34);
        let horizontal_metric_count = reader.u16().ok_or(FontError::MalformedTable("hhea"))?;
        if horizontal_metric_count == 0 {
            return Err(FontError::MalformedTable("hhea"));
        }

        let mut reader = Reader::at(&data, maxp.offset + 4);
        let glyph_count = reader.u16().ok_or(FontError::MalformedTable("maxp"))?;

        let character_map =
            CharMap::read(&data, cmap).ok_or(FontError::MalformedTable("cmap"))?;
        // Kerning is optional and answers nothing when the font has none, so
        // it cannot fail the load the way a missing `cmap` does.
        let kerning = Kerning::read(&data, &directory);

        Ok(Self {
            data,
            units_per_em,
            ascent,
            // `hhea` states descent as a negative number; every caller wants the
            // distance, so the sign is dropped once, here.
            descent: -descent,
            line_gap,
            glyph_count,
            long_glyph_offsets,
            glyf,
            loca,
            hmtx,
            horizontal_metric_count,
            character_map,
            kerning,
        })
    }

    /// The glyph this font uses for a character, or `.notdef` when it has none.
    pub fn glyph_for(&self, character: char) -> GlyphId {
        GlyphId(self.character_map.glyph(character))
    }

    /// Whether this font actually has a glyph for a character.
    ///
    /// Distinct from [`Font::glyph_for`] answering zero, because drawing
    /// `.notdef` is a legitimate thing to want; this is for deciding whether to
    /// look in another font first.
    pub fn has_glyph(&self, character: char) -> bool {
        self.character_map.glyph(character) != 0
    }

    /// Line measurements at a given pixel size.
    pub fn metrics(&self, size: f32) -> LineMetrics {
        let scale = self.scale_for(size);
        LineMetrics {
            ascent: self.ascent * scale,
            descent: self.descent * scale,
            line_gap: self.line_gap * scale,
        }
    }

    /// How far the pen moves after drawing a glyph, in pixels.
    ///
    /// Glyphs past the end of the metrics table share the last entry's advance:
    /// that is how the format stores a run of equal-width glyphs, not an error.
    pub fn advance(&self, glyph: GlyphId, size: f32) -> f32 {
        let index = glyph.0.min(self.horizontal_metric_count - 1) as usize;
        let mut reader = Reader::at(&self.data, self.hmtx.offset + index * 4);
        let units = reader.u16().unwrap_or(0) as f32;
        units * self.scale_for(size)
    }

    /// How much closer `right` should sit after `left`, in pixels.
    ///
    /// Almost always negative or zero: kerning closes up the gaps a pair like
    /// `AV` leaves when both glyphs are set at their own advance. Zero for a
    /// pair the font says nothing about, and for every pair in a font that
    /// carries no kerning at all.
    ///
    /// This belongs to the *pair*, so it is only meaningful for two glyphs of
    /// the same face — a caller mixing faces must not carry an adjustment
    /// across the join.
    pub fn kerning(&self, left: GlyphId, right: GlyphId, size: f32) -> f32 {
        if self.kerning.is_empty() {
            return 0.0;
        }
        self.kerning.adjustment(left.0, right.0) as f32 * self.scale_for(size)
    }

    /// Whether the font states any kerning at all.
    ///
    /// Lets a caller that walks a string pair by pair skip the lookup entirely
    /// for the many faces — most monospaced ones among them — that carry none.
    pub fn has_kerning(&self) -> bool {
        !self.kerning.is_empty()
    }

    /// Renders a glyph at `size` pixels, offset `subpixel_x` into its pixel.
    ///
    /// `subpixel_x` is the fractional part of where the pen sits, and letting it
    /// through to the rasteriser rather than rounding the pen to whole pixels is
    /// what keeps letter spacing even in a run of text. It is expected to be in
    /// `[0, 1)`; anything else is folded into that range.
    ///
    /// A glyph that marks nothing — a space, or one the font leaves blank —
    /// renders to an empty mask rather than failing.
    pub fn render(&self, glyph: GlyphId, size: f32, subpixel_x: f32) -> RenderedGlyph {
        let blank = RenderedGlyph { mask: Mask::empty(), left: 0, top: 0 };
        if size <= 0.0 || !size.is_finite() {
            return blank;
        }

        let subpixel_x = subpixel_x.rem_euclid(1.0);
        let mut edges = Edges::new();
        let transform = Transform::for_glyph(self.scale_for(size), (subpixel_x, 0.0));
        let source = outline::GlyphSource {
            data: &self.data,
            glyf: self.glyf,
            loca: self.loca,
            long_offsets: self.long_glyph_offsets,
            glyph_count: self.glyph_count,
        };
        if outline::append_glyph(&source, glyph.0, transform, &mut edges, 0).is_none() {
            return blank;
        }

        let Some((min, max)) = edges.bounds() else {
            return blank;
        };
        let left = min.0.floor() as i32;
        let top = min.1.floor() as i32;
        let width = (max.0.ceil() as i32 - left).clamp(0, MAX_GLYPH_PIXELS);
        let height = (max.1.ceil() as i32 - top).clamp(0, MAX_GLYPH_PIXELS);
        if width == 0 || height == 0 {
            return blank;
        }

        let mut rasteriser = Rasteriser::new(width as usize, height as usize);
        let shift = (left as f32, top as f32);
        for (from, to) in &edges.segments {
            rasteriser.edge(
                (from.0 - shift.0, from.1 - shift.1),
                (to.0 - shift.0, to.1 - shift.1),
            );
        }

        RenderedGlyph {
            mask: Mask {
                width: width as u32,
                height: height as u32,
                coverage: rasteriser.finish(),
            },
            left,
            top,
        }
    }

    /// Pixels per font unit at a given pixel size.
    fn scale_for(&self, size: f32) -> f32 {
        size / self.units_per_em
    }
}

impl std::fmt::Debug for Font {
    /// Summarises the font without dumping the megabyte of file behind it.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Font")
            .field("bytes", &self.data.len())
            .field("glyphs", &self.glyph_count)
            .field("units_per_em", &self.units_per_em)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonsense_bytes_are_not_a_font() {
        assert_eq!(Font::parse(vec![0; 64]).err(), Some(FontError::NotAFont));
        assert_eq!(Font::parse(Vec::new()).err(), Some(FontError::NotAFont));
    }

    #[test]
    fn a_truncated_font_is_refused_rather_than_panicking() {
        // A valid SFNT version and a table count, and then nothing.
        let mut bytes = 0x0001_0000u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&5u16.to_be_bytes());
        assert!(Font::parse(bytes).is_err());
    }

    #[test]
    fn errors_explain_themselves() {
        assert!(FontError::PostScriptOutlines.to_string().contains("CFF"));
        assert!(FontError::MissingTable("glyf").to_string().contains("glyf"));
        assert_eq!(
            FontError::NoSuchFace { wanted: 9, available: 2 }.to_string(),
            "asked for face 9 of a collection that holds 2"
        );
    }

    #[test]
    fn line_height_is_the_sum_of_the_three_measurements() {
        let metrics = LineMetrics { ascent: 10.0, descent: 3.0, line_gap: 2.0 };
        assert_eq!(metrics.line_height(), 15.0);
    }
}
