//! A face built here, rather than found on the machine.
//!
//! The library deliberately ships no font: a real one is several hundred
//! kilobytes of someone else's licensed work, and every desktop already has
//! better ones installed. That is the right decision for a *program*, and it
//! leaves a hole in the *tests* — with no face loaded every glyph resolves to
//! nothing, every string measures zero units wide, and so every assertion about
//! a layout containing text is an assertion about an empty box.
//!
//! Borrowing the machine's fonts instead would swap that for a worse problem: a
//! test whose expected numbers depend on which version of which face the
//! machine running it happens to have, and which therefore cannot state an
//! exact width at all.
//!
//! So this builds one. It is a real TrueType file, assembled a table at a time
//! and parsed by exactly the same code that parses a font off the disk — which
//! means it also serves as the parser's own test case, because a file this
//! module writes and [`Font::parse`] refuses is one of the two being wrong.
//!
//! # What it measures
//!
//! Every glyph is half an em wide, and a line is exactly one em. Both
//! numbers are round on purpose, so a test can state what it expects rather
//! than measuring first and pasting the answer back:
//!
//! | at text size | one character | one line |
//! |---|---|---|
//! | 10 | 5.0 | 10.0 |
//! | 20 | 10.0 | 20.0 |
//!
//! Every character draws a filled box of a height that depends on which
//! character it is, so two different words are two different pictures — enough
//! for a rendering test to tell them apart, and no more than that.

use crate::font::Font;

/// Font units to an em. A thousand, so a size in units is a size in thousandths.
const UNITS_PER_EM: u16 = 1000;

/// How far the pen moves for every glyph, in font units: half an em.
///
/// One width for every character, so the width of a run is its length times
/// half the text size, and no test has to know anything about letterforms.
const ADVANCE: u16 = 500;

/// How far the tallest letters rise above the baseline.
const ASCENT: i16 = 800;

/// How far the deepest fall below it, as `hhea` states it: negative.
const DESCENT: i16 = -200;

/// The first character the face covers.
const FIRST: char = ' ';

/// The last character it covers in one run.
const LAST: char = '~';

/// Two more characters, mapped after that run, in ascending order.
///
/// `é` is two bytes in UTF-8 and the ellipsis is what a run cut short is marked
/// with — between them they cover the two things a text test needs that plain
/// ASCII cannot say.
const EXTRAS: [char; 2] = ['é', '…'];

/// The left edge of every glyph's box, in font units.
const BOX_LEFT: i16 = 50;

/// Its right edge.
const BOX_RIGHT: i16 = 450;

/// How many different heights the boxes come in.
const HEIGHTS: u16 = 6;

/// The shortest box, in font units.
const SHORTEST: i16 = 300;

/// How much taller each successive box is.
const HEIGHT_STEP: i16 = 100;

/// The face this module builds, parsed.
///
/// # Panics
///
/// If the bytes it assembles are not a font this crate can read, which is a
/// defect in one of the two and not something a caller can do anything about.
pub fn test_font() -> Font {
    Font::parse(test_font_bytes()).expect("the face assembled here must parse")
}

/// The same face, as the bytes of a TrueType file.
///
/// For a test that wants to feed a *valid* font to something — a loader, a
/// truncation check — rather than to draw with it.
pub fn test_font_bytes() -> Vec<u8> {
    let characters = coverage();
    // One glyph per character, plus `.notdef` at zero, which every font has and
    // which a character map answers with when it has nothing better.
    let glyph_count = characters.len() as u16 + 1;

    let (glyf, loca) = outlines(&characters);
    assemble(&[
        (*b"cmap", character_map(&characters)),
        (*b"glyf", glyf),
        (*b"head", head()),
        (*b"hhea", horizontal_header()),
        (*b"hmtx", horizontal_metrics(glyph_count)),
        (*b"loca", loca),
        (*b"maxp", maximum_profile(glyph_count)),
    ])
}

/// Every character the face covers, in the order its glyphs are numbered.
fn coverage() -> Vec<char> {
    let mut characters: Vec<char> = (FIRST..=LAST).collect();
    characters.extend(EXTRAS);
    characters
}

/// The outlines of every glyph, and the table of offsets into them.
///
/// The space draws nothing, which the format spells as an entry of no length
/// rather than as an outline with no contours — so this is also where the
/// "blank glyph" path through the outline reader gets exercised.
fn outlines(characters: &[char]) -> (Vec<u8>, Vec<u8>) {
    let mut glyf = Vec::new();
    let mut loca = Vec::new();

    // `.notdef` first, and blank: nothing in these tests asks to draw it, and a
    // font whose first glyph is empty is a font whose short `loca` starts at
    // zero like every other one.
    push_short_offset(&mut loca, glyf.len());
    for (index, &character) in characters.iter().enumerate() {
        push_short_offset(&mut loca, glyf.len());
        if character != ' ' {
            glyf.extend(box_glyph(box_height(index)));
        }
    }
    // `loca` holds one more offset than there are glyphs: the end of the last.
    push_short_offset(&mut loca, glyf.len());
    (glyf, loca)
}

/// How tall the box for the `index`th glyph is.
fn box_height(index: usize) -> i16 {
    SHORTEST + HEIGHT_STEP * (index as u16 % HEIGHTS) as i16
}

/// One glyph: a filled box, as a simple outline of four on-curve points.
fn box_glyph(top: i16) -> Vec<u8> {
    let mut glyph = Vec::with_capacity(34);
    push_i16(&mut glyph, 1); // one contour
    for edge in [BOX_LEFT, 0, BOX_RIGHT, top] {
        push_i16(&mut glyph, edge); // the bounding box, which the reader distrusts
    }
    push_u16(&mut glyph, 3); // the contour ends at the fourth point
    push_u16(&mut glyph, 0); // no hinting instructions
    glyph.extend([0x01; 4]); // four points, every one of them on the curve

    // Coordinates are stored as deltas from the point before, starting at the
    // origin, and the box is walked anticlockwise.
    for delta in [BOX_LEFT, BOX_RIGHT - BOX_LEFT, 0, BOX_LEFT - BOX_RIGHT] {
        push_i16(&mut glyph, delta);
    }
    for delta in [0, 0, top, 0] {
        push_i16(&mut glyph, delta);
    }
    glyph
}

/// The `cmap` table: characters to glyph numbers.
///
/// Format 12, tagged as Windows full Unicode, which is the widest map the
/// reader recognises and therefore the one it prefers.
fn character_map(characters: &[char]) -> Vec<u8> {
    let groups = contiguous_runs(characters);

    let mut subtable = Vec::new();
    push_u16(&mut subtable, 12); // format
    push_u16(&mut subtable, 0); // reserved
    push_u32(&mut subtable, 16 + groups.len() as u32 * 12); // length
    push_u32(&mut subtable, 0); // language
    push_u32(&mut subtable, groups.len() as u32);
    for (first, last, glyph) in &groups {
        push_u32(&mut subtable, *first as u32);
        push_u32(&mut subtable, *last as u32);
        push_u32(&mut subtable, *glyph);
    }

    let mut table = Vec::new();
    push_u16(&mut table, 0); // version
    push_u16(&mut table, 1); // one subtable
    push_u16(&mut table, 3); // Windows
    push_u16(&mut table, 10); // full Unicode
    push_u32(&mut table, 12); // where the subtable starts, from here
    table.extend(subtable);
    table
}

/// The runs of consecutive characters that map to consecutive glyphs.
///
/// Answers `(first character, last character, first glyph)`, which is exactly
/// what one group of a format 12 map holds. Glyphs are numbered in coverage
/// order, so they are consecutive by construction and a run continues for
/// exactly as long as the *characters* do.
fn contiguous_runs(characters: &[char]) -> Vec<(char, char, u32)> {
    let mut runs: Vec<(char, char, u32)> = Vec::new();
    for (index, &character) in characters.iter().enumerate() {
        match runs.last_mut() {
            Some((_, last, _)) if *last as u32 + 1 == character as u32 => *last = character,
            _ => runs.push((character, character, index as u32 + 1)),
        }
    }
    runs
}

/// The `head` table: what the units are, and how `loca` is stored.
fn head() -> Vec<u8> {
    let mut table = Vec::new();
    push_u32(&mut table, 0x0001_0000); // version
    push_u32(&mut table, 0x0001_0000); // revision
    push_u32(&mut table, 0); // checksum adjustment
    push_u32(&mut table, 0x5f0f_3cf5); // the magic number the format specifies
    push_u16(&mut table, 0); // flags
    push_u16(&mut table, UNITS_PER_EM);
    table.extend([0; 16]); // created and modified, eight bytes each
    push_i16(&mut table, 0); // xMin
    push_i16(&mut table, DESCENT); // yMin
    push_i16(&mut table, ADVANCE as i16); // xMax
    push_i16(&mut table, ASCENT); // yMax
    push_u16(&mut table, 0); // macStyle
    push_u16(&mut table, 8); // smallest readable size
    push_i16(&mut table, 2); // direction hint
    push_i16(&mut table, 0); // `loca` holds halved two-byte offsets
    push_i16(&mut table, 0); // glyph data format
    table
}

/// The `hhea` table: how tall a line is, and how many advances `hmtx` spells out.
fn horizontal_header() -> Vec<u8> {
    let mut table = Vec::new();
    push_u32(&mut table, 0x0001_0000); // version
    push_i16(&mut table, ASCENT);
    push_i16(&mut table, DESCENT);
    push_i16(&mut table, 0); // line gap
    push_u16(&mut table, ADVANCE); // widest advance
    push_i16(&mut table, 0); // minimum left side bearing
    push_i16(&mut table, 0); // minimum right side bearing
    push_i16(&mut table, ADVANCE as i16); // furthest extent
    push_i16(&mut table, 1); // caret slope rise
    push_i16(&mut table, 0); // caret slope run
    push_i16(&mut table, 0); // caret offset
    table.extend([0; 8]); // four reserved fields
    push_i16(&mut table, 0); // metric data format
    push_u16(&mut table, 1); // one advance spelled out; every glyph shares it
    table
}

/// The `hmtx` table: one advance, and a side bearing for every other glyph.
///
/// Storing a single advance is how the format says "these glyphs are all the
/// same width", and reading it back exercises the path in [`Font::advance`]
/// that shares the last entry rather than running off the end of the table.
fn horizontal_metrics(glyph_count: u16) -> Vec<u8> {
    let mut table = Vec::new();
    push_u16(&mut table, ADVANCE);
    push_i16(&mut table, 0);
    for _ in 1..glyph_count {
        push_i16(&mut table, 0);
    }
    table
}

/// The `maxp` table: how many glyphs there are.
fn maximum_profile(glyph_count: u16) -> Vec<u8> {
    let mut table = Vec::new();
    push_u32(&mut table, 0x0000_5000); // version 0.5: the count and nothing else
    push_u16(&mut table, glyph_count);
    table
}

/// Puts the tables into a file, behind the directory that says where they are.
fn assemble(tables: &[([u8; 4], Vec<u8>)]) -> Vec<u8> {
    let header = 12 + tables.len() * 16;
    let mut file = Vec::with_capacity(header + tables.iter().map(|(_, body)| body.len()).sum::<usize>());

    push_u32(&mut file, 0x0001_0000); // TrueType outlines
    push_u16(&mut file, tables.len() as u16);
    // searchRange, entrySelector, and rangeShift accelerate a binary search
    // over the directory. Nothing here searches it, and a reader that trusted
    // them would be trusting numbers the format lets a font state wrongly.
    push_u16(&mut file, 0);
    push_u16(&mut file, 0);
    push_u16(&mut file, 0);

    let mut offset = header;
    for (tag, body) in tables {
        file.extend(tag);
        push_u32(&mut file, 0); // checksum
        push_u32(&mut file, offset as u32);
        push_u32(&mut file, body.len() as u32);
        offset += aligned(body.len());
    }
    for (_, body) in tables {
        file.extend(body);
        file.resize(aligned(file.len()), 0);
    }
    file
}

/// The next four-byte boundary at or after `length`, where a table may start.
fn aligned(length: usize) -> usize {
    length.div_ceil(4) * 4
}

/// Appends one `loca` entry: an offset into `glyf`, halved as the short form
/// stores it.
///
/// Every glyph this module writes is an even number of bytes long, which is
/// what makes halving them lossless — and is why the outline is built from
/// whole `i16` coordinates rather than the format's shorter one-byte form.
fn push_short_offset(loca: &mut Vec<u8>, offset: usize) {
    debug_assert!(offset % 2 == 0, "a short `loca` cannot address an odd offset");
    push_u16(loca, (offset / 2) as u16);
}

fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend(value.to_be_bytes());
}

fn push_i16(out: &mut Vec<u8>, value: i16) {
    out.extend(value.to_be_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend(value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::font::GlyphId;

    #[test]
    fn the_face_assembled_here_is_a_font_this_crate_can_read() {
        let font = test_font();
        assert_eq!(Font::face_count(&test_font_bytes()), 1);
        assert!(font.has_glyph('A'));
        assert!(font.has_glyph('…'), "the mark a truncated run ends with");
        assert!(font.has_glyph('é'), "a character that is two bytes of UTF-8");
        assert!(!font.has_glyph('漢'), "nothing claims coverage it does not have");
    }

    #[test]
    fn every_character_is_half_the_text_size_wide() {
        let font = test_font();
        for character in ['A', 'i', 'W', ' ', '1'] {
            let glyph = font.glyph_for(character);
            assert_eq!(font.advance(glyph, 20.0), 10.0, "{character} should be half an em");
        }
    }

    #[test]
    fn a_line_is_exactly_the_text_size_tall() {
        let metrics = test_font().metrics(20.0);
        assert_eq!(metrics.ascent, 16.0);
        assert_eq!(metrics.descent, 4.0);
        assert_eq!(metrics.line_height(), 20.0);
    }

    #[test]
    fn a_letter_marks_pixels_and_a_space_marks_none() {
        let font = test_font();
        let letter = font.render(font.glyph_for('A'), 32.0, 0.0);
        assert!(!letter.mask.is_empty(), "a letter must draw something");
        assert!(letter.mask.coverage.iter().any(|&value| value > 128), "and draw it solidly");

        let space = font.render(font.glyph_for(' '), 32.0, 0.0);
        assert!(space.mask.is_empty(), "a space must draw nothing at all");
    }

    #[test]
    fn different_characters_are_different_pictures() {
        // Not a claim about letterforms — every glyph here is a box. It is what
        // lets a rendering test tell one word from another at all.
        let font = test_font();
        let first = font.render(font.glyph_for('a'), 40.0, 0.0);
        let second = font.render(font.glyph_for('b'), 40.0, 0.0);
        assert_ne!(first.mask.height, second.mask.height);
    }

    #[test]
    fn glyphs_are_numbered_from_one_with_notdef_at_zero() {
        let font = test_font();
        assert_eq!(font.glyph_for(FIRST), GlyphId(1));
        assert_eq!(font.glyph_for('!'), GlyphId(2));
        assert_eq!(font.glyph_for('漢'), GlyphId(0), "an uncovered character is `.notdef`");
    }

    #[test]
    fn every_table_starts_on_a_four_byte_boundary() {
        assert_eq!(aligned(0), 0);
        assert_eq!(aligned(1), 4);
        assert_eq!(aligned(4), 4);
        assert_eq!(aligned(5), 8);
    }
}
