//! Pair kerning: how much closer two particular glyphs should sit.
//!
//! Setting every glyph at its own advance leaves gaps that the eye reads as
//! holes — `AV`, `To`, `r.` — because a letter's advance has to suit every
//! neighbour it might have. A font states the exceptions as pairs, in one of
//! two places:
//!
//! - the **`kern` table**, a flat list of glyph pairs and adjustments, which is
//!   the older form and the one small and monospaced faces still ship;
//! - **`GPOS`**, where the same information is a `kern` feature holding pair
//!   positioning lookups, either as explicit pairs or as a matrix over classes
//!   of glyphs that kern alike.
//!
//! Both are read here. `GPOS` wins when it carries anything, because a font
//! that has both is stating the same adjustments twice and the `kern` table is
//! the legacy copy — which is exactly what a shaping engine does.
//!
//! # What is read, and what is not
//!
//! - **Script and language selection is skipped.** Every lookup reached by a
//!   feature tagged `kern` is used, whichever script listed it. Choosing per
//!   script would only matter to a renderer that itemises runs by script, and
//!   this one does not.
//! - **Only the horizontal advance of the first glyph** is taken from a value
//!   record. Placement adjustments and vertical kerning are read past and
//!   dropped: this engine sets one horizontal line and has nowhere to put them.
//! - **Device tables are ignored**, as they are hinting corrections and there
//!   is no hinting here.
//! - **Cross-stream and minimum-value `kern` subtables are skipped**, since
//!   both change the meaning of the numbers rather than adding to them.
//! - **A malformed table yields no kerning rather than refusing the font.**
//!   Kerning is an optical refinement; a face that sets unkerned is far better
//!   than one that will not load, and the tables are optional to begin with.

use super::sfnt::{Directory, Reader, Table};
use std::collections::HashMap;

/// How many explicit pairs are kept from one subtable.
///
/// A bound on what a font file can make this allocate, in the spirit of the
/// glyph size cap: a real face states a few thousand pairs, so reaching this is
/// a corrupt or hostile table rather than an unusual font.
const MAX_LISTED_PAIRS: usize = 1 << 16;

/// How many glyphs one coverage table may list, which is every glyph there is.
const MAX_COVERED_GLYPHS: usize = u16::MAX as usize + 1;

/// The bit of a `ValueFormat` that says a record carries a horizontal advance.
const X_ADVANCE: u16 = 0x0004;

/// Everything a font says about how pairs of glyphs sit together.
///
/// Empty for a font that says nothing, which answers zero for every pair.
pub(super) struct Kerning {
    subtables: Vec<Pairs>,
}

impl Kerning {
    /// Reads whatever pair kerning the font offers, in font units.
    ///
    /// Never fails: a font with no kerning, or with kerning this reader cannot
    /// make sense of, answers an empty set rather than an error.
    pub(super) fn read(data: &[u8], directory: &Directory) -> Self {
        let mut subtables = Vec::new();
        if let Some(gpos) = directory.find(b"GPOS") {
            read_gpos(data, gpos, &mut subtables);
        }
        if subtables.is_empty() {
            if let Some(kern) = directory.find(b"kern") {
                read_kern(data, kern, &mut subtables);
            }
        }
        Self { subtables }
    }

    /// Whether the font states no kerning at all.
    pub(super) fn is_empty(&self) -> bool {
        self.subtables.is_empty()
    }

    /// How much closer `right` sits after `left`, in font units.
    ///
    /// Negative closes the pair up, which is what almost every pair does.
    /// Subtables accumulate, as the `kern` table's own rules require and as
    /// successive `GPOS` lookups do.
    pub(super) fn adjustment(&self, left: u16, right: u16) -> i32 {
        self.subtables.iter().map(|pairs| pairs.adjustment(left, right)).sum()
    }
}

/// One subtable's worth of adjustments.
enum Pairs {
    /// Adjustments spelled out one glyph pair at a time.
    Listed(HashMap<(u16, u16), i16>),
    /// Adjustments held as a matrix over classes of glyphs that kern alike,
    /// which is how a large face avoids listing tens of thousands of pairs.
    Classed {
        /// The glyphs that may appear on the left. A glyph outside it is not
        /// kerned even if its class says otherwise.
        covered: Vec<u16>,
        /// The class of the glyph on the left.
        first: ClassDef,
        /// The class of the glyph on the right.
        second: ClassDef,
        /// How wide the matrix is, so a row can be found in it.
        second_classes: usize,
        /// The matrix, row by row.
        values: Vec<i16>,
    },
}

impl Pairs {
    /// The adjustment this subtable makes to one pair, or zero.
    fn adjustment(&self, left: u16, right: u16) -> i32 {
        match self {
            Self::Listed(pairs) => pairs.get(&(left, right)).copied().unwrap_or(0) as i32,
            Self::Classed { covered, first, second, second_classes, values } => {
                if covered.binary_search(&left).is_err() {
                    return 0;
                }
                let row = first.class(left) as usize;
                let column = second.class(right) as usize;
                if column >= *second_classes {
                    return 0;
                }
                values.get(row * second_classes + column).copied().unwrap_or(0) as i32
            }
        }
    }
}

/// Which class each glyph belongs to, as ranges; anything unlisted is class 0.
struct ClassDef {
    ranges: Vec<(u16, u16, u16)>,
}

impl ClassDef {
    /// The class of a glyph.
    fn class(&self, glyph: u16) -> u16 {
        let found = self.ranges.binary_search_by(|(first, last, _)| {
            if *last < glyph {
                std::cmp::Ordering::Less
            } else if *first > glyph {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        });
        found.map_or(0, |index| self.ranges[index].2)
    }
}

/// Reads the pair positioning `GPOS` states under its `kern` feature.
///
/// Failure at any point leaves whatever was already read: one unreadable
/// lookup costs that lookup's pairs and not the font.
fn read_gpos(data: &[u8], gpos: Table, out: &mut Vec<Pairs>) -> Option<()> {
    let mut reader = Reader::at(data, gpos.offset);
    if reader.u16()? != 1 {
        return None; // No major version but 1 has ever been published.
    }
    reader.skip(2)?; // minor version
    reader.skip(2)?; // the script list, which this reader deliberately ignores
    let features = gpos.offset.checked_add(reader.u16()? as usize)?;
    let lookups = gpos.offset.checked_add(reader.u16()? as usize)?;

    let mut wanted = kern_feature_lookups(data, features)?;
    wanted.sort_unstable();
    wanted.dedup();

    let mut reader = Reader::at(data, lookups);
    let count = reader.u16()? as usize;
    let offsets: Vec<u16> = (0..count).map(|_| reader.u16()).collect::<Option<_>>()?;
    for index in wanted {
        let Some(offset) = offsets.get(index as usize) else {
            continue;
        };
        if let Some(table) = lookups.checked_add(*offset as usize) {
            read_lookup(data, table, out);
        }
    }
    Some(())
}

/// The lookups every feature tagged `kern` points at.
fn kern_feature_lookups(data: &[u8], features: usize) -> Option<Vec<u16>> {
    let mut reader = Reader::at(data, features);
    let count = reader.u16()? as usize;

    let mut wanted = Vec::new();
    for _ in 0..count {
        let tag = reader.bytes(4)?;
        let offset = reader.u16()? as usize;
        if tag != b"kern".as_slice() {
            continue;
        }
        let Some(table) = features.checked_add(offset) else {
            continue;
        };
        let mut feature = Reader::at(data, table);
        // `featureParams`, which only a handful of features define and `kern`
        // is not one of them.
        feature.skip(2)?;
        let indices = feature.u16()?;
        for _ in 0..indices {
            wanted.push(feature.u16()?);
        }
    }
    Some(wanted)
}

/// Reads one lookup's subtables, keeping the pair positioning among them.
fn read_lookup(data: &[u8], table: usize, out: &mut Vec<Pairs>) -> Option<()> {
    let mut reader = Reader::at(data, table);
    let kind = reader.u16()?;
    reader.skip(2)?; // lookupFlag: mark filtering, which needs `GDEF` and no
                     // kerning pair depends on it
    let count = reader.u16()? as usize;
    let offsets: Vec<u16> = (0..count).map(|_| reader.u16()).collect::<Option<_>>()?;

    for offset in offsets {
        let Some(subtable) = table.checked_add(offset as usize) else {
            continue;
        };
        match kind {
            2 => {
                read_pair_positioning(data, subtable, out);
            }
            // An extension is a lookup held elsewhere in the file, which is how
            // a font whose tables outgrew 16-bit offsets stores them.
            9 => {
                read_extension(data, subtable, out);
            }
            _ => {}
        }
    }
    Some(())
}

/// Follows an extension subtable to the pair positioning it points at.
fn read_extension(data: &[u8], subtable: usize, out: &mut Vec<Pairs>) -> Option<()> {
    let mut reader = Reader::at(data, subtable);
    if reader.u16()? != 1 {
        return None;
    }
    let kind = reader.u16()?;
    let offset = reader.u32()? as usize;
    if kind != 2 {
        return None;
    }
    // Not recursive: an extension pointing at another extension is disallowed
    // by the format, and following one would be a way to make this loop.
    read_pair_positioning(data, subtable.checked_add(offset)?, out)
}

/// Reads one pair positioning subtable in either of its two shapes.
fn read_pair_positioning(data: &[u8], subtable: usize, out: &mut Vec<Pairs>) -> Option<()> {
    let mut reader = Reader::at(data, subtable);
    match reader.u16()? {
        1 => read_listed_pairs(data, subtable, &mut reader, out),
        2 => read_classed_pairs(data, subtable, &mut reader, out),
        _ => None,
    }
}

/// Reads pair positioning format 1: a list of second glyphs per first glyph.
fn read_listed_pairs(
    data: &[u8],
    subtable: usize,
    reader: &mut Reader<'_>,
    out: &mut Vec<Pairs>,
) -> Option<()> {
    let covered = read_coverage(data, subtable.checked_add(reader.u16()? as usize)?)?;
    let first_format = reader.u16()?;
    let second_format = reader.u16()?;
    let count = reader.u16()? as usize;
    let sets: Vec<u16> = (0..count).map(|_| reader.u16()).collect::<Option<_>>()?;

    let mut pairs = HashMap::new();
    for (index, offset) in sets.iter().enumerate() {
        let Some(&left) = covered.get(index) else {
            break; // More pair sets than covered glyphs: the rest name nothing.
        };
        let mut set = Reader::at(data, subtable.checked_add(*offset as usize)?);
        let pair_count = set.u16()?;
        for _ in 0..pair_count {
            let right = set.u16()?;
            let adjustment = read_value_record(&mut set, first_format)?;
            read_value_record(&mut set, second_format)?;
            if adjustment != 0 && pairs.len() < MAX_LISTED_PAIRS {
                pairs.insert((left, right), adjustment);
            }
        }
    }

    if !pairs.is_empty() {
        out.push(Pairs::Listed(pairs));
    }
    Some(())
}

/// Reads pair positioning format 2: a matrix over classes of glyphs.
fn read_classed_pairs(
    data: &[u8],
    subtable: usize,
    reader: &mut Reader<'_>,
    out: &mut Vec<Pairs>,
) -> Option<()> {
    let covered = read_coverage(data, subtable.checked_add(reader.u16()? as usize)?)?;
    let first_format = reader.u16()?;
    let second_format = reader.u16()?;
    // A subtable whose records hold nothing states no adjustment, and reading
    // it would be a loop over a matrix that consumes no bytes.
    if first_format & X_ADVANCE == 0 && second_format == 0 {
        return None;
    }
    let first = read_class_def(data, subtable.checked_add(reader.u16()? as usize)?)?;
    let second = read_class_def(data, subtable.checked_add(reader.u16()? as usize)?)?;
    let first_classes = reader.u16()? as usize;
    let second_classes = reader.u16()? as usize;
    if first_classes == 0 || second_classes == 0 {
        return None;
    }

    // Every record consumes at least two bytes, so the matrix cannot be larger
    // than the file; a truncated one abandons the subtable rather than leaving
    // a matrix with missing rows.
    let mut values = Vec::new();
    for _ in 0..first_classes * second_classes {
        let adjustment = read_value_record(reader, first_format)?;
        read_value_record(reader, second_format)?;
        values.push(adjustment);
    }

    if values.iter().any(|value| *value != 0) {
        out.push(Pairs::Classed { covered, first, second, second_classes, values });
    }
    Some(())
}

/// Reads one value record, answering the horizontal advance it adjusts by.
///
/// The other fields are read past rather than skipped by arithmetic, so the
/// cursor lands after the record whatever the format says it holds.
fn read_value_record(reader: &mut Reader<'_>, format: u16) -> Option<i16> {
    let mut advance = 0;
    for bit in 0..8 {
        let flag = 1u16 << bit;
        if format & flag == 0 {
            continue;
        }
        let value = reader.i16()?;
        if flag == X_ADVANCE {
            advance = value;
        }
    }
    Some(advance)
}

/// Reads a coverage table: the glyphs a lookup applies to, in coverage order.
fn read_coverage(data: &[u8], offset: usize) -> Option<Vec<u16>> {
    let mut reader = Reader::at(data, offset);
    let mut glyphs = Vec::new();
    match reader.u16()? {
        1 => {
            let count = reader.u16()? as usize;
            for _ in 0..count {
                glyphs.push(reader.u16()?);
            }
        }
        2 => {
            let count = reader.u16()? as usize;
            for _ in 0..count {
                let first = reader.u16()?;
                let last = reader.u16()?;
                reader.skip(2)?; // the coverage index of `first`
                if first > last || glyphs.len() + (last - first) as usize >= MAX_COVERED_GLYPHS {
                    return None;
                }
                glyphs.extend(first..=last);
            }
        }
        _ => return None,
    }
    Some(glyphs)
}

/// Reads a class definition in either of its two shapes.
///
/// The ranges come back sorted and disjoint so they can be searched; a table
/// that overlaps itself is malformed and is refused rather than resolved
/// arbitrarily.
fn read_class_def(data: &[u8], offset: usize) -> Option<ClassDef> {
    let mut reader = Reader::at(data, offset);
    let mut ranges: Vec<(u16, u16, u16)> = Vec::new();
    match reader.u16()? {
        1 => {
            let start = reader.u16()?;
            let count = reader.u16()? as usize;
            for index in 0..count {
                let class = reader.u16()?;
                let glyph = start.checked_add(index as u16)?;
                // Class zero is the default and listing it changes nothing.
                if class != 0 {
                    ranges.push((glyph, glyph, class));
                }
            }
        }
        2 => {
            let count = reader.u16()? as usize;
            for _ in 0..count {
                let first = reader.u16()?;
                let last = reader.u16()?;
                let class = reader.u16()?;
                if first > last {
                    return None;
                }
                if class != 0 {
                    ranges.push((first, last, class));
                }
            }
        }
        _ => return None,
    }

    ranges.sort_unstable_by_key(|(first, _, _)| *first);
    if ranges.windows(2).any(|pair| pair[0].1 >= pair[1].0) {
        return None;
    }
    Some(ClassDef { ranges })
}

/// Reads the `kern` table in either the OpenType or the Apple layout.
fn read_kern(data: &[u8], table: Table, out: &mut Vec<Pairs>) -> Option<()> {
    let mut reader = Reader::at(data, table.offset);
    // OpenType's version is a `u16` 0; Apple's is a `u32` 0x00010000, whose
    // first two bytes are the 1 just read.
    let (count, apple) = match reader.u16()? {
        0 => (reader.u16()? as usize, false),
        1 => {
            reader.skip(2)?; // the low half of Apple's version
            (reader.u32()? as usize, true)
        }
        _ => return None,
    };

    let mut next = reader.position();
    for _ in 0..count {
        let mut header = Reader::at(data, next);
        let (length, coverage) = if apple {
            let length = header.u32()? as usize;
            let coverage = header.u16()?;
            header.skip(2)?; // tupleIndex, which only a variable font sets
            (length, coverage)
        } else {
            header.skip(2)?; // subtable version
            let length = header.u16()? as usize;
            (length, header.u16()?)
        };
        // A subtable of no length cannot be stepped over, so the table is
        // corrupt and what follows it cannot be trusted either.
        if length == 0 {
            return None;
        }

        if horizontal_format_0(coverage, apple) {
            read_kern_pairs(data, header.position(), out)?;
        }
        next = next.checked_add(length)?;
        if next >= data.len() {
            break;
        }
    }
    Some(())
}

/// Whether a `kern` subtable is one whose numbers simply add to the advance.
///
/// The two layouts disagree about where the format lives and which way the
/// direction bit reads, which is the whole reason this is a function.
fn horizontal_format_0(coverage: u16, apple: bool) -> bool {
    if apple {
        // Apple: the format is the low byte; bit 15 is vertical, bit 14 is
        // cross-stream, bit 13 is variation.
        coverage & 0x00ff == 0 && coverage & 0xe000 == 0
    } else {
        // OpenType: the format is the high byte; bit 0 is horizontal, bit 1 is
        // "these are minimums", bit 2 is cross-stream.
        coverage >> 8 == 0 && coverage & 0x0007 == 0x0001
    }
}

/// Reads the body of a format 0 `kern` subtable: a flat list of pairs.
fn read_kern_pairs(data: &[u8], body: usize, out: &mut Vec<Pairs>) -> Option<()> {
    let mut reader = Reader::at(data, body);
    let count = reader.u16()?;
    reader.skip(6)?; // searchRange, entrySelector, rangeShift

    let mut pairs = HashMap::new();
    for _ in 0..count {
        let left = reader.u16()?;
        let right = reader.u16()?;
        let value = reader.i16()?;
        if value != 0 && pairs.len() < MAX_LISTED_PAIRS {
            pairs.insert((left, right), value);
        }
    }

    if !pairs.is_empty() {
        out.push(Pairs::Listed(pairs));
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u16s(values: &[u16]) -> Vec<u8> {
        values.iter().flat_map(|value| value.to_be_bytes()).collect()
    }

    /// A font file holding one table, and the directory that finds it.
    fn font_with(tag: &[u8; 4], body: Vec<u8>) -> Vec<u8> {
        let mut file = 0x0001_0000u32.to_be_bytes().to_vec();
        file.extend(u16s(&[1, 0, 0, 0])); // one table, and the unused search hints
        file.extend(tag);
        file.extend(0u32.to_be_bytes()); // checksum
        file.extend(28u32.to_be_bytes()); // where the table starts
        file.extend((body.len() as u32).to_be_bytes());
        file.extend(body);
        file
    }

    fn kerning_of(tag: &[u8; 4], body: Vec<u8>) -> Kerning {
        let data = font_with(tag, body);
        let directory = Directory::read(&data, 0).expect("the assembled file must have a directory");
        Kerning::read(&data, &directory)
    }

    /// A `kern` table in the OpenType layout, with the pairs given.
    fn kern_table(pairs: &[(u16, u16, i16)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (left, right, value) in pairs {
            body.extend(u16s(&[*left, *right, *value as u16]));
        }
        let mut table = u16s(&[0, 1]); // version, one subtable
        table.extend(u16s(&[0, (14 + body.len()) as u16, 0x0001])); // version, length, coverage
        table.extend(u16s(&[pairs.len() as u16, 0, 0, 0])); // nPairs and the search hints
        table.extend(body);
        table
    }

    #[test]
    fn a_font_with_no_tables_kerns_nothing() {
        let kerning = kerning_of(b"post", Vec::new());
        assert!(kerning.is_empty());
        assert_eq!(kerning.adjustment(1, 2), 0);
    }

    #[test]
    fn the_kern_table_states_pairs_and_only_those_pairs() {
        let kerning = kerning_of(b"kern", kern_table(&[(3, 7, -80), (7, 3, 25)]));
        assert!(!kerning.is_empty());
        assert_eq!(kerning.adjustment(3, 7), -80);
        assert_eq!(kerning.adjustment(7, 3), 25);
        assert_eq!(kerning.adjustment(3, 3), 0, "a pair the font says nothing about");
        assert_eq!(kerning.adjustment(999, 999), 0, "glyphs the font does not have");
    }

    #[test]
    fn a_vertical_kern_subtable_is_left_alone() {
        let mut table = kern_table(&[(3, 7, -80)]);
        table[8..10].copy_from_slice(&0x0000u16.to_be_bytes()); // clear the horizontal bit
        assert!(kerning_of(b"kern", table).is_empty());
    }

    #[test]
    fn a_truncated_kern_table_kerns_nothing_rather_than_panicking() {
        let mut table = kern_table(&[(3, 7, -80), (7, 3, 25)]);
        table.truncate(table.len() - 3);
        // A subtable that runs off the end is dropped whole rather than kept
        // as far as it parsed, because half a subtable is not what the font
        // said. What matters is that it does not panic inside a redraw.
        assert!(kerning_of(b"kern", table).is_empty());
    }

    /// A coverage table in format 1, listing glyphs one at a time.
    fn coverage(glyphs: &[u16]) -> Vec<u8> {
        let mut table = u16s(&[1, glyphs.len() as u16]);
        table.extend(u16s(glyphs));
        table
    }

    /// A `GPOS` table wrapping one pair positioning subtable.
    ///
    /// Laid out as header, feature list, lookup list, lookup, subtable, so
    /// every offset below is the length of what came before it.
    fn gpos(subtable: Vec<u8>) -> Vec<u8> {
        let features = 10;
        let lookups = features + 14;
        let lookup = lookups + 4;
        let pair_pos = lookup + 8;

        let mut table = u16s(&[1, 0, 0, features as u16, lookups as u16]);
        // One feature, tagged `kern`, naming lookup zero.
        table.extend(u16s(&[1]));
        table.extend(b"kern");
        table.extend(u16s(&[8, 0, 1, 0])); // offset to it, featureParams, one index, index 0
        // One lookup, of type 2, with one subtable.
        table.extend(u16s(&[1, 4]));
        table.extend(u16s(&[2, 0, 1, (pair_pos - lookup) as u16]));
        table.extend(subtable);
        table
    }

    #[test]
    fn gpos_states_pairs_one_at_a_time() {
        // Coverage of glyph 3 at 12, one pair set at 18 naming glyph 7.
        let mut subtable = u16s(&[1, 12, X_ADVANCE, 0, 1, 18]);
        subtable.extend(coverage(&[3]));
        subtable.extend(u16s(&[1, 7, (-80i16) as u16])); // one pair: glyph 7, -80

        let kerning = kerning_of(b"GPOS", gpos(subtable));
        assert_eq!(kerning.adjustment(3, 7), -80);
        assert_eq!(kerning.adjustment(7, 3), 0);
    }

    #[test]
    fn gpos_states_pairs_as_a_matrix_over_classes() {
        // Glyphs 3 and 4 are class 1 on the left; glyph 7 is class 1 on the
        // right. The matrix is two by two, and only (1, 1) is set.
        let mut subtable = u16s(&[2, 44, X_ADVANCE, 0, 24, 34, 2, 2]);
        subtable.extend(u16s(&[0, 0, 0, (-120i16) as u16])); // the matrix, at 16
        subtable.extend(u16s(&[2, 1, 3, 4, 1])); // class def 2 at 24: glyphs 3-4 are class 1
        subtable.extend(u16s(&[2, 1, 7, 7, 1])); // class def 2 at 34: glyph 7 is class 1
        subtable.extend(coverage(&[3, 4])); // at 44

        let kerning = kerning_of(b"GPOS", gpos(subtable));
        assert_eq!(kerning.adjustment(3, 7), -120);
        assert_eq!(kerning.adjustment(4, 7), -120, "the class covers both glyphs");
        assert_eq!(kerning.adjustment(3, 8), 0, "class zero on the right");
        assert_eq!(kerning.adjustment(5, 7), 0, "a glyph outside the coverage");
    }

    #[test]
    fn a_value_record_is_read_past_whatever_it_holds() {
        // Placement, advance, and a device offset: only the advance is wanted,
        // and the cursor must land after all three.
        let bytes = u16s(&[1, (-40i16) as u16, 9, 0xffff]);
        let mut reader = Reader::at(&bytes, 0);
        assert_eq!(read_value_record(&mut reader, 0x0001 | X_ADVANCE | 0x0010), Some(-40));
        assert_eq!(reader.u16(), Some(0xffff), "the cursor must be past the record");
    }

    #[test]
    fn a_class_definition_answers_zero_for_everything_it_omits() {
        let bytes = u16s(&[1, 5, 3, 0, 2, 1]); // format 1: glyphs 5, 6, 7
        let classes = read_class_def(&bytes, 0).expect("a well-formed class definition");
        assert_eq!(classes.class(5), 0);
        assert_eq!(classes.class(6), 2);
        assert_eq!(classes.class(7), 1);
        assert_eq!(classes.class(400), 0);
    }

    #[test]
    fn overlapping_classes_are_refused_rather_than_resolved_arbitrarily() {
        let bytes = u16s(&[2, 2, 3, 9, 1, 5, 12, 2]); // 3-9 and 5-12 overlap
        assert!(read_class_def(&bytes, 0).is_none());
    }
}
