//! Reading the SFNT container: the table directory, and the character map.
//!
//! Every read is bounds-checked and answers `Option`, because a font file is
//! input like any other. These files come from the operating system rather than
//! from the network, but "trusted source" is not a memory-safety argument, and a
//! truncated or hostile font must fail to load rather than panic inside a redraw.

/// A cursor over a font file that cannot read past the end.
pub(super) struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    /// A reader positioned at `offset`, or at the end if that is out of range.
    pub(super) fn at(data: &'a [u8], offset: usize) -> Self {
        Self { data, position: offset.min(data.len()) }
    }

    /// How far into the file the cursor is.
    pub(super) fn position(&self) -> usize {
        self.position
    }

    /// Advances the cursor, failing if that would pass the end.
    pub(super) fn skip(&mut self, bytes: usize) -> Option<()> {
        self.position = self.position.checked_add(bytes).filter(|end| *end <= self.data.len())?;
        Some(())
    }

    /// The next `count` bytes.
    pub(super) fn bytes(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.position.checked_add(count)?;
        let slice = self.data.get(self.position..end)?;
        self.position = end;
        Some(slice)
    }

    /// The next unsigned byte.
    pub(super) fn u8(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.position)?;
        self.position += 1;
        Some(byte)
    }

    /// The next big-endian `u16`.
    pub(super) fn u16(&mut self) -> Option<u16> {
        let bytes = self.bytes(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// The next big-endian `i16`.
    pub(super) fn i16(&mut self) -> Option<i16> {
        self.u16().map(|value| value as i16)
    }

    /// The next big-endian `u32`.
    pub(super) fn u32(&mut self) -> Option<u32> {
        let bytes = self.bytes(4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// The next `F2Dot14` fixed-point value, used by composite glyph transforms.
    pub(super) fn f2dot14(&mut self) -> Option<f32> {
        self.i16().map(|value| value as f32 / 16384.0)
    }
}

/// Where one table lives in the file.
#[derive(Debug, Clone, Copy)]
pub(super) struct Table {
    /// Offset from the start of the file.
    pub(super) offset: usize,
    /// Length in bytes.
    pub(super) length: usize,
}

/// The tables of one font, by four-character tag.
pub(super) struct Directory {
    entries: Vec<([u8; 4], Table)>,
}

impl Directory {
    /// Reads the table directory of the font at `offset`.
    ///
    /// Accepts the two SFNT version tags that carry TrueType outlines, and
    /// `OTTO` — which is an OpenType font with PostScript outlines. `OTTO` is
    /// admitted here and refused later by name, so the failure says "this font
    /// has no TrueType outlines" instead of "this is not a font".
    pub(super) fn read(data: &[u8], offset: usize) -> Option<Self> {
        let mut reader = Reader::at(data, offset);
        let version = reader.u32()?;
        // 0x00010000 is TrueType; `true` is the older Apple tag; `OTTO` is
        // OpenType with PostScript outlines.
        if !matches!(version, 0x0001_0000 | 0x7472_7565 | 0x4f54_544f) {
            return None;
        }

        let count = reader.u16()? as usize;
        reader.skip(6)?; // searchRange, entrySelector, rangeShift
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            let tag = reader.bytes(4)?;
            let tag = [tag[0], tag[1], tag[2], tag[3]];
            reader.skip(4)?; // checksum
            let table_offset = reader.u32()? as usize;
            let length = reader.u32()? as usize;
            // A table claiming to run past the end of the file is dropped rather
            // than clamped: a wrong length is a corrupt font, and silently
            // shortening it would hand later parsing a plausible-looking lie.
            if table_offset.checked_add(length).is_some_and(|end| end <= data.len()) {
                entries.push((tag, Table { offset: table_offset, length }));
            }
        }
        Some(Self { entries })
    }

    /// The table with this tag, if the font has it.
    pub(super) fn find(&self, tag: &[u8; 4]) -> Option<Table> {
        self.entries.iter().find(|(entry, _)| entry == tag).map(|(_, table)| *table)
    }
}

/// The offsets of every font inside a file.
///
/// A plain font file answers one offset; a TrueType collection — which is what
/// most of the fonts shipped with macOS are — answers one per face it packs.
pub(super) fn face_offsets(data: &[u8]) -> Option<Vec<usize>> {
    if data.len() >= 4 && &data[..4] == b"ttcf" {
        let mut reader = Reader::at(data, 8);
        let count = reader.u32()? as usize;
        // A collection header is 12 bytes plus four per face; a count that could
        // not fit is a corrupt file, and reserving from it would be a way to ask
        // for an arbitrary allocation.
        if 12 + count.checked_mul(4)? > data.len() {
            return None;
        }
        let mut offsets = Vec::with_capacity(count);
        for _ in 0..count {
            offsets.push(reader.u32()? as usize);
        }
        Some(offsets)
    } else {
        Some(vec![0])
    }
}

/// One run of character codes that map to glyphs the same way.
///
/// Both `cmap` formats this reads reduce to ranges: format 4's `idDelta`
/// segments and format 12's groups are both "add a constant", and format 4's
/// `idRangeOffset` segments are the one case that needs the glyph ids spelled
/// out. Holding them as ranges rather than expanding every character keeps a
/// CJK font's map to a few hundred entries instead of tens of thousands.
enum Segment {
    /// `glyph = character + delta`, wrapping at 16 bits as the format requires.
    Delta { start: u32, end: u32, delta: i32 },
    /// Glyph ids listed one per character from `start`.
    Explicit { start: u32, end: u32, glyphs: Vec<u16> },
}

impl Segment {
    fn start(&self) -> u32 {
        match self {
            Self::Delta { start, .. } | Self::Explicit { start, .. } => *start,
        }
    }

    fn end(&self) -> u32 {
        match self {
            Self::Delta { end, .. } | Self::Explicit { end, .. } => *end,
        }
    }

    fn lookup(&self, character: u32) -> u16 {
        match self {
            Self::Delta { delta, .. } => (character as i32).wrapping_add(*delta) as u16,
            Self::Explicit { start, glyphs, .. } => {
                glyphs.get((character - start) as usize).copied().unwrap_or(0)
            }
        }
    }
}

/// Characters to glyph indices.
pub(super) struct CharMap {
    segments: Vec<Segment>,
}

impl CharMap {
    /// The glyph for a character, or 0 — `.notdef` — when the font has none.
    pub(super) fn glyph(&self, character: char) -> u16 {
        let code = character as u32;
        let found = self.segments.binary_search_by(|segment| {
            if segment.end() < code {
                std::cmp::Ordering::Less
            } else if segment.start() > code {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        });
        match found {
            Ok(index) => self.segments[index].lookup(code),
            Err(_) => 0,
        }
    }

    /// Reads the best character map the font offers.
    ///
    /// "Best" is the widest: a format 12 table covering all of Unicode is
    /// preferred over a format 4 table that stops at U+FFFF, and a Windows
    /// encoding over a Macintosh one. The alternative — taking the first
    /// subtable — picks the legacy 8-bit map on many fonts and loses every
    /// character past ASCII.
    pub(super) fn read(data: &[u8], table: Table) -> Option<Self> {
        let mut reader = Reader::at(data, table.offset);
        reader.skip(2)?; // version
        let count = reader.u16()? as usize;

        let mut best: Option<(u32, usize)> = None;
        for _ in 0..count {
            let platform = reader.u16()?;
            let encoding = reader.u16()?;
            let subtable = table.offset.checked_add(reader.u32()? as usize)?;
            let rank = match (platform, encoding) {
                (3, 10) => 4, // Windows, full Unicode
                (0, 4) | (0, 6) => 3, // Unicode, full repertoire
                (3, 1) => 2,  // Windows, basic multilingual plane
                (0, _) => 1,  // Unicode, older
                _ => 0,
            };
            if rank > 0 && best.is_none_or(|(best_rank, _)| rank > best_rank) {
                best = Some((rank, subtable));
            }
        }

        let (_, subtable) = best?;
        let mut segments = match Reader::at(data, subtable).u16()? {
            4 => read_format_4(data, subtable)?,
            12 => read_format_12(data, subtable)?,
            _ => return None,
        };

        // Binary search in `glyph` needs the segments ordered and disjoint. Both
        // formats specify sorted segments, but a font that breaks that would
        // otherwise turn into wrong glyphs rather than a refusal to load.
        segments.sort_by_key(|segment| segment.start());
        if segments.windows(2).any(|pair| pair[0].end() >= pair[1].start()) {
            return None;
        }
        Some(Self { segments })
    }
}

/// Reads a format 4 subtable: segments over the basic multilingual plane.
fn read_format_4(data: &[u8], offset: usize) -> Option<Vec<Segment>> {
    let mut reader = Reader::at(data, offset);
    reader.skip(6)?; // format, length, language
    let segment_count = reader.u16()? as usize / 2;
    reader.skip(6)?; // searchRange, entrySelector, rangeShift

    let ends: Vec<u16> = (0..segment_count).map(|_| reader.u16()).collect::<Option<_>>()?;
    reader.skip(2)?; // reservedPad
    let starts: Vec<u16> = (0..segment_count).map(|_| reader.u16()).collect::<Option<_>>()?;
    let deltas: Vec<i16> = (0..segment_count).map(|_| reader.i16()).collect::<Option<_>>()?;

    // `idRangeOffset` is a byte offset measured from its own position in the
    // file, so where each one sits has to be remembered to resolve it.
    let range_offset_base = reader.position();
    let range_offsets: Vec<u16> = (0..segment_count).map(|_| reader.u16()).collect::<Option<_>>()?;

    let mut segments = Vec::with_capacity(segment_count);
    for index in 0..segment_count {
        let (start, end) = (starts[index] as u32, ends[index] as u32);
        // The format requires a final segment mapping 0xFFFF to nothing.
        if start > end || start == 0xffff {
            continue;
        }

        if range_offsets[index] == 0 {
            segments.push(Segment::Delta { start, end, delta: deltas[index] as i32 });
            continue;
        }

        let base = range_offset_base + index * 2 + range_offsets[index] as usize;
        let mut glyphs = Vec::with_capacity((end - start + 1) as usize);
        for character in start..=end {
            let mut entry = Reader::at(data, base + (character - start) as usize * 2);
            let glyph = entry.u16()?;
            // A zero entry means "no glyph" and must not have the delta added,
            // or every unmapped character in the segment would resolve to a real
            // glyph somewhere else in the font.
            glyphs.push(if glyph == 0 {
                0
            } else {
                (glyph as i32).wrapping_add(deltas[index] as i32) as u16
            });
        }
        segments.push(Segment::Explicit { start, end, glyphs });
    }
    Some(segments)
}

/// Reads a format 12 subtable: groups over all of Unicode.
fn read_format_12(data: &[u8], offset: usize) -> Option<Vec<Segment>> {
    let mut reader = Reader::at(data, offset);
    reader.skip(12)?; // format, reserved, length, language
    let count = reader.u32()? as usize;
    // Each group is 12 bytes; a count that could not fit in the file is corrupt,
    // and reserving from it would be an allocation controlled by the file.
    if count.checked_mul(12)? > data.len() {
        return None;
    }

    let mut segments = Vec::with_capacity(count);
    for _ in 0..count {
        let start = reader.u32()?;
        let end = reader.u32()?;
        let first_glyph = reader.u32()?;
        if start > end {
            continue;
        }
        segments.push(Segment::Delta {
            start,
            end,
            delta: (first_glyph as i64 - start as i64) as i32,
        });
    }
    Some(segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reader_refuses_to_run_off_the_end() {
        let mut reader = Reader::at(&[1, 2, 3], 0);
        assert_eq!(reader.u16(), Some(0x0102));
        assert_eq!(reader.u16(), None, "read past the end");
        assert_eq!(reader.u8(), Some(3), "a failed read must not consume input");
    }

    #[test]
    fn seeking_past_the_end_lands_at_the_end_rather_than_out_of_range() {
        let mut reader = Reader::at(&[1, 2, 3], 999);
        assert_eq!(reader.position(), 3);
        assert_eq!(reader.u8(), None);
    }

    #[test]
    fn skipping_past_the_end_fails_instead_of_wrapping() {
        let mut reader = Reader::at(&[1, 2, 3], 0);
        assert_eq!(reader.skip(usize::MAX), None);
        assert_eq!(reader.position(), 0);
    }

    #[test]
    fn a_plain_font_has_one_face_and_a_collection_has_several() {
        assert_eq!(face_offsets(&[0, 1, 0, 0]), Some(vec![0]));

        let mut collection = b"ttcf".to_vec();
        collection.extend_from_slice(&[0, 1, 0, 0]); // version
        collection.extend_from_slice(&2u32.to_be_bytes());
        collection.extend_from_slice(&100u32.to_be_bytes());
        collection.extend_from_slice(&200u32.to_be_bytes());
        collection.resize(256, 0);
        assert_eq!(face_offsets(&collection), Some(vec![100, 200]));
    }

    #[test]
    fn a_collection_claiming_more_faces_than_could_fit_is_refused() {
        let mut collection = b"ttcf".to_vec();
        collection.extend_from_slice(&[0, 1, 0, 0]);
        collection.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(face_offsets(&collection), None);
    }

    #[test]
    fn a_delta_segment_maps_by_addition() {
        let map = CharMap { segments: vec![Segment::Delta { start: 65, end: 90, delta: -29 }] };
        assert_eq!(map.glyph('A'), 36);
        assert_eq!(map.glyph('Z'), 61);
        assert_eq!(map.glyph('a'), 0, "outside every segment is .notdef");
    }

    #[test]
    fn an_explicit_segment_maps_by_lookup() {
        let map = CharMap {
            segments: vec![Segment::Explicit { start: 10, end: 12, glyphs: vec![7, 0, 9] }],
        };
        assert_eq!(map.glyph('\u{a}'), 7);
        assert_eq!(map.glyph('\u{b}'), 0, "a zero entry stays unmapped");
        assert_eq!(map.glyph('\u{c}'), 9);
    }

    #[test]
    fn lookup_finds_the_right_segment_among_many() {
        let map = CharMap {
            segments: vec![
                Segment::Delta { start: 0, end: 10, delta: 1 },
                Segment::Delta { start: 100, end: 110, delta: 2 },
                Segment::Delta { start: 1000, end: 1010, delta: 3 },
            ],
        };
        assert_eq!(map.glyph('\u{5}'), 6);
        assert_eq!(map.glyph('\u{69}'), 107);
        assert_eq!(map.glyph('\u{3ea}'), 1005);
        assert_eq!(map.glyph('\u{32}'), 0, "the gap between segments is unmapped");
    }
}
