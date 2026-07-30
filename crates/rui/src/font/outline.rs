//! Reading glyph outlines out of the `glyf` table and flattening them to edges.
//!
//! TrueType describes a glyph as closed contours of quadratic B-splines, with a
//! compact twist: consecutive off-curve points imply an on-curve point halfway
//! between them, so a run of curves stores one point each instead of two. The
//! reconstruction here puts those implied points back before walking the
//! contour, which turns a case that is easy to get subtly wrong into an
//! ordinary alternating sequence.
//!
//! Curves are flattened to straight edges *here*, at the size the glyph will be
//! drawn, rather than being handed to the rasteriser as curves. Flattening
//! needs to know the scale to pick a segment count — the same curve needs one
//! segment in a table row and a dozen in a heading — and the rasteriser is
//! simpler and faster for only ever seeing lines.

use super::sfnt::{Reader, Table};

/// How far a flattened curve may stray from the true one, in device pixels.
///
/// A fifth of a pixel: below what antialiasing can express, so tightening it
/// further costs segments and changes no pixel.
const FLATTENING_TOLERANCE: f32 = 0.2;

/// The most segments one curve is split into.
///
/// Reached only by curves far larger than any text, and it bounds the work a
/// single glyph can demand.
const MAX_SEGMENTS: usize = 24;

/// How deep composite glyphs may nest before the font is treated as broken.
///
/// Composites refer to other glyphs by index, and nothing in the format stops
/// one referring to itself. Real fonts nest one or two deep — an accented
/// letter built from a letter and an accent.
const MAX_COMPOSITE_DEPTH: u32 = 8;

/// An affine map from font units to device pixels.
#[derive(Debug, Clone, Copy)]
pub(super) struct Transform {
    a: f32,
    b: f32,
    c: f32,
    d: f32,
    dx: f32,
    dy: f32,
}

impl Transform {
    /// The map from font units to pixels for a glyph drawn at `scale`.
    ///
    /// `scale` is pixels per font unit. The y axis is negated because font
    /// coordinates grow upward from the baseline and pixels grow downward.
    /// `origin` is where the glyph's baseline origin lands on the mask.
    pub(super) fn for_glyph(scale: f32, origin: (f32, f32)) -> Self {
        Self { a: scale, b: 0.0, c: 0.0, d: -scale, dx: origin.0, dy: origin.1 }
    }

    /// A component's own map, in font units, before its parent's is applied.
    fn component(a: f32, b: f32, c: f32, d: f32, dx: f32, dy: f32) -> Self {
        Self { a, b, c, d, dx, dy }
    }

    /// Where a point in this transform's input space lands.
    fn apply(self, x: f32, y: f32) -> (f32, f32) {
        (self.a * x + self.c * y + self.dx, self.b * x + self.d * y + self.dy)
    }

    /// This transform followed by `outer`.
    fn then(self, outer: Self) -> Self {
        Self {
            a: self.a * outer.a + self.b * outer.c,
            b: self.a * outer.b + self.b * outer.d,
            c: self.c * outer.a + self.d * outer.c,
            d: self.c * outer.b + self.d * outer.d,
            dx: self.dx * outer.a + self.dy * outer.c + outer.dx,
            dy: self.dx * outer.b + self.dy * outer.d + outer.dy,
        }
    }
}

/// Where a font's glyph outlines live, and how they are indexed.
///
/// Gathered into one value because these five travel together through every
/// step of reading a glyph — including the recursion into a composite's
/// components — and threading them individually made the signature longer than
/// the work it described.
#[derive(Clone, Copy)]
pub(super) struct GlyphSource<'a> {
    /// The whole font file.
    pub(super) data: &'a [u8],
    /// The table holding the outlines.
    pub(super) glyf: Table,
    /// The table of offsets into it.
    pub(super) loca: Table,
    /// Whether those offsets are four bytes rather than two.
    pub(super) long_offsets: bool,
    /// How many glyphs the font has.
    pub(super) glyph_count: u16,
}

/// Collects the straight edges a glyph's contours flatten to.
pub(super) struct Edges {
    /// Every edge as a pair of endpoints, in device pixels.
    pub(super) segments: Vec<((f32, f32), (f32, f32))>,
    start: Option<(f32, f32)>,
    current: (f32, f32),
}

impl Edges {
    /// An empty collection.
    pub(super) fn new() -> Self {
        Self { segments: Vec::new(), start: None, current: (0.0, 0.0) }
    }

    /// The bounding box of every edge collected, or `None` when there are none.
    pub(super) fn bounds(&self) -> Option<((f32, f32), (f32, f32))> {
        let mut min = (f32::INFINITY, f32::INFINITY);
        let mut max = (f32::NEG_INFINITY, f32::NEG_INFINITY);
        for (from, to) in &self.segments {
            for point in [from, to] {
                min = (min.0.min(point.0), min.1.min(point.1));
                max = (max.0.max(point.0), max.1.max(point.1));
            }
        }
        (min.0 <= max.0).then_some((min, max))
    }

    fn move_to(&mut self, point: (f32, f32)) {
        self.close();
        self.start = Some(point);
        self.current = point;
    }

    fn line_to(&mut self, point: (f32, f32)) {
        if self.start.is_some() {
            self.segments.push((self.current, point));
            self.current = point;
        }
    }

    /// Flattens one quadratic segment into straight edges.
    ///
    /// The segment count comes from how far the curve bows away from its chord:
    /// splitting into `n` reduces that error by `n²`, so the count needed for a
    /// given tolerance is the square root of the ratio.
    fn quadratic_to(&mut self, control: (f32, f32), end: (f32, f32)) {
        let start = self.current;
        let bow_x = start.0 - 2.0 * control.0 + end.0;
        let bow_y = start.1 - 2.0 * control.1 + end.1;
        let deviation = (bow_x * bow_x + bow_y * bow_y).sqrt() / 8.0;

        let steps = if deviation <= FLATTENING_TOLERANCE {
            1
        } else {
            ((deviation / FLATTENING_TOLERANCE).sqrt().ceil() as usize).clamp(1, MAX_SEGMENTS)
        };

        for step in 1..=steps {
            let t = step as f32 / steps as f32;
            let inverse = 1.0 - t;
            let point = (
                inverse * inverse * start.0 + 2.0 * inverse * t * control.0 + t * t * end.0,
                inverse * inverse * start.1 + 2.0 * inverse * t * control.1 + t * t * end.1,
            );
            self.line_to(point);
        }
    }

    /// Closes the contour in progress, if any.
    ///
    /// Contours are closed here rather than being trusted to close themselves:
    /// the format defines them as closed, but leaving a gap because a font did
    /// not repeat its first point would let the fill leak across the whole row.
    fn close(&mut self) {
        if let Some(start) = self.start.take() {
            if start != self.current {
                self.segments.push((self.current, start));
            }
        }
    }
}

/// Where one glyph's description sits inside `glyf`, or `None` when it is blank.
///
/// A blank glyph — a space — is stored as a zero-length entry rather than as an
/// outline with no contours, so an empty range is normal and not an error.
fn glyph_range(source: &GlyphSource<'_>, glyph: u16) -> Option<(usize, usize)> {
    if glyph >= source.glyph_count {
        return None;
    }
    let index = glyph as usize;
    let (start, end) = if source.long_offsets {
        let mut reader = Reader::at(source.data, source.loca.offset + index * 4);
        (reader.u32()? as usize, reader.u32()? as usize)
    } else {
        let mut reader = Reader::at(source.data, source.loca.offset + index * 2);
        // The short format stores halved offsets, which is why every glyph in a
        // short-`loca` font must start on an even byte.
        (reader.u16()? as usize * 2, reader.u16()? as usize * 2)
    };
    (end > start).then_some((start, end))
}

/// Appends one glyph's flattened outline to `edges`.
///
/// Answers `None` only when the font is malformed; a glyph with no outline —
/// a space — succeeds and appends nothing.
pub(super) fn append_glyph(
    source: &GlyphSource<'_>,
    glyph: u16,
    transform: Transform,
    edges: &mut Edges,
    depth: u32,
) -> Option<()> {
    if depth > MAX_COMPOSITE_DEPTH {
        return None;
    }
    let Some((start, end)) = glyph_range(source, glyph) else {
        return Some(());
    };
    let description = source.glyf.offset.checked_add(start)?;
    if end > source.glyf.length {
        return None;
    }

    let mut reader = Reader::at(source.data, description);
    let contour_count = reader.i16()?;
    reader.skip(8)?; // the glyph's own bounding box, which we do not trust

    if contour_count >= 0 {
        append_simple(&mut reader, contour_count as usize, transform, edges)
    } else {
        append_composite(source, &mut reader, transform, edges, depth)
    }
}

/// Reads a glyph made of its own contours.
fn append_simple(
    reader: &mut Reader<'_>,
    contour_count: usize,
    transform: Transform,
    edges: &mut Edges,
) -> Option<()> {
    if contour_count == 0 {
        return Some(());
    }

    let mut contour_ends = Vec::with_capacity(contour_count);
    for _ in 0..contour_count {
        contour_ends.push(reader.u16()? as usize);
    }
    // Ends must ascend, or the contour ranges derived from them overlap.
    if contour_ends.windows(2).any(|pair| pair[1] <= pair[0]) {
        return None;
    }
    let point_count = contour_ends[contour_count - 1] + 1;

    let instruction_length = reader.u16()? as usize;
    // Hinting instructions are skipped deliberately. They are a bytecode meant
    // to snap stems to a low-resolution pixel grid, which is a problem that
    // largely went away with HiDPI displays, and interpreting them would be a
    // second language to implement and sandbox.
    reader.skip(instruction_length)?;

    let flags = read_flags(reader, point_count)?;
    let xs = read_coordinates(reader, &flags, 0x02, 0x10)?;
    let ys = read_coordinates(reader, &flags, 0x04, 0x20)?;

    let mut first = 0usize;
    for &last in &contour_ends {
        let points: Vec<Point> = (first..=last)
            .map(|index| Point {
                position: transform.apply(xs[index], ys[index]),
                on_curve: flags[index] & 0x01 != 0,
            })
            .collect();
        append_contour(&points, edges);
        first = last + 1;
    }
    edges.close();
    Some(())
}

/// Reads a glyph assembled from other glyphs.
fn append_composite(
    source: &GlyphSource<'_>,
    reader: &mut Reader<'_>,
    transform: Transform,
    edges: &mut Edges,
    depth: u32,
) -> Option<()> {
    const ARGUMENTS_ARE_WORDS: u16 = 0x0001;
    const ARGUMENTS_ARE_OFFSETS: u16 = 0x0002;
    const HAS_SCALE: u16 = 0x0008;
    const HAS_MORE: u16 = 0x0020;
    const HAS_XY_SCALE: u16 = 0x0040;
    const HAS_TWO_BY_TWO: u16 = 0x0080;

    loop {
        let flags = reader.u16()?;
        let component = reader.u16()?;

        let (dx, dy) = if flags & ARGUMENTS_ARE_WORDS != 0 {
            (reader.i16()? as f32, reader.i16()? as f32)
        } else {
            (reader.u8()? as i8 as f32, reader.u8()? as i8 as f32)
        };

        // The alternative to offsets is "align these two point indices", which
        // needs the parent's points to have been read already. No font in
        // ordinary use does it, so the component is placed at the origin rather
        // than at a guess: a visibly misplaced accent is easier to diagnose than
        // one silently offset by whatever the arguments happened to be.
        let (dx, dy) = if flags & ARGUMENTS_ARE_OFFSETS != 0 { (dx, dy) } else { (0.0, 0.0) };

        let component_transform = if flags & HAS_TWO_BY_TWO != 0 {
            let (a, b, c, d) =
                (reader.f2dot14()?, reader.f2dot14()?, reader.f2dot14()?, reader.f2dot14()?);
            Transform::component(a, b, c, d, dx, dy)
        } else if flags & HAS_XY_SCALE != 0 {
            let (x, y) = (reader.f2dot14()?, reader.f2dot14()?);
            Transform::component(x, 0.0, 0.0, y, dx, dy)
        } else if flags & HAS_SCALE != 0 {
            let scale = reader.f2dot14()?;
            Transform::component(scale, 0.0, 0.0, scale, dx, dy)
        } else {
            Transform::component(1.0, 0.0, 0.0, 1.0, dx, dy)
        };

        append_glyph(source, component, component_transform.then(transform), edges, depth + 1)?;

        if flags & HAS_MORE == 0 {
            return Some(());
        }
    }
}

/// One outline point and whether the curve passes through it.
#[derive(Clone, Copy, PartialEq)]
struct Point {
    position: (f32, f32),
    on_curve: bool,
}

/// Walks one contour, emitting lines and flattened curves.
///
/// The implied on-curve points between consecutive off-curve points are
/// inserted first, so the walk below only ever sees an alternating sequence and
/// needs no special case for a run of curves.
fn append_contour(points: &[Point], edges: &mut Edges) {
    if points.len() < 2 {
        return;
    }

    let mut expanded = Vec::with_capacity(points.len() * 2);
    for (index, &point) in points.iter().enumerate() {
        let previous = points[(index + points.len() - 1) % points.len()];
        if !previous.on_curve && !point.on_curve {
            expanded.push(Point { position: midpoint(previous.position, point.position), on_curve: true });
        }
        expanded.push(point);
    }

    // A contour can legally have no on-curve point at all — a circle drawn from
    // four control points. Starting from an implied midpoint gives the walk the
    // on-curve start it needs without changing the shape.
    let Some(start) = expanded.iter().position(|point| point.on_curve).or_else(|| {
        let first = expanded.first().copied()?;
        let last = expanded.last().copied()?;
        expanded.insert(0, Point { position: midpoint(last.position, first.position), on_curve: true });
        Some(0)
    }) else {
        return;
    };

    edges.move_to(expanded[start].position);
    let count = expanded.len();
    let mut step = 1;
    while step <= count {
        let point = expanded[(start + step) % count];
        if point.on_curve {
            edges.line_to(point.position);
            step += 1;
        } else {
            let end = expanded[(start + step + 1) % count];
            edges.quadratic_to(point.position, end.position);
            step += 2;
        }
    }
    edges.close();
}

fn midpoint(a: (f32, f32), b: (f32, f32)) -> (f32, f32) {
    ((a.0 + b.0) / 2.0, (a.1 + b.1) / 2.0)
}

/// Reads the per-point flag array, expanding its run-length encoding.
fn read_flags(reader: &mut Reader<'_>, point_count: usize) -> Option<Vec<u8>> {
    const REPEATS: u8 = 0x08;

    let mut flags = Vec::with_capacity(point_count);
    while flags.len() < point_count {
        let flag = reader.u8()?;
        flags.push(flag);
        if flag & REPEATS != 0 {
            let repeats = reader.u8()? as usize;
            // A repeat count that overruns the contour is a corrupt font; taking
            // only what fits would leave the coordinate arrays misaligned and
            // draw a plausible but wrong glyph.
            if flags.len() + repeats > point_count {
                return None;
            }
            flags.extend(std::iter::repeat_n(flag, repeats));
        }
    }
    Some(flags)
}

/// Reads one delta-encoded coordinate array into absolute font units.
///
/// Both axes encode the same way, differing only in which flag bits they use:
/// `short_bit` says the delta is a single unsigned byte, and `same_bit` then
/// gives its sign — or, when the delta is not short, says the coordinate did
/// not change at all.
fn read_coordinates(
    reader: &mut Reader<'_>,
    flags: &[u8],
    short_bit: u8,
    same_bit: u8,
) -> Option<Vec<f32>> {
    let mut coordinates = Vec::with_capacity(flags.len());
    let mut position = 0i32;
    for &flag in flags {
        if flag & short_bit != 0 {
            let delta = reader.u8()? as i32;
            position += if flag & same_bit != 0 { delta } else { -delta };
        } else if flag & same_bit == 0 {
            position += reader.i16()? as i32;
        }
        coordinates.push(position as f32);
    }
    Some(coordinates)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> Transform {
        Transform::component(1.0, 0.0, 0.0, 1.0, 0.0, 0.0)
    }

    fn on(x: f32, y: f32) -> Point {
        Point { position: (x, y), on_curve: true }
    }

    fn off(x: f32, y: f32) -> Point {
        Point { position: (x, y), on_curve: false }
    }

    #[test]
    fn transforms_compose_in_application_order() {
        let scale = Transform::component(2.0, 0.0, 0.0, 2.0, 0.0, 0.0);
        let shift = Transform::component(1.0, 0.0, 0.0, 1.0, 10.0, 0.0);
        // Scale first, then shift: (3,0) doubles to (6,0) and shifts to (16,0).
        assert_eq!(scale.then(shift).apply(3.0, 0.0), (16.0, 0.0));
        // Shift first, then scale: (3,0) shifts to (13,0) and doubles to (26,0).
        assert_eq!(shift.then(scale).apply(3.0, 0.0), (26.0, 0.0));
    }

    #[test]
    fn the_glyph_transform_flips_the_y_axis() {
        let transform = Transform::for_glyph(0.5, (10.0, 20.0));
        // A point above the baseline must land above the origin on the mask.
        assert_eq!(transform.apply(0.0, 100.0), (10.0, -30.0));
    }

    #[test]
    fn a_square_contour_becomes_four_edges() {
        let mut edges = Edges::new();
        append_contour(&[on(0.0, 0.0), on(10.0, 0.0), on(10.0, 10.0), on(0.0, 10.0)], &mut edges);
        assert_eq!(edges.segments.len(), 4);
        assert_eq!(edges.bounds(), Some(((0.0, 0.0), (10.0, 10.0))));
    }

    #[test]
    fn a_contour_is_closed_even_when_the_font_does_not_repeat_its_first_point() {
        let mut edges = Edges::new();
        append_contour(&[on(0.0, 0.0), on(10.0, 0.0), on(10.0, 10.0)], &mut edges);
        let last = edges.segments.last().expect("edges");
        assert_eq!(last.1, (0.0, 0.0), "the contour was left open");
    }

    #[test]
    fn consecutive_off_curve_points_imply_an_on_curve_point_between_them() {
        // Two control points in a row: the curve passes through their midpoint,
        // so the outline must reach y = 5 even though no point says so.
        let mut edges = Edges::new();
        append_contour(&[on(0.0, 0.0), off(0.0, 10.0), off(10.0, 0.0), on(10.0, 10.0)], &mut edges);
        let (_, max) = edges.bounds().expect("bounds");
        assert!(max.1 >= 9.0, "the curve did not reach the far point: {max:?}");
        assert!(edges.segments.len() > 4, "curves were not flattened");
    }

    #[test]
    fn a_contour_with_no_on_curve_point_still_produces_a_closed_shape() {
        let mut edges = Edges::new();
        append_contour(&[off(0.0, 5.0), off(5.0, 10.0), off(10.0, 5.0), off(5.0, 0.0)], &mut edges);
        assert!(!edges.segments.is_empty());
        let bounds = edges.bounds().expect("bounds");
        assert!(bounds.1.0 > bounds.0.0 && bounds.1.1 > bounds.0.1);
    }

    #[test]
    fn a_flatter_curve_needs_fewer_segments_than_a_sharper_one() {
        let mut flat = Edges::new();
        flat.move_to((0.0, 0.0));
        flat.quadratic_to((5.0, 0.1), (10.0, 0.0));

        let mut sharp = Edges::new();
        sharp.move_to((0.0, 0.0));
        sharp.quadratic_to((5.0, 60.0), (10.0, 0.0));

        assert!(
            sharp.segments.len() > flat.segments.len(),
            "flat {} vs sharp {}",
            flat.segments.len(),
            sharp.segments.len()
        );
    }

    #[test]
    fn flags_expand_their_run_length_encoding() {
        // One flag with the repeat bit, repeated three more times, then another.
        let bytes = [0x09, 0x03, 0x01];
        let mut reader = Reader::at(&bytes, 0);
        assert_eq!(read_flags(&mut reader, 5), Some(vec![0x09, 0x09, 0x09, 0x09, 0x01]));
    }

    #[test]
    fn a_repeat_count_overrunning_the_contour_is_refused() {
        let bytes = [0x09, 0xff];
        let mut reader = Reader::at(&bytes, 0);
        assert_eq!(read_flags(&mut reader, 4), None);
    }

    #[test]
    fn short_coordinates_take_their_sign_from_the_same_bit() {
        // Both points short: the first positive, the second negative.
        let flags = [0x02 | 0x10, 0x02];
        let bytes = [10, 4];
        let mut reader = Reader::at(&bytes, 0);
        assert_eq!(read_coordinates(&mut reader, &flags, 0x02, 0x10), Some(vec![10.0, 6.0]));
    }

    #[test]
    fn an_unchanged_coordinate_repeats_the_previous_one() {
        // First point long, second says "same".
        let flags = [0x00, 0x10];
        let bytes = [0x01, 0x00];
        let mut reader = Reader::at(&bytes, 0);
        assert_eq!(read_coordinates(&mut reader, &flags, 0x02, 0x10), Some(vec![256.0, 256.0]));
    }

    #[test]
    fn long_coordinates_accumulate_as_signed_deltas() {
        let flags = [0x00, 0x00];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&100i16.to_be_bytes());
        bytes.extend_from_slice(&(-30i16).to_be_bytes());
        let mut reader = Reader::at(&bytes, 0);
        assert_eq!(read_coordinates(&mut reader, &flags, 0x02, 0x10), Some(vec![100.0, 70.0]));
    }

    #[test]
    fn an_empty_collection_has_no_bounds() {
        assert_eq!(Edges::new().bounds(), None);
    }

    #[test]
    fn points_are_transformed_before_being_emitted() {
        let mut edges = Edges::new();
        let doubled = Transform::component(2.0, 0.0, 0.0, 2.0, 1.0, 1.0);
        let points: Vec<Point> = [(0.0, 0.0), (5.0, 0.0), (5.0, 5.0)]
            .iter()
            .map(|&(x, y)| Point { position: doubled.apply(x, y), on_curve: true })
            .collect();
        append_contour(&points, &mut edges);
        assert_eq!(edges.bounds(), Some(((1.0, 1.0), (11.0, 11.0))));
    }

    #[test]
    fn identity_leaves_a_point_alone() {
        assert_eq!(identity().apply(3.0, 4.0), (3.0, 4.0));
    }
}
