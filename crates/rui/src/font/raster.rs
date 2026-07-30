//! Turning closed outlines into a coverage mask.
//!
//! # How it works
//!
//! Rather than sampling — testing whether points are inside the shape, which
//! trades quality for the number of samples taken — this computes coverage
//! *analytically*, in one pass over the outline's edges and with no sorting.
//!
//! Each edge deposits, into every scanline it crosses, the signed area it
//! sweeps across each pixel it passes through. Summing those deposits from left
//! to right along a row gives the accumulated signed area at each pixel, which
//! is exactly that pixel's coverage: the deposits left of a pixel inside the
//! shape add up to one, and an edge going back out subtracts what the edge
//! coming in added. Cost is proportional to the outline's length, not to its
//! area, and every fractional edge position is accounted for exactly.
//!
//! The sign is discarded at the end. A glyph whose contours wind in opposite
//! directions — the counter of an `o`, or a shape drawn from overlapping
//! strokes — would otherwise come out inverted in the overlap.
//!
//! # Why the accumulation buffer is wider than the mask
//!
//! An edge landing on the last column deposits part of its area into the column
//! *after* it. With a tightly-packed buffer that lands on the next row's first
//! pixel, and a glyph's right edge bleeds onto the left of the row below. Two
//! columns of padding per row absorb it, and summing each row independently
//! keeps rows from leaking into each other at all.

/// Accumulates edges, then resolves them into per-pixel coverage.
pub(super) struct Rasteriser {
    width: usize,
    height: usize,
    /// `width + 2`: the mask, plus the two columns that absorb the overhang.
    stride: usize,
    area: Vec<f32>,
}

impl Rasteriser {
    /// A rasteriser for a mask of `width` by `height` pixels.
    pub(super) fn new(width: usize, height: usize) -> Self {
        let stride = width + 2;
        Self { width, height, stride, area: vec![0.0; stride * height] }
    }

    /// Accumulates one straight edge of the outline.
    ///
    /// Horizontal edges are skipped: they cross no scanline, so they contribute
    /// no area, and the slope they would be divided by is zero.
    pub(super) fn edge(&mut self, from: (f32, f32), to: (f32, f32)) {
        if !from.0.is_finite() || !from.1.is_finite() || !to.0.is_finite() || !to.1.is_finite() {
            return;
        }
        if (from.1 - to.1).abs() < 1e-6 {
            return;
        }

        // Edges are walked downward, and the direction they were given in is
        // kept as the sign — that is what makes a contour going back up cancel
        // the one that came down, and so what hollows out a counter.
        let (winding, top, bottom) = if from.1 < to.1 { (1.0, from, to) } else { (-1.0, to, from) };
        let slope = (bottom.0 - top.0) / (bottom.1 - top.1);
        if !slope.is_finite() {
            return;
        }

        let first_row = top.1.floor().max(0.0) as usize;
        if first_row >= self.height {
            return;
        }
        let last_row = (bottom.1.ceil().max(0.0) as usize).min(self.height);

        // Where the edge is when it enters the first row that is actually on the
        // mask, which is not where it started if it began above the top.
        let mut x = top.0 + ((first_row as f32).max(top.1) - top.1) * slope;

        for row in first_row..last_row {
            let enters = (row as f32).max(top.1);
            let leaves = ((row + 1) as f32).min(bottom.1);
            let height = leaves - enters;
            if height <= 0.0 {
                continue;
            }

            let x_next = x + slope * height;
            let (left, right) = if x < x_next { (x, x_next) } else { (x_next, x) };
            self.deposit(
                row,
                left.clamp(0.0, self.width as f32),
                right.clamp(0.0, self.width as f32),
                height * winding,
            );
            x = x_next;
        }
    }

    /// Spreads one row's worth of an edge across the columns it crosses.
    ///
    /// `signed_height` is how much of the scanline the edge spanned, signed by
    /// its direction. It is divided between columns in proportion to how much of
    /// the swept trapezoid falls in each — exactly, not by sampling.
    fn deposit(&mut self, row: usize, left: f32, right: f32, signed_height: f32) {
        let base = row * self.stride;
        let left_floor = left.floor();
        let first = left_floor as usize;
        let right_ceil = right.ceil();
        let last = right_ceil as usize;

        if last <= first + 1 {
            // The edge stayed within a single column: split the area between
            // that column and the next by where the edge's midpoint sits.
            let midpoint = 0.5 * (left + right) - left_floor;
            self.area[base + first] += signed_height * (1.0 - midpoint);
            self.area[base + first + 1] += signed_height * midpoint;
            return;
        }

        let inverse_width = (right - left).recip();
        let left_fraction = left - left_floor;
        let first_area = 0.5 * inverse_width * (1.0 - left_fraction) * (1.0 - left_fraction);
        let right_fraction = right - right_ceil + 1.0;
        let last_area = 0.5 * inverse_width * right_fraction * right_fraction;

        self.area[base + first] += signed_height * first_area;

        if last == first + 2 {
            // Exactly two columns: whatever the first and last do not take.
            self.area[base + first + 1] += signed_height * (1.0 - first_area - last_area);
        } else {
            let second_area = inverse_width * (1.5 - left_fraction);
            self.area[base + first + 1] += signed_height * (second_area - first_area);
            for column in first + 2..last - 1 {
                self.area[base + column] += signed_height * inverse_width;
            }
            let before_last = second_area + (last - first - 3) as f32 * inverse_width;
            self.area[base + last - 1] += signed_height * (1.0 - before_last - last_area);
        }

        self.area[base + last] += signed_height * last_area;
    }

    /// Resolves the accumulated areas into coverage, 0 to 255 per pixel.
    pub(super) fn finish(&self) -> Vec<u8> {
        let mut coverage = vec![0u8; self.width * self.height];
        for row in 0..self.height {
            let mut accumulated = 0.0f32;
            let source = row * self.stride;
            let destination = row * self.width;
            for column in 0..self.width {
                accumulated += self.area[source + column];
                // Saturating: a float-to-integer cast in Rust clamps, so an
                // outline that overlaps itself cannot wrap around to zero.
                coverage[destination + column] = (accumulated.abs().min(1.0) * 255.0 + 0.5) as u8;
            }
        }
        coverage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rasterises a closed polygon given in pixel coordinates.
    fn fill(width: usize, height: usize, points: &[(f32, f32)]) -> Vec<u8> {
        let mut rasteriser = Rasteriser::new(width, height);
        for pair in points.windows(2) {
            rasteriser.edge(pair[0], pair[1]);
        }
        if let (Some(first), Some(last)) = (points.first(), points.last()) {
            rasteriser.edge(*last, *first);
        }
        rasteriser.finish()
    }

    fn at(coverage: &[u8], width: usize, x: usize, y: usize) -> u8 {
        coverage[y * width + x]
    }

    #[test]
    fn a_pixel_aligned_square_is_solid_inside_and_empty_outside() {
        let mask = fill(8, 8, &[(2.0, 2.0), (6.0, 2.0), (6.0, 6.0), (2.0, 6.0)]);
        assert_eq!(at(&mask, 8, 3, 3), 255);
        assert_eq!(at(&mask, 8, 5, 5), 255);
        assert_eq!(at(&mask, 8, 1, 3), 0);
        assert_eq!(at(&mask, 8, 6, 3), 0);
        assert_eq!(at(&mask, 8, 3, 1), 0);
    }

    #[test]
    fn a_half_covered_column_comes_out_half_covered() {
        let mask = fill(8, 4, &[(2.5, 0.0), (6.0, 0.0), (6.0, 4.0), (2.5, 4.0)]);
        let edge = at(&mask, 8, 2, 1);
        assert!((125..=130).contains(&edge), "expected about half, got {edge}");
        assert_eq!(at(&mask, 8, 3, 1), 255);
    }

    #[test]
    fn total_coverage_matches_the_area_of_the_shape() {
        let mask = fill(16, 16, &[(1.25, 2.5), (12.75, 2.5), (12.75, 11.5), (1.25, 11.5)]);
        let painted: f32 = mask.iter().map(|&value| value as f32 / 255.0).sum();
        let area = (12.75 - 1.25) * (11.5 - 2.5);
        assert!((painted - area).abs() < 0.5, "painted {painted}, expected {area}");
    }

    #[test]
    fn a_triangles_diagonal_is_antialiased() {
        let mask = fill(16, 16, &[(0.0, 0.0), (16.0, 16.0), (0.0, 16.0)]);
        let on_diagonal = at(&mask, 16, 8, 8);
        assert!(on_diagonal > 0 && on_diagonal < 255, "diagonal not antialiased: {on_diagonal}");
        assert_eq!(at(&mask, 16, 1, 15), 255, "well inside");
        assert_eq!(at(&mask, 16, 15, 1), 0, "well outside");
    }

    #[test]
    fn a_reversed_inner_contour_cuts_a_hole() {
        let mut rasteriser = Rasteriser::new(12, 12);
        let outer = [(1.0, 1.0), (11.0, 1.0), (11.0, 11.0), (1.0, 11.0), (1.0, 1.0)];
        // Wound the other way, so its contribution cancels the outer contour's.
        let inner = [(4.0, 4.0), (4.0, 8.0), (8.0, 8.0), (8.0, 4.0), (4.0, 4.0)];
        for contour in [outer.as_slice(), inner.as_slice()] {
            for pair in contour.windows(2) {
                rasteriser.edge(pair[0], pair[1]);
            }
        }
        let mask = rasteriser.finish();

        assert_eq!(at(&mask, 12, 2, 6), 255, "the ring should be filled");
        assert_eq!(at(&mask, 12, 6, 6), 0, "the middle should be hollow");
    }

    #[test]
    fn an_outline_reaching_the_last_column_does_not_bleed_onto_the_next_row() {
        let mask = fill(8, 4, &[(4.0, 0.0), (8.0, 0.0), (8.0, 4.0), (4.0, 4.0)]);
        assert_eq!(at(&mask, 8, 7, 1), 255);
        assert_eq!(at(&mask, 8, 0, 2), 0, "the right edge wrapped onto the next row");
    }

    #[test]
    fn geometry_outside_the_mask_is_clipped_rather_than_panicking() {
        let mask = fill(8, 8, &[(-100.0, -100.0), (100.0, -100.0), (100.0, 100.0), (-100.0, 100.0)]);
        assert!(mask.iter().all(|&value| value == 255));
    }

    #[test]
    fn horizontal_edges_contribute_nothing() {
        let mut rasteriser = Rasteriser::new(4, 4);
        rasteriser.edge((0.0, 2.0), (4.0, 2.0));
        assert!(rasteriser.finish().iter().all(|&value| value == 0));
    }

    #[test]
    fn a_degenerate_outline_produces_an_empty_mask() {
        let mask = fill(4, 4, &[(1.0, 1.0), (1.0, 1.0), (1.0, 1.0)]);
        assert!(mask.iter().all(|&value| value == 0));
    }
}
