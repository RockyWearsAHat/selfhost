//! Colours, and the one blend the whole toolkit is drawn with.
//!
//! Colours are 8-bit sRGB with a straight (not premultiplied) alpha. Straight
//! alpha is what a person writing a theme types, and premultiplying at the point
//! of use costs one multiply that the blend does anyway.
//!
//! # Why blending is not gamma-corrected
//!
//! Compositing sRGB values directly is, strictly, wrong: the values are not
//! linear light. Doing it properly means converting to linear, blending, and
//! converting back, on every pixel of every glyph. Every windowing system this
//! draws into composites the same wrong way, so matching them makes our text
//! sit correctly next to native chrome, and the alternative would make it look
//! subtly different from every other window on the screen. This is a deliberate
//! choice to be consistent rather than correct in isolation.

/// An 8-bit sRGB colour with straight alpha.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Color {
    /// Red channel.
    pub r: u8,
    /// Green channel.
    pub g: u8,
    /// Blue channel.
    pub b: u8,
    /// Opacity; 0 is invisible and 255 is opaque.
    pub a: u8,
}

impl Color {
    /// An opaque colour.
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    /// A colour with an explicit alpha.
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Fully transparent; drawing with it is a no-op.
    pub const TRANSPARENT: Self = Self::rgba(0, 0, 0, 0);
    /// Opaque white.
    pub const WHITE: Self = Self::rgb(255, 255, 255);
    /// Opaque black.
    pub const BLACK: Self = Self::rgb(0, 0, 0);

    /// This colour at a different opacity.
    pub const fn with_alpha(self, a: u8) -> Self {
        Self { a, ..self }
    }

    /// This colour scaled to `factor` of its current opacity.
    ///
    /// Multiplying rather than replacing lets a caller fade something that is
    /// already translucent without having to know how translucent it was.
    pub fn fade(self, factor: f32) -> Self {
        let a = (self.a as f32 * factor.clamp(0.0, 1.0)).round() as u8;
        Self { a, ..self }
    }

    /// A colour `t` of the way from this one to `other`, channel by channel.
    ///
    /// `t` is clamped, so an over- or undershooting animation cannot produce a
    /// colour outside the pair it was told to move between.
    pub fn mix(self, other: Self, t: f32) -> Self {
        let t = t.clamp(0.0, 1.0);
        let lerp = |a: u8, b: u8| (a as f32 + (b as f32 - a as f32) * t).round() as u8;
        Self {
            r: lerp(self.r, other.r),
            g: lerp(self.g, other.g),
            b: lerp(self.b, other.b),
            a: lerp(self.a, other.a),
        }
    }

    /// Whether drawing with this colour could change any pixel.
    pub fn is_visible(self) -> bool {
        self.a > 0
    }

    /// This colour packed into the canvas's `0xAARRGGBB` word.
    pub const fn to_argb(self) -> u32 {
        (self.a as u32) << 24 | (self.r as u32) << 16 | (self.g as u32) << 8 | self.b as u32
    }

    /// The colour a packed `0xAARRGGBB` word represents.
    pub const fn from_argb(word: u32) -> Self {
        Self {
            a: (word >> 24) as u8,
            r: (word >> 16) as u8,
            g: (word >> 8) as u8,
            b: word as u8,
        }
    }

    /// The perceived lightness of the colour, from 0 (black) to 1 (white).
    ///
    /// Rec. 601 luma. Used to decide whether a theme is light or dark and which
    /// of a pair of foregrounds will be legible on it, which is a judgement
    /// about perception rather than about channel values.
    pub fn luminance(self) -> f32 {
        (0.299 * self.r as f32 + 0.587 * self.g as f32 + 0.114 * self.b as f32) / 255.0
    }

    /// The WCAG contrast ratio between this colour and another, from 1 to 21.
    ///
    /// Symmetric — which of the two is the ink does not matter — and computed
    /// on the linearised relative luminance the guidelines define rather than
    /// on [`Color::luminance`]'s quick luma, because a legibility law should be
    /// asserted in the units the law is written in. Alpha is ignored: contrast
    /// is a question about two colours as they land, and what a translucent one
    /// lands *as* depends on what is under it, which is not this colour's to
    /// know.
    pub fn contrast_ratio(self, other: Self) -> f32 {
        let (a, b) = (self.relative_luminance(), other.relative_luminance());
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    /// The colour's WCAG relative luminance, from 0 (black) to 1 (white).
    ///
    /// Each sRGB channel linearised as the guidelines prescribe, then weighted
    /// per Rec. 709. Kept private behind [`Color::contrast_ratio`]: a ratio is
    /// the judgement anything outside actually wants, and two luminances handed
    /// out separately invite someone to divide them without the 0.05 the
    /// formula flattens black with.
    fn relative_luminance(self) -> f32 {
        let channel = |value: u8| {
            let c = value as f32 / 255.0;
            if c <= 0.03928 { c / 12.92 } else { ((c + 0.055) / 1.055).powf(2.4) }
        };
        0.2126 * channel(self.r) + 0.7152 * channel(self.g) + 0.0722 * channel(self.b)
    }
}

/// Composites `source` over `destination` with `coverage` applied to its alpha.
///
/// `destination` is opaque — it is a pixel already in the buffer — so the result
/// is opaque too and the usual divide by the composed alpha falls away. Both
/// words are `0xAARRGGBB`.
///
/// `coverage` is the rasteriser's answer for how much of the pixel the shape
/// covers, which is why it multiplies the alpha rather than being a second
/// blend: a half-covered pixel of a half-transparent fill is a quarter of a
/// pixel of paint, and doing it in one step avoids rounding it twice.
pub fn blend_over(destination: u32, source: Color, coverage: u8) -> u32 {
    // `a * c / 255` with the divide replaced by the usual reciprocal trick, so
    // that 255 * 255 lands on exactly 255 rather than 254.
    let alpha = mul_255(source.a, coverage);
    if alpha == 0 {
        return destination;
    }
    if alpha == 255 {
        return source.to_argb() | 0xff00_0000;
    }

    let inverse = 255 - alpha;
    let channel = |src: u8, dst: u32| mul_255(src, alpha) as u32 + mul_255(dst as u8, inverse) as u32;

    let r = channel(source.r, (destination >> 16) & 0xff);
    let g = channel(source.g, (destination >> 8) & 0xff);
    let b = channel(source.b, destination & 0xff);
    0xff00_0000 | r << 16 | g << 8 | b
}

/// Composites `source` onto `destination` by ADDING light, with `coverage`
/// applied to its alpha, saturating each channel at 255.
///
/// Where [`blend_over`] replaces the destination in proportion to alpha, this
/// adds to it: two lit things overlapping grow brighter and tend toward white,
/// which is what makes neon bloom rather than merely lie on top. `destination`
/// is an opaque buffer pixel, so the result stays opaque. Both words are
/// `0xAARRGGBB`.
///
/// `coverage` multiplies the source alpha exactly as it does in [`blend_over`],
/// so an antialiased edge or a glow falloff dims the light it adds by how much
/// of the pixel it reaches.
pub fn blend_add(destination: u32, source: Color, coverage: u8) -> u32 {
    let alpha = mul_255(source.a, coverage);
    if alpha == 0 {
        return destination;
    }
    let add = |src: u8, dst: u32| {
        let sum = mul_255(src, alpha) as u32 + dst;
        if sum > 255 { 255 } else { sum }
    };
    let r = add(source.r, (destination >> 16) & 0xff);
    let g = add(source.g, (destination >> 8) & 0xff);
    let b = add(source.b, destination & 0xff);
    0xff00_0000 | r << 16 | g << 8 | b
}

/// `a * b / 255`, rounded, without a divide.
fn mul_255(a: u8, b: u8) -> u8 {
    let product = a as u32 * b as u32 + 128;
    ((product + (product >> 8)) >> 8) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_coverage_of_an_opaque_colour_replaces_the_pixel() {
        let red = Color::rgb(255, 0, 0);
        assert_eq!(blend_over(0xff00_00ff, red, 255), 0xffff_0000);
    }

    #[test]
    fn zero_coverage_leaves_the_pixel_alone() {
        let red = Color::rgb(255, 0, 0);
        assert_eq!(blend_over(0xff00_00ff, red, 0), 0xff00_00ff);
    }

    #[test]
    fn a_transparent_colour_never_draws_however_covered() {
        assert_eq!(blend_over(0xff12_3456, Color::TRANSPARENT, 255), 0xff12_3456);
    }

    #[test]
    fn half_coverage_lands_halfway_between_the_two_colours() {
        let white_over_black = blend_over(0xff00_0000, Color::WHITE, 128);
        let mid = white_over_black & 0xff;
        assert!((127..=129).contains(&mid), "expected about half, got {mid}");
    }

    #[test]
    fn blending_always_produces_an_opaque_pixel() {
        let faint = Color::rgba(10, 20, 30, 3);
        assert_eq!(blend_over(0xff00_0000, faint, 40) >> 24, 0xff);
    }

    #[test]
    fn coverage_and_alpha_multiply_rather_than_blending_twice() {
        // Half-transparent paint at half coverage is a quarter of a pixel.
        let half = Color::rgba(255, 255, 255, 128);
        let quarter = blend_over(0xff00_0000, half, 128) & 0xff;
        assert!((62..=66).contains(&quarter), "expected about a quarter, got {quarter}");
    }

    #[test]
    fn packing_round_trips() {
        let colour = Color::rgba(1, 2, 3, 4);
        assert_eq!(Color::from_argb(colour.to_argb()), colour);
    }

    #[test]
    fn mixing_is_clamped_at_both_ends() {
        let a = Color::rgb(0, 0, 0);
        let b = Color::rgb(255, 255, 255);
        assert_eq!(a.mix(b, -5.0), a);
        assert_eq!(a.mix(b, 5.0), b);
    }

    #[test]
    fn mul_255_reaches_both_extremes_exactly() {
        assert_eq!(mul_255(255, 255), 255);
        assert_eq!(mul_255(0, 255), 0);
        assert_eq!(mul_255(255, 0), 0);
    }

    #[test]
    fn luminance_orders_black_below_white() {
        assert!(Color::BLACK.luminance() < Color::WHITE.luminance());
        assert_eq!(Color::WHITE.luminance(), 1.0);
    }

    #[test]
    fn contrast_spans_its_whole_scale() {
        // The two ends the formula is defined by: black against white is 21:1,
        // and a colour against itself is 1:1.
        let extreme = Color::BLACK.contrast_ratio(Color::WHITE);
        assert!((extreme - 21.0).abs() < 0.01, "expected 21:1, got {extreme}");
        let none = Color::rgb(0x80, 0x80, 0x80).contrast_ratio(Color::rgb(0x80, 0x80, 0x80));
        assert_eq!(none, 1.0);
    }

    #[test]
    fn contrast_does_not_care_which_colour_is_the_ink() {
        let (ink, ground) = (Color::rgb(0x25, 0x63, 0xd4), Color::rgb(0xf2, 0xf3, 0xf5));
        assert_eq!(ink.contrast_ratio(ground), ground.contrast_ratio(ink));
    }

    #[test]
    fn contrast_is_computed_on_linear_light_and_not_on_luma() {
        // The published figure for #767676 on white is 4.54:1 — the grey WCAG's
        // own examples sit at. Quick luma lands somewhere else entirely, so
        // hitting this number is what says the linearisation is really there.
        let ratio = Color::rgb(0x76, 0x76, 0x76).contrast_ratio(Color::WHITE);
        assert!((ratio - 4.54).abs() < 0.01, "expected about 4.54:1, got {ratio}");
    }

    #[test]
    fn contrast_ignores_alpha() {
        // A translucent ink's landing depends on what it lands on, which the
        // ratio of two colours cannot know; it answers for the colours as told.
        let faint = Color::rgba(0xff, 0xff, 0xff, 10);
        assert_eq!(faint.contrast_ratio(Color::BLACK), Color::WHITE.contrast_ratio(Color::BLACK));
    }

    #[test]
    fn adding_onto_black_is_the_source_scaled_by_coverage() {
        // Nothing to add to, so the result is exactly the light laid down.
        let grey = Color::rgb(120, 120, 120);
        assert_eq!(blend_add(0xff00_0000, grey, 255), 0xff78_7878);
        // Half coverage is half the light.
        let half = blend_add(0xff00_0000, grey, 128) & 0xff;
        assert!((58..=62).contains(&half), "expected about half, got {half}");
    }

    #[test]
    fn two_half_lights_add_toward_and_clamp_at_white() {
        let half = Color::rgb(140, 140, 140);
        let once = blend_add(0xff00_0000, half, 255);
        let twice = blend_add(once, half, 255);
        assert!((twice & 0xff) > (once & 0xff), "adding a second light must brighten");

        // Two lights that would sum past 255 clamp rather than wrap.
        let bright = Color::rgb(200, 200, 200);
        let summed = blend_add(blend_add(0xff00_0000, bright, 255), bright, 255);
        assert_eq!(summed & 0xff, 255, "the channel saturates at white");
    }

    #[test]
    fn adding_nothing_leaves_the_pixel_exactly() {
        let light = Color::rgb(90, 90, 90);
        assert_eq!(blend_add(0xff12_3456, light, 0), 0xff12_3456, "zero coverage adds nothing");
        assert_eq!(
            blend_add(0xff12_3456, Color::TRANSPARENT, 255),
            0xff12_3456,
            "a zero-alpha source adds nothing"
        );
    }

    #[test]
    fn adding_always_produces_an_opaque_pixel() {
        let faint = Color::rgba(10, 20, 30, 3);
        assert_eq!(blend_add(0xff00_0000, faint, 40) >> 24, 0xff);
    }
}
