//! The pixel buffer everything is drawn into, and the shapes it can draw.
//!
//! # One buffer, one format, every platform
//!
//! Pixels are `0xAARRGGBB` words. Read as bytes on a little-endian machine that
//! is B, G, R, A — which is exactly what Core Graphics wants from a
//! `kCGImageAlphaNoneSkipFirst | kCGBitmapByteOrder32Little` bitmap, what a
//! Win32 32-bit `BI_RGB` device-independent bitmap wants, and what an X11
//! `TrueColor` visual at depth 24 or 32 wants. One format satisfies all three
//! backends, so presenting a frame is a copy and never a conversion.
//!
//! The buffer is always opaque. Nothing composites this window against anything
//! else, so alpha is a property of the *paint*, not of the surface, and
//! [`crate::color::blend_over`] can drop the divide that a translucent
//! destination would need.
//!
//! # Logical units in, device pixels out
//!
//! Every public method takes logical coordinates and multiplies by [`scale`]
//! itself. That conversion happens here and nowhere else, which is what lets a
//! layout be written once and be correct on a HiDPI display. The exception is
//! [`Canvas::fill_mask`], which takes device pixels: a glyph is rasterised at
//! the size it will actually occupy, so rounding its position anywhere but at
//! the device grid would blur it.
//!
//! # Antialiasing
//!
//! Every shape here — a rectangle with shaped corners, the band of a ring or an
//! arc, the capsule of a line — is drawn from its signed distance field: the
//! distance from a pixel's centre to the shape's edge, turned into coverage by
//! `clamp(0.5 - distance, 0, 1)`. That is one rule for fills, strokes, and
//! glows alike, it is exact rather than sampled, and it antialiases fractional
//! coordinates without a supersampling pass. A circle is a square rounded by
//! half its side; a hairline is a stroke.
//!
//! Three fields is the whole set, and each earns its place by being something
//! the others cannot say. A rectangle is every panel, row, and control. A band
//! is a gauge: a reading stated as how far round a circle it has got, which no
//! rectangle expresses. A capsule is a line between two points at any angle,
//! which is a bracket, a crosshair, a tick, and a rule with ends on it.
//!
//! There are two corner shapes, [`Corner::Round`] and [`Corner::Cut`], and they
//! cost the same: both are a distance field evaluated over the same band of
//! pixels, and neither is a path. That matters because the corner is the single
//! strongest signal of what an interface *is* — a rounded corner reads as a card
//! in a document, and a cut one reads as a machined panel — and a toolkit that
//! can only draw one of them has already decided.
//!
//! # The one thing here that is not a distance field
//!
//! [`Canvas::blit_bgra`] copies a picture somebody else made — a decoded image,
//! a screen captured on another machine — and there is no field to evaluate
//! because there is no shape: the answer for each pixel is already written down.
//! It is a copy and never a resample, which is what keeps it costing what a
//! copy costs; see [`Bgra`] for the byte order and that decision.
//!
//! # Gradients and glows cost what a flat fill costs
//!
//! Two things above a flat fill are what stop an interface reading as a grid of
//! grey boxes: a surface that shades from top to bottom, and a halo around the
//! control a view is mostly for.
//!
//! Both are drawn by the same scan as everything else. A gradient here is
//! vertical only, which is the one direction that costs nothing: a row of a
//! vertical gradient is a single colour, so the bulk span that writes a panel's
//! interior still writes one word repeatedly, and the mix happens once per row
//! rather than once per pixel. A horizontal or angled gradient would have to be
//! evaluated per pixel and is deliberately not offered.
//!
//! A glow is the distance field read *outside* the shape instead of across its
//! edge, so it scans the band it occupies and never the area it surrounds — the
//! same trade that makes a one-pixel outline cheap. It stops at the shape's edge
//! because whatever casts it is drawn on top.
//!
//! [`scale`]: Canvas::scale

use crate::color::{Color, blend_add, blend_over};
use crate::geom::{Insets, Point, Rect};
use crate::sdf::{Sculpt, Shape};
use std::f32::consts::TAU;

/// What shape a rectangle's four corners are.
///
/// Every fill, stroke, and glow takes one of these rather than a bare radius, so
/// that "what shape is a panel" is a decision made once in the theme instead of
/// separately by each widget that happens to draw one.
///
/// # Why a cut corner is offered at all
///
/// A rounded corner is the corner of a card, and a card is a piece of paper. The
/// console is not showing paper — it is an instrument reporting on a machine —
/// and a corner cut at forty-five degrees is what a panel bolted into a rack
/// looks like. The two are the same amount of work to draw and one word apart to
/// choose between, which is the point: the interface's whole character can be
/// changed from the theme without a widget being touched.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Corner {
    /// A right angle.
    Square,
    /// A quarter-circle of this radius, in logical units.
    Round(f32),
    /// A forty-five degree cut running this far along each edge it meets.
    Cut(f32),
}

impl Corner {
    /// How far the corner treatment reaches along an edge.
    ///
    /// The same measurement for both shapes, which is what lets one clamp, one
    /// interior-span calculation, and one set of bounds serve them both.
    pub fn size(self) -> f32 {
        match self {
            Self::Square => 0.0,
            Self::Round(size) | Self::Cut(size) => size,
        }
    }

    /// The same corner, grown by `amount` — what a shape's outer edge needs.
    ///
    /// A glow cast from a shape spread outward, or a focus ring drawn around
    /// one, has to keep the corner *shape* while taking the larger size, or a cut
    /// panel ends up haloed by a rounded one.
    pub fn grown(self, amount: f32) -> Self {
        match self {
            Self::Square => Self::Square,
            Self::Round(size) => Self::Round(size + amount),
            Self::Cut(size) => Self::Cut(size + amount),
        }
    }

    /// The same corner at `size`, keeping which shape it is.
    pub fn resized(self, size: f32) -> Self {
        match self {
            Self::Square => Self::Square,
            Self::Round(_) => Self::Round(size),
            Self::Cut(_) => Self::Cut(size),
        }
    }
}

/// A coverage bitmap: how much of each pixel a shape covers, 0 to 255.
///
/// Produced by the glyph rasteriser and consumed by [`Canvas::fill_mask`]. It
/// carries no colour, so one rasterised glyph serves every colour it is ever
/// drawn in.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Mask {
    /// Width in device pixels.
    pub width: u32,
    /// Height in device pixels.
    pub height: u32,
    /// `width * height` coverage values, row-major.
    pub coverage: Vec<u8>,
}

impl Mask {
    /// An empty mask, which draws nothing.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Whether the mask covers no area.
    pub fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }
}

/// A rectangle of 32-bit BGRA pixels somebody else owns.
///
/// The one thing this library draws that it did not rasterise: a picture that
/// arrived from outside — a screen captured on another machine, a decoded
/// image, a frame from a camera. [`Canvas::blit_bgra`] copies it; this type is
/// how the copy is *described*, and the only place the description is checked.
///
/// # Why the bytes are BGRA and the stride is separate
///
/// Both facts come from what real capture buffers look like rather than from
/// what would be convenient here. Every platform this library runs on hands out
/// screen pixels in exactly the order the canvas already stores them — B, G, R,
/// A on a little-endian machine, which is `0xAARRGGBB` read as a word — so the
/// common case is a copy and never a conversion, the same trade
/// [the module header](self) makes for presenting.
///
/// A stride wider than the row is the normal case and not the exception:
/// Core Graphics pads every row of a capture to a multiple of sixteen or sixty-four
/// bytes, and a Windows DIB pads to four. A blitter that assumed
/// `stride == width * 4` would draw a picture that skewed a little further
/// right on every row — the classic symptom, and one that only appears at
/// widths the padding is not already a multiple of, which is why it survives
/// casual testing.
///
/// # Why alpha is carried but not used
///
/// The surface is opaque (see [the module header](self)), and a screen capture
/// has nothing behind it to show through: alpha in these buffers is either 255
/// or, on macOS, *undefined* — `kCGImageAlphaNoneSkipFirst` means the byte is
/// there and means nothing. Honouring it would blend a remote desktop against
/// whatever this window happened to be showing, controlled by a byte the
/// capturing platform does not promise to set. So the byte is skipped, and the
/// blit writes opaque pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bgra<'a> {
    width: u32,
    height: u32,
    stride: usize,
    bytes: &'a [u8],
}

impl<'a> Bgra<'a> {
    /// Describes `bytes` as a `width` by `height` picture whose rows are
    /// `stride` bytes apart, or `None` if they cannot be.
    ///
    /// The check is here, once, rather than in the blit: a frame arrives from a
    /// network or a foreign capture API, so "the sizes agree with the buffer"
    /// is exactly the kind of claim that is someone else's mistake. Refusing it
    /// at the door means [`Canvas::blit_bgra`] indexes rows it has already
    /// proven are there, and a mis-described frame is a picture that does not
    /// appear rather than a read past the end of a buffer.
    ///
    /// The last row is allowed to be short of a full stride, since a buffer
    /// sized exactly `height * width * 4` with padding on every row but the
    /// last is a real thing a capture API returns.
    pub fn new(width: u32, height: u32, stride: usize, bytes: &'a [u8]) -> Option<Self> {
        let row = (width as usize).checked_mul(4)?;
        if stride < row {
            return None;
        }
        if width > 0 && height > 0 {
            let full = stride.checked_mul(height as usize - 1)?;
            let needed = full.checked_add(row)?;
            if bytes.len() < needed {
                return None;
            }
        }
        Some(Self { width, height, stride, bytes })
    }

    /// The same, for a picture whose rows have no padding between them.
    pub fn packed(width: u32, height: u32, bytes: &'a [u8]) -> Option<Self> {
        Self::new(width, height, (width as usize).checked_mul(4)?, bytes)
    }

    /// Width in pixels.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Height in pixels.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// How many bytes apart two rows are.
    pub fn stride(&self) -> usize {
        self.stride
    }

    /// Whether it covers no area, and so draws nothing.
    pub fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }

    /// One row of the picture, exactly `width * 4` bytes.
    ///
    /// `None` past the last row. Every caller is inside bounds this type
    /// established in [`Bgra::new`], so this cannot fail for a row the blit
    /// asks for — it answers an `Option` anyway so that the one indexing
    /// decision lives here rather than at each use.
    fn row(&self, y: u32) -> Option<&'a [u8]> {
        if y >= self.height {
            return None;
        }
        let start = self.stride.checked_mul(y as usize)?;
        let end = start.checked_add((self.width as usize).checked_mul(4)?)?;
        self.bytes.get(start..end)
    }
}

/// A rectangle of device pixels, in whole pixels.
///
/// Clipping is integral because a partly-clipped pixel is not a thing the
/// buffer can represent; rounding outward would let drawing escape its region
/// by up to a pixel, so bounds round *inward* to the pixels wholly inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PixelBounds {
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
}

impl PixelBounds {
    fn intersect(self, other: Self) -> Self {
        Self {
            left: self.left.max(other.left),
            top: self.top.max(other.top),
            right: self.right.min(other.right),
            bottom: self.bottom.min(other.bottom),
        }
    }

    fn is_empty(self) -> bool {
        self.right <= self.left || self.bottom <= self.top
    }
}

/// The smallest backing scale a display may claim before it is disbelieved.
///
/// A zero or negative scale collapses every layout to nothing, and a windowing
/// system reporting one is a bug to survive rather than to propagate.
const MIN_SCALE: f32 = 0.25;

/// The largest backing scale a display may claim, for the same reason.
const MAX_SCALE: f32 = 8.0;

/// An unmarked pixel: black, fully opaque.
const OPAQUE_BLACK: u32 = 0xff00_0000;

/// A buffer of pixels and the operations that mark it.
pub struct Canvas {
    pixels: Vec<u32>,
    width: u32,
    height: u32,
    scale: f32,
    clip: PixelBounds,
}

impl Canvas {
    /// A canvas of `width` by `height` *device* pixels at `scale`, filled black.
    ///
    /// `scale` is the display's backing scale factor: 1.0 for an ordinary
    /// screen, 2.0 for a Retina one. It is clamped to a sane range because a
    /// zero or negative scale would collapse every layout to nothing, and a
    /// windowing system reporting one is a bug we should survive rather than
    /// propagate.
    pub fn new(width: u32, height: u32, scale: f32) -> Self {
        let mut canvas = Self {
            pixels: Vec::new(),
            width: 0,
            height: 0,
            scale: 1.0,
            clip: PixelBounds { left: 0, top: 0, right: 0, bottom: 0 },
        };
        canvas.resize(width, height, scale);
        canvas
    }

    /// Resizes the buffer, discarding its contents.
    ///
    /// Contents are discarded rather than rescaled: the caller redraws every
    /// frame, so preserving them would cost a copy that is immediately painted
    /// over. Resizing also resets the clip, since the old one may no longer be
    /// inside the surface.
    ///
    /// The allocation is kept and re-lengthened rather than replaced. A window
    /// being dragged by its corner resizes on every frame of the gesture, and a
    /// surface is megabytes; asking the allocator for a fresh one sixty times a
    /// second is a page fault per four kilobytes of window, which is felt as the
    /// resize stuttering.
    pub fn resize(&mut self, width: u32, height: u32, scale: f32) {
        self.width = width;
        self.height = height;
        self.scale = if scale.is_finite() { scale.clamp(MIN_SCALE, MAX_SCALE) } else { 1.0 };
        self.clip =
            PixelBounds { left: 0, top: 0, right: width as i32, bottom: height as i32 };
        self.pixels.clear();
        self.pixels.resize((width as usize) * (height as usize), OPAQUE_BLACK);
    }

    /// Width in device pixels.
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Height in device pixels.
    pub fn height(&self) -> u32 {
        self.height
    }

    /// Device pixels per logical unit.
    pub fn scale(&self) -> f32 {
        self.scale
    }

    /// The whole surface, in logical units.
    pub fn bounds(&self) -> Rect {
        Rect::new(0.0, 0.0, self.width as f32 / self.scale, self.height as f32 / self.scale)
    }

    /// The pixels, for a backend to present.
    pub fn pixels(&self) -> &[u32] {
        &self.pixels
    }

    /// The current clip, in logical units.
    pub fn clip(&self) -> Rect {
        Rect::new(
            self.clip.left as f32 / self.scale,
            self.clip.top as f32 / self.scale,
            (self.clip.right - self.clip.left) as f32 / self.scale,
            (self.clip.bottom - self.clip.top) as f32 / self.scale,
        )
    }

    /// Narrows the clip to `rect` and answers the previous one, for restoring.
    ///
    /// The new clip is always the *intersection* with the old one, so a nested
    /// region can never draw outside its parent however it was called.
    #[must_use = "the previous clip must be restored, or later drawing stays clipped"]
    pub fn push_clip(&mut self, rect: Rect) -> Rect {
        let previous = self.clip();
        self.clip = self.clip.intersect(self.device_bounds(rect));
        previous
    }

    /// Restores a clip taken from [`Canvas::push_clip`].
    pub fn pop_clip(&mut self, previous: Rect) {
        self.clip = PixelBounds { left: 0, top: 0, right: self.width as i32, bottom: self.height as i32 }
            .intersect(self.device_bounds(previous));
    }

    /// Whether anything drawn inside `rect` could be visible.
    ///
    /// Widgets ask this to skip work — a list scrolled past its thousandth row
    /// should cost nothing to not draw.
    pub fn is_visible(&self, rect: Rect) -> bool {
        !self.clip.intersect(self.device_bounds(rect)).is_empty()
    }

    /// Paints the entire surface, ignoring the clip.
    pub fn clear(&mut self, color: Color) {
        self.pixels.fill(color.to_argb() | 0xff00_0000);
    }

    /// The same, shading from `top` at the first row to `bottom` at the last.
    ///
    /// A window filled with one flat value has no depth for anything to sit in
    /// front of; shading it very slightly downward gives every panel something
    /// to be lit against. This replaces the flat clear rather than being drawn
    /// over it, so it costs a single pass exactly as the flat one does.
    pub fn clear_vertical(&mut self, top: Color, bottom: Color) {
        if self.height == 0 {
            return;
        }
        let last = (self.height - 1).max(1) as f32;
        for y in 0..self.height {
            let word = top.mix(bottom, y as f32 / last).to_argb() | 0xff00_0000;
            let row = (y as usize) * self.width as usize;
            self.pixels[row..row + self.width as usize].fill(word);
        }
    }

    /// Fills a rectangle with square corners.
    pub fn fill_rect(&mut self, rect: Rect, color: Color) {
        self.fill(rect, Corner::Square, color);
    }

    /// Fills a rectangle whose corners are shaped by `corner`.
    ///
    /// The corner size is clamped to half the shorter side, so asking for more
    /// than the shape can hold yields a capsule — or, cut, a diamond — rather
    /// than an inverted corner.
    pub fn fill(&mut self, rect: Rect, corner: Corner, color: Color) {
        if !color.is_visible() || rect.is_empty() {
            return;
        }
        let device = self.device_rect(rect);
        let corner = self.device_corner(corner, device);

        if corner.size() <= 0.0 && color.a == 255 && is_pixel_aligned(device) {
            self.fill_aligned_opaque(device, color);
            return;
        }
        self.fill_shape(device, corner, Paint::solid(color));
    }

    /// Fills a shaped rectangle shading from `top` at its top edge to `bottom`.
    ///
    /// Vertical because that is the direction a row of pixels is constant in,
    /// which keeps this exactly as cheap as a flat fill; see the module's own
    /// notes. A gradient between two equal colours is a flat fill and is drawn
    /// as one.
    pub fn fill_vertical(&mut self, rect: Rect, corner: Corner, top: Color, bottom: Color) {
        if rect.is_empty() || (!top.is_visible() && !bottom.is_visible()) {
            return;
        }
        let device = self.device_rect(rect);
        let corner = self.device_corner(corner, device);
        self.fill_shape(device, corner, Paint::vertical(device, top, bottom));
    }

    /// Fills a shaped rectangle shading from `left` at its left edge to `right`.
    ///
    /// The horizontal companion to [`Canvas::fill_vertical`]. Unlike the vertical
    /// gradient — whose every row is one colour and so costs a flat fill — a
    /// horizontal gradient varies along the row, so the colour is evaluated per
    /// pixel. Reach for it on a readout, a bar, or a lit conduit rather than on a
    /// panel's whole background.
    pub fn fill_horizontal(&mut self, rect: Rect, corner: Corner, left: Color, right: Color) {
        if rect.is_empty() || (!left.is_visible() && !right.is_visible()) {
            return;
        }
        let device = self.device_rect(rect);
        let corner = self.device_corner(corner, device);
        let mid_y = device.y + device.h / 2.0;
        let shade =
            Shade::linear((device.min_x(), mid_y), (device.max_x(), mid_y), left, right);
        self.fill_shaded(device, corner, shade);
    }

    /// Fills a shaped rectangle shading from `c0` at point `a` to `c1` at point
    /// `b`, along the axis between them.
    ///
    /// The general linear gradient: the colour at a pixel is `c0` mixed toward
    /// `c1` by that pixel's fractional distance along the segment `a`→`b`,
    /// clamped so everything behind `a` is solid `c0` and everything past `b` is
    /// solid `c1`. Points are logical units. Costs one mix per covered pixel; see
    /// [`Canvas::fill_horizontal`].
    pub fn fill_gradient(
        &mut self,
        rect: Rect,
        corner: Corner,
        a: Point,
        b: Point,
        c0: Color,
        c1: Color,
    ) {
        if rect.is_empty() || (!c0.is_visible() && !c1.is_visible()) {
            return;
        }
        let device = self.device_rect(rect);
        let corner = self.device_corner(corner, device);
        let shade = Shade::linear(self.device_point(a), self.device_point(b), c0, c1);
        self.fill_shaded(device, corner, shade);
    }

    /// Draws a soft halo outside a shaped rectangle's edge.
    ///
    /// `blur` is how far the halo reaches beyond the shape, in logical units,
    /// fading from `color` at the edge to nothing at that distance. Nothing
    /// inside the shape is touched: a glow exists to be seen *around* whatever
    /// casts it, and the caster is drawn on top.
    ///
    /// `spread` grows the shape the halo is cast from before it is drawn, which
    /// is how a shadow is offset outward from a small control without the halo
    /// hugging its outline so tightly that it reads as a blurred border. The
    /// corner grows with it, so a cut panel is haloed by a cut shape.
    ///
    /// The colour is the caller's, and one that is not a black is a *glow*
    /// rather than a shadow: light thrown onto what is behind the shape instead
    /// of light taken away from it. Which of the two an element casts is said
    /// once, in the theme's own language, by [`El::shadow`](crate::El::shadow)
    /// and [`El::glow`](crate::El::glow).
    pub fn shadow(
        &mut self,
        rect: Rect,
        corner: Corner,
        blur: f32,
        spread: f32,
        color: Color,
    ) {
        if !color.is_visible() || rect.is_empty() || blur <= 0.0 {
            return;
        }
        let cast = rect.expand(crate::geom::Insets::uniform(spread));
        let device = self.device_rect(cast);
        let corner = self.device_corner(corner.grown(spread), device);
        self.glow_shape(device, corner, blur * self.scale, color);
    }

    /// Strokes the outline of a shaped rectangle, centred on its edge.
    ///
    /// Centred rather than inside or outside because that is what makes a
    /// one-pixel border land on one row of pixels instead of straddling two and
    /// rendering as two grey rows.
    pub fn stroke(&mut self, rect: Rect, corner: Corner, thickness: f32, color: Color) {
        if !color.is_visible() || rect.is_empty() || thickness <= 0.0 {
            return;
        }
        let device = self.device_rect(rect);
        let corner = self.device_corner(corner, device);
        self.stroke_shape(device, corner, thickness * self.scale, color);
    }

    /// Draws a circle's outline, `thickness` units wide.
    ///
    /// [`Canvas::arc`] all the way round, and the shape a gauge's track is: the
    /// whole of the reading it could report, under the part of it that has.
    pub fn ring(&mut self, center: Point, radius: f32, thickness: f32, color: Color) {
        self.arc(center, radius, thickness, 0.0, TAU, color);
    }

    /// Draws part of that outline, from `start` and running `sweep` far.
    ///
    /// `radius` is measured to the middle of the band and `thickness` is how
    /// wide it is, so the band reaches half of that either side — the same
    /// centring [`Canvas::stroke`] uses, and for the same reason.
    ///
    /// Angles are in radians from the direction of the positive x axis, and a
    /// positive `sweep` runs *clockwise*: y grows downward here, so an
    /// increasing angle turns the way a clock's hand does. A sweep of a whole
    /// turn or more is a closed ring, and a negative one runs backwards from
    /// the same start.
    ///
    /// The two ends are round, because an arc is a line bent about a centre and
    /// a line here has round ends; see [`Canvas::line`].
    pub fn arc(
        &mut self,
        center: Point,
        radius: f32,
        thickness: f32,
        start: f32,
        sweep: f32,
        color: Color,
    ) {
        if !color.is_visible() || radius <= 0.0 || thickness <= 0.0 || sweep == 0.0 {
            return;
        }
        let band = self.device_band(center, radius, thickness, start, sweep);
        self.band_shape(&band, color);
    }

    /// Draws a soft halo either side of that band, without marking the band.
    ///
    /// What [`Canvas::shadow`] is to a panel, this is to a gauge: `blur` is how
    /// far the halo reaches past the band's own edges, fading from `color` to
    /// nothing across it, and the band is left for whatever casts it to be
    /// drawn on top. A halo runs both inward and outward, since a line that is
    /// lit lights what is on either side of it.
    #[allow(clippy::too_many_arguments)]
    pub fn arc_glow(
        &mut self,
        center: Point,
        radius: f32,
        thickness: f32,
        start: f32,
        sweep: f32,
        blur: f32,
        color: Color,
    ) {
        if !color.is_visible() || radius <= 0.0 || thickness <= 0.0 || sweep == 0.0 || blur <= 0.0 {
            return;
        }
        let band = self.device_band(center, radius, thickness, start, sweep);
        self.band_glow(&band, blur * self.scale, color);
    }

    /// Fills a disc shading from `inner` at `center` to `outer` at `radius`.
    ///
    /// The radial companion to the linear fills: a reactor core, a node aura, or
    /// a soft point of light. `outer` given a zero alpha makes the disc fade to
    /// nothing at its rim, which is the aura; two opaque colours make a shaded
    /// sphere with a clean antialiased edge. `center` and `radius` are logical
    /// units.
    pub fn fill_radial(&mut self, center: Point, radius: f32, inner: Color, outer: Color) {
        if radius <= 0.0 || (!inner.is_visible() && !outer.is_visible()) {
            return;
        }
        let (cx, cy) = self.device_point(center);
        let r = radius * self.scale;
        // A disc is a rounded square of corner radius half its side, so the same
        // distance field that antialiases a panel's corners antialiases its rim.
        let device = Rect { x: cx - r, y: cy - r, w: 2.0 * r, h: 2.0 * r };
        let shade = Shade::Radial { inner, outer, cx, cy, inv_radius: 1.0 / r.max(SHADE_EPS) };
        self.fill_shaded(device, Corner::Round(r), shade);
    }

    /// Draws `count` radial marks evenly round a circle, the first at `start`.
    ///
    /// Each runs from `inner` to `outer` from the centre, so a tick that starts
    /// where the gauge's band ends reads as a scale beside it and one that
    /// straddles the band reads as a division of it.
    ///
    /// Spaced round the *whole* circle rather than across a sweep, because what
    /// a scale is for is saying how far round the reading has got — and a scale
    /// that stretched with the reading would say nothing at all. `start` is
    /// shared with [`Canvas::arc`] so the first mark can sit at the sweep's own
    /// beginning.
    #[allow(clippy::too_many_arguments)]
    pub fn ticks(
        &mut self,
        center: Point,
        inner: f32,
        outer: f32,
        thickness: f32,
        count: u32,
        start: f32,
        color: Color,
    ) {
        if count == 0 || outer <= inner {
            return;
        }
        let step = TAU / count as f32;
        for index in 0..count {
            let (sin, cos) = (start + step * index as f32).sin_cos();
            self.line(
                Point::new(center.x + cos * inner, center.y + sin * inner),
                Point::new(center.x + cos * outer, center.y + sin * outer),
                thickness,
                color,
            );
        }
    }

    /// Draws a straight line from `from` to `to`, `thickness` units wide.
    ///
    /// The ends are round rather than square, which is what makes a corner
    /// bracket meet itself cleanly and a tick sit on a circle without a flat
    /// edge showing at any angle but the four.
    pub fn line(&mut self, from: Point, to: Point, thickness: f32, color: Color) {
        if !color.is_visible() || thickness <= 0.0 {
            return;
        }
        let segment = Segment::new(
            self.device_point(from),
            self.device_point(to),
            thickness * self.scale / 2.0,
        );
        self.segment_shape(&segment, color);
    }

    /// Draws a line through every point in turn.
    ///
    /// Each segment is drawn on its own, which is what keeps the scan the same
    /// one a single line uses. The consequence is that a *translucent* polyline
    /// is denser where two segments meet, since the join is painted twice —
    /// which is what a round join looks like, and is why the ends are round.
    pub fn polyline(&mut self, points: &[Point], thickness: f32, color: Color) {
        for pair in points.windows(2) {
            self.line(pair[0], pair[1], thickness, color);
        }
    }

    /// Draws a glowing conduit from `from` to `to`: a lit core with an additive
    /// halo `blur` units wide either side of it.
    ///
    /// The neon-HUD counterpart of [`Canvas::line`]. Where a line lays opaque
    /// paint down, a beam *adds* light through
    /// [`blend_add`], so two beams that cross sum toward
    /// white at the crossing rather than one hiding the other, and a beam over
    /// its own glow blooms. `thickness` is the lit core's width and `blur` is how
    /// far the halo reaches past it, fading quadratically to nothing; both are
    /// logical units. A `blur` of zero is a bare additive line.
    pub fn beam(&mut self, from: Point, to: Point, thickness: f32, blur: f32, color: Color) {
        if !color.is_visible() || thickness <= 0.0 {
            return;
        }
        let segment = Segment::new(
            self.device_point(from),
            self.device_point(to),
            thickness * self.scale / 2.0,
        );
        self.segment_glow(&segment, blur.max(0.0) * self.scale, color);
    }

    /// Draws a composable signed-distance [`Shape`] in `paint`, read according
    /// to `style`; see [`crate::sdf`].
    ///
    /// The one entry point for the SDF algebra. Where the built-in shapes each
    /// carry a hand-written scan, a sculpted shape is an arbitrary tree, so this
    /// bounds the work by the shape's own [`Shape::bbox`] (grown for a stroke's
    /// width or a glow's reach), clamps that to the clip, and evaluates the field
    /// once per pixel inside it. The shape answers in logical units and the field
    /// is scaled to device pixels here, so the same coverage rule
    /// `clamp(0.5 - d_device)` that antialiases every other shape antialiases
    /// this one — a [`Sculpt::Fill`] blends over, a [`Sculpt::Stroke`] folds the
    /// distance about the edge, and a [`Sculpt::Glow`] adds light through
    /// [`blend_add`] so overlapping glows bloom.
    pub fn sculpt(&mut self, shape: &Shape, paint: &crate::sdf::Paint, style: Sculpt) {
        let scale = self.scale;
        // Grow the shape's own bounds by whatever the style reaches past the
        // edge, plus a pixel of antialiasing, all in logical units.
        let margin = 1.0
            + match style {
                Sculpt::Fill => 0.0,
                Sculpt::Stroke { width } => width.max(0.0) / 2.0,
                Sculpt::Glow { radius, .. } => radius.max(0.0),
            };
        let bounds =
            self.clip.intersect(self.device_bounds(shape.bbox().expand(Insets::uniform(margin))));
        if bounds.is_empty() {
            return;
        }

        for y in bounds.top..bounds.bottom {
            let row = (y as usize) * self.width as usize;
            let py = (y as f32 + 0.5) / scale;
            for x in bounds.left..bounds.right {
                let px = (x as f32 + 0.5) / scale;
                let p = Point::new(px, py);
                let d = shape.sd(p);
                let d_device = d * scale;
                let index = row + x as usize;

                match style {
                    Sculpt::Fill => {
                        let coverage = 0.5 - d_device;
                        if coverage <= 0.0 {
                            continue;
                        }
                        let color = paint.at(shape, p, d);
                        self.pixels[index] =
                            blend_over(self.pixels[index], color, (coverage.min(1.0) * 255.0) as u8);
                    }
                    Sculpt::Stroke { width } => {
                        let folded = d_device.abs() - width.max(0.0) * scale / 2.0;
                        let coverage = 0.5 - folded;
                        if coverage <= 0.0 {
                            continue;
                        }
                        let color = paint.at(shape, p, d);
                        self.pixels[index] =
                            blend_over(self.pixels[index], color, (coverage.min(1.0) * 255.0) as u8);
                    }
                    Sculpt::Glow { radius, intensity } => {
                        let blur = radius.max(0.0) * scale;
                        // The interior (and its antialiased edge) is lit through
                        // the shared coverage rule; outside, the halo falls away
                        // quadratically to nothing by `blur`, as every glow here
                        // does — a linear ramp ends visibly.
                        let core = (0.5 - d_device).clamp(0.0, 1.0);
                        let halo = if blur > 0.0 && d_device > 0.0 && d_device < blur {
                            let remaining = 1.0 - d_device / blur;
                            remaining * remaining
                        } else {
                            0.0
                        };
                        let coverage = (core.max(halo) * intensity).clamp(0.0, 1.0);
                        if coverage <= 0.0 {
                            continue;
                        }
                        let color = paint.at(shape, p, d);
                        self.pixels[index] =
                            blend_add(self.pixels[index], color, (coverage * 255.0) as u8);
                    }
                }
            }
        }
    }

    /// A logical band in device pixels.
    ///
    /// The scaling happens here rather than in each of the three entry points
    /// that need a band, so a radius cannot be scaled twice.
    fn device_band(
        &self,
        center: Point,
        radius: f32,
        thickness: f32,
        start: f32,
        sweep: f32,
    ) -> Band {
        Band::new(
            self.device_point(center),
            radius * self.scale,
            thickness * self.scale / 2.0,
            start,
            sweep,
        )
    }

    /// A logical corner in device pixels, clamped to what the shape can hold.
    ///
    /// Both the scaling and the clamp happen here rather than in each of the four
    /// entry points, so a corner cannot be scaled twice or clamped against the
    /// wrong rectangle.
    fn device_corner(&self, corner: Corner, device: Rect) -> Corner {
        let limit = device.w.min(device.h) / 2.0;
        corner.resized((corner.size() * self.scale).clamp(0.0, limit.max(0.0)))
    }

    /// Draws a coverage mask in `color`, with its top-left at a *device* pixel.
    ///
    /// Device coordinates because masks come from the glyph rasteriser, which
    /// renders at the exact size and subpixel offset the text will occupy.
    pub fn fill_mask(&mut self, left: i32, top: i32, mask: &Mask, color: Color) {
        if !color.is_visible() || mask.is_empty() {
            return;
        }
        let bounds = self.clip.intersect(PixelBounds {
            left,
            top,
            right: left + mask.width as i32,
            bottom: top + mask.height as i32,
        });
        if bounds.is_empty() {
            return;
        }

        for y in bounds.top..bounds.bottom {
            let mask_row = ((y - top) as usize) * mask.width as usize;
            let pixel_row = (y as usize) * self.width as usize;
            for x in bounds.left..bounds.right {
                let coverage = mask.coverage[mask_row + (x - left) as usize];
                if coverage == 0 {
                    continue;
                }
                let index = pixel_row + x as usize;
                self.pixels[index] = blend_over(self.pixels[index], color, coverage);
            }
        }
    }

    /// Copies a BGRA picture into `dest`, one source pixel per device pixel.
    ///
    /// The bitmap primitive, and the only drawing here that does not come from
    /// a distance field: a picture made somewhere else — a screen captured on
    /// another machine, a decoded image — put on this surface. See [`Bgra`] for
    /// the byte order and for why the alpha byte is skipped.
    ///
    /// # It does not scale, and that is the point
    ///
    /// One source pixel lands on one *device* pixel, anchored at `dest`'s
    /// top-left and clipped to `dest`. A picture larger than `dest` is cropped
    /// and a smaller one leaves the rest of `dest` as it was; neither is
    /// resampled.
    ///
    /// Scaling would make this a filter rather than a copy — a weight computed
    /// per pixel over millions of them, every frame, in software, which is
    /// precisely the cost every other primitive here is shaped to avoid. It also
    /// cannot be done well in one line: nearest-neighbour shimmers on a moving
    /// picture and bilinear blurs text, and which of those is wrong depends on what the
    /// picture *is*, which this cannot know. So the decision stays with whoever
    /// has the picture: ask the far end for the size that fits, or resample
    /// deliberately before handing it over.
    ///
    /// A caller that wants a *part* of a picture builds a [`Bgra`] over the
    /// bytes from that offset with the same stride — which is why panning
    /// around a screen larger than the pane needs nothing more here.
    ///
    /// # What it is careful about
    ///
    /// Three things, each of which is a way real pictures arrive and each of
    /// which is a corrupt frame if it is got wrong: a `dest` that hangs off the
    /// edge of the surface, a `dest` whose origin is *negative* — a viewport
    /// scrolled up out of view — and a stride wider than the row.
    pub fn blit_bgra(&mut self, dest: Rect, source: &Bgra<'_>) {
        if source.is_empty() {
            return;
        }
        let device = self.device_rect(dest);
        // Rounded rather than truncated: truncation moves toward zero, so a
        // viewport scrolled to a negative origin would jump half a pixel the
        // moment it crossed the top-left corner of the window.
        let left = device.min_x().round() as i32;
        let top = device.min_y().round() as i32;
        let (Some(right), Some(bottom)) =
            (left.checked_add_unsigned(source.width()), top.checked_add_unsigned(source.height()))
        else {
            return;
        };

        let bounds = self
            .clip
            .intersect(self.device_bounds(dest))
            .intersect(PixelBounds { left, top, right, bottom });
        if bounds.is_empty() {
            return;
        }

        for y in bounds.top..bounds.bottom {
            // Every one of these is inside a rectangle already intersected with
            // the picture's own extent, so none of them can be `None`; they are
            // asked as questions rather than asserted because a slice index that
            // is wrong is a panic and this crate aborts on one.
            let Some(row) = source.row((y - top) as u32) else {
                continue;
            };
            let first = ((bounds.left - left) as usize) * 4;
            let last = ((bounds.right - left) as usize) * 4;
            let Some(span) = row.get(first..last) else {
                continue;
            };
            let start = (y as usize) * self.width as usize + bounds.left as usize;
            let Some(target) = self.pixels.get_mut(start..start + span.len() / 4) else {
                continue;
            };
            for (word, pixel) in target.iter_mut().zip(span.chunks_exact(4)) {
                let Ok(bgra) = <[u8; 4]>::try_from(pixel) else {
                    continue;
                };
                // B, G, R, A read little-endian is 0xAARRGGBB, which is the
                // word this surface stores; the alpha is replaced rather than
                // trusted.
                *word = (u32::from_le_bytes(bgra) & 0x00ff_ffff) | 0xff00_0000;
            }
        }
    }

    /// A logical point in device pixels, unrounded.
    fn device_point(&self, point: Point) -> (f32, f32) {
        (point.x * self.scale, point.y * self.scale)
    }

    /// A logical rectangle in device pixels, unrounded.
    fn device_rect(&self, rect: Rect) -> Rect {
        Rect {
            x: rect.x * self.scale,
            y: rect.y * self.scale,
            w: rect.w * self.scale,
            h: rect.h * self.scale,
        }
    }

    /// The whole pixels a logical rectangle covers, rounded outward.
    ///
    /// Outward for clipping, so that a region's own antialiased edge is not
    /// clipped away by the region it belongs to.
    fn device_bounds(&self, rect: Rect) -> PixelBounds {
        let device = self.device_rect(rect);
        PixelBounds {
            left: device.min_x().floor().max(0.0) as i32,
            top: device.min_y().floor().max(0.0) as i32,
            right: (device.max_x().ceil().max(0.0) as i32).min(self.width as i32),
            bottom: (device.max_y().ceil().max(0.0) as i32).min(self.height as i32),
        }
    }

    /// The fast path: whole pixels, square corners, no transparency.
    ///
    /// This is the common case — panel backgrounds, table rows, separators —
    /// and it is a row-wise fill with no arithmetic per pixel.
    fn fill_aligned_opaque(&mut self, device: Rect, color: Color) {
        let bounds = self.clip.intersect(PixelBounds {
            left: device.min_x() as i32,
            top: device.min_y() as i32,
            right: device.max_x() as i32,
            bottom: device.max_y() as i32,
        });
        if bounds.is_empty() {
            return;
        }
        let word = color.to_argb() | 0xff00_0000;
        for y in bounds.top..bounds.bottom {
            let row = (y as usize) * self.width as usize;
            let start = row + bounds.left as usize;
            let end = row + bounds.right as usize;
            self.pixels[start..end].fill(word);
        }
    }

    /// Fills a rounded rectangle from its signed distance field.
    ///
    /// # Why the interior is not evaluated
    ///
    /// Coverage only varies within about a pixel of the edge; everywhere else it
    /// is exactly one. Evaluating the distance field across a whole panel means
    /// millions of square roots to discover that the middle is, in fact, filled.
    /// So each row is split: the span that is unambiguously inside is written
    /// straight out, and the distance field is evaluated only on the margins.
    ///
    /// For the panels this console is made of, that is the difference between a
    /// frame costing tens of milliseconds and costing one.
    fn fill_shape(&mut self, device: Rect, corner: Corner, paint: Paint) {
        let bounds = self.clip.intersect(PixelBounds {
            left: (device.min_x() - 1.0).floor() as i32,
            top: (device.min_y() - 1.0).floor() as i32,
            right: (device.max_x() + 1.0).ceil() as i32,
            bottom: (device.max_y() + 1.0).ceil() as i32,
        });
        if bounds.is_empty() {
            return;
        }

        let size = corner.size();
        let field = DistanceField::new(device, corner);
        // A pixel is wholly inside once it is a pixel clear of the straight
        // edges and of the corner treatment, which is `size` in from each side —
        // true of an arc and of a cut alike, since both reach exactly that far.
        let solid_left = (device.min_x() + size + 1.0).ceil() as i32;
        let solid_right = (device.max_x() - size - 1.0).floor() as i32;
        let solid_top = device.min_y() + size + 1.0;
        let solid_bottom = device.max_y() - size - 1.0;

        for y in bounds.top..bounds.bottom {
            let sample_y = y as f32 + 0.5;
            let row = (y as usize) * self.width as usize;
            // One colour for the whole row, which is what makes a vertical
            // gradient cost no more than a flat fill.
            let color = paint.at(sample_y);

            let interior = (sample_y >= solid_top && sample_y <= solid_bottom)
                .then(|| (solid_left.max(bounds.left), solid_right.min(bounds.right)))
                .filter(|(start, end)| end > start);

            let (left_end, right_start) = match interior {
                Some((start, end)) => (start, end),
                None => (bounds.right, bounds.right),
            };

            self.blend_span(row, bounds.left, left_end, sample_y, &field, color);
            if let Some((start, end)) = interior {
                if color.a == 255 {
                    let word = color.to_argb() | 0xff00_0000;
                    self.pixels[row + start as usize..row + end as usize].fill(word);
                } else {
                    for x in start..end {
                        let index = row + x as usize;
                        self.pixels[index] = blend_over(self.pixels[index], color, 255);
                    }
                }
            }
            self.blend_span(row, right_start, bounds.right, sample_y, &field, color);
        }
    }

    /// Fills a shaped rectangle whose colour varies per pixel; see [`Shade`].
    ///
    /// The scan is [`Canvas::fill_shape`]'s, keeping its interior/margin split so
    /// the distance field's square root is still taken only near the edge. What
    /// it cannot keep is the bulk word write: the interior colour is no longer
    /// one value per row, so each interior pixel is written from the shade —
    /// opaque pixels straight, translucent ones through [`blend_over`].
    fn fill_shaded(&mut self, device: Rect, corner: Corner, shade: Shade) {
        let bounds = self.clip.intersect(PixelBounds {
            left: (device.min_x() - 1.0).floor() as i32,
            top: (device.min_y() - 1.0).floor() as i32,
            right: (device.max_x() + 1.0).ceil() as i32,
            bottom: (device.max_y() + 1.0).ceil() as i32,
        });
        if bounds.is_empty() {
            return;
        }

        let size = corner.size();
        let field = DistanceField::new(device, corner);
        let solid_left = (device.min_x() + size + 1.0).ceil() as i32;
        let solid_right = (device.max_x() - size - 1.0).floor() as i32;
        let solid_top = device.min_y() + size + 1.0;
        let solid_bottom = device.max_y() - size - 1.0;

        for y in bounds.top..bounds.bottom {
            let sample_y = y as f32 + 0.5;
            let row = (y as usize) * self.width as usize;

            let interior = (sample_y >= solid_top && sample_y <= solid_bottom)
                .then(|| (solid_left.max(bounds.left), solid_right.min(bounds.right)))
                .filter(|(start, end)| end > start);

            let (left_end, right_start) = match interior {
                Some((start, end)) => (start, end),
                None => (bounds.right, bounds.right),
            };

            self.shade_span(row, bounds.left, left_end, sample_y, &field, &shade);
            if let Some((start, end)) = interior {
                // No bulk `.fill(word)`: the colour varies along the row.
                for x in start..end {
                    let index = row + x as usize;
                    let c = shade.at(x as f32 + 0.5, sample_y);
                    self.pixels[index] = if c.a == 255 {
                        c.to_argb() | 0xff00_0000
                    } else {
                        blend_over(self.pixels[index], c, 255)
                    };
                }
            }
            self.shade_span(row, right_start, bounds.right, sample_y, &field, &shade);
        }
    }

    /// The shaded analogue of [`Canvas::blend_span`]: each covered margin pixel
    /// is blended from the shade's own colour at that point, rather than from one
    /// colour held for the whole run.
    fn shade_span(
        &mut self,
        row: usize,
        from: i32,
        to: i32,
        sample_y: f32,
        field: &DistanceField,
        shade: &Shade,
    ) {
        for x in from..to {
            let fx = x as f32 + 0.5;
            let coverage = 0.5 - field.at(fx, sample_y);
            if coverage <= 0.0 {
                continue;
            }
            let index = row + x as usize;
            self.pixels[index] =
                blend_over(self.pixels[index], shade.at(fx, sample_y), (coverage.min(1.0) * 255.0) as u8);
        }
    }

    /// Draws the halo outside a shape's edge.
    ///
    /// Banded exactly as [`Canvas::stroke_shape`] is, and for the same reason:
    /// between the corners the only marked pixels are the two vertical strips
    /// beside the shape, and everything between them is inside it and untouched.
    fn glow_shape(&mut self, device: Rect, corner: Corner, blur: f32, color: Color) {
        let bounds = self.clip.intersect(PixelBounds {
            left: (device.min_x() - blur).floor() as i32,
            top: (device.min_y() - blur).floor() as i32,
            right: (device.max_x() + blur).ceil() as i32,
            bottom: (device.max_y() + blur).ceil() as i32,
        });
        if bounds.is_empty() {
            return;
        }

        let field = DistanceField::new(device, corner);
        let straight_top = device.min_y() + corner.size();
        let straight_bottom = device.max_y() - corner.size();
        let left_edge = device.min_x().floor() as i32;
        let right_edge = device.max_x().ceil() as i32;

        for y in bounds.top..bounds.bottom {
            let sample_y = y as f32 + 0.5;
            let row = (y as usize) * self.width as usize;

            if sample_y > straight_top && sample_y < straight_bottom && right_edge > left_edge {
                self.glow_span(row, bounds.left, left_edge.min(bounds.right), sample_y, &field, blur, color);
                self.glow_span(row, right_edge.max(bounds.left), bounds.right, sample_y, &field, blur, color);
            } else {
                self.glow_span(row, bounds.left, bounds.right, sample_y, &field, blur, color);
            }
        }
    }

    /// Strokes a rounded rectangle's outline, centred on its edge.
    ///
    /// Only the band the line actually occupies is evaluated. Scanning the whole
    /// rectangle to draw a one-pixel border around it costs the area of the
    /// panel to mark its perimeter, which for the outlines here was most of the
    /// work in a frame.
    fn stroke_shape(&mut self, device: Rect, corner: Corner, thickness: f32, color: Color) {
        // Half a line width to each side of the edge, plus a pixel of
        // antialiasing, is everything the stroke can touch.
        let reach = thickness / 2.0 + 1.0;
        let bounds = self.clip.intersect(PixelBounds {
            left: (device.min_x() - reach).floor() as i32,
            top: (device.min_y() - reach).floor() as i32,
            right: (device.max_x() + reach).ceil() as i32,
            bottom: (device.max_y() + reach).ceil() as i32,
        });
        if bounds.is_empty() {
            return;
        }

        let field = DistanceField::new(device, corner);
        // Between the corners, the only marked pixels are the two vertical
        // edges; everything between them is inside the shape and untouched.
        let straight_top = device.min_y() + corner.size() + reach;
        let straight_bottom = device.max_y() - corner.size() - reach;
        let left_edge = (device.min_x() + reach).ceil() as i32;
        let right_edge = (device.max_x() - reach).floor() as i32;

        for y in bounds.top..bounds.bottom {
            let sample_y = y as f32 + 0.5;
            let row = (y as usize) * self.width as usize;

            if sample_y > straight_top && sample_y < straight_bottom && right_edge > left_edge {
                self.stroke_span(row, bounds.left, left_edge.min(bounds.right), sample_y, &field, thickness, color);
                self.stroke_span(row, right_edge.max(bounds.left), bounds.right, sample_y, &field, thickness, color);
            } else {
                self.stroke_span(row, bounds.left, bounds.right, sample_y, &field, thickness, color);
            }
        }
    }

    /// Blends one run of pixels according to how much of the shape covers them.
    fn blend_span(
        &mut self,
        row: usize,
        from: i32,
        to: i32,
        sample_y: f32,
        field: &DistanceField,
        color: Color,
    ) {
        for x in from..to {
            let distance = field.at(x as f32 + 0.5, sample_y);
            let coverage = 0.5 - distance;
            if coverage <= 0.0 {
                continue;
            }
            let index = row + x as usize;
            self.pixels[index] =
                blend_over(self.pixels[index], color, (coverage.min(1.0) * 255.0) as u8);
        }
    }

    /// The same, for a halo: coverage falls away with distance outside the edge.
    ///
    /// The falloff is quadratic rather than linear because a linear ramp has a
    /// visible hard end where it reaches zero, and a glow with an outline around
    /// it is not a glow.
    #[allow(clippy::too_many_arguments)]
    fn glow_span(
        &mut self,
        row: usize,
        from: i32,
        to: i32,
        sample_y: f32,
        field: &DistanceField,
        blur: f32,
        color: Color,
    ) {
        for x in from..to {
            let distance = field.at(x as f32 + 0.5, sample_y);
            // Inside the shape is left alone: whatever casts the glow covers it.
            if distance <= 0.0 || distance >= blur {
                continue;
            }
            let remaining = 1.0 - distance / blur;
            let index = row + x as usize;
            self.pixels[index] =
                blend_over(self.pixels[index], color, (remaining * remaining * 255.0) as u8);
        }
    }

    /// Marks the band a ring or an arc occupies, and nothing else.
    ///
    /// Banded by row exactly as [`Canvas::stroke_shape`] is, and for the same
    /// reason: a row that crosses the hole in the middle is two short runs
    /// rather than one long one, so a gauge costs its own line and never the
    /// area it encircles.
    fn band_shape(&mut self, band: &Band, color: Color) {
        let reach = band.half + 1.0;
        let bounds = self.band_bounds(band, reach);
        if bounds.is_empty() {
            return;
        }

        for y in bounds.top..bounds.bottom {
            let sample_y = y as f32 + 0.5;
            let row = (y as usize) * self.width as usize;
            for (from, to) in runs(band.spans(sample_y, reach), bounds) {
                for x in from..to {
                    let coverage = 0.5 - band.at(x as f32 + 0.5, sample_y);
                    if coverage <= 0.0 {
                        continue;
                    }
                    let index = row + x as usize;
                    self.pixels[index] =
                        blend_over(self.pixels[index], color, (coverage.min(1.0) * 255.0) as u8);
                }
            }
        }
    }

    /// The same, for the halo either side of that band.
    ///
    /// The falloff is quadratic for the reason [`Canvas::glow_span`] gives: a
    /// linear ramp ends visibly, and a glow with an outline is not a glow.
    fn band_glow(&mut self, band: &Band, blur: f32, color: Color) {
        let bounds = self.band_bounds(band, band.half + blur);
        if bounds.is_empty() {
            return;
        }

        for y in bounds.top..bounds.bottom {
            let sample_y = y as f32 + 0.5;
            let row = (y as usize) * self.width as usize;
            for (from, to) in runs(band.spans(sample_y, band.half + blur), bounds) {
                for x in from..to {
                    let distance = band.at(x as f32 + 0.5, sample_y);
                    // The band itself is left alone: whatever casts the halo
                    // covers it.
                    if distance <= 0.0 || distance >= blur {
                        continue;
                    }
                    let remaining = 1.0 - distance / blur;
                    let index = row + x as usize;
                    self.pixels[index] = blend_over(
                        self.pixels[index],
                        color,
                        (remaining * remaining * 255.0) as u8,
                    );
                }
            }
        }
    }

    /// Everything a band of this reach could mark, in whole pixels.
    fn band_bounds(&self, band: &Band, reach: f32) -> PixelBounds {
        let outer = band.radius + reach;
        self.clip.intersect(PixelBounds {
            left: (band.center_x - outer).floor() as i32,
            top: (band.center_y - outer).floor() as i32,
            right: (band.center_x + outer).ceil() as i32,
            bottom: (band.center_y + outer).ceil() as i32,
        })
    }

    /// Marks the capsule a line occupies, and nothing else.
    ///
    /// Narrowed per row to the strip the line crosses that row in, so a
    /// diagonal across a window costs its own length rather than the area of
    /// the box it spans.
    fn segment_shape(&mut self, segment: &Segment, color: Color) {
        let reach = segment.half + 1.0;
        let bounds = self.clip.intersect(segment.bounds(reach));
        if bounds.is_empty() {
            return;
        }

        for y in bounds.top..bounds.bottom {
            let sample_y = y as f32 + 0.5;
            let row = (y as usize) * self.width as usize;
            for (from, to) in runs([segment.span(sample_y, reach), None], bounds) {
                for x in from..to {
                    let coverage = 0.5 - segment.at(x as f32 + 0.5, sample_y);
                    if coverage <= 0.0 {
                        continue;
                    }
                    let index = row + x as usize;
                    self.pixels[index] =
                        blend_over(self.pixels[index], color, (coverage.min(1.0) * 255.0) as u8);
                }
            }
        }
    }

    /// Adds a glowing line's light to the buffer: a lit core, and a halo that
    /// falls away with distance from the line.
    ///
    /// The additive counterpart of [`Canvas::segment_shape`]. It keeps that
    /// scan's per-row narrowing to the strip the line crosses, but reads the
    /// distance field across the whole reach — core and halo alike — and
    /// composites with [`blend_add`] so overlapping
    /// beams brighten toward white instead of the later one hiding the earlier.
    fn segment_glow(&mut self, segment: &Segment, blur: f32, color: Color) {
        let reach = segment.half + blur + 1.0;
        let bounds = self.clip.intersect(segment.bounds(reach));
        if bounds.is_empty() {
            return;
        }

        for y in bounds.top..bounds.bottom {
            let sample_y = y as f32 + 0.5;
            let row = (y as usize) * self.width as usize;
            for (from, to) in runs([segment.span(sample_y, reach), None], bounds) {
                for x in from..to {
                    let distance = segment.at(x as f32 + 0.5, sample_y);
                    let coverage = glow_coverage(distance, blur);
                    if coverage == 0 {
                        continue;
                    }
                    let index = row + x as usize;
                    self.pixels[index] = blend_add(self.pixels[index], color, coverage);
                }
            }
        }
    }

    /// The same, for an outline: the distance is folded about the shape's edge.
    #[allow(clippy::too_many_arguments)]
    fn stroke_span(
        &mut self,
        row: usize,
        from: i32,
        to: i32,
        sample_y: f32,
        field: &DistanceField,
        thickness: f32,
        color: Color,
    ) {
        let half = thickness / 2.0;
        for x in from..to {
            let distance = field.at(x as f32 + 0.5, sample_y).abs() - half;
            let coverage = 0.5 - distance;
            if coverage <= 0.0 {
                continue;
            }
            let index = row + x as usize;
            self.pixels[index] =
                blend_over(self.pixels[index], color, (coverage.min(1.0) * 255.0) as u8);
        }
    }
}

/// What colour a fill is at a given device row.
///
/// A shape is filled row by row, and both kinds of fill this canvas offers —
/// flat, and shading top to bottom — answer one colour for a whole row. Keeping
/// that as the interface is what lets one scan serve both, and is why an angled
/// gradient is not offered: it would make the colour vary along the row and cost
/// a mix per pixel.
#[derive(Debug, Clone, Copy)]
struct Paint {
    top: Color,
    bottom: Color,
    /// Device y of the top edge.
    y: f32,
    /// One over the height, or zero when the paint is flat.
    ///
    /// Held as a reciprocal so the per-row lookup is a multiply, and zero is
    /// what marks a flat paint — which then needs no branch of its own.
    inverse_height: f32,
}

impl Paint {
    /// One colour everywhere.
    fn solid(color: Color) -> Self {
        Self { top: color, bottom: color, y: 0.0, inverse_height: 0.0 }
    }

    /// Shading from `top` at the rectangle's top edge to `bottom` at its bottom.
    fn vertical(device: Rect, top: Color, bottom: Color) -> Self {
        Self {
            top,
            bottom,
            y: device.y,
            inverse_height: if device.h > 0.0 { 1.0 / device.h } else { 0.0 },
        }
    }

    /// The colour at a device row.
    fn at(&self, y: f32) -> Color {
        if self.inverse_height == 0.0 {
            return self.top;
        }
        self.top.mix(self.bottom, (y - self.y) * self.inverse_height)
    }
}

/// The smallest gradient axis or radius trusted before it is treated as a
/// point: a zero-length axis or radius collapses the shade to its first colour
/// rather than dividing by nothing.
const SHADE_EPS: f32 = 1e-6;

/// A colour that varies across the surface, evaluated per device pixel.
///
/// The per-pixel counterpart of [`Paint`]. `Paint` answers one colour for a
/// whole row, which is why a vertical gradient is free; a `Shade` answers a
/// colour at a point, which is what a horizontal, angled, or radial gradient
/// needs and what makes it cost a mix per pixel.
enum Shade {
    /// `c0` at `t = 0`, `c1` at `t = 1`, where `t` is the clamped projection of
    /// the pixel onto the gradient axis. `gx, gy` is the axis vector divided by
    /// its own squared length, so the projection is `(x-ox)*gx + (y-oy)*gy`.
    Linear { c0: Color, c1: Color, ox: f32, oy: f32, gx: f32, gy: f32 },
    /// `inner` at the centre, `outer` at `radius` and beyond; `inv_radius` is
    /// `1.0 / radius` so the falloff is a multiply.
    Radial { inner: Color, outer: Color, cx: f32, cy: f32, inv_radius: f32 },
}

impl Shade {
    /// A linear gradient from `c0` at device point `a` to `c1` at device point
    /// `b`, solid beyond either end. A zero-length axis collapses to `c0`.
    fn linear(a: (f32, f32), b: (f32, f32), c0: Color, c1: Color) -> Self {
        let (dx, dy) = (b.0 - a.0, b.1 - a.1);
        let inv = 1.0 / (dx * dx + dy * dy).max(SHADE_EPS);
        Shade::Linear { c0, c1, ox: a.0, oy: a.1, gx: dx * inv, gy: dy * inv }
    }

    /// The colour at device pixel centre `(x, y)`.
    fn at(&self, x: f32, y: f32) -> Color {
        match *self {
            Shade::Linear { c0, c1, ox, oy, gx, gy } => {
                let t = ((x - ox) * gx + (y - oy) * gy).clamp(0.0, 1.0);
                c0.mix(c1, t)
            }
            Shade::Radial { inner, outer, cx, cy, inv_radius } => {
                let (dx, dy) = (x - cx, y - cy);
                let t = ((dx * dx + dy * dy).sqrt() * inv_radius).clamp(0.0, 1.0);
                inner.mix(outer, t)
            }
        }
    }
}

/// How much light a glowing line lays down at signed `distance` from its core
/// edge, with a halo `blur` wide.
///
/// The lit core is solid, its edge antialiased by the shared `0.5 - distance`
/// rule; past it the halo falls away quadratically, for the reason
/// [`Canvas::glow_span`] gives — a linear ramp ends visibly, and a glow with an
/// outline is not a glow. The two are combined by taking the greater, so the
/// core's edge meets the halo without a step.
fn glow_coverage(distance: f32, blur: f32) -> u8 {
    let core = (0.5 - distance).clamp(0.0, 1.0);
    let halo = if blur > 0.0 && distance > 0.0 && distance < blur {
        let remaining = 1.0 - distance / blur;
        remaining * remaining
    } else {
        0.0
    };
    (core.max(halo) * 255.0) as u8
}

/// The signed distance from a point to a shaped rectangle's edge.
///
/// Negative inside, positive outside, and zero exactly on the edge. Precomputed
/// from the shape so that a scan does not recompute its centre and half-extents
/// for every pixel.
///
/// # How one field serves both corner shapes
///
/// A rounded rectangle is the set of points within `radius` of an inner
/// rectangle shrunk by that much — the classic form, and the reason the square
/// root is only ever taken in the corners.
///
/// A cut rectangle is the *intersection* of the full rectangle with the diagonal
/// half-planes that slice its corners off, and the distance to an intersection
/// of convex regions is the greater of the distances to each. The diagonal's
/// distance is `(|dx| + |dy| - k) / √2` — a plane whose normal is the diagonal —
/// so it costs an add and a multiply and never a square root at all.
///
/// Which arm runs is a branch on a `bool` that is constant for the whole scan,
/// so the predictor gets it right every time after the first pixel.
struct DistanceField {
    center_x: f32,
    center_y: f32,
    /// Half-width less the corner size: the straight section's half-extent.
    straight_x: f32,
    /// Half-height less the corner size.
    straight_y: f32,
    /// How far the corner treatment reaches along each edge.
    size: f32,
    /// Half-width and half-height, for the cut form's own rectangle test.
    half_x: f32,
    half_y: f32,
    /// Where the diagonal that cuts the corner sits: `|dx| + |dy| = corner_line`.
    corner_line: f32,
    /// Whether the corners are cut rather than rounded.
    cut: bool,
}

/// One over the square root of two: what turns a diagonal's `|dx| + |dy|`
/// difference into a true perpendicular distance.
const DIAGONAL_SCALE: f32 = std::f32::consts::FRAC_1_SQRT_2;

impl DistanceField {
    fn new(device: Rect, corner: Corner) -> Self {
        let size = corner.size();
        let half_x = device.w / 2.0;
        let half_y = device.h / 2.0;
        Self {
            center_x: device.x + half_x,
            center_y: device.y + half_y,
            straight_x: half_x - size,
            straight_y: half_y - size,
            size,
            half_x,
            half_y,
            corner_line: half_x + half_y - size,
            cut: matches!(corner, Corner::Cut(_)),
        }
    }

    /// The distance from `(x, y)` to the edge.
    ///
    /// For a rounded shape the square root is taken only in the corners.
    /// Everywhere else the nearest edge is a straight one and the distance is a
    /// subtraction — which matters, because the corners are a few hundred pixels
    /// of a panel and the straight edges are the rest of it.
    fn at(&self, x: f32, y: f32) -> f32 {
        let from_x = (x - self.center_x).abs();
        let from_y = (y - self.center_y).abs();

        if self.cut {
            let offset_x = from_x - self.half_x;
            let offset_y = from_y - self.half_y;
            let to_rectangle = if offset_x > 0.0 && offset_y > 0.0 {
                (offset_x * offset_x + offset_y * offset_y).sqrt()
            } else {
                offset_x.max(offset_y)
            };
            let to_diagonal = (from_x + from_y - self.corner_line) * DIAGONAL_SCALE;
            return to_rectangle.max(to_diagonal);
        }

        let offset_x = from_x - self.straight_x;
        let offset_y = from_y - self.straight_y;
        if offset_x > 0.0 && offset_y > 0.0 {
            (offset_x * offset_x + offset_y * offset_y).sqrt() - self.size
        } else {
            offset_x.max(offset_y) - self.size
        }
    }
}

/// The signed distance from a point to the middle of a ring or an arc.
///
/// Negative inside the band, positive outside, zero on its edge — the contract
/// [`DistanceField`] keeps, so the same two scans that fill a rectangle and
/// glow from one serve a gauge without knowing it is round.
///
/// # Why the ends are a pair of points
///
/// Within the sweep, the nearest edge is the band's own and the distance is
/// `||p - centre| - radius| - half`: one square root and two subtractions.
/// Past an end, the nearest part of the band *is* that end — so the distance
/// there is the distance to a disc of the same half width sitting on it, which
/// is what makes the end round and costs one more square root on the handful of
/// pixels beyond it.
struct Band {
    center_x: f32,
    center_y: f32,
    /// To the middle of the band.
    radius: f32,
    /// Half the line width: how far the band reaches either side of `radius`.
    half: f32,
    /// Where the sweep begins, once normalised to run forwards.
    start: f32,
    /// How far it runs from there.
    sweep: f32,
    /// The middles of the two round ends, or `None` for a closed ring.
    ///
    /// A ring has no ends to cap, and testing a pixel against a sweep of a full
    /// turn would reject the seam at the start angle — a hairline crack across
    /// the gauge, in the one place floating point is least likely to agree.
    ends: Option<[(f32, f32); 2]>,
}

impl Band {
    fn new(center: (f32, f32), radius: f32, half: f32, start: f32, sweep: f32) -> Self {
        // A backwards sweep is the same band read the other way, so it is
        // turned round here and nothing below has to know a sweep can be
        // negative.
        let (start, sweep) = if sweep < 0.0 { (start + sweep, -sweep) } else { (start, sweep) };
        let ends = (sweep < TAU).then(|| {
            [on_circle(center, radius, start), on_circle(center, radius, start + sweep)]
        });
        Self { center_x: center.0, center_y: center.1, radius, half, start, sweep, ends }
    }

    /// The distance from `(x, y)` to the band's edge.
    fn at(&self, x: f32, y: f32) -> f32 {
        let from_x = x - self.center_x;
        let from_y = y - self.center_y;
        let radial = ((from_x * from_x + from_y * from_y).sqrt() - self.radius).abs();

        let Some(ends) = self.ends else {
            return radial - self.half;
        };
        if (from_y.atan2(from_x) - self.start).rem_euclid(TAU) <= self.sweep {
            return radial - self.half;
        }
        let to = |(end_x, end_y): (f32, f32)| {
            let (dx, dy) = (x - end_x, y - end_y);
            (dx * dx + dy * dy).sqrt()
        };
        to(ends[0]).min(to(ends[1])) - self.half
    }

    /// The one or two runs of a row this band, grown by `reach`, can touch.
    ///
    /// Two whenever the row crosses the hole in the middle, which is the whole
    /// saving: the interior of a gauge is never scanned to discover that it is
    /// empty.
    fn spans(&self, sample_y: f32, reach: f32) -> [Option<(f32, f32)>; 2] {
        let outer = self.radius + reach;
        let inner = self.radius - reach;
        let from_y = (sample_y - self.center_y).abs();
        if from_y >= outer {
            return [None, None];
        }
        let wide = (outer * outer - from_y * from_y).sqrt();
        if inner <= 0.0 || from_y >= inner {
            return [Some((self.center_x - wide, self.center_x + wide)), None];
        }
        let narrow = (inner * inner - from_y * from_y).sqrt();
        [
            Some((self.center_x - wide, self.center_x - narrow)),
            Some((self.center_x + narrow, self.center_x + wide)),
        ]
    }
}

/// Where an angle round a circle of this radius lands.
fn on_circle(center: (f32, f32), radius: f32, angle: f32) -> (f32, f32) {
    let (sin, cos) = angle.sin_cos();
    (center.0 + cos * radius, center.1 + sin * radius)
}

/// The signed distance from a point to a line between two points.
///
/// The capsule form: the distance to the nearest point *on the segment*, less
/// half the line width. Clamping the projection to the segment is what rounds
/// the ends, and it is one branch-free `clamp` rather than a case for each end.
struct Segment {
    ax: f32,
    ay: f32,
    /// From the first point to the second.
    dx: f32,
    dy: f32,
    /// One over the segment's squared length, or zero when it has none.
    ///
    /// Held as a reciprocal so the projection is a multiply, and zero is what
    /// makes a segment of no length collapse onto its own first point — which
    /// draws the dot that a line from somewhere to itself is.
    inverse_length_squared: f32,
    /// Half the line width.
    half: f32,
    /// The unit normal, and where the line sits along it: `nx*x + ny*y = offset`.
    ///
    /// What lets a row be narrowed to the strip the line crosses it in. Without
    /// it a diagonal across a window would be scanned over its whole bounding
    /// box, which is the square of the work its own length is.
    nx: f32,
    ny: f32,
    offset: f32,
}

impl Segment {
    fn new(from: (f32, f32), to: (f32, f32), half: f32) -> Self {
        let dx = to.0 - from.0;
        let dy = to.1 - from.1;
        let length_squared = dx * dx + dy * dy;
        // A segment with no length has no direction to take a normal from, so
        // rows are narrowed against a vertical through it instead.
        let (inverse_length_squared, nx, ny) = if length_squared > 0.0 {
            let length = length_squared.sqrt();
            (1.0 / length_squared, -dy / length, dx / length)
        } else {
            (0.0, 1.0, 0.0)
        };
        Self {
            ax: from.0,
            ay: from.1,
            dx,
            dy,
            inverse_length_squared,
            half,
            nx,
            ny,
            offset: nx * from.0 + ny * from.1,
        }
    }

    /// The distance from `(x, y)` to the capsule's edge.
    fn at(&self, x: f32, y: f32) -> f32 {
        let from_x = x - self.ax;
        let from_y = y - self.ay;
        let along =
            ((from_x * self.dx + from_y * self.dy) * self.inverse_length_squared).clamp(0.0, 1.0);
        let offset_x = from_x - self.dx * along;
        let offset_y = from_y - self.dy * along;
        (offset_x * offset_x + offset_y * offset_y).sqrt() - self.half
    }

    /// Everything a capsule of this reach could mark, in whole pixels.
    fn bounds(&self, reach: f32) -> PixelBounds {
        let (bx, by) = (self.ax + self.dx, self.ay + self.dy);
        PixelBounds {
            left: (self.ax.min(bx) - reach).floor() as i32,
            top: (self.ay.min(by) - reach).floor() as i32,
            right: (self.ax.max(bx) + reach).ceil() as i32,
            bottom: (self.ay.max(by) + reach).ceil() as i32,
        }
    }

    /// The run of a row this capsule, grown by `reach`, can touch.
    ///
    /// The strip the *infinite* line makes across the row, which the bounding
    /// box then cuts to the segment's own extent. Both ends are inside it
    /// already, since a cap is centred on the line and no wider than the strip.
    fn span(&self, sample_y: f32, reach: f32) -> Option<(f32, f32)> {
        if self.nx == 0.0 {
            // A horizontal line: a row is either within reach of it or misses
            // it entirely, and the bounds hold the ends either way.
            return ((self.ny * sample_y - self.offset).abs() <= reach)
                .then_some((f32::NEG_INFINITY, f32::INFINITY));
        }
        let middle = (self.offset - self.ny * sample_y) / self.nx;
        let spread = (reach / self.nx).abs();
        Some((middle - spread, middle + spread))
    }
}

/// The whole pixels a row's spans come to, clipped and dropped when empty.
fn runs(
    spans: [Option<(f32, f32)>; 2],
    bounds: PixelBounds,
) -> impl Iterator<Item = (i32, i32)> {
    let (left, right) = (bounds.left as f32, bounds.right as f32);
    spans.into_iter().flatten().filter_map(move |(from, to)| {
        let from = from.floor().clamp(left, right) as i32;
        let to = to.ceil().clamp(left, right) as i32;
        (to > from).then_some((from, to))
    })
}

/// Whether a device-space rectangle lands exactly on the pixel grid.
fn is_pixel_aligned(rect: Rect) -> bool {
    let whole = |value: f32| (value - value.round()).abs() < 1.0 / 512.0;
    whole(rect.x) && whole(rect.y) && whole(rect.w) && whole(rect.h)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The colour of one device pixel, for assertions.
    fn pixel_at(canvas: &Canvas, x: u32, y: u32) -> Color {
        Color::from_argb(canvas.pixels()[(y * canvas.width() + x) as usize])
    }

    fn blank(width: u32, height: u32, scale: f32) -> Canvas {
        let mut canvas = Canvas::new(width, height, scale);
        canvas.clear(Color::BLACK);
        canvas
    }

    #[test]
    fn a_new_canvas_is_opaque_everywhere() {
        let canvas = Canvas::new(4, 4, 1.0);
        assert!(canvas.pixels().iter().all(|word| word >> 24 == 0xff));
    }

    #[test]
    fn an_absurd_scale_is_clamped_rather_than_collapsing_the_layout() {
        assert_eq!(Canvas::new(4, 4, 0.0).scale(), 0.25);
        assert_eq!(Canvas::new(4, 4, f32::NAN).scale(), 1.0);
    }

    #[test]
    fn logical_bounds_account_for_the_scale() {
        let canvas = Canvas::new(200, 100, 2.0);
        assert_eq!(canvas.bounds(), Rect::new(0.0, 0.0, 100.0, 50.0));
    }

    #[test]
    fn a_filled_rectangle_covers_exactly_its_pixels() {
        let mut canvas = blank(10, 10, 1.0);
        canvas.fill_rect(Rect::new(2.0, 2.0, 3.0, 3.0), Color::WHITE);

        assert_eq!(pixel_at(&canvas, 2, 2), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 4, 4), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 5, 5), Color::BLACK, "right/bottom edge is exclusive");
        assert_eq!(pixel_at(&canvas, 1, 1), Color::BLACK);
    }

    #[test]
    fn a_cut_corner_removes_the_corner_and_keeps_the_edges() {
        // What separates a cut rectangle from a rounded one and from a plain
        // one: the corner pixel is gone, the pixel just inside the diagonal is
        // painted, and the middle of every edge is untouched by the cut.
        let mut canvas = blank(40, 40, 1.0);
        canvas.fill(Rect::new(0.0, 0.0, 40.0, 40.0), Corner::Cut(10.0), Color::WHITE);

        assert_eq!(pixel_at(&canvas, 0, 0), Color::BLACK, "the corner should be cut away");
        assert_eq!(pixel_at(&canvas, 2, 2), Color::BLACK, "still outside the diagonal");
        assert_eq!(pixel_at(&canvas, 8, 8), Color::WHITE, "inside the diagonal");
        assert_eq!(pixel_at(&canvas, 20, 0), Color::WHITE, "the top edge is not cut");
        assert_eq!(pixel_at(&canvas, 0, 20), Color::WHITE, "the left edge is not cut");
        assert_eq!(pixel_at(&canvas, 39, 39), Color::BLACK, "every corner is cut, not just one");
    }

    #[test]
    fn a_cut_corner_is_a_straight_diagonal_rather_than_an_arc() {
        // The whole difference between the two shapes. A rounded corner bulges
        // outward from the chord between its ends; a cut one *is* that chord, so
        // every pixel along it sits at the same coverage.
        let mut canvas = blank(60, 60, 1.0);
        canvas.fill(Rect::new(0.0, 0.0, 60.0, 60.0), Corner::Cut(20.0), Color::WHITE);

        // Points on the diagonal x + y = 20: all just inside, none filled solid.
        for (x, y) in [(4u32, 15u32), (10, 9), (15, 4)] {
            let on_edge = pixel_at(&canvas, x, y);
            assert!(
                on_edge.r > 40 && on_edge.r < 215,
                "({x}, {y}) should be a part-covered edge pixel, got {on_edge:?}"
            );
        }
    }

    #[test]
    fn a_cut_and_a_rounded_corner_of_the_same_size_differ_where_it_matters() {
        // A regression guard for the corner shape being silently ignored: an arc
        // covers more of its corner than the chord across it does, so the two
        // must disagree between the diagonal and the corner itself.
        let sample = |corner: Corner| {
            let mut canvas = blank(40, 40, 1.0);
            canvas.fill(Rect::new(0.0, 0.0, 40.0, 40.0), corner, Color::WHITE);
            pixel_at(&canvas, 4, 4).r
        };
        assert!(
            sample(Corner::Round(14.0)) > sample(Corner::Cut(14.0)),
            "an arc should cover more of its corner than a straight cut does"
        );
    }

    #[test]
    fn a_corner_larger_than_the_shape_is_clamped_rather_than_inverted() {
        // Asking for more than the shape can hold yields a diamond, not a
        // rectangle turned inside out by a negative straight section.
        let mut canvas = blank(20, 20, 1.0);
        canvas.fill(Rect::new(0.0, 0.0, 20.0, 20.0), Corner::Cut(999.0), Color::WHITE);

        assert_eq!(pixel_at(&canvas, 10, 10), Color::WHITE, "the centre is still filled");
        assert_eq!(pixel_at(&canvas, 1, 1), Color::BLACK, "the corners are gone entirely");
        // The diamond's points sit exactly at the middle of each edge, so the
        // pixel astride one is half covered and the pixel inside it is solid.
        assert_eq!(pixel_at(&canvas, 10, 2), Color::WHITE, "the points of the diamond survive");
    }

    #[test]
    fn growing_a_corner_keeps_the_shape_it_already_was() {
        // What a glow and a focus ring depend on: a cut panel must be haloed by
        // a cut shape, or the halo shows through its own corners.
        assert_eq!(Corner::Cut(4.0).grown(2.0), Corner::Cut(6.0));
        assert_eq!(Corner::Round(4.0).grown(2.0), Corner::Round(6.0));
        // A square corner has no size to grow: growing it would round a shape
        // that was deliberately not rounded.
        assert_eq!(Corner::Square.grown(2.0), Corner::Square);
        assert_eq!(Corner::Square.size(), 0.0);
    }

    #[test]
    fn logical_coordinates_are_multiplied_by_the_scale() {
        let mut canvas = blank(20, 20, 2.0);
        canvas.fill_rect(Rect::new(1.0, 1.0, 2.0, 2.0), Color::WHITE);

        // Logical (1,1)-(3,3) is device (2,2)-(6,6).
        assert_eq!(pixel_at(&canvas, 2, 2), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 5, 5), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 6, 6), Color::BLACK);
    }

    #[test]
    fn a_fractional_edge_is_antialiased_rather_than_snapped() {
        let mut canvas = blank(10, 10, 1.0);
        canvas.fill_rect(Rect::new(2.5, 0.0, 5.0, 10.0), Color::WHITE);

        let edge = pixel_at(&canvas, 2, 5);
        assert!(edge.r > 0 && edge.r < 255, "expected a partly covered pixel, got {edge:?}");
    }

    #[test]
    fn drawing_outside_the_surface_is_clipped_not_wrapped() {
        let mut canvas = blank(8, 8, 1.0);
        canvas.fill_rect(Rect::new(-100.0, -100.0, 1000.0, 1000.0), Color::WHITE);
        assert!(canvas.pixels().iter().all(|&word| Color::from_argb(word) == Color::WHITE));
    }

    #[test]
    fn a_clip_confines_drawing() {
        let mut canvas = blank(10, 10, 1.0);
        let previous = canvas.push_clip(Rect::new(0.0, 0.0, 5.0, 10.0));
        canvas.fill_rect(Rect::new(0.0, 0.0, 10.0, 10.0), Color::WHITE);
        canvas.pop_clip(previous);

        assert_eq!(pixel_at(&canvas, 4, 5), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 5, 5), Color::BLACK);
    }

    #[test]
    fn a_nested_clip_cannot_widen_its_parent() {
        let mut canvas = blank(10, 10, 1.0);
        let outer = canvas.push_clip(Rect::new(0.0, 0.0, 4.0, 10.0));
        let inner = canvas.push_clip(Rect::new(0.0, 0.0, 10.0, 10.0));
        canvas.fill_rect(Rect::new(0.0, 0.0, 10.0, 10.0), Color::WHITE);
        canvas.pop_clip(inner);
        canvas.pop_clip(outer);

        assert_eq!(pixel_at(&canvas, 3, 5), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 5, 5), Color::BLACK, "the inner clip widened the outer one");
    }

    #[test]
    fn popping_a_clip_restores_the_earlier_one() {
        let mut canvas = blank(10, 10, 1.0);
        let previous = canvas.push_clip(Rect::new(0.0, 0.0, 2.0, 2.0));
        canvas.pop_clip(previous);
        canvas.fill_rect(Rect::new(0.0, 0.0, 10.0, 10.0), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 9, 9), Color::WHITE);
    }

    #[test]
    fn visibility_follows_the_clip() {
        let mut canvas = blank(10, 10, 1.0);
        let previous = canvas.push_clip(Rect::new(0.0, 0.0, 5.0, 5.0));
        assert!(canvas.is_visible(Rect::new(4.0, 4.0, 2.0, 2.0)));
        assert!(!canvas.is_visible(Rect::new(6.0, 6.0, 2.0, 2.0)));
        canvas.pop_clip(previous);
    }

    #[test]
    fn a_rounded_corner_is_lighter_than_the_middle() {
        let mut canvas = blank(20, 20, 1.0);
        canvas.fill(Rect::new(0.0, 0.0, 20.0, 20.0), Corner::Round(8.0), Color::WHITE);

        assert_eq!(pixel_at(&canvas, 10, 10), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 0, 0), Color::BLACK, "the corner should be cut away");
    }

    #[test]
    fn a_large_rounded_rectangle_has_no_seam_where_the_fast_path_begins() {
        // The interior is written in bulk and the margins are evaluated pixel by
        // pixel. If those two disagree by even one step, a panel gets a visible
        // vertical line down each side.
        let mut canvas = blank(200, 120, 1.0);
        canvas.fill(Rect::new(10.0, 10.0, 180.0, 100.0), Corner::Round(12.0), Color::WHITE);

        for x in 24..176 {
            assert_eq!(
                pixel_at(&canvas, x, 60),
                Color::WHITE,
                "a seam appeared at x = {x} on the middle row"
            );
        }
        for y in 24..96 {
            assert_eq!(pixel_at(&canvas, 100, y), Color::WHITE, "a seam appeared at y = {y}");
        }
    }

    #[test]
    fn a_translucent_fill_covers_its_interior_evenly() {
        // The bulk path and the per-pixel path must blend identically, or the
        // middle of a translucent panel comes out a different shade from its
        // edges.
        let mut canvas = blank(120, 80, 1.0);
        let half = Color::rgba(255, 255, 255, 128);
        canvas.fill(Rect::new(5.0, 5.0, 110.0, 70.0), Corner::Round(10.0), half);

        let middle = pixel_at(&canvas, 60, 40);
        let near_edge = pixel_at(&canvas, 20, 40);
        assert_eq!(middle, near_edge, "the interior is not one even shade");
        assert!(middle.r > 100 && middle.r < 160, "expected about half, got {middle:?}");
    }

    #[test]
    fn a_stroke_on_a_tall_shape_marks_both_edges_and_nothing_between() {
        // Tall enough that the straight section is scanned by the banded path
        // rather than the whole-row one.
        let mut canvas = blank(60, 200, 1.0);
        canvas.stroke(Rect::new(10.0, 10.0, 40.0, 180.0), Corner::Round(8.0), 1.0, Color::WHITE);

        assert!(pixel_at(&canvas, 10, 100).r > 100, "the left edge should be drawn");
        assert!(pixel_at(&canvas, 49, 100).r > 100, "the right edge should be drawn");
        for x in 13..47 {
            assert_eq!(pixel_at(&canvas, x, 100), Color::BLACK, "x = {x} should be untouched");
        }
        assert!(pixel_at(&canvas, 30, 10).r > 100, "the top edge should be drawn");
        assert!(pixel_at(&canvas, 30, 189).r > 100, "the bottom edge should be drawn");
    }

    #[test]
    fn a_stroked_corner_joins_the_edges_that_meet_there() {
        let mut canvas = blank(80, 80, 1.0);
        canvas.stroke(Rect::new(10.0, 10.0, 60.0, 60.0), Corner::Round(20.0), 2.0, Color::WHITE);

        // On the arc of the top-left corner, at forty-five degrees.
        let offset = 20.0 - (20.0f32 / std::f32::consts::SQRT_2);
        let x = (10.0 + offset).round() as u32;
        let y = (10.0 + offset).round() as u32;
        assert!(pixel_at(&canvas, x, y).r > 80, "the corner arc should be drawn");
        assert_eq!(pixel_at(&canvas, 40, 40), Color::BLACK, "the middle stays empty");
    }

    #[test]
    fn an_oversized_radius_becomes_a_capsule_not_an_inverted_corner() {
        let mut canvas = blank(40, 20, 1.0);
        canvas.fill(Rect::new(0.0, 0.0, 40.0, 20.0), Corner::Round(999.0), Color::WHITE);

        assert_eq!(pixel_at(&canvas, 20, 10), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 20, 0), Color::WHITE, "the flat top should survive");
        assert_eq!(pixel_at(&canvas, 0, 0), Color::BLACK);
    }

    #[test]
    fn a_stroke_marks_the_edge_and_leaves_the_middle_alone() {
        let mut canvas = blank(20, 20, 1.0);
        canvas.stroke(Rect::new(2.0, 2.0, 16.0, 16.0), Corner::Square, 1.0, Color::WHITE);

        assert!(pixel_at(&canvas, 10, 2).r > 100, "the top edge should be drawn");
        assert_eq!(pixel_at(&canvas, 10, 10), Color::BLACK, "the middle should be untouched");
    }

    #[test]
    fn a_vertical_gradient_runs_from_its_top_colour_to_its_bottom_one() {
        let mut canvas = blank(20, 100, 1.0);
        canvas.fill_vertical(
            Rect::new(0.0, 0.0, 20.0, 100.0),
            Corner::Square,
            Color::BLACK,
            Color::WHITE,
        );

        let top = pixel_at(&canvas, 10, 0);
        let middle = pixel_at(&canvas, 10, 50);
        let bottom = pixel_at(&canvas, 10, 99);
        assert!(top.r < 8, "the top should be near the top colour, got {top:?}");
        assert!((120..=136).contains(&middle.r), "the middle should be halfway, got {middle:?}");
        assert!(bottom.r > 247, "the bottom should be near the bottom colour, got {bottom:?}");
    }

    #[test]
    fn a_gradient_row_is_one_even_colour_across_its_width() {
        // The interior is written in bulk and the margins pixel by pixel. If the
        // gradient were evaluated differently by the two, every panel would show
        // a vertical seam a few pixels in from each side.
        let mut canvas = blank(120, 60, 1.0);
        canvas.fill_vertical(
            Rect::new(0.0, 0.0, 120.0, 60.0),
            Corner::Square,
            Color::BLACK,
            Color::WHITE,
        );

        let expected = pixel_at(&canvas, 60, 30);
        for x in 0..120 {
            assert_eq!(pixel_at(&canvas, x, 30), expected, "the row is not even at x = {x}");
        }
    }

    #[test]
    fn a_gradient_between_two_equal_colours_is_a_flat_fill() {
        let mut canvas = blank(20, 40, 1.0);
        canvas.fill_vertical(
            Rect::new(0.0, 0.0, 20.0, 40.0),
            Corner::Square,
            Color::WHITE,
            Color::WHITE,
        );
        assert!(canvas.pixels().iter().all(|&word| Color::from_argb(word) == Color::WHITE));
    }

    #[test]
    fn a_glow_surrounds_a_shape_without_touching_its_inside() {
        let mut canvas = blank(80, 80, 1.0);
        canvas.shadow(Rect::new(30.0, 30.0, 20.0, 20.0), Corner::Round(4.0), 10.0, 0.0, Color::WHITE);

        assert_eq!(pixel_at(&canvas, 40, 40), Color::BLACK, "the inside must be left for the caster");
        assert!(pixel_at(&canvas, 40, 28).r > 0, "the halo should reach just outside the edge");
        assert_eq!(pixel_at(&canvas, 40, 5), Color::BLACK, "the halo should not reach past its blur");
    }

    #[test]
    fn a_glow_fades_with_distance_from_the_edge() {
        let mut canvas = blank(80, 80, 1.0);
        canvas.shadow(Rect::new(30.0, 30.0, 20.0, 20.0), Corner::Round(0.0), 12.0, 0.0, Color::WHITE);

        let near = pixel_at(&canvas, 40, 28).r;
        let far = pixel_at(&canvas, 40, 22).r;
        assert!(near > far, "expected the halo to fade outward, got {near} then {far}");
        assert!(far > 0, "the halo should still be present further out");
    }

    #[test]
    fn a_glow_with_spread_starts_further_out_than_one_without() {
        // Spread moves the band the halo occupies outward rather than widening
        // it, so what changes is where the halo *starts*, not how much of it
        // there is.
        let cast = Rect::new(30.0, 30.0, 20.0, 20.0);
        let topmost = |spread: f32| {
            let mut canvas = blank(80, 80, 1.0);
            canvas.shadow(cast, Corner::Round(0.0), 8.0, spread, Color::WHITE);
            (0..30).find(|&y| pixel_at(&canvas, 40, y).r > 0).expect("the halo should be drawn")
        };
        assert!(
            topmost(6.0) < topmost(0.0),
            "spread should push the halo further from the shape"
        );
    }

    #[test]
    fn an_invisible_colour_draws_nothing() {
        let mut canvas = blank(8, 8, 1.0);
        canvas.fill_rect(Rect::new(0.0, 0.0, 8.0, 8.0), Color::TRANSPARENT);
        assert_eq!(pixel_at(&canvas, 4, 4), Color::BLACK);
    }

    #[test]
    fn an_empty_rectangle_draws_nothing() {
        let mut canvas = blank(8, 8, 1.0);
        canvas.fill_rect(Rect::new(2.0, 2.0, 0.0, 5.0), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 2, 4), Color::BLACK);
    }

    #[test]
    fn a_mask_paints_its_coverage() {
        let mut canvas = blank(8, 8, 1.0);
        let mask = Mask { width: 2, height: 1, coverage: vec![255, 0] };
        canvas.fill_mask(3, 3, &mask, Color::WHITE);

        assert_eq!(pixel_at(&canvas, 3, 3), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 4, 3), Color::BLACK);
    }

    #[test]
    fn a_mask_hanging_off_the_edge_is_clipped_not_wrapped() {
        let mut canvas = blank(4, 4, 1.0);
        let mask = Mask { width: 4, height: 4, coverage: vec![255; 16] };
        canvas.fill_mask(-2, -2, &mask, Color::WHITE);

        assert_eq!(pixel_at(&canvas, 0, 0), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 2, 2), Color::BLACK);
        assert_eq!(pixel_at(&canvas, 3, 0), Color::BLACK, "the mask wrapped onto the next row");
    }

    // ----- a picture from somewhere else -------------------------------------

    /// One BGRA pixel, in the byte order a capture buffer holds it.
    fn bgra(color: Color) -> [u8; 4] {
        [color.b, color.g, color.r, 0xff]
    }

    /// A picture of `width` by `height` in one colour, with `padding` bytes of
    /// whatever a capture API left at the end of each row.
    fn picture(width: u32, height: u32, color: Color, padding: usize) -> (Vec<u8>, usize) {
        let stride = width as usize * 4 + padding;
        let mut bytes = Vec::with_capacity(stride * height as usize);
        for _ in 0..height {
            for _ in 0..width {
                bytes.extend_from_slice(&bgra(color));
            }
            // Deliberately not zero: padding that happened to be black would
            // let a blitter that copies it draw the right picture anyway.
            bytes.extend(std::iter::repeat_n(0x7f, padding));
        }
        (bytes, stride)
    }

    #[test]
    fn a_picture_lands_one_source_pixel_per_device_pixel() {
        let mut canvas = blank(8, 8, 1.0);
        let (bytes, stride) = picture(2, 2, Color::WHITE, 0);
        let source = Bgra::new(2, 2, stride, &bytes).expect("the buffer describes the picture");
        canvas.blit_bgra(Rect::new(3.0, 3.0, 2.0, 2.0), &source);

        assert_eq!(pixel_at(&canvas, 3, 3), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 4, 4), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 5, 3), Color::BLACK, "right edge is exclusive");
        assert_eq!(pixel_at(&canvas, 2, 3), Color::BLACK);
    }

    #[test]
    fn a_picture_is_clipped_by_the_canvas_edge_rather_than_wrapping() {
        // The failure this replaces is not a missing pixel: a blit that walked
        // past the end of a row writes the next row's beginning, so a picture
        // hanging off the right edge reappears down the left one.
        let mut canvas = blank(4, 4, 1.0);
        let (bytes, stride) = picture(4, 4, Color::WHITE, 0);
        let source = Bgra::new(4, 4, stride, &bytes).expect("the buffer describes the picture");
        canvas.blit_bgra(Rect::new(2.0, 2.0, 4.0, 4.0), &source);

        assert_eq!(pixel_at(&canvas, 2, 2), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 3, 3), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 0, 3), Color::BLACK, "the picture wrapped onto the next row");
        assert_eq!(pixel_at(&canvas, 1, 1), Color::BLACK, "nothing above or left of it");
    }

    #[test]
    fn a_picture_at_a_negative_origin_shows_its_far_corner() {
        // A viewport scrolled up and to the left: the first rows and columns are
        // off the surface, and what is on it must be the *rest* of the picture
        // rather than the whole of it moved into view.
        let mut canvas = blank(4, 4, 1.0);
        let mut bytes = Vec::new();
        for y in 0u32..4 {
            for x in 0u32..4 {
                // Each pixel says where it came from, in its blue channel.
                bytes.extend_from_slice(&[(y * 4 + x) as u8, 0, 0, 0xff]);
            }
        }
        let source = Bgra::packed(4, 4, &bytes).expect("the buffer describes the picture");
        canvas.blit_bgra(Rect::new(-2.0, -2.0, 4.0, 4.0), &source);

        assert_eq!(pixel_at(&canvas, 0, 0).b, 2 * 4 + 2, "the pixel at (2, 2) of the picture");
        assert_eq!(pixel_at(&canvas, 1, 0).b, 2 * 4 + 3);
        assert_eq!(pixel_at(&canvas, 0, 1).b, 3 * 4 + 2);
        assert_eq!(pixel_at(&canvas, 2, 2), Color::BLACK, "past the picture's own extent");
    }

    #[test]
    fn a_row_wider_than_the_picture_does_not_skew_it() {
        // What every real capture buffer looks like: Core Graphics pads each row
        // out to a multiple of sixteen or sixty-four bytes. A blitter that
        // assumed the rows were packed would shift each one further right than
        // the last, which is a picture that leans.
        let mut canvas = blank(8, 8, 1.0);
        let (bytes, stride) = picture(3, 3, Color::WHITE, 20);
        assert_eq!(stride, 32, "three pixels padded out to a multiple of sixteen");
        let source = Bgra::new(3, 3, stride, &bytes).expect("the buffer describes the picture");
        canvas.blit_bgra(Rect::new(0.0, 0.0, 3.0, 3.0), &source);

        for y in 0..3 {
            for x in 0..3 {
                assert_eq!(pixel_at(&canvas, x, y), Color::WHITE, "({x}, {y}) came out wrong");
            }
        }
        assert_eq!(pixel_at(&canvas, 3, 0), Color::BLACK, "the padding was drawn");
    }

    #[test]
    fn a_picture_is_cropped_by_its_destination() {
        // A remote screen larger than the pane showing it. The overflow must be
        // dropped rather than drawn over whatever is beside the pane.
        let mut canvas = blank(8, 8, 1.0);
        let (bytes, stride) = picture(6, 6, Color::WHITE, 0);
        let source = Bgra::new(6, 6, stride, &bytes).expect("the buffer describes the picture");
        canvas.blit_bgra(Rect::new(1.0, 1.0, 3.0, 3.0), &source);

        assert_eq!(pixel_at(&canvas, 3, 3), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 4, 3), Color::BLACK, "drawn outside its destination");
        assert_eq!(pixel_at(&canvas, 3, 4), Color::BLACK);
    }

    #[test]
    fn a_picture_obeys_the_clip_it_is_drawn_inside() {
        let mut canvas = blank(8, 8, 1.0);
        let previous = canvas.push_clip(Rect::new(0.0, 0.0, 4.0, 8.0));
        let (bytes, stride) = picture(8, 8, Color::WHITE, 0);
        let source = Bgra::new(8, 8, stride, &bytes).expect("the buffer describes the picture");
        canvas.blit_bgra(Rect::new(0.0, 0.0, 8.0, 8.0), &source);
        canvas.pop_clip(previous);

        assert_eq!(pixel_at(&canvas, 3, 4), Color::WHITE);
        assert_eq!(pixel_at(&canvas, 4, 4), Color::BLACK, "the clip was ignored");
    }

    #[test]
    fn a_picture_is_opaque_however_the_capture_left_its_alpha() {
        // macOS captures with `kCGImageAlphaNoneSkipFirst`: the byte is present
        // and means nothing. Trusting it would blend a remote desktop against
        // whatever this window was showing.
        let mut canvas = blank(4, 4, 1.0);
        let bytes = [0xff, 0xff, 0xff, 0x00];
        let source = Bgra::packed(1, 1, &bytes).expect("the buffer describes the picture");
        canvas.blit_bgra(Rect::new(0.0, 0.0, 1.0, 1.0), &source);
        assert_eq!(pixel_at(&canvas, 0, 0), Color::WHITE);
        assert_eq!(canvas.pixels()[0] >> 24, 0xff, "the surface stopped being opaque");
    }

    #[test]
    fn a_picture_the_buffer_cannot_hold_is_refused_at_the_door() {
        // A frame from a network is somebody else's arithmetic. The refusal is
        // what keeps the blit itself free of a length it has to re-check.
        let bytes = [0u8; 15];
        assert_eq!(Bgra::packed(2, 2, &bytes), None, "sixteen bytes are needed");
        assert_eq!(Bgra::new(4, 1, 8, &bytes), None, "a stride narrower than the row");
        assert!(Bgra::new(2, 2, 8, &[0u8; 16]).is_some());
        assert!(Bgra::packed(0, 0, &[]).is_some(), "an empty picture is describable");
    }

    #[test]
    fn a_picture_at_a_retina_scale_still_lands_pixel_for_pixel() {
        // Blitting is the one thing here that is not in logical units all the
        // way down: a captured pixel is a *device* pixel, or a remote screen
        // arrives at half its resolution on a Retina display.
        let mut canvas = blank(8, 8, 2.0);
        let (bytes, stride) = picture(4, 4, Color::WHITE, 0);
        let source = Bgra::new(4, 4, stride, &bytes).expect("the buffer describes the picture");
        canvas.blit_bgra(Rect::new(1.0, 1.0, 3.0, 3.0), &source);

        assert_eq!(pixel_at(&canvas, 2, 2), Color::WHITE, "logical (1, 1) is device (2, 2)");
        assert_eq!(pixel_at(&canvas, 5, 5), Color::WHITE, "four device pixels across");
        assert_eq!(pixel_at(&canvas, 1, 1), Color::BLACK);
    }

    // ----- rings, arcs, and lines --------------------------------------------

    /// The middle of every ring below, in logical units.
    const MIDDLE: Point = Point::new(20.0, 20.0);

    #[test]
    fn a_ring_marks_its_band_and_neither_side_of_it() {
        // What separates a ring from a filled circle: the hole is the point,
        // and it must survive the scan that writes the band.
        let mut canvas = blank(40, 40, 1.0);
        canvas.ring(MIDDLE, 12.0, 2.0, Color::WHITE);

        for (x, y) in [(20u32, 8u32), (20, 32), (8, 20), (32, 20)] {
            assert!(pixel_at(&canvas, x, y).r > 200, "the band is missing at ({x}, {y})");
        }
        assert_eq!(pixel_at(&canvas, 20, 20), Color::BLACK, "the middle is not filled");
        assert_eq!(pixel_at(&canvas, 20, 1), Color::BLACK, "and nothing is drawn outside it");
    }

    #[test]
    fn a_bands_edge_is_antialiased_rather_than_stepped() {
        // The whole reason this is a distance field and not a plotted circle: a
        // band an odd fraction of a pixel wide has part-covered pixels at its
        // edges, at every angle.
        let mut canvas = blank(40, 40, 1.0);
        canvas.ring(MIDDLE, 11.7, 1.4, Color::WHITE);

        let column: Vec<u8> = (0..20).map(|y| pixel_at(&canvas, 20, y).r).collect();
        assert!(
            column.iter().any(|&value| value > 0 && value < 255),
            "expected a part-covered pixel down the band's edge, got {column:?}"
        );
    }

    #[test]
    fn an_arc_marks_only_what_it_sweeps() {
        // Clockwise from the direction of the positive x axis, because y grows
        // downward: a quarter turn from there is the bottom, never the top.
        let mut canvas = blank(40, 40, 1.0);
        canvas.arc(MIDDLE, 12.0, 2.0, 0.0, std::f32::consts::FRAC_PI_2, Color::WHITE);

        assert!(pixel_at(&canvas, 32, 20).r > 200, "the sweep starts at the right");
        assert!(pixel_at(&canvas, 20, 32).r > 200, "and ends at the bottom");
        assert_eq!(pixel_at(&canvas, 20, 8), Color::BLACK, "the top is outside it");
        assert_eq!(pixel_at(&canvas, 8, 20), Color::BLACK, "and so is the left");
    }

    #[test]
    fn a_ring_is_an_arc_that_goes_all_the_way_round() {
        let mut ring = blank(40, 40, 1.0);
        ring.ring(MIDDLE, 12.0, 2.0, Color::WHITE);
        let mut swept = blank(40, 40, 1.0);
        swept.arc(MIDDLE, 12.0, 2.0, 0.0, std::f32::consts::TAU, Color::WHITE);

        assert_eq!(ring.pixels(), swept.pixels());
        // And it has no seam where the sweep would have begun and ended, which
        // is why a closed ring is not capped at all.
        assert!(pixel_at(&ring, 32, 20).r > 200, "a crack opened where the sweep closes");
    }

    #[test]
    fn a_sweep_run_backwards_covers_what_the_same_one_forwards_does() {
        let quarter = std::f32::consts::FRAC_PI_2;
        let mut forwards = blank(40, 40, 1.0);
        forwards.arc(MIDDLE, 12.0, 2.0, 0.0, quarter, Color::WHITE);
        let mut backwards = blank(40, 40, 1.0);
        backwards.arc(MIDDLE, 12.0, 2.0, quarter, -quarter, Color::WHITE);

        assert_eq!(forwards.pixels(), backwards.pixels());
    }

    #[test]
    fn a_bands_halo_surrounds_it_on_both_sides_without_covering_it() {
        // A lit line lights what is inside the ring as well as what is outside
        // it, and leaves the band itself for whatever casts the halo.
        let mut canvas = blank(40, 40, 1.0);
        canvas.arc_glow(MIDDLE, 12.0, 2.0, 0.0, std::f32::consts::TAU, 5.0, Color::WHITE);

        assert_eq!(pixel_at(&canvas, 20, 8), Color::BLACK, "the band is left for its caster");
        assert!(pixel_at(&canvas, 20, 6).r > 0, "the halo should reach outward");
        assert!(pixel_at(&canvas, 20, 12).r > 0, "and inward");
        assert_eq!(pixel_at(&canvas, 20, 0), Color::BLACK, "and no further than its blur");
    }

    #[test]
    fn a_halo_fades_with_distance_from_the_band() {
        let mut canvas = blank(40, 40, 1.0);
        canvas.arc_glow(MIDDLE, 12.0, 2.0, 0.0, std::f32::consts::TAU, 6.0, Color::WHITE);

        let near = pixel_at(&canvas, 20, 6).r;
        let far = pixel_at(&canvas, 20, 3).r;
        assert!(near > far, "expected the halo to fade outward, got {near} then {far}");
        assert!(far > 0, "the halo should still be there further out");
    }

    #[test]
    fn ticks_are_spaced_evenly_round_the_whole_circle() {
        // Four of them from the direction of the positive x axis: right, then
        // bottom, then left, then top — the order the sweep runs in.
        let mut canvas = blank(40, 40, 1.0);
        canvas.ticks(MIDDLE, 10.0, 14.0, 2.0, 4, 0.0, Color::WHITE);

        for (x, y) in [(32u32, 20u32), (20, 32), (8, 20), (20, 8)] {
            assert!(pixel_at(&canvas, x, y).r > 200, "no tick at ({x}, {y})");
        }
        assert_eq!(pixel_at(&canvas, 28, 28), Color::BLACK, "a tick appeared between two");
        assert_eq!(pixel_at(&canvas, 20, 20), Color::BLACK, "the ticks reached the centre");
    }

    #[test]
    fn a_tick_ring_of_none_draws_nothing() {
        let mut canvas = blank(40, 40, 1.0);
        canvas.ticks(MIDDLE, 10.0, 14.0, 2.0, 0, 0.0, Color::WHITE);
        assert!(canvas.pixels().iter().all(|&word| Color::from_argb(word) == Color::BLACK));
    }

    #[test]
    fn a_line_marks_the_run_between_its_ends_and_stops_there() {
        let mut canvas = blank(20, 10, 1.0);
        canvas.line(Point::new(2.0, 5.0), Point::new(18.0, 5.0), 2.0, Color::WHITE);

        assert!(pixel_at(&canvas, 10, 5).r > 200, "the middle of the line");
        assert!(pixel_at(&canvas, 10, 4).r > 200, "which is two pixels thick");
        assert_eq!(pixel_at(&canvas, 10, 2), Color::BLACK, "and no thicker");
        assert_eq!(pixel_at(&canvas, 0, 5), Color::BLACK, "nothing before it begins");
        assert_eq!(pixel_at(&canvas, 19, 5), Color::BLACK, "nor after it ends");
    }

    #[test]
    fn a_diagonal_line_is_antialiased_along_its_whole_length() {
        // A line at an angle is the case a plotted one gets wrong: every pixel
        // along it sits a different fraction of the way across the edge.
        let mut canvas = blank(24, 24, 1.0);
        canvas.line(Point::new(2.0, 2.0), Point::new(22.0, 20.0), 1.5, Color::WHITE);

        let marked = (0..24)
            .flat_map(|y| (0..24).map(move |x| (x, y)))
            .filter(|&(x, y)| pixel_at(&canvas, x, y).r > 0)
            .count();
        assert!(marked > 20, "the line should have been drawn at all");
        let partial = (0..24)
            .flat_map(|y| (0..24).map(move |x| (x, y)))
            .filter(|&(x, y)| {
                let value = pixel_at(&canvas, x, y).r;
                value > 0 && value < 255
            })
            .count();
        assert!(partial > 10, "a diagonal drawn without antialiasing is a staircase");
    }

    #[test]
    fn a_line_from_a_point_to_itself_is_a_dot_rather_than_nothing() {
        // The degenerate case the projection has to survive: a segment with no
        // length has no direction, and dividing by that length would draw a
        // window full of nothing.
        let mut canvas = blank(20, 20, 1.0);
        canvas.line(Point::new(10.0, 10.0), Point::new(10.0, 10.0), 4.0, Color::WHITE);

        assert!(pixel_at(&canvas, 10, 10).r > 200, "the dot should be drawn");
        assert_eq!(pixel_at(&canvas, 16, 10), Color::BLACK);
    }

    #[test]
    fn a_polyline_draws_every_pair_in_turn() {
        let mut canvas = blank(20, 20, 1.0);
        let bracket =
            [Point::new(2.0, 8.0), Point::new(2.0, 2.0), Point::new(8.0, 2.0)];
        canvas.polyline(&bracket, 2.0, Color::WHITE);

        assert!(pixel_at(&canvas, 2, 6).r > 100, "the arm running down");
        assert!(pixel_at(&canvas, 6, 2).r > 100, "the arm running across");
        assert!(pixel_at(&canvas, 2, 2).r > 100, "and the corner they meet at");
        assert_eq!(pixel_at(&canvas, 10, 10), Color::BLACK, "and nothing between the ends");
    }

    #[test]
    fn a_ring_and_a_line_are_scaled_like_everything_else() {
        // Logical units in, device pixels out, for the round shapes as much as
        // for the rectangular ones.
        let mut canvas = blank(40, 40, 2.0);
        canvas.ring(Point::new(10.0, 10.0), 6.0, 1.0, Color::WHITE);
        canvas.line(Point::new(1.0, 0.0), Point::new(1.0, 20.0), 1.0, Color::WHITE);

        assert!(pixel_at(&canvas, 20, 8).r > 200, "logical 10 across and 4 up is device 20, 8");
        assert_eq!(pixel_at(&canvas, 20, 20), Color::BLACK, "the hole is scaled too");
        assert!(pixel_at(&canvas, 1, 20).r > 200, "a one-unit line is two pixels wide");
        assert!(pixel_at(&canvas, 2, 20).r > 200);
        assert_eq!(pixel_at(&canvas, 3, 20), Color::BLACK);
    }

    #[test]
    fn a_clip_confines_a_ring_and_a_line_as_it_does_a_rectangle() {
        let mut canvas = blank(40, 40, 1.0);
        let previous = canvas.push_clip(Rect::new(0.0, 0.0, 20.0, 40.0));
        canvas.ring(MIDDLE, 12.0, 2.0, Color::WHITE);
        canvas.line(Point::new(0.0, 4.0), Point::new(40.0, 4.0), 2.0, Color::WHITE);
        canvas.pop_clip(previous);

        assert!(pixel_at(&canvas, 8, 20).r > 200, "inside the clip");
        assert_eq!(pixel_at(&canvas, 32, 20), Color::BLACK, "the band escaped its clip");
        assert!(pixel_at(&canvas, 10, 4).r > 200);
        assert_eq!(pixel_at(&canvas, 30, 4), Color::BLACK, "the line escaped its clip");
    }

    #[test]
    fn an_invisible_or_impossible_band_draws_nothing() {
        let mut canvas = blank(40, 40, 1.0);
        canvas.ring(MIDDLE, 12.0, 2.0, Color::TRANSPARENT);
        canvas.ring(MIDDLE, 0.0, 2.0, Color::WHITE);
        canvas.ring(MIDDLE, 12.0, 0.0, Color::WHITE);
        canvas.ring(MIDDLE, -12.0, 2.0, Color::WHITE);
        canvas.ring(MIDDLE, 12.0, -2.0, Color::WHITE);
        canvas.arc(MIDDLE, 12.0, 2.0, 0.0, 0.0, Color::WHITE);
        canvas.line(Point::new(0.0, 0.0), Point::new(40.0, 40.0), 0.0, Color::WHITE);
        canvas.line(Point::new(0.0, 0.0), Point::new(40.0, 40.0), -1.0, Color::WHITE);
        assert!(canvas.pixels().iter().all(|&word| Color::from_argb(word) == Color::BLACK));
    }

    #[test]
    fn a_polyline_needs_two_points_before_it_draws() {
        let mut canvas = blank(20, 20, 1.0);
        canvas.polyline(&[], 2.0, Color::WHITE);
        canvas.polyline(&[Point::new(10.0, 10.0)], 2.0, Color::WHITE);
        assert!(canvas.pixels().iter().all(|&word| Color::from_argb(word) == Color::BLACK));
    }

    #[test]
    fn a_band_is_drawn_in_the_colour_it_was_given() {
        // A glow that is not a black: what a shadow deliberately never is, and
        // what a live instrument is made of.
        let mut canvas = blank(40, 40, 1.0);
        let cyan = Color::rgb(0x5f, 0xd9, 0xf2);
        canvas.arc_glow(MIDDLE, 12.0, 2.0, 0.0, std::f32::consts::TAU, 5.0, cyan);

        let halo = pixel_at(&canvas, 20, 6);
        assert!(halo.b > halo.r, "the halo lost the hue it was cast in: {halo:?}");
    }

    // ----- neon-HUD primitives: shaded fills and glowing beams ---------------

    #[test]
    fn a_horizontal_gradient_runs_from_its_left_colour_to_its_right_one() {
        let mut canvas = blank(100, 20, 1.0);
        canvas.fill_horizontal(
            Rect::new(0.0, 0.0, 100.0, 20.0),
            Corner::Square,
            Color::BLACK,
            Color::WHITE,
        );

        let left = pixel_at(&canvas, 0, 10);
        let middle = pixel_at(&canvas, 50, 10);
        let right = pixel_at(&canvas, 99, 10);
        assert!(left.r < 8, "the left should be near the left colour, got {left:?}");
        assert!((120..=136).contains(&middle.r), "the middle should be halfway, got {middle:?}");
        assert!(right.r > 247, "the right should be near the right colour, got {right:?}");
    }

    #[test]
    fn a_horizontal_gradient_column_is_one_even_colour_down_its_height() {
        // The vertical mirror of the vertical gradient's row test: a horizontal
        // gradient varies across a row but must be constant down a column, or a
        // bar shows a horizontal seam where the interior meets its margins.
        let mut canvas = blank(60, 40, 1.0);
        canvas.fill_horizontal(
            Rect::new(0.0, 0.0, 60.0, 40.0),
            Corner::Square,
            Color::BLACK,
            Color::WHITE,
        );
        let expected = pixel_at(&canvas, 30, 20);
        for y in 0..40 {
            assert_eq!(pixel_at(&canvas, 30, y), expected, "the column is not even at y = {y}");
        }
    }

    #[test]
    fn a_gradient_between_two_equal_colours_fills_flat() {
        let mut canvas = blank(30, 30, 1.0);
        canvas.fill_gradient(
            Rect::new(0.0, 0.0, 30.0, 30.0),
            Corner::Square,
            Point::new(0.0, 0.0),
            Point::new(30.0, 30.0),
            Color::WHITE,
            Color::WHITE,
        );
        assert!(canvas.pixels().iter().all(|&word| Color::from_argb(word) == Color::WHITE));
    }

    #[test]
    fn a_gradient_is_solid_beyond_either_end_of_its_axis() {
        // Everything behind `a` is `c0` and everything past `b` is `c1`: the
        // projection is clamped, so a short axis inside a wide rectangle does not
        // extrapolate past white.
        let mut canvas = blank(60, 10, 1.0);
        canvas.fill_gradient(
            Rect::new(0.0, 0.0, 60.0, 10.0),
            Corner::Square,
            Point::new(20.0, 5.0),
            Point::new(40.0, 5.0),
            Color::BLACK,
            Color::WHITE,
        );
        assert_eq!(pixel_at(&canvas, 5, 5), Color::BLACK, "behind the axis stays c0");
        assert_eq!(pixel_at(&canvas, 55, 5), Color::WHITE, "past the axis stays c1");
    }

    #[test]
    fn a_radial_fill_is_brightest_at_its_centre() {
        let mut canvas = blank(40, 40, 1.0);
        canvas.fill_radial(Point::new(20.0, 20.0), 15.0, Color::WHITE, Color::BLACK);

        let center = pixel_at(&canvas, 20, 20).r;
        let mid = pixel_at(&canvas, 20, 12).r;
        let edge = pixel_at(&canvas, 20, 7).r;
        assert!(center > 235, "the centre is near the inner colour, got {center}");
        assert!(center > mid && mid > edge, "expected a falloff, got {center}, {mid}, {edge}");
        assert_eq!(pixel_at(&canvas, 20, 2), Color::BLACK, "and nothing beyond the radius");
    }

    #[test]
    fn a_radial_aura_fades_to_nothing_at_its_rim() {
        // An outer colour with zero alpha leaves the background showing at the
        // rim rather than drawing a hard disc edge.
        let mut canvas = blank(40, 40, 1.0);
        canvas.fill_radial(Point::new(20.0, 20.0), 15.0, Color::WHITE, Color::WHITE.with_alpha(0));

        assert!(pixel_at(&canvas, 20, 20).r > 235, "near-solid at the centre");
        let rim = pixel_at(&canvas, 20, 8).r;
        assert!(rim > 0 && rim < 255, "the aura is part-lit near its rim, got {rim}");
    }

    #[test]
    fn crossing_beams_are_brighter_where_they_meet() {
        // The whole point of an additive beam: two conduits that cross sum toward
        // white at the crossing rather than one hiding the other.
        let dim = Color::rgb(120, 0, 0);

        let mut one = blank(40, 40, 1.0);
        one.beam(Point::new(0.0, 20.0), Point::new(40.0, 20.0), 3.0, 0.0, dim);
        let single = pixel_at(&one, 20, 20).r;

        let mut both = blank(40, 40, 1.0);
        both.beam(Point::new(0.0, 20.0), Point::new(40.0, 20.0), 3.0, 0.0, dim);
        both.beam(Point::new(20.0, 0.0), Point::new(20.0, 40.0), 3.0, 0.0, dim);
        let crossing = pixel_at(&both, 20, 20).r;

        assert_eq!(single, 120, "one beam lays its own light down");
        assert_eq!(crossing, 240, "two add toward white where they cross");
        assert!(crossing > single);
    }

    #[test]
    fn a_beams_halo_reaches_beyond_its_core_and_stops_at_the_blur() {
        let mut canvas = blank(40, 40, 1.0);
        canvas.beam(Point::new(0.0, 20.0), Point::new(40.0, 20.0), 2.0, 6.0, Color::WHITE);

        let core = pixel_at(&canvas, 20, 20).r;
        let near = pixel_at(&canvas, 20, 23).r;
        let far = pixel_at(&canvas, 20, 25).r;
        assert_eq!(core, 255, "the core is fully lit");
        assert!(near > 0 && near < 255, "the halo is present but dimmer, got {near}");
        assert!(near > far, "and fades outward, got {near} then {far}");
        assert_eq!(pixel_at(&canvas, 20, 30), Color::BLACK, "and stops at the blur");
    }

    #[test]
    fn resizing_keeps_the_canvas_consistent() {
        let mut canvas = blank(4, 4, 1.0);
        canvas.resize(10, 6, 2.0);
        assert_eq!(canvas.width(), 10);
        assert_eq!(canvas.pixels().len(), 60);
        assert_eq!(canvas.scale(), 2.0);
        assert_eq!(canvas.clip(), Rect::new(0.0, 0.0, 5.0, 3.0));
    }
}
