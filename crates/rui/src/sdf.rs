//! A composable signed-distance-field shape algebra, and the fields that paint
//! it.
//!
//! # A shape is a distance, not a box
//!
//! Everywhere else a toolkit grows by adding primitives and box-property flags:
//! a rectangle gains a `border`, then a `border_radius`, then a `box_shadow`,
//! and every effect is a toggle bolted onto the same box. That model sprawls and
//! never lets a shape be *hand-shaped*.
//!
//! This module takes the other road. A [`Shape`] is a function giving the signed
//! distance from a point to its surface — negative inside, zero on the edge,
//! positive outside — and from that one field the renderer derives everything:
//! a crisp antialiased [`Sculpt::Fill`] (coverage across the zero crossing), an
//! [`Sculpt::Stroke`] (`|d| - w/2`), a [`Sculpt::Glow`] (a falloff of `d` added
//! to the buffer), rounding (`d - r`), and even bevel edge-light (from the field
//! *gradient* against a light direction; see [`Paint::Bevel`]).
//!
//! Beautiful shapes are **composed**, never assembled from flags. A glowing
//! notched HUD frame is an expression — a rounded rectangle, outlined, with a
//! corner conduit subtracted and a status hub unioned on — not a box with a
//! catalogue of properties:
//!
//! ```ignore
//! use rui::sdf::{rounded_rect, capsule, ring, solid, Sculpt};
//! use rui::{Point, Rect};
//!
//! let frame = rounded_rect(bounds, 8.0).outline(2.0)
//!     - capsule(a, b, 6.0)                 // subtract a corner conduit slot
//!     | ring(hub, 10.0, 2.0);              // union a status hub
//! canvas.sculpt(&frame, &solid(accent), Sculpt::Glow { radius: 12.0, intensity: 0.8 });
//! ```
//!
//! The operators are a tiny orthogonal set — union is `min`, intersection is
//! `max`, subtraction is `max(a, -b)`, smooth-union is a soft `min` — reachable
//! both as builder methods ([`Shape::union`]) and as operators (`a | b`, `a & b`,
//! `a - b`).
//!
//! # Logical units, one antialiasing rule
//!
//! Every point, distance, and bound here is in *logical* units — the units a
//! layout is written in; see [`crate::geom`]. Only [`Canvas::sculpt`] multiplies
//! by the display scale to reach device pixels, exactly as the built-in shapes
//! do, so the one antialiasing rule the whole toolkit shares —
//! `coverage = clamp(0.5 - d_device, 0, 1)` — holds here too.
//!
//! # Field validity caveat
//!
//! The makers ([`circle`], [`rect`], [`capsule`], [`arc`], [`ngon`],
//! [`polygon`]) give *exact* Euclidean distance fields. The combining operators
//! (`min`/`max`/`smin`/subtract) give a **bounded** field rather than an exact
//! metric everywhere — but the zero-set is correct and the gradient is very near
//! unit length close to the surface, which is all the coverage rule and the
//! bevel gradient need. Rounding, offset, outline, translate, rotate, and
//! uniform scale all preserve exactness.
//!
//! [`Canvas::sculpt`]: crate::canvas::Canvas::sculpt

use crate::color::Color;
use crate::geom::{Point, Rect, Size};
use std::f32::consts::{PI, TAU};

/// The distance below which a length is treated as zero rather than divided by.
const EPS: f32 = 1e-6;

/// A composable signed-distance shape, in logical units.
///
/// An owned enum tree rather than a generic combinator trait: composition must
/// return one uniform type so that `a | b - c` type-checks, layers can be stored
/// heterogeneously, and [`Clone`] is trivial. Each operator arm boxes its
/// children, so composing is one allocation per node and evaluating is a
/// recursive `match` per pixel — nothing for the HUD-sized trees this draws.
///
/// Build leaves with the makers ([`circle`], [`rect`], [`rounded_rect`],
/// [`capsule`], [`ring`], [`arc`], [`ngon`], [`polygon`]) and combine them with
/// the builder methods or the `|`, `&`, and `-` operators.
#[derive(Debug, Clone)]
pub enum Shape {
    /// A disc of `radius` about `center`.
    Circle {
        /// The centre.
        center: Point,
        /// The radius.
        radius: f32,
    },
    /// An axis-aligned rectangle given by its centre and half-extents.
    Rect {
        /// The centre.
        center: Point,
        /// Half the width and half the height.
        half: Size,
    },
    /// A line from `a` to `b` with round ends, `half` the thickness either side.
    Capsule {
        /// One end of the core segment.
        a: Point,
        /// The other end.
        b: Point,
        /// Half the line thickness.
        half: f32,
    },
    /// A band of an arc centred on `radius`, running `sweep` from `start`.
    Arc {
        /// The centre of the circle the band lies on.
        center: Point,
        /// The radius to the middle of the band.
        radius: f32,
        /// Half the band width.
        half: f32,
        /// Where the sweep begins, in radians.
        start: f32,
        /// How far it runs, in radians; a whole turn or more is a closed ring.
        sweep: f32,
    },
    /// A regular polygon: `sides` vertices at `circumradius`, turned `rotation`.
    Ngon {
        /// The centre.
        center: Point,
        /// The distance from the centre to each vertex.
        circumradius: f32,
        /// How many sides.
        sides: u32,
        /// How far the polygon is turned, in radians.
        rotation: f32,
    },
    /// A polygon through `points` in order; exact for any simple polygon.
    Polygon {
        /// The vertices, in order.
        points: Vec<Point>,
    },
    /// `of` with its field shifted out by `delta` — rounding and offset alike.
    Offset {
        /// The shape being offset.
        of: Box<Shape>,
        /// How far the surface moves outward.
        delta: f32,
    },
    /// The outline of `of`: `|d| - width/2`.
    Outline {
        /// The shape being outlined.
        of: Box<Shape>,
        /// The full width of the outline.
        width: f32,
    },
    /// `of` moved by `(dx, dy)`.
    Translate {
        /// The shape being moved.
        of: Box<Shape>,
        /// The horizontal offset.
        dx: f32,
        /// The vertical offset.
        dy: f32,
    },
    /// `of` turned `radians` about `center` (rigid; distance preserved).
    Rotate {
        /// The shape being turned.
        of: Box<Shape>,
        /// The pivot.
        center: Point,
        /// The angle, in radians.
        radians: f32,
    },
    /// `of` scaled uniformly by `factor` about `center`.
    Scale {
        /// The shape being scaled.
        of: Box<Shape>,
        /// The fixed point of the scaling.
        center: Point,
        /// The uniform factor.
        factor: f32,
    },
    /// The union of two shapes: `min` of their fields.
    Union(Box<Shape>, Box<Shape>),
    /// The intersection of two shapes: `max` of their fields.
    Intersect(Box<Shape>, Box<Shape>),
    /// The first shape with the second cut out of it: `max(a, -b)`.
    Subtract(Box<Shape>, Box<Shape>),
    /// A union whose join is rounded by a blend radius `k` (polynomial `smin`).
    SmoothUnion {
        /// The first shape.
        a: Box<Shape>,
        /// The second shape.
        b: Box<Shape>,
        /// The blend radius; `k -> 0` recovers a hard [`Shape::Union`].
        k: f32,
    },
}

// ---------------------------------------------------------------------------
// makers
// ---------------------------------------------------------------------------

/// A disc of `radius` about `center`.
pub fn circle(center: Point, radius: f32) -> Shape {
    Shape::Circle { center, radius }
}

/// The axis-aligned rectangle `bounds`, square-cornered.
pub fn rect(bounds: Rect) -> Shape {
    Shape::Rect { center: bounds.center(), half: Size::new(bounds.w / 2.0, bounds.h / 2.0) }
}

/// `bounds` with all four corners rounded to `radius`, staying within `bounds`.
///
/// Built as a box shrunk by `radius` then offset back out by it, so the rounded
/// shape never grows past the rectangle it was asked for — matching how
/// [`Canvas::fill`](crate::canvas::Canvas::fill) clamps a corner to the shape.
pub fn rounded_rect(bounds: Rect, radius: f32) -> Shape {
    let radius = radius.max(0.0);
    let half = Size::new((bounds.w / 2.0 - radius).max(0.0), (bounds.h / 2.0 - radius).max(0.0));
    Shape::Rect { center: bounds.center(), half }.offset(radius)
}

/// A line from `a` to `b`, `thickness` wide, with round ends.
pub fn capsule(a: Point, b: Point, thickness: f32) -> Shape {
    Shape::Capsule { a, b, half: thickness / 2.0 }
}

/// A full ring: a band of width `thickness` centred on `radius`.
pub fn ring(center: Point, radius: f32, thickness: f32) -> Shape {
    Shape::Arc { center, radius, half: thickness / 2.0, start: 0.0, sweep: TAU }
}

/// Part of a ring, from `start` running `sweep` radians (clockwise; round ends).
pub fn arc(center: Point, radius: f32, thickness: f32, start: f32, sweep: f32) -> Shape {
    Shape::Arc { center, radius, half: thickness / 2.0, start, sweep }
}

/// A regular polygon of `sides` sides, `circumradius` to each vertex, turned
/// `rotation` radians.
pub fn ngon(center: Point, sides: u32, circumradius: f32, rotation: f32) -> Shape {
    Shape::Ngon { center, circumradius, sides, rotation }
}

/// A polygon through `points` in order.
pub fn polygon(points: Vec<Point>) -> Shape {
    Shape::Polygon { points }
}

// ---------------------------------------------------------------------------
// evaluation
// ---------------------------------------------------------------------------

impl Shape {
    /// The signed distance from `p` to the surface: negative inside, zero on the
    /// edge, positive outside. Logical units. Costs one recursive `match` per
    /// node in the tree.
    pub fn sd(&self, p: Point) -> f32 {
        match self {
            Shape::Circle { center, radius } => length(sub(p, *center)) - radius,
            Shape::Rect { center, half } => rect_sd(p, *center, *half),
            Shape::Capsule { a, b, half } => capsule_sd(p, *a, *b, *half),
            Shape::Arc { center, radius, half, start, sweep } => {
                arc_sd(p, *center, *radius, *half, *start, *sweep)
            }
            Shape::Ngon { center, circumradius, sides, rotation } => {
                ngon_sd(p, *center, *circumradius, *sides, *rotation)
            }
            Shape::Polygon { points } => polygon_sd(p, points),
            Shape::Offset { of, delta } => of.sd(p) - delta,
            Shape::Outline { of, width } => of.sd(p).abs() - width * 0.5,
            Shape::Translate { of, dx, dy } => of.sd(Point::new(p.x - dx, p.y - dy)),
            Shape::Rotate { of, center, radians } => {
                let r = rotate(sub(p, *center), -radians);
                of.sd(Point::new(center.x + r.0, center.y + r.1))
            }
            Shape::Scale { of, center, factor } => {
                let f = if factor.abs() < EPS { EPS } else { *factor };
                let local = Point::new(center.x + (p.x - center.x) / f, center.y + (p.y - center.y) / f);
                of.sd(local) * f
            }
            Shape::Union(a, b) => a.sd(p).min(b.sd(p)),
            Shape::Intersect(a, b) => a.sd(p).max(b.sd(p)),
            Shape::Subtract(a, b) => a.sd(p).max(-b.sd(p)),
            Shape::SmoothUnion { a, b, k } => {
                let (da, db) = (a.sd(p), b.sd(p));
                if *k <= 0.0 {
                    return da.min(db);
                }
                let h = (0.5 + 0.5 * (db - da) / k).clamp(0.0, 1.0);
                (db + (da - db) * h) - k * h * (1.0 - h)
            }
        }
    }

    /// An axis-aligned box that contains the shape's zero-set, logical units.
    ///
    /// Conservative — an operator's box may be loose — but never tighter than
    /// the shape, so the renderer can bound its scan by it and then clamp to the
    /// clip.
    pub fn bbox(&self) -> Rect {
        match self {
            Shape::Circle { center, radius } => square(*center, *radius),
            Shape::Rect { center, half } => {
                Rect::new(center.x - half.w, center.y - half.h, 2.0 * half.w, 2.0 * half.h)
            }
            Shape::Capsule { a, b, half } => {
                Rect::from_corners(*a, *b).expand(crate::geom::Insets::uniform(*half))
            }
            Shape::Arc { center, radius, half, .. } => square(*center, radius + half),
            Shape::Ngon { center, circumradius, .. } => square(*center, *circumradius),
            Shape::Polygon { points } => aabb(points.iter().map(|p| (p.x, p.y))),
            Shape::Offset { of, delta } => {
                of.bbox().expand(crate::geom::Insets::uniform(delta.max(0.0)))
            }
            Shape::Outline { of, width } => {
                of.bbox().expand(crate::geom::Insets::uniform(width * 0.5))
            }
            Shape::Translate { of, dx, dy } => of.bbox().translate(*dx, *dy),
            Shape::Rotate { of, center, radians } => {
                let b = of.bbox();
                aabb(corners(b).into_iter().map(|c| {
                    let r = rotate((c.0 - center.x, c.1 - center.y), *radians);
                    (center.x + r.0, center.y + r.1)
                }))
            }
            Shape::Scale { of, center, factor } => {
                let b = of.bbox();
                aabb(corners(b).into_iter().map(|c| {
                    (center.x + (c.0 - center.x) * factor, center.y + (c.1 - center.y) * factor)
                }))
            }
            Shape::Union(a, b) => a.bbox().union(b.bbox()),
            Shape::Intersect(a, b) => a.bbox().intersect(b.bbox()),
            Shape::Subtract(a, _) => a.bbox(),
            Shape::SmoothUnion { a, b, k } => {
                a.bbox().union(b.bbox()).expand(crate::geom::Insets::uniform(k.max(0.0)))
            }
        }
    }

    /// The union with `other`: `min` of the two fields.
    pub fn union(self, other: Shape) -> Shape {
        Shape::Union(Box::new(self), Box::new(other))
    }

    /// The intersection with `other`: `max` of the two fields.
    pub fn intersect(self, other: Shape) -> Shape {
        Shape::Intersect(Box::new(self), Box::new(other))
    }

    /// This shape with `other` cut out of it: `max(a, -b)`.
    pub fn subtract(self, other: Shape) -> Shape {
        Shape::Subtract(Box::new(self), Box::new(other))
    }

    /// A union with `other` whose join is blended over a radius `k`.
    pub fn smooth_union(self, other: Shape, k: f32) -> Shape {
        Shape::SmoothUnion { a: Box::new(self), b: Box::new(other), k }
    }

    /// This shape's field shifted outward by `delta` (its surface grows).
    pub fn offset(self, delta: f32) -> Shape {
        Shape::Offset { of: Box::new(self), delta }
    }

    /// This shape rounded by `radius` — the same operation as [`Shape::offset`],
    /// named for the sculpting move it performs on a hard-cornered shape.
    pub fn round(self, radius: f32) -> Shape {
        self.offset(radius)
    }

    /// This shape's outline, `width` wide, centred on its edge.
    pub fn outline(self, width: f32) -> Shape {
        Shape::Outline { of: Box::new(self), width }
    }

    /// This shape moved by `(dx, dy)`.
    pub fn translate(self, dx: f32, dy: f32) -> Shape {
        Shape::Translate { of: Box::new(self), dx, dy }
    }

    /// This shape turned `radians` about `center`.
    pub fn rotate(self, center: Point, radians: f32) -> Shape {
        Shape::Rotate { of: Box::new(self), center, radians }
    }

    /// This shape scaled uniformly by `factor` about `center`.
    pub fn scale(self, center: Point, factor: f32) -> Shape {
        Shape::Scale { of: Box::new(self), center, factor }
    }
}

impl std::ops::BitOr for Shape {
    type Output = Shape;
    /// `a | b` is [`Shape::union`].
    fn bitor(self, rhs: Shape) -> Shape {
        self.union(rhs)
    }
}

impl std::ops::BitAnd for Shape {
    type Output = Shape;
    /// `a & b` is [`Shape::intersect`].
    fn bitand(self, rhs: Shape) -> Shape {
        self.intersect(rhs)
    }
}

impl std::ops::Sub for Shape {
    type Output = Shape;
    /// `a - b` is [`Shape::subtract`].
    fn sub(self, rhs: Shape) -> Shape {
        self.subtract(rhs)
    }
}

// ---------------------------------------------------------------------------
// leaf distance fields
// ---------------------------------------------------------------------------

/// The exact signed distance to an axis-aligned box (Inigo Quilez's form).
fn rect_sd(p: Point, center: Point, half: Size) -> f32 {
    let dx = (p.x - center.x).abs() - half.w;
    let dy = (p.y - center.y).abs() - half.h;
    let ox = dx.max(0.0);
    let oy = dy.max(0.0);
    (ox * ox + oy * oy).sqrt() + dx.max(dy).min(0.0)
}

/// The exact signed distance to a capsule (a segment thickened by `half`).
fn capsule_sd(p: Point, a: Point, b: Point, half: f32) -> f32 {
    let pa = sub(p, a);
    let ba = sub(b, a);
    let t = (dot(pa, ba) / dot(ba, ba).max(EPS)).clamp(0.0, 1.0);
    length((pa.0 - ba.0 * t, pa.1 - ba.1 * t)) - half
}

/// The signed distance to an arc band, matching the built-in gauge band: within
/// the sweep it is the radial distance; past an end it is the distance to that
/// end's round cap. A sweep of a whole turn or more is a closed ring with no
/// caps and no seam at the start angle.
fn arc_sd(p: Point, center: Point, radius: f32, half: f32, start: f32, sweep: f32) -> f32 {
    // A backwards sweep is the same band read the other way, turned round here.
    let (start, sweep) = if sweep < 0.0 { (start + sweep, -sweep) } else { (start, sweep) };
    let v = sub(p, center);
    let radial = (length(v) - radius).abs();
    if sweep >= TAU {
        return radial - half;
    }
    if (v.1.atan2(v.0) - start).rem_euclid(TAU) <= sweep {
        return radial - half;
    }
    let e0 = on_circle(center, radius, start);
    let e1 = on_circle(center, radius, start + sweep);
    length(sub(p, e0)).min(length(sub(p, e1))) - half
}

/// The exact signed distance to a regular polygon (Inigo Quilez's apothem form,
/// <https://iquilezles.org/articles/distfunctions2d/>), taking the circumradius
/// in and deriving the apothem `R * cos(pi/n)`.
fn ngon_sd(p: Point, center: Point, circumradius: f32, sides: u32, rotation: f32) -> f32 {
    let n = sides.max(3) as f32;
    let an = PI / n;
    let (san, can) = an.sin_cos();
    // Bring the point into the polygon's canonical, un-rotated frame.
    let q = rotate(sub(p, center), -rotation);
    // Fold into the first sector, then the distance is to one edge line.
    let bn = q.0.atan2(q.1).rem_euclid(2.0 * an) - an;
    let l = length(q);
    let wx = l * bn.cos() - circumradius * can; // subtract the apothem
    let mut wy = l * bn.sin().abs() - circumradius * san; // and the R*sin(an) term
    wy += (-wy).clamp(0.0, circumradius * san);
    length((wx, wy)) * sign(wx)
}

/// The exact signed distance to a simple polygon (Inigo Quilez's winding form):
/// the unsigned distance to the nearest edge, signed by a ray-crossing count.
fn polygon_sd(p: Point, points: &[Point]) -> f32 {
    let n = points.len();
    if n == 0 {
        return f32::INFINITY;
    }
    let mut d = dot(sub(p, points[0]), sub(p, points[0]));
    let mut s = 1.0f32;
    for i in 0..n {
        let j = (i + n - 1) % n;
        let e = sub(points[j], points[i]);
        let w = sub(p, points[i]);
        let t = (dot(w, e) / dot(e, e).max(EPS)).clamp(0.0, 1.0);
        let b = (w.0 - e.0 * t, w.1 - e.1 * t);
        d = d.min(dot(b, b));
        let c0 = p.y >= points[i].y;
        let c1 = p.y < points[j].y;
        let c2 = e.0 * w.1 > e.1 * w.0;
        if (c0 && c1 && c2) || (!c0 && !c1 && !c2) {
            s = -s;
        }
    }
    s * d.sqrt()
}

// ---------------------------------------------------------------------------
// paint
// ---------------------------------------------------------------------------

/// A field that colours a shape at a point.
///
/// [`Paint::at`] answers the colour at a logical point, given the shape's signed
/// distance there (already computed by the renderer, so [`Paint::Solid`],
/// [`Paint::Linear`], and [`Paint::Radial`] cost no extra distance evaluations).
/// [`Paint::Bevel`] is the exception: it reads the field *gradient*, which is the
/// surface normal, so it costs four extra distance calls per pixel.
#[derive(Debug, Clone, Copy)]
pub enum Paint {
    /// One colour everywhere.
    Solid(Color),
    /// `c0` at `a`, `c1` at `b`, clamped and mixed along the axis between them.
    Linear {
        /// Where the gradient starts.
        a: Point,
        /// Where it ends.
        b: Point,
        /// The colour at `a`.
        c0: Color,
        /// The colour at `b`.
        c1: Color,
    },
    /// `c0` within `inner`, mixing to `c1` by `outer`, radially from `center`.
    Radial {
        /// The centre.
        center: Point,
        /// The radius within which the colour is solid `c0`.
        inner: f32,
        /// The radius by which the colour has reached `c1`.
        outer: f32,
        /// The inner colour.
        c0: Color,
        /// The outer colour.
        c1: Color,
    },
    /// Edge-light from the field gradient: an edge facing `direction` catches
    /// `light`, one facing away catches `shadow`, both fading to `base` by
    /// `depth` in from the surface.
    Bevel {
        /// The unlit surface colour.
        base: Color,
        /// The colour a lit edge takes.
        light: Color,
        /// The colour a shadowed edge takes.
        shadow: Color,
        /// The direction the light comes from (need not be normalised).
        direction: Point,
        /// How far in from the edge the lighting fades to `base`.
        depth: f32,
    },
}

/// A shape painted in one flat colour.
pub fn solid(color: Color) -> Paint {
    Paint::Solid(color)
}

/// A linear gradient from `c0` at `a` to `c1` at `b`.
pub fn linear(a: Point, b: Point, c0: Color, c1: Color) -> Paint {
    Paint::Linear { a, b, c0, c1 }
}

/// A radial gradient: solid `c0` within `inner`, mixing to `c1` by `outer`.
pub fn radial(center: Point, inner: f32, outer: f32, c0: Color, c1: Color) -> Paint {
    Paint::Radial { center, inner, outer, c0, c1 }
}

/// A bevel edge-light lit from `direction`; see [`Paint::Bevel`].
pub fn bevel(base: Color, light: Color, shadow: Color, direction: Point, depth: f32) -> Paint {
    Paint::Bevel { base, light, shadow, direction, depth }
}

impl Paint {
    /// The colour at logical point `p`, where `shape.sd(p) == d`.
    ///
    /// `d` is passed in rather than recomputed so the flat and gradient fields
    /// cost no distance evaluations of their own; only [`Paint::Bevel`] calls
    /// back into `shape` for its gradient.
    pub fn at(&self, shape: &Shape, p: Point, d: f32) -> Color {
        match *self {
            Paint::Solid(c) => c,
            Paint::Linear { a, b, c0, c1 } => {
                let ab = sub(b, a);
                let ap = sub(p, a);
                let t = (dot(ap, ab) / dot(ab, ab).max(EPS)).clamp(0.0, 1.0);
                c0.mix(c1, t)
            }
            Paint::Radial { center, inner, outer, c0, c1 } => {
                let t = ((length(sub(p, center)) - inner) / (outer - inner).max(EPS)).clamp(0.0, 1.0);
                c0.mix(c1, t)
            }
            Paint::Bevel { base, light, shadow, direction, depth } => {
                let e = 0.5;
                let gx = shape.sd(Point::new(p.x + e, p.y)) - shape.sd(Point::new(p.x - e, p.y));
                let gy = shape.sd(Point::new(p.x, p.y + e)) - shape.sd(Point::new(p.x, p.y - e));
                let n = normalize((gx, gy));
                let l = normalize((direction.x, direction.y));
                let facing = dot(n, l);
                let rim = (1.0 - (-d) / depth.max(EPS)).clamp(0.0, 1.0);
                if facing >= 0.0 {
                    base.mix(light, rim * facing)
                } else {
                    base.mix(shadow, rim * -facing)
                }
            }
        }
    }
}

/// How a [`Shape`] is laid onto the canvas.
///
/// The three ways the one distance field is read: [`Sculpt::Fill`] paints the
/// interior, [`Sculpt::Stroke`] paints a band about the edge, and
/// [`Sculpt::Glow`] adds light that falls away outside the edge. Named `Sculpt`
/// rather than `Style` so it does not collide with the layout [`Style`](crate::Style).
#[derive(Debug, Clone, Copy)]
pub enum Sculpt {
    /// Fill the shape's interior, antialiasing its edge.
    Fill,
    /// Stroke a band `width` wide centred on the shape's edge.
    Stroke {
        /// The full width of the stroke.
        width: f32,
    },
    /// Add a glow: the interior lit and a halo reaching `radius` beyond the
    /// edge, all scaled by `intensity`, composited additively so overlapping
    /// glows brighten toward white.
    Glow {
        /// How far the halo reaches past the edge, in logical units.
        radius: f32,
        /// How bright the light is, from zero to one.
        intensity: f32,
    },
}

// ---------------------------------------------------------------------------
// private vector helpers (kept local so geom.rs is untouched)
// ---------------------------------------------------------------------------

/// The vector from `b` to `a`.
fn sub(a: Point, b: Point) -> (f32, f32) {
    (a.x - b.x, a.y - b.y)
}

/// The dot product of two vectors.
fn dot(a: (f32, f32), b: (f32, f32)) -> f32 {
    a.0 * b.0 + a.1 * b.1
}

/// The Euclidean length of a vector.
fn length(v: (f32, f32)) -> f32 {
    (v.0 * v.0 + v.1 * v.1).sqrt()
}

/// `v` turned by `theta` radians (y-down, so a positive angle turns clockwise).
fn rotate(v: (f32, f32), theta: f32) -> (f32, f32) {
    let (s, c) = theta.sin_cos();
    (v.0 * c - v.1 * s, v.0 * s + v.1 * c)
}

/// `v` scaled to unit length, or the zero vector when it has no length.
fn normalize(v: (f32, f32)) -> (f32, f32) {
    let l = length(v);
    if l <= EPS { (0.0, 0.0) } else { (v.0 / l, v.1 / l) }
}

/// The sign of `x`, with zero counted positive so an on-edge point reads out.
fn sign(x: f32) -> f32 {
    if x < 0.0 { -1.0 } else { 1.0 }
}

/// Where `angle` round a circle of `radius` about `center` lands.
fn on_circle(center: Point, radius: f32, angle: f32) -> Point {
    let (s, c) = angle.sin_cos();
    Point::new(center.x + c * radius, center.y + s * radius)
}

/// The square of side `2 * reach` centred on `center`.
fn square(center: Point, reach: f32) -> Rect {
    Rect::new(center.x - reach, center.y - reach, 2.0 * reach, 2.0 * reach)
}

/// The four corners of a rectangle, clockwise from the top-left.
fn corners(r: Rect) -> [(f32, f32); 4] {
    [(r.x, r.y), (r.max_x(), r.y), (r.max_x(), r.max_y()), (r.x, r.max_y())]
}

/// The axis-aligned bounding box of a set of points, empty if there are none.
fn aabb(points: impl IntoIterator<Item = (f32, f32)>) -> Rect {
    let mut it = points.into_iter();
    let Some((mut min_x, mut min_y)) = it.next() else {
        return Rect::ZERO;
    };
    let (mut max_x, mut max_y) = (min_x, min_y);
    for (x, y) in it {
        min_x = min_x.min(x);
        min_y = min_y.min(y);
        max_x = max_x.max(x);
        max_y = max_y.max(y);
    }
    Rect::new(min_x, min_y, max_x - min_x, max_y - min_y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canvas::Canvas;

    fn near(a: f32, b: f32) -> bool {
        (a - b).abs() < 1e-3
    }

    #[test]
    fn a_circles_distance_is_signed_and_measured_from_its_edge() {
        let c = circle(Point::new(0.0, 0.0), 10.0);
        assert!(near(c.sd(Point::new(0.0, 0.0)), -10.0), "the centre is a radius inside");
        assert!(near(c.sd(Point::new(10.0, 0.0)), 0.0), "the rim is on the edge");
        assert!(near(c.sd(Point::new(15.0, 0.0)), 5.0), "outside is the gap to the rim");
    }

    #[test]
    fn a_union_is_the_nearer_of_the_two_fields() {
        let a = circle(Point::new(-5.0, 0.0), 6.0);
        let b = circle(Point::new(5.0, 0.0), 6.0);
        let u = a.clone().union(b.clone());
        for p in [Point::new(0.0, 0.0), Point::new(-8.0, 3.0), Point::new(20.0, 20.0)] {
            assert!(near(u.sd(p), a.sd(p).min(b.sd(p))), "union must be the min at {p:?}");
        }
        // `|` is the same operator.
        let piped = a.clone() | b.clone();
        assert!(near(piped.sd(Point::ZERO), u.sd(Point::ZERO)));
    }

    #[test]
    fn subtracting_carves_the_second_shape_out_of_the_first() {
        let a = circle(Point::new(0.0, 0.0), 10.0);
        let b = circle(Point::new(0.0, 0.0), 4.0);
        let ring = a - b; // a disc with its middle removed
        assert!(ring.sd(Point::new(0.0, 0.0)) > 0.0, "the removed middle is now outside");
        assert!(ring.sd(Point::new(7.0, 0.0)) < 0.0, "the surviving annulus is inside");
    }

    #[test]
    fn a_smooth_union_never_pushes_past_the_hard_one_and_bulges_at_the_join() {
        let a = circle(Point::new(-5.0, 0.0), 6.0);
        let b = circle(Point::new(5.0, 0.0), 6.0);
        let k = 4.0;
        let smooth = a.clone().smooth_union(b.clone(), k);
        for p in [Point::new(0.0, 0.0), Point::new(0.0, 5.0), Point::new(3.0, 2.0)] {
            let hard = a.sd(p).min(b.sd(p));
            let s = smooth.sd(p);
            assert!(s <= hard + 1e-4, "smin never exceeds min at {p:?}");
            assert!(s >= hard - k - 1e-3, "and stays within k of it at {p:?}");
        }
    }

    #[test]
    fn rounding_moves_the_whole_surface_out_by_the_radius() {
        let c = circle(Point::new(0.0, 0.0), 10.0);
        let rounded = c.clone().round(3.0);
        // Rounding a circle is a bigger circle: every point is 3 units more inside.
        for p in [Point::new(0.0, 0.0), Point::new(8.0, 0.0), Point::new(14.0, 0.0)] {
            assert!(near(rounded.sd(p), c.sd(p) - 3.0), "round shifts the field by -r at {p:?}");
        }
    }

    #[test]
    fn an_outline_is_symmetric_about_the_edge_it_traces() {
        let c = circle(Point::new(0.0, 0.0), 10.0);
        let line = c.outline(2.0);
        // A point a given distance inside the edge and one the same distance
        // outside sit at the same signed distance from the outline.
        let inside = line.sd(Point::new(8.0, 0.0)); // 2 in
        let outside = line.sd(Point::new(12.0, 0.0)); // 2 out
        assert!(near(inside, outside), "the outline is not symmetric: {inside} vs {outside}");
        assert!(near(line.sd(Point::new(10.0, 0.0)), -1.0), "its own centre is half a width in");
    }

    #[test]
    fn a_regular_polygon_measures_its_inradius_at_the_centre() {
        let hex = ngon(Point::new(0.0, 0.0), 6, 10.0, 0.0);
        let apothem = 10.0 * (PI / 6.0).cos();
        assert!(near(hex.sd(Point::new(0.0, 0.0)), -apothem), "centre is an inradius inside");
        assert!(hex.sd(Point::new(20.0, 0.0)) > 0.0, "well outside is positive");
    }

    #[test]
    fn a_polygon_is_negative_inside_and_positive_outside() {
        let tri = polygon(vec![
            Point::new(0.0, -10.0),
            Point::new(10.0, 8.0),
            Point::new(-10.0, 8.0),
        ]);
        assert!(tri.sd(Point::new(0.0, 0.0)) < 0.0, "the centroid is inside");
        assert!(tri.sd(Point::new(0.0, 40.0)) > 0.0, "far below is outside");
    }

    #[test]
    fn a_bbox_contains_the_zero_set() {
        let shapes = [
            circle(Point::new(3.0, 4.0), 7.0),
            rounded_rect(Rect::new(1.0, 2.0, 30.0, 20.0), 5.0),
            capsule(Point::new(2.0, 2.0), Point::new(40.0, 30.0), 6.0),
            ring(Point::new(10.0, 10.0), 8.0, 3.0),
            ngon(Point::new(15.0, 15.0), 5, 9.0, 0.7),
        ];
        for shape in shapes {
            let b = shape.bbox();
            // Sample the bbox densely; every point at or inside the surface must
            // fall within the box (a loose box is fine, a tight-cropping one not).
            let steps = 40;
            for i in 0..=steps {
                for j in 0..=steps {
                    let p = Point::new(
                        b.x - 5.0 + (b.w + 10.0) * i as f32 / steps as f32,
                        b.y - 5.0 + (b.h + 10.0) * j as f32 / steps as f32,
                    );
                    if shape.sd(p) <= 0.0 {
                        assert!(
                            b.contains(p) || on_border(b, p),
                            "a point inside the shape fell outside its bbox: {p:?} not in {b:?}"
                        );
                    }
                }
            }
        }
    }

    /// Whether `p` sits on (within a hair of) the border of `r`, since a
    /// half-open `contains` excludes the far edges a zero-set can touch exactly.
    fn on_border(r: Rect, p: Point) -> bool {
        p.x >= r.x - 1e-3
            && p.x <= r.max_x() + 1e-3
            && p.y >= r.y - 1e-3
            && p.y <= r.max_y() + 1e-3
    }

    #[test]
    fn translate_and_rotate_preserve_distance() {
        let c = circle(Point::new(0.0, 0.0), 5.0);
        let moved = c.clone().translate(20.0, 10.0);
        assert!(near(moved.sd(Point::new(20.0, 10.0)), -5.0), "the centre moved with it");

        let turned = c.rotate(Point::new(0.0, 0.0), 1.0);
        // Rotating a circle about its own centre changes nothing.
        assert!(near(turned.sd(Point::new(5.0, 0.0)), 0.0));
    }

    fn pixel(canvas: &Canvas, x: u32, y: u32) -> Color {
        Color::from_argb(canvas.pixels()[(y * canvas.width() + x) as usize])
    }

    fn blank(w: u32, h: u32) -> Canvas {
        let mut canvas = Canvas::new(w, h, 1.0);
        canvas.clear(Color::BLACK);
        canvas
    }

    #[test]
    fn a_filled_shape_covers_its_interior_and_leaves_the_outside_alone() {
        let mut canvas = blank(40, 40);
        let disc = circle(Point::new(20.0, 20.0), 10.0);
        canvas.sculpt(&disc, &solid(Color::WHITE), Sculpt::Fill);
        assert_eq!(pixel(&canvas, 20, 20), Color::WHITE, "the middle is filled");
        assert_eq!(pixel(&canvas, 2, 2), Color::BLACK, "far outside is untouched");
    }

    #[test]
    fn a_fractional_edge_is_antialiased_rather_than_snapped() {
        let mut canvas = blank(40, 40);
        canvas.sculpt(&circle(Point::new(20.0, 20.0), 10.5), &solid(Color::WHITE), Sculpt::Fill);
        // A pixel astride the rim is partly covered.
        let edge = pixel(&canvas, 30, 20);
        assert!(edge.r > 0 && edge.r < 255, "expected a part-covered rim pixel, got {edge:?}");
    }

    #[test]
    fn two_overlapping_glows_are_brighter_than_one() {
        let disc = circle(Point::new(20.0, 20.0), 6.0);
        let paint = solid(Color::rgb(80, 80, 80));

        let mut once = blank(40, 40);
        once.sculpt(&disc, &paint, Sculpt::Glow { radius: 8.0, intensity: 1.0 });

        let mut twice = blank(40, 40);
        twice.sculpt(&disc, &paint, Sculpt::Glow { radius: 8.0, intensity: 1.0 });
        twice.sculpt(&disc, &paint, Sculpt::Glow { radius: 8.0, intensity: 1.0 });

        assert!(
            pixel(&twice, 20, 20).r > pixel(&once, 20, 20).r,
            "a second additive glow must brighten the buffer"
        );
    }

    #[test]
    fn a_linear_field_reaches_its_endpoint_colours() {
        let mut canvas = blank(60, 20);
        let bar = rect(Rect::new(0.0, 0.0, 60.0, 20.0));
        let a = Point::new(2.0, 10.0);
        let b = Point::new(58.0, 10.0);
        canvas.sculpt(&bar, &linear(a, b, Color::rgb(0, 0, 0), Color::rgb(255, 255, 255)), Sculpt::Fill);
        assert!(pixel(&canvas, 1, 10).r < 20, "the start is near c0");
        assert!(pixel(&canvas, 58, 10).r > 235, "the end is near c1");
    }

    #[test]
    fn a_stroke_marks_the_edge_and_leaves_the_middle_alone() {
        let mut canvas = blank(40, 40);
        let disc = circle(Point::new(20.0, 20.0), 12.0);
        canvas.sculpt(&disc, &solid(Color::WHITE), Sculpt::Stroke { width: 2.0 });
        assert!(pixel(&canvas, 20, 8).r > 100, "the top of the ring is drawn");
        assert_eq!(pixel(&canvas, 20, 20), Color::BLACK, "the middle is untouched");
    }
}
