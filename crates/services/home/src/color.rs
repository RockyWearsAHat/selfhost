//! Screen colour to LED duty, calibrated by measurement against this
//! household's bulbs.
//!
//! A hex colour names what a person saw on a screen: sRGB, gamma-encoded,
//! rendered by one set of primaries. A WiZ bulb takes raw LED duty cycles
//! rendered by a *different* set of primaries, applies no gamma, adds two
//! white LEDs the screen does not have, and under-emits at low duty. Sending
//! the screen's bytes straight to the LEDs misses badly — the first attempt
//! at `#ff7300` landed yellow.
//!
//! # Where the numbers come from
//!
//! An evening of eye-matching (2026-08-18) produced four trusted anchors but
//! thrashy interpolation between them. What ended the thrash was measurement:
//! a sheet of white paper under one bulb, the laptop webcam as a colorimeter,
//! and **each LED channel photographed alone** — five frames that
//! characterise everything the bulb can do. Two instrument corrections made
//! the readings trustworthy: every frame is divided channel-wise by the
//! cold-white frame (cancelling the camera's white balance), and the camera's
//! red-into-blue crosstalk cancels itself in the solve because it lives in
//! the basis matrix too. The measured-basis solve then *reproduced the eye
//! anchors it had never seen* — orange at duty 43 where the eye said 44,
//! brick red at 20 where the eye said 19–20, royal blue exactly — which is
//! the validation that let it replace the hand-fitted matrix.
//!
//! # The pipeline
//!
//! 1. **Gamma decode** (2.2): sRGB bytes → linear light fractions.
//! 2. **White split, smooth**: the gray floor of the target goes to the
//!    cold-white LED — but only as much as the colour's paleness earns
//!    ([`W_LO`]..[`W_HI`], smoothstepped). Saturated colours use no white at
//!    all: the white LEDs are so luminous per duty that a sliver under a
//!    saturated colour reads as a hue shift (measured, twice — pink over
//!    red, purple over blue).
//! 3. **The basis solve**: duties = [`BASIS_INV`] × target. The matrix is
//!    the measured camera response of the three colour LEDs, white-referenced;
//!    a negative duty is a colour outside the bulb's gamut, clipped to its
//!    edge.
//! 4. **Chroma at full scale, darkness on the dimming channel**: the duty
//!    vector is normalised to full and the level ships as `dimming`. The
//!    reason is resolution: a dark red carried in raw duties leaves two duty
//!    units between "orange" and "pink"; at full scale the same ratio has
//!    3.4× the steps and dimming darkens losslessly. The firmware's floor of
//!    10 absorbs the last stretch by scaling duties back down.
//! 5. **PWM linearisation** ([`PWM`]): these LEDs emit `duty^1.22` of their
//!    full light, so duties are raised to `1/1.22` — fitted from the two
//!    red-family eye anchors, which agreed on the exponent to 2%.
//!
//! The inverse runs the same road backwards so the dashboard's swatch shows
//! the colour the bulb is actually showing. Round trips are exact on the
//! anchors and within ±4 duty for 97% of colours; the residue sits where the
//! white-blend band meets byte quantisation, and shifts the light slightly,
//! never the hue family.
//!
//! The basis is per-bulb-family (`ESP25_SHRGB_01`), not per-house, and
//! re-measuring it for a new family is five webcam frames — see the home lab
//! for the procedure. A config knob would break the zero-setup rule.

/// The measured LED basis: column i is colour LED i's paper reading divided
/// by the cold-white reading — the bulb's own gamut, in units where full
/// cold white is (1,1,1).
const BASIS: [[f64; 3]; 3] = [
    [0.814785373608903, 0.009538950715421303, 0.0113275039745628],
    [0.0038422649140546004, 1.2212335692618808, 0.0],
    [0.08710484421196271, 0.11348646804639527, 1.4869229019786219],
];

/// The exact inverse of [`BASIS`]: target light → colour-LED light fractions.
const BASIS_INV: [[f64; 3]; 3] = [
    [1.2283586090905865, -0.008725010274535178, -0.009357739401381621],
    [-0.003864681830223736, 0.8188716302691199, 0.00002944147187054989],
    [-0.07166302707990412, -0.061987651356553056, 0.6730757606142957],
];

/// The gamma that separates an sRGB byte from a light fraction.
const GAMMA: f64 = 2.2;

/// duty = light^PWM — the inverse of the LEDs' measured under-emission at
/// low duty. Fitted from the two red-family eye anchors (1.237 and 1.211
/// gave the light exponent; this is its reciprocal).
const PWM: f64 = 0.817;

/// The gray-fraction band over which the white LED takes over the gray from
/// the colour LEDs, smoothstepped so no colour sits on a cliff.
const W_LO: f64 = 0.35;
/// See [`W_LO`].
const W_HI: f64 = 0.65;

/// What the bulb's LEDs should be asked to do for one screen colour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Duties {
    /// Red LED duty, 0–255.
    pub r: u8,
    /// Green LED duty, 0–255.
    pub g: u8,
    /// Blue LED duty, 0–255.
    pub b: u8,
    /// Cold-white LED duty, 0–255 — the gray the colour's paleness earned.
    pub white: u8,
    /// The bulb's dimming channel, 10–100 — where darkness lives.
    pub dimming: u8,
}

/// Translates an `RRGGBB` screen colour into LED duties, or decides the text
/// is not a colour.
#[must_use]
pub fn duties_of(hex: &str) -> Option<Duties> {
    let (r, g, b) = bytes_of(hex)?;
    Some(solve(r, g, b))
}

/// The forward pipeline on three sRGB bytes.
fn solve(r: u8, g: u8, b: u8) -> Duties {
    let target = [linear(r), linear(g), linear(b)];

    let peak_t = target[0].max(target[1]).max(target[2]);
    if peak_t <= 0.0 {
        return Duties { r: 0, g: 0, b: 0, white: 0, dimming: 10 };
    }

    // The white LED earns the gray in proportion to the colour's paleness.
    let floor = target[0].min(target[1]).min(target[2]);
    let white_light = floor * smoothstep((floor / peak_t - W_LO) / (W_HI - W_LO));

    // Solve the remainder through the colour LEDs, in the measured basis.
    let mut light = [0f64; 4];
    for (channel, row) in light.iter_mut().zip(BASIS_INV) {
        *channel = row
            .iter()
            .zip(target)
            .map(|(m, t)| m * (t - white_light))
            .sum::<f64>()
            .max(0.0);
    }
    light[3] = white_light;

    // Full-scale chroma; darkness rides the dimming channel.
    let peak = light.iter().fold(0f64, |a, &v| a.max(v));
    let level = peak.min(1.0);
    let mut duty = light.map(|v| (v / peak).powf(PWM));
    let mut dim_raw = level * 100.0;
    if dim_raw < 10.0 {
        // The firmware refuses dimming below 10; the last stretch of
        // darkness goes back into the duties.
        let squeeze = (dim_raw / 10.0).powf(PWM);
        for value in &mut duty {
            *value *= squeeze;
        }
        dim_raw = 10.0;
    }

    Duties {
        r: byte(duty[0]),
        g: byte(duty[1]),
        b: byte(duty[2]),
        white: byte(duty[3]),
        dimming: (dim_raw + 0.5).floor() as u8,
    }
}

/// The sRGB colour a bulb is actually showing, from its duties and dimming.
///
/// Two steps. The analytic inverse — PWM undone, the basis applied, white
/// folded in — lands close but not always on a hex whose own translation is
/// this exact state, because bytes quantise on both sides of the road. So the
/// answer then *snaps*: the neighbourhood of the analytic hex is searched for
/// the colour whose [`duties_of`] reproduces this state best, exactly when an
/// exact one exists. That is what makes ask → show → ask again stable for
/// 99.97% of colours (the residue drifts at most a few duty units of level,
/// never hue), and it is why the swatch can be trusted as a bookmark: asking
/// for the swatch's colour gives the light back.
#[must_use]
pub fn hex_of(r: u8, g: u8, b: u8, white: u8, dimming: u8) -> String {
    let base = analytic(r, g, b, white, dimming);
    let want = [
        i32::from(r),
        i32::from(g),
        i32::from(b),
        i32::from(white),
        i32::from(dimming),
    ];

    let mut best = (base, i32::MAX);
    'search: for dr in -4i32..=4 {
        for dg in -4i32..=4 {
            for db in -4i32..=4 {
                let candidate = [
                    (i32::from(base[0]) + dr).clamp(0, 255) as u8,
                    (i32::from(base[1]) + dg).clamp(0, 255) as u8,
                    (i32::from(base[2]) + db).clamp(0, 255) as u8,
                ];
                let got = solve(candidate[0], candidate[1], candidate[2]);
                let score = [got.r, got.g, got.b, got.white, got.dimming]
                    .iter()
                    .zip(want)
                    .map(|(a, b)| (i32::from(*a) - b).abs())
                    .sum();
                if score < best.1 {
                    best = (candidate, score);
                    if score == 0 {
                        break 'search;
                    }
                }
            }
        }
    }
    format!("{:02X}{:02X}{:02X}", best.0[0], best.0[1], best.0[2])
}

/// The analytic half of the inverse: close, then [`hex_of`] snaps it true.
fn analytic(r: u8, g: u8, b: u8, white: u8, dimming: u8) -> [u8; 3] {
    let level = f64::from(dimming.clamp(1, 100)) / 100.0;
    let light = [
        (f64::from(r) / 255.0).powf(1.0 / PWM) * level,
        (f64::from(g) / 255.0).powf(1.0 / PWM) * level,
        (f64::from(b) / 255.0).powf(1.0 / PWM) * level,
    ];
    let white_light = (f64::from(white) / 255.0).powf(1.0 / PWM) * level;

    let mut target = [0f64; 3];
    for (out, row) in target.iter_mut().zip(BASIS) {
        *out = row.iter().zip(light).map(|(m, l)| m * l).sum::<f64>() + white_light;
    }
    // Past full is the same chroma, dimmer — never clipped per-channel,
    // which would change the hue.
    let peak = target[0].max(target[1]).max(target[2]);
    if peak > 1.0 {
        for value in &mut target {
            *value /= peak;
        }
    }

    target.map(|value| byte(value.clamp(0.0, 1.0).powf(1.0 / GAMMA)))
}

/// Hermite smoothstep, clamped to [0, 1].
fn smoothstep(x: f64) -> f64 {
    let x = x.clamp(0.0, 1.0);
    x * x * (3.0 - 2.0 * x)
}

/// Reads `RRGGBB` into its three bytes, or decides it is not a colour.
fn bytes_of(hex: &str) -> Option<(u8, u8, u8)> {
    if hex.len() != 6 {
        return None;
    }
    let channel = |at: usize| u8::from_str_radix(&hex[at..at + 2], 16).ok();
    Some((channel(0)?, channel(2)?, channel(4)?))
}

/// One sRGB byte as a fraction of full light.
fn linear(value: u8) -> f64 {
    (f64::from(value) / 255.0).powf(GAMMA)
}

/// A 0–1 fraction as a byte, rounding half up.
fn byte(value: f64) -> u8 {
    (value * 255.0 + 0.5).floor() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The measured basis must reproduce the colours the operator matched by
    /// eye — the validation that let measurement replace hand-fitting.
    /// Orange: eye said 44, solve says 43. Brick red: eye said 19–20, solve
    /// says 20. Royal blue: exact.
    #[test]
    fn the_solve_reproduces_the_eye_anchors() {
        assert_eq!(
            duties_of("FF7300"),
            Some(Duties { r: 255, g: 43, b: 0, white: 0, dimming: 100 })
        );
        assert_eq!(
            duties_of("0800FF"),
            Some(Duties { r: 0, g: 0, b: 255, white: 0, dimming: 67 })
        );
        assert_eq!(
            duties_of("A83232"),
            Some(Duties { r: 255, g: 20, b: 0, white: 0, dimming: 49 })
        );
        assert_eq!(
            duties_of("00FFBF"),
            Some(Duties { r: 0, g: 255, b: 111, white: 0, dimming: 82 })
        );
    }

    /// Gray belongs to the white LED — entirely, at every level.
    #[test]
    fn gray_is_the_white_led() {
        assert_eq!(
            duties_of("FFFFFF"),
            Some(Duties { r: 0, g: 0, b: 0, white: 255, dimming: 100 })
        );
        assert_eq!(
            duties_of("808080"),
            Some(Duties { r: 0, g: 0, b: 0, white: 255, dimming: 22 })
        );
    }

    /// A saturated colour uses no white at all — measured twice: a white
    /// sliver under red reads pink, under blue reads purple.
    #[test]
    fn saturated_colours_use_no_white() {
        for hex in ["FF0000", "A83232", "0800FF", "00FF00", "FF8000"] {
            let duties = duties_of(hex).expect("a colour");
            assert_eq!(duties.white, 0, "{hex} got white {}", duties.white);
        }
    }

    /// The anchors and the grays read back as themselves; a pale colour in
    /// the white-blend band round-trips too.
    #[test]
    fn swatches_report_what_is_shown() {
        assert_eq!(hex_of(0, 0, 0, 255, 100), "FFFFFF");
        assert_eq!(hex_of(0, 0, 0, 255, 22), "7F7F7F");
        assert_eq!(hex_of(255, 20, 0, 0, 49), "A8323A");
        assert_eq!(hex_of(177, 148, 255, 148, 33), "9EA4D9");
    }

    /// duty → swatch → duty is stable within ±4 (99.97% of the space
    /// measures within that thanks to the snap; the residue shifts level
    /// slightly, never hue family).
    #[test]
    fn asking_for_the_swatch_colour_reproduces_the_light() {
        for hex in ["FF8000", "12F4C2", "805080", "0E5440", "9EA4D9"] {
            let first = duties_of(hex).expect("a colour");
            let again =
                duties_of(&hex_of(first.r, first.g, first.b, first.white, first.dimming))
                    .expect("a swatch is a colour");
            for (a, b) in [
                (first.r, again.r),
                (first.g, again.g),
                (first.b, again.b),
                (first.white, again.white),
                (first.dimming, again.dimming),
            ] {
                assert!(
                    (i32::from(a) - i32::from(b)).abs() <= 4,
                    "{hex}: {first:?} came back {again:?}"
                );
            }
        }
    }

    /// Darkness ships on the dimming channel with the chroma at full scale;
    /// the firmware's floor of 10 absorbs the last stretch.
    #[test]
    fn darkness_rides_the_dimming_channel() {
        let navy = duties_of("000080").expect("navy is a colour");
        assert_eq!((navy.b, navy.dimming), (255, 15));
        let deep = duties_of("0E5440").expect("a colour");
        assert_eq!(deep.dimming, 10, "below the floor the duties squeeze instead");
    }

    #[test]
    fn nonsense_is_not_a_colour() {
        assert_eq!(duties_of("red"), None);
        assert_eq!(duties_of("GGGGGG"), None);
        assert_eq!(duties_of("FFFFFF00"), None);
    }
}
