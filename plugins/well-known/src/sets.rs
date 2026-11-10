//! The values of ready sets of video guides, drawn from a seed: the same seed
//! gives the same values. Bindgen-free.

/// What a liveness check asks, before its holds and timings.
#[derive(Debug, PartialEq)]
pub struct Liveness {
    /// The face's oval, as a fraction of the frame's shorter side.
    pub width: f32,
    /// The colours flashed in the oval, `(red, green, blue)`, in order.
    pub colors: Vec<(u8, u8, u8)>,
    /// The turns of the head, in degrees, negative to the applicant's left.
    pub turns: [i8; 2],
}

/// How many colours a liveness check flashes.
const COLORS: usize = 5;

/// A liveness check's values, drawn from `seed`: the oval 0.40–0.55 wide;
/// bright colours of hues spread round the circle from one of the seed's, in
/// an order of its; then a turn by 20–30° to a side of its, and one to the
/// other.
pub fn liveness(seed: u32) -> Liveness {
    let mut draws = Draws(u64::from(seed));
    let width = draws.between(0.40, 0.55) as f32;
    let start = draws.between(0.0, 360.0);
    let mut colors: Vec<(u8, u8, u8)> = (0..COLORS)
        .map(|i| bright(start + 360.0 * i as f64 / COLORS as f64))
        .collect();
    for i in (1..colors.len()).rev() {
        colors.swap(i, (draws.next() % (i as u64 + 1)) as usize);
    }
    let side: i8 = if draws.next() & 1 == 0 { -1 } else { 1 };
    let mut degrees = || draws.between(20.0, 30.0).round() as i8;
    Liveness {
        width,
        colors,
        turns: [side * degrees(), -side * degrees()],
    }
}

/// SplitMix64, each output a bijection of a counter's: enough to spread a
/// seed over a check's values.
struct Draws(u64);

impl Draws {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A number from `min` up to `max`.
    fn between(&mut self, min: f64, max: f64) -> f64 {
        min + (self.next() >> 11) as f64 / (1u64 << 53) as f64 * (max - min)
    }
}

/// The brightest colour of `hue`, in degrees.
fn bright(hue: f64) -> (u8, u8, u8) {
    let h = hue.rem_euclid(360.0) / 60.0;
    let rise = (255.0 * (1.0 - (h % 2.0 - 1.0).abs())).round() as u8;
    match h as u8 {
        0 => (255, rise, 0),
        1 => (rise, 255, 0),
        2 => (0, 255, rise),
        3 => (0, rise, 255),
        4 => (rise, 0, 255),
        _ => (255, 0, rise),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A seed gives its values every time, and another seed others.
    #[test]
    fn a_seed_gives_its_values() {
        assert_eq!(liveness(7), liveness(7));
        assert_ne!(liveness(7), liveness(8));
    }

    /// Every seed's values are within their ranges: the oval, five bright
    /// colours of hues apart, and two turns to either side.
    #[test]
    fn the_values_are_within_their_ranges() {
        for seed in (0..2000).chain([u32::MAX]) {
            let Liveness {
                width,
                colors,
                turns,
            } = liveness(seed);
            assert!((0.40..=0.55).contains(&width), "{seed}: {width}");
            assert_eq!(colors.len(), COLORS, "{seed}");
            for &(r, g, b) in &colors {
                assert_eq!(r.max(g).max(b), 255, "{seed}: {colors:?}");
                assert_eq!(r.min(g).min(b), 0, "{seed}: {colors:?}");
            }
            for (i, a) in colors.iter().enumerate() {
                assert!(!colors[i + 1..].contains(a), "{seed}: {colors:?}");
            }
            assert_eq!(turns[0].signum(), -turns[1].signum(), "{seed}: {turns:?}");
            for turn in turns {
                assert!((20..=30).contains(&turn.abs()), "{seed}: {turns:?}");
            }
        }
    }

    /// A hue's brightest colour, round the circle.
    #[test]
    fn a_hue_is_drawn_at_its_brightest() {
        assert_eq!(bright(0.0), (255, 0, 0));
        assert_eq!(bright(60.0), (255, 255, 0));
        assert_eq!(bright(120.0), (0, 255, 0));
        assert_eq!(bright(240.0), (0, 0, 255));
        assert_eq!(bright(300.0), (255, 0, 255));
        assert_eq!(bright(360.0), (255, 0, 0));
    }
}
