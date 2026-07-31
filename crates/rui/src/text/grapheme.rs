//! Where a run of text may be cut: extended grapheme clusters.
//!
//! A cluster is what a reader calls "a character" — a base letter together with
//! everything that hangs off it. `e` followed by U+0301 is one cluster, and so
//! is a flag, a keycap, or an emoji built out of joined parts. Everything a
//! person can land on or break at is a cluster boundary: a caret, an ellipsis,
//! a wrapped line. Bytes and `char`s are both the wrong unit — a caret between
//! a letter and its accent draws the accent over the wrong letter, and a line
//! broken there leaves half a character behind.
//!
//! # The subset of UAX #29 this implements
//!
//! There is no Unicode database here and none may be added, so the character
//! classes below are a hand-written table rather than a generated one. What
//! that table covers is stated exactly, because an approximation nobody wrote
//! down is worse than a limit somebody did.
//!
//! **Covered** — the rules, by their number in UAX #29:
//!
//! - **GB3–GB5.** `CR LF` is one cluster; every other control character stands
//!   alone.
//! - **GB9, GB9a.** A combining mark joins what precedes it. The marks
//!   recognised are the general-purpose combining blocks (U+0300–U+036F,
//!   U+1AB0–U+1AFF, U+1DC0–U+1DFF, U+20D0–U+20F0, U+FE20–U+FE2F), the Cyrillic,
//!   Hebrew, Arabic, Syriac, Thaana, Thai, Lao, and Ethiopic marks, the
//!   variation selectors (U+FE00–U+FE0F and U+E0100–U+E01EF), the emoji skin
//!   tone modifiers, the tag characters, and both zero-width joiners.
//! - **GB11**, in the loosened form "never break after U+200D". This admits
//!   every emoji ZWJ sequence without needing the Extended_Pictographic
//!   property, at the cost of also joining across a ZWJ used between letters —
//!   which is a joiner doing its job, so the result is defensible either way.
//! - **GB12, GB13.** Regional indicators pair up, so a flag is one cluster and
//!   two flags are two.
//!
//! **Not covered**, and these will cluster wrongly:
//!
//! - **Brahmic scripts.** Devanagari, Bengali, Tamil, and their relatives use
//!   marks and virama-joined conjuncts this table does not list, so a caret can
//!   land inside an Indic syllable.
//! - **Hangul jamo (GB6–GB8).** A precomposed syllable — which is what text
//!   normally holds — is a single character and is fine; a syllable spelled out
//!   as separate jamo will break into its parts.
//! - **GB9b (Prepend).** No character is treated as prepending.
//!
//! Everything here is a plain function of a `&str`: no state, no allocation,
//! and no clock.

/// The byte offsets and text of each grapheme cluster in a string.
///
/// Yields `(offset, cluster)` pairs in order, where `offset` is the byte index
/// the cluster starts at. Every offset is a `char` boundary, so the slices are
/// always valid strings.
#[derive(Debug, Clone)]
pub struct Clusters<'a> {
    text: &'a str,
    offset: usize,
}

impl<'a> Iterator for Clusters<'a> {
    type Item = (usize, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.offset;
        let rest = self.text.get(start..)?;
        let mut characters = rest.char_indices();
        let (_, first) = characters.next()?;

        let mut previous = class(first);
        let mut regional_run = usize::from(previous == Class::RegionalIndicator);
        let mut end = rest.len();
        for (offset, character) in characters {
            let next = class(character);
            if breaks(previous, next, regional_run) {
                end = offset;
                break;
            }
            regional_run =
                if next == Class::RegionalIndicator { regional_run + 1 } else { 0 };
            previous = next;
        }

        self.offset = start + end;
        Some((start, &rest[..end]))
    }
}

/// Walks `text` one grapheme cluster at a time.
pub fn clusters(text: &str) -> Clusters<'_> {
    Clusters { text, offset: 0 }
}

/// Where the cluster before `offset` starts, or `None` at the start of `text`.
///
/// This is where a caret goes when it moves left. An `offset` that is not a
/// cluster boundary answers the start of the cluster it lands inside, which is
/// still a move to the left; an `offset` past the end is treated as the end.
///
/// Costs a walk from the start of `text` rather than a step back from `offset`,
/// because whether two regional indicators pair up is only decidable in the
/// forward direction — the flag before a caret depends on how many indicators
/// preceded *it*.
pub fn before(text: &str, offset: usize) -> Option<usize> {
    clusters(text).map(|(start, _)| start).take_while(|start| *start < offset).last()
}

/// Where the cluster at `offset` ends, or `None` at the end of `text`.
///
/// This is where a caret goes when it moves right. An `offset` that is not a
/// cluster boundary answers the end of the cluster it lands inside.
pub fn after(text: &str, offset: usize) -> Option<usize> {
    clusters(text)
        .map(|(start, cluster)| start + cluster.len())
        .find(|end| *end > offset)
}

/// Whether `offset` is somewhere a caret may sit or a line may be cut.
///
/// Both ends of the string count. A byte offset that is not a `char` boundary
/// never does.
pub fn is_boundary(text: &str, offset: usize) -> bool {
    offset == 0
        || offset == text.len()
        || (offset < text.len() && clusters(text).any(|(start, _)| start == offset))
}

/// The byte length of the first cluster, or one for an empty string.
///
/// One rather than zero so that a caller cutting a string it cannot otherwise
/// break always makes progress instead of looping.
pub fn first_cluster_len(text: &str) -> usize {
    clusters(text).next().map_or(1, |(_, cluster)| cluster.len())
}

/// What a character does to the cluster it appears in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// A carriage return, which joins a following line feed and nothing else.
    Cr,
    /// A line feed.
    Lf,
    /// Any other control character: always a cluster of its own.
    Control,
    /// A combining mark, variation selector, or other character that attaches
    /// to what precedes it.
    Extend,
    /// U+200D, which joins what precedes it to what follows.
    Zwj,
    /// Half of a flag; two of them make one cluster.
    RegionalIndicator,
    /// Anything else, which starts a cluster.
    Other,
}

/// Whether a cluster boundary falls between two adjacent characters.
///
/// `regional_run` is how many regional indicators run consecutively up to and
/// including `previous`, which is what decides whether the next one pairs with
/// it or starts a new flag.
fn breaks(previous: Class, next: Class, regional_run: usize) -> bool {
    match (previous, next) {
        (Class::Cr, Class::Lf) => false,
        // A control character is never part of a cluster on either side, and
        // that outranks every joining rule below — including a joiner, which
        // must not glue a letter to a newline.
        (Class::Cr | Class::Lf | Class::Control, _) => true,
        (_, Class::Cr | Class::Lf | Class::Control) => true,
        (_, Class::Extend | Class::Zwj) => false,
        (Class::Zwj, _) => false,
        (Class::RegionalIndicator, Class::RegionalIndicator) => regional_run % 2 == 0,
        _ => true,
    }
}

/// Which class a character belongs to.
fn class(character: char) -> Class {
    match character {
        '\r' => Class::Cr,
        '\n' => Class::Lf,
        '\u{200d}' => Class::Zwj,
        '\u{1f1e6}'..='\u{1f1ff}' => Class::RegionalIndicator,
        _ if character.is_control() => Class::Control,
        _ if is_extend(character) => Class::Extend,
        _ => Class::Other,
    }
}

/// Whether a character attaches to the one before it.
fn is_extend(character: char) -> bool {
    let code = character as u32;
    EXTEND
        .binary_search_by(|(first, last)| {
            if *last < code {
                std::cmp::Ordering::Less
            } else if *first > code {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// The characters treated as attaching to what precedes them.
///
/// Sorted and disjoint, so it can be searched; see this module's header for
/// what it deliberately leaves out. Written out rather than derived, because
/// deriving it would mean carrying the Unicode database and this crate carries
/// no data it did not write.
const EXTEND: [(u32, u32); 33] = [
    (0x0300, 0x036f),   // combining diacritical marks
    (0x0483, 0x0489),   // Cyrillic
    (0x0591, 0x05bd),   // Hebrew points
    (0x05bf, 0x05bf),
    (0x05c1, 0x05c2),
    (0x05c4, 0x05c5),
    (0x05c7, 0x05c7),
    (0x0610, 0x061a),   // Arabic
    (0x064b, 0x065f),
    (0x0670, 0x0670),
    (0x06d6, 0x06dc),
    (0x06df, 0x06e4),
    (0x06e7, 0x06e8),
    (0x06ea, 0x06ed),
    (0x0711, 0x0711),   // Syriac
    (0x0730, 0x074a),
    (0x07a6, 0x07b0),   // Thaana
    (0x0e31, 0x0e31),   // Thai
    (0x0e34, 0x0e3a),
    (0x0e47, 0x0e4e),
    (0x0eb1, 0x0eb1),   // Lao
    (0x0eb4, 0x0ebc),
    (0x0ec8, 0x0ecd),
    (0x135d, 0x135f),   // Ethiopic
    (0x1ab0, 0x1aff),   // combining diacritical marks extended
    (0x1dc0, 0x1dff),   // combining diacritical marks supplement
    (0x200c, 0x200c),   // zero width non-joiner
    (0x20d0, 0x20f0),   // combining marks for symbols, including the keycap
    (0xfe00, 0xfe0f),   // variation selectors
    (0xfe20, 0xfe2f),   // combining half marks
    (0x1f3fb, 0x1f3ff), // emoji skin tone modifiers
    (0xe0020, 0xe007f), // tag characters, which spell out a subdivision flag
    (0xe0100, 0xe01ef), // variation selectors supplement
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The clusters of a string, as text, which is what every case below reads.
    fn split(text: &str) -> Vec<&str> {
        clusters(text).map(|(_, cluster)| cluster).collect()
    }

    #[test]
    fn plain_text_is_one_cluster_per_character() {
        assert_eq!(split("abc"), ["a", "b", "c"]);
        assert_eq!(split(""), Vec::<&str>::new());
    }

    #[test]
    fn a_combining_mark_belongs_to_the_letter_before_it() {
        // `e` and a combining acute, which is what a caret must not split.
        assert_eq!(split("ae\u{301}b"), ["a", "e\u{301}", "b"]);
        assert_eq!(split("e\u{301}\u{327}"), ["e\u{301}\u{327}"]);
    }

    #[test]
    fn a_variation_selector_belongs_to_the_character_it_varies() {
        assert_eq!(split("\u{2764}\u{fe0f}!"), ["\u{2764}\u{fe0f}", "!"]);
    }

    #[test]
    fn a_joined_emoji_sequence_is_one_cluster() {
        // Family: man, joiner, woman, joiner, girl.
        let family = "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}";
        assert_eq!(split(family), [family]);
    }

    #[test]
    fn a_skin_tone_modifier_belongs_to_the_hand_it_colours() {
        let wave = "\u{1f44b}\u{1f3fd}";
        assert_eq!(split(wave), [wave]);
    }

    #[test]
    fn regional_indicators_pair_into_flags() {
        let flag = "\u{1f1fa}\u{1f1f8}"; // US
        assert_eq!(split(flag), [flag]);
        assert_eq!(split(&format!("{flag}{flag}")), [flag, flag]);
        // An odd one at the end is a cluster of its own rather than joining
        // the pair before it.
        assert_eq!(split("\u{1f1fa}\u{1f1f8}\u{1f1e9}"), [flag, "\u{1f1e9}"]);
    }

    #[test]
    fn a_carriage_return_and_line_feed_are_one_cluster() {
        assert_eq!(split("a\r\nb"), ["a", "\r\n", "b"]);
        assert_eq!(split("a\n\rb"), ["a", "\n", "\r", "b"]);
    }

    #[test]
    fn a_joiner_cannot_glue_a_letter_to_a_control_character() {
        assert_eq!(split("a\u{200d}\nb"), ["a\u{200d}", "\n", "b"]);
    }

    #[test]
    fn a_mark_with_nothing_to_attach_to_stands_alone() {
        // Degenerate input must still make progress, or a caret would stall.
        assert_eq!(split("\u{301}a"), ["\u{301}", "a"]);
    }

    #[test]
    fn a_caret_steps_over_a_whole_cluster() {
        let text = "ae\u{301}b"; // a, e-acute (three bytes), b
        assert_eq!(after(text, 0), Some(1));
        assert_eq!(after(text, 1), Some(4));
        assert_eq!(after(text, 4), Some(5));
        assert_eq!(after(text, 5), None);

        assert_eq!(before(text, 5), Some(4));
        assert_eq!(before(text, 4), Some(1));
        assert_eq!(before(text, 1), Some(0));
        assert_eq!(before(text, 0), None);
    }

    #[test]
    fn a_caret_inside_a_cluster_is_moved_out_of_it() {
        let text = "e\u{301}";
        assert_eq!(after(text, 1), Some(3), "forward, to the end of the cluster");
        assert_eq!(before(text, 2), Some(0), "back, to the start of it");
    }

    #[test]
    fn the_ends_of_a_string_are_boundaries_and_the_middle_of_a_cluster_is_not() {
        let text = "e\u{301}b";
        assert!(is_boundary(text, 0));
        assert!(!is_boundary(text, 1), "between a letter and its accent");
        assert!(is_boundary(text, 3));
        assert!(is_boundary(text, text.len()));
    }

    #[test]
    fn the_first_cluster_is_never_measured_as_nothing() {
        assert_eq!(first_cluster_len(""), 1);
        assert_eq!(first_cluster_len("é"), 2);
        assert_eq!(first_cluster_len("e\u{301}x"), 3);
    }

    #[test]
    fn the_extend_table_is_sorted_and_disjoint_so_it_can_be_searched() {
        for pair in EXTEND.windows(2) {
            assert!(pair[0].0 <= pair[0].1, "a range must not run backwards");
            assert!(pair[0].1 < pair[1].0, "ranges must not overlap: {pair:?}");
        }
        assert!(is_extend('\u{301}'));
        assert!(is_extend('\u{fe0f}'));
        assert!(!is_extend('a'));
        assert!(!is_extend('\u{200d}'), "the joiner has its own class");
    }
}
