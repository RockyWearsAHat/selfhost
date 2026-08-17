//! Byte-range requests (RFC 9110 §14).
//!
//! This is load-bearing for video. An adaptive HLS ladder is served as segments
//! that players fetch with `Range`, and a seek in the player is a `Range` request
//! for the middle of a file. A server that ignores `Range` and returns `200` with
//! the whole body forces the player to download from the start every time
//! somebody scrubs the timeline.
//!
//! Only a single range is honoured. Multi-range responses require a
//! `multipart/byteranges` body, which no video player asks for, and implementing
//! it would add a second body-framing path for no practical gain — so a
//! multi-range request is answered with the full representation instead, which
//! the specification explicitly permits.

use std::fmt;

/// A resolved byte range: a half-open interval over an entity of known length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    /// First byte position, inclusive.
    pub start: u64,
    /// Last byte position, inclusive.
    pub end: u64,
}

impl ByteRange {
    /// Number of bytes covered.
    pub fn len(&self) -> u64 {
        self.end - self.start + 1
    }

    /// Whether the range covers no bytes. Never true for a resolved range.
    pub fn is_empty(&self) -> bool {
        false
    }

    /// The `Content-Range` field value for this range within `total` bytes.
    pub fn content_range(&self, total: u64) -> String {
        format!("bytes {}-{}/{}", self.start, self.end, total)
    }
}

/// The outcome of evaluating a `Range` header against a known entity length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RangeOutcome {
    /// No usable range was requested; send the whole representation with `200`.
    Full,
    /// Send this range with `206 Partial Content`.
    Partial(ByteRange),
    /// The range cannot be satisfied; answer `416` with `Content-Range: bytes */len`.
    Unsatisfiable,
}

impl fmt::Display for RangeOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "full"),
            Self::Partial(r) => write!(f, "partial {}-{}", r.start, r.end),
            Self::Unsatisfiable => write!(f, "unsatisfiable"),
        }
    }
}

/// Evaluates a `Range` field value against an entity of `total` bytes.
///
/// A malformed `Range` is ignored rather than rejected, as the specification
/// requires: the client still gets its content, just unranged.
pub fn evaluate(header_value: Option<&str>, total: u64) -> RangeOutcome {
    let Some(value) = header_value else {
        return RangeOutcome::Full;
    };

    let Some(spec) = value.trim().strip_prefix("bytes=") else {
        // Only the `bytes` unit is defined for normal use; anything else is
        // ignored rather than treated as an error.
        return RangeOutcome::Full;
    };

    let mut parts = spec.split(',');
    let first = parts.next().unwrap_or_default().trim();
    if parts.next().is_some() {
        // Multi-range: answer with the whole representation instead.
        return RangeOutcome::Full;
    }

    // A zero-length entity can satisfy no range at all.
    if total == 0 {
        return RangeOutcome::Unsatisfiable;
    }

    let Some((raw_start, raw_end)) = first.split_once('-') else {
        return RangeOutcome::Full;
    };
    let raw_start = raw_start.trim();
    let raw_end = raw_end.trim();

    match (raw_start.is_empty(), raw_end.is_empty()) {
        // `bytes=-N` — the final N bytes. Used by players probing a file's tail.
        (true, false) => {
            let Some(suffix) = parse_u64(raw_end) else {
                return RangeOutcome::Full;
            };
            if suffix == 0 {
                return RangeOutcome::Unsatisfiable;
            }
            let start = total.saturating_sub(suffix);
            RangeOutcome::Partial(ByteRange { start, end: total - 1 })
        }
        // `bytes=N-` — from N to the end. The common case for video seeking.
        (false, true) => {
            let Some(start) = parse_u64(raw_start) else {
                return RangeOutcome::Full;
            };
            if start >= total {
                return RangeOutcome::Unsatisfiable;
            }
            RangeOutcome::Partial(ByteRange { start, end: total - 1 })
        }
        // `bytes=N-M` — an explicit window, clamped to the entity.
        (false, false) => {
            let (Some(start), Some(end)) = (parse_u64(raw_start), parse_u64(raw_end)) else {
                return RangeOutcome::Full;
            };
            if start > end || start >= total {
                return RangeOutcome::Unsatisfiable;
            }
            RangeOutcome::Partial(ByteRange { start, end: end.min(total - 1) })
        }
        (true, true) => RangeOutcome::Full,
    }
}

/// Parses bare ASCII digits. Rejects signs, whitespace, and overflow.
fn parse_u64(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn partial(start: u64, end: u64) -> RangeOutcome {
        RangeOutcome::Partial(ByteRange { start, end })
    }

    #[test]
    fn absent_range_serves_everything() {
        assert_eq!(evaluate(None, 1000), RangeOutcome::Full);
    }

    #[test]
    fn explicit_window() {
        assert_eq!(evaluate(Some("bytes=0-499"), 1000), partial(0, 499));
        assert_eq!(evaluate(Some("bytes=500-999"), 1000), partial(500, 999));
    }

    #[test]
    fn open_ended_range_is_the_video_seek_case() {
        assert_eq!(evaluate(Some("bytes=500-"), 1000), partial(500, 999));
        assert_eq!(evaluate(Some("bytes=0-"), 1000), partial(0, 999));
    }

    #[test]
    fn suffix_range_reads_the_tail() {
        assert_eq!(evaluate(Some("bytes=-100"), 1000), partial(900, 999));
    }

    #[test]
    fn suffix_larger_than_entity_clamps_to_the_whole_entity() {
        assert_eq!(evaluate(Some("bytes=-5000"), 1000), partial(0, 999));
    }

    #[test]
    fn end_beyond_entity_is_clamped_not_rejected() {
        assert_eq!(evaluate(Some("bytes=900-5000"), 1000), partial(900, 999));
    }

    #[test]
    fn start_beyond_entity_is_unsatisfiable() {
        assert_eq!(evaluate(Some("bytes=1000-"), 1000), RangeOutcome::Unsatisfiable);
        assert_eq!(evaluate(Some("bytes=5000-6000"), 1000), RangeOutcome::Unsatisfiable);
    }

    #[test]
    fn inverted_range_is_unsatisfiable() {
        assert_eq!(evaluate(Some("bytes=500-100"), 1000), RangeOutcome::Unsatisfiable);
    }

    #[test]
    fn zero_length_suffix_is_unsatisfiable() {
        assert_eq!(evaluate(Some("bytes=-0"), 1000), RangeOutcome::Unsatisfiable);
    }

    #[test]
    fn empty_entity_satisfies_nothing() {
        assert_eq!(evaluate(Some("bytes=0-"), 0), RangeOutcome::Unsatisfiable);
    }

    #[test]
    fn multi_range_falls_back_to_the_whole_entity() {
        assert_eq!(evaluate(Some("bytes=0-99,200-299"), 1000), RangeOutcome::Full);
    }

    #[test]
    fn malformed_ranges_are_ignored_not_rejected() {
        for value in ["bytes=abc-def", "bytes=", "items=0-10", "bytes=-", "bytes=+5-10", "0-10"] {
            assert_eq!(evaluate(Some(value), 1000), RangeOutcome::Full, "value {value:?}");
        }
    }

    #[test]
    fn single_byte_range_has_length_one() {
        let RangeOutcome::Partial(range) = evaluate(Some("bytes=0-0"), 1000) else {
            panic!("expected a partial range");
        };
        assert_eq!(range.len(), 1);
        assert_eq!(range.content_range(1000), "bytes 0-0/1000");
    }

    #[test]
    fn content_range_matches_the_wire_format() {
        let RangeOutcome::Partial(range) = evaluate(Some("bytes=500-"), 1000) else {
            panic!("expected a partial range");
        };
        assert_eq!(range.content_range(1000), "bytes 500-999/1000");
        assert_eq!(range.len(), 500);
    }
}
