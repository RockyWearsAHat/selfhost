//! HTTP dates.
//!
//! `Last-Modified`, `If-Modified-Since`, and `Date` all use the fixed format
//! from RFC 9110 §5.6.7 — `Sun, 26 Jul 2026 18:09:28 GMT`. It is always GMT,
//! always this exact spelling, and always English day and month names
//! regardless of the machine's locale.
//!
//! Written here rather than pulled from a date library because the entire
//! requirement is one conversion in each direction over a fixed grammar, and a
//! calendar library brings a timezone database along with it.
//!
//! The civil-date conversion is Howard Hinnant's `days_from_civil` /
//! `civil_from_days`, which is exact for every date in range and avoids the
//! leap-year special cases that hand-rolled versions get wrong.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DAY_NAMES: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
const MONTH_NAMES: [&str; 12] =
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// Converts a day count since 1970-01-01 into a civil year, month, and day.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    // Shift the epoch to 0000-03-01 so leap days land at the end of the cycle.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Converts a civil year, month, and day into a day count since 1970-01-01.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = (year - era * 400) as u64;
    let month = month as u64;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day as u64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era as i64 - 719_468
}

/// Formats a system time as an HTTP date.
///
/// Times before the Unix epoch cannot appear in a valid HTTP date, so they are
/// clamped to the epoch rather than producing a nonsensical string.
pub fn format(time: SystemTime) -> String {
    let seconds = time.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs() as i64;
    format_unix(seconds)
}

/// Formats a count of seconds since the Unix epoch as an HTTP date.
pub fn format_unix(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let time_of_day = seconds.rem_euclid(86_400);

    let (year, month, day) = civil_from_days(days);
    // 1970-01-01 was a Thursday, which is index 3 in a Monday-first table.
    let weekday = (days + 3).rem_euclid(7) as usize;

    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        DAY_NAMES[weekday],
        day,
        MONTH_NAMES[(month - 1) as usize],
        year,
        time_of_day / 3600,
        (time_of_day % 3600) / 60,
        time_of_day % 60,
    )
}

/// Parses an HTTP date into seconds since the Unix epoch.
///
/// Only the preferred `IMF-fixdate` form is accepted. The two obsolete formats
/// are deliberately not parsed: both are ambiguous about the century, and a
/// misread `If-Modified-Since` serves a stale page rather than failing loudly.
/// Returning `None` makes the caller fall back to sending the full response,
/// which is always correct.
pub fn parse(text: &str) -> Option<i64> {
    let text = text.trim();
    // "Sun, 26 Jul 2026 18:09:28 GMT"
    let rest = text.get(5..)?;
    let mut parts = rest.split(' ');

    let day: u32 = parts.next()?.parse().ok()?;
    let month_name = parts.next()?;
    let year: i64 = parts.next()?.parse().ok()?;
    let clock = parts.next()?;
    if parts.next()? != "GMT" {
        return None;
    }

    let month = MONTH_NAMES.iter().position(|m| *m == month_name)? as u32 + 1;
    if !(1..=31).contains(&day) {
        return None;
    }

    let mut clock_parts = clock.split(':');
    let hour: i64 = clock_parts.next()?.parse().ok()?;
    let minute: i64 = clock_parts.next()?.parse().ok()?;
    let second: i64 = clock_parts.next()?.parse().ok()?;
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Builds a weak entity tag from a file's size and modification time.
///
/// Weak, because two files with the same size and mtime are equivalent for
/// caching but not guaranteed byte-identical — a strong tag would be a lie that
/// breaks range requests when it turns out to be wrong.
pub fn entity_tag(size: u64, modified: Option<SystemTime>) -> String {
    let stamp = modified
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("W/\"{size:x}-{stamp:x}\"")
}

/// Whether an `If-None-Match` value matches an entity tag.
///
/// `*` matches any existing representation. Comparison is weak, so `W/"abc"` and
/// `"abc"` are the same tag — which is what the specification requires for the
/// cache validation this is used for.
pub fn if_none_match_matches(header: &str, tag: &str) -> bool {
    let strip = |t: &str| t.trim().trim_start_matches("W/").trim_matches('"').to_owned();
    let wanted = strip(tag);
    header.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == "*" || strip(candidate) == wanted
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_the_epoch() {
        assert_eq!(format_unix(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn formats_a_known_instant() {
        // 2026-07-26T18:09:28Z — a Sunday.
        assert_eq!(format_unix(1_785_089_368), "Sun, 26 Jul 2026 18:09:28 GMT");
    }

    #[test]
    fn round_trips() {
        for stamp in [0_i64, 1, 86_399, 86_400, 951_782_400, 1_785_089_368, 2_000_000_000] {
            let text = format_unix(stamp);
            assert_eq!(parse(&text), Some(stamp), "round trip failed for {text}");
        }
    }

    #[test]
    fn handles_leap_days() {
        // 2000-02-29 — a leap year divisible by 400, the case naive
        // implementations get wrong.
        let stamp = 951_782_400;
        assert_eq!(format_unix(stamp), "Tue, 29 Feb 2000 00:00:00 GMT");
        assert_eq!(parse("Tue, 29 Feb 2000 00:00:00 GMT"), Some(stamp));
    }

    #[test]
    fn handles_a_century_that_is_not_a_leap_year() {
        // 1900 was divisible by 4 but not a leap year.
        assert_eq!(parse("Thu, 01 Mar 1900 00:00:00 GMT"), Some(-2_203_891_200));
    }

    #[test]
    fn rejects_obsolete_and_malformed_forms() {
        // Obsolete two-digit-year formats are ambiguous about the century, and
        // a misread date serves a stale page rather than failing loudly.
        for text in [
            "Sunday, 26-Jul-26 18:09:28 GMT",
            "Sun Jul 26 18:09:28 2026",
            "not a date",
            "",
            "Sun, 26 Jul 2026 18:09:28 PST",
            "Sun, 26 Xxx 2026 18:09:28 GMT",
            "Sun, 26 Jul 2026 25:09:28 GMT",
        ] {
            assert_eq!(parse(text), None, "accepted {text:?}");
        }
    }

    #[test]
    fn entity_tags_change_when_the_file_does() {
        let time = UNIX_EPOCH + Duration::from_secs(1_785_089_368);
        let later = UNIX_EPOCH + Duration::from_secs(1_785_089_369);

        let base = entity_tag(1000, Some(time));
        assert_ne!(base, entity_tag(1001, Some(time)), "size change ignored");
        assert_ne!(base, entity_tag(1000, Some(later)), "mtime change ignored");
        assert_eq!(base, entity_tag(1000, Some(time)), "not stable");
        // Weak, because equal size and mtime does not guarantee equal bytes.
        assert!(base.starts_with("W/\""));
    }

    #[test]
    fn if_none_match_compares_weakly() {
        let tag = "W/\"3e8-6884a1d8\"";
        assert!(if_none_match_matches(tag, tag));
        assert!(if_none_match_matches("\"3e8-6884a1d8\"", tag), "strong form should match weak");
        assert!(if_none_match_matches("*", tag));
        assert!(if_none_match_matches("W/\"other\", W/\"3e8-6884a1d8\"", tag), "list form");
        assert!(!if_none_match_matches("W/\"different\"", tag));
        assert!(!if_none_match_matches("", tag));
    }
}
