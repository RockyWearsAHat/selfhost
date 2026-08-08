//! Shared civil-calendar math for timestamps written to the wire.
//!
//! Both SMTP's `Received:` trace (RFC 5322) and IMAP's `INTERNALDATE` turn a
//! Unix timestamp into a weekday/date/time; this is the one place that
//! arithmetic lives, so the two can never quietly disagree about what day a
//! given second falls on. No date/time crate is added for this — the
//! dependency policy admits none, and proleptic-Gregorian civil-from-days is
//! a few lines of integer arithmetic, not a library's worth of problem.

use std::time::{SystemTime, UNIX_EPOCH};

/// Weekday names, indexed by days-since-epoch mod 7 — 1970-01-01 was a Thursday.
pub(crate) const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];

/// Month names, indexed by month number minus one.
pub(crate) const MONTHS: [&str; 12] =
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// Seconds since the Unix epoch, floored at zero for a time before it.
pub(crate) fn secs_since_epoch(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Civil calendar fields for a Unix timestamp, in UTC.
///
/// Returns `(weekday, year, month, day, hour, minute, second)`, month 1-12.
pub(crate) fn civil(secs: u64) -> (&'static str, i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, minute, second) =
        ((rem / 3600) as u32, ((rem % 3600) / 60) as u32, (rem % 60) as u32);
    let weekday = WEEKDAYS[(days.rem_euclid(7)) as usize];
    let (year, month, day) = civil_from_days(days);
    (weekday, year, month, day, hour, minute, second)
}

/// Days-since-epoch to (year, month, day), proleptic Gregorian, UTC.
///
/// Howard Hinnant's `civil_from_days` algorithm — the standard closed-form
/// answer for this that avoids a loop over months.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_epoch_days_map_to_the_right_date() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(365), (1971, 1, 1));
    }

    #[test]
    fn nineteen_seventy_jan_one_was_a_thursday() {
        let (weekday, year, month, day, ..) = civil(0);
        assert_eq!((weekday, year, month, day), ("Thu", 1970, 1, 1));
    }

    #[test]
    fn a_time_of_day_within_the_first_day_is_read_correctly() {
        let (.., hour, minute, second) = civil(3_661); // 01:01:01
        assert_eq!((hour, minute, second), (1, 1, 1));
    }
}
