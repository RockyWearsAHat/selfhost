//! The two time formats this crate writes, and nothing else.
//!
//! A report carries an ISO-8601 stamp (what the database and the console read) and a mail
//! message carries an RFC 5322 `Date` (what a mail client reads). Both are derived from the
//! same civil-calendar conversion, in UTC, so a report and the message announcing it can
//! never disagree about when it arrived.
//!
//! Written here rather than pulled from a dependency for the reason the workspace states at
//! the top of `Cargo.toml`: a date is a format, not a protocol, and `selfhost_mail` keeps
//! its own copy private.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, saturating at the epoch for a clock set before it.
fn seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Splits a Unix timestamp into `(year, month, day, hour, minute, second, weekday)`, UTC.
///
/// `weekday` is 0 for Thursday — the epoch's own day — counted forward, which is what the
/// day-name lookup below expects.
fn civil(secs: u64) -> (i64, u32, u32, u32, u32, u32, usize) {
    let days = (secs / 86_400) as i64;
    let rest = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let weekday = ((days % 7) + 7) as usize % 7;
    (
        year,
        month,
        day,
        (rest / 3_600) as u32,
        ((rest % 3_600) / 60) as u32,
        (rest % 60) as u32,
        weekday,
    )
}

/// Days-since-epoch to `(year, month, day)`, proleptic Gregorian, UTC.
///
/// Howard Hinnant's `civil_from_days`: the standard closed form, with no loop over months.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// `time` as an ISO-8601 UTC stamp — `2026-08-11T18:38:13Z`.
///
/// The same shape `dx` writes into its own records, so a report filed by an agent and the
/// row this box stores for it sort together.
#[must_use]
pub fn iso8601(time: SystemTime) -> String {
    let (year, month, day, hour, minute, second, _) = civil(seconds(time));
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// `time` as an RFC 5322 date — `Tue, 11 Aug 2026 18:38:13 +0000`.
///
/// A message with no `Date`, or with one a client cannot parse, sorts to the bottom of an
/// inbox or is filed as spam; this header is the one thing that makes a delivered report
/// arrive *at the top*, which is the whole point of delivering it.
#[must_use]
pub fn rfc5322(time: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (year, month, day, hour, minute, second, weekday) = civil(seconds(time));
    let month_name = MONTHS
        .get(month.saturating_sub(1) as usize)
        .copied()
        .unwrap_or("Jan");
    let day_name = DAYS.get(weekday).copied().unwrap_or("Thu");
    format!("{day_name}, {day:02} {month_name} {year:04} {hour:02}:{minute:02}:{second:02} +0000")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn the_epoch_is_a_thursday_in_january() {
        assert_eq!(iso8601(at(0)), "1970-01-01T00:00:00Z");
        assert_eq!(rfc5322(at(0)), "Thu, 01 Jan 1970 00:00:00 +0000");
    }

    #[test]
    fn a_leap_day_is_the_day_it_says_it_is() {
        // 2024-02-29T12:34:56Z — the case a naive 365-day arithmetic gets wrong.
        assert_eq!(iso8601(at(1_709_210_096)), "2024-02-29T12:34:56Z");
        assert_eq!(
            rfc5322(at(1_709_210_096)),
            "Thu, 29 Feb 2024 12:34:56 +0000"
        );
    }

    #[test]
    fn a_clock_set_before_the_epoch_still_answers() {
        // A report is never dropped because the reporter's clock is wrong.
        let ancient = UNIX_EPOCH - Duration::from_secs(86_400);
        assert_eq!(iso8601(ancient), "1970-01-01T00:00:00Z");
    }
}
