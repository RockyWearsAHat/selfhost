//! A compact UTC log timestamp, matching the format every other subsystem's
//! log lines carry (`selfhost_mail::time::stamp`).
//!
//! Not shared with `mail` directly: `mail` depends on `dns`, not the other
//! way around, so `dns` cannot call into `mail` for this without a cycle. The
//! date math itself is not duplicated a second time *within* this crate,
//! though — [`crate::zone::civil_from_days`] already exists (it stamps the
//! SOA serial), so this reuses it rather than keeping its own copy.

use crate::zone::civil_from_days;
use std::time::{SystemTime, UNIX_EPOCH};

/// Formats a Unix timestamp as the compact UTC log stamp, `MM-DD HH:MM:SSZ`.
///
/// Every narrated log line carries this prefix so an operator can correlate
/// events across the daemon's streams (mail, ACME, proxy, DNS) and against
/// client logs; without it an intermittent failure has no timeline at all.
/// Split from [`stamp`] so the formatting can be tested against a fixed
/// second count rather than the wall clock.
fn format_stamp(secs: u64) -> String {
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (hour, minute, second) = ((rem / 3600) as u32, ((rem % 3600) / 60) as u32, (rem % 60) as u32);
    let (_, month, day) = civil_from_days(days as i64);
    format!("{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}Z")
}

/// The current moment as a compact UTC log stamp — see [`format_stamp`].
pub(crate) fn stamp() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format_stamp(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_known_epoch_second_formats_as_the_right_calendar_stamp() {
        // 2024-02-29 01:01:01 UTC = 1_709_168_461 seconds since the epoch —
        // exercises the leap-day path through the shared civil_from_days.
        assert_eq!(format_stamp(1_709_168_461), "02-29 01:01:01Z");
    }
}
