//! The identity keys the tunnel pins, and rotating them.
//!
//! The window shows a short fingerprint of the client and server identities so
//! the operator can tell at a glance which keypair is live, and drives the
//! rotation script that swaps the long-term key. Nothing here holds a private
//! key; it reads the public halves and shells out to the rotation script, which
//! is the one thing that knows how to change a key safely.

use std::process::Command;

/// One pinned identity, as the window names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Which end this is ("client" or "server").
    pub name: String,
    /// A short, stable fingerprint of the public key.
    pub fingerprint: String,
}

/// The client and server fingerprints, each present only if its file is.
pub fn identities() -> (Option<Identity>, Option<Identity>) {
    (read_identity("client"), read_identity("server"))
}

/// Reads one `<name>.pub` from the key directory and fingerprints it.
fn read_identity(name: &str) -> Option<Identity> {
    let home = std::env::var("HOME").ok()?;
    let path = format!("{home}/.securevpn/keys/{name}.pub");
    let text = std::fs::read_to_string(path).ok()?;
    let base64 = text.split_whitespace().nth(1)?;
    Some(Identity { name: name.to_string(), fingerprint: fingerprint(base64) })
}

/// A short fingerprint from a base64 public key: the head and tail of the key
/// itself, which is the honest identifier — no invented hash, and enough to tell
/// two keys apart at a glance.
pub(crate) fn fingerprint(base64: &str) -> String {
    let trimmed = base64.trim_end_matches('=');
    if trimmed.len() <= 14 {
        return trimmed.to_string();
    }
    let head: String = trimmed.chars().take(8).collect();
    let tail: String = trimmed.chars().rev().take(6).collect::<Vec<_>>().into_iter().rev().collect();
    format!("{head}…{tail}")
}

/// When the client key was last rotated, as the rotation script recorded it.
///
/// Reads the same UserDefaults key the script writes on success. `None` means it
/// has not run yet (or the key was set up by hand).
pub fn last_rotation() -> Option<String> {
    let output = Command::new("defaults")
        .args(["read", "com.selfhost.vpn", "lastKeyRotation"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Epoch seconds parsed from a recorded rotation time.
///
/// The rotation script records a civil date-time — "2026-08-01 21:11:03 +0000"
/// as `defaults` prints a date, or ISO "2026-08-01T21:11:03Z" — and this reads
/// the six clock fields plus the offset when one is present. `None` for
/// anything that does not read as a date, so the window falls back to showing
/// the raw record rather than inventing an age.
pub(crate) fn parse_epoch(text: &str) -> Option<i64> {
    let fields: Vec<i64> = text
        .split(|c: char| !c.is_ascii_digit())
        .filter(|run| !run.is_empty())
        .map(|run| run.parse().ok())
        .collect::<Option<Vec<_>>>()?;
    if fields.len() < 6 {
        return None;
    }
    let (year, month, day) = (fields[0], fields[1], fields[2]);
    let (hour, minute, second) = (fields[3], fields[4], fields[5]);
    let in_range = (1970..10000).contains(&year)
        && (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && (0..24).contains(&hour)
        && (0..60).contains(&minute)
        && (0..61).contains(&second);
    if !in_range {
        return None;
    }
    let mut epoch = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
    if let Some(offset) = fields.get(6) {
        // A seventh field is a "+0700"-style offset; the sign is whichever
        // sign character follows the clock, and west of UTC adds to the epoch.
        let seconds = (offset / 100) * 3_600 + (offset % 100) * 60;
        let clock_end = text.rfind(':').unwrap_or(0);
        let west = text[clock_end..].contains('-');
        epoch += if west { seconds } else { -seconds };
    }
    Some(epoch)
}

/// Days between civil `year-month-day` and 1970-01-01, proleptic Gregorian.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_shifted = (month + 9) % 12;
    let day_of_year = (153 * month_shifted + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// A rotation age spoken the way an operator reads a clock: "59s ago",
/// "1m ago", "today 21:11" for earlier the same day, "23h ago" across
/// midnight, "6d ago" beyond that. Both instants are epoch seconds.
pub(crate) fn rotation_age(then: i64, now: i64) -> String {
    let age = (now - then).max(0);
    if age < 60 {
        return format!("{age}s ago");
    }
    if age < 3_600 {
        return format!("{}m ago", age / 60);
    }
    if age < 86_400 {
        if now.div_euclid(86_400) == then.div_euclid(86_400) {
            let clock = then.rem_euclid(86_400);
            return format!("today {:02}:{:02}", clock / 3_600, (clock % 3_600) / 60);
        }
        return format!("{}h ago", age / 3_600);
    }
    format!("{}d ago", age / 86_400)
}

/// Whether a rotation is a week or more old — the AUTO deadline is due, which
/// is the cause for the age reading to turn amber.
pub(crate) fn rotation_stale(then: i64, now: i64) -> bool {
    now - then >= 7 * 86_400
}

/// Runs the rotation script and reports whether it succeeded.
///
/// Blocking — a rotation takes a few seconds and the caller runs it off the
/// window thread. The script is lock-out-proof on its own (it rolls back over
/// SSH), so the worst a failure here does is leave the current key in place.
pub fn rotate() -> Result<(), String> {
    let home = std::env::var("HOME").map_err(|_| "no HOME".to_string())?;
    let script = format!("{home}/.securevpn/rotate-keys.sh");
    if !std::path::Path::new(&script).exists() {
        return Err("rotation script is not installed".into());
    }
    let output = Command::new("/bin/bash")
        .arg(script)
        .output()
        .map_err(|error| format!("could not run rotation: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let last = stderr.lines().last().unwrap_or("rotation failed");
        Err(last.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fingerprint_is_the_head_and_tail_of_the_key() {
        let fp = fingerprint("Vnwx6Avt3DH9aQKLFyTj1e/c02aMxw7igP/JMfFrgYU=");
        assert!(fp.starts_with("Vnwx6Avt"));
        assert!(fp.ends_with("FrgYU"));
        assert!(fp.contains('…'));
    }

    #[test]
    fn a_short_key_is_shown_whole() {
        assert_eq!(fingerprint("abcd="), "abcd");
    }

    /// A whole number of days since the epoch, for building test instants.
    const DAY: i64 = 86_400;

    #[test]
    fn seconds_become_minutes_at_the_minute() {
        let now = 20_000 * DAY;
        assert_eq!(rotation_age(now - 59, now), "59s ago");
        assert_eq!(rotation_age(now - 60, now), "1m ago");
    }

    #[test]
    fn hours_become_days_at_the_day() {
        // An instant just past a UTC midnight, so 23 hours ago is yesterday
        // and reads in hours, not as "today".
        let now = 20_000 * DAY + 600;
        assert_eq!(rotation_age(now - 23 * 3_600, now), "23h ago");
        assert_eq!(rotation_age(now - 24 * 3_600, now), "1d ago");
    }

    #[test]
    fn the_same_day_reads_as_a_clock_time() {
        let then = 20_000 * DAY + 21 * 3_600 + 11 * 60; // today, 21:11 UTC
        let now = then + 2 * 3_600;
        assert_eq!(rotation_age(then, now), "today 21:11");
    }

    #[test]
    fn a_week_old_key_is_stale_and_a_younger_one_is_not() {
        let now = 20_000 * DAY;
        assert!(!rotation_stale(now - (7 * DAY - 1), now));
        assert!(rotation_stale(now - 7 * DAY, now));
        assert_eq!(rotation_age(now - 6 * DAY, now), "6d ago");
    }

    #[test]
    fn a_recorded_date_parses_in_both_shapes_the_script_writes() {
        let iso = parse_epoch("2026-08-01T21:11:03Z").expect("iso form");
        let defaults = parse_epoch("2026-08-01 21:11:03 +0000").expect("defaults form");
        assert_eq!(iso, defaults);
        // 2026-08-01 is 20_666 days after the epoch.
        assert_eq!(iso, 20_666 * DAY + 21 * 3_600 + 11 * 60 + 3);
        // An offset shifts the instant: 21:11 at +0200 is 19:11 UTC.
        let east = parse_epoch("2026-08-01 21:11:03 +0200").expect("east form");
        assert_eq!(east, iso - 2 * 3_600);
    }

    #[test]
    fn words_are_not_a_date() {
        assert_eq!(parse_epoch("not yet"), None);
        assert_eq!(parse_epoch("2026-08-01"), None);
    }
}
