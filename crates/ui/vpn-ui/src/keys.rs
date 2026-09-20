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
///
/// `account` is the signed-in identity name (see [`account`]); its own key
/// file is read for the "client" side once someone has signed in, so the
/// fingerprint shown actually matches what the tunnel dials with instead of
/// always reading the generic, unbound `client.pub`.
pub fn identities(account: Option<&str>) -> (Option<Identity>, Option<Identity>) {
    (read_identity(account.unwrap_or("client")), read_identity("server"))
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

/// Where the peer identity is recorded — unchanged path from when this held a
/// hand-typed account name, so `tunnel.rs`'s dialing code and the rotation
/// script (`--identity`) need no changes at all for what the file now means.
fn account_path() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    Some(format!("{home}/.securevpn/account"))
}

/// Where the signed-in account's human-facing label is recorded — separate
/// from [`account_path`], which holds the `peer`/key-file identity: the two
/// no longer need to be the same string once a peer name is derived from the
/// hostname rather than typed by a person.
fn account_label_path() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    Some(format!("{home}/.securevpn/account-label"))
}

/// The peer this install last signed in as, if any — the identity
/// `tunnel::Endpoint` should dial as, the key-file stem, and the roster entry
/// name — instead of the generic, unbound `"client"`.
pub fn account() -> Option<String> {
    let text = std::fs::read_to_string(account_path()?).ok()?;
    let name = text.trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// The human-facing account name the console approved this device under, for
/// the masthead's "@name" — distinct from [`account`], which is the roster
/// `peer`, not something meant for display.
pub fn account_label() -> Option<String> {
    let text = std::fs::read_to_string(account_label_path()?).ok()?;
    let name = text.trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// A `[a-z0-9-]` peer name derived from this device's hostname, for a first
/// sign-in that has no peer recorded yet — mirrors
/// `selfhost_config::vpn::peer_name_problem`'s rule, since this name becomes
/// both a key-file stem and the roster's `peer` value. Runs of anything else
/// collapse to one hyphen; a hostname that sanitizes to nothing at all (or
/// could not be read) falls back to a fixed name rather than an empty one.
///
/// Ends in a short random disambiguator: macOS's factory-default hostname is
/// the same "MacBook-Pro" on every unconfigured Mac, and the roster keys
/// entries on this name alone — two such devices signing in for the first
/// time would otherwise silently overwrite each other's roster entry, one
/// disconnecting the other with no error on either side. The suffix is
/// generated once, at first sign-in, and then persisted in [`account_path`]
/// like the rest of the name, so it never changes underneath an enrolled
/// device.
pub(crate) fn generate_peer_name() -> String {
    let raw = crate::hostname::hostname().unwrap_or_default();
    let host = raw.strip_suffix(".local").unwrap_or(&raw);
    let mut sanitized = String::new();
    let mut last_was_hyphen = true; // swallow a leading separator
    for ch in host.chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_lowercase() || lower.is_ascii_digit() {
            sanitized.push(lower);
            last_was_hyphen = false;
        } else if !last_was_hyphen {
            sanitized.push('-');
            last_was_hyphen = true;
        }
    }
    let sanitized = sanitized.trim_end_matches('-');
    let base = if sanitized.is_empty() { "mac" } else { sanitized };
    // The suffix below adds 7 characters ("-" + 6 hex); truncated here so the
    // combined name never trips `peer_name_problem`'s 32-character ceiling —
    // a long hostname must not turn a sign-in into an opaque 400 from the
    // server over a limit this function already knows about.
    let base: String = base.chars().take(MAX_PEER_NAME_LEN - 7).collect();
    let base = base.trim_end_matches('-');
    format!("{base}-{}", random_suffix())
}

/// Mirrors `selfhost_config::vpn::MAX_PEER_NAME_LEN` — not imported directly
/// to keep this crate's dependency graph free of `selfhost-config`, which
/// pulls in far more than one constant.
const MAX_PEER_NAME_LEN: usize = 32;

/// A short, lowercase hex disambiguator for [`generate_peer_name`] — not a
/// secret, just enough entropy (2^24 values) that two devices with the same
/// sanitized hostname essentially never pick the same roster name.
fn random_suffix() -> String {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut bytes = [0u8; 3];
    if SystemRandom::new().fill(&mut bytes).is_err() {
        // Practically never happens on a real OS RNG; falls back to the
        // process id rather than leaving the name with no disambiguator at
        // all, which would put this back to square one.
        return format!("{:06x}", std::process::id() & 0xff_ffff);
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Records a completed sign-in: `peer` as the identity the tunnel dials and
/// the roster tracks, `label` as the human-facing name for display.
pub(crate) fn set_signed_in(peer: &str, label: &str) -> Result<(), String> {
    let account_path = account_path().ok_or("no HOME")?;
    let label_path = account_label_path().ok_or("no HOME")?;
    if let Some(parent) = std::path::Path::new(&account_path).parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    std::fs::write(&account_path, format!("{peer}\n")).map_err(|error| error.to_string())?;
    std::fs::write(&label_path, format!("{label}\n")).map_err(|error| error.to_string())?;
    Ok(())
}

/// Clears a completed sign-in: the inverse of [`set_signed_in`], for "My
/// devices" removing the device this install itself is.
///
/// Only ever removes the two local label files [`account_path`] and
/// [`account_label_path`] — it holds no private key material to begin with
/// (see this module's own doc comment) and never talks to the network; the
/// server-side half (the roster line, the `.pub` file, the binding, the
/// audit record) is `crates/services/vpn/src/peer_binding.rs`'s
/// `forget_device`, reached only through a signed-in console session, not
/// from this desktop process (see `app::my_devices_screen`'s doc comment for
/// why). A file that is already gone is not an error — signing out twice is
/// still signed out.
pub(crate) fn sign_out() -> Result<(), String> {
    for path in [account_path(), account_label_path()].into_iter().flatten() {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

/// Shells out to Secure-VPN's own key manager to generate (or load) one
/// named identity and print its public key — the one call here that
/// touches private key material, and it never leaves that script's process.
pub(crate) fn generate_named_key(name: &str) -> Result<String, String> {
    let home = std::env::var("HOME").map_err(|_| "no HOME".to_string())?;
    let script = format!("{home}/.securevpn/app/key_manager.py");
    if !std::path::Path::new(&script).exists() {
        return Err("Secure-VPN is not installed (key_manager.py not found)".into());
    }
    let output = Command::new(crate::tunnel::real_python())
        .arg(script)
        .arg("--generate")
        .arg(name)
        .output()
        .map_err(|error| format!("could not generate a key: {error}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let last = stderr.lines().last().unwrap_or("key generation failed");
        return Err(last.to_string());
    }
    // `generate_identity()` prints its own progress lines on a fresh key
    // (an existing one is loaded silently) — the public key is always the
    // last line printed, not the whole of stdout.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let key = stdout.lines().last().unwrap_or("").trim().to_string();
    if key.is_empty() {
        return Err("key generation produced no public key".into());
    }
    Ok(key)
}

/// Runs the rotation script and reports whether it succeeded.
///
/// Blocking — a rotation takes a few seconds and the caller runs it off the
/// window thread. The script is lock-out-proof on its own (it rolls back over
/// SSH), so the worst a failure here does is leave the current key in place.
///
/// Passes `--identity` explicitly as the signed-in account (see [`account`]),
/// falling back to the script's own `client` default when signed out —
/// otherwise a signed-in account's "Rotate now" would silently rotate the
/// unrelated, unbound `client` key instead of the one actually in use.
pub fn rotate() -> Result<(), String> {
    let home = std::env::var("HOME").map_err(|_| "no HOME".to_string())?;
    let script = format!("{home}/.securevpn/rotate-keys.sh");
    if !std::path::Path::new(&script).exists() {
        return Err("rotation script is not installed".into());
    }
    let mut command = Command::new("/bin/bash");
    command.arg(&script);
    if let Some(name) = account() {
        command.arg("--identity").arg(name);
    }
    let output = command.output().map_err(|error| format!("could not run rotation: {error}"))?;
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
