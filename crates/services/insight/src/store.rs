//! The on-disk history: `<data_dir>/insight/<kind>-YYYY-MM-DD.ndjson`, one JSON
//! line per record, one file per UTC day.
//!
//! Appends are one `write` of one line, so a crash loses at most that line and
//! a reader never sees half a record it cannot skip. Reads open only the days
//! the window covers. Old days are pruned when the day rolls over, not on every
//! write. The current problems live beside them in `problems.json`, rewritten
//! whole (temp file, then rename) whenever the set changes.

use crate::{Event, Sample};
use selfhost_json::Json;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Days of samples kept: a week of ten-second history.
pub const KEEP_SAMPLE_DAYS: u64 = 7;

/// Days of timeline kept. Events are rare, so a month is cheap.
pub const KEEP_EVENT_DAYS: u64 = 30;

/// How much of the newest file a "latest" read looks at: a few minutes of samples.
const TAIL_BYTES: u64 = 64 * 1024;

const DAY: u64 = 86_400;

/// The insight directory under a data directory.
pub fn dir(data_dir: &Path) -> PathBuf {
    data_dir.join("insight")
}

/// Appends records and prunes old days. One per writer.
pub struct Store {
    dir: PathBuf,
    pruned_through: Option<u64>,
}

impl Store {
    /// A store writing under `<data_dir>/insight/`.
    pub fn new(data_dir: &Path) -> Self {
        Self { dir: dir(data_dir), pruned_through: None }
    }

    /// Appends one sample to its day's file.
    pub fn append_sample(&mut self, sample: &Sample) -> io::Result<()> {
        self.append("samples", sample.at_unix, &sample.to_json())
    }

    /// Appends one event to its day's file.
    pub fn append_event(&mut self, event: &Event) -> io::Result<()> {
        self.append("events", event.at_unix, &event.to_json())
    }

    fn append(&mut self, kind: &str, at_unix: u64, record: &Json) -> io::Result<()> {
        let day = at_unix / DAY;
        if self.pruned_through != Some(day) {
            fs::create_dir_all(&self.dir)?;
            prune(&self.dir, day)?;
            self.pruned_through = Some(day);
        }
        let mut line = record.to_text();
        line.push('\n');
        OpenOptions::new().create(true).append(true).open(self.dir.join(file_name(kind, day)))?.write_all(line.as_bytes())
    }
}

/// Writes `contents` to `path` whole: a reader sees the old file or the new
/// one, never a partial write.
pub fn replace(path: &Path, contents: &str) -> io::Result<()> {
    let temp = path.with_extension(format!("{}.tmp", std::process::id()));
    fs::write(&temp, contents)?;
    fs::rename(&temp, path)
}

fn prune(dir: &Path, today: u64) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let name = entry?.file_name();
        let Some((kind, day)) = name.to_str().and_then(parse_file_name) else {
            continue;
        };
        let keep = if kind == "samples" { KEEP_SAMPLE_DAYS } else { KEEP_EVENT_DAYS };
        if day + keep <= today {
            // Best effort: a file another reader holds open on Windows is
            // pruned on a later rollover instead.
            let _ = fs::remove_file(dir.join(&name));
        }
    }
    Ok(())
}

/// Samples with `since <= at_unix < until`, oldest first.
pub fn read_samples(data_dir: &Path, since: u64, until: u64) -> io::Result<Vec<Sample>> {
    read_window(data_dir, "samples", since, until, Sample::from_json, |sample| sample.at_unix)
}

/// Events with `since <= at_unix < until`, oldest first.
pub fn read_events(data_dir: &Path, since: u64, until: u64) -> io::Result<Vec<Event>> {
    read_window(data_dir, "events", since, until, Event::from_json, |event| event.at_unix)
}

fn read_window<T>(
    data_dir: &Path,
    kind: &str,
    since: u64,
    until: u64,
    parse: impl Fn(&Json) -> Option<T>,
    at: impl Fn(&T) -> u64,
) -> io::Result<Vec<T>> {
    let dir = dir(data_dir);
    let mut found = Vec::new();
    if until <= since {
        return Ok(found);
    }
    for day in since / DAY..=(until - 1) / DAY {
        let file = match File::open(dir.join(file_name(kind, day))) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for line in BufReader::new(file).lines() {
            // An unreadable line (a torn final write) is skipped, not fatal.
            if let Some(record) = selfhost_json::parse(&line?).ok().as_ref().and_then(&parse) {
                if (since..until).contains(&at(&record)) {
                    found.push(record);
                }
            }
        }
    }
    found.sort_by_key(|record| at(record));
    Ok(found)
}

/// The newest sample that matches `wanted`, looking only at the last few
/// minutes of today's file (or yesterday's, just after midnight).
pub fn latest_sample(data_dir: &Path, now_unix: u64, wanted: impl Fn(&Sample) -> bool) -> io::Result<Option<Sample>> {
    let dir = dir(data_dir);
    for day in [now_unix / DAY, (now_unix / DAY).saturating_sub(1)] {
        let mut file = match File::open(dir.join(file_name("samples", day))) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let length = file.metadata()?.len();
        let start = length.saturating_sub(TAIL_BYTES);
        file.seek(SeekFrom::Start(start))?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        // Lossy: the seek can land inside a multi-byte character.
        let tail = String::from_utf8_lossy(&bytes);
        // When the read began mid-file its first line is a fragment.
        let skip = usize::from(start > 0);
        if let Some(sample) = tail
            .lines()
            .skip(skip)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .filter_map(|line| Sample::from_json(&selfhost_json::parse(line).ok()?))
            .find(|sample| wanted(sample))
        {
            return Ok(Some(sample));
        }
    }
    Ok(None)
}

fn file_name(kind: &str, day: u64) -> String {
    let (year, month, date) = civil_from_days(day);
    format!("{kind}-{year:04}-{month:02}-{date:02}.ndjson")
}

fn parse_file_name(name: &str) -> Option<(&str, u64)> {
    let stem = name.strip_suffix(".ndjson")?;
    let (kind, date) = stem.split_once('-')?;
    let mut parts = date.splitn(3, '-').map(|part| part.parse::<u64>().ok());
    let (year, month, day) = (parts.next()??, parts.next()??, parts.next()??);
    Some((kind, days_from_civil(year, month, day)?))
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian (Howard
/// Hinnant's algorithm).
pub(crate) fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// The inverse of [`civil_from_days`]; `None` for an impossible date.
pub(crate) fn days_from_civil(year: u64, month: u64, day: u64) -> Option<u64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || year < 1970 {
        return None;
    }
    let year = if month <= 2 { year - 1 } else { year };
    let era = year / 400;
    let yoe = year - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era * 146_097 + doe).checked_sub(719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("selfhost-insight-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn sample(at_unix: u64) -> Sample {
        Sample { at_unix, mem_total_mb: 100, ..Sample::default() }
    }

    #[test]
    fn calendar_round_trips() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(file_name("samples", 20_364), "samples-2025-10-03.ndjson");
        for day in [0, 59, 60, 365, 11_016, 20_364, 40_000] {
            let (y, m, d) = civil_from_days(day);
            assert_eq!(days_from_civil(y, m, d), Some(day));
        }
        assert_eq!(parse_file_name("events-2025-10-03.ndjson"), Some(("events", 20_364)));
        assert_eq!(parse_file_name("dns-stats.json"), None);
    }

    #[test]
    fn a_window_reads_only_its_days_and_bounds() {
        let data = temp_dir("window");
        let mut store = Store::new(&data);
        for at in [DAY * 100 - 5, DAY * 100 + 5, DAY * 100 + 15, DAY * 101 + 1] {
            store.append_sample(&sample(at)).unwrap();
        }
        let got: Vec<u64> = read_samples(&data, DAY * 100, DAY * 100 + 15).unwrap().iter().map(|s| s.at_unix).collect();
        assert_eq!(got, vec![DAY * 100 + 5]);
        let all = read_samples(&data, 0, DAY * 102).unwrap();
        assert_eq!(all.len(), 4);
        fs::remove_dir_all(&data).unwrap();
    }

    #[test]
    fn rollover_prunes_old_days_and_keeps_events_longer() {
        let data = temp_dir("prune");
        let mut store = Store::new(&data);
        store.append_sample(&sample(DAY * 100)).unwrap();
        let event = Event { at_unix: DAY * 100, kind: "warning".into(), source: "x".into(), title: "t".into(), evidence: Json::Null };
        store.append_event(&event).unwrap();
        store.append_sample(&sample(DAY * (100 + KEEP_SAMPLE_DAYS))).unwrap();
        assert_eq!(read_samples(&data, 0, DAY * 200).unwrap().len(), 1, "the old day is gone");
        assert_eq!(read_events(&data, 0, DAY * 200).unwrap().len(), 1, "events outlive samples");
        fs::remove_dir_all(&data).unwrap();
    }

    #[test]
    fn latest_skips_a_torn_line_and_finds_the_newest_match() {
        let data = temp_dir("latest");
        let mut store = Store::new(&data);
        let mut with_processes = sample(DAY * 100 + 10);
        with_processes.processes.push(crate::ProcessSample { pid: 1, name: "selfhost.exe".into(), ..Default::default() });
        store.append_sample(&with_processes).unwrap();
        store.append_sample(&sample(DAY * 100 + 20)).unwrap();
        let path = dir(&data).join(file_name("samples", 100));
        OpenOptions::new().append(true).open(&path).unwrap().write_all(b"{\"at_unix\": 9").unwrap();

        let newest = latest_sample(&data, DAY * 100 + 25, |_| true).unwrap().unwrap();
        assert_eq!(newest.at_unix, DAY * 100 + 20);
        let ranked = latest_sample(&data, DAY * 100 + 25, |s| !s.processes.is_empty()).unwrap().unwrap();
        assert_eq!(ranked.at_unix, DAY * 100 + 10);
        assert!(latest_sample(&data, DAY * 300, |_| true).unwrap().is_none());
        fs::remove_dir_all(&data).unwrap();
    }
}
