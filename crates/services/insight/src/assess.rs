//! What is wrong right now, and since when.
//!
//! Each sample is checked against a fixed set of conditions. A condition must
//! hold for its `raise_after` consecutive observations to become a problem,
//! so one busy second is not a warning, and must be absent for
//! [`CLEAR_AFTER`] to clear, so the timeline does not flap. Raising and
//! clearing are the only things written to the timeline; the problem's
//! evidence carries the numbers behind it.

use crate::json::{num, real, text};
use crate::store::{self, latest_sample};
use crate::{Event, ProcessSample, Sample};
use selfhost_json::Json;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::path::Path;

/// Absent this many observations in a row, a problem clears.
const CLEAR_AFTER: u32 = 3;
/// Whole-machine CPU this busy for a minute is saturation.
const CPU_SATURATED_PCT: f64 = 95.0;
/// Memory or commit this full is one allocation from failure.
const MEMORY_HIGH_PCT: f64 = 90.0;
/// A disk below this share free, or below [`DISK_LOW_MB`], is low.
const DISK_LOW_PCT: f64 = 10.0;
const DISK_LOW_MB: u64 = 5 * 1024;
/// A disk projected to fill within this many hours is filling.
const DISK_FILLING_HOURS: f64 = 24.0;
/// Discarded packets per sample worth reporting. A few are routine.
const NET_DISCARDS: u64 = 100;
/// A selfhost process busier than this is not idle. Idle means idle (§2.2).
const SELFHOST_BUSY_CORES: f64 = 0.25;
/// Private memory this many times its recent low, and this much above it, is
/// a climb.
const CLIMB_RATIO: f64 = 1.5;
const CLIMB_MB: u64 = 200;
/// Handles a selfhost process should never need.
const SELFHOST_HANDLES: u32 = 5000;
/// DNS failures above this share of queries in five minutes is failing.
const DNS_FAILING_PCT: f64 = 1.0;
/// Answers slower than 500 ms above this share is slow.
const DNS_SLOW_PCT: f64 = 5.0;
/// Fewer queries than this in five minutes says nothing either way.
const DNS_MIN_QUERIES: u64 = 20;
/// A resolver that has not written its stats for this long has stopped.
const DNS_STALE_SECS: u64 = 60;
/// A sampler that has not written for this long has stopped.
const SAMPLER_STALE_SECS: u64 = 60;
/// A component repaired this many times within [`FLAP_WINDOW_SECS`] is
/// flapping: each repair works, briefly, and the cause is still there.
pub const FLAP_REPAIRS: usize = 3;
/// The window [`FLAP_REPAIRS`] is counted over.
pub const FLAP_WINDOW_SECS: u64 = 1800;
/// Trend history: one point per this many seconds, this many points.
const TREND_STEP_SECS: u64 = 300;
const TREND_POINTS: usize = 25;

/// A condition that is true now, with the numbers that show it.
#[derive(Debug, Clone, PartialEq)]
pub struct Problem {
    /// Stable while the condition lasts (`memory_high`, `disk_low:C:\`).
    pub id: String,
    /// One sentence a person reads.
    pub title: String,
    /// Unix seconds when the condition was first observed.
    pub since_unix: u64,
    /// The measurements behind the title.
    pub evidence: Json,
}

impl Problem {
    /// The JSON form.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("id", text(&self.id)),
            ("title", text(&self.title)),
            ("since_unix", num(self.since_unix)),
            ("evidence", self.evidence.clone()),
        ])
    }

    fn from_json(json: &Json) -> Option<Self> {
        Some(Self {
            id: json.get("id")?.as_str()?.to_owned(),
            title: json.get("title")?.as_str()?.to_owned(),
            since_unix: json.get("since_unix")?.as_u64()?,
            evidence: json.get("evidence").cloned().unwrap_or(Json::Null),
        })
    }
}

/// Which observations a condition is judged on. A process condition is only
/// judged on samples that carry a process ranking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Machine,
    Processes,
    Dns,
    Repairs,
}

struct Finding {
    id: String,
    family: Family,
    raise_after: u32,
    title: String,
    evidence: Json,
}

struct Track {
    family: Family,
    streak: u32,
    quiet: u32,
    first_seen: u64,
    raised: Option<Problem>,
}

/// Remembers recent observations and decides which problems are current.
#[derive(Default)]
pub struct Assessor {
    tracks: BTreeMap<String, Track>,
    disk_trend: HashMap<String, VecDeque<(u64, u64)>>,
    private_trend: HashMap<u32, VecDeque<(u64, u64)>>,
    dns_dropped: Option<(u64, u64, u64)>,
}

impl Assessor {
    /// An assessor with no history.
    pub fn new() -> Self {
        Self::default()
    }

    /// Judges one sample, with the resolver's `dns-stats.json` when it writes
    /// one, and the timeline's repairs of the last [`FLAP_WINDOW_SECS`] when
    /// they were read (`None` leaves flapping unjudged this time). Returns the
    /// timeline entries for problems raised or cleared.
    pub fn observe(&mut self, sample: &Sample, dns: Option<&Json>, repairs: Option<&[Event]>) -> Vec<Event> {
        let at = sample.at_unix;
        let mut findings = self.machine(sample);
        let mut judged = vec![Family::Machine, Family::Dns];
        if !sample.processes.is_empty() {
            judged.push(Family::Processes);
            findings.extend(self.processes(at, &sample.processes));
        }
        findings.extend(self.dns(at, dns));
        if let Some(repairs) = repairs {
            judged.push(Family::Repairs);
            findings.extend(flapping(at, repairs));
        }

        let mut timeline = Vec::new();
        let found: Vec<String> = findings.iter().map(|finding| finding.id.clone()).collect();
        for finding in findings {
            let track = self.tracks.entry(finding.id.clone()).or_insert(Track {
                family: finding.family,
                streak: 0,
                quiet: 0,
                first_seen: at,
                raised: None,
            });
            track.streak += 1;
            track.quiet = 0;
            let problem = Problem { id: finding.id, title: finding.title, since_unix: track.first_seen, evidence: finding.evidence };
            if track.raised.is_none() && track.streak < finding.raise_after {
                continue;
            }
            if track.raised.is_none() {
                timeline.push(Event {
                    at_unix: at,
                    kind: "warning".to_owned(),
                    source: problem.id.clone(),
                    title: problem.title.clone(),
                    evidence: problem.evidence.clone(),
                });
            }
            track.raised = Some(problem);
        }

        // Conditions judged this time but not found count towards clearing; an
        // unraised one is simply forgotten, so its streak starts over.
        let mut finished = Vec::new();
        for (id, track) in &mut self.tracks {
            if !judged.contains(&track.family) || found.contains(id) {
                continue;
            }
            track.streak = 0;
            let Some(problem) = &track.raised else {
                finished.push(id.clone());
                continue;
            };
            track.quiet += 1;
            if track.quiet >= CLEAR_AFTER {
                timeline.push(Event {
                    at_unix: at,
                    kind: "cleared".to_owned(),
                    source: id.clone(),
                    title: format!("Cleared: {}", problem.title),
                    evidence: Json::object([("lasted_secs", num(at.saturating_sub(problem.since_unix)))]),
                });
                finished.push(id.clone());
            }
        }
        for id in finished {
            self.tracks.remove(&id);
        }
        timeline
    }

    /// The problems raised and not yet cleared.
    pub fn problems(&self) -> Vec<Problem> {
        self.tracks.values().filter_map(|track| track.raised.clone()).collect()
    }

    fn machine(&mut self, sample: &Sample) -> Vec<Finding> {
        let at = sample.at_unix;
        let mut found = Vec::new();
        if let Some(cpu) = sample.cpu_pct.filter(|cpu| *cpu >= CPU_SATURATED_PCT) {
            found.push(Finding {
                id: "cpu_saturated".into(),
                family: Family::Machine,
                raise_after: 6,
                title: format!("CPU {cpu:.0}% busy for over a minute"),
                evidence: Json::object([("cpu_pct", real(cpu))]),
            });
        }
        if sample.mem_total_mb > 0 && sample.mem_pct() >= MEMORY_HIGH_PCT {
            found.push(Finding {
                id: "memory_high".into(),
                family: Family::Machine,
                raise_after: 3,
                title: format!("Memory {:.0}% used ({} of {} MB)", sample.mem_pct(), sample.mem_used_mb, sample.mem_total_mb),
                evidence: Json::object([("used_mb", num(sample.mem_used_mb)), ("total_mb", num(sample.mem_total_mb))]),
            });
        }
        if sample.commit_limit_mb > 0 && sample.commit_pct() >= MEMORY_HIGH_PCT {
            found.push(Finding {
                id: "commit_high".into(),
                family: Family::Machine,
                raise_after: 3,
                title: format!(
                    "Commit charge {:.0}% of its limit ({} of {} MB): allocations will start failing",
                    sample.commit_pct(),
                    sample.commit_used_mb,
                    sample.commit_limit_mb
                ),
                evidence: Json::object([("used_mb", num(sample.commit_used_mb)), ("limit_mb", num(sample.commit_limit_mb))]),
            });
        }
        for disk in &sample.disks {
            let evidence = Json::object([("mount", text(&disk.mount)), ("free_mb", num(disk.free_mb)), ("total_mb", num(disk.total_mb))]);
            if disk.total_mb > 0 && (disk.free_pct() < DISK_LOW_PCT || disk.free_mb < DISK_LOW_MB) {
                found.push(Finding {
                    id: format!("disk_low:{}", disk.mount),
                    family: Family::Machine,
                    raise_after: 1,
                    title: format!("Disk {} has {} MB free ({:.1}%)", disk.mount, disk.free_mb, disk.free_pct()),
                    evidence: evidence.clone(),
                });
            }
            let trend = self.disk_trend.entry(disk.mount.clone()).or_default();
            push_trend(trend, at, disk.free_mb);
            if let Some(hours) = hours_until_empty(trend) {
                found.push(Finding {
                    id: format!("disk_filling:{}", disk.mount),
                    family: Family::Machine,
                    raise_after: 1,
                    title: format!("Disk {} will be full in about {hours:.0} h at the current rate", disk.mount),
                    evidence,
                });
            }
        }
        for adapter in &sample.net {
            if adapter.errors > 0 || adapter.discards >= NET_DISCARDS {
                found.push(Finding {
                    id: format!("net_errors:{}", adapter.name),
                    family: Family::Machine,
                    raise_after: 3,
                    title: format!(
                        "Adapter {} is dropping traffic ({} errors, {} discards in 10 s)",
                        adapter.name, adapter.errors, adapter.discards
                    ),
                    evidence: Json::object([("errors", num(adapter.errors)), ("discards", num(adapter.discards))]),
                });
            }
        }
        found
    }

    fn processes(&mut self, at: u64, processes: &[ProcessSample]) -> Vec<Finding> {
        let mut found = Vec::new();
        let ours: Vec<&ProcessSample> = processes.iter().filter(|p| crate::sys::is_selfhost(&p.name)).collect();
        self.private_trend.retain(|pid, _| ours.iter().any(|p| p.pid == *pid));
        for process in ours {
            let who = format!("{} (pid {})", process.name, process.pid);
            let evidence = process.to_json();
            if process.cpu_cores >= SELFHOST_BUSY_CORES {
                found.push(Finding {
                    id: format!("selfhost_busy:{}", process.pid),
                    family: Family::Processes,
                    raise_after: 2,
                    title: format!("{who} is using {:.2} cores while it should idle", process.cpu_cores),
                    evidence: evidence.clone(),
                });
            }
            if process.handles >= SELFHOST_HANDLES {
                found.push(Finding {
                    id: format!("selfhost_handles:{}", process.pid),
                    family: Family::Processes,
                    raise_after: 2,
                    title: format!("{who} holds {} handles: a leak", process.handles),
                    evidence: evidence.clone(),
                });
            }
            let trend = self.private_trend.entry(process.pid).or_default();
            push_trend(trend, at, process.private_mb);
            let low = trend.iter().map(|(_, mb)| *mb).min().unwrap_or(0);
            let span = trend.back().map_or(0, |(t, _)| *t) - trend.front().map_or(0, |(t, _)| *t);
            if span >= 3600 && process.private_mb as f64 > low as f64 * CLIMB_RATIO && process.private_mb >= low + CLIMB_MB {
                found.push(Finding {
                    id: format!("selfhost_memory_climbing:{}", process.pid),
                    family: Family::Processes,
                    raise_after: 1,
                    title: format!("{who} private memory climbed from {low} MB to {} MB", process.private_mb),
                    evidence,
                });
            }
        }
        found
    }

    fn dns(&mut self, at: u64, stats: Option<&Json>) -> Vec<Finding> {
        let Some(stats) = stats else {
            return Vec::new();
        };
        let mut found = Vec::new();
        let written = stats.get("at_unix").and_then(Json::as_u64).unwrap_or(0);
        let process = stats.get("process").and_then(Json::as_str).unwrap_or("dns");
        if at.saturating_sub(written) > DNS_STALE_SECS {
            found.push(Finding {
                id: "dns_stopped".into(),
                family: Family::Dns,
                raise_after: 1,
                title: format!("The {process} resolver has not reported for {} s: it is down or hung", at.saturating_sub(written)),
                evidence: Json::object([("last_report_unix", num(written))]),
            });
            return found;
        }
        let window = dns_window(stats, at);
        if window.queries >= DNS_MIN_QUERIES {
            let failing = window.failures as f64 * 100.0 / window.queries as f64;
            if failing > DNS_FAILING_PCT {
                found.push(Finding {
                    id: "dns_failing".into(),
                    family: Family::Dns,
                    raise_after: 1,
                    title: format!("{failing:.1}% of DNS queries failed in the last 5 minutes ({} of {})", window.failures, window.queries),
                    evidence: window.to_json(),
                });
            }
            let slow = window.slow as f64 * 100.0 / window.queries as f64;
            if slow > DNS_SLOW_PCT {
                found.push(Finding {
                    id: "dns_slow".into(),
                    family: Family::Dns,
                    raise_after: 1,
                    title: format!("{slow:.1}% of DNS answers took over 500 ms in the last 5 minutes"),
                    evidence: window.to_json(),
                });
            }
        }
        let counter = |key: &str| stats.get("counters").and_then(|c| c.get(key)).and_then(Json::as_u64).unwrap_or(0);
        let losses = (counter("dropped"), counter("recv_errors"), counter("loops"));
        if let Some(before) = self.dns_dropped.replace(losses) {
            let dropped = losses.0.saturating_sub(before.0);
            let errors = losses.1.saturating_sub(before.1);
            let loops = losses.2.saturating_sub(before.2);
            if loops > 0 {
                found.push(Finding {
                    id: "dns_loop".into(),
                    family: Family::Dns,
                    raise_after: 1,
                    title: format!(
                        "An upstream resolver sent {loops} of our own forwarded questions back to us: it forwards to this machine"
                    ),
                    evidence: Json::object([("loops", num(loops)), ("upstreams", stats.get("upstreams").cloned().unwrap_or(Json::Null))]),
                });
            }
            if dropped + errors > 0 {
                found.push(Finding {
                    id: "dns_dropping".into(),
                    family: Family::Dns,
                    raise_after: 1,
                    title: format!("The resolver turned away {dropped} queries and hit {errors} receive errors in 10 s"),
                    evidence: Json::object([("dropped", num(dropped)), ("recv_errors", num(errors))]),
                });
            }
        }
        found
    }
}

fn push_trend(trend: &mut VecDeque<(u64, u64)>, at: u64, value: u64) {
    if trend.back().is_none_or(|(last, _)| at >= last + TREND_STEP_SECS) {
        trend.push_back((at, value));
        if trend.len() > TREND_POINTS {
            trend.pop_front();
        }
    }
}

/// Hours until a disk's free space reaches zero, if it has been falling for
/// at least half an hour fast enough to get there within a day.
fn hours_until_empty(trend: &VecDeque<(u64, u64)>) -> Option<f64> {
    let (start, first) = *trend.front()?;
    let (end, last) = *trend.back()?;
    if end < start + 1800 || last >= first {
        return None;
    }
    let mb_per_hour = (first - last) as f64 * 3600.0 / (end - start) as f64;
    let hours = last as f64 / mb_per_hour;
    (hours < DISK_FILLING_HOURS).then_some(hours)
}

/// The resolver's last five minutes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct DnsWindow {
    queries: u64,
    failures: u64,
    slow: u64,
}

impl DnsWindow {
    fn to_json(self) -> Json {
        Json::object([("queries", num(self.queries)), ("failures", num(self.failures)), ("slow", num(self.slow))])
    }
}

/// One finding per component repaired [`FLAP_REPAIRS`] or more times in the
/// window ending at `at`.
fn flapping(at: u64, events: &[Event]) -> Vec<Finding> {
    let mut by_source: BTreeMap<&str, Vec<&Event>> = BTreeMap::new();
    for event in events {
        if event.kind == "repair" && event.at_unix + FLAP_WINDOW_SECS > at && event.at_unix <= at {
            by_source.entry(&event.source).or_default().push(event);
        }
    }
    by_source
        .into_iter()
        .filter(|(_, repairs)| repairs.len() >= FLAP_REPAIRS)
        .map(|(source, repairs)| {
            let last = repairs.iter().max_by_key(|event| event.at_unix).expect("at least FLAP_REPAIRS");
            Finding {
                id: format!("flapping:{source}"),
                family: Family::Repairs,
                raise_after: 1,
                title: format!("{source} was repaired {} times in {} minutes: the cause is still there", repairs.len(), FLAP_WINDOW_SECS / 60),
                evidence: Json::object([
                    ("repairs", num(repairs.len() as u64)),
                    ("window_secs", num(FLAP_WINDOW_SECS)),
                    ("last", text(&last.title)),
                ]),
            }
        })
        .collect()
}

fn dns_window(stats: &Json, now: u64) -> DnsWindow {
    let mut window = DnsWindow::default();
    for minute in stats.get("minutes").and_then(Json::as_array).unwrap_or_default() {
        let field = |key: &str| minute.get(key).and_then(Json::as_u64).unwrap_or(0);
        if field("at_unix") + 300 >= now {
            window.queries += field("queries");
            window.failures += field("failures");
            window.slow += field("slow");
        }
    }
    window
}

/// The machine's condition as an agent or a console reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct Now {
    /// When this was computed.
    pub at_unix: u64,
    /// `ok`, `warning` (problems listed), or `unknown` (the sampler is not running).
    pub condition: String,
    /// One sentence covering the machine and DNS.
    pub summary: String,
    /// Current problems, oldest first.
    pub problems: Vec<Problem>,
    /// The newest sample, if any.
    pub latest: Option<Sample>,
    /// The newest process ranking.
    pub processes: Vec<ProcessSample>,
    /// The resolver's last five minutes and lifetime counters, when it reports.
    pub dns: Option<Json>,
}

impl Now {
    /// The JSON form.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("at_unix", num(self.at_unix)),
            ("condition", text(&self.condition)),
            ("summary", text(&self.summary)),
            ("problems", Json::array(self.problems.iter().map(Problem::to_json))),
            ("latest", self.latest.as_ref().map_or(Json::Null, Sample::to_json)),
            ("processes", Json::array(self.processes.iter().map(ProcessSample::to_json))),
            ("dns", self.dns.clone().unwrap_or(Json::Null)),
        ])
    }
}

/// The file the watcher keeps the current problems in.
pub(crate) fn problems_path(data_dir: &Path) -> std::path::PathBuf {
    store::dir(data_dir).join("problems.json")
}

/// The DNS stats file the resolver writes.
pub(crate) fn dns_stats_path(data_dir: &Path) -> std::path::PathBuf {
    store::dir(data_dir).join("dns-stats.json")
}

/// Reads the resolver's stats; `None` when it does not run here.
pub fn read_dns_stats(data_dir: &Path) -> Option<Json> {
    selfhost_json::parse(&std::fs::read_to_string(dns_stats_path(data_dir)).ok()?).ok()
}

/// What is wrong on this machine right now, with evidence. Reads only the
/// newest few minutes of history, so it is cheap to ask often.
pub fn now(data_dir: &Path, now_unix: u64) -> io::Result<Now> {
    let latest = latest_sample(data_dir, now_unix, |_| true)?;
    let processes = latest_sample(data_dir, now_unix, |sample| !sample.processes.is_empty())?
        .map(|sample| sample.processes)
        .unwrap_or_default();
    let dns_stats = read_dns_stats(data_dir);
    let dns = dns_stats.as_ref().map(|stats| {
        Json::object([
            ("last_5_minutes", dns_window(stats, now_unix).to_json()),
            ("process", stats.get("process").cloned().unwrap_or(Json::Null)),
            ("reported_unix", stats.get("at_unix").cloned().unwrap_or(Json::Null)),
            ("counters", stats.get("counters").cloned().unwrap_or(Json::Null)),
            ("upstreams", stats.get("upstreams").cloned().unwrap_or(Json::Null)),
        ])
    });

    let fresh = latest.as_ref().is_some_and(|sample| now_unix.saturating_sub(sample.at_unix) <= SAMPLER_STALE_SECS);
    let problems = if fresh {
        let mut problems: Vec<Problem> = std::fs::read_to_string(problems_path(data_dir))
            .ok()
            .and_then(|text| selfhost_json::parse(&text).ok())
            .and_then(|json| json.as_array().map(|items| items.iter().filter_map(Problem::from_json).collect()))
            .unwrap_or_default();
        problems.sort_by_key(|problem| problem.since_unix);
        problems
    } else {
        let since = latest.as_ref().map_or(0, |sample| sample.at_unix);
        vec![Problem {
            id: "sampler_stopped".into(),
            title: "No machine sample in the last minute: the selfhost daemon's sampler is not running".into(),
            since_unix: since,
            evidence: Json::object([("last_sample_unix", num(since))]),
        }]
    };
    let condition = match (fresh, problems.is_empty()) {
        (false, _) => "unknown",
        (true, true) => "ok",
        (true, false) => "warning",
    };
    Ok(Now {
        at_unix: now_unix,
        condition: condition.to_owned(),
        summary: summarise(latest.as_ref(), dns_stats.as_ref().map(|stats| dns_window(stats, now_unix)), problems.len()),
        problems,
        latest,
        processes,
        dns,
    })
}

fn summarise(latest: Option<&Sample>, dns: Option<DnsWindow>, problems: usize) -> String {
    let mut parts = Vec::new();
    match latest {
        Some(sample) if sample.mem_total_mb > 0 => {
            if let Some(cpu) = sample.cpu_pct {
                parts.push(format!("CPU {cpu:.0}%"));
            }
            parts.push(format!("memory {:.0}%", sample.mem_pct()));
            parts.push(format!("commit {:.0}%", sample.commit_pct()));
            for disk in &sample.disks {
                parts.push(format!("{} {:.0} GB free", disk.mount, disk.free_mb as f64 / 1024.0));
            }
        }
        Some(_) => parts.push("no machine counters on this OS".into()),
        None => parts.push("no samples yet".into()),
    }
    if let Some(window) = dns {
        parts.push(format!("DNS {} queries, {} failed in 5 min", window.queries, window.failures));
    }
    parts.push(match problems {
        0 => "no problems".into(),
        1 => "1 problem".into(),
        n => format!("{n} problems"),
    });
    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DiskSample;

    fn sample(at: u64, mem_used_mb: u64) -> Sample {
        Sample { at_unix: at, mem_total_mb: 1000, mem_used_mb, ..Sample::default() }
    }

    fn kinds(events: &[Event]) -> Vec<(&str, &str)> {
        events.iter().map(|event| (event.kind.as_str(), event.source.as_str())).collect()
    }

    #[test]
    fn a_problem_needs_its_streak_to_raise_and_quiet_to_clear() {
        let mut assessor = Assessor::new();
        assert!(assessor.observe(&sample(10, 950), None, None).is_empty());
        assert!(assessor.observe(&sample(20, 950), None, None).is_empty());
        assert_eq!(kinds(&assessor.observe(&sample(30, 950), None, None)), vec![("warning", "memory_high")]);
        let problem = assessor.problems().remove(0);
        assert_eq!(problem.since_unix, 10, "since is when it was first seen, not when it was raised");

        assert!(assessor.observe(&sample(40, 100), None, None).is_empty());
        assert!(assessor.observe(&sample(50, 950), None, None).is_empty(), "a relapse continues the same problem");
        assert!(assessor.observe(&sample(60, 100), None, None).is_empty());
        assert!(assessor.observe(&sample(70, 100), None, None).is_empty());
        let cleared = assessor.observe(&sample(80, 100), None, None);
        assert_eq!(kinds(&cleared), vec![("cleared", "memory_high")]);
        assert_eq!(cleared[0].evidence.get("lasted_secs").and_then(Json::as_u64), Some(70));
        assert!(assessor.problems().is_empty());
    }

    #[test]
    fn a_blip_shorter_than_the_streak_is_forgotten() {
        let mut assessor = Assessor::new();
        assessor.observe(&sample(10, 950), None, None);
        assessor.observe(&sample(20, 100), None, None);
        assessor.observe(&sample(30, 950), None, None);
        assessor.observe(&sample(40, 950), None, None);
        assert!(assessor.problems().is_empty(), "the streak restarted after the healthy sample");
    }

    #[test]
    fn process_problems_are_judged_only_on_process_rankings() {
        let busy = |at: u64| Sample {
            at_unix: at,
            processes: vec![ProcessSample { pid: 7316, name: "selfhost.exe".into(), cpu_cores: 1.0, ..Default::default() }],
            ..Sample::default()
        };
        let mut assessor = Assessor::new();
        assessor.observe(&busy(60), None, None);
        assessor.observe(&Sample { at_unix: 70, ..Sample::default() }, None, None);
        let raised = assessor.observe(&busy(120), None, None);
        assert_eq!(kinds(&raised), vec![("warning", "selfhost_busy:7316")]);
        assert!(raised[0].title.contains("1.00 cores"));
        for at in [130, 140, 150, 160] {
            assessor.observe(&Sample { at_unix: at, ..Sample::default() }, None, None);
        }
        assert_eq!(assessor.problems().len(), 1, "samples without a ranking say nothing about processes");
    }

    fn dns_stats(at: u64, queries: u64, failures: u64, dropped: u64) -> Json {
        Json::object([
            ("at_unix", num(at)),
            ("process", text("lan-dns")),
            ("counters", Json::object([("dropped", num(dropped)), ("recv_errors", num(0))])),
            (
                "minutes",
                Json::array([Json::object([
                    ("at_unix", num(at - 60)),
                    ("queries", num(queries)),
                    ("failures", num(failures)),
                    ("slow", num(0)),
                ])]),
            ),
        ])
    }

    #[test]
    fn dns_failures_drops_and_silence_are_problems() {
        let mut assessor = Assessor::new();
        let raised = assessor.observe(&sample(1000, 0), Some(&dns_stats(995, 1000, 30, 0)), None);
        assert_eq!(kinds(&raised), vec![("warning", "dns_failing")]);

        let mut assessor = Assessor::new();
        assessor.observe(&sample(1000, 0), Some(&dns_stats(995, 1000, 0, 5)), None);
        let raised = assessor.observe(&sample(1010, 0), Some(&dns_stats(1005, 1000, 0, 9)), None);
        assert_eq!(kinds(&raised), vec![("warning", "dns_dropping")]);
        assert_eq!(raised[0].evidence.get("dropped").and_then(Json::as_u64), Some(4));

        let mut assessor = Assessor::new();
        let raised = assessor.observe(&sample(1000, 0), Some(&dns_stats(900, 1000, 0, 0)), None);
        assert_eq!(kinds(&raised), vec![("warning", "dns_stopped")]);
    }

    #[test]
    fn a_disk_filling_within_a_day_is_projected() {
        let mut assessor = Assessor::new();
        let disk = |at: u64, free_mb: u64| Sample {
            at_unix: at,
            disks: vec![DiskSample { mount: "C:\\".into(), total_mb: 1_000_000, free_mb }],
            ..Sample::default()
        };
        // 10 GB lost per hour with 100 GB left: about ten hours.
        assessor.observe(&disk(0, 110_000), None, None);
        assessor.observe(&disk(1200, 106_667), None, None);
        let raised = assessor.observe(&disk(3600, 100_000), None, None);
        assert_eq!(kinds(&raised), vec![("warning", "disk_filling:C:\\")]);
        assert!(raised[0].title.contains("about 10 h"), "{}", raised[0].title);
    }

    #[test]
    fn now_reports_a_stopped_sampler_instead_of_a_clean_bill() {
        let data = std::env::temp_dir().join(format!("selfhost-insight-now-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data);
        let report = now(&data, 1000).unwrap();
        assert_eq!(report.condition, "unknown");
        assert_eq!(report.problems[0].id, "sampler_stopped");

        let mut store = crate::store::Store::new(&data);
        store.append_sample(&sample(995, 500)).unwrap();
        let report = now(&data, 1000).unwrap();
        assert_eq!(report.condition, "ok");
        assert!(report.summary.contains("memory 50%"), "{}", report.summary);

        let problem = Problem { id: "memory_high".into(), title: "t".into(), since_unix: 900, evidence: Json::Null };
        store::replace(&problems_path(&data), &Json::array([problem.to_json()]).to_text()).unwrap();
        let report = now(&data, 1000).unwrap();
        assert_eq!((report.condition.as_str(), report.problems.len()), ("warning", 1));
        assert_eq!(now(&data, 2000).unwrap().condition, "unknown", "an old sample is not a current one");
        std::fs::remove_dir_all(&data).unwrap();
    }

    #[test]
    fn a_component_repaired_three_times_in_half_an_hour_is_flapping() {
        let repair = |at_unix: u64, source: &str| Event {
            at_unix,
            kind: "repair".into(),
            source: source.into(),
            title: format!("{source} repaired: restarted"),
            evidence: Json::Null,
        };
        let mut assessor = Assessor::new();
        let two = [repair(100, "dns"), repair(700, "dns"), repair(800, "https")];
        assert!(assessor.observe(&sample(1000, 0), None, Some(&two)).is_empty());

        let three = [repair(100, "dns"), repair(700, "dns"), repair(900, "dns"), repair(800, "https")];
        let raised = assessor.observe(&sample(1060, 0), None, Some(&three));
        assert_eq!(kinds(&raised), vec![("warning", "flapping:dns")]);
        assert_eq!(raised[0].evidence.get("repairs").and_then(Json::as_u64), Some(3));

        assert!(assessor.observe(&sample(1070, 0), None, None).is_empty(), "unjudged, so not cleared");
        assert_eq!(assessor.problems().len(), 1);
        let later = 100 + FLAP_WINDOW_SECS;
        for at in [later, later + 60] {
            assert!(assessor.observe(&sample(at, 0), None, Some(&three)).is_empty());
        }
        let cleared = assessor.observe(&sample(later + 120, 0), None, Some(&three));
        assert_eq!(kinds(&cleared), vec![("cleared", "flapping:dns")]);
    }
}
