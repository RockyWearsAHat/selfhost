//! Turns cumulative OS counters into per-interval rates.

use crate::sys::{self, CpuTimes, Disk, Memory, NetCounters, ProcessRaw, is_selfhost};
use crate::{DiskSample, NetSample, PROCESSES_EVERY, ProcessSample, Sample};
use std::collections::HashMap;
use std::time::Instant;

/// How many processes each ranking keeps, by CPU, by memory and by I/O. Every
/// selfhost process is kept on top of these.
const RANK: usize = 5;

/// A process busier than this (in cores) is worth naming in the CPU ranking.
const NOTICEABLE_CORES: f64 = 0.01;

/// A process moving more than this (read plus write) is worth naming in the I/O ranking.
const NOTICEABLE_IO_BPS: u64 = 256 * 1024;

const MB: u64 = 1024 * 1024;

/// Reads the machine and remembers the previous reading, so each sample can
/// report what happened since the last one.
#[derive(Default)]
pub struct Sampler {
    count: u64,
    previous: Option<Previous>,
    previous_processes: Option<(Instant, CountersByProcess)>,
}

/// CPU seconds and I/O bytes so far, keyed by (pid, start time) so a reused
/// PID is a new process.
type CountersByProcess = HashMap<(u32, u64), Counters>;

#[derive(Clone, Copy, Default)]
struct Counters {
    cpu_secs: f64,
    io_read: u64,
    io_write: u64,
}

struct Previous {
    at: Instant,
    cpu: Option<CpuTimes>,
    net: HashMap<String, NetCounters>,
}

/// One raw read of the OS, before any differencing.
pub(crate) struct Reading {
    pub cpu: Option<CpuTimes>,
    pub memory: Option<Memory>,
    pub disks: Vec<Disk>,
    pub net: Vec<NetCounters>,
    pub processes: Option<Vec<ProcessRaw>>,
}

impl Sampler {
    /// A sampler with no history: its first sample has no rates.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads the machine now. Blocking but brief (one process walk a minute,
    /// a few cheap calls otherwise): run it off the async runtime.
    pub fn sample(&mut self, at_unix: u64) -> Sample {
        let ranking = self.count % PROCESSES_EVERY == 0;
        self.count += 1;
        let reading = Reading {
            cpu: sys::cpu(),
            memory: sys::memory(),
            disks: sys::disks(),
            net: sys::net(),
            processes: ranking.then(sys::processes),
        };
        self.derive(at_unix, Instant::now(), reading)
    }

    pub(crate) fn derive(&mut self, at_unix: u64, now: Instant, reading: Reading) -> Sample {
        let previous = self.previous.take();
        let elapsed = previous.as_ref().map(|previous| now.duration_since(previous.at).as_secs_f64());
        let cpu_pct = match (previous.as_ref().and_then(|p| p.cpu), reading.cpu) {
            (Some(before), Some(after)) => busy_pct(before, after),
            _ => None,
        };
        let net = reading
            .net
            .iter()
            .map(|adapter| {
                let before = previous.as_ref().and_then(|p| p.net.get(&adapter.name));
                net_rates(adapter, before, elapsed)
            })
            .collect();
        let memory = reading.memory.unwrap_or(Memory { total: 0, available: 0, commit_limit: 0, commit_available: 0 });
        let processes = reading.processes.map(|found| self.rank(now, found)).unwrap_or_default();
        self.previous = Some(Previous {
            at: now,
            cpu: reading.cpu,
            net: reading.net.into_iter().map(|adapter| (adapter.name.clone(), adapter)).collect(),
        });
        Sample {
            at_unix,
            cpu_pct,
            mem_total_mb: memory.total / MB,
            mem_used_mb: memory.total.saturating_sub(memory.available) / MB,
            commit_limit_mb: memory.commit_limit / MB,
            commit_used_mb: memory.commit_limit.saturating_sub(memory.commit_available) / MB,
            disks: reading
                .disks
                .into_iter()
                .map(|disk| DiskSample { mount: disk.mount, total_mb: disk.total / MB, free_mb: disk.free / MB })
                .collect(),
            net,
            processes,
        }
    }

    /// The busiest, largest and most I/O-heavy processes plus every selfhost
    /// one, with CPU as cores and I/O as bytes per second since the previous
    /// ranking. The first ranking only sets the baseline: a lifetime total is
    /// not a rate.
    fn rank(&mut self, now: Instant, found: Vec<ProcessRaw>) -> Vec<ProcessSample> {
        let previous = self.previous_processes.replace((
            now,
            found
                .iter()
                .map(|process| {
                    let counters =
                        Counters { cpu_secs: process.cpu_secs, io_read: process.io_read, io_write: process.io_write };
                    ((process.pid, process.start), counters)
                })
                .collect(),
        ));
        let Some((then, before)) = previous else {
            return Vec::new();
        };
        let window = now.duration_since(then).as_secs_f64();
        if window <= 0.0 {
            return Vec::new();
        }
        let mut all: Vec<ProcessSample> = found
            .into_iter()
            .map(|process| {
                // A process born since the last ranking did all its work in the window.
                let then = before.get(&(process.pid, process.start)).copied().unwrap_or_default();
                let per_sec = |now: u64, then: u64| (now.saturating_sub(then) as f64 / window).round() as u64;
                ProcessSample {
                    pid: process.pid,
                    name: process.name,
                    cpu_cores: ((process.cpu_secs - then.cpu_secs) / window).max(0.0),
                    working_set_mb: process.working_set / MB,
                    private_mb: process.private / MB,
                    handles: process.handles,
                    io_read_bps: per_sec(process.io_read, then.io_read),
                    io_write_bps: per_sec(process.io_write, then.io_write),
                }
            })
            .collect();
        let mut keep: Vec<u32> = all.iter().filter(|p| is_selfhost(&p.name)).map(|p| p.pid).collect();
        all.sort_by(|a, b| b.cpu_cores.total_cmp(&a.cpu_cores));
        keep.extend(all.iter().take(RANK).filter(|p| p.cpu_cores >= NOTICEABLE_CORES).map(|p| p.pid));
        all.sort_by_key(|p| std::cmp::Reverse(p.working_set_mb));
        keep.extend(all.iter().take(RANK).map(|p| p.pid));
        let io = |p: &ProcessSample| p.io_read_bps + p.io_write_bps;
        all.sort_by_key(|p| std::cmp::Reverse(io(p)));
        keep.extend(all.iter().take(RANK).filter(|p| io(p) >= NOTICEABLE_IO_BPS).map(|p| p.pid));
        all.retain(|process| keep.contains(&process.pid));
        all.sort_by(|a, b| b.cpu_cores.total_cmp(&a.cpu_cores));
        all
    }
}

fn busy_pct(before: CpuTimes, after: CpuTimes) -> Option<f64> {
    let busy = after.busy.checked_sub(before.busy)?;
    let total = busy + after.idle.checked_sub(before.idle)?;
    (total > 0).then(|| busy as f64 * 100.0 / total as f64)
}

/// Rates over the elapsed window. A counter that went backwards (an adapter
/// reset) or has no predecessor reports zero rather than a lifetime total.
fn net_rates(adapter: &NetCounters, before: Option<&NetCounters>, elapsed: Option<f64>) -> NetSample {
    let (Some(before), Some(elapsed)) = (before, elapsed.filter(|secs| *secs > 0.0)) else {
        return NetSample { name: adapter.name.clone(), ..NetSample::default() };
    };
    let per_sec = |after: u64, before: u64| (after.saturating_sub(before) as f64 / elapsed).round() as u64;
    NetSample {
        name: adapter.name.clone(),
        rx_bps: per_sec(adapter.rx, before.rx),
        tx_bps: per_sec(adapter.tx, before.tx),
        errors: adapter.errors.saturating_sub(before.errors),
        discards: adapter.discards.saturating_sub(before.discards),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn reading(idle: u64, busy: u64, rx: u64, processes: Option<Vec<ProcessRaw>>) -> Reading {
        Reading {
            cpu: Some(CpuTimes { idle, busy }),
            memory: Some(Memory { total: 32_000 * MB, available: 12_000 * MB, commit_limit: 40_000 * MB, commit_available: 10_000 * MB }),
            disks: vec![Disk { mount: "C:\\".into(), total: 1000 * MB, free: 250 * MB }],
            net: vec![NetCounters { name: "Ethernet".into(), rx, tx: 0, errors: 0, discards: 0 }],
            processes,
        }
    }

    fn process(pid: u32, name: &str, cpu_secs: f64, working_set_mb: u64) -> ProcessRaw {
        ProcessRaw {
            pid,
            start: 1,
            name: name.into(),
            cpu_secs,
            working_set: working_set_mb * MB,
            private: working_set_mb * MB,
            handles: 0,
            io_read: 0,
            io_write: 0,
        }
    }

    #[test]
    fn the_first_sample_has_no_rates_and_the_second_does() {
        let mut sampler = Sampler::new();
        let start = Instant::now();
        let first = sampler.derive(100, start, reading(1000, 1000, 5_000, None));
        assert_eq!(first.cpu_pct, None);
        assert_eq!(first.net[0].rx_bps, 0);
        assert_eq!((first.mem_total_mb, first.mem_used_mb), (32_000, 20_000));
        assert_eq!((first.commit_limit_mb, first.commit_used_mb), (40_000, 30_000));

        let second = sampler.derive(110, start + Duration::from_secs(10), reading(1300, 1100, 15_000, None));
        assert_eq!(second.cpu_pct, Some(25.0));
        assert_eq!(second.net[0].rx_bps, 1000);
    }

    #[test]
    fn an_adapter_counter_reset_reads_as_zero_not_a_lifetime() {
        let mut sampler = Sampler::new();
        let start = Instant::now();
        sampler.derive(100, start, reading(0, 0, 1_000_000, None));
        let after = sampler.derive(110, start + Duration::from_secs(10), reading(0, 0, 10, None));
        assert_eq!(after.net[0].rx_bps, 0);
    }

    #[test]
    fn process_cpu_is_a_rate_over_the_ranking_window() {
        let mut sampler = Sampler::new();
        let start = Instant::now();
        let baseline = vec![process(7316, "selfhost.exe", 44_708.0, 23), process(1, "game.exe", 100.0, 4000)];
        let first = sampler.derive(100, start, reading(0, 0, 0, Some(baseline)));
        assert!(first.processes.is_empty(), "a lifetime total is not a rate");

        let later = vec![process(7316, "selfhost.exe", 44_768.0, 23), process(1, "game.exe", 130.0, 4000)];
        let ranked = sampler.derive(160, start + Duration::from_secs(60), reading(0, 0, 0, Some(later))).processes;
        let selfhost = ranked.iter().find(|p| p.pid == 7316).unwrap();
        assert!((selfhost.cpu_cores - 1.0).abs() < 1e-9, "60 s of CPU in 60 s is one core");
        let game = ranked.iter().find(|p| p.pid == 1).unwrap();
        assert!((game.cpu_cores - 0.5).abs() < 1e-9);
    }

    #[test]
    fn idle_selfhost_processes_are_always_listed_and_strangers_only_when_notable() {
        let mut sampler = Sampler::new();
        let start = Instant::now();
        let mut idle: Vec<ProcessRaw> = (10..30).map(|pid| process(pid, "svchost.exe", 1.0, 1)).collect();
        idle.push(process(7316, "SelfHost.exe", 1.0, 1));
        sampler.derive(100, start, reading(0, 0, 0, Some(idle.clone())));
        let ranked = sampler.derive(160, start + Duration::from_secs(60), reading(0, 0, 0, Some(idle))).processes;
        assert!(ranked.iter().any(|p| p.pid == 7316));
        assert_eq!(ranked.len(), 1 + RANK, "selfhost plus the top memory five; nobody is busy");
    }

    #[test]
    fn a_small_process_moving_a_lot_of_data_is_ranked_by_its_io_rate() {
        let mut sampler = Sampler::new();
        let start = Instant::now();
        let mut found: Vec<ProcessRaw> = (10..30).map(|pid| process(pid, "big.exe", 1.0, 100)).collect();
        found.push(process(99, "copier.exe", 1.0, 1));
        sampler.derive(100, start, reading(0, 0, 0, Some(found.clone())));
        let copier = found.last_mut().unwrap();
        (copier.io_read, copier.io_write) = (60 * MB, 30 * MB);
        let ranked = sampler.derive(160, start + Duration::from_secs(60), reading(0, 0, 0, Some(found))).processes;
        let copier = ranked.iter().find(|p| p.pid == 99).expect("the I/O-heavy process is kept");
        assert_eq!((copier.io_read_bps, copier.io_write_bps), (MB, MB / 2));
        assert_eq!(ranked.len(), 1 + RANK, "the top memory five plus the copier");
    }
}
