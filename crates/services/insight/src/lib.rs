//! Machine insight: what this computer is doing, recorded cheaply enough that
//! watching never becomes the load (ASSIGNMENT §2.2, §2.4).
//!
//! Every [`SAMPLE_EVERY`] the [`Sampler`] reads the operating system's
//! cumulative counters and turns the difference since its previous read into
//! rates: whole-machine CPU, memory and commit charge, fixed-disk space, and
//! per-adapter throughput, errors and discards. Every [`PROCESSES_EVERY`]th
//! sample also ranks processes by CPU and by memory and always includes every
//! selfhost process, so a spinning or leaking selfhost shows up by name.
//!
//! The [`Assessor`] turns samples, plus the DNS resolver's own
//! `dns-stats.json`, into the problems that are true right now. A problem
//! appearing or clearing is written to the event timeline next to the Windows
//! events that explain outages: crashes, unexpected reboots, resource
//! exhaustion, adapter resets, name-resolution timeouts. Nothing here acts on
//! a problem. Warnings are recorded, never remediated.
//!
//! Everything lives under `<data_dir>/insight/` as one NDJSON file per UTC day
//! (see [`store`]), so the history survives restarts and any process, from the
//! admin API to an agent's shell, reads the same truth.

mod assess;
mod events;
mod json;
mod sampler;
pub mod store;
mod sys;
mod watch;

pub use assess::{Assessor, Now, Problem, now, read_dns_stats};
pub use events::{WindowsEvent, parse_rendered_events};
pub use sampler::Sampler;
pub use watch::run;

use selfhost_json::Json;
use std::time::Duration;

/// How often the machine is sampled.
pub const SAMPLE_EVERY: Duration = Duration::from_secs(10);

/// Every this many samples also carries the process ranking (once a minute).
pub const PROCESSES_EVERY: u64 = 6;

/// How often the Windows event logs are read for new entries.
pub const EVENTS_EVERY: Duration = Duration::from_secs(300);

/// One reading of the whole machine.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Sample {
    /// Unix seconds when the sample was taken.
    pub at_unix: u64,
    /// Whole-machine CPU busy since the previous sample, 0–100. `None` on the
    /// first sample, which has nothing to difference against.
    pub cpu_pct: Option<f64>,
    /// Physical memory installed.
    pub mem_total_mb: u64,
    /// Physical memory in use (total minus available).
    pub mem_used_mb: u64,
    /// The commit limit: RAM plus page file. Running out of commit is what
    /// makes allocations fail while RAM still looks free.
    pub commit_limit_mb: u64,
    /// Commit charge in use.
    pub commit_used_mb: u64,
    /// Fixed disks.
    pub disks: Vec<DiskSample>,
    /// Network adapters that are up.
    pub net: Vec<NetSample>,
    /// Ranked processes; empty except on every [`PROCESSES_EVERY`]th sample.
    pub processes: Vec<ProcessSample>,
}

/// One fixed disk's space.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DiskSample {
    /// Mount point (`C:\` on Windows).
    pub mount: String,
    /// Capacity.
    pub total_mb: u64,
    /// Free space available to this process.
    pub free_mb: u64,
}

/// One network adapter's traffic since the previous sample.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NetSample {
    /// The adapter's friendly name (`Ethernet`, `Wi-Fi`).
    pub name: String,
    /// Bytes received per second.
    pub rx_bps: u64,
    /// Bytes sent per second.
    pub tx_bps: u64,
    /// Receive and transmit errors since the previous sample.
    pub errors: u64,
    /// Packets discarded since the previous sample.
    pub discards: u64,
}

/// One process at a process-ranking sample.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProcessSample {
    /// Process ID.
    pub pid: u32,
    /// Executable name.
    pub name: String,
    /// Cores busy since the previous ranking (1.0 is one whole core).
    pub cpu_cores: f64,
    /// Resident memory.
    pub working_set_mb: u64,
    /// Private committed memory: what a leak grows.
    pub private_mb: u64,
    /// Open handles, read for selfhost processes only (0 for others).
    pub handles: u32,
    /// Bytes per second read through any I/O (files, sockets, devices) since
    /// the previous ranking.
    pub io_read_bps: u64,
    /// Bytes per second written, likewise.
    pub io_write_bps: u64,
}

/// One entry in the event timeline.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// Unix seconds when it happened.
    pub at_unix: u64,
    /// `warning` (a problem appeared), `cleared` (it went away), or `windows`
    /// (an entry from a Windows event log).
    pub kind: String,
    /// What it concerns: a problem id, or the Windows event provider.
    pub source: String,
    /// One line a person reads.
    pub title: String,
    /// The numbers behind it.
    pub evidence: Json,
}

impl Sample {
    /// The share of physical memory in use, 0–100.
    pub fn mem_pct(&self) -> f64 {
        percent(self.mem_used_mb, self.mem_total_mb)
    }

    /// The share of the commit limit in use, 0–100.
    pub fn commit_pct(&self) -> f64 {
        percent(self.commit_used_mb, self.commit_limit_mb)
    }
}

impl DiskSample {
    /// The share of the disk that is free, 0–100.
    pub fn free_pct(&self) -> f64 {
        percent(self.free_mb, self.total_mb)
    }
}

fn percent(part: u64, whole: u64) -> f64 {
    if whole == 0 { 0.0 } else { part as f64 * 100.0 / whole as f64 }
}

/// Unix seconds now.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
