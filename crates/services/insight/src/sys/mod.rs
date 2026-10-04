//! The operating system's raw, cumulative counters. Rates are the
//! [`Sampler`](crate::Sampler)'s job; this layer only reads.

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::{cpu, disks, memory, net, processes};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::{cpu, disks, memory, net, processes};

// Production is Windows and the fleet's other OS is Linux. Elsewhere (a macOS
// development machine) the sampler records timestamps and nothing else, which
// the console shows as "no machine data" rather than as zeros.
#[cfg(not(any(windows, target_os = "linux")))]
mod none;
#[cfg(not(any(windows, target_os = "linux")))]
pub(crate) use none::{cpu, disks, memory, net, processes};

/// Time the CPUs spent idle and busy, in any one unit, since boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CpuTimes {
    pub idle: u64,
    pub busy: u64,
}

/// Memory, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Memory {
    pub total: u64,
    pub available: u64,
    pub commit_limit: u64,
    pub commit_available: u64,
}

/// One fixed disk, in bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Disk {
    pub mount: String,
    pub total: u64,
    pub free: u64,
}

/// One adapter's counters since boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetCounters {
    pub name: String,
    pub rx: u64,
    pub tx: u64,
    pub errors: u64,
    pub discards: u64,
}

/// One process. `start` disambiguates a reused PID.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProcessRaw {
    pub pid: u32,
    pub start: u64,
    pub name: String,
    pub cpu_secs: f64,
    pub working_set: u64,
    pub private: u64,
    pub handles: u32,
}

/// Whether a process is one of ours, whose handles are worth reading.
pub(crate) fn is_selfhost(name: &str) -> bool {
    name.get(..8).is_some_and(|prefix| prefix.eq_ignore_ascii_case("selfhost"))
}
