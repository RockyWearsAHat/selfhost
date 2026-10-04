//! No machine counters on this OS: the sampler records timestamps only.

use super::{CpuTimes, Disk, Memory, NetCounters, ProcessRaw};

pub(crate) fn cpu() -> Option<CpuTimes> {
    None
}

pub(crate) fn memory() -> Option<Memory> {
    None
}

pub(crate) fn disks() -> Vec<Disk> {
    Vec::new()
}

pub(crate) fn net() -> Vec<NetCounters> {
    Vec::new()
}

pub(crate) fn processes() -> Vec<ProcessRaw> {
    Vec::new()
}
