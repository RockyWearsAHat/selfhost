//! Unix/Linux-specific system sampling via libc.
//!
//! This is a placeholder implementation. The production system runs on Windows;
//! Unix/Linux support is not a priority.

use crate::{DiskSample, NetSample, ProcessSample, Sample, WindowsEvent};
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn sample() -> io::Result<Sample> {
    let at_unix = current_unix_time()?;
    let cpu_pct = None;
    let (mem_total_mb, mem_used_mb) = (0, 0);
    let disks = Vec::new();
    let net = Vec::new();

    Ok(Sample {
        at_unix,
        cpu_pct,
        mem_total_mb,
        mem_used_mb,
        disks,
        net,
    })
}

/// Returns the current Unix timestamp in seconds.
fn current_unix_time() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "time error"))
}

/// Samples running processes (not implemented on Unix/Linux).
///
/// Returns an empty vector.
pub fn sample_processes() -> io::Result<Vec<ProcessSample>> {
    Ok(Vec::new())
}

/// Reads Windows events (not available on Unix/Linux).
///
/// Returns an empty vector.
pub fn read_windows_events() -> io::Result<Vec<WindowsEvent>> {
    Ok(Vec::new())
}
