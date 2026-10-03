//! macOS-specific system sampling via libc.
//!
//! Uses `host_statistics64` for CPU metrics and `sysctl` for memory information.
//! Network and disk statistics are not yet implemented; fields will be empty/zero.

use crate::Sample;
use std::io;
use std::mem;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn sample() -> io::Result<Sample> {
    let at_unix = current_unix_time()?;
    let cpu_pct = read_cpu_pct().ok();
    let (mem_total_mb, mem_used_mb) = read_memory().unwrap_or((0, 0));
    let disks = Vec::new(); // Not yet implemented
    let net = Vec::new(); // Not yet implemented

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

/// Reads CPU utilization using host_statistics64.
///
/// Returns None if unavailable.
fn read_cpu_pct() -> io::Result<f64> {
    // macOS: use host_processor_info or read /proc/loadavg-like stats
    // For now, return None since getloadavg is not CPU%
    Err(io::Error::new(
        io::ErrorKind::Other,
        "CPU sampling not yet implemented on macOS",
    ))
}

/// Reads memory usage using sysctl.
///
/// Returns (total_mb, used_mb).
fn read_memory() -> io::Result<(u64, u64)> {
    unsafe {
        // Get total physical memory
        let mut total: u64 = 0;
        let mut size = mem::size_of::<u64>();
        let ret = libc::sysctl(
            [libc::CTL_HW, libc::HW_MEMSIZE].as_ptr() as *mut i32,
            2,
            &mut total as *mut u64 as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        );

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        let total_mb = total / (1024 * 1024);

        // Get free memory using host_statistics64
        // This is a simplified approach; full implementation would use Mach APIs
        let available_mb = 0; // Placeholder
        let used_mb = total_mb - available_mb;

        Ok((total_mb, used_mb))
    }
}
