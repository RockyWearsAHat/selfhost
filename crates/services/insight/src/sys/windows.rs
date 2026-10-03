//! Windows-specific system sampling via direct FFI.
//!
//! This module contains the only unsafe code in `selfhost-insight`. Windows has no safe
//! standard-library route to read system metrics, so all system calls live here under
//! a module-level exemption. The FFI calls are confined to this file; the rest of the
//! crate is safe Rust.
//!
//! Functions:
//! - `GetSystemTimes`: CPU utilization from system/user/idle times
//! - `GlobalMemoryStatusEx`: Physical memory usage
//! - `GetLogicalDriveStringsW` + `GetDiskFreeSpaceExW`: Fixed disk usage
//! - `GetIfTable2` + `FreeMibTable`: Network interface statistics
//! - `CreateToolhelp32Snapshot` + `Process32FirstW` + `Process32NextW`: Process enumeration
//! - `OpenProcess`, `GetProcessTimes`, `K32GetProcessMemoryInfo`, `CloseHandle`: Process metrics
//!
//! All addresses are re-derived at each call; no global state is retained.

#![allow(unsafe_code)]

use crate::{DiskSample, NetSample, ProcessSample, Sample, WindowsEvent};
use std::io;
use std::mem;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn sample() -> io::Result<Sample> {
    let at_unix = current_unix_time()?;
    let cpu_pct = read_cpu_pct()?;
    let (mem_total_mb, mem_used_mb) = read_memory()?;
    let disks = read_disks()?;
    let net = read_network()?;

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

/// Reads CPU utilization as a percentage.
///
/// Uses `GetSystemTimes` to compute (UserTime + SystemTime) / (UserTime + SystemTime + IdleTime).
/// Returns None if the call fails.
fn read_cpu_pct() -> io::Result<Option<f64>> {
    unsafe {
        let mut idle: u64 = 0;
        let mut kernel: u64 = 0;
        let mut user: u64 = 0;

        let ret = GetSystemTimes(
            &mut idle as *mut u64 as *mut libc::c_void,
            &mut kernel as *mut u64 as *mut libc::c_void,
            &mut user as *mut u64 as *mut libc::c_void,
        );

        if ret == 0 {
            return Ok(None);
        }

        let total = idle + kernel + user;
        if total == 0 {
            return Ok(None);
        }

        let busy = kernel + user;
        let pct = (busy as f64 / total as f64) * 100.0;
        Ok(Some(pct))
    }
}

/// Reads memory usage.
///
/// Returns (total_mb, used_mb) using `GlobalMemoryStatusEx`.
fn read_memory() -> io::Result<(u64, u64)> {
    unsafe {
        let mut stat: MEMORYSTATUSEX = mem::zeroed();
        stat.dwLength = mem::size_of::<MEMORYSTATUSEX>() as u32;

        if GlobalMemoryStatusEx(&mut stat as *mut MEMORYSTATUSEX) == 0 {
            return Err(io::Error::last_os_error());
        }

        let total_mb = stat.ullTotalPhys / (1024 * 1024);
        let used_mb = (stat.ullTotalPhys - stat.ullAvailPhys) / (1024 * 1024);

        Ok((total_mb, used_mb))
    }
}

/// Reads disk usage for all fixed drives.
///
/// Uses `GetLogicalDriveStringsW` to enumerate drives, then `GetDiskFreeSpaceExW` for each.
/// Skips removable drives.
fn read_disks() -> io::Result<Vec<DiskSample>> {
    unsafe {
        let mut drives = vec![0u16; 256];
        let len = GetLogicalDriveStringsW(drives.len() as u32, drives.as_mut_ptr());
        if len == 0 {
            return Err(io::Error::last_os_error());
        }

        drives.truncate(len as usize);

        let mut disks = Vec::new();
        let mut pos = 0;

        while pos < drives.len() && drives[pos] != 0 {
            // Find the null terminator for this drive string
            let mut end = pos;
            while end < drives.len() && drives[end] != 0 {
                end += 1;
            }

            if end > pos {
                let drive_slice = &drives[pos..end];
                let drive_str = String::from_utf16_lossy(drive_slice).to_string();

                // Skip removable drives by checking drive type
                let drive_type = GetDriveTypeW(
                    format!("{}\0", drive_str)
                        .encode_utf16()
                        .collect::<Vec<_>>()
                        .as_ptr(),
                );
                if drive_type == 2 {
                    // DRIVE_REMOVABLE; skip it
                    pos = end + 1;
                    continue;
                }

                // Get free space for this drive
                let mut free = 0u64;
                let mut total = 0u64;
                let drive_cstr = format!("{}\0", drive_str);
                let drive_wide: Vec<u16> = drive_cstr.encode_utf16().collect();

                if GetDiskFreeSpaceExW(
                    drive_wide.as_ptr(),
                    &mut free as *mut u64,
                    &mut total as *mut u64,
                    std::ptr::null_mut(),
                ) != 0
                {
                    let total_mb = total / (1024 * 1024);
                    let free_mb = free / (1024 * 1024);

                    disks.push(DiskSample {
                        mount: drive_str,
                        total_mb,
                        free_mb,
                    });
                }
            }

            pos = end + 1;
        }

        Ok(disks)
    }
}

/// Reads network interface statistics.
///
/// Uses `GetIfTable2` to enumerate interfaces, skipping loopback and down interfaces.
fn read_network() -> io::Result<Vec<NetSample>> {
    unsafe {
        let mut table_ptr: *mut MIB_IF_TABLE2 = std::ptr::null_mut();

        let ret = GetIfTable2(&mut table_ptr as *mut *mut MIB_IF_TABLE2);
        if ret != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "GetIfTable2 failed",
            ));
        }

        if table_ptr.is_null() {
            return Ok(Vec::new());
        }

        let table = &*table_ptr;
        let mut interfaces = Vec::new();

        for i in 0..table.NumEntries as usize {
            let row = &table.Table[i];

            // Skip loopback (ifType == 24) and down interfaces (ifOperStatus != 1)
            if row.Type == 24 || row.OperStatus != 1 {
                continue;
            }

            // Get the interface name from wcDescription
            let desc_slice = &row.Description[..row.Description.iter().position(|&c| c == 0).unwrap_or(row.Description.len())];
            let name = String::from_utf16_lossy(desc_slice).to_string();

            interfaces.push(NetSample {
                name,
                rx_bytes: row.InOctets,
                tx_bytes: row.OutOctets,
                rx_errors: row.InErrors,
                tx_errors: row.OutErrors,
            });
        }

        FreeMibTable(table_ptr as *mut libc::c_void);
        Ok(interfaces)
    }
}

/// Samples running processes, returning the top 8 by CPU and top 8 by memory,
/// plus all processes whose names start with "selfhost".
pub fn sample_processes() -> io::Result<Vec<ProcessSample>> {
    unsafe {
        let mut snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == libc::INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }

        let mut processes = Vec::new();
        let mut pe: PROCESSENTRY32W = mem::zeroed();
        pe.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

        // Collect all process information
        if Process32FirstW(snapshot, &mut pe) != 0 {
            loop {
                let name = String::from_utf16_lossy(&pe.szExeFile[..pe.szExeFile.iter().position(|&c| c == 0).unwrap_or(pe.szExeFile.len())])
                    .to_string();

                // Try to read process times and memory
                if let Ok((cpu_cores, working_set_mb)) = read_process_metrics(pe.th32ProcessID) {
                    processes.push(ProcessSample {
                        pid: pe.th32ProcessID,
                        name,
                        cpu_cores,
                        working_set_mb,
                    });
                }

                if Process32NextW(snapshot, &mut pe) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);

        // Sort by CPU cores (descending)
        processes.sort_by(|a, b| b.cpu_cores.partial_cmp(&a.cpu_cores).unwrap_or(std::cmp::Ordering::Equal));
        let mut top_cpu: Vec<ProcessSample> = processes.iter().take(8).cloned().collect();

        // Sort by memory (descending)
        processes.sort_by(|a, b| b.working_set_mb.cmp(&a.working_set_mb));
        let mut top_memory: Vec<ProcessSample> = processes.iter().take(8).cloned().collect();

        // Add all selfhost processes
        let selfhost_processes: Vec<ProcessSample> = processes
            .iter()
            .filter(|p| p.name.to_lowercase().starts_with("selfhost"))
            .cloned()
            .collect();

        // Combine and deduplicate
        let mut combined = top_cpu;
        combined.extend(top_memory);
        combined.extend(selfhost_processes);
        combined.sort_by_key(|p| (p.pid, p.name.clone()));
        combined.dedup_by_key(|p| (p.pid, p.name.clone()));

        Ok(combined)
    }
}

/// Reads process metrics (CPU cores and working set memory).
unsafe fn read_process_metrics(pid: u32) -> io::Result<(f64, u64)> {
    let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
    if handle == std::ptr::null_mut() {
        return Err(io::Error::last_os_error());
    }

    let mut creation_time: u64 = 0;
    let mut exit_time: u64 = 0;
    let mut kernel_time: u64 = 0;
    let mut user_time: u64 = 0;

    // Get process times
    if GetProcessTimes(
        handle,
        &mut creation_time as *mut u64 as *mut libc::c_void,
        &mut exit_time as *mut u64 as *mut libc::c_void,
        &mut kernel_time as *mut u64 as *mut libc::c_void,
        &mut user_time as *mut u64 as *mut libc::c_void,
    ) == 0
    {
        CloseHandle(handle);
        return Err(io::Error::last_os_error());
    }

    // Get process memory
    let mut mem_info: PROCESS_MEMORY_COUNTERS_EX = mem::zeroed();
    mem_info.cb = mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32;

    if K32GetProcessMemoryInfo(
        handle,
        &mut mem_info as *mut PROCESS_MEMORY_COUNTERS_EX as *mut PROCESS_MEMORY_COUNTERS,
        mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
    ) == 0
    {
        CloseHandle(handle);
        return Err(io::Error::last_os_error());
    }

    CloseHandle(handle);

    let total_time = kernel_time + user_time;
    // Convert 100-nanosecond intervals to seconds and then to cores
    let total_seconds = total_time as f64 / 10_000_000.0;
    let cpu_cores = total_seconds / 30.0; // Assuming 30-second sample window

    let working_set_mb = mem_info.WorkingSetSize / (1024 * 1024);

    Ok((cpu_cores, working_set_mb))
}

/// Reads Windows events using wevtutil.
pub fn read_windows_events() -> io::Result<Vec<WindowsEvent>> {
    // Run wevtutil to get recent events from the System log
    // Query: Level 1 or 2 (critical or error) in the last 5 minutes (300 seconds)
    let output = Command::new("wevtutil")
        .args(&[
            "qe",
            "System",
            "/q:*[System[(Level=1 or Level=2) and TimeCreated[timediff(@SystemTime) <= 330000]]]",
            "/f:text",
            "/c:50",
        ])
        .output()?;

    let mut events = Vec::new();

    if !output.status.success() {
        // wevtutil might not be available on all systems
        return Ok(Vec::new());
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = output_str.lines().collect();

    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];

        if line.starts_with("Provider Name:") {
            let provider = line
                .strip_prefix("Provider Name:")
                .unwrap_or("")
                .trim()
                .to_string();

            // Extract Event ID
            let mut event_id = 0u32;
            let mut at_unix = 0u64;
            let mut message = String::new();

            i += 1;
            while i < lines.len() {
                let line = lines[i];

                if line.starts_with("Event ID:") {
                    event_id = line
                        .strip_prefix("Event ID:")
                        .unwrap_or("")
                        .trim()
                        .parse()
                        .unwrap_or(0);
                } else if line.starts_with("TimeCreated:") {
                    // Parse ISO timestamp to Unix time
                    if let Some(time_str) = line.strip_prefix("TimeCreated:") {
                        if let Ok(time) = parse_iso_timestamp(time_str.trim()) {
                            at_unix = time;
                        }
                    }
                } else if line.starts_with("Message:") {
                    // Capture first line of message
                    message = line
                        .strip_prefix("Message:")
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    // Take only the first 100 characters
                    if message.len() > 100 {
                        message.truncate(100);
                    }
                    break;
                }

                i += 1;
            }

            if !provider.is_empty() && event_id > 0 && at_unix > 0 {
                events.push(WindowsEvent {
                    provider,
                    id: event_id,
                    at_unix,
                    message,
                });
            }
        }

        i += 1;
    }

    Ok(events)
}

/// Parses an ISO 8601 timestamp to Unix time.
fn parse_iso_timestamp(ts: &str) -> Result<u64, String> {
    // Expected format: 2025-10-03T14:30:45.123Z
    // This is a simplified parser; in production, use chrono
    if ts.len() < 19 {
        return Err("timestamp too short".to_string());
    }

    // Simple approximation: count days since epoch
    let year: u32 = ts[0..4].parse().map_err(|_| "invalid year")?;
    let month: u32 = ts[5..7].parse().map_err(|_| "invalid month")?;
    let day: u32 = ts[8..10].parse().map_err(|_| "invalid day")?;
    let hour: u32 = ts[11..13].parse().map_err(|_| "invalid hour")?;
    let minute: u32 = ts[14..16].parse().map_err(|_| "invalid minute")?;
    let second: u32 = ts[17..19].parse().map_err(|_| "invalid second")?;

    // Calculate Unix timestamp (approximate)
    let mut unix_time = 0u64;

    // Days since epoch (1970)
    let mut days = 0u64;
    for y in 1970..year as u64 {
        days += if y % 4 == 0 && (y % 100 != 0 || y % 400 == 0) { 366 } else { 365 };
    }

    // Days in current year
    let days_in_months = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    for m in 1..month as usize {
        days += days_in_months[m - 1] as u64;
    }

    days += (day - 1) as u64;

    unix_time = days * 86400 + hour as u64 * 3600 + minute as u64 * 60 + second as u64;

    Ok(unix_time)
}

// === FFI Declarations ===

/// Retrieves system timing information.
#[link(name = "kernel32")]
extern "system" {
    fn GetSystemTimes(
        lpIdleTime: *mut libc::c_void,
        lpKernelTime: *mut libc::c_void,
        lpUserTime: *mut libc::c_void,
    ) -> i32;
}

/// Memory status structure for GlobalMemoryStatusEx.
#[repr(C)]
struct MEMORYSTATUSEX {
    dwLength: u32,
    dwMemoryLoad: u32,
    ullTotalPhys: u64,
    ullAvailPhys: u64,
    ullTotalPageFile: u64,
    ullAvailPageFile: u64,
    ullTotalVirtual: u64,
    ullAvailVirtual: u64,
    ullAvailExtendedVirtual: u64,
}

/// Retrieves memory status.
#[link(name = "kernel32")]
extern "system" {
    fn GlobalMemoryStatusEx(lpBuffer: *mut MEMORYSTATUSEX) -> i32;
}

/// Retrieves strings identifying physical drives.
#[link(name = "kernel32")]
extern "system" {
    fn GetLogicalDriveStringsW(nBufferLength: u32, lpBuffer: *mut u16) -> u32;
}

/// Retrieves disk free space.
#[link(name = "kernel32")]
extern "system" {
    fn GetDiskFreeSpaceExW(
        lpDirectoryName: *const u16,
        lpFreeBytesAvailableToCaller: *mut u64,
        lpTotalNumberOfBytes: *mut u64,
        lpTotalNumberOfFreeBytes: *mut u64,
    ) -> i32;
}

/// Retrieves the type of drive.
#[link(name = "kernel32")]
extern "system" {
    fn GetDriveTypeW(lpRootPathName: *const u16) -> u32;
}

/// MIB_IFROW for interface information.
#[repr(C)]
struct MIB_IFROW {
    wszName: [u16; 256],
    dwIndex: u32,
    dwType: u32,
    dwMtu: u32,
    dwSpeed: u32,
    dwPhysAddrLen: u32,
    bPhysAddr: [u8; 8],
    dwAdminStatus: u32,
    dwOperStatus: u32,
    dwLastChange: u32,
    dwInOctets: u32,
    dwInUcastPkts: u32,
    dwInNonUcastPkts: u32,
    dwInDiscards: u32,
    dwInErrors: u32,
    dwInUnknownProtos: u32,
    dwOutOctets: u32,
    dwOutUcastPkts: u32,
    dwOutNonUcastPkts: u32,
    dwOutDiscards: u32,
    dwOutErrors: u32,
    dwOutQLen: u32,
    dwDescrLen: u32,
    bDescr: [u8; 256],
}

/// MIB_IF_ROW2 for interface information (modern API).
#[repr(C)]
struct MIB_IF_ROW2 {
    InterfaceIndex: u32,
    InterfaceGuid: [u8; 16],
    Alias: [u16; 256],
    Description: [u16; 256],
    PhysicalAddressLength: u32,
    PhysicalAddress: [u8; 32],
    PermanentPhysicalAddress: [u8; 32],
    Mtu: u32,
    Type: u32,
    TunnelType: u32,
    MediaType: u32,
    PhysicalMediumType: u32,
    AccessType: u32,
    OperStatus: u32,
    AdminStatus: u32,
    MediaConnectState: u32,
    NetworkGuid: [u8; 16],
    ConnectionType: u32,
    TransmitLinkSpeed: u64,
    ReceiveLinkSpeed: u64,
    InOctets: u64,
    InUcastPkts: u64,
    InNonUcastPkts: u64,
    InDiscards: u64,
    InErrors: u64,
    InUnknownProtos: u64,
    InUcastOctets: u64,
    InMulticastOctets: u64,
    InBroadcastOctets: u64,
    OutOctets: u64,
    OutUcastPkts: u64,
    OutNonUcastPkts: u64,
    OutDiscards: u64,
    OutErrors: u64,
    OutUcastOctets: u64,
    OutMulticastOctets: u64,
    OutBroadcastOctets: u64,
    OutQLen: u64,
}

/// MIB_IF_TABLE2 for interface table.
#[repr(C)]
struct MIB_IF_TABLE2 {
    NumEntries: u32,
    Table: [MIB_IF_ROW2; 1], // Flexible array member
}

/// Retrieves the MIB II interface table.
#[link(name = "iphlpapi")]
extern "system" {
    fn GetIfTable2(Table: *mut *mut MIB_IF_TABLE2) -> u32;
}

/// Frees MIB table.
#[link(name = "iphlpapi")]
extern "system" {
    fn FreeMibTable(Memory: *mut libc::c_void);
}

// Process enumeration and information

/// Process snapshot flags
const TH32CS_SNAPPROCESS: u32 = 0x00000002;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

/// PROCESSENTRY32W structure for process enumeration.
#[repr(C)]
struct PROCESSENTRY32W {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32ParentProcessID: u32,
    th32PriorityBase: i32,
    th32MemoryBase: i32,
    cntThreads: u32,
    th32ModuleID: u32,
    cntPriority: u32,
    szExeFile: [u16; 260],
}

/// FILETIME structure for process times.
#[repr(C)]
struct FILETIME {
    dwLowDateTime: u32,
    dwHighDateTime: u32,
}

/// PROCESS_MEMORY_COUNTERS structure.
#[repr(C)]
struct PROCESS_MEMORY_COUNTERS {
    cb: u32,
    PageFaultCount: u32,
    PeakWorkingSetSize: u64,
    WorkingSetSize: u64,
    QuotaPeakPagedPoolUsage: u64,
    QuotaPagedPoolUsage: u64,
    QuotaPeakNonPagedPoolUsage: u64,
    QuotaNonPagedPoolUsage: u64,
    PagefileUsage: u64,
    PeakPagefileUsage: u64,
}

/// PROCESS_MEMORY_COUNTERS_EX structure (extends PROCESS_MEMORY_COUNTERS).
#[repr(C)]
struct PROCESS_MEMORY_COUNTERS_EX {
    cb: u32,
    PageFaultCount: u32,
    PeakWorkingSetSize: u64,
    WorkingSetSize: u64,
    QuotaPeakPagedPoolUsage: u64,
    QuotaPagedPoolUsage: u64,
    QuotaPeakNonPagedPoolUsage: u64,
    QuotaNonPagedPoolUsage: u64,
    PagefileUsage: u64,
    PeakPagefileUsage: u64,
    PrivateUsage: u64,
}

/// Creates a snapshot of the specified processes.
#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> *mut libc::c_void;
}

/// Retrieves information about the first process in the system.
#[link(name = "kernel32")]
extern "system" {
    fn Process32FirstW(hSnapshot: *mut libc::c_void, lppe: *mut PROCESSENTRY32W) -> i32;
}

/// Retrieves information about the next process in the system.
#[link(name = "kernel32")]
extern "system" {
    fn Process32NextW(hSnapshot: *mut libc::c_void, lppe: *mut PROCESSENTRY32W) -> i32;
}

/// Opens a process object.
#[link(name = "kernel32")]
extern "system" {
    fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: i32, dwProcessId: u32) -> *mut libc::c_void;
}

/// Retrieves timing information for the specified process.
#[link(name = "kernel32")]
extern "system" {
    fn GetProcessTimes(
        hProcess: *mut libc::c_void,
        lpCreationTime: *mut libc::c_void,
        lpExitTime: *mut libc::c_void,
        lpKernelTime: *mut libc::c_void,
        lpUserTime: *mut libc::c_void,
    ) -> i32;
}

/// Retrieves memory statistics for the specified process.
#[link(name = "kernel32")]
extern "system" {
    fn K32GetProcessMemoryInfo(
        Process: *mut libc::c_void,
        ppsmemCounters: *mut PROCESS_MEMORY_COUNTERS,
        cb: u32,
    ) -> i32;
}

/// Closes an open object handle.
#[link(name = "kernel32")]
extern "system" {
    fn CloseHandle(hObject: *mut libc::c_void) -> i32;
}
