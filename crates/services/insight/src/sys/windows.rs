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
//!
//! All addresses are re-derived at each call; no global state is retained.

#![allow(unsafe_code)]

use crate::{DiskSample, NetSample, Sample};
use std::io;
use std::mem;
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
