//! Windows counters through kernel32 and iphlpapi, without a bindings crate.
//!
//! Every struct below mirrors a Windows SDK definition and is checked at
//! compile time against the SDK's own size and the offsets that matter, so a
//! layout mistake fails the build instead of reading past an allocation inside
//! the daemon that serves the house's DNS. Every call is cheap and
//! non-blocking: no WMI, no performance-counter queries, no subprocesses.

// The one module in the crate allowed `unsafe`; the crate itself denies it.
#![allow(unsafe_code, non_snake_case, non_camel_case_types, clippy::upper_case_acronyms)]

use super::{CpuTimes, Disk, Memory, NetCounters, ProcessRaw, is_selfhost};
use std::ffi::c_void;
use std::mem::{offset_of, size_of};

type HANDLE = *mut c_void;
const INVALID_HANDLE_VALUE: HANDLE = -1_isize as HANDLE;
const TH32CS_SNAPPROCESS: u32 = 0x2;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const DRIVE_FIXED: u32 = 3;
const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
const IF_OPER_STATUS_UP: u32 = 1;
/// `InterfaceAndOperStatusFlags.FilterInterface`: a filter-driver shadow of a
/// real adapter, whose counters would double-count it.
const FILTER_INTERFACE: u8 = 0b10;
/// FILETIME ticks (100 ns) per second.
const TICKS_PER_SEC: f64 = 10_000_000.0;

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
const _: () = assert!(size_of::<MEMORYSTATUSEX>() == 64);

#[repr(C)]
struct PROCESSENTRY32W {
    dwSize: u32,
    cntUsage: u32,
    th32ProcessID: u32,
    th32DefaultHeapID: usize,
    th32ModuleID: u32,
    cntThreads: u32,
    th32ParentProcessID: u32,
    pcPriClassBase: i32,
    dwFlags: u32,
    szExeFile: [u16; 260],
}
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<PROCESSENTRY32W>() == 568 && offset_of!(PROCESSENTRY32W, szExeFile) == 44);

#[repr(C)]
struct PROCESS_MEMORY_COUNTERS_EX {
    cb: u32,
    PageFaultCount: u32,
    PeakWorkingSetSize: usize,
    WorkingSetSize: usize,
    QuotaPeakPagedPoolUsage: usize,
    QuotaPagedPoolUsage: usize,
    QuotaPeakNonPagedPoolUsage: usize,
    QuotaNonPagedPoolUsage: usize,
    PagefileUsage: usize,
    PeakPagefileUsage: usize,
    PrivateUsage: usize,
}
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<PROCESS_MEMORY_COUNTERS_EX>() == 80);

/// `netioapi.h`. `IF_MAX_STRING_SIZE + 1` is 257, `IF_MAX_PHYS_ADDRESS_LENGTH` 32.
#[repr(C)]
struct MIB_IF_ROW2 {
    InterfaceLuid: u64,
    InterfaceIndex: u32,
    InterfaceGuid: [u8; 16],
    Alias: [u16; 257],
    Description: [u16; 257],
    PhysicalAddressLength: u32,
    PhysicalAddress: [u8; 32],
    PermanentPhysicalAddress: [u8; 32],
    Mtu: u32,
    Type: u32,
    TunnelType: u32,
    MediaType: u32,
    PhysicalMediumType: u32,
    AccessType: u32,
    DirectionType: u32,
    InterfaceAndOperStatusFlags: u8,
    OperStatus: u32,
    AdminStatus: u32,
    MediaConnectState: u32,
    NetworkGuid: [u8; 16],
    ConnectionType: u32,
    TransmitLinkSpeed: u64,
    ReceiveLinkSpeed: u64,
    InOctets: u64,
    InUcastPkts: u64,
    InNUcastPkts: u64,
    InDiscards: u64,
    InErrors: u64,
    InUnknownProtos: u64,
    InUcastOctets: u64,
    InMulticastOctets: u64,
    InBroadcastOctets: u64,
    OutOctets: u64,
    OutUcastPkts: u64,
    OutNUcastPkts: u64,
    OutDiscards: u64,
    OutErrors: u64,
    OutUcastOctets: u64,
    OutMulticastOctets: u64,
    OutBroadcastOctets: u64,
    OutQLen: u64,
}
const _: () = assert!(
    size_of::<MIB_IF_ROW2>() == 1352
        && offset_of!(MIB_IF_ROW2, Alias) == 28
        && offset_of!(MIB_IF_ROW2, OperStatus) == 1156
        && offset_of!(MIB_IF_ROW2, InOctets) == 1208
        && offset_of!(MIB_IF_ROW2, OutQLen) == 1344
);

#[repr(C)]
struct MIB_IF_TABLE2 {
    NumEntries: u32,
    Table: [MIB_IF_ROW2; 1],
}
const _: () = assert!(offset_of!(MIB_IF_TABLE2, Table) == 8);

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetSystemTimes(idle: *mut u64, kernel: *mut u64, user: *mut u64) -> i32;
    fn GlobalMemoryStatusEx(buffer: *mut MEMORYSTATUSEX) -> i32;
    fn GetLogicalDriveStringsW(length: u32, buffer: *mut u16) -> u32;
    fn GetDriveTypeW(root: *const u16) -> u32;
    fn GetDiskFreeSpaceExW(root: *const u16, available: *mut u64, total: *mut u64, free: *mut u64) -> i32;
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> HANDLE;
    fn Process32FirstW(snapshot: HANDLE, entry: *mut PROCESSENTRY32W) -> i32;
    fn Process32NextW(snapshot: HANDLE, entry: *mut PROCESSENTRY32W) -> i32;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> HANDLE;
    fn GetProcessTimes(process: HANDLE, creation: *mut u64, exit: *mut u64, kernel: *mut u64, user: *mut u64) -> i32;
    fn K32GetProcessMemoryInfo(process: HANDLE, counters: *mut PROCESS_MEMORY_COUNTERS_EX, size: u32) -> i32;
    fn GetProcessHandleCount(process: HANDLE, count: *mut u32) -> i32;
    fn CloseHandle(handle: HANDLE) -> i32;
}

#[link(name = "iphlpapi")]
unsafe extern "system" {
    fn GetIfTable2(table: *mut *mut MIB_IF_TABLE2) -> u32;
    fn FreeMibTable(memory: *const c_void);
}

/// `GetSystemTimes`' kernel time includes idle time, so busy is kernel plus
/// user minus idle.
pub(crate) fn cpu() -> Option<CpuTimes> {
    let (mut idle, mut kernel, mut user) = (0_u64, 0_u64, 0_u64);
    // A FILETIME is two little-endian u32 halves: the same bytes as a u64.
    let ok = unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) } != 0;
    ok.then(|| CpuTimes { idle, busy: (kernel + user).saturating_sub(idle) })
}

pub(crate) fn memory() -> Option<Memory> {
    let mut status = MEMORYSTATUSEX {
        dwLength: size_of::<MEMORYSTATUSEX>() as u32,
        dwMemoryLoad: 0,
        ullTotalPhys: 0,
        ullAvailPhys: 0,
        ullTotalPageFile: 0,
        ullAvailPageFile: 0,
        ullTotalVirtual: 0,
        ullAvailVirtual: 0,
        ullAvailExtendedVirtual: 0,
    };
    let ok = unsafe { GlobalMemoryStatusEx(&mut status) } != 0;
    // The "page file" fields are the commit limit and what remains of it.
    ok.then_some(Memory {
        total: status.ullTotalPhys,
        available: status.ullAvailPhys,
        commit_limit: status.ullTotalPageFile,
        commit_available: status.ullAvailPageFile,
    })
}

/// Fixed drives only: asking a card reader or optical drive with no media
/// for its size can stall or raise a dialog.
pub(crate) fn disks() -> Vec<Disk> {
    let mut buffer = [0_u16; 512];
    let written = unsafe { GetLogicalDriveStringsW(buffer.len() as u32, buffer.as_mut_ptr()) } as usize;
    if written == 0 || written > buffer.len() {
        return Vec::new();
    }
    // A run of NUL-terminated roots ("C:\\\0D:\\\0\0").
    buffer[..written]
        .split(|&unit| unit == 0)
        .filter(|root| !root.is_empty())
        .filter_map(|root| {
            let terminated: Vec<u16> = root.iter().copied().chain([0]).collect();
            if unsafe { GetDriveTypeW(terminated.as_ptr()) } != DRIVE_FIXED {
                return None;
            }
            let (mut available, mut total, mut free) = (0_u64, 0_u64, 0_u64);
            let ok = unsafe { GetDiskFreeSpaceExW(terminated.as_ptr(), &mut available, &mut total, &mut free) } != 0;
            ok.then(|| Disk { mount: String::from_utf16_lossy(root), total, free: available })
        })
        .collect()
}

/// Adapters that are up, excluding loopback and filter-driver shadows.
pub(crate) fn net() -> Vec<NetCounters> {
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    if unsafe { GetIfTable2(&mut table) } != 0 || table.is_null() {
        return Vec::new();
    }
    let mut adapters = Vec::new();
    // SAFETY: GetIfTable2 succeeded, so `table` points at NumEntries rows laid
    // out as MIB_IF_ROW2 (whose size is asserted above), freed only below.
    unsafe {
        let count = (*table).NumEntries as usize;
        let rows = std::ptr::addr_of!((*table).Table).cast::<MIB_IF_ROW2>();
        for index in 0..count {
            let row = &*rows.add(index);
            if row.OperStatus != IF_OPER_STATUS_UP
                || row.Type == IF_TYPE_SOFTWARE_LOOPBACK
                || row.InterfaceAndOperStatusFlags & FILTER_INTERFACE != 0
            {
                continue;
            }
            adapters.push(NetCounters {
                name: wide_to_string(&row.Alias),
                rx: row.InOctets,
                tx: row.OutOctets,
                errors: row.InErrors + row.OutErrors,
                discards: row.InDiscards + row.OutDiscards,
            });
        }
        FreeMibTable(table.cast());
    }
    adapters
}

/// Every process this account can open. Protected processes refuse and are
/// skipped; they are the kernel's, not anything that could be ours.
pub(crate) fn processes() -> Vec<ProcessRaw> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Vec::new();
    }
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; 260],
    };
    let mut found = Vec::new();
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while more {
        let name = wide_to_string(&entry.szExeFile);
        if let Some(process) = open(entry.th32ProcessID, name) {
            found.push(process);
        }
        let next = unsafe { Process32NextW(snapshot, &mut entry) };
        more = next != 0;
    }
    unsafe {
        CloseHandle(snapshot);
    }
    found
}

fn open(pid: u32, name: String) -> Option<ProcessRaw> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }
    let (mut creation, mut exit, mut kernel, mut user) = (0_u64, 0_u64, 0_u64, 0_u64);
    let mut memory = PROCESS_MEMORY_COUNTERS_EX {
        cb: size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        PageFaultCount: 0,
        PeakWorkingSetSize: 0,
        WorkingSetSize: 0,
        QuotaPeakPagedPoolUsage: 0,
        QuotaPagedPoolUsage: 0,
        QuotaPeakNonPagedPoolUsage: 0,
        QuotaNonPagedPoolUsage: 0,
        PagefileUsage: 0,
        PeakPagefileUsage: 0,
        PrivateUsage: 0,
    };
    let mut handles = 0_u32;
    // SAFETY: `handle` is open until the CloseHandle below; every out-pointer
    // is a live local of the size the call expects.
    let ok = unsafe {
        let timed = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) != 0;
        let sized = K32GetProcessMemoryInfo(handle, &mut memory, memory.cb) != 0;
        if is_selfhost(&name) {
            GetProcessHandleCount(handle, &mut handles);
        }
        CloseHandle(handle);
        timed && sized
    };
    ok.then(|| ProcessRaw {
        pid,
        start: creation,
        name,
        cpu_secs: (kernel + user) as f64 / TICKS_PER_SEC,
        working_set: memory.WorkingSetSize as u64,
        private: memory.PrivateUsage as u64,
        handles,
    })
}

fn wide_to_string(wide: &[u16]) -> String {
    let end = wide.iter().position(|&unit| unit == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..end])
}
