//! Linux counters from `/proc`: plain file reads, no `unsafe`.
//!
//! Disk space needs `statvfs`, which std does not expose, so Linux reports no
//! disks; production is Windows, where disks are read.

use super::{CpuTimes, Disk, Memory, NetCounters, ProcessRaw};
use std::fs;

/// USER_HZ, the unit of `/proc/<pid>/stat` CPU times on every mainstream
/// Linux.
const TICKS_PER_SEC: f64 = 100.0;

pub(crate) fn cpu() -> Option<CpuTimes> {
    let stat = fs::read_to_string("/proc/stat").ok()?;
    parse_cpu(stat.lines().next()?)
}

fn parse_cpu(line: &str) -> Option<CpuTimes> {
    // cpu  user nice system idle iowait irq softirq steal ...
    let fields: Vec<u64> = line.strip_prefix("cpu ")?.split_whitespace().filter_map(|f| f.parse().ok()).collect();
    let idle = fields.get(3)? + fields.get(4).unwrap_or(&0);
    let total: u64 = fields.iter().take(8).sum();
    Some(CpuTimes { idle, busy: total.saturating_sub(idle) })
}

pub(crate) fn memory() -> Option<Memory> {
    let info = fs::read_to_string("/proc/meminfo").ok()?;
    let field = |key: &str| -> Option<u64> {
        let line = info.lines().find(|line| line.starts_with(key))?;
        let kib: u64 = line[key.len()..].trim().trim_end_matches("kB").trim().parse().ok()?;
        Some(kib * 1024)
    };
    let limit = field("CommitLimit:")?;
    Some(Memory {
        total: field("MemTotal:")?,
        available: field("MemAvailable:")?,
        commit_limit: limit,
        commit_available: limit.saturating_sub(field("Committed_AS:")?),
    })
}

pub(crate) fn disks() -> Vec<Disk> {
    Vec::new()
}

pub(crate) fn net() -> Vec<NetCounters> {
    let Ok(dev) = fs::read_to_string("/proc/net/dev") else {
        return Vec::new();
    };
    dev.lines().skip(2).filter_map(parse_net).filter(|adapter| adapter.name != "lo").collect()
}

fn parse_net(line: &str) -> Option<NetCounters> {
    // name: rx_bytes packets errs drop fifo frame compressed multicast tx_bytes packets errs drop ...
    let (name, rest) = line.split_once(':')?;
    let fields: Vec<u64> = rest.split_whitespace().filter_map(|f| f.parse().ok()).collect();
    Some(NetCounters {
        name: name.trim().to_owned(),
        rx: *fields.first()?,
        tx: *fields.get(8)?,
        errors: fields.get(2)? + fields.get(10)?,
        discards: fields.get(3)? + fields.get(11)?,
    })
}

pub(crate) fn processes() -> Vec<ProcessRaw> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<u32>().ok())
        .filter_map(|pid| parse_process(pid, &fs::read_to_string(format!("/proc/{pid}/stat")).ok()?))
        .collect()
}

fn parse_process(pid: u32, stat: &str) -> Option<ProcessRaw> {
    // pid (comm) state ppid ... utime(14) stime(15) ... starttime(22) vsize(23) rss(24)
    let (head, tail) = stat.rsplit_once(')')?;
    let name = head.split_once('(')?.1.to_owned();
    let fields: Vec<&str> = tail.split_whitespace().collect();
    let at = |field: usize| -> Option<u64> { fields.get(field - 3)?.parse().ok() };
    let rss_pages = at(24)?;
    Some(ProcessRaw {
        pid,
        start: at(22)?,
        name,
        cpu_secs: (at(14)? + at(15)?) as f64 / TICKS_PER_SEC,
        working_set: rss_pages * 4096,
        private: rss_pages * 4096,
        handles: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_busy_excludes_idle_and_iowait() {
        let times = parse_cpu("cpu  100 0 50 800 50 0 0 0 0 0").unwrap();
        assert_eq!(times, CpuTimes { idle: 850, busy: 150 });
    }

    #[test]
    fn net_reads_bytes_errors_and_drops() {
        let adapter = parse_net("  eth0: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0").unwrap();
        assert_eq!(adapter, NetCounters { name: "eth0".into(), rx: 1000, tx: 2000, errors: 4, discards: 6 });
    }

    #[test]
    fn a_process_name_may_contain_spaces_and_parentheses() {
        let stat = "42 (selfhost (x)) S 1 1 1 0 -1 0 0 0 0 0 300 200 0 0 20 0 1 0 5000 1000 25 0";
        let process = parse_process(42, stat).unwrap();
        assert_eq!(process.name, "selfhost (x)");
        assert_eq!(process.cpu_secs, 5.0);
        assert_eq!(process.start, 5000);
        assert_eq!(process.working_set, 25 * 4096);
    }
}
