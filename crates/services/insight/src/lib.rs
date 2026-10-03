//! Machine sampler: cheap monitoring of CPU, memory, disk, and network.
//!
//! Every 10 seconds, captures one Sample of the whole machine's vitals:
//! CPU percentage, memory, disk space and throughput, network throughput and errors.
//!
//! Stores samples as an append-only NDJSON ring under `<data_dir>/insight/samples-YYYY-MM-DD.ndjson`,
//! deleting files older than 7 days at each day rollover.
//!
//! Every 30 seconds, samples the top processes by CPU and memory.
//! Every 5 minutes, reads Windows events.
//! Every 10 seconds, evaluates trend warnings and writes events to the timeline.
//!
//! This crate is NOT wired into the daemon yet; it provides the sampling and storage primitives
//! for the admin API and the UI to query.

mod sys;

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use tokio::io::AsyncWriteExt;

/// One system snapshot: CPU, memory, disk, network at a point in time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Sample {
    /// Unix timestamp in seconds when the sample was taken.
    pub at_unix: u64,
    /// CPU utilization as a percentage of one core (0-100 or higher on multicore).
    /// None if not available on this platform.
    pub cpu_pct: Option<f64>,
    /// Total physical memory in megabytes.
    pub mem_total_mb: u64,
    /// Currently used memory in megabytes.
    pub mem_used_mb: u64,
    /// Per-disk usage snapshot.
    pub disks: Vec<DiskSample>,
    /// Per-interface network counters.
    pub net: Vec<NetSample>,
}

/// One disk's usage snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DiskSample {
    /// Mount point path.
    pub mount: String,
    /// Total capacity in megabytes.
    pub total_mb: u64,
    /// Free space in megabytes.
    pub free_mb: u64,
}

/// One network interface's cumulative counters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetSample {
    /// Interface name (e.g., "eth0", "en0").
    pub name: String,
    /// Cumulative bytes received.
    pub rx_bytes: u64,
    /// Cumulative bytes transmitted.
    pub tx_bytes: u64,
    /// Cumulative receive errors.
    pub rx_errors: u64,
    /// Cumulative transmit errors.
    pub tx_errors: u64,
}

/// One process snapshot: CPU cores used (as delta), working set memory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessSample {
    /// Process ID.
    pub pid: u32,
    /// Process name.
    pub name: String,
    /// CPU cores used (delta since last sample, computed as (delta process times) / wall time).
    pub cpu_cores: f64,
    /// Working set memory in megabytes.
    pub working_set_mb: u64,
}

/// One Windows event entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WindowsEvent {
    /// Event provider name.
    pub provider: String,
    /// Event ID.
    pub id: u32,
    /// Unix timestamp when the event occurred.
    pub at_unix: u64,
    /// First line of the event message.
    pub message: String,
}

/// One event in the timeline: warning, cleared, windows-event, repair, or dns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Event {
    /// Unix timestamp when the event was recorded.
    pub at_unix: u64,
    /// Event kind: "warning", "cleared", "windows-event", "repair", or "dns".
    pub kind: String,
    /// Source of the event (e.g., "memory", "disk", "selfhost-cli", "dns").
    pub source: String,
    /// Event title.
    pub title: String,
    /// Event detail.
    pub detail: String,
    /// Evidence object (JSON).
    #[serde(default)]
    pub evidence: serde_json::Value,
}

/// DNS counters from the DNS stats file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsCounters {
    /// Total queries in the last 5 minutes.
    pub queries: u64,
    /// Failed queries in the last 5 minutes.
    pub failures: u64,
    /// Dropped queries in the last 5 minutes.
    pub dropped: u64,
}

/// Problem entry for the Now status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Problem {
    /// Problem ID.
    pub id: String,
    /// Problem title.
    pub title: String,
    /// Unix timestamp when the problem started.
    pub since_unix: u64,
    /// Evidence object (JSON).
    #[serde(default)]
    pub evidence: serde_json::Value,
}

/// Current machine status snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Now {
    /// Overall condition: "ok", "warning", or "failing".
    pub condition: String,
    /// List of current problems.
    pub problems: Vec<Problem>,
    /// Machine summary string.
    pub machine_summary: String,
    /// List of selfhost processes running.
    pub selfhost_processes: Vec<ProcessSample>,
    /// DNS stats from the last 5 minutes.
    pub dns_last_5min: DnsCounters,
}

/// Returns the current system sample.
///
/// This is a cheap operation (no polling loop, no allocations for fixed-size fields).
/// Platform-specific implementations live in `sys/`.
pub fn sample() -> io::Result<Sample> {
    sys::sample()
}

/// Samples running processes (top 8 by CPU, top 8 by memory, and all selfhost processes).
///
/// Only implemented on Windows; returns an empty vector on other platforms.
pub fn sample_processes() -> io::Result<Vec<ProcessSample>> {
    sys::sample_processes()
}

/// Reads recent Windows events (critical and error level, from the last 5 minutes).
///
/// Only implemented on Windows; returns an empty vector on other platforms.
pub fn read_windows_events() -> io::Result<Vec<WindowsEvent>> {
    sys::read_windows_events()
}

/// Reads samples from the day-file ring within a time window.
///
/// # Arguments
///
/// * `data_dir` - The root data directory (samples are in `<data_dir>/insight/`)
/// * `since` - Unix timestamp in seconds (inclusive)
/// * `until` - Unix timestamp in seconds (exclusive)
///
/// Returns samples in chronological order (earliest first).
pub fn read_samples(data_dir: &Path, since: u64, until: u64) -> io::Result<Vec<Sample>> {
    let insight_dir = data_dir.join("insight");
    if !insight_dir.exists() {
        return Ok(Vec::new());
    }

    let mut samples = Vec::new();

    // Iterate over all sample files in the insight directory
    for entry in fs::read_dir(&insight_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            let filename = path.file_name().unwrap().to_string_lossy();
            if filename.starts_with("samples-") && filename.ends_with(".ndjson") {
                // Try to parse samples from this file
                if let Ok(file_samples) = read_file_samples(&path, since, until) {
                    samples.extend(file_samples);
                }
            }
        }
    }

    // Ensure samples are sorted by timestamp
    samples.sort_by_key(|s| s.at_unix);
    Ok(samples)
}

/// Reads samples from a single file, filtering by time window.
fn read_file_samples(path: &Path, since: u64, until: u64) -> io::Result<Vec<Sample>> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut samples = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        if let Ok(sample) = serde_json::from_str::<Sample>(&line) {
            if sample.at_unix >= since && sample.at_unix < until {
                samples.push(sample);
            }
        }
    }

    Ok(samples)
}

/// Appends a sample to today's sample file, rolling to a new day if needed.
/// Deletes sample files older than 7 days.
pub async fn append_sample(data_dir: &Path, sample: &Sample) -> io::Result<()> {
    let insight_dir = data_dir.join("insight");
    tokio::fs::create_dir_all(&insight_dir).await?;

    // Determine today's date in YYYY-MM-DD format
    let today = format_date_from_unix(sample.at_unix);
    let sample_file = insight_dir.join(format!("samples-{}.ndjson", today));

    // Append the sample as a JSON line
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&sample_file)
        .await?;

    let json_line = serde_json::to_string(sample)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    file.write_all(json_line.as_bytes()).await?;
    file.write_all(b"\n").await?;

    // Clean up old files (older than 7 days)
    cleanup_old_samples(&insight_dir, sample.at_unix).await?;

    Ok(())
}

/// Formats a Unix timestamp as YYYY-MM-DD.
fn format_date_from_unix(unix_time: u64) -> String {
    let secs_per_day = 86400;
    let days_since_epoch = unix_time / secs_per_day;

    // Epoch is 1970-01-01
    // Calculate year, month, day
    let mut year = 1970;
    let mut day_of_year = days_since_epoch;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if day_of_year < days_in_year {
            break;
        }
        day_of_year -= days_in_year;
        year += 1;
    }

    let days_in_months = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 0;
    let mut day = day_of_year;
    for (i, &days_in_month) in days_in_months.iter().enumerate() {
        if day < days_in_month {
            month = i + 1;
            break;
        }
        day -= days_in_month;
    }

    format!("{:04}-{:02}-{:02}", year, month, day + 1)
}

/// Checks if a year is a leap year.
fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Deletes sample files older than 7 days.
async fn cleanup_old_samples(insight_dir: &Path, current_unix: u64) -> io::Result<()> {
    let seven_days_ago = if current_unix > 7 * 86400 {
        current_unix - 7 * 86400
    } else {
        0
    };
    let cutoff_date = format_date_from_unix(seven_days_ago);

    let mut read_dir = tokio::fs::read_dir(insight_dir).await?;
    while let Some(entry) = read_dir.next_entry().await? {
        let path = entry.path();
        if path.is_file() {
            let filename = path.file_name().unwrap().to_string_lossy();
            if let Some(date_str) = filename.strip_prefix("samples-").and_then(|s| s.strip_suffix(".ndjson")) {
                if date_str < cutoff_date.as_str() {
                    let _ = tokio::fs::remove_file(&path).await;
                }
            }
        }
    }

    Ok(())
}

/// Reads DNS stats from <data_dir>/insight/dns-stats.json.
/// Returns the total queries, failures, and dropped packets in the last 5 minutes.
pub async fn read_dns_stats(data_dir: &Path) -> io::Result<DnsCounters> {
    let stats_file = data_dir.join("insight/dns-stats.json");
    if !stats_file.exists() {
        return Ok(DnsCounters {
            queries: 0,
            failures: 0,
            dropped: 0,
        });
    }

    let content = tokio::fs::read_to_string(&stats_file).await?;
    let stats: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Sum counters from the last 5 minutes (300 seconds)
    let mut queries = 0u64;
    let mut failures = 0u64;
    let mut dropped = 0u64;

    if let Some(minutes) = stats.get("minutes").and_then(|m| m.as_array()) {
        // Last 5 minutes = last 5 entries (each entry is 1 minute)
        let start_idx = if minutes.len() > 5 {
            minutes.len() - 5
        } else {
            0
        };

        for minute in &minutes[start_idx..] {
            if let Some(q) = minute.get("queries").and_then(|v| v.as_u64()) {
                queries += q;
            }
            if let Some(f) = minute.get("failures").and_then(|v| v.as_u64()) {
                failures += f;
            }
        }
    }

    // Check for dropped in the last 5 minutes
    if let Some(counters) = stats.get("counters") {
        if let Some(d) = counters.get("dropped").and_then(|v| v.as_u64()) {
            dropped = d;
        }
    }

    Ok(DnsCounters {
        queries,
        failures,
        dropped,
    })
}

/// Appends an event to today's event file.
pub async fn append_event(data_dir: &Path, event: &Event) -> io::Result<()> {
    let insight_dir = data_dir.join("insight");
    tokio::fs::create_dir_all(&insight_dir).await?;

    let today = format_date_from_unix(event.at_unix);
    let event_file = insight_dir.join(format!("events-{}.ndjson", today));

    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&event_file)
        .await?;

    let json_line = serde_json::to_string(event)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    file.write_all(json_line.as_bytes()).await?;
    file.write_all(b"\n").await?;

    Ok(())
}

/// Reads events from the event timeline within a time window.
pub fn read_events(data_dir: &Path, since: u64, until: u64) -> io::Result<Vec<Event>> {
    let insight_dir = data_dir.join("insight");
    if !insight_dir.exists() {
        return Ok(Vec::new());
    }

    let mut events = Vec::new();

    for entry in fs::read_dir(&insight_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            let filename = path.file_name().unwrap().to_string_lossy();
            if filename.starts_with("events-") && filename.ends_with(".ndjson") {
                let file = fs::File::open(&path)?;
                let reader = BufReader::new(file);

                for line in reader.lines() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }

                    if let Ok(event) = serde_json::from_str::<Event>(&line) {
                        if event.at_unix >= since && event.at_unix < until {
                            events.push(event);
                        }
                    }
                }
            }
        }
    }

    events.sort_by_key(|e| e.at_unix);
    Ok(events)
}

/// Computes the current machine status based on the latest samples, events, and DNS stats.
pub async fn now(data_dir: &Path, current_unix: u64) -> io::Result<Now> {
    // Read the latest sample (last 10 seconds worth)
    let samples = read_samples(data_dir, current_unix - 10, current_unix)?;
    let latest_sample = samples.last();

    // Read DNS stats
    let dns_stats = read_dns_stats(data_dir).await?;

    // Compute overall condition and problems
    let mut problems = Vec::new();
    let mut condition = "ok".to_string();

    // Check memory usage
    if let Some(sample) = latest_sample {
        let mem_pct = if sample.mem_total_mb > 0 {
            (sample.mem_used_mb as f64 / sample.mem_total_mb as f64) * 100.0
        } else {
            0.0
        };

        if mem_pct > 90.0 {
            condition = "warning".to_string();
            problems.push(Problem {
                id: "memory_high".to_string(),
                title: format!("Memory usage {:.1}%", mem_pct),
                since_unix: current_unix,
                evidence: serde_json::json!({
                    "used_mb": sample.mem_used_mb,
                    "total_mb": sample.mem_total_mb,
                }),
            });
        }

        // Check disk usage
        for disk in &sample.disks {
            let disk_pct = if disk.total_mb > 0 {
                ((disk.total_mb - disk.free_mb) as f64 / disk.total_mb as f64) * 100.0
            } else {
                0.0
            };

            if disk_pct > 90.0 {
                condition = "warning".to_string();
                problems.push(Problem {
                    id: format!("disk_full_{}", disk.mount.replace("/", "_").replace(":", "")),
                    title: format!("Disk {} usage {:.1}%", disk.mount, disk_pct),
                    since_unix: current_unix,
                    evidence: serde_json::json!({
                        "mount": disk.mount,
                        "free_mb": disk.free_mb,
                        "total_mb": disk.total_mb,
                    }),
                });
            }
        }
    }

    // Check DNS failure rate
    if dns_stats.queries > 0 {
        let failure_rate = (dns_stats.failures as f64 / dns_stats.queries as f64) * 100.0;
        if failure_rate > 1.0 || dns_stats.dropped > 0 {
            condition = "warning".to_string();
            problems.push(Problem {
                id: "dns_failures".to_string(),
                title: format!("DNS failure rate {:.1}%", failure_rate),
                since_unix: current_unix,
                evidence: serde_json::json!({
                    "failures": dns_stats.failures,
                    "queries": dns_stats.queries,
                    "dropped": dns_stats.dropped,
                }),
            });
        }
    }

    // Build machine summary
    let machine_summary = if let Some(sample) = latest_sample {
        format!(
            "CPU: {:.1}%, Memory: {}/{} MB, Disk: {} mounts",
            sample.cpu_pct.unwrap_or(0.0),
            sample.mem_used_mb,
            sample.mem_total_mb,
            sample.disks.len()
        )
    } else {
        "No samples available".to_string()
    };

    Ok(Now {
        condition,
        problems,
        machine_summary,
        selfhost_processes: Vec::new(), // Populated by process sampling
        dns_last_5min: dns_stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_format_date_from_unix() {
        // 1970-01-01 00:00:00 UTC
        assert_eq!(format_date_from_unix(0), "1970-01-01");

        // 1970-01-02 00:00:00 UTC
        assert_eq!(format_date_from_unix(86400), "1970-01-02");

        // 2000-01-01 00:00:00 UTC (leap year)
        assert_eq!(format_date_from_unix(946684800), "2000-01-01");

        // 2025-10-03 00:00:00 UTC (approximate)
        // Days from 1970-01-01 to 2025-10-03
        let days = (2025 - 1970) * 365
            + ((2025 - 1970) / 4) - ((2025 - 1970) / 100) + ((2025 - 1970) / 400)
            + 276; // days from Jan 1 to Oct 3
        let unix_time = days as u64 * 86400;
        let formatted = format_date_from_unix(unix_time);
        assert!(formatted.starts_with("2025-10-"));
    }

    #[test]
    fn test_sample_serialization() {
        let sample = Sample {
            at_unix: 1696320000,
            cpu_pct: Some(25.5),
            mem_total_mb: 16384,
            mem_used_mb: 8192,
            disks: vec![DiskSample {
                mount: "/".to_string(),
                total_mb: 1000000,
                free_mb: 500000,
            }],
            net: vec![NetSample {
                name: "eth0".to_string(),
                rx_bytes: 1000000,
                tx_bytes: 2000000,
                rx_errors: 0,
                tx_errors: 0,
            }],
        };

        let json = serde_json::to_string(&sample).unwrap();
        let deserialized: Sample = serde_json::from_str(&json).unwrap();
        assert_eq!(sample, deserialized);
    }

    #[tokio::test]
    async fn test_append_and_read_samples() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path();

        let sample1 = Sample {
            at_unix: 1696320000,
            cpu_pct: Some(25.5),
            mem_total_mb: 16384,
            mem_used_mb: 8192,
            disks: vec![],
            net: vec![],
        };

        let sample2 = Sample {
            at_unix: 1696320010,
            cpu_pct: Some(30.0),
            mem_total_mb: 16384,
            mem_used_mb: 9000,
            disks: vec![],
            net: vec![],
        };

        // Append samples
        append_sample(data_dir, &sample1).await.unwrap();
        append_sample(data_dir, &sample2).await.unwrap();

        // Read them back
        let samples = read_samples(data_dir, 1696320000, 1696320020).unwrap();
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].at_unix, 1696320000);
        assert_eq!(samples[1].at_unix, 1696320010);
    }

    #[tokio::test]
    async fn test_read_samples_with_window() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path();

        // Create samples across a day boundary (for testing purposes, all on same day)
        for i in 0..5 {
            let sample = Sample {
                at_unix: 1696320000 + (i * 10),
                cpu_pct: Some(20.0 + i as f64),
                mem_total_mb: 16384,
                mem_used_mb: 8192,
                disks: vec![],
                net: vec![],
            };
            append_sample(data_dir, &sample).await.unwrap();
        }

        // Read only a window
        let samples = read_samples(data_dir, 1696320010, 1696320030).unwrap();
        assert_eq!(samples.len(), 2); // Only samples at 10 and 20
        assert_eq!(samples[0].at_unix, 1696320010);
        assert_eq!(samples[1].at_unix, 1696320020);
    }

    #[tokio::test]
    async fn test_cleanup_old_samples() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path();
        let insight_dir = data_dir.join("insight");
        tokio::fs::create_dir_all(&insight_dir).await.unwrap();

        // Create very old sample files (from July, which is > 7 days before October)
        let old_files = vec!["samples-2025-07-01.ndjson", "samples-2025-07-15.ndjson"];
        for file in &old_files {
            tokio::fs::write(insight_dir.join(file), "{}").await.unwrap();
        }

        // Create recent sample files (within 7 days of October 3)
        let recent_files = vec!["samples-2025-10-01.ndjson", "samples-2025-10-02.ndjson"];
        for file in &recent_files {
            tokio::fs::write(insight_dir.join(file), "{}").await.unwrap();
        }

        // Run cleanup with a timestamp of 2025-10-03
        // This should delete files older than 2025-09-26
        let cutoff_unix = 1759420800u64; // Approximate 2025-10-03
        cleanup_old_samples(&insight_dir, cutoff_unix).await.unwrap();

        // Old files should be deleted
        for file in &old_files {
            assert!(!insight_dir.join(file).exists(), "Old file {} should be deleted", file);
        }

        // Recent files should still exist
        for file in &recent_files {
            assert!(insight_dir.join(file).exists(), "Recent file {} should exist", file);
        }
    }

    #[tokio::test]
    async fn test_append_and_read_events() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path();

        let event1 = Event {
            at_unix: 1696320000,
            kind: "warning".to_string(),
            source: "memory".to_string(),
            title: "High memory usage".to_string(),
            detail: "Memory at 95%".to_string(),
            evidence: serde_json::json!({"mem_pct": 95.0}),
        };

        let event2 = Event {
            at_unix: 1696320100,
            kind: "cleared".to_string(),
            source: "memory".to_string(),
            title: "Memory usage normal".to_string(),
            detail: "Memory at 60%".to_string(),
            evidence: serde_json::json!({"mem_pct": 60.0}),
        };

        // Append events
        append_event(data_dir, &event1).await.unwrap();
        append_event(data_dir, &event2).await.unwrap();

        // Read them back
        let events = read_events(data_dir, 1696320000, 1696320200).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, "warning");
        assert_eq!(events[1].kind, "cleared");
    }

    #[tokio::test]
    async fn test_read_dns_stats() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path();
        let insight_dir = data_dir.join("insight");
        tokio::fs::create_dir_all(&insight_dir).await.unwrap();

        // Create a mock DNS stats file
        let dns_stats = serde_json::json!({
            "at_unix": 1696320000,
            "since_unix": 1696300000,
            "process": "daemon",
            "counters": {
                "queries": 1000,
                "dropped": 5
            },
            "minutes": [
                {"at_unix": 1696300000, "queries": 100, "failures": 1},
                {"at_unix": 1696300060, "queries": 100, "failures": 1},
                {"at_unix": 1696300120, "queries": 100, "failures": 1},
                {"at_unix": 1696300180, "queries": 100, "failures": 1},
                {"at_unix": 1696300240, "queries": 100, "failures": 1},
            ]
        });

        let stats_file = insight_dir.join("dns-stats.json");
        tokio::fs::write(&stats_file, serde_json::to_string(&dns_stats).unwrap())
            .await
            .unwrap();

        let stats = read_dns_stats(data_dir).await.unwrap();
        assert_eq!(stats.queries, 500); // 5 minutes * 100 queries
        assert_eq!(stats.failures, 5); // 5 minutes * 1 failure
        assert_eq!(stats.dropped, 5); // From counters
    }

    #[tokio::test]
    async fn test_now_high_memory() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path();

        let sample = Sample {
            at_unix: 1696320000,
            cpu_pct: Some(20.0),
            mem_total_mb: 16384,
            mem_used_mb: 15600, // 95% usage
            disks: vec![],
            net: vec![],
        };

        append_sample(data_dir, &sample).await.unwrap();

        let status = now(data_dir, 1696320005).await.unwrap();
        assert_eq!(status.condition, "warning");
        assert_eq!(status.problems.len(), 1);
        assert_eq!(status.problems[0].id, "memory_high");
    }

    #[tokio::test]
    async fn test_now_high_disk() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path();

        let sample = Sample {
            at_unix: 1696320000,
            cpu_pct: Some(20.0),
            mem_total_mb: 16384,
            mem_used_mb: 8192,
            disks: vec![DiskSample {
                mount: "C:".to_string(),
                total_mb: 1000000,
                free_mb: 50000, // 95% used
            }],
            net: vec![],
        };

        append_sample(data_dir, &sample).await.unwrap();

        let status = now(data_dir, 1696320005).await.unwrap();
        assert_eq!(status.condition, "warning");
        assert!(status.problems.iter().any(|p| p.id.contains("disk_full")));
    }

    #[tokio::test]
    async fn test_now_high_dns_failure_rate() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path();
        let insight_dir = data_dir.join("insight");
        tokio::fs::create_dir_all(&insight_dir).await.unwrap();

        let sample = Sample {
            at_unix: 1696320000,
            cpu_pct: Some(20.0),
            mem_total_mb: 16384,
            mem_used_mb: 8192,
            disks: vec![],
            net: vec![],
        };

        append_sample(data_dir, &sample).await.unwrap();

        // Create DNS stats with high failure rate
        let dns_stats = serde_json::json!({
            "at_unix": 1696320000,
            "counters": {
                "queries": 100,
                "dropped": 0
            },
            "minutes": [
                {"at_unix": 1696300000, "queries": 100, "failures": 2},
            ]
        });

        tokio::fs::write(
            insight_dir.join("dns-stats.json"),
            serde_json::to_string(&dns_stats).unwrap(),
        )
        .await
        .unwrap();

        let status = now(data_dir, 1696320005).await.unwrap();
        assert_eq!(status.condition, "warning");
        assert!(status.problems.iter().any(|p| p.id == "dns_failures"));
    }

    #[test]
    fn test_process_sample_serialization() {
        let process = ProcessSample {
            pid: 1234,
            name: "selfhost-cli".to_string(),
            cpu_cores: 0.5,
            working_set_mb: 256,
        };

        let json = serde_json::to_string(&process).unwrap();
        let deserialized: ProcessSample = serde_json::from_str(&json).unwrap();
        assert_eq!(process, deserialized);
    }

    #[test]
    fn test_event_serialization() {
        let event = Event {
            at_unix: 1696320000,
            kind: "warning".to_string(),
            source: "memory".to_string(),
            title: "High memory usage".to_string(),
            detail: "Memory at 95%".to_string(),
            evidence: serde_json::json!({"mem_pct": 95.0}),
        };

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_now_serialization() {
        let now = Now {
            condition: "warning".to_string(),
            problems: vec![Problem {
                id: "memory_high".to_string(),
                title: "High memory usage".to_string(),
                since_unix: 1696320000,
                evidence: serde_json::json!({"mem_pct": 95.0}),
            }],
            machine_summary: "CPU: 20.0%, Memory: 8192/16384 MB, Disk: 1 mounts".to_string(),
            selfhost_processes: vec![ProcessSample {
                pid: 1234,
                name: "selfhost-cli".to_string(),
                cpu_cores: 0.5,
                working_set_mb: 256,
            }],
            dns_last_5min: DnsCounters {
                queries: 500,
                failures: 5,
                dropped: 0,
            },
        };

        let json = serde_json::to_string(&now).unwrap();
        let deserialized: Now = serde_json::from_str(&json).unwrap();
        assert_eq!(now, deserialized);
    }
}
