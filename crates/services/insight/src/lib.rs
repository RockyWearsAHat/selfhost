//! Machine sampler: cheap monitoring of CPU, memory, disk, and network.
//!
//! Every 10 seconds, captures one Sample of the whole machine's vitals:
//! CPU percentage, memory, disk space and throughput, network throughput and errors.
//!
//! Stores samples as an append-only NDJSON ring under `<data_dir>/insight/samples-YYYY-MM-DD.ndjson`,
//! deleting files older than 7 days at each day rollover.
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

/// Returns the current system sample.
///
/// This is a cheap operation (no polling loop, no allocations for fixed-size fields).
/// Platform-specific implementations live in `sys/`.
pub fn sample() -> io::Result<Sample> {
    sys::sample()
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
}
