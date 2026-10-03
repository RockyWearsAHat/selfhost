//! DNS statistics writer: periodically writes telemetry to a JSON file.

use crate::authority::Authority;
use crate::telemetry::snapshot_to_json;
use std::path::Path;
use std::time::Duration;
use tokio::time::interval;

/// Spawns a background task that writes DNS statistics every 10 seconds.
///
/// Writes to `<data_dir>/insight/dns-stats.json` atomically (temp file + rename).
pub async fn spawn_stats_writer(
    authority: Authority,
    data_dir: &Path,
    process: &str,
) {
    let data_dir = data_dir.to_path_buf();
    let process_name = process.to_string();
    let insight_dir = data_dir.join("insight");

    // Ensure the insight directory exists.
    if let Err(e) = tokio::fs::create_dir_all(&insight_dir).await {
        eprintln!(
            "{} [dns-writer] failed to create insight directory: {e}",
            crate::time::stamp()
        );
        return;
    }

    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(10));

        loop {
            ticker.tick().await;

            let snapshot = authority.telemetry_snapshot(&process_name);
            let json = snapshot_to_json(&snapshot);
            let json_str = json.to_text();

            let stats_file = insight_dir.join("dns-stats.json");
            let temp_file = insight_dir.join("dns-stats.json.tmp");

            // Write to temp file first.
            if let Err(e) = tokio::fs::write(&temp_file, json_str.as_bytes()).await {
                eprintln!(
                    "{} [dns-writer] failed to write temp file: {e}",
                    crate::time::stamp()
                );
                continue;
            }

            // Atomically rename temp file to final location.
            if let Err(e) = tokio::fs::rename(&temp_file, &stats_file).await {
                eprintln!(
                    "{} [dns-writer] failed to rename stats file: {e}",
                    crate::time::stamp()
                );
                // Attempt cleanup of temp file.
                let _ = tokio::fs::remove_file(&temp_file).await;
            }
        }
    });
}
