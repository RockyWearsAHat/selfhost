//! Scheduled host maintenance and graceful reboot.
//!
//! This module provides a scheduler that wakes at a configured daily time,
//! marks the host in maintenance mode, drains in-flight HTTP connections,
//! and triggers a platform-specific reboot.
//!
//! The scheduler reads the [maintenance] config section on daemon startup.
//! If present, a background task is spawned that wakes on the schedule.
//!
//! State (last reboot, next reboot, in-maintenance flag) is exposed via
//! the admin API and CLI. The drain signal is a shared flag that the proxy
//! layer checks on each inbound connection.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod reboot;
pub mod state;

pub use state::MaintenanceState;

use chrono_tz::Tz;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;
use tracing::{info, warn};

use selfhost_config::Maintenance;

/// A scheduler task that wakes daily at a configured time and reboots
/// the host after draining. Cheap to clone (state is Arc-wrapped).
#[derive(Clone)]
pub struct MaintenanceScheduler {
    /// Shared mutable state: last reboot, next reboot, in-maintenance flag.
    state: Arc<Mutex<MaintenanceState>>,

    /// Configuration parsed at daemon startup.
    config: Arc<Maintenance>,
}

impl MaintenanceScheduler {
    /// Construct a new scheduler from the [maintenance] config section.
    /// Does not spawn any task; call `spawn_task()` in the daemon's
    /// main startup to begin scheduling.
    pub fn new(config: Maintenance) -> Self {
        let next_wake = Self::compute_next_wake(&config);
        let state = MaintenanceState {
            in_maintenance: false,
            last_reboot: None,
            next_reboot: next_wake,
        };

        Self {
            state: Arc::new(Mutex::new(state)),
            config: Arc::new(config),
        }
    }

    /// Return a clone of the current state (for admin API / CLI queries).
    pub fn status(&self) -> MaintenanceState {
        self.state.lock().unwrap().clone()
    }

    /// Spawn the background scheduler task. Call this once during daemon
    /// startup after loading the config. The task will wake daily at the
    /// configured time and proceed with the reboot sequence.
    ///
    /// This method clones the scheduler so it can be called on an Arc-wrapped
    /// scheduler without consuming the Arc itself.
    pub fn spawn_task(&self) -> tokio::task::JoinHandle<()> {
        let scheduler = self.clone();
        tokio::spawn(async move {
            scheduler.scheduler_loop().await;
        })
    }

    /// Background loop that wakes at the next scheduled time, drains, and reboots.
    async fn scheduler_loop(&self) {
        loop {
            let next = Self::compute_next_wake(&self.config);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            if next > now {
                let duration = Duration::from_secs(next - now);
                info!(
                    "maintenance: next reboot scheduled in {} seconds (at {})",
                    duration.as_secs(),
                    next
                );
                sleep(duration).await;
            }

            // Wake time reached; proceed with reboot sequence
            self.reboot_sequence().await;

            // Update last reboot time and compute next wake
            {
                let mut state = self.state.lock().unwrap();
                state.last_reboot = Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                );
                state.next_reboot = Self::compute_next_wake(&self.config);
                state.in_maintenance = false;
            }
        }
    }

    /// Execute the reboot sequence: mark maintenance, drain, and reboot.
    async fn reboot_sequence(&self) {
        info!("maintenance: entering reboot sequence");

        // Mark maintenance mode globally
        {
            let mut state = self.state.lock().unwrap();
            state.in_maintenance = true;
        }

        // Drain in-flight connections (proxy stops accepting new ones on next poll)
        info!(
            "maintenance: draining connections for {} seconds",
            self.config.drain_timeout_secs
        );
        sleep(Duration::from_secs(self.config.drain_timeout_secs as u64)).await;

        // Check peer health (future work; for now, single-node case just reboots)
        if !self.config.peers.is_empty() {
            info!(
                "maintenance: {} peer(s) configured; peer health check is future work",
                self.config.peers.len()
            );
        }

        // Reboot the host
        info!("maintenance: calling reboot");
        match reboot::reboot() {
            Ok(_) => {
                info!("maintenance: reboot issued successfully");
                // The process should terminate; if it doesn't, we loop and try again.
            }
            Err(e) => {
                warn!("maintenance: reboot failed: {}", e);
                // Clear in_maintenance flag and retry on next schedule
                let mut state = self.state.lock().unwrap();
                state.in_maintenance = false;
            }
        }
    }

    /// Compute the next time the reboot should wake, given the config.
    /// Returns a UNIX timestamp representing the next occurrence of the
    /// configured hour:minute in the configured timezone.
    fn compute_next_wake(config: &Maintenance) -> u64 {
        use chrono::{Timelike, Local};

        let tz: Tz = config
            .tz
            .parse()
            .expect("tz validation should have rejected invalid names");

        let local_now = Local::now().with_timezone(&tz);

        // Build a candidate time for today
        let mut candidate = local_now
            .with_hour(config.reboot_hour)
            .and_then(|t| t.with_minute(config.reboot_minute))
            .and_then(|t| t.with_second(0))
            .expect("hour/minute/second are all in valid range");

        // If the candidate is in the past, use tomorrow
        if candidate <= local_now {
            candidate = candidate + chrono::Duration::days(1);
        }

        // Convert to UNIX timestamp
        candidate.timestamp() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_constructs_successfully() {
        let config = Maintenance {
            reboot_hour: 5,
            reboot_minute: 30,
            tz: "America/Denver".into(),
            drain_timeout_secs: 30,
            peers: vec![],
        };

        let scheduler = MaintenanceScheduler::new(config);
        let status = scheduler.status();

        assert!(!status.in_maintenance);
        assert!(status.last_reboot.is_none());
        assert!(status.next_reboot > 0);
    }

    #[test]
    fn compute_next_wake_returns_future_time() {
        let config = Maintenance {
            reboot_hour: 5,
            reboot_minute: 30,
            tz: "UTC".into(),
            drain_timeout_secs: 30,
            peers: vec![],
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let next = MaintenanceScheduler::compute_next_wake(&config);

        // Next wake should be in the future
        assert!(next > now);

        // Next wake should be within 24 hours + a buffer
        assert!(next < now + 86400 + 3600);
    }
}
