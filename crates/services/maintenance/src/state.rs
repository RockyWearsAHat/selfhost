//! Maintenance scheduler state: last reboot, next reboot, in-maintenance flag.

use serde::{Serialize, Deserialize};

/// Current state of the maintenance scheduler.
/// Shared across the daemon and queried by the admin API and CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaintenanceState {
    /// Whether the daemon is currently in the reboot sequence
    /// (draining connections, about to reboot).
    pub in_maintenance: bool,

    /// The last time the host was rebooted by the maintenance scheduler
    /// (as a UNIX timestamp in seconds). None if the daemon has never completed
    /// a reboot cycle since startup.
    pub last_reboot: Option<u64>,

    /// The next scheduled reboot time (as a UNIX timestamp in seconds).
    /// Updated after each reboot to the following day's scheduled time.
    pub next_reboot: u64,
}

impl MaintenanceState {
    /// Create a new maintenance state with the given values.
    pub fn new(in_maintenance: bool, last_reboot: Option<u64>, next_reboot: u64) -> Self {
        Self {
            in_maintenance,
            last_reboot,
            next_reboot,
        }
    }

    /// Serialize to JSON for the admin API response.
    pub fn to_json(&self) -> selfhost_json::Json {
        let mut fields = vec![
            ("in_maintenance".to_string(), selfhost_json::Json::Bool(self.in_maintenance)),
            ("next_reboot".to_string(), selfhost_json::Json::Number(self.next_reboot as f64)),
        ];

        if let Some(last) = self.last_reboot {
            fields.push(("last_reboot".to_string(), selfhost_json::Json::Number(last as f64)));
        }

        selfhost_json::Json::Object(fields.into_iter().collect())
    }
}
