//! Scheduled host maintenance and graceful reboot configuration.
//!
//! A deployment that performs scheduled maintenance declares it here in
//! `selfhost.config.toml`. This module holds the schema and its validation.
//!
//! When present, the daemon spawns a background scheduler that wakes daily at
//! a fixed local time, marks the host in maintenance mode, drains in-flight
//! HTTP connections, and triggers a platform-specific reboot.
//!
//! The `peers` list shapes the config for optional multi-node coordination.
//! For single-node deployments (peers empty), the reboot is unconditional on
//! the local schedule. Future work can implement peer health checks before
//! rebooting.

use serde::{Deserialize, Serialize};

use crate::validate::Problem;

/// Longest a peer name may be, in characters.
const MAX_PEER_NAME_LEN: usize = 32;

/// Longest a person name may be, in characters. Mirrors
/// `identity::MAX_PERSON_NAME_CHARS`, kept local so `config` stays free of a
/// dependency on `identity`.
const MAX_PERSON_NAME_CHARS: usize = 32;

/// Scheduled maintenance window and graceful reboot configuration.
///
/// This section is optional. When present, the daemon runs a background
/// scheduler that reboots the host daily at a fixed local time, after draining
/// in-flight connections and stopping new accept on the proxy.
///
/// The peers list allows future coordination: a second selfhost deployment
/// can be listed here, and the scheduler will check its health before rebooting.
/// For single-node deployments (peers empty), the reboot is unconditional
/// on the local schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Maintenance {
    /// Hour of day in local time (0-23) at which the reboot is scheduled.
    /// Combined with reboot_minute and tz to form the daily trigger.
    /// Required.
    pub reboot_hour: u32,

    /// Minute of the hour (0-59) at which the reboot is scheduled.
    /// Required.
    pub reboot_minute: u32,

    /// IANA timezone string (e.g., "America/Denver", "UTC", "Europe/London").
    /// Used to interpret reboot_hour and reboot_minute in the deployment's
    /// local wall-clock time. Required.
    pub tz: String,

    /// Number of seconds to wait for in-flight HTTP connections to drain
    /// before forcing the reboot. During this window, the proxy stops
    /// accepting new inbound connections but allows existing ones to finish.
    /// Defaults to 30 seconds.
    #[serde(default = "default_drain_timeout_secs")]
    pub drain_timeout_secs: u32,

    /// Optional list of peer selfhost deployments to check before rebooting.
    ///
    /// When empty (single-node case), the reboot happens on schedule without
    /// coordination. When populated, the scheduler queries each peer's health
    /// before proceeding; future work can implement staggered reboot times
    /// or skip reboot if a peer is unhealthy. For now, this list is parsed
    /// and validated but not acted upon at runtime.
    #[serde(default)]
    pub peers: Vec<MaintenancePeer>,
}

/// Default drain timeout: 30 seconds.
fn default_drain_timeout_secs() -> u32 {
    30
}

/// A peer selfhost deployment to coordinate maintenance with.
///
/// When the local scheduler wakes, it may check peer health via their
/// admin API before proceeding with the reboot. In single-node deployments,
/// this list is empty and the reboot is unconditional.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MaintenancePeer {
    /// Short name for this peer, e.g., "node-2" or "remote-box".
    /// Used in log messages and state output.
    pub name: String,

    /// Person who operates this peer node, validated as a PersonName.
    /// Determines permission to reboot this peer (future work).
    pub person: String,

    /// Admin API address of this peer, e.g., "127.0.0.1:9191" or
    /// "remote-box.local:9191". The scheduler will periodically check
    /// this peer's `/api/maintenance/status` endpoint before rebooting.
    pub admin_socket: String,
}

impl Maintenance {
    /// Collects every structural problem with the maintenance configuration.
    ///
    /// `at` is the dotted path problems are reported under (`maintenance`).
    /// Every rule is checked and every violation collected, in the crate's
    /// all-at-once style, so one `selfhost check` names everything that
    /// needs fixing rather than the first thing.
    pub fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        // Validate hour
        if self.reboot_hour > 23 {
            problems.push(Problem {
                field: format!("{at}.reboot_hour"),
                message: format!("hour {} is out of range [0-23]", self.reboot_hour),
            });
        }

        // Validate minute
        if self.reboot_minute > 59 {
            problems.push(Problem {
                field: format!("{at}.reboot_minute"),
                message: format!("minute {} is out of range [0-59]", self.reboot_minute),
            });
        }

        // Validate timezone is not empty
        if self.tz.is_empty() {
            problems.push(Problem {
                field: format!("{at}.tz"),
                message: "timezone is required and cannot be empty".into(),
            });
        }

        // Validate drain timeout is positive
        if self.drain_timeout_secs == 0 {
            problems.push(Problem {
                field: format!("{at}.drain_timeout_secs"),
                message: "must be at least 1 second; zero would not allow any drain time".into(),
            });
        }

        // Validate each peer
        for (i, peer) in self.peers.iter().enumerate() {
            peer.check(&format!("{at}.peers[{i}]"), problems);
        }
    }
}

impl MaintenancePeer {
    /// Validates this peer's configuration.
    fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        // Validate peer name
        if self.name.is_empty() {
            problems.push(Problem {
                field: format!("{at}.name"),
                message: "peer name is required".into(),
            });
        } else if self.name.len() > MAX_PEER_NAME_LEN {
            problems.push(Problem {
                field: format!("{at}.name"),
                message: format!("peer name \"{}\" exceeds {} characters", self.name, MAX_PEER_NAME_LEN),
            });
        }

        // Validate person name
        if self.person.is_empty() {
            problems.push(Problem {
                field: format!("{at}.person"),
                message: "person name is required".into(),
            });
        } else if self.person.len() > MAX_PERSON_NAME_CHARS {
            problems.push(Problem {
                field: format!("{at}.person"),
                message: format!("person name \"{}\" exceeds {} characters", self.person, MAX_PERSON_NAME_CHARS),
            });
        } else if self.person.eq_ignore_ascii_case("owner") {
            problems.push(Problem {
                field: format!("{at}.person"),
                message: "\"owner\" is a reserved name and cannot be used for a person".into(),
            });
        } else if self.person.chars().any(char::is_whitespace) {
            problems.push(Problem {
                field: format!("{at}.person"),
                message: "person name cannot contain whitespace".into(),
            });
        }

        // Validate admin_socket is not empty
        if self.admin_socket.is_empty() {
            problems.push(Problem {
                field: format!("{at}.admin_socket"),
                message: "admin socket address is required".into(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_maintenance_config_passes() {
        let config = Maintenance {
            reboot_hour: 5,
            reboot_minute: 30,
            tz: "America/Denver".into(),
            drain_timeout_secs: 30,
            peers: vec![],
        };

        let mut problems = Vec::new();
        config.check("maintenance", &mut problems);
        assert!(problems.is_empty(), "valid config should have no problems: {problems:?}");
    }

    #[test]
    fn hour_out_of_range_is_caught() {
        let config = Maintenance {
            reboot_hour: 25,
            reboot_minute: 0,
            tz: "UTC".into(),
            drain_timeout_secs: 30,
            peers: vec![],
        };

        let mut problems = Vec::new();
        config.check("maintenance", &mut problems);
        assert!(!problems.is_empty());
        assert!(problems[0].field.contains("reboot_hour"));
    }

    #[test]
    fn minute_out_of_range_is_caught() {
        let config = Maintenance {
            reboot_hour: 5,
            reboot_minute: 60,
            tz: "UTC".into(),
            drain_timeout_secs: 30,
            peers: vec![],
        };

        let mut problems = Vec::new();
        config.check("maintenance", &mut problems);
        assert!(!problems.is_empty());
        assert!(problems[0].field.contains("reboot_minute"));
    }

    #[test]
    fn empty_timezone_is_caught() {
        let config = Maintenance {
            reboot_hour: 5,
            reboot_minute: 30,
            tz: String::new(),
            drain_timeout_secs: 30,
            peers: vec![],
        };

        let mut problems = Vec::new();
        config.check("maintenance", &mut problems);
        assert!(!problems.is_empty());
        assert!(problems[0].field.contains("tz"));
    }

    #[test]
    fn zero_drain_timeout_is_caught() {
        let config = Maintenance {
            reboot_hour: 5,
            reboot_minute: 30,
            tz: "UTC".into(),
            drain_timeout_secs: 0,
            peers: vec![],
        };

        let mut problems = Vec::new();
        config.check("maintenance", &mut problems);
        assert!(!problems.is_empty());
        assert!(problems[0].field.contains("drain_timeout_secs"));
    }

    #[test]
    fn peer_with_empty_name_is_caught() {
        let config = Maintenance {
            reboot_hour: 5,
            reboot_minute: 30,
            tz: "UTC".into(),
            drain_timeout_secs: 30,
            peers: vec![MaintenancePeer {
                name: String::new(),
                person: "alex".into(),
                admin_socket: "127.0.0.1:9191".into(),
            }],
        };

        let mut problems = Vec::new();
        config.check("maintenance", &mut problems);
        assert!(!problems.is_empty());
        assert!(problems[0].field.contains("name"));
    }

    #[test]
    fn peer_with_reserved_owner_person_is_caught() {
        let config = Maintenance {
            reboot_hour: 5,
            reboot_minute: 30,
            tz: "UTC".into(),
            drain_timeout_secs: 30,
            peers: vec![MaintenancePeer {
                name: "node2".into(),
                person: "owner".into(),
                admin_socket: "127.0.0.1:9191".into(),
            }],
        };

        let mut problems = Vec::new();
        config.check("maintenance", &mut problems);
        assert!(!problems.is_empty());
        assert!(problems[0].field.contains("person"));
    }

    #[test]
    fn peer_with_whitespace_in_person_is_caught() {
        let config = Maintenance {
            reboot_hour: 5,
            reboot_minute: 30,
            tz: "UTC".into(),
            drain_timeout_secs: 30,
            peers: vec![MaintenancePeer {
                name: "node2".into(),
                person: "john doe".into(),
                admin_socket: "127.0.0.1:9191".into(),
            }],
        };

        let mut problems = Vec::new();
        config.check("maintenance", &mut problems);
        assert!(!problems.is_empty());
        assert!(problems[0].field.contains("person"));
    }
}

#[cfg(test)]
mod integration_tests {
    use crate::Config;

    #[test]
    fn maintenance_section_parses_from_toml() {
        let text = r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "example"
domains = ["example.com"]
static_root = "./public"

[maintenance]
reboot_hour = 5
reboot_minute = 30
tz = "America/Denver"
drain_timeout_secs = 30
"#;
        let config = Config::parse(text).expect("should parse valid maintenance config");
        assert!(config.maintenance.is_some());
        let maint = config.maintenance.unwrap();
        assert_eq!(maint.reboot_hour, 5);
        assert_eq!(maint.reboot_minute, 30);
        assert_eq!(maint.tz, "America/Denver");
        assert_eq!(maint.drain_timeout_secs, 30);
        assert!(maint.peers.is_empty());
    }

    #[test]
    fn maintenance_section_with_peers_parses_from_toml() {
        let text = r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "example"
domains = ["example.com"]
static_root = "./public"

[maintenance]
reboot_hour = 5
reboot_minute = 30
tz = "UTC"
drain_timeout_secs = 30

[[maintenance.peers]]
name = "node-2"
person = "alex"
admin_socket = "192.168.1.9:9191"
"#;
        let config = Config::parse(text).expect("should parse valid maintenance config with peers");
        assert!(config.maintenance.is_some());
        let maint = config.maintenance.unwrap();
        assert_eq!(maint.peers.len(), 1);
        assert_eq!(maint.peers[0].name, "node-2");
        assert_eq!(maint.peers[0].person, "alex");
    }

    #[test]
    fn maintenance_section_is_optional() {
        let text = r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "example"
domains = ["example.com"]
static_root = "./public"
"#;
        let config = Config::parse(text).expect("should parse config without maintenance");
        assert!(config.maintenance.is_none());
    }

    #[test]
    fn maintenance_with_invalid_hour_fails_validation() {
        let text = r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "example"
domains = ["example.com"]
static_root = "./public"

[maintenance]
reboot_hour = 25
reboot_minute = 30
tz = "UTC"
"#;
        let result = Config::parse(text);
        assert!(result.is_err(), "config with invalid hour should fail validation");
    }
}
