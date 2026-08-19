//! The smart-home subsystem: the `[home]` block.
//!
//! Not to be confused with [`crate::home`], which is this crate's other
//! meaning of the word — the note a running daemon leaves saying which
//! directory it started in. That one is about *this machine's* home; this one
//! is about *the house*. They are kept in separate modules rather than merged
//! because they share nothing but a noun.
//!
//! # Absence is the default
//!
//! No `[home]` block means the subsystem does not exist: nothing is
//! discovered, nothing is polled, and the daemon's arm for it pends forever.
//! That matters more here than the small size of the block suggests, because
//! the subsystem *sweeps the local network by multicast* and then speaks to
//! whatever answered. On a deployment that has no smart-home devices, that is
//! traffic and attack surface bought for nothing.
//!
//! # Why the bind is a port and not an address
//!
//! Every other listener in this configuration takes a full `address:port`, and
//! this one deliberately does not. The home API must be on loopback — the
//! deployment's rule is one public surface, the reverse proxy — and a field
//! that accepts an address is a field somebody can put `0.0.0.0` in. Taking
//! only a port removes the mistake rather than validating it afterwards.
//! `selfhost_home::server::serve` refuses a non-loopback address as well, so
//! the rule is enforced twice, in the configuration and at the socket.
//!
//! # It is reached through a site, not through the admin API
//!
//! The dashboard is served by an ordinary `[[sites]]` block whose `instances`
//! name this port and whose `app_paths` is `["/api"]`. The admin API's relay
//! is not available to it: `console = true` is what unlocks that relay and
//! validation permits only one console site, which the admin console needs.
//! So the site's `allowed_cidrs` is the whole access control for the house,
//! deliberately and as recorded in `docs/labs/home-lab.dx`.

use serde::{Deserialize, Serialize};

use crate::validate::Problem;

/// The smart-home subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Home {
    /// Whether the subsystem runs at all.
    ///
    /// Present-but-false is a real state and a useful one: it parks the
    /// subsystem without deleting the port and the notes around it, the same
    /// way `[mesh] dial = false` parks a peer link.
    #[serde(default)]
    pub enabled: bool,

    /// The loopback port the house API listens on.
    ///
    /// Must match the `port` of the `[[sites.instances]]` entry that serves the
    /// dashboard, or the proxy forwards `/api/*` to a closed door. Validation
    /// cannot check that for you — the site does not know it is this
    /// subsystem's site — so it is worth stating in both places and worth
    /// checking by hand once.
    #[serde(default = "default_port")]
    pub port: u16,

    /// Seconds between re-reading every known device's state.
    ///
    /// Lower feels more immediate and costs more of the network; the default
    /// is chosen so that a person pressing pause on their phone sees the
    /// speaker's own state agree before they conclude the button did nothing.
    #[serde(default = "default_refresh")]
    pub refresh_secs: u64,

    /// Seconds between multicast sweeps for devices that were not there before.
    ///
    /// Far rarer than a refresh, because a device appearing is something that
    /// happens when a person plugs something in.
    #[serde(default = "default_discover")]
    pub discover_secs: u64,
}

fn default_port() -> u16 {
    9210
}

fn default_refresh() -> u64 {
    2
}

fn default_discover() -> u64 {
    60
}

impl Default for Home {
    fn default() -> Self {
        Home {
            enabled: false,
            port: default_port(),
            refresh_secs: default_refresh(),
            discover_secs: default_discover(),
        }
    }
}

impl Home {
    /// Collects every structural problem with this section.
    ///
    /// `at` is the dotted path problems are reported under (`home`), matching
    /// every other `check` in this crate. Every rule is checked and every
    /// violation collected, so one `selfhost check` names everything that needs
    /// fixing rather than the first thing.
    pub fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        // Port 0 asks the operating system to choose, which would leave the
        // site's `instances` pointing at a port nothing can predict. A
        // subsystem reached through a fixed forward cannot have a floating
        // port, so this is refused rather than allowed to fail at runtime as
        // an unexplained 502.
        if self.port == 0 {
            problems.push(Problem {
                field: format!("{at}.port"),
                message: "must name a fixed port; the site's instances forward to it".into(),
            });
        }

        // A refresh of zero is a busy loop against somebody's speakers. It is
        // the one value here that would do real harm to the network rather
        // than merely being useless.
        if self.refresh_secs == 0 {
            problems.push(Problem {
                field: format!("{at}.refresh_secs"),
                message: "must be at least 1; zero polls every device continuously".into(),
            });
        }
        if self.discover_secs == 0 {
            problems.push(Problem {
                field: format!("{at}.discover_secs"),
                message: "must be at least 1; zero sweeps the network continuously".into(),
            });
        }

        // Sweeping more often than the state refresh is backwards: discovery
        // is the expensive, rarely-productive question and refresh is the
        // cheap, always-productive one. A block written that way is more
        // likely a transposition than an intention, and reads to whoever
        // inherits it as though discovery were the cheap one.
        if self.discover_secs < self.refresh_secs {
            problems.push(Problem {
                field: format!("{at}.discover_secs"),
                message: format!(
                    "sweeping every {}s while refreshing every {}s is backwards; \
                     discovery is the expensive question",
                    self.discover_secs, self.refresh_secs
                ),
            });
        }
    }

    /// The refresh interval as a [`std::time::Duration`].
    #[must_use]
    pub fn refresh(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.refresh_secs)
    }

    /// The discovery interval as a [`std::time::Duration`].
    #[must_use]
    pub fn discover(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.discover_secs)
    }

    /// The loopback address the API binds.
    ///
    /// Composed here so that no caller has the opportunity to compose a
    /// different one.
    #[must_use]
    pub fn bind(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problems(home: &Home) -> Vec<String> {
        let mut problems = Vec::new();
        home.check("home", &mut problems);
        problems.into_iter().map(|p| p.to_string()).collect()
    }

    /// The default is off, and that is the property that matters most: a
    /// deployment that has never heard of this subsystem must not sweep its
    /// network because the struct gained a field.
    #[test]
    fn the_default_is_switched_off() {
        assert!(!Home::default().enabled);
    }

    #[test]
    fn a_default_block_has_nothing_wrong_with_it() {
        assert!(problems(&Home::default()).is_empty());
    }

    #[test]
    fn the_bind_is_always_loopback() {
        let home = Home { port: 9210, ..Home::default() };
        assert_eq!(home.bind(), "127.0.0.1:9210");
    }

    #[test]
    fn a_floating_port_is_refused() {
        let home = Home { port: 0, ..Home::default() };
        assert!(problems(&home).iter().any(|p| p.contains("home.port")));
    }

    /// Zero would poll somebody's speakers continuously, which is the one
    /// value here that does harm rather than being merely useless.
    #[test]
    fn a_refresh_of_zero_is_refused() {
        let home = Home { refresh_secs: 0, ..Home::default() };
        assert!(problems(&home).iter().any(|p| p.contains("refresh_secs")));
    }

    #[test]
    fn a_sweep_of_zero_is_refused() {
        let home = Home { discover_secs: 0, ..Home::default() };
        assert!(problems(&home).iter().any(|p| p.contains("discover_secs")));
    }

    /// A transposition, caught because it reads to the next editor as though
    /// discovery were the cheap question.
    #[test]
    fn sweeping_more_often_than_refreshing_is_refused_as_backwards() {
        let home = Home { refresh_secs: 60, discover_secs: 2, ..Home::default() };
        let problems = problems(&home);
        assert!(problems.iter().any(|p| p.contains("backwards")), "{problems:?}");
    }

    #[test]
    fn every_problem_is_collected_rather_than_the_first() {
        let home = Home { port: 0, refresh_secs: 0, discover_secs: 0, enabled: true };
        assert!(problems(&home).len() >= 3);
    }

    #[test]
    fn the_durations_are_the_seconds_they_say() {
        let home = Home { refresh_secs: 2, discover_secs: 60, ..Home::default() };
        assert_eq!(home.refresh(), std::time::Duration::from_secs(2));
        assert_eq!(home.discover(), std::time::Duration::from_secs(60));
    }
}
