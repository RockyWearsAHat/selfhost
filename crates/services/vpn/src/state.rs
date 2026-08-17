//! Where a relay is, in words an operator can act on.
//!
//! A thin, total translation of [`ServiceState`] into the vocabulary this
//! subsystem actually has, and the reason it is not simply re-exported is the same
//! reason `selfhost_supervisor::state` is more detailed than running/stopped:
//! two positions that both mean "no process" can want completely different
//! reactions. Here there are two of them. **Declared** is a relay written down
//! and deliberately not armed — the config's `enabled = false`, which is the
//! posture every shipped example takes. **Down** is an armed relay that is not
//! running, which on the console's relay means an operator is locked out. A
//! console that rendered the two the same way would hide the one that is urgent.
//!
//! There used to be a third, `Unrunnable`, for a relay whose backend this build
//! had no runner for. It went with `Backend::Wireguard` on 2026-08-17: with one
//! transport left, every declared relay is one this build can start, and a state
//! that can never occur is a branch a console renders and nobody ever sees.
//!
//! Pure, and tested exhaustively over every supervisor state, so the mapping is a
//! table rather than a judgement made inside a `select!`.

use selfhost_config::vpn::Relay;
use selfhost_json::Json;
use selfhost_supervisor::state::ServiceState;

/// The lifecycle position of one relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayState {
    /// Written down and not armed: `enabled = false`.
    ///
    /// Not a fault. A relay has to exist in the file before a peer can be
    /// enrolled into it, and on a box with a real public IP arming one is a
    /// second decision.
    Declared,
    /// Armed, and no process. On the relay in front of the console, this is an
    /// operator with no way in.
    Down,
    /// Spawning.
    Starting,
    /// Up: the vetted implementation holds the socket.
    Up {
        /// Operating-system process id of the tunnel server.
        pid: u32,
        /// Seconds it has been up.
        uptime_secs: u64,
    },
    /// Asked to stop, waiting for it to comply.
    Stopping,
    /// Down, and the supervisor will try again shortly.
    Backoff {
        /// Seconds until the next attempt.
        retry_in_secs: u64,
        /// How many attempts have already been made.
        attempt: u32,
    },
    /// Down, and it will not come back without somebody.
    Failed {
        /// What went wrong, in the supervisor's or the platform's own words.
        reason: String,
    },
}

impl RelayState {
    /// Reads a relay's position from its supervised service's, or from its
    /// absence.
    ///
    /// `service` is `None` when the relay has never been installed into the
    /// supervisor this run, which is the normal state of a declared relay and of
    /// an armed one before the first `up`.
    pub fn of(relay: &Relay, service: Option<&ServiceState>) -> Self {
        match service {
            None | Some(ServiceState::Stopped) => {
                if relay.enabled {
                    Self::Down
                } else {
                    Self::Declared
                }
            }
            Some(ServiceState::Disabled) => Self::Declared,
            Some(ServiceState::Starting) => Self::Starting,
            Some(ServiceState::Running { pid, uptime_secs }) => {
                Self::Up { pid: *pid, uptime_secs: *uptime_secs }
            }
            Some(ServiceState::Stopping) => Self::Stopping,
            Some(ServiceState::Backoff { retry_in_secs, attempt }) => {
                Self::Backoff { retry_in_secs: *retry_in_secs, attempt: *attempt }
            }
            // A tunnel that exited on its own is a door that closed. The exit
            // code is carried rather than summarised, because "exited with code
            // 0" and "was killed" send an operator to different places.
            Some(ServiceState::Exited { code }) => Self::Failed {
                reason: match code {
                    Some(code) => format!("the tunnel exited with code {code}"),
                    None => "the tunnel was killed".to_owned(),
                },
            },
            Some(ServiceState::GaveUp { attempts, reason }) => Self::Failed {
                reason: format!(
                    "gave up after {attempts} consecutive restarts: {reason}. Fix the cause and \
                     bring the relay up again — the counter clears on an explicit start"
                ),
            },
            Some(ServiceState::Unstartable { reason }) => Self::Failed { reason: reason.clone() },
        }
    }

    /// Whether the tunnel is currently holding its socket.
    pub fn is_up(&self) -> bool {
        matches!(self, Self::Up { .. })
    }

    /// Whether a person needs to look at this.
    ///
    /// [`Self::Down`] counts and [`Self::Declared`] does not, even though neither
    /// has a process: an armed relay that is not running is the one that has
    /// stopped letting people in.
    pub fn needs_attention(&self) -> bool {
        matches!(self, Self::Down | Self::Failed { .. })
    }

    /// The wire discriminant.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Down => "down",
            Self::Starting => "starting",
            Self::Up { .. } => "up",
            Self::Stopping => "stopping",
            Self::Backoff { .. } => "backoff",
            Self::Failed { .. } => "failed",
        }
    }

    /// A short label for a table cell.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Declared => "Declared",
            Self::Down => "Down",
            Self::Starting => "Starting",
            Self::Up { .. } => "Up",
            Self::Stopping => "Stopping",
            Self::Backoff { .. } => "Restarting",
            Self::Failed { .. } => "Failed",
        }
    }

    /// The state as it goes over the wire.
    pub fn to_json(&self) -> Json {
        let mut fields: Vec<(&str, Json)> = vec![
            ("state", Json::string(self.tag())),
            ("needsAttention", Json::Bool(self.needs_attention())),
        ];
        match self {
            Self::Up { pid, uptime_secs } => {
                fields.push(("pid", Json::Number(*pid as f64)));
                fields.push(("uptimeSecs", Json::Number(*uptime_secs as f64)));
            }
            Self::Backoff { retry_in_secs, attempt } => {
                fields.push(("retryInSecs", Json::Number(*retry_in_secs as f64)));
                fields.push(("attempt", Json::Number(*attempt as f64)));
            }
            Self::Failed { reason } => fields.push(("reason", Json::string(reason))),
            Self::Declared | Self::Down | Self::Starting | Self::Stopping => {}
        }
        Json::object(fields)
    }
}

/// One relay as a console row: what it is, and where it is.
///
/// `attributable` is here rather than left to be inferred from the roster,
/// because it is the single fact everything above the tunnel has to reason about
/// — whether a session on this relay can be traced to a person — and a front-end
/// that re-derives it will one day derive it wrongly. It is true when at least
/// one peer holds a `forward_port` of its own; a relay where everybody shares
/// `forward` answers "nobody" for every session, which is the state the audit
/// found and which must be visible in the listing rather than inferred from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySummary {
    /// The relay's name.
    pub name: String,
    /// Which implementation carries it.
    pub backend: &'static str,
    /// Whether the daemon is meant to run it.
    pub enabled: bool,
    /// Whether its socket is reachable from off this machine.
    pub public: bool,
    /// The socket it accepts sessions on.
    pub listen: String,
    /// Where an admitted session lands.
    pub forward: String,
    /// How many roster entries will be admitted.
    pub peers: usize,
    /// How many roster entries were dropped because nobody could be named.
    pub rejected: usize,
    /// Whether a session on this relay can be traced to a person at all.
    pub attributable: bool,
    /// Where it is.
    pub state: RelayState,
}

impl RelaySummary {
    /// The row as it goes over the wire.
    pub fn to_json(&self) -> Json {
        let mut object = match self.state.to_json() {
            Json::Object(map) => map,
            _ => unreachable!("RelayState::to_json always produces an object"),
        };
        object.insert("name".into(), Json::string(&self.name));
        object.insert("backend".into(), Json::string(self.backend));
        object.insert("enabled".into(), Json::Bool(self.enabled));
        object.insert("public".into(), Json::Bool(self.public));
        object.insert("listen".into(), Json::string(&self.listen));
        object.insert("forward".into(), Json::string(&self.forward));
        object.insert("peers".into(), Json::Number(self.peers as f64));
        object.insert("rejected".into(), Json::Number(self.rejected as f64));
        object.insert("attributable".into(), Json::Bool(self.attributable));
        Json::Object(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::forwarding_relay;

    #[test]
    fn a_relay_nobody_armed_is_declared_and_a_relay_that_stopped_is_down() {
        // Both have no process, and only one of them means somebody is locked
        // out of the console.
        let mut relay = forwarding_relay();
        assert_eq!(RelayState::of(&relay, None), RelayState::Declared);
        assert!(!RelayState::of(&relay, None).needs_attention());

        relay.enabled = true;
        assert_eq!(RelayState::of(&relay, None), RelayState::Down);
        assert!(RelayState::of(&relay, None).needs_attention());
    }

    #[test]
    fn an_explicit_stop_reads_the_same_as_never_having_started() {
        let mut relay = forwarding_relay();
        relay.enabled = true;
        assert_eq!(RelayState::of(&relay, Some(&ServiceState::Stopped)), RelayState::Down);
    }

    #[test]
    fn every_supervisor_state_maps_to_exactly_one_relay_state() {
        let mut relay = forwarding_relay();
        relay.enabled = true;
        let cases = [
            (ServiceState::Disabled, "declared"),
            (ServiceState::Stopped, "down"),
            (ServiceState::Starting, "starting"),
            (ServiceState::Running { pid: 42, uptime_secs: 7 }, "up"),
            (ServiceState::Stopping, "stopping"),
            (ServiceState::Backoff { retry_in_secs: 5, attempt: 2 }, "backoff"),
            (ServiceState::Exited { code: Some(1) }, "failed"),
            (ServiceState::Exited { code: None }, "failed"),
            (ServiceState::GaveUp { attempts: 5, reason: "exit 1".into() }, "failed"),
            (ServiceState::Unstartable { reason: "not found".into() }, "failed"),
        ];
        for (service, expected) in cases {
            assert_eq!(RelayState::of(&relay, Some(&service)).tag(), expected, "{service:?}");
        }
    }

    #[test]
    fn a_tunnel_that_exited_cleanly_is_still_a_failure_here() {
        // A door that closes on its own is not "fine"; the supervisor's own
        // `Exited` is neutral because most services are not the only way in.
        let mut relay = forwarding_relay();
        relay.enabled = true;
        let state = RelayState::of(&relay, Some(&ServiceState::Exited { code: Some(0) }));
        assert!(state.needs_attention(), "{state:?}");
        assert!(state.to_json().to_text().contains("code 0"));
    }

    #[test]
    fn a_killed_tunnel_is_not_reported_as_exit_code_zero() {
        let relay = forwarding_relay();
        let state = RelayState::of(&relay, Some(&ServiceState::Exited { code: None }));
        let text = state.to_json().to_text();
        assert!(text.contains("was killed"), "{text}");
        assert!(!text.contains("code 0"), "{text}");
    }

    #[test]
    fn a_giving_up_relay_says_what_clears_the_counter() {
        let relay = forwarding_relay();
        let state = RelayState::of(
            &relay,
            Some(&ServiceState::GaveUp { attempts: 5, reason: "port in use".into() }),
        );
        match &state {
            RelayState::Failed { reason } => {
                assert!(reason.contains("port in use"), "{reason}");
                assert!(reason.contains("explicit start"), "{reason}");
            }
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[test]
    fn a_summary_carries_whether_this_relay_can_name_anybody() {
        let relay = forwarding_relay();
        let summary = RelaySummary {
            name: relay.name.clone(),
            backend: relay.backend.tag(),
            enabled: relay.enabled,
            public: relay.public,
            listen: relay.listen.clone(),
            forward: relay.forward.clone(),
            peers: 1,
            rejected: 0,
            attributable: relay.attributes(),
            state: RelayState::of(&relay, None),
        };
        let text = summary.to_json().to_text();
        assert!(text.contains(r#""attributable":false"#), "{text}");
        assert!(text.contains(r#""state":"declared""#), "{text}");
        assert!(text.contains(r#""name":"console""#), "{text}");
    }
}
