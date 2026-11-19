//! Running the relays a deployment has declared, and answering who is on one.
//!
//! A *relay* is one socket in front of one local service. Who may come through
//! it is enrolment state: each signed-in account enrols its own devices. `crates/foundation/config/src/vpn.rs` is its schema
//! and `docs/labs/vpn-lab.dx` is its design; this crate is the half that runs.
//!
//! # It runs the vetted implementation as a supervised child
//!
//! **selfhost binds no VPN socket.** The listener is opened by the tunnel program,
//! supervised by [`selfhost_supervisor`], exactly as `crates/services/storage`'s
//! `smb` module drives the platform's own SMB server rather than implementing SMB.
//! That is a security decision first: the daemon builds with `panic = "abort"` and
//! is the same process that serves 80 and 443, mail, and the certificate store, so
//! a handshake parser fed unauthenticated bytes by strangers *inside* it is a way
//! to take all of that down. It stays in its own process with its own crash
//! domain. No protocol is invented here and no cryptography is written here; that
//! decision is recorded in `docs/VPN.md` and in the workspace dependency policy,
//! and it is final.
//!
//! The bind ledger for this subsystem therefore reads: **nothing new.**
//! `server.admin_bind` stays `127.0.0.1:9191`, and the one inbound socket is the
//! relay's own — TCP 8443, already enumerated in `docs/SECURITY.md` §1 and
//! justified there as VPN-01. The loader refuses a non-loopback `listen` that has
//! not been acknowledged with `public = true`, refuses a `forward` that is not
//! loopback, and refuses a `forward` that is `server.admin_bind`. None of those
//! rules is re-decided here.
//!
//! # Who is on it
//!
//! The tunnel proves which Peer completed the handshake and asks the admin API
//! (`POST /api/vpn/check-access`) whether that Peer's Person holds
//! `vpn.access:<relay>`. [`peer_binding`] is the record of which Person that is.
//!
//! # The shape of the crate
//!
//! | Module | Pure? | What it holds |
//! |---|---|---|
//! | [`roster`] | impure | reads the peer set that will be admitted, and the entries that will not |
//! | [`peer_binding`] | impure | which Person each Peer belongs to |
//! | [`runner`] | **pure** | the argument vector, and the refusal for a backend with no runner |
//! | [`state`] | **pure** | declared, down, up, failed — named states rather than errors |
//! | [`probe`] | impure | whether a relay answers the first step of its handshake |
//! | [`heal`] | **pure** | what to do about a relay that is dead or not answering |
//! | [`keys`] | impure | reads the key directory; never writes it, never generates a key |
//! | [`enrol`] | impure | writes a peer's `.pub` file and the roster file; never generates a key |
//! | this module | impure | the supervisor, and the four verbs a caller drives |
//!
//! The split is `desk`'s: one impure edge, everything that decides anything on the
//! other side of it, so the whole subsystem is exercised without a tunnel, a
//! config file, or a socket.
//!
//! # What is not proven by any test here
//!
//! Said plainly, because a green suite is easy to read for more than it is worth.
//! The tests drive stand-in programs, never the real tunnel: that an enrolled
//! device completes a handshake and is admitted is proven only on the box,
//! where the daemon has run `vpn-console` and `vpn-ssh` since the 2026-09-09
//! cutover. [`heal`] restarting a killed or wedged relay was proven there on
//! 2026-11-18 (`index.dx`, journal).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod enrol;
pub mod heal;
pub mod image_auth;
pub mod keys;
pub mod peer_binding;
pub mod probe;
pub mod roster;
pub mod runner;
pub mod state;
pub mod updater;

pub use enrol::{EnrolError, enrol, revoke};
pub use image_auth::{ImageAuthConfig, validate_image_auth_key};
pub use keys::KeyReport;
pub use roster::{Enrolled, Rejected, Roster};
pub use runner::{Install, Launch, service_name};
pub use updater::Updater;
pub use state::{RelayState, RelaySummary};

use heal::{Memory, Remedy, STARTUP_GRACE, Seen};
use selfhost_config::vpn::Relay;
use selfhost_supervisor::Supervisor;
use selfhost_supervisor::state::ServiceState;
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Why a relay could not be run, or could not be found.
///
/// Every variant's `Display` says what to do rather than only what broke, in the
/// idiom `selfhost_storage`'s `SmbError` and `selfhost_firewall`'s
/// `FirewallError` established. None of them is a rule this crate invented: each
/// one is a condition the loader cannot see, because it depends on the disk, on
/// the platform, or on the people registry.
#[derive(Debug)]
pub enum VpnError {
    /// No relay of that name is declared.
    UnknownRelay {
        /// The name that was asked for.
        name: String,
    },
    /// The relay is declared but not armed.
    NotEnabled {
        /// The relay.
        relay: String,
    },
    /// A socket in the block is not an address. Validation has already said so;
    /// this is the runner refusing to hand the text to a child.
    Unaddressable {
        /// The relay.
        relay: String,
        /// Which field: `listen` or `forward`.
        field: &'static str,
        /// What was written there.
        value: String,
    },
    /// Nobody usable is enrolled, so the relay would bind a port and admit
    /// nobody.
    NoUsablePeers {
        /// The relay.
        relay: String,
        /// The entries that were dropped, with the reason for each.
        rejected: Vec<Rejected>,
    },
    /// The tunnel implementation is not on this machine.
    ImplementationMissing {
        /// The relay.
        relay: String,
        /// Where it was expected.
        server: PathBuf,
    },
    /// Key material the relay needs is not in its key directory.
    KeysMissing {
        /// The relay.
        relay: String,
        /// What was and was not found. Boxed to keep the error small — this is
        /// the one variant carrying a whole report.
        report: Box<KeyReport>,
    },
}

impl fmt::Display for VpnError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRelay { name } => write!(
                formatter,
                "no relay named \"{name}\" is declared; add a [[vpn]] block for it, or check the \
                 spelling against `selfhost vpn status`"
            ),
            Self::NotEnabled { relay } => write!(
                formatter,
                "relay \"{relay}\" is declared but not enabled, and starting it is a second \
                 decision on a box with a real public IP. Write enabled = true in its [[vpn]] \
                 block once the roster is right"
            ),
            Self::Unaddressable { relay, field, value } => write!(
                formatter,
                "relay \"{relay}\" has {field} = \"{value}\", which is not a socket address. \
                 Validation reports this at load; nothing is spawned with it, because a child \
                 given that text would fail to bind and then be restarted for ever"
            ),
            Self::NoUsablePeers { relay, rejected } => {
                write!(
                    formatter,
                    "relay \"{relay}\" has no device enrolled, so it would bind a socket that \
                     admits nobody. Sign in on a device to enrol it"
                )?;
                for entry in rejected {
                    write!(formatter, "; \"{}\": {}", entry.peer, entry.reason)?;
                }
                Ok(())
            }
            Self::ImplementationMissing { relay, server } => write!(
                formatter,
                "relay \"{relay}\" cannot start: the tunnel server is not at {}. server.py \
                 comes from the Secure-VPN repository, \
                 https://github.com/RockyWearsAHat/Secure-VPN.git, and is put on a box by \
                 scripts/securevpn/install-vpn-service.ps1 or scripts/securevpn/join-mac.sh \
                 — so it has to be installed on this machine, and this crate will not guess \
                 where else it might be",
                server.display()
            ),
            Self::KeysMissing { relay, report } => {
                write!(formatter, "relay \"{relay}\" is missing key material in {}", report.dir.display())?;
                if !report.dir_present {
                    write!(formatter, "; the directory does not exist")?;
                }
                if !report.server_key {
                    write!(formatter, "; there is no {}", keys::SERVER_KEY_FILE)?;
                }
                write!(
                    formatter,
                    ". Starting anyway would bind a port nobody can complete a handshake on"
                )
            }
        }
    }
}

impl std::error::Error for VpnError {}

/// Everything a relay would do, decided and reported before anything is spawned.
///
/// The shape `crates/net/firewall` established and `smb` copied: report a plan,
/// then act on it, so an operator or an agent can see the exact command line and
/// the exact roster before a socket exists. Obtaining one is proof the relay is
/// startable — every fatal condition is a [`VpnError`] instead.
#[derive(Debug, Clone)]
pub struct Preflight {
    /// The relay this is for.
    pub relay: String,
    /// The invocation, exactly as it will be spawned.
    pub launch: Launch,
    /// The peers that will be admitted, and the ones that will not.
    pub roster: Roster,
    /// What is on disk for it.
    pub keys: KeyReport,
    /// Everything worth saying that is not fatal, ready for the service log.
    pub notes: Vec<String>,
}

/// The relays a deployment has declared, and the supervisor that runs them.
///
/// The one impure object in this crate. Cheap to clone: the supervisor is shared,
/// so the admin API and the CLI hold the same relays rather than two sets that
/// disagree about which are up.
#[derive(Debug, Clone)]
pub struct Relays {
    supervisor: Supervisor,
    data_dir: PathBuf,
    admin_bind: String,
    install: Install,
    relays: Vec<Relay>,
}

impl Relays {
    /// Reads a deployment's `[[vpn]]` blocks into a drivable set.
    ///
    /// `admin_bind` is `server.admin_bind` (`127.0.0.1:9191`) — where a started
    /// relay points its `--account-manager` so a completed handshake still has
    /// to clear `vpn.access:<relay>` before the tunnel opens. Not read from the
    /// disk here: it is config the caller already has, the same as `data_dir`.
    pub fn new(
        supervisor: Supervisor,
        data_dir: impl Into<PathBuf>,
        admin_bind: impl Into<String>,
        install: Install,
        relays: Vec<Relay>,
    ) -> Self {
        Self {
            supervisor,
            data_dir: data_dir.into(),
            admin_bind: admin_bind.into(),
            install,
            relays,
        }
    }

    /// Every declared relay, in config order.
    pub fn relays(&self) -> &[Relay] {
        &self.relays
    }

    /// One relay's block, by name.
    pub fn relay(&self, name: &str) -> Option<&Relay> {
        self.relays.iter().find(|relay| relay.name == name)
    }

    /// One relay's usable peer set, by name, as enrolment has it now.
    ///
    /// Read on every call rather than kept: a device signed in a minute ago is
    /// a Peer now, and the tunnel re-reads the same files per handshake.
    pub fn roster(&self, name: &str) -> Option<Roster> {
        let relay = self.relay(name)?;
        Some(Roster::read(relay, &self.key_dir(relay), &self.data_dir))
    }

    /// Where this relay's key material is expected.
    pub fn key_dir(&self, relay: &Relay) -> PathBuf {
        keys::key_dir(relay, &self.data_dir)
    }

    /// Every relay as a console row, with its live state.
    pub async fn list(&self) -> Vec<RelaySummary> {
        let mut rows = Vec::with_capacity(self.relays.len());
        for relay in &self.relays {
            let roster = Roster::read(relay, &self.key_dir(relay), &self.data_dir);
            rows.push(RelaySummary {
                name: relay.name.clone(),
                backend: relay.backend.tag(),
                enabled: relay.enabled,
                public: relay.public,
                listen: relay.listen.clone(),
                forward: relay.forward.clone(),
                peers: roster.enrolled().len(),
                rejected: roster.rejected().len(),
                state: self.state_of(relay).await,
            });
        }
        rows
    }

    /// Where one relay is.
    pub async fn state(&self, name: &str) -> Result<RelayState, VpnError> {
        let relay = self.find(name)?;
        Ok(self.state_of(relay).await)
    }

    /// Everything that would happen, without doing any of it.
    ///
    /// Answers `Ok` only for a relay that would actually start, so a caller that
    /// holds a [`Preflight`] can print the command line knowing it is the one
    /// that runs. The order of the checks is the order in which their failures
    /// are cheapest to fix: the config first, then the implementation, then the
    /// disk.
    pub async fn preflight(&self, name: &str) -> Result<Preflight, VpnError> {
        let relay = self.find(name)?;

        if !relay.enabled {
            return Err(VpnError::NotEnabled { relay: relay.name.clone() });
        }
        let key_dir = self.key_dir(relay);
        let roster = Roster::read(relay, &key_dir, &self.data_dir);
        // `server.py` exits when its roster names nobody; say so here instead.
        if roster.enrolled().is_empty() {
            return Err(VpnError::NoUsablePeers {
                relay: relay.name.clone(),
                rejected: roster.rejected().to_vec(),
            });
        }

        let admin_token_path = self.data_dir.join("admin.token");
        let launch =
            runner::plan(relay, &self.install, &key_dir, &self.admin_bind, &admin_token_path)?;

        if !self.install.present().await {
            return Err(VpnError::ImplementationMissing {
                relay: relay.name.clone(),
                server: self.install.server.clone(),
            });
        }

        let report = keys::inspect(&key_dir).await;
        if !report.is_startable() {
            return Err(VpnError::KeysMissing {
                relay: relay.name.clone(),
                report: Box::new(report),
            });
        }

        // A dropped peer is a person who has lost access. It is not fatal while
        // somebody is still admitted, and it must not be silent either.
        let mut notes = report.notes();
        for entry in roster.rejected() {
            notes.push(format!(
                "[vpn] peer \"{}\" is NOT admitted: {}",
                entry.peer, entry.reason
            ));
        }

        Ok(Preflight {
            relay: relay.name.clone(),
            launch,
            roster,
            keys: report,
            notes,
        })
    }

    /// Brings a relay up, and reports where it got to.
    ///
    /// Installing and starting are two supervisor calls rather than one because
    /// the spec must land before the notes do — a note written to a service that
    /// does not exist yet is a note nobody ever reads. The state comes back read
    /// from the supervisor rather than predicted: the one moment a prediction and
    /// the machine disagree is the moment the operator most needs the truth,
    /// which is the same reason `smb::sync` re-reads the host after applying.
    pub async fn up(&self, name: &str) -> Result<RelayState, VpnError> {
        let plan = self.preflight(name).await?;
        let relay = self.find(name)?;
        let service = service_name(&relay.name);

        self.supervisor.install(runner::service(relay, &plan.launch)).await;
        self.supervisor
            .note(&service, format!("[vpn] {}", plan.launch.command_line()))
            .await;
        for note in &plan.notes {
            self.supervisor.note(&service, note.clone()).await;
        }
        self.supervisor.start(&service).await;

        Ok(self.state_of(relay).await)
    }

    /// Brings up every relay declared `enabled = true`, into *this* `Relays`'
    /// own supervisor.
    ///
    /// This is the daemon-boot half of the fix for the bug `docs/VPN.md`
    /// records: `selfhost vpn up <name>` used to be the only way to start a
    /// relay, and it installed the relay into a `Supervisor` owned by the
    /// one-shot CLI process — so the relay's Job Object (on Windows) died the
    /// instant that process exited, seconds later. Calling this once, from
    /// `serve_everything`'s own long-lived `Supervisor`, gives every enabled
    /// relay the same lifetime as every other supervised service (mail, the
    /// git-watched apps, `vpn-updater`): as long as the daemon itself runs.
    ///
    /// One relay's failure does not stop the rest: a bad roster on `console`
    /// must not also keep `ssh` down. Every outcome is returned, in relay
    /// order, so the caller can log or print each one; a relay that is not
    /// `enabled` is skipped entirely rather than reported as an error, since
    /// leaving it off is the deployment's own choice (`VpnError::NotEnabled`
    /// is for an operator typing `up` by hand, not for this sweep).
    pub async fn start_enabled(&self) -> Vec<(String, Result<RelayState, VpnError>)> {
        let mut outcomes = Vec::new();
        for relay in &self.relays {
            if !relay.enabled {
                continue;
            }
            outcomes.push((relay.name.clone(), self.up(&relay.name).await));
        }
        outcomes
    }

    /// Takes a relay down.
    ///
    /// A relay that was never installed is already down, and that is not an
    /// error: `down` is what an operator reaches for when they want the port
    /// closed, and reporting a failure because it was closed already would be a
    /// refusal that means "you got what you asked for".
    pub async fn down(&self, name: &str) -> Result<RelayState, VpnError> {
        let relay = self.find(name)?;
        self.supervisor.stop(&service_name(&relay.name)).await;
        Ok(self.state_of(relay).await)
    }

    /// Looks at every armed relay once: reports the restarts the supervisor
    /// made on its own since the last look, and applies what [`Memory::judge`]
    /// decides — a dead relay is brought up again, a running one that stopped
    /// answering its handshake is restarted. Every remedy is also noted in the
    /// relay's own service log, with its reason.
    ///
    /// `memory` is the caller's, kept between calls; the daemon calls this every
    /// [`heal::HEAL_INTERVAL`] for as long as it runs and writes each report to
    /// its log.
    pub async fn heal(&self, memory: &mut HashMap<String, Memory>) -> Vec<Report> {
        let mut reports = Vec::new();
        for relay in self.relays.iter().filter(|relay| relay.enabled) {
            let service = service_name(&relay.name);
            let status = self.supervisor.status(&service).await;
            let memory = memory.entry(relay.name.clone()).or_default();

            let total = status.as_ref().map_or(0, |status| status.total_restarts);
            let times = memory.restarts_since_last_look(total);
            if times > 0 {
                let last_exit = self.last_exit(&service).await;
                reports.push(Report::Restarted { relay: relay.name.clone(), times, last_exit });
            }

            let state = status.map(|status| status.state);
            let probed = match &state {
                Some(ServiceState::Running { pid, .. }) => Some(*pid),
                _ => None,
            };
            let seen = match (self.look(relay, state).await, probed) {
                (unanswered @ Seen::Unanswered(_), Some(pid)) => {
                    let now = self.supervisor.status(&service).await.map(|status| status.state);
                    heal::after_probe(unanswered, pid, now.as_ref())
                }
                (seen, _) => seen,
            };
            if let Some(remedy) = memory.judge(seen, Instant::now()) {
                let outcome = self.apply(relay, &remedy).await;
                reports.push(Report::Healed(Healing { relay: relay.name.clone(), remedy, outcome }));
            }
        }
        reports
    }

    /// Carries out one remedy and reports where the relay got to.
    async fn apply(&self, relay: &Relay, remedy: &Remedy) -> Result<RelayState, VpnError> {
        let service = service_name(&relay.name);
        match remedy {
            Remedy::Restart(reason) => {
                self.supervisor.note(&service, format!("[heal] restarting: {reason}")).await;
                self.supervisor.restart(&service).await;
                Ok(self.state_of(relay).await)
            }
            Remedy::Start(reason) => {
                // After `up`, which installs the service the note lands in.
                let outcome = self.up(&relay.name).await;
                self.supervisor.note(&service, format!("[heal] started: {reason}")).await;
                outcome
            }
            Remedy::Retry(reason) => {
                // A start during the supervisor's backoff spawns at once and
                // clears its failure count, so its next waits are short again.
                self.supervisor.note(&service, format!("[heal] retrying now: {reason}")).await;
                self.supervisor.start(&service).await;
                Ok(self.state_of(relay).await)
            }
        }
    }

    /// The supervisor's last word on why the relay's process ended, read back
    /// from the relay's own service log.
    async fn last_exit(&self, service: &str) -> Option<String> {
        let status = self.supervisor.status(service).await?;
        let from = status.log_seq.saturating_sub(EXIT_LOOKBACK as u64);
        let slice = self.supervisor.logs(service, from, EXIT_LOOKBACK).await?;
        slice.lines.iter().rev().find_map(|line| {
            let said = line.text.strip_prefix("[supervisor] ")?;
            (said.starts_with("exited") || said.starts_with("was killed")).then(|| said.to_owned())
        })
    }

    /// What one relay is doing, given its supervised state, probing it when
    /// it claims to run.
    async fn look(&self, relay: &Relay, state: Option<ServiceState>) -> Seen {
        match state {
            None => Seen::Dead("it is not running in this daemon: it never started".to_owned()),
            Some(ServiceState::Stopped | ServiceState::Disabled) => Seen::Stopped,
            Some(ServiceState::Backoff { retry_in_secs, .. }) => {
                Seen::Waiting(Duration::from_secs(retry_in_secs))
            }
            Some(ServiceState::Starting | ServiceState::Stopping) => Seen::Settling,
            Some(ServiceState::Running { uptime_secs, .. })
                if Duration::from_secs(uptime_secs) < STARTUP_GRACE =>
            {
                Seen::Settling
            }
            Some(ServiceState::Running { .. }) => match relay.listen_addr() {
                Some(listen) => match probe::hello(listen, probe::PROBE_TIMEOUT).await {
                    Ok(()) => Seen::Answering,
                    Err(failure) => Seen::Unanswered(failure),
                },
                None => Seen::Settling,
            },
            Some(stopped) => match RelayState::of(relay, Some(&stopped)) {
                RelayState::Failed { reason } => Seen::Dead(reason),
                _ => Seen::Settling,
            },
        }
    }

    /// The block for a name, or the refusal that names it.
    fn find(&self, name: &str) -> Result<&Relay, VpnError> {
        self.relay(name).ok_or_else(|| VpnError::UnknownRelay { name: name.to_owned() })
    }

    /// One relay's lifecycle position, read from the supervisor.
    ///
    /// It asks the supervisor and nothing else. It used to run [`runner::plan`]
    /// first, to report a backend with no runner as its own state; with one
    /// transport left there is no such backend, and a listing that re-derived a
    /// plan on every row would be answering "can this start" in a function whose
    /// question is "is it running". Whether a relay *would* start is
    /// [`Relays::preflight`]'s to say, in one place, with the reason.
    async fn state_of(&self, relay: &Relay) -> RelayState {
        let service = self.supervisor.status(&service_name(&relay.name)).await.map(|s| s.state);
        RelayState::of(relay, service.as_ref())
    }
}

/// How many of a relay's newest log lines are searched for its last exit.
const EXIT_LOOKBACK: usize = 500;

/// One thing [`Relays::heal`] saw or did, for the daemon's log.
#[derive(Debug)]
pub enum Report {
    /// The relay's process ended and the supervisor restarted it on its own.
    Restarted {
        /// The relay.
        relay: String,
        /// How many restarts since the last look.
        times: u64,
        /// The supervisor's note on the last exit, while its log still has it.
        last_exit: Option<String>,
    },
    /// A remedy was applied.
    Healed(Healing),
}

impl fmt::Display for Report {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Restarted { relay, times, last_exit } => {
                write!(formatter, "vpn relay \"{relay}\" died and was restarted {times} time(s)")?;
                match last_exit {
                    Some(exit) => write!(formatter, "; last it {exit}"),
                    None => Ok(()),
                }
            }
            Self::Healed(healing) => healing.fmt(formatter),
        }
    }
}

/// One remedy [`Relays::heal`] applied, and where the relay got to.
#[derive(Debug)]
pub struct Healing {
    /// The relay.
    pub relay: String,
    /// What was done, and why.
    pub remedy: Remedy,
    /// The relay's state afterwards, or why it could not be brought up.
    pub outcome: Result<RelayState, VpnError>,
}

impl fmt::Display for Healing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let verb = match self.remedy {
            Remedy::Restart(_) => "restarted",
            Remedy::Start(_) => "started",
            Remedy::Retry(_) => "started early",
        };
        write!(formatter, "vpn relay \"{}\" {verb} because {}: ", self.relay, self.remedy.reason())?;
        match &self.outcome {
            Ok(state) => write!(formatter, "now {}", state.label()),
            Err(error) => write!(formatter, "still down: {error}"),
        }
    }
}

/// The service state of a relay, for a caller that already holds a supervisor.
///
/// Exposed so `selfhost doctor` and the admin API can ask the supervisor the same
/// question this crate asks, under the same service name, rather than
/// reconstructing the name themselves and getting it subtly wrong.
pub async fn service_state(supervisor: &Supervisor, relay: &str) -> Option<ServiceState> {
    supervisor.status(&service_name(relay)).await.map(|status| status.state)
}

/// Where a relay's keys live, for a caller that has a relay and a data directory.
pub fn relay_key_dir(relay: &Relay, data_dir: &Path) -> PathBuf {
    keys::key_dir(relay, data_dir)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use selfhost_config::vpn::Relay;
    use selfhost_supervisor::await_state;
    use std::time::Duration;

    /// A well-formed public key, as a device sends one at enrolment.
    pub(crate) const A_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    /// The deployed shape: a Secure-VPN relay in front of the proxy.
    ///
    /// Loopback rather than `0.0.0.0` so the fixture is a relay validation
    /// accepts without `public = true`.
    pub(crate) fn forwarding_relay() -> Relay {
        Relay::new("console", "127.0.0.1:8443", "127.0.0.1:443")
    }

    /// A data directory holding [`forwarding_relay`]'s enrolment state.
    pub(crate) struct Scratch(PathBuf);

    impl Scratch {
        pub(crate) fn new(tag: &str) -> Self {
            Self(scratch(tag))
        }

        pub(crate) fn data_dir(&self) -> &Path {
            &self.0
        }

        pub(crate) fn key_dir(&self) -> PathBuf {
            keys::key_dir(&forwarding_relay(), &self.0)
        }

        /// What signing in on a device does: key file, roster line, binding.
        pub(crate) fn enrol(&self, peer: &str, person: &str) {
            enrol::enrol(&self.key_dir(), peer, A_KEY).expect("enrol");
            peer_binding::bind(&self.0, peer, person).expect("bind");
        }

        pub(crate) fn roster(&self) -> Roster {
            Roster::read(&forwarding_relay(), &self.key_dir(), &self.0)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A scratch directory unique to one test.
    fn scratch(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("selfhost-vpn-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    /// A harmless program standing in for the tunnel: it runs until it is
    /// stopped and ignores every argument, which is all the supervision path
    /// needs of it. The real server lives in the Secure-VPN repository and is not
    /// installed on a machine running these tests, so a stand-in is what makes the
    /// supervision path testable at all.
    fn fake_install(dir: &Path) -> Install {
        stand_in(
            dir,
            ":loop\r\nping -n 2 127.0.0.1 >NUL\r\ngoto loop\r\n",
            "#!/bin/sh\nwhile true; do sleep 0.05; done\n",
        )
    }

    /// A stand-in for the tunnel that exits with code 1 as soon as it starts.
    fn failing_install(dir: &Path) -> Install {
        stand_in(dir, "exit /b 1\r\n", "#!/bin/sh\nexit 1\n")
    }

    /// A stand-in tunnel: a script for the platform's own shell, which
    /// ignores the relay's arguments.
    fn stand_in(dir: &Path, windows: &str, unix: &str) -> Install {
        if cfg!(windows) {
            let server = dir.join("server.cmd");
            std::fs::write(&server, windows).expect("write");
            Install::new("cmd", vec!["/c".to_owned()], server)
        } else {
            let server = dir.join("server.sh");
            std::fs::write(&server, unix).expect("write");
            Install::new("/bin/sh", Vec::new(), server)
        }
    }

    /// A relay whose key directory is complete and has one device enrolled,
    /// under `data_dir`.
    fn armed_relay(data_dir: &Path) -> Relay {
        let mut relay = forwarding_relay();
        relay.enabled = true;
        let key_dir = keys::key_dir(&relay, data_dir);
        enrol::enrol(&key_dir, "alex-mac", A_KEY).expect("enrol");
        peer_binding::bind(data_dir, "alex-mac", "Alex").expect("bind");
        std::fs::write(keys::server_key_file(&key_dir), "private").expect("write");
        relay
    }

    fn relays(dir: &Path, install: Install, blocks: Vec<Relay>) -> Relays {
        Relays::new(Supervisor::new(dir), dir, "127.0.0.1:9191", install, blocks)
    }

    #[test]
    fn the_fixture_is_a_relay_the_loader_would_actually_accept() {
        let mut problems = Vec::new();
        forwarding_relay().check("vpn[0]", &mut problems);
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[tokio::test]
    async fn a_declared_relay_is_listed_and_not_running() {
        let dir = scratch("declared");
        let mut relay = armed_relay(&dir);
        relay.enabled = false;
        let subject = relays(&dir, fake_install(&dir), vec![relay]);

        let rows = subject.list().await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, RelayState::Declared);
        assert_eq!(rows[0].peers, 1);
        assert!(!rows[0].state.needs_attention());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_unenabled_relay_refuses_to_start_and_says_what_to_write() {
        let dir = scratch("not-enabled");
        let subject = relays(&dir, fake_install(&dir), vec![forwarding_relay()]);
        let error = subject.up("console").await.expect_err("a declared relay does not start");
        assert!(matches!(error, VpnError::NotEnabled { .. }), "{error}");
        assert!(error.to_string().contains("enabled = true"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_relay_nobody_declared_is_named_rather_than_ignored() {
        let dir = scratch("unknown");
        let subject = relays(&dir, fake_install(&dir), Vec::new());
        for outcome in [
            subject.state("console").await.err(),
            subject.up("console").await.err(),
            subject.down("console").await.err(),
        ] {
            assert!(matches!(outcome, Some(VpnError::UnknownRelay { .. })), "{outcome:?}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_relay_with_no_private_key_refuses_before_it_binds_anything() {
        let dir = scratch("no-keys");
        let relay = armed_relay(&dir);
        std::fs::remove_file(keys::server_key_file(&keys::key_dir(&relay, &dir))).expect("remove");
        let subject = relays(&dir, fake_install(&dir), vec![relay]);

        let error = subject.up("console").await.expect_err("no keys, no start");
        assert!(matches!(error, VpnError::KeysMissing { .. }), "{error}");
        assert!(error.to_string().contains("server.key"), "{error}");
        assert!(subject.state("console").await.expect("declared").needs_attention());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_relay_whose_implementation_is_absent_says_so_rather_than_crash_looping() {
        let dir = scratch("no-implementation");
        let relay = armed_relay(&dir);
        let missing = Install::new("/bin/sh", Vec::new(), dir.join("not-installed.py"));
        let subject = relays(&dir, missing, vec![relay]);

        let error = subject.up("console").await.expect_err("nothing to run");
        assert!(matches!(error, VpnError::ImplementationMissing { .. }), "{error}");
        // The refusal names the file, and where to get it. It used to say the
        // implementation was missing from the world, which was never true — it is
        // the operator's own repository — and sent a reader looking for a file
        // that was committed the whole time instead of installing it.
        assert!(error.to_string().contains("server.py"), "{error}");
        assert!(error.to_string().contains("Secure-VPN.git"), "{error}");
        assert!(error.to_string().contains("install-vpn-service.ps1"), "{error}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_relay_nobody_has_enrolled_on_binds_nothing() {
        let dir = scratch("no-peers");
        let mut relay = forwarding_relay();
        relay.enabled = true;
        // Listed, but no account enrolled it: the old shared key's shape.
        enrol::enrol(&keys::key_dir(&relay, &dir), "stray", A_KEY).expect("enrol");
        let subject = relays(&dir, fake_install(&dir), vec![relay]);

        let error = subject.up("console").await.expect_err("nobody to admit");
        assert!(matches!(error, VpnError::NoUsablePeers { .. }), "{error}");
        assert!(error.to_string().contains("stray"), "{error}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_device_enrolled_after_the_relays_were_read_is_a_peer_at_once() {
        let dir = scratch("live-roster");
        let subject = relays(&dir, fake_install(&dir), vec![forwarding_relay()]);
        assert!(subject.roster("console").expect("declared").enrolled().is_empty());
        armed_relay(&dir);
        assert!(subject.roster("console").expect("declared").enrolled_peer("alex-mac").is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_relay_comes_up_as_a_supervised_child_and_goes_back_down() {
        let dir = scratch("lifecycle");
        let relay = armed_relay(&dir);
        let subject = relays(&dir, fake_install(&dir), vec![relay]);

        let plan = subject.preflight("console").await.expect("startable");
        assert!(plan.launch.command_line().contains("--roster "), "{}", plan.launch.command_line());
        assert!(!plan.launch.command_line().contains("--peer"), "{}", plan.launch.command_line());

        subject.up("console").await.expect("starts");
        let service = service_name("console");
        let up = await_state(subject.supervisor(), &service, Duration::from_secs(5), |state| {
            state.is_live()
        })
        .await
        .expect("the tunnel process starts");
        assert!(matches!(up, ServiceState::Running { .. }), "{up:?}");
        assert!(subject.state("console").await.expect("known").is_up());

        subject.down("console").await.expect("stops");
        let down = await_state(subject.supervisor(), &service, Duration::from_secs(5), |state| {
            !state.is_live()
        })
        .await
        .expect("the tunnel process stops");
        assert!(!down.is_live(), "{down:?}");
        assert_eq!(subject.state("console").await.expect("known"), RelayState::Down);

        subject.supervisor().shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn start_enabled_installs_and_starts_every_enabled_relay_into_this_supervisor() {
        // The regression this exists for: a relay started only by a one-shot
        // CLI process dies with that process (Windows Job Object kill-on-close).
        // `start_enabled` is what the daemon calls at boot instead, into its own
        // long-lived supervisor — so proving the relay lands there, running, is
        // exactly what closes the gap.
        let dir = scratch("start-enabled");
        // `armed_relay`'s key material is written under a path derived from its
        // (default) name, so it keeps that name here rather than being renamed
        // after its keys are already on disk.
        let enabled = armed_relay(&dir);
        let mut disabled = forwarding_relay();
        disabled.name = "down-one".to_owned();
        // `disabled.enabled` defaults to `false` from `Relay::new`.
        let subject = relays(&dir, fake_install(&dir), vec![enabled, disabled]);

        let outcomes = subject.start_enabled().await;
        assert_eq!(outcomes.len(), 1, "only the enabled relay is attempted: {outcomes:?}");
        let (name, result) = &outcomes[0];
        assert_eq!(name, "console");
        result.as_ref().expect("the enabled, fully-keyed relay starts");

        let service = service_name("console");
        let up = await_state(subject.supervisor(), &service, Duration::from_secs(5), |state| {
            state.is_live()
        })
        .await
        .expect("the tunnel process starts under this Relays' own supervisor");
        assert!(matches!(up, ServiceState::Running { .. }), "{up:?}");

        // The disabled relay was never installed at all — not even as a
        // stopped service — because installing something nobody armed would
        // be a second, silent way to bind a socket.
        assert!(
            subject.supervisor().status(&service_name("down-one")).await.is_none(),
            "a disabled relay must not be installed by the boot-time sweep"
        );

        subject.supervisor().shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A loopback socket nothing listens on, so a probe of it cannot answer.
    fn unused_listen() -> String {
        let socket = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        socket.local_addr().expect("address").to_string()
    }

    #[tokio::test]
    async fn a_relay_that_could_not_start_at_boot_is_started_by_heal_once_it_can() {
        let dir = scratch("heal-boot");
        let relay = armed_relay(&dir);
        let install = fake_install(&dir);
        std::fs::remove_file(&install.server).expect("the implementation is missing at boot");
        let subject = relays(&dir, install, vec![relay]);
        let outcomes = subject.start_enabled().await;
        assert!(
            matches!(outcomes[0].1, Err(VpnError::ImplementationMissing { .. })),
            "{outcomes:?}"
        );

        fake_install(&dir);
        let reports = subject.heal(&mut HashMap::new()).await;
        assert!(
            matches!(&reports[..], [Report::Healed(Healing { remedy: Remedy::Start(_), .. })]),
            "{reports:?}"
        );
        let up = await_state(subject.supervisor(), &service_name("console"), Duration::from_secs(5), |state| {
            state.is_live()
        })
        .await;
        assert!(matches!(up, Some(ServiceState::Running { .. })), "{up:?}");

        subject.supervisor().shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_running_relay_that_never_answers_its_handshake_is_restarted_by_heal() {
        let dir = scratch("heal-silent");
        let mut relay = armed_relay(&dir);
        relay.listen = unused_listen();
        let subject = relays(&dir, fake_install(&dir), vec![relay]);
        subject.up("console").await.expect("starts");
        let service = service_name("console");
        let grace = STARTUP_GRACE.as_secs();
        let first = await_state(subject.supervisor(), &service, Duration::from_secs(20), |state| {
            matches!(state, ServiceState::Running { uptime_secs, .. } if *uptime_secs >= grace)
        })
        .await;
        let Some(ServiceState::Running { pid: first_pid, .. }) = first else {
            panic!("the stand-in runs past its grace: {first:?}");
        };

        let mut memory = HashMap::new();
        let mut reports = Vec::new();
        for _ in 0..heal::MISSES_BEFORE_RESTART {
            reports.extend(subject.heal(&mut memory).await);
        }
        assert!(
            matches!(&reports[..], [Report::Healed(Healing { remedy: Remedy::Restart(_), .. })]),
            "restarted on the third miss, not before: {reports:?}"
        );
        assert!(reports[0].to_string().contains("nothing accepts"), "{}", reports[0]);
        let again = await_state(subject.supervisor(), &service, Duration::from_secs(10), |state| {
            matches!(state, ServiceState::Running { pid, .. } if *pid != first_pid)
        })
        .await;
        assert!(again.is_some(), "a new process holds the relay");

        subject.supervisor().shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_relay_the_supervisor_restarted_is_reported_with_how_it_died() {
        let dir = scratch("heal-restarted");
        let subject = relays(&dir, failing_install(&dir), vec![armed_relay(&dir)]);
        let mut memory = HashMap::new();
        let first = subject.heal(&mut memory).await;
        assert!(
            matches!(&first[..], [Report::Healed(Healing { remedy: Remedy::Start(_), .. })]),
            "{first:?}"
        );
        let service = service_name("console");
        let mut restarted = false;
        for _ in 0..500 {
            let total = subject.supervisor().status(&service).await.map_or(0, |s| s.total_restarts);
            if total > 0 {
                restarted = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(restarted, "the stand-in exits and the supervisor restarts it");

        let reports = subject.heal(&mut memory).await;
        let said: Vec<String> = reports.iter().map(ToString::to_string).collect();
        assert!(
            reports.iter().any(|report| matches!(report, Report::Restarted { times, .. } if *times >= 1)),
            "{said:?}"
        );
        assert!(said.iter().any(|line| line.contains("exited with code 1")), "{said:?}");

        subject.supervisor().shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_relay_failing_to_start_is_retried_every_heal_interval_never_less_often() {
        // A port held by another program fails every start; the supervisor's
        // backoff would grow to five minutes, so the door would stay shut that
        // long after the port came free. heal cuts any wait longer than its own
        // interval short.
        let dir = scratch("heal-retry");
        let subject = relays(&dir, failing_install(&dir), vec![armed_relay(&dir)]);
        subject.up("console").await.expect("starts, and fails at once");
        let service = service_name("console");
        let mut memory = HashMap::new();
        let mut retried = None;
        for _ in 0..400 {
            let reports = subject.heal(&mut memory).await;
            if let Some(report) = reports.into_iter().find(|report| {
                matches!(report, Report::Healed(Healing { remedy: Remedy::Retry(_), .. }))
            }) {
                retried = Some(report);
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let retried = retried.expect("a wait longer than the heal interval is cut short");
        assert!(retried.to_string().contains("backoff"), "{retried}");
        let short_again = await_state(subject.supervisor(), &service, Duration::from_secs(5), |state| {
            matches!(state, ServiceState::Backoff { retry_in_secs, .. } if *retry_in_secs <= 5)
        })
        .await;
        assert!(short_again.is_some(), "the start cleared the supervisor's count");

        subject.supervisor().shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn taking_down_a_relay_that_never_started_is_not_an_error() {
        let dir = scratch("down-twice");
        let subject = relays(&dir, fake_install(&dir), vec![armed_relay(&dir)]);
        assert_eq!(subject.down("console").await.expect("already down"), RelayState::Down);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_deployment_with_no_relay_at_all_lists_nothing() {
        let dir = scratch("no-relays");
        let subject = relays(&dir, fake_install(&dir), Vec::new());
        assert!(subject.list().await.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    impl Relays {
        /// The supervisor these relays run under, for tests that wait on a
        /// process rather than on this crate's own view of one.
        fn supervisor(&self) -> &Supervisor {
            &self.supervisor
        }
    }
}
