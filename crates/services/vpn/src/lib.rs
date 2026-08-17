//! Running the relays a deployment has declared, and answering who is on one.
//!
//! A *relay* is one socket in front of one local service, and a roster of the
//! people allowed through it. `crates/foundation/config/src/vpn.rs` is its schema
//! and `docs/labs/vpn-lab.dx` is its design; this crate is the half that runs.
//! It does two things and deliberately nothing else.
//!
//! # 1. It runs the vetted implementation as a supervised child
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
//! # 2. It answers who arrived at a socket, or refuses to
//!
//! This is the point of the subsystem. `docs/labs/vpn-identity-lab.dx` confirmed
//! on 2026-08-17 that the tunnel knows which peer connected and discards that
//! before anything above can ask — so every peer is identical to the proxy, and
//! the only remaining wall is a shared password that mints ownership.
//! [`Relays::who_arrived_at`] is the question that was previously unaskable.
//!
//! The transport is a stream forwarder, so a session's *source* address is
//! `127.0.0.1` for every peer alive and always will be. What survives is the
//! **destination**: `scripts/securevpn/app/protocol.py` proves which Ed25519
//! identity completed the handshake before any payload moves, so a peer given a
//! `forward_port` of its own lands on a loopback socket nobody else lands on, and
//! that socket is the roster entry. A peer without one shares `forward` with
//! everybody else who has none, and the honest answer there is "nobody", with the
//! reason. [`Attribution`] is shaped so a caller cannot mistake either for the
//! other: three variants, no `Default`, no `unwrap_or`, and the only route to an
//! [`Identity`](selfhost_identity::Identity) hangs off the variant that actually
//! named somebody.
//!
//! A destination port is evidence, not authentication — any local process can
//! connect to it, exactly as it could forge a preamble (`docs/SECURITY.md`
//! VPN-02). What it buys is that the daemon learns the identity from the accept
//! rather than from bytes it had to parse, which is why this and not a
//! PROXY-protocol header. `docs/labs/vpn-lab.dx` carries the comparison in full.
//!
//! # The shape of the crate
//!
//! | Module | Pure? | What it holds |
//! |---|---|---|
//! | [`roster`] | **pure** | the peer set that will be admitted, and the entries that will not |
//! | [`attribution`] | **pure** | address → person, and the four honest ways to fail |
//! | [`runner`] | **pure** | the argument vector, and the refusal for a backend with no runner |
//! | [`state`] | **pure** | declared, down, up, failed — named states rather than errors |
//! | [`keys`] | impure | reads the key directory; never writes it, never generates a key |
//! | this module | impure | the supervisor, and the four verbs a caller drives |
//!
//! The split is `desk`'s: one impure edge, everything that decides anything on the
//! other side of it, so the whole subsystem is exercised without a tunnel, a
//! config file, or a socket.
//!
//! # What is not proven by any test here
//!
//! Said plainly, because a green suite is easy to read for more than it is worth.
//! No relay in this deployment has been started by this code on the production
//! box; the tunnel carrying the operator's console traffic today is still the
//! scheduled task described in `docs/VPN.md`. **No per-peer forward has carried a
//! byte on this deployment.** `runner::plan` emits `--peer-forward` for every
//! roster entry that declares a port, and `server.py` implements it — in the
//! operator's own repository, `https://github.com/RockyWearsAHat/Secure-VPN.git`,
//! which is where the whole implementation has always lived. What is unproven
//! here is the *installed* copy: a box still running a `server.py` from before
//! that support will reject the argument and fail to start, loudly, until it is
//! updated. Nothing here has ever named a person to a real request,
//! because nothing in `crates/app` calls this crate. And none of this reduces
//! what a shared credential is worth: an attributed session belonging to a named
//! guest is still only as separate as the credentials behind it.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod attribution;
pub mod keys;
pub mod roster;
pub mod runner;
pub mod state;

pub use attribution::{Attributed, Attribution, Unanswered, who_arrived_at};
pub use keys::KeyReport;
pub use roster::{Enrolled, Rejected, Roster};
pub use runner::{Install, Launch, service_name};
pub use state::{RelayState, RelaySummary};

use selfhost_config::vpn::Relay;
use selfhost_supervisor::Supervisor;
use selfhost_supervisor::state::ServiceState;
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

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
    /// Every roster entry was dropped, so the relay would bind a port and admit
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
                    "relay \"{relay}\" has no peer whose holder this deployment can name, so it \
                     would bind a socket that admits nobody"
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
                if !report.missing_peers.is_empty() {
                    write!(
                        formatter,
                        "; no public key for {}",
                        report
                            .missing_peers
                            .iter()
                            .map(|peer| format!("\"{peer}\""))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )?;
                }
                write!(
                    formatter,
                    ". Starting anyway would bind a port and then refuse somebody who has been \
                     told they have access"
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
    install: Install,
    relays: Vec<Relay>,
    rosters: Vec<Roster>,
}

impl Relays {
    /// Reads a deployment's `[[vpn]]` blocks into a drivable set.
    ///
    /// The rosters are built once, here, rather than on every call: building one
    /// is pure and cheap, but doing it per request would mean two callers could
    /// see different rosters from the same config, and "who is at this address"
    /// is exactly the question that must not have two answers.
    pub fn new(
        supervisor: Supervisor,
        data_dir: impl Into<PathBuf>,
        install: Install,
        relays: Vec<Relay>,
    ) -> Self {
        let rosters = relays.iter().map(Roster::build).collect();
        Self { supervisor, data_dir: data_dir.into(), install, relays, rosters }
    }

    /// Every declared relay, in config order.
    pub fn relays(&self) -> &[Relay] {
        &self.relays
    }

    /// One relay's block, by name.
    pub fn relay(&self, name: &str) -> Option<&Relay> {
        self.relays.iter().find(|relay| relay.name == name)
    }

    /// One relay's usable peer set, by name.
    pub fn roster(&self, name: &str) -> Option<&Roster> {
        self.rosters.iter().find(|roster| roster.relay() == name)
    }

    /// Where this relay's key material is expected.
    pub fn key_dir(&self, relay: &Relay) -> PathBuf {
        keys::key_dir(relay, &self.data_dir)
    }

    /// Every relay as a console row, with its live state.
    pub async fn list(&self) -> Vec<RelaySummary> {
        let mut rows = Vec::with_capacity(self.relays.len());
        for (relay, roster) in self.relays.iter().zip(&self.rosters) {
            rows.push(RelaySummary {
                name: relay.name.clone(),
                backend: relay.backend.tag(),
                enabled: relay.enabled,
                public: relay.public,
                listen: relay.listen.clone(),
                forward: relay.forward.clone(),
                peers: roster.enrolled().len(),
                rejected: roster.rejected().len(),
                attributable: relay.attributes(),
                state: self.state_of(relay, roster).await,
            });
        }
        rows
    }

    /// Where one relay is.
    pub async fn state(&self, name: &str) -> Result<RelayState, VpnError> {
        let (relay, roster) = self.find(name)?;
        Ok(self.state_of(relay, roster).await)
    }

    /// Everything that would happen, without doing any of it.
    ///
    /// Answers `Ok` only for a relay that would actually start, so a caller that
    /// holds a [`Preflight`] can print the command line knowing it is the one
    /// that runs. The order of the checks is the order in which their failures
    /// are cheapest to fix: the config first, then the implementation, then the
    /// disk.
    pub async fn preflight(&self, name: &str) -> Result<Preflight, VpnError> {
        let (relay, roster) = self.find(name)?;

        if !relay.enabled {
            return Err(VpnError::NotEnabled { relay: relay.name.clone() });
        }
        if !roster.is_startable() {
            return Err(VpnError::NoUsablePeers {
                relay: relay.name.clone(),
                rejected: roster.rejected().to_vec(),
            });
        }

        let key_dir = self.key_dir(relay);
        let launch = runner::plan(relay, roster, &self.install, &key_dir)?;

        if !self.install.present().await {
            return Err(VpnError::ImplementationMissing {
                relay: relay.name.clone(),
                server: self.install.server.clone(),
            });
        }

        let report = keys::inspect(&key_dir, roster).await;
        if !report.is_startable() {
            return Err(VpnError::KeysMissing {
                relay: relay.name.clone(),
                report: Box::new(report),
            });
        }

        // A dropped peer is a person who has lost access. It is not fatal while
        // somebody is still admitted, and it must not be silent either.
        let mut notes = report.notes();
        // And the one thing an operator cannot find out by reading their own
        // config: whether the `server.py` actually installed on this box is new
        // enough to understand `--peer-forward`. The flag is implemented in the
        // Secure-VPN repository, but what runs here is a copy somebody installed,
        // and Python exits non-zero on an argument it does not recognise. Said
        // before the first start, in the relay's own log, rather than discovered
        // as a child that exits immediately.
        if roster.attributes() {
            notes.push(
                "[vpn] this roster declares per-peer forwards, so the tunnel is launched with \
                 --peer-forward. The server.py installed on this box must be new enough to \
                 understand that argument — it is implemented in \
                 https://github.com/RockyWearsAHat/Secure-VPN.git — and Python exits non-zero \
                 on an unrecognised one. See scripts/securevpn/app/README.md"
                    .to_owned(),
            );
        }
        for entry in roster.rejected() {
            notes.push(format!(
                "[vpn] peer \"{}\" is NOT admitted: {}",
                entry.peer, entry.reason
            ));
        }

        Ok(Preflight {
            relay: relay.name.clone(),
            launch,
            roster: roster.clone(),
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
        let (relay, roster) = self.find(name)?;
        let service = service_name(&relay.name);

        self.supervisor.install(runner::service(relay, &plan.launch)).await;
        self.supervisor
            .note(&service, format!("[vpn] {}", plan.launch.command_line()))
            .await;
        for note in &plan.notes {
            self.supervisor.note(&service, note.clone()).await;
        }
        self.supervisor.start(&service).await;

        Ok(self.state_of(relay, roster).await)
    }

    /// Takes a relay down.
    ///
    /// A relay that was never installed is already down, and that is not an
    /// error: `down` is what an operator reaches for when they want the port
    /// closed, and reporting a failure because it was closed already would be a
    /// refusal that means "you got what you asked for".
    pub async fn down(&self, name: &str) -> Result<RelayState, VpnError> {
        let (relay, roster) = self.find(name)?;
        self.supervisor.stop(&service_name(&relay.name)).await;
        Ok(self.state_of(relay, roster).await)
    }

    /// Who arrived at this loopback socket, asking every relay.
    ///
    /// The deployment-wide question, and the one the proxy and the admin API
    /// would ask. `landed` is the **local** address of the accepted connection —
    /// `TcpStream::local_addr`, not `peer_addr` — because the source address of
    /// a forwarded session is `127.0.0.1` for every peer alive. Read
    /// [`Attribution`] before acting on it: two of its three variants name
    /// nobody, and they name nobody for different reasons.
    pub fn who_arrived_at(&self, landed: SocketAddr) -> Attribution {
        let answers = self
            .relays
            .iter()
            .zip(&self.rosters)
            .map(|(relay, roster)| who_arrived_at(relay, roster, landed))
            .collect();
        attribution::combine(landed, answers)
    }

    /// Who arrived at this loopback socket on one named relay.
    pub fn who_arrived_at_on(
        &self,
        relay: &str,
        landed: SocketAddr,
    ) -> Result<Attribution, VpnError> {
        let (relay, roster) = self.find(relay)?;
        Ok(who_arrived_at(relay, roster, landed))
    }

    /// The block and the roster for a name, or the refusal that names it.
    fn find(&self, name: &str) -> Result<(&Relay, &Roster), VpnError> {
        let relay = self
            .relay(name)
            .ok_or_else(|| VpnError::UnknownRelay { name: name.to_owned() })?;
        let roster = self
            .roster(name)
            .expect("every relay gets a roster in `new`, and both lists are built from one input");
        Ok((relay, roster))
    }

    /// One relay's lifecycle position, read from the supervisor.
    ///
    /// It asks the supervisor and nothing else. It used to run [`runner::plan`]
    /// first, to report a backend with no runner as its own state; with one
    /// transport left there is no such backend, and a listing that re-derived a
    /// plan on every row would be answering "can this start" in a function whose
    /// question is "is it running". Whether a relay *would* start is
    /// [`Relays::preflight`]'s to say, in one place, with the reason.
    async fn state_of(&self, relay: &Relay, _roster: &Roster) -> RelayState {
        let service = self.supervisor.status(&service_name(&relay.name)).await.map(|s| s.state);
        RelayState::of(relay, service.as_ref())
    }
}

/// Whether a live session on `relay` could ever be traced to a person.
///
/// A free function, and public, because it is the one thing a caller outside this
/// crate has to know before it decides what a landed socket means — the proxy's
/// site gate, in particular. `false` means every session on this relay exits on
/// one shared socket, so a check there reads as identity and is really "which
/// network", which is exactly the shape the audit found.
pub fn carries_identity(relay: &Relay) -> bool {
    relay.attributes()
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
    use selfhost_config::vpn::{Peer, Relay};
    use selfhost_supervisor::await_state;
    use std::time::Duration;

    /// The deployed shape: a Secure-VPN relay in front of the proxy, one peer.
    ///
    /// Loopback rather than `0.0.0.0` so the fixture is a relay validation
    /// accepts without `public = true` — the tests that care about the public
    /// bind widen it themselves.
    pub(crate) fn forwarding_relay() -> Relay {
        let mut relay = Relay::new("console", "127.0.0.1:8443", "127.0.0.1:443");
        relay.peers.push(Peer::new("alex-mac", "Alex", "A".repeat(43)));
        relay
    }

    /// The same relay with the identity carry turned on: its one peer holds a
    /// loopback port nobody else lands on.
    pub(crate) fn attributing_relay() -> Relay {
        let mut relay = forwarding_relay();
        relay.peers[0].forward_port = Some(9443);
        relay
    }

    /// A socket written as a literal in a test.
    pub(crate) fn socket(text: &str) -> SocketAddr {
        text.parse().expect("a literal socket in a test")
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
        if cfg!(windows) {
            let server = dir.join("server.cmd");
            std::fs::write(&server, ":loop\r\nping -n 2 127.0.0.1 >NUL\r\ngoto loop\r\n")
                .expect("write");
            Install::new("cmd", vec!["/c".to_owned()], server)
        } else {
            let server = dir.join("server.sh");
            std::fs::write(&server, "#!/bin/sh\nwhile true; do sleep 0.05; done\n")
                .expect("write");
            Install::new("/bin/sh", Vec::new(), server)
        }
    }

    /// A relay whose key directory is complete, under `data_dir`.
    fn armed_relay(data_dir: &Path) -> Relay {
        let mut relay = forwarding_relay();
        relay.enabled = true;
        let key_dir = keys::key_dir(&relay, data_dir);
        std::fs::create_dir_all(&key_dir).expect("a key directory");
        std::fs::write(keys::server_key_file(&key_dir), "private").expect("write");
        std::fs::write(keys::peer_key_file(&key_dir, "alex-mac"), "A".repeat(43)).expect("write");
        relay
    }

    fn relays(dir: &Path, install: Install, blocks: Vec<Relay>) -> Relays {
        Relays::new(Supervisor::new(dir), dir, install, blocks)
    }

    #[test]
    fn both_fixtures_are_relays_the_loader_would_actually_accept() {
        // Everything in this crate is tested against these two blocks, so if
        // either one is a relay `Config::parse` would refuse, the whole suite is
        // measuring a shape no deployment can have.
        for relay in [forwarding_relay(), attributing_relay()] {
            let mut problems = Vec::new();
            relay.check("vpn[0]", &mut problems);
            assert!(problems.is_empty(), "{}: {problems:?}", relay.name);
        }
    }

    #[tokio::test]
    async fn a_declared_relay_is_listed_and_not_running() {
        let dir = scratch("declared");
        let subject = relays(&dir, fake_install(&dir), vec![forwarding_relay()]);

        let rows = subject.list().await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, RelayState::Declared);
        assert_eq!(rows[0].peers, 1);
        assert!(!rows[0].attributable, "the deployed backend cannot name anybody");
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
    async fn a_relay_with_no_key_material_refuses_before_it_binds_anything() {
        // The whole point of the preflight: the failure is "there is no key for
        // alex-mac", not a child in a restart loop printing a traceback.
        let dir = scratch("no-keys");
        let mut relay = forwarding_relay();
        relay.enabled = true;
        let subject = relays(&dir, fake_install(&dir), vec![relay]);

        let error = subject.up("console").await.expect_err("no keys, no start");
        match &error {
            VpnError::KeysMissing { report, .. } => {
                assert_eq!(report.missing_peers, vec!["alex-mac".to_owned()]);
            }
            other => panic!("expected missing keys, got {other}"),
        }
        assert!(error.to_string().contains("alex-mac"), "{error}");
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
    async fn a_relay_whose_every_peer_is_unnameable_binds_nothing() {
        let dir = scratch("no-peers");
        let mut relay = armed_relay(&dir);
        relay.peers[0].person = "Alex/Bob".into();
        let subject = relays(&dir, fake_install(&dir), vec![relay]);

        let error = subject.up("console").await.expect_err("nobody to admit");
        assert!(matches!(error, VpnError::NoUsablePeers { .. }), "{error}");
        assert!(error.to_string().contains("alex-mac"), "{error}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_relay_that_attributes_says_so_in_the_listing_and_warns_about_the_tunnel() {
        // The two halves of the identity carry that a caller can see without
        // starting anything: the row says this relay can name somebody, and the
        // preflight says the deployed server does not understand the argument
        // that makes it true.
        let dir = scratch("attributing");
        let mut relay = armed_relay(&dir);
        relay.peers[0].forward_port = Some(9443);
        let subject = relays(&dir, fake_install(&dir), vec![relay]);

        let rows = subject.list().await;
        assert_eq!(rows.len(), 1);
        assert!(rows[0].attributable, "a peer with a port of its own can be named");
        assert_eq!(rows[0].state, RelayState::Down, "armed and not started");

        let plan = subject.preflight("console").await.expect("startable");
        assert!(
            plan.launch.command_line().contains("--peer-forward alex-mac=127.0.0.1:9443"),
            "{}",
            plan.launch.command_line()
        );
        assert!(
            plan.notes.iter().any(|note| note.contains("server.py")),
            "the preflight must warn that the tunnel does not know the flag yet: {:?}",
            plan.notes
        );

        // And the question the whole subsystem exists for now has an answer.
        assert_eq!(
            subject.who_arrived_at(socket("127.0.0.1:9443")).person().map(|p| p.as_str()),
            Some("Alex")
        );
        assert!(carries_identity(subject.relay("console").expect("declared")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_relay_comes_up_as_a_supervised_child_and_goes_back_down() {
        let dir = scratch("lifecycle");
        let relay = armed_relay(&dir);
        let subject = relays(&dir, fake_install(&dir), vec![relay]);

        let plan = subject.preflight("console").await.expect("startable");
        assert!(plan.launch.command_line().contains("--peer alex-mac"), "{}", plan.launch.command_line());

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
    async fn taking_down_a_relay_that_never_started_is_not_an_error() {
        let dir = scratch("down-twice");
        let subject = relays(&dir, fake_install(&dir), vec![armed_relay(&dir)]);
        assert_eq!(subject.down("console").await.expect("already down"), RelayState::Down);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_deployments_own_shape_attributes_nobody_and_says_why() {
        // The relay this deployment actually runs — every peer on one shared
        // forward — asked the question the audit is about. If this ever answers
        // with a person, something has started inventing attribution.
        let dir = scratch("deployed-shape");
        let subject = relays(&dir, fake_install(&dir), vec![armed_relay(&dir)]);

        let answer = subject.who_arrived_at(socket("127.0.0.1:443"));
        assert!(!answer.is_attributed(), "{answer}");
        assert!(matches!(answer, Attribution::Nobody { why: Unanswered::Shared { .. }, .. }));
        assert!(!carries_identity(subject.relay("console").expect("declared")));

        // And the preflight of such a relay says nothing about --peer-forward,
        // because it emits none: an unmigrated relay is launched exactly as it
        // always was.
        let plan = subject.preflight("console").await.expect("startable");
        assert!(!plan.launch.command_line().contains("--peer-forward"), "{}", plan.launch.command_line());
        assert!(!plan.notes.iter().any(|note| note.contains("server.py")), "{:?}", plan.notes);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn asking_one_relay_and_asking_them_all_agree() {
        let dir = scratch("one-and-all");
        let mut relay = attributing_relay();
        relay.enabled = true;
        let subject = relays(&dir, fake_install(&dir), vec![relay]);

        let landed = socket("127.0.0.1:9443");
        assert_eq!(
            subject.who_arrived_at_on("console", landed).expect("declared"),
            subject.who_arrived_at(landed)
        );
        assert!(matches!(
            subject.who_arrived_at_on("absent", landed),
            Err(VpnError::UnknownRelay { .. })
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_deployment_with_no_relay_at_all_answers_nobody() {
        let dir = scratch("no-relays");
        let subject = relays(&dir, fake_install(&dir), Vec::new());
        assert!(subject.list().await.is_empty());
        assert!(matches!(
            subject.who_arrived_at(socket("127.0.0.1:9443")),
            Attribution::Nobody { why: Unanswered::NoRelay, .. }
        ));
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
