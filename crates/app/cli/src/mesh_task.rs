//! The peer link, as the daemon holds it: a worker dialling its owner.
//!
//! # Absent config means the subsystem does not exist
//!
//! [`start`] answers [`Posture::Absent`] unless `[mesh]` is present. No section,
//! no dial, no task, nothing polled, nothing opened — the default posture, and
//! the one a box gets by writing no config at all. `dial = false` is
//! [`Posture::Parked`]: the section is kept so an operator does not have to
//! retype a URL and a node name from memory after an incident, and nothing runs.
//!
//! # Nothing here binds a socket, and nothing here can
//!
//! **The worker dials the owner.** That direction is the whole security argument
//! and it is worth stating at the top of the only file in this crate that opens
//! a connection for the mesh:
//!
//! ```text
//! worker daemon ──wss://<owner console host>/api/mesh/link──► owner proxy :443 ──► owner admin
//! ```
//!
//! The worker binds nothing, so `lsof -nP -iTCP -sTCP:LISTEN` on it shows
//! nothing new and NAT is irrelevant. The owner binds nothing new either: the
//! dial lands on the console site's existing 443, so it passes the *same*
//! `allowed_cidrs` gate as every other console request — the mesh works only
//! over the tunnel, and no exemption anywhere is widened to make it work. If a
//! change here appears to need a listener, the change has taken a wrong turn.
//!
//! # The transport verifies, without exception
//!
//! `[mesh].owner_url` may only be `wss://` — `selfhost_config::mesh` refuses the
//! plaintext scheme at load — and [`OwnerConnector`] verifies the owner's
//! certificate against the bundled Mozilla roots, the same set `selfhost-acme`
//! uses. There is deliberately no "accept any certificate" path of the kind
//! outbound mail has: opportunistic encryption is right for delivering to an
//! arbitrary MX and wrong for a link that carries a screen, the keystrokes going
//! to it, and the contents of a share.
//!
//! # What this build's worker does with the link, and what it does not
//!
//! It **establishes and keeps** the link: dial, prove enrolment, run the
//! multiplexer, answer liveness probes, record why every drop happened, and come
//! back with the backoff `selfhost_mesh::dial` already worked out.
//!
//! It **serves no channel**. A channel the owner opens is refused with a code
//! and a reason recorded locally, because the service that would answer it — a
//! desktop session driven from the far end of a spliced channel — needs the
//! owner's `/api/mesh/link` route and the splice, and both live in
//! `crates/admin`. Refusing plainly is the honest half: an owner that opens a
//! channel is told at once instead of waiting for a stream that will not start,
//! and `doctor` reports the link state either way. That gap is named in this
//! crate's follow-ups rather than hidden behind a channel that accepts and then
//! says nothing.

use selfhost_config::Config;
use selfhost_mesh::channel::Reject;
use selfhost_mesh::dial::{Attempts, Connector, DialConfig, Session, Target};
use selfhost_mesh::enroll::NodeToken;
use selfhost_mesh::link::{LinkControl, LinkHandle};
use selfhost_mesh::mux::Kind;
use selfhost_mesh::registry::{DropReason, Liveness, NodeName, PeerRecord, SharedRegistry};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::net::TcpStream;

/// The refusal code sent for a channel this build serves no service for.
///
/// Chosen from the same space the WebSocket close codes use, and it means what
/// it says: the request was understood and this end will not carry it out.
const NO_SUCH_SERVICE: u16 = 1003;

/// How long to wait for the owner's TCP connection before giving up.
///
/// The connector's own concern rather than the protocol's, which is why
/// `selfhost_mesh::dial` does not impose it: how long to wait for a TCP
/// handshake is a property of the transport. Ten seconds is generous for a link
/// that is retried on a backoff anyway and short enough that a black-holed
/// address does not park a task for two minutes.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// What this deployment's `[mesh]` section amounts to.
///
/// A closed set rather than an `Option<Result<..>>`, because every one of these
/// is a state an operator can be *told*, and three of the four are states a
/// perfectly healthy box can be in. The daemon prints it at startup and `doctor`
/// renders the same value, so the two cannot drift.
pub enum Posture {
    /// No `[mesh]` section. This machine is not a worker and dials nothing.
    Absent,
    /// A `[mesh]` section with `dial = false`.
    Parked {
        /// The node name the section names, so the line is about a machine.
        node: String,
    },
    /// Everything needed to dial is present.
    Dialling(Arc<Peers>),
    /// A `[mesh]` section that cannot be used, and the reason in one sentence.
    ///
    /// Never fatal to the daemon. A worker that cannot reach its owner still
    /// serves its websites, its mail and its shares, and stopping all of that
    /// because a token file is missing would be an outage caused by a feature
    /// nobody was using yet.
    Broken(String),
}

impl Posture {
    /// The line the daemon prints at startup, or `None` when there is nothing
    /// to say.
    ///
    /// [`Posture::Absent`] says nothing at all: a deployment with no `[mesh]`
    /// section should look, in its own log, exactly like a build that has no
    /// mesh in it.
    pub fn banner(&self) -> Option<String> {
        match self {
            Self::Absent => None,
            Self::Parked { node } => Some(format!(
                "mesh: parked — [mesh] names {node} and dial = false, so no link is attempted"
            )),
            Self::Dialling(peers) => Some(format!(
                "mesh: dialling {} as {} — this daemon binds no socket for the link",
                peers.target, peers.node
            )),
            Self::Broken(why) => Some(format!("mesh: not dialling — {why}")),
        }
    }

    /// The dialler, when there is one to run.
    pub fn peers(&self) -> Option<&Arc<Peers>> {
        match self {
            Self::Dialling(peers) => Some(peers),
            _ => None,
        }
    }
}

/// The peer link this machine maintains, and what it knows about its state.
///
/// Shared between the dialler that writes it and the console and `doctor` that
/// read it, so there is one belief about whether the link is up rather than one
/// per reader.
pub struct Peers {
    /// This machine's declared name, which the enrolment proof is computed under.
    node: NodeName,
    /// Where the owner is, for the operator's benefit. Never a secret.
    target: Target,
    /// Everything the dialler has recorded about the link.
    registry: SharedRegistry,
    /// The dial parameters, token included.
    config: DialConfig,
}

impl fmt::Debug for Peers {
    /// Never renders the dial configuration, because it holds the node token.
    ///
    /// [`NodeToken`] redacts itself, so this is belt and braces — and it is the
    /// cheap kind: the first person to add a `{:?}` while debugging should not
    /// be the person who has to remember that.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Peers")
            .field("node", &self.node.as_str())
            .field("target", &self.target.to_string())
            .finish_non_exhaustive()
    }
}

impl Peers {
    /// This machine's declared node name.
    pub fn node(&self) -> &str {
        self.node.as_str()
    }

    /// Where this machine dials, as a URL.
    pub fn owner(&self) -> String {
        self.target.to_string()
    }

    /// What the registry currently says about the link.
    ///
    /// `None` only before the dialler has declared itself, which is a window of
    /// microseconds at startup.
    pub fn record(&self) -> Option<PeerRecord> {
        self.registry.get(&self.node)
    }

    /// The link's state as one sentence, for `doctor` and the daemon's log.
    ///
    /// Always a whole sentence, in every state, because a diagnostic that says
    /// nothing when it has nothing to complain about leaves an operator unable
    /// to tell "healthy" from "not checked".
    pub fn state_line(&self) -> String {
        let Some(record) = self.record() else {
            return format!(
                "the link to {} has not been attempted yet; the dialler starts with the daemon.",
                self.target
            );
        };
        match record.liveness {
            Liveness::Linked { since } => format!(
                "linked to {} as {}, up for {}.",
                self.target,
                self.node.as_str(),
                elapsed(since)
            ),
            Liveness::NeverLinked => format!(
                "not linked to {}: {}. The dialler keeps trying on a backoff.",
                self.target,
                DropReason::NeverConnected
            ),
            Liveness::Down { reason, since } => format!(
                "not linked to {}: {reason}, {} ago, after {} consecutive failure(s). The \
                 dialler keeps trying on a backoff.",
                self.target,
                elapsed(since),
                record.consecutive_failures,
            ),
        }
    }

    /// Keeps the link up for as long as this future is polled.
    ///
    /// One arm of the daemon's `select!`, and it never returns: a link that
    /// drops is re-established without anybody being asked, and a link that
    /// cannot be established is retried with jitter so a fleet that lost the
    /// same router does not return in lockstep.
    ///
    /// **Cancellation** is the caller's `select!`. Dropping this future stops
    /// the loop wherever it is; the link's own task ends with the socket and the
    /// registry's last recorded reason is already correct.
    pub async fn run(&self) {
        let connector = OwnerConnector::new();
        let connector = match connector {
            Ok(connector) => connector,
            Err(error) => {
                // Nothing to retry: a TLS configuration that will not assemble
                // will not assemble on the next attempt either. The link is
                // recorded as down with the reason and the future parks, which
                // leaves the rest of the daemon running.
                eprintln!("mesh: cannot build the outbound TLS configuration ({error})");
                self.registry.declare_dropped(
                    &self.node,
                    SystemTime::now(),
                    DropReason::TransportFailed,
                );
                return std::future::pending().await;
            }
        };
        // The dialler and the narrator run together, for as long as the daemon
        // does. Neither returns.
        tokio::join!(
            selfhost_mesh::dial::maintain(
                &self.config,
                &connector,
                &self.registry,
                Attempts::Forever,
                serve_link,
            ),
            self.narrate(),
        );
    }
}

/// How often the link's recorded state is re-read for the log.
///
/// Two seconds: fast enough that an operator watching a daemon start sees why
/// the first attempt failed while they are still looking at it, and cheap enough
/// to be free — it is one mutex and one string comparison.
const NARRATE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

impl Peers {
    /// Says out loud, once, every time the link's state changes.
    ///
    /// # Why this is a watcher and not a line at the point of failure
    ///
    /// `selfhost_mesh::dial::maintain` records every ending — including the ones
    /// where nothing was ever established — into the registry, and offers no
    /// hook at the moment of a *failed* attempt. Reaching for one would have
    /// meant reimplementing the retry schedule here to get a log line, which is
    /// the wrong trade twice over: duplicated backoff logic, and two places that
    /// could disagree about what happened.
    ///
    /// So the registry stays the single record and this reads it. The state is
    /// compared rather than the attempt counted, which is what stops a peer that
    /// is refusing the token from writing a line every retry for the rest of the
    /// night: the reason has not changed, so there is nothing new to say.
    async fn narrate(&self) {
        let mut ticker = tokio::time::interval(NARRATE_INTERVAL);
        let mut said: Option<(bool, String)> = None;
        loop {
            ticker.tick().await;
            let Some(record) = self.record() else { continue };
            let now = (record.is_linked(), record.describe());
            if said.as_ref() == Some(&now) {
                continue;
            }
            said = Some(now);
            eprintln!("mesh: {}", self.state_line());
        }
    }
}

/// Reads `[mesh]` and says what this machine's peer link amounts to.
///
/// Total: every way the section can be present, absent, parked or unusable is
/// one of the four answers, and none of them is an error the daemon must handle.
pub fn start(config: &Config, data_dir: &Path) -> Posture {
    let Some(mesh) = config.mesh.as_ref() else {
        return Posture::Absent;
    };
    if !mesh.dial {
        return Posture::Parked { node: mesh.node.clone() };
    }
    let node = match NodeName::parse(&mesh.node) {
        Ok(node) => node,
        Err(error) => {
            return Posture::Broken(format!("[mesh].node \"{}\" is not a node name: {error}", mesh.node));
        }
    };
    let target = match Target::parse(&mesh.owner_url) {
        Ok(target) => target,
        Err(error) => {
            return Posture::Broken(format!("[mesh].owner_url is unusable: {error}"));
        }
    };
    let path = token_path(data_dir, &mesh.token_file);
    let token = match read_token(&path) {
        Ok(token) => token,
        Err(why) => return Posture::Broken(why),
    };
    Posture::Dialling(Arc::new(Peers {
        node: node.clone(),
        target: target.clone(),
        registry: SharedRegistry::new(),
        config: DialConfig::new(target, node, token),
    }))
}

/// Where a worker's token lives, given the configured relative path.
///
/// Public because `selfhost node join` writes the file this reads, and the two
/// must agree about where it is or the daemon reports a missing token beside a
/// command that reported success.
pub fn token_path(data_dir: &Path, token_file: &Path) -> PathBuf {
    data_dir.join(token_file)
}

/// Reads a node token from its file, or explains what is wrong in one sentence.
///
/// Every failure names the path and what to do, because this is the error an
/// operator meets when they set a worker up and the useful answer is always
/// "run `selfhost node join` on this machine with the token the owner printed".
fn read_token(path: &Path) -> Result<NodeToken, String> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            format!(
                "there is no node token at {}. On the owner run `selfhost node invite <this \
                 node's name>`, then on this machine run `selfhost node join` and paste the \
                 token when it asks.",
                path.display()
            )
        } else {
            format!("cannot read the node token at {}: {error}", path.display())
        }
    })?;
    NodeToken::from_hex(&text).map_err(|error| {
        format!(
            "the node token at {} is not usable: {error}. It must be exactly 64 hex characters, \
             as `selfhost node invite` printed it.",
            path.display()
        )
    })
}

/// How long ago something happened, in words.
///
/// Saturating rather than panicking on a clock that has gone backwards: an
/// operator changing the system time must not abort a daemon that also serves
/// 80/443, and "0 seconds ago" is a harmless answer to an impossible question.
fn elapsed(since: SystemTime) -> String {
    let seconds = SystemTime::now().duration_since(since).map(|gap| gap.as_secs()).unwrap_or(0);
    match seconds {
        0..=59 => format!("{seconds}s"),
        60..=3599 => format!("{}m", seconds / 60),
        3600..=86_399 => format!("{}h", seconds / 3600),
        _ => format!("{}d", seconds / 86_400),
    }
}

/// Drives one established link until it ends, and says why it ended.
///
/// Two things happen at once and the link ends when either does: the
/// multiplexer runs, and the control channel is answered. They are joined with
/// `select!` rather than run in sequence because the multiplexer is what feeds
/// the control queue — running them one after another would mean answering
/// frames that had already stopped arriving.
async fn serve_link<S>(session: Session<S>) -> DropReason
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let Session { link, handle, control } = session;
    tokio::select! {
        reason = link.run() => reason,
        // Answering the control channel cannot end the link by itself; when it
        // returns, the link is already gone and the multiplexer's own reason is
        // the accurate one, so this arm reports the shutdown it observed.
        () = answer_control(control, handle) => DropReason::LocalShutdown,
    }
}

/// Answers what arrives on channel 0 and on channels nobody holds.
///
/// Three cases, and the third is the one that matters:
///
/// - An `ECHO` is echoed. That probe is how the console shows hop RTT and
///   end-to-end RTT as two separate numbers, and a worker that did not answer
///   would make its own link look dead to the owner.
/// - A `CLOSE` for a channel nobody holds is normal on a spliced path and is
///   ignored.
/// - An `OPEN` is **refused**, with a code and a reason. This build serves no
///   channel; see the module documentation for why that is stated rather than
///   met with silence.
async fn answer_control(mut control: LinkControl, handle: LinkHandle) {
    while let Some(frame) = control.recv().await {
        let sent = match frame.kind() {
            Kind::Echo => {
                handle.send_frame(Kind::Echoed, frame.channel(), &frame.payload).await
            }
            Kind::Open => {
                // The service the owner asked for is not named back: the reason
                // is prose for the owner's log, and echoing a number the peer
                // chose would put a peer-chosen value in this side's own output.
                let reason = Reject {
                    code: NO_SUCH_SERVICE,
                    reason: "this worker serves no channel yet: the desktop service over the \
                             mesh is not built in this deployment",
                };
                match reason.encode() {
                    Ok(payload) => {
                        handle.send_frame(Kind::Reject, frame.channel(), &payload).await
                    }
                    // The refusal did not fit its own limit, which can only mean
                    // the constant above was edited past it. Say nothing on the
                    // wire rather than send a malformed frame.
                    Err(_) => Ok(()),
                }
            }
            // Everything else on the control path is either a reply to something
            // this side never sent or a frame for a channel that has just
            // closed. Neither is a reason to end a link.
            _ => Ok(()),
        };
        if sent.is_err() {
            return;
        }
    }
}

/// The one thing this module opens: a verified TLS connection to the owner.
///
/// Named as a type rather than a closure so the verification policy has one
/// place to live and one place to be read. See the module documentation for why
/// there is no unverified path.
struct OwnerConnector {
    tls: tokio_rustls::TlsConnector,
}

impl OwnerConnector {
    /// Builds a connector that verifies the owner against the bundled roots.
    ///
    /// The `ring` provider is named explicitly rather than taken from the
    /// process default, exactly as `selfhost_acme::transport::HttpsClient` does:
    /// a connection that carries a desktop should not depend on whether some
    /// other subsystem happened to install a provider first.
    fn new() -> Result<Self, String> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| error.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self { tls: tokio_rustls::TlsConnector::from(Arc::new(config)) })
    }
}

impl Connector for OwnerConnector {
    type Stream = tokio_rustls::client::TlsStream<TcpStream>;

    fn connect(
        &self,
        target: &Target,
    ) -> impl std::future::Future<Output = io::Result<Self::Stream>> {
        let host = target.host().to_owned();
        let port = target.port();
        let tls = self.tls.clone();
        async move {
            let name = rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|_| io::Error::other(format!("{host} is not a usable server name")))?
                .to_owned();
            let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the owner did not answer"))??;
            // Nagle off: this link carries small, latency-sensitive frames — a
            // keystroke, a pointer sample — and coalescing them into 40ms
            // batches is exactly the wrong trade for a desktop.
            let _ = tcp.set_nodelay(true);
            tls.connect(name, tcp).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config with `[mesh]` in whichever state the test wants, parsed from
    /// TOML so it exercises the loader the daemon uses rather than a struct
    /// literal that would keep passing when a required field appears.
    fn config_with(mesh: &str) -> Config {
        let text = format!(
            "version = 1\n\n[server]\nacme_email = \"a@b.com\"\nacme = \"self-signed\"\n\n\
             [[nodes]]\nname = \"home\"\nrole = \"owner\"\n\n             [[nodes]]\nname = \"alex-desktop\"\nrole = \"worker\"\n{mesh}"
        );
        Config::parse(&text).expect("the config parses")
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("selfhost-mesh-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the temp dir");
        dir
    }

    #[test]
    fn no_section_means_no_dialler_at_all() {
        let dir = temp_dir("absent");
        let posture = start(&config_with(""), &dir);
        assert!(matches!(posture, Posture::Absent));
        assert!(posture.banner().is_none(), "a box with no [mesh] says nothing about one");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dial_false_parks_the_link_without_losing_the_configuration() {
        let dir = temp_dir("parked");
        let posture = start(
            &config_with(
                "\n[mesh]\nnode = \"alex-desktop\"\n\
                 owner_url = \"wss://admin.example.com/api/mesh/link\"\ndial = false\n",
            ),
            &dir,
        );
        assert!(matches!(posture, Posture::Parked { .. }));
        assert!(posture.banner().expect("a parked link is stated").contains("alex-desktop"));
        assert!(posture.peers().is_none(), "parked means nothing dials");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The error an operator actually meets, and the one that must name the fix.
    #[test]
    fn a_missing_token_is_a_sentence_naming_the_command_that_writes_it() {
        let dir = temp_dir("no-token");
        let posture = start(
            &config_with(
                "\n[mesh]\nnode = \"alex-desktop\"\n\
                 owner_url = \"wss://admin.example.com/api/mesh/link\"\n",
            ),
            &dir,
        );
        let Posture::Broken(why) = &posture else {
            panic!("a worker with no token cannot dial");
        };
        assert!(why.contains("node invite"), "{why}");
        assert!(why.contains("node join"), "{why}");
        assert!(posture.peers().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A truncated token file is a weakened credential, and accepting one would
    /// make the weakening invisible.
    #[test]
    fn a_malformed_token_is_refused_rather_than_padded() {
        let dir = temp_dir("bad-token");
        std::fs::write(dir.join("peer.token"), "abcd").expect("write a short token");
        let posture = start(
            &config_with(
                "\n[mesh]\nnode = \"alex-desktop\"\n\
                 owner_url = \"wss://admin.example.com/api/mesh/link\"\n",
            ),
            &dir,
        );
        let Posture::Broken(why) = &posture else { panic!("a short token is not a token") };
        assert!(why.contains("64 hex characters"), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_complete_worker_configuration_dials_and_says_where() {
        let dir = temp_dir("ready");
        std::fs::write(dir.join("peer.token"), "ab".repeat(32)).expect("write a token");
        let posture = start(
            &config_with(
                "\n[mesh]\nnode = \"alex-desktop\"\n\
                 owner_url = \"wss://admin.example.com/api/mesh/link\"\n",
            ),
            &dir,
        );
        let peers = posture.peers().expect("a complete configuration dials").clone();
        assert_eq!(peers.node(), "alex-desktop");
        assert_eq!(peers.owner(), "wss://admin.example.com/api/mesh/link");
        assert!(
            peers.state_line().ends_with('.'),
            "the state reads as a sentence before the first attempt: {}",
            peers.state_line()
        );
        // The secret must not be renderable by accident.
        assert!(!format!("{peers:?}").contains("abab"), "the token is not in the debug output");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every liveness state must produce a whole sentence, because `doctor`
    /// prints it verbatim.
    #[test]
    fn every_link_state_reads_as_a_sentence() {
        let dir = temp_dir("states");
        std::fs::write(dir.join("peer.token"), "cd".repeat(32)).expect("write a token");
        let posture = start(
            &config_with(
                "\n[mesh]\nnode = \"alex-desktop\"\n\
                 owner_url = \"wss://admin.example.com/api/mesh/link\"\n",
            ),
            &dir,
        );
        let peers = posture.peers().expect("dialling").clone();
        let name = NodeName::parse("alex-desktop").expect("a node name");

        peers.registry.declare(name.clone());
        assert!(peers.state_line().contains("never connected"), "{}", peers.state_line());

        peers.registry.declare_dropped(&name, SystemTime::now(), DropReason::ProofRefused);
        let line = peers.state_line();
        assert!(line.contains("enrolment proof was refused"), "{line}");
        assert!(line.ends_with('.'), "{line}");

        peers.registry.declare_linked(&name, SystemTime::now());
        let line = peers.state_line();
        assert!(line.starts_with("linked to"), "{line}");
        assert!(line.ends_with('.'), "{line}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
