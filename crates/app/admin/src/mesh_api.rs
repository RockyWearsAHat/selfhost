//! The owner's half of a peer link: `GET /api/mesh/link`.
//!
//! `crates/mesh` builds everything a link is made of — the mux header, credit
//! accounting, the enrolment proof, the registry, the dialler and the admission
//! — and it binds nothing, because a worker **dials the owner** and the owner
//! opens no port for it. The dial lands on the console site's existing 443,
//! passes the same source-address gate as every other console request, and is
//! relayed to this loopback API as an ordinary upgrade. This module is the
//! twenty lines of routing at the end of that sentence: the place where the
//! owner's daemon answers the handshake and hands the connection to
//! [`selfhost_mesh::accept::admit`].
//!
//! Without it every worker's dial met a `404` and the whole crate — the mux, the
//! credit windows, the proof, the registry, the splice — was unreachable code.
//! Multi-machine remote desktop is not a feature that *degrades* without this
//! route; it does not exist.
//!
//! # Where the credential is, and why the `101` is written before it arrives
//!
//! Every other upgrade this API serves is authorised **before** the handshake is
//! answered, by a single-use ticket minted at a CSRF-protected `POST`. A peer
//! link cannot work that way and must not pretend to: a worker is a daemon, not
//! a browser; it holds no session, mints no ticket, and the thing it can prove is
//! that it knows a secret the owner wrote down when the operator ran
//! `selfhost node invite`. That proof is an HMAC **bound to this handshake** —
//! over the `Sec-WebSocket-Key` and the `Sec-WebSocket-Accept` derived from it —
//! so it cannot even be computed until the handshake exists, and a captured one
//! is worthless on any other connection.
//!
//! So the `101` here is not a statement that the caller is trusted. It is the
//! start of the conversation in which they prove they are, and the very next
//! frame decides it. What that costs an unauthenticated caller is bounded on
//! purpose: [`MAX_PENDING_LINKS`] concurrent admissions, a ten-second greeting
//! timeout inside `admit`, and a two-second linger on refusal. What it costs the
//! owner is one task that cannot outlive those.
//!
//! # Every refusal is the same refusal
//!
//! A refused greeting gets a bare close code and nothing else — no reason, no
//! `REJECT`, no hint about which check failed — and an unknown node is verified
//! against a decoy token so the *timing* does not answer what the close code
//! refuses to. That behaviour lives in `selfhost_mesh::accept` and is inherited
//! rather than re-implemented; the rule it protects is that the operator's list
//! of their own machines must not be enumerable, one guess at a time, by anything
//! that can reach the console site.
//!
//! The failure counter is **per node**, in the mesh registry. It must never
//! reach [`FailureGate`](crate::FailureGate): that gate locks the console's login
//! door after five failures in a minute, which is right for a password guess and
//! catastrophic for a worker whose token is stale — the operator would be locked
//! out of their own console by their own laptop, and the harder the laptop
//! retried the longer it would last.
//!
//! # What this owner offers a worker, which is nothing
//!
//! Channels on a link are opened by the side that wants a service. The owner
//! opens them — a desktop session on a worker's screen is the owner asking — and
//! offers none in return, so an inbound `OPEN` is **refused with a code and a
//! sentence** rather than met with silence. A worker that asked for something is
//! owed an answer it can log; silence would leave it waiting for a timeout and
//! its operator reading nothing at all.

use crate::stream::{PeerKey, Upgraded};
use selfhost_mesh::accept::{self, Admitted, MemoryTokens};
use selfhost_mesh::channel::Reject;
use selfhost_mesh::enroll::{NodeToken, NonceLedger};
use selfhost_mesh::link::{LinkControl, LinkHandle};
use selfhost_mesh::mux::Kind;
use selfhost_mesh::registry::{DropReason, NodeName, Registry, SharedRegistry};
use selfhost_ws::Limits;
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncWrite};

/// The one path a worker dials.
///
/// Named here rather than spelled in the router, because `selfhost node invite`
/// prints this URL for an operator to paste and `[mesh].owner_url` is validated
/// against it: three copies of a path is three chances for one of them to be
/// wrong in a way that only shows up on somebody else's machine.
pub const LINK_PATH: &str = "/api/mesh/link";

/// The directory, under the data directory, holding one token per invited node.
///
/// Mirrors `crates/cli`'s `node_command::PEERS_DIR` rather than importing it —
/// the CLI depends on this crate and not the other way round — for the same
/// reason `crates/config`'s mail module mirrors constants instead of depending on
/// the subsystem that owns them.
pub const PEERS_DIR: &str = "peers";

/// The most link admissions that may be in flight at once.
///
/// The ceiling on what an unauthenticated caller can make this daemon hold. Each
/// pending admission is one task, one buffer and at most `GREETING_TIMEOUT`
/// seconds; eight is more simultaneous *first frames* than a fleet this size can
/// legitimately produce, since a link that is up is not pending and a worker
/// dials one at a time on a backoff.
///
/// Deliberately separate from [`MAX_STREAMS`](crate::upgrade::MAX_STREAMS): that
/// ceiling bounds authorised console streams and is spent by a credential, and
/// letting a stranger's dial consume places in it would hand anyone who can reach
/// the console site a way to lock the operator out of their own console.
pub const MAX_PENDING_LINKS: usize = 8;

/// The refusal code for a channel this side does not serve.
///
/// The same number `crates/cli`'s worker uses for the mirror-image refusal, so
/// the two ends of a link speak one vocabulary.
const NO_SUCH_SERVICE: u16 = 1003;

/// One live link, and which admission established it.
struct Live {
    /// Distinguishes this link from the one that replaced it. See
    /// [`Peerage::retire`].
    epoch: u64,
    /// The writing half, for whoever wants to open a channel to this machine.
    handle: LinkHandle,
}

/// The owner's peer state: who is enrolled, who is linked, and how to reach them.
///
/// One value shared by every clone of the [`Api`](crate::Api) and by the daemon
/// that wants to splice a desktop session onto a peer, so there is exactly one
/// belief about which machines are up rather than one per reader.
///
/// # Why the tokens are read once, at start-up
///
/// [`MemoryTokens`] rather than a file read per dial, and that is a security
/// property rather than a performance one: a dial is the one operation an
/// unauthenticated caller can provoke, and a filesystem walk per attempt would be
/// a lever they hold. It also matches what the operator is already told —
/// `selfhost node invite` says in as many words that a replaced token stops
/// working *at the owner's next daemon restart*.
#[derive(Clone)]
pub struct Peerage {
    inner: Arc<Inner>,
}

/// The state behind a [`Peerage`], shared by every clone.
struct Inner {
    /// Who is declared, who is live, and why the last link dropped.
    registry: SharedRegistry,
    /// Each enrolled node's secret, read once at start-up.
    tokens: MemoryTokens,
    /// The replay ledger: one handshake key is honoured exactly once.
    ledger: Mutex<NonceLedger>,
    /// The links that are up right now, by node name.
    live: Mutex<BTreeMap<String, Live>>,
    /// How many admissions are in flight, bounded by [`MAX_PENDING_LINKS`].
    pending: Mutex<usize>,
    /// The next epoch to stamp a link with.
    epochs: Mutex<u64>,
}

impl fmt::Debug for Peerage {
    /// Never renders a token, and never renders the ledger.
    ///
    /// [`NodeToken`] redacts itself, so this is belt and braces — and it is the
    /// cheap kind: the first person to add a `{:?}` while debugging should not
    /// be the person who has to remember that.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Peerage")
            .field("enrolled", &self.enrolled())
            .field("linked", &self.linked().len())
            .finish_non_exhaustive()
    }
}

impl Peerage {
    /// The owner's peer state over an explicit registry and token store.
    ///
    /// The seam a test uses, and the one a daemon that already holds a
    /// [`SharedRegistry`] should use so that the console's node picker and this
    /// route cannot disagree about which machines exist.
    pub fn new(registry: SharedRegistry, tokens: MemoryTokens) -> Self {
        Self {
            inner: Arc::new(Inner {
                registry,
                tokens,
                ledger: Mutex::new(NonceLedger::new()),
                live: Mutex::new(BTreeMap::new()),
                pending: Mutex::new(0),
                epochs: Mutex::new(0),
            }),
        }
    }

    /// The owner's peer state, read from configuration and the data directory.
    ///
    /// Declares every `[[nodes]]` entry with `role = "worker"` and loads the
    /// token `selfhost node invite` wrote for it at
    /// `<data_dir>/peers/<name>.token`. A node declared with no token, or with a
    /// token file that will not parse, is still **declared**: it appears in the
    /// registry as a machine that exists and is not linked, which is what an
    /// operator who has not run `invite` yet should see. It cannot link — an
    /// admission needs both — and the refusal it gets is byte-for-byte the one a
    /// name this owner never heard of gets.
    ///
    /// The filename is composed from a validated [`NodeName`], whose alphabet has
    /// no separator and no dot, so no configured name can reach outside the peers
    /// directory. A name that is not a legal node name is skipped rather than
    /// joined into a path.
    pub fn for_owner(nodes: &[selfhost_config::Node], data_dir: &Path) -> Self {
        let peers = data_dir.join(PEERS_DIR);
        let mut registry = Registry::new();
        let mut tokens = MemoryTokens::new();
        for node in nodes {
            if !matches!(node.role, selfhost_config::Role::Worker) {
                continue;
            }
            let Ok(name) = NodeName::parse(&node.name) else {
                eprintln!(
                    "admin: [[nodes]] declares \"{}\", which is not a legal node name; \
                     it cannot link",
                    node.name
                );
                continue;
            };
            registry.declare(name.clone());
            if let Some(token) = read_token(&peers, &name) {
                tokens.insert(&name, token);
            }
        }
        Self::new(SharedRegistry::from_registry(registry), tokens)
    }

    /// Who is declared, who is live, and why the last link dropped.
    ///
    /// The console's node picker reads this; so does `doctor`. Absence is never
    /// the answer — a peer that is down is a row with a reason, not a missing
    /// row.
    pub fn registry(&self) -> &SharedRegistry {
        &self.inner.registry
    }

    /// How many nodes have an enrolment token here.
    ///
    /// For the daemon's start-up banner: a box that declares three workers and
    /// has invited none of them should say so before the first dial is refused.
    pub fn enrolled(&self) -> usize {
        self.inner.tokens.len()
    }

    /// The names of the nodes whose links are up right now.
    pub fn linked(&self) -> Vec<String> {
        lock(&self.inner.live).keys().cloned().collect()
    }

    /// The writing half of the live link to `node`, if there is one.
    ///
    /// The seam a desktop session is spliced onto: the daemon resolves a peer,
    /// asks for its handle, and opens a channel. `None` means the machine is not
    /// linked right now, which the console renders as a reason and a last-seen
    /// time rather than as an absent row.
    pub fn link(&self, node: &NodeName) -> Option<LinkHandle> {
        lock(&self.inner.live).get(node.as_str()).map(|live| live.handle.clone())
    }

    /// Reserves one of the [`MAX_PENDING_LINKS`] admission slots.
    ///
    /// `None` at the ceiling, which is refused **before** the handshake is
    /// answered: a caller that is not going to be admitted should not be given an
    /// upgraded connection first.
    fn begin(&self) -> Option<Pending> {
        let mut pending = lock(&self.inner.pending);
        if *pending >= MAX_PENDING_LINKS {
            return None;
        }
        *pending += 1;
        Some(Pending { peerage: self.clone() })
    }

    /// Gives back an admission slot. See [`Pending`].
    fn finish(&self) {
        let mut pending = lock(&self.inner.pending);
        *pending = pending.saturating_sub(1);
    }

    /// Records a newly admitted link, replacing any older one for that node.
    ///
    /// **Replacing rather than refusing** is deliberate. A link that dropped
    /// half-open — a slept laptop, a NAT that forgot — looks live from this end
    /// until its pong deadline fires, and a worker that reconnects in that window
    /// is the ordinary case rather than the strange one. Refusing it would make
    /// recovery wait for a timeout the *owner* controls; replacing it means the
    /// machine is reachable again as soon as it says so, and the superseded
    /// link's own loop ends when its socket does.
    ///
    /// Returns the epoch this link is stamped with, which is what lets
    /// [`Peerage::retire`] tell "my link ended" from "my link was replaced and
    /// the new one is fine".
    fn publish(&self, node: &NodeName, handle: LinkHandle) -> u64 {
        let epoch = {
            let mut epochs = lock(&self.inner.epochs);
            *epochs = epochs.wrapping_add(1);
            *epochs
        };
        lock(&self.inner.live).insert(node.as_str().to_owned(), Live { epoch, handle });
        epoch
    }

    /// Retires a link that has ended, if it is still the live one.
    ///
    /// The epoch check is the whole of it: a superseded link ending must not
    /// remove the handle that replaced it, and must not tell the registry the
    /// node is down while it is up on the newer link.
    fn retire(&self, node: &NodeName, epoch: u64, reason: DropReason) -> bool {
        let mut live = lock(&self.inner.live);
        if live.get(node.as_str()).is_none_or(|held| held.epoch != epoch) {
            return false;
        }
        live.remove(node.as_str());
        drop(live);
        self.inner.registry.declare_dropped(node, SystemTime::now(), reason);
        true
    }
}

/// One in-flight admission's place in [`MAX_PENDING_LINKS`], released on drop.
///
/// An RAII guard rather than a counter incremented at the top of a function and
/// decremented at the bottom, for the reason
/// [`StreamSlot`](crate::upgrade::StreamSlot) is one: a place given back only on
/// the paths somebody remembered is a place that leaks on the next early return
/// anyone adds, and a leaked place here is a fleet that can never reconnect.
pub struct Pending {
    peerage: Peerage,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.peerage.finish();
    }
}

impl fmt::Debug for Pending {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("Pending")
    }
}

/// Reads one node's enrolment token off disk, or `None` if it has none.
///
/// A missing file is the ordinary state of a declared-but-uninvited node and is
/// not reported; a file that exists and will not parse **is** reported, because
/// that is an operator who ran `invite`, believes the machine is enrolled, and
/// will otherwise watch it be refused for ever with no explanation anywhere.
fn read_token(peers: &Path, node: &NodeName) -> Option<NodeToken> {
    let path = peers.join(format!("{}.token", node.as_str()));
    let text = std::fs::read_to_string(&path).ok()?;
    match NodeToken::from_hex(text.trim()) {
        Ok(token) => Some(token),
        Err(error) => {
            eprintln!(
                "admin: {} is not a readable enrolment token ({error}); {node} cannot link. \
                 Re-run `selfhost node invite {node}` on this machine.",
                path.display()
            );
            None
        }
    }
}

/// The state a mutex holds, with poisoning treated as recoverable.
///
/// A poisoned lock here means a panic happened while the peer tables were held.
/// Unlike the credential stores — where [`crate::Tickets`] treats poisoning as
/// fatal because limping on with credentials in an unknown state is worse than
/// stopping — none of these tables decides an authorisation: the proof does, in
/// constant time, in `selfhost_mesh`. Losing the fleet's reachability because one
/// link's task fell over would be the wrong trade on a box that self-updates
/// unattended.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Whether this deployment will admit a link at all right now.
///
/// Separated from [`serve`] so the route can refuse at the ceiling **before**
/// answering the handshake, which is the only ordering that does not hand an
/// upgraded connection to a caller who is about to be dropped.
pub fn admission_slot(peerage: &Peerage) -> Option<Pending> {
    peerage.begin()
}

/// Admits a dialler, runs its link to the end, and says how it ended.
///
/// The whole of the owner's side after the `101`. Everything that *decides* is
/// `selfhost_mesh::accept::admit`: it reads the greeting under a timeout,
/// verifies the proof in constant time against exactly one HMAC whatever the
/// answer, spends the handshake key in the replay ledger, and marks the peer
/// linked. This function owns what happens either side of that — the pending
/// slot, the live-handle table, the control channel, and the log lines.
///
/// The returned sentence is for the daemon's log. It names the node and the
/// reason and nothing else: a link carries desktop pixels and keystrokes, and
/// none of that belongs in a file.
pub async fn serve<S>(upgraded: Upgraded<S, PeerKey>, peerage: Peerage, pending: Pending) -> String
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (io, key) = upgraded.into_parts();
    let admitted = accept::admit(
        io,
        key.as_str(),
        &peerage.inner.tokens,
        &peerage.inner.ledger,
        &peerage.inner.registry,
        Limits::default(),
    )
    .await;
    // The slot is held for exactly the admission and not for the link: a link
    // that is up is not an in-flight attempt, and counting it as one would mean
    // eight linked workers refusing the ninth's first dial for ever.
    drop(pending);

    let Admitted { node, link, handle, control } = match admitted {
        Ok(admitted) => admitted,
        // The peer has already been closed with a bare code by `admit`. The
        // reason exists here and nowhere else.
        Err(refused) => return format!("a peer link was refused: {refused}"),
    };

    let epoch = peerage.publish(&node, handle.clone());
    println!("admin: peer link up: {node}");

    let reason = tokio::select! {
        reason = link.run() => reason,
        // Answering the control channel cannot end a link by itself; when it
        // returns the link is already gone and the multiplexer's own reason is
        // the accurate one, so this arm reports the shutdown it observed.
        () = answer_control(control, handle) => DropReason::LocalShutdown,
    };

    if peerage.retire(&node, epoch, reason) {
        format!("the peer link with {node} ended: {reason}")
    } else {
        // A newer link for this node is live. Saying "ended" without saying that
        // would read, in a log, as the machine having gone away.
        format!("a superseded peer link with {node} ended: {reason}")
    }
}

/// Answers what arrives on channel 0 and on channels nobody holds.
///
/// Three cases, and the third is the one that matters:
///
/// - An `ECHO` is echoed. That probe is how the console shows hop RTT and
///   end-to-end RTT as two separate numbers, and an owner that did not answer
///   would make every link look dead from the worker's side.
/// - A `CLOSE` for a channel nobody holds is normal on a spliced path and is
///   ignored.
/// - An `OPEN` is **refused**, with a code and a sentence. The owner opens
///   channels to a worker and serves none to it; see the module note for why
///   that is stated rather than met with silence.
async fn answer_control(mut control: LinkControl, handle: LinkHandle) {
    while let Some(frame) = control.recv().await {
        let sent = match frame.kind() {
            Kind::Echo => handle.send_frame(Kind::Echoed, frame.channel(), &frame.payload).await,
            Kind::Open => {
                // The service the worker asked for is not named back: the reason
                // is prose for the worker's log, and echoing a number the peer
                // chose would put a peer-chosen value in this side's own output.
                let refusal = Reject {
                    code: NO_SUCH_SERVICE,
                    reason: "this owner opens channels to a worker and serves none to it",
                };
                match refusal.encode() {
                    Ok(payload) => handle.send_frame(Kind::Reject, frame.channel(), &payload).await,
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

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_config::{Node, Role};

    fn node(text: &str) -> NodeName {
        NodeName::parse(text).expect("a legal node name")
    }

    /// A directory that removes itself when dropped.
    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!("selfhost-peerage-{name}"));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(path.join(PEERS_DIR)).expect("a scratch directory");
            Self(path)
        }

        fn write_token(&self, node: &str, text: &str) {
            std::fs::write(self.0.join(PEERS_DIR).join(format!("{node}.token")), text)
                .expect("a token file");
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn declared(names: &[(&str, Role)]) -> Vec<Node> {
        names
            .iter()
            .map(|(name, role)| Node { name: (*name).to_owned(), role: *role, mesh_ip: None })
            .collect()
    }

    #[test]
    fn only_workers_are_declared_and_only_invited_ones_can_link() {
        let scratch = Scratch::new("workers-only");
        scratch.write_token("alex-desktop", &NodeToken::from_bytes([3u8; 32]).to_hex());

        let peerage = Peerage::for_owner(
            &declared(&[
                ("home", Role::Owner),
                ("alex-desktop", Role::Worker),
                ("study-mac", Role::Worker),
            ]),
            scratch.path(),
        );

        // The owner is not a peer of itself, and is not declared as one.
        assert!(!peerage.registry().is_declared(&node("home")));
        // A worker with no token is still a machine that exists: the picker must
        // show it as not linked rather than pretend it was never configured.
        assert!(peerage.registry().is_declared(&node("study-mac")));
        assert!(peerage.registry().is_declared(&node("alex-desktop")));
        assert_eq!(peerage.enrolled(), 1, "a node with no token file must not hold one");
    }

    #[test]
    fn a_token_file_that_will_not_parse_leaves_the_node_declared_and_unenrolled() {
        let scratch = Scratch::new("bad-token");
        scratch.write_token("alex-desktop", "not hexadecimal at all");
        let peerage =
            Peerage::for_owner(&declared(&[("alex-desktop", Role::Worker)]), scratch.path());
        assert!(peerage.registry().is_declared(&node("alex-desktop")));
        assert_eq!(peerage.enrolled(), 0);
    }

    #[test]
    fn whitespace_around_a_token_is_not_part_of_it() {
        // `selfhost node invite` writes the hex and the shell adds a newline;
        // an owner that could not read back what it wrote would be refusing
        // every one of its own workers.
        let scratch = Scratch::new("trailing-newline");
        let token = NodeToken::from_bytes([9u8; 32]);
        scratch.write_token("alex-desktop", &format!("{}\n", token.to_hex()));
        let peerage =
            Peerage::for_owner(&declared(&[("alex-desktop", Role::Worker)]), scratch.path());
        assert_eq!(peerage.enrolled(), 1);
    }

    #[test]
    fn a_data_directory_with_no_peers_directory_is_an_owner_with_no_workers_invited() {
        let scratch = Scratch::new("no-peers-dir");
        let _ = std::fs::remove_dir_all(scratch.path().join(PEERS_DIR));
        let peerage =
            Peerage::for_owner(&declared(&[("alex-desktop", Role::Worker)]), scratch.path());
        assert_eq!(peerage.enrolled(), 0);
        assert!(peerage.registry().is_declared(&node("alex-desktop")));
    }

    #[test]
    fn the_pending_ceiling_binds_and_gives_every_place_back() {
        let peerage = Peerage::new(SharedRegistry::new(), MemoryTokens::new());
        let held: Vec<Pending> = (0..MAX_PENDING_LINKS)
            .map(|round| {
                admission_slot(&peerage).unwrap_or_else(|| panic!("slot {round} inside the limit"))
            })
            .collect();
        assert!(admission_slot(&peerage).is_none(), "the pending ceiling did not bind");
        drop(held);
        assert!(admission_slot(&peerage).is_some(), "pending slots leaked");
    }

    #[test]
    fn an_unlinked_node_has_no_handle_to_splice_onto() {
        let peerage = Peerage::new(SharedRegistry::new(), MemoryTokens::new());
        assert!(peerage.link(&node("alex-desktop")).is_none());
        assert!(peerage.linked().is_empty());
    }

    #[test]
    fn a_superseded_link_ending_does_not_take_the_live_one_down() {
        // The epoch rule, which is what keeps a reconnect from being reported as
        // a disconnect: the older link's loop ends *after* the newer one is
        // published, and it must retire nothing.
        let mut registry = Registry::new();
        registry.declare(node("alex-desktop"));
        let peerage =
            Peerage::new(SharedRegistry::from_registry(registry), MemoryTokens::new());
        let (link, handle, _control) = fake_link();
        let first = peerage.publish(&node("alex-desktop"), handle.clone());
        let second = peerage.publish(&node("alex-desktop"), handle);
        assert_ne!(first, second);

        assert!(
            !peerage.retire(&node("alex-desktop"), first, DropReason::TransportFailed),
            "a superseded link retired the one that replaced it"
        );
        assert_eq!(peerage.linked(), vec!["alex-desktop".to_owned()]);

        assert!(peerage.retire(&node("alex-desktop"), second, DropReason::LocalShutdown));
        assert!(peerage.linked().is_empty());
        assert_eq!(
            peerage.registry().get(&node("alex-desktop")).expect("a record").describe(),
            DropReason::LocalShutdown.to_string()
        );
        drop(link);
    }

    /// A link over a pipe with nothing on the other end, for the table tests.
    ///
    /// The driver is never run; what these tests are about is the handle table,
    /// and building a real admission for them would be testing
    /// `selfhost_mesh::accept` a second time in the wrong crate.
    fn fake_link() -> (
        selfhost_mesh::link::Link<tokio::io::DuplexStream>,
        LinkHandle,
        LinkControl,
    ) {
        let (near, far) = tokio::io::duplex(1024);
        drop(far);
        selfhost_mesh::link::Link::new(
            selfhost_ws::Duplex::server(near, Limits::default()),
            selfhost_mesh::channel::Role::Accepter,
        )
    }
}
