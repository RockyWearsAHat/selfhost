//! One machine's connection, and what it takes to close it and open another
//! without restarting the program.
//!
//! # The defect this exists for
//!
//! The console used to decide its connection once, in `main`, and bake it into
//! three places that never changed again: the closure that builds a [`Client`],
//! the tunnel thread, and the poller thread — all keyed to one address and one
//! token, with a single flag shutting the whole application down. So the only
//! way to look at a second machine was to quit and start again, and the overview
//! of every paired machine had nowhere to lead.
//!
//! # The shape
//!
//! A [`Link`] is the pair of threads that keep one machine's connection alive,
//! and it owns the [`Snapshot`] they write into. Opening another machine builds
//! a new one; the old one's flag is cleared and its threads are left to notice —
//! which they do within a tick — while the window immediately reads the new
//! link's snapshot instead.
//!
//! **Each link owning its own snapshot is what makes that safe.** A poller
//! half-way through a request when the operator switches machines will finish
//! that request and write what it learned; if both links shared one snapshot,
//! that write would put one machine's services under another machine's name for
//! as long as it took the new poller to overwrite them, and would leave the
//! plates it does not touch — the notice, the file listing, the firewall —
//! showing the previous machine indefinitely. Writing into a snapshot nobody
//! reads any more cannot be seen at all, and needs no lock discipline, no
//! generation counter, and no change to the two threads.
//!
//! # The credential
//!
//! A [`Target`] is where the console is talking and with what, behind one lock,
//! so the [`Connector`] the poller and the desktop stream share is built once
//! and keeps working across a switch without knowing a switch happened. A
//! machine reached over SSH has its token read from the far side *on demand*,
//! which is what lets a machine be opened from the interface, where there is no
//! terminal for a failure to land on — and read *afresh* for every client, which
//! is what lets the console survive a daemon that restarted and rewrote it.

use crate::client::Client;
use crate::machines::{Machine, Machines};
use crate::state::Snapshot;
use crate::tunnel::TunnelSpec;
use crate::{poller, tunnel};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// How a console reaches its daemon, when it has been given one.
///
/// A function and not a [`Client`], for the reason [`crate::poller::Connect`] is
/// one: the token the daemon wrote may not exist when the window opens, and a
/// console launched from the Dock before its daemon has started must still show
/// a window. Shared with the poller rather than duplicated, so there is one
/// place a credential is read from.
pub type Connector = Arc<dyn Fn() -> Result<Client, String> + Send + Sync>;

/// Where the console is talking, and with what.
///
/// Behind a lock and reached through the [`Connector`], so that changing
/// machines changes what every holder of that connector builds — without any of
/// them holding an address or a token of their own to be left stale.
pub struct Target {
    /// The near end: loopback, and the forwarded port when there is a tunnel.
    address: SocketAddr,
    /// Where the bearer token comes from.
    credential: Credential,
    /// A token read before the window opened, for the first client only.
    ///
    /// Taken rather than kept: after that first use every client is built from
    /// a freshly read token, which is what lets the console recover from a
    /// daemon that restarted and rewrote it. Clients are built rarely — at
    /// launch, when a desktop session opens, and when the daemon refuses the
    /// credential in hand — so re-reading costs a file read, or one `ssh` for a
    /// machine reached over one.
    held: Option<String>,
}

/// Where a bearer token is read from.
///
/// Never a token *value* in the paired-machine store: the daemon rewrites its
/// token whenever it restarts, so a copy kept on disk is a stale secret that
/// produces a confusing `401` instead of a reconnection.
pub enum Credential {
    /// A token file on this machine, named by the operator.
    File(PathBuf),
    /// Beside the console, or wherever a running daemon recorded itself.
    ///
    /// The local case, and the one that is asked again on every poll: a console
    /// opened before its daemon must connect when the daemon starts rather than
    /// having reported at launch that there was nothing to connect to.
    Discovered,
    /// Read from the machine itself over SSH, each time a client is built.
    ///
    /// `pair` is a machine to write into the store the first time a token does
    /// arrive — the rule that a pairing is a connection which has worked at
    /// least once, enforced in the one place that can know it. A pairing made
    /// from the interface has no terminal for a refusal to land on, so the
    /// refusal reaches the window as a lost link and the store is left as it
    /// was.
    OverSsh {
        /// The tunnel to read it through.
        spec: TunnelSpec,
        /// Where the daemon writes it over there, relative to the login
        /// directory.
        path: String,
        /// Saved under this name, once a token has proved the connection works.
        pair: Option<Pairing>,
    },
}

/// A machine to remember once its connection has been proved.
pub struct Pairing {
    /// The store to write into.
    pub store: PathBuf,
    /// What to write.
    pub machine: Machine,
}

impl Target {
    /// A target at `address`, authenticated by `credential`.
    pub fn new(address: SocketAddr, credential: Credential) -> Self {
        Self { address, credential, held: None }
    }

    /// The same, with a token already in hand.
    ///
    /// What a launch that named `--ssh` on a command line produces: the token is
    /// read before the window opens so the failure lands on the terminal the
    /// operator typed at, where the fix — a key to add, a host to accept — is a
    /// command to run.
    pub fn holding(mut self, token: String) -> Self {
        self.held = Some(token);
        self
    }

    /// The token, read now unless one was put in hand before the window opened.
    ///
    /// The one place a credential is obtained, so the poller and the desktop
    /// stream cannot come to hold two different ones. The read happens with the
    /// target's lock held, which is deliberate: two threads asking at once
    /// produce one read rather than two, and for a machine over SSH that is the
    /// difference between one `ssh` and two.
    fn token(&mut self) -> Result<String, String> {
        if let Some(token) = self.held.take() {
            return Ok(token);
        }
        match &mut self.credential {
            Credential::File(path) => read_token(path),
            Credential::Discovered => find_token(),
            Credential::OverSsh { spec, path, pair } => {
                let token = tunnel::fetch_token(spec, path)?;
                // On the far side of a token that actually arrived, and nowhere
                // else. A pairing that could not read one is left unsaved, so an
                // entry in the store is always a connection that has worked.
                if let Some(pairing) = pair.take() {
                    pairing.save();
                }
                Ok(token)
            }
        }
    }
}

impl Pairing {
    /// Writes this machine into the store and marks it as the one now open.
    ///
    /// Best effort, and it says so if it fails: the console is connected by the
    /// time this runs, and refusing to show a working machine because a note
    /// could not be written would trade the session for a preference.
    fn save(self) {
        let mut paired = match Machines::load(&self.store) {
            Ok(paired) => paired,
            Err(reason) => {
                eprintln!("selfhost-console: cannot read the paired machines: {reason}");
                return;
            }
        };
        let name = self.machine.name.clone();
        paired.pair(self.machine);
        paired.opened(&name);
        if let Err(reason) = paired.save(&self.store) {
            eprintln!("selfhost-console: cannot save the pairing: {reason}");
        }
    }
}

/// Builds the one connector every part of the console reaches its daemon with.
///
/// It closes over the target rather than over an address and a token, which is
/// the whole of what makes a switch possible: the desktop stream's own socket
/// keeps working across one without knowing it happened.
pub fn connector(target: &Arc<Mutex<Target>>) -> Connector {
    let target = Arc::clone(target);
    Arc::new(move || {
        let mut target = target.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let token = target.token()?;
        Client::new(target.address, token)
    })
}

/// The threads keeping one machine's connection alive, and what they write into.
///
/// Dropping it stops them and waits: a command may be half-written on a socket,
/// and dropping the process on top of one leaves the daemon reading a truncated
/// request it then has to report as malformed. The tunnel is waited for too, so
/// closing the window does not leave `ssh` forwarding a port.
pub struct Link {
    /// Cleared to tell both threads to stop.
    alive: Arc<AtomicBool>,
    /// The tunnel and the poller, in that order when there is a tunnel.
    threads: Vec<JoinHandle<()>>,
    /// What they write into, and what the window reads.
    shared: Arc<Mutex<Snapshot>>,
}

impl Link {
    /// Opens a connection: the tunnel if there is one, and the poller.
    pub fn open(spec: Option<TunnelSpec>, connect: Connector) -> Self {
        let shared = Arc::new(Mutex::new(Snapshot::default()));
        let alive = Arc::new(AtomicBool::new(true));
        let mut threads = Vec::new();
        if let Some(spec) = spec {
            threads.push(tunnel::spawn(spec, Arc::clone(&shared), Arc::clone(&alive)));
        }
        threads.push(poller::spawn(
            move || connect(),
            Arc::clone(&shared),
            Arc::clone(&alive),
        ));
        Self { alive, threads, shared }
    }

    /// What this link's threads are writing into.
    pub fn snapshot(&self) -> Arc<Mutex<Snapshot>> {
        Arc::clone(&self.shared)
    }

    /// Tells both threads to stop, without waiting for them.
    ///
    /// What a switch does. Waiting here would stall the window for as long as a
    /// request already in flight takes to time out, and there is nothing to wait
    /// for: the threads write into this link's own snapshot, which nothing reads
    /// once the window is looking at another one. They are still joined
    /// eventually — see [`Link::finished`] and the console's own drop — so a
    /// closing window never leaves `ssh` forwarding a port.
    pub fn closing(&self) {
        self.alive.store(false, Ordering::Relaxed);
    }

    /// Whether both threads have noticed and stopped.
    pub fn finished(&self) -> bool {
        self.threads.iter().all(JoinHandle::is_finished)
    }

    /// Stops both threads and waits for them.
    pub fn shutdown(self) {
        self.closing();
        for thread in self.threads {
            let _ = thread.join();
        }
    }
}

/// Which machine the window is showing, at what address, and over what.
///
/// The three facts the masthead states, held together because they change
/// together: an address that survived a switch while the name beside it did not
/// would be a console lying about where it is pointed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    /// The near end of the connection.
    pub address: SocketAddr,
    /// The server the tunnel reaches, when the console is managing one.
    pub via: Option<String>,
    /// The paired machine this is, when it is one.
    ///
    /// `None` for a local daemon and for a connection described entirely by
    /// flags: both are perfectly good things to be looking at, and neither has a
    /// name in the store to step back to.
    pub machine: Option<String>,
}

impl Bound {
    /// A console pointed at an address, over an optional tunnel.
    pub fn new(address: SocketAddr, via: Option<String>) -> Self {
        Self { address, via, machine: None }
    }

    /// The same, naming the paired machine it is.
    pub fn of(machine: &Machine) -> Self {
        let spec = machine.tunnel();
        Self {
            address: spec.local_address(),
            via: Some(machine.destination.clone()),
            machine: Some(machine.name.clone()),
        }
    }

    /// What the window is called.
    pub fn title(&self) -> String {
        match (&self.machine, &self.via) {
            (Some(name), _) => format!("selfhost — {name}"),
            (None, Some(destination)) => format!("selfhost — {destination}"),
            (None, None) => format!("selfhost — {}", self.address),
        }
    }
}

/// Where in the console the operator is standing.
///
/// Two places and not five tabs. The tabs belong to a machine — SERVICES, FILES,
/// DESKTOP and PEOPLE are all *that machine's* — so the list of machines is one
/// step back from them rather than one more of them. A fifth tab would say that
/// choosing which machine to look at is the same kind of act as choosing which
/// of its plates to read, and it is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Place {
    /// Every paired machine, and the form that adds one.
    Overview,
    /// The machine this console is bound to, and its four screens.
    #[default]
    Machine,
}

/// Reads the bearer token the daemon generated.
///
/// Never creates one. The token is proof of having read a file the daemon wrote
/// with mode `0600`; a console that generated its own when the file was missing
/// would authenticate against nothing and report a confusing 401 instead of the
/// real problem, which is that it is looking in the wrong place.
fn read_token(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| {
        format!(
            "cannot read the admin token from {}: {error}\n\
             The daemon writes it there when it starts. Run the console from the same \
             directory as `selfhost.config.toml`, or pass --token-file.",
            path.display()
        )
    })
}

/// Where the daemon writes its token, relative to the project directory.
pub const DEFAULT_TOKEN_PATH: &str = "data/admin.token";

/// Finds the token when nobody said where it is.
///
/// Two places, in this order, and the order is the point:
///
/// 1. `data/admin.token` under the working directory — what a console started
///    from a terminal inside the project should use, and what it has always
///    used. Looking anywhere else first would let a note left by some other
///    daemon quietly win over the project the operator is standing in.
/// 2. Wherever a running daemon recorded itself. This is the case the Dock
///    needs: an application launched by the Finder has no working directory
///    worth resolving against, so step one cannot succeed for it.
///
/// A failure names both, because "cannot read data/admin.token" from an icon
/// click is an answer to a question nobody asked.
fn find_token() -> Result<String, String> {
    locate_token(Path::new(DEFAULT_TOKEN_PATH), selfhost_config::home::recorded().as_deref())
}

/// The search itself, with both candidates supplied.
///
/// Separated from [`find_token`] so the order and the failure can be asserted
/// on. Which one wins is a decision, not a detail, and a test is the only thing
/// that stops it from being quietly reversed.
pub fn locate_token(beside_us: &Path, recorded: Option<&Path>) -> Result<String, String> {
    if let Ok(token) = std::fs::read_to_string(beside_us) {
        return Ok(token);
    }
    if let Some(directory) = recorded {
        if let Ok(token) = std::fs::read_to_string(directory.join(DEFAULT_TOKEN_PATH)) {
            return Ok(token);
        }
    }

    let second = match recorded {
        Some(directory) => directory.join(DEFAULT_TOKEN_PATH).display().to_string(),
        None => "nowhere — no running daemon has recorded itself".to_owned(),
    };
    Err(format!(
        "no admin token found. Looked in:\n  {}\n  {second}\n\n\
         Start the daemon with `selfhost daemon` in the directory holding \
         selfhost.config.toml, then open this again — it records where it is running so \
         the console can find it. Or pass --token-file.",
        std::path::absolute(beside_us).unwrap_or_else(|_| beside_us.to_owned()).display(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address() -> SocketAddr {
        "127.0.0.1:9191".parse().expect("a valid address")
    }

    /// A directory of this test's own, holding a token at the usual place.
    fn project_with_token(name: &str, token: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!("selfhost-session-{name}-{unique}"));
        let data = root.join("data");
        std::fs::create_dir_all(&data).expect("a writable temporary directory");
        std::fs::write(data.join("admin.token"), token).expect("writable");
        root
    }

    #[test]
    fn a_token_beside_the_console_wins_over_one_a_daemon_recorded() {
        // The order matters and is not arbitrary. An operator standing in a
        // project expects to be talking to *that* project; letting a note left
        // by some other daemon win would silently connect them elsewhere.
        let here = project_with_token("here", "the-local-one");
        let elsewhere = project_with_token("elsewhere", "the-recorded-one");
        let token =
            locate_token(&here.join(DEFAULT_TOKEN_PATH), Some(&elsewhere)).expect("both exist");
        assert_eq!(token, "the-local-one");
        let _ = std::fs::remove_dir_all(&here);
        let _ = std::fs::remove_dir_all(&elsewhere);
    }

    #[test]
    fn the_recorded_daemon_is_used_when_there_is_nothing_beside_the_console() {
        // This is the case an icon in the Dock is in: launched by the Finder,
        // with no working directory worth resolving `data/` against.
        let elsewhere = project_with_token("dock", "the-recorded-one");
        let token = locate_token(Path::new("/no/such/admin.token"), Some(&elsewhere))
            .expect("the recorded daemon has one");
        assert_eq!(token, "the-recorded-one");
        let _ = std::fs::remove_dir_all(&elsewhere);
    }

    #[test]
    fn finding_no_token_anywhere_names_every_place_that_was_tried() {
        let error =
            locate_token(Path::new("data/admin.token"), None).expect_err("nothing to find");
        assert!(error.contains("data/admin.token"), "{error}");
        assert!(error.contains("no running daemon has recorded itself"), "{error}");
        assert!(error.contains("selfhost daemon"), "the message should say what to run");

        let missing = Path::new("/no/such/project");
        let error =
            locate_token(Path::new("data/admin.token"), Some(missing)).expect_err("nothing");
        assert!(
            error.contains("/no/such/project"),
            "the recorded directory should be named when there is one: {error}"
        );
    }

    #[test]
    fn a_missing_token_file_says_where_it_looked_and_how_to_change_it() {
        let error = read_token(Path::new("/no/such/admin.token")).expect_err("should fail");
        assert!(error.contains("/no/such/admin.token"));
        assert!(error.contains("--token-file"));
    }

    #[test]
    fn a_token_already_in_hand_is_not_read_again() {
        // What a launch that named --ssh produces: the token was read before the
        // window opened, so nothing here may run a second `ssh` for it.
        let mut target =
            Target::new(address(), Credential::File(PathBuf::from("/no/such/token")))
                .holding("already-read".into());
        assert_eq!(target.token().expect("held"), "already-read");
    }

    #[test]
    fn every_client_after_the_first_is_built_from_a_freshly_read_token() {
        // The defect this closes: the daemon rewrites its token whenever it
        // restarts — which the self-updater makes it do on every push — so a
        // console holding the token it read at launch answers 401 for ever and
        // has to be quit and started again. A token in hand is used once; after
        // that the credential is read afresh for each client.
        let project = project_with_token("fresh", "the-first-one");
        let path = project.join(DEFAULT_TOKEN_PATH);
        let mut target = Target::new(address(), Credential::File(path.clone()))
            .holding("primed-before-the-window-opened".into());
        assert_eq!(target.token().expect("primed"), "primed-before-the-window-opened");
        assert_eq!(target.token().expect("the file exists"), "the-first-one");

        std::fs::write(&path, "the-daemon-restarted").expect("writable");
        assert_eq!(
            target.token().expect("still there"),
            "the-daemon-restarted",
            "the console kept a token the daemon had already replaced"
        );
        let _ = std::fs::remove_dir_all(&project);
    }

    #[test]
    fn the_connector_builds_a_client_for_whatever_the_target_now_says() {
        let project = project_with_token("switch", "first-machine");
        let target = Arc::new(Mutex::new(Target::new(
            address(),
            Credential::File(project.join(DEFAULT_TOKEN_PATH)),
        )));
        let connect = connector(&target);
        assert!(connect().is_ok(), "the first machine's client is built");

        // The switch: the same connector, a different machine behind it. This is
        // what lets the desktop stream keep its own socket working across one.
        let elsewhere = project_with_token("switch-to", "second-machine");
        *target.lock().expect("not poisoned") = Target::new(
            "127.0.0.1:9292".parse().expect("valid"),
            Credential::File(elsewhere.join(DEFAULT_TOKEN_PATH)),
        );
        let client = connect().expect("the second machine's client is built");
        assert_eq!(
            client.address().port(),
            9292,
            "the connector kept the address it was built with rather than reading the target"
        );
        let _ = std::fs::remove_dir_all(&project);
        let _ = std::fs::remove_dir_all(&elsewhere);
    }

    #[test]
    fn a_bound_console_is_named_after_the_machine_rather_than_its_address() {
        let machine = Machine::new("alex-desktop", "alex@192.168.1.8");
        let bound = Bound::of(&machine);
        assert_eq!(bound.machine.as_deref(), Some("alex-desktop"));
        assert_eq!(bound.via.as_deref(), Some("alex@192.168.1.8"));
        assert_eq!(bound.title(), "selfhost — alex-desktop");
        assert_eq!(bound.address, machine.tunnel().local_address());
    }

    #[test]
    fn a_console_with_no_paired_machine_is_named_after_what_it_is_pointed_at() {
        assert_eq!(Bound::new(address(), None).title(), "selfhost — 127.0.0.1:9191");
        assert_eq!(
            Bound::new(address(), Some("pi@host".into())).title(),
            "selfhost — pi@host"
        );
    }
}
