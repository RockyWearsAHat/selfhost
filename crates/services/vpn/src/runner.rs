//! The supervised child: which program runs a relay, with which arguments.
//!
//! **selfhost binds no VPN socket and this module does not change that.** The
//! listener is opened by the vetted implementation, run as a program, exactly as
//! `crates/services/storage/src/smb/` drives the platform's own SMB server and as
//! `ssh` and `git` are used elsewhere here. That is a security decision before it
//! is a policy one: the daemon builds with `panic = "abort"` and is the same
//! process that serves 80 and 443, mail, and the certificate store, so a parser
//! fed unauthenticated bytes by strangers inside it is a way to take all of that
//! down. The tunnel's handshake is exactly such a parser. It stays in its own
//! process, under supervision, with its own crash domain — the identical argument
//! `crates/app/proxy` makes for relaying opaque WebSocket bytes rather than
//! parsing a frame.
//!
//! The bind ledger for this subsystem therefore reads: **selfhost binds nothing
//! new.** `admin_bind` stays `127.0.0.1:9191`. The one inbound socket is the
//! relay's own, already enumerated in `docs/SECURITY.md` §1 as the sanctioned TCP
//! 8443 and justified there as VPN-01, and the loader refuses a non-loopback
//! `listen` that has not been acknowledged with `public = true`.
//!
//! # Where the argument vector comes from
//!
//! Not invented. It is the command line the production box has been running since
//! the tunnel was installed, read out of
//! `scripts/securevpn/install-vpn-service.ps1`, with `--peer` repeated per roster
//! entry as the multi-peer change made it. Writing it down here rather than in a
//! PowerShell script is the point of the exercise: the scheduled task and this
//! crate now derive the same invocation from the same roster.
//!
//! # The argument that carries the identity, and which server understands it
//!
//! `--peer-forward <peer>=<socket>` is the identity carry on the wire between
//! this crate and the tunnel: it tells the server to open peer `<peer>`'s
//! loopback connection to `<socket>` instead of to `--ssh-host`/`--ssh-port`, so
//! that the socket a local service accepts on names the person. It is emitted
//! **only** for roster entries that declare a `forward_port`, which means a
//! deployment that has given nobody a port produces byte-for-byte the invocation
//! the production box already runs — asserted by a test, so that this change
//! cannot silently alter a live tunnel's command line.
//!
//! `server.py` is where the flag is implemented, and it lives in the operator's
//! own repository — `https://github.com/RockyWearsAHat/Secure-VPN.git` — beside
//! the rest of the implementation, not in this one. Earlier revisions of this
//! comment said it existed nowhere but a single Windows disk; that was wrong, and
//! the error started from a path in `crates/app/cli/src/service_install.rs` that
//! named a file this repository never had. What is true is narrower and still
//! worth stating: the copy a deployment *runs* is the one installed at
//! `C:\ProgramData\selfhost\securevpn\server.py` by
//! `scripts/securevpn/install-vpn-service.ps1`, and an installed copy that
//! predates the `--peer-forward` support will be started with an argument it
//! rejects, because Python's `argparse` exits non-zero on an unrecognised
//! argument. That failure is loud on purpose. The alternative considered and
//! rejected was folding the socket into the existing `--peer` value
//! (`--peer alex-mac=127.0.0.1:9443`): an old server would take the whole string
//! as a key-file stem, fail to find `alex-mac=127.0.0.1:9443.pub`, and silently
//! refuse that one peer — a person locked out with no message that says so, on a
//! relay that came up looking healthy. [`crate::Preflight`] carries a note naming
//! the requirement so it lands in the relay's own service log before the first
//! start rather than after it.

use selfhost_config::vpn::Relay;
use selfhost_config::{RestartPolicy, ServiceSpec, StartMode};
use std::path::{Path, PathBuf};

use crate::VpnError;
use crate::roster::Roster;

/// The identity the *server* end answers to on a Secure-VPN relay.
///
/// The deployed value, and it is a fixed word rather than the relay's name on
/// purpose: it names the key file the server reads its own private key from
/// (`server.key`), and every Mac already joined to this tunnel pins that identity.
/// Renaming it per relay would invalidate every client that has already joined.
pub const SERVER_IDENTITY: &str = "server";

/// The prefix a relay's supervised service is named under.
///
/// Distinct from the `selfhost-` prefix on purpose. On Windows the firewall
/// reconciler adopts and deletes any rule whose name starts `selfhost-`, and
/// `scripts/securevpn/install-vpn-service.ps1` keeps the tunnel's rule out of that
/// namespace for exactly that reason; a supervised service that shared the prefix
/// would invite the same confusion in the other direction.
pub const SERVICE_PREFIX: &str = "vpn-";

/// The supervisor's name for a relay's child process.
///
/// One function rather than a format string at each call site, because the name
/// is also a log filename and `up`, `down` and `state` must all mean the same
/// file — a mismatch there is a relay that starts and can never be stopped.
pub fn service_name(relay: &str) -> String {
    format!("{SERVICE_PREFIX}{relay}")
}

/// Where the vetted tunnel implementation is installed on this machine.
///
/// Named explicitly rather than searched for. The implementation is the
/// operator's own project, `https://github.com/RockyWearsAHat/Secure-VPN.git`,
/// and every file of it — including `server.py`, the half this struct points at —
/// is committed there. A snapshot of the client half is vendored here under
/// `scripts/securevpn/app/` so the copy this deployment installs can be diffed
/// against a reviewed one.
///
/// What is installed is still a *copy*, made by `install-vpn-service.ps1` or
/// `join-mac.sh`, and that is why this is a path a deployment states rather than
/// one this crate derives from either repository, and why [`Install::present`]
/// checks it before anything is started: the question at start-up is not "does
/// this program exist somewhere" but "is it on this disk, where the service
/// definition says".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Install {
    /// The program actually executed: the Python interpreter, on the deployment
    /// this exists for.
    pub program: PathBuf,
    /// Arguments the interpreter needs before the script's own.
    ///
    /// `-X utf8 -u` on the production box, and both are load-bearing rather than
    /// decoration: the server prints Unicode status marks, and a detached SYSTEM
    /// task with a `cp1252` console raised `UnicodeEncodeError` inside a
    /// connection handler without them. `-u` is what keeps the log live enough to
    /// read while a peer is failing to connect.
    pub leading_args: Vec<String>,
    /// The tunnel server itself.
    pub server: PathBuf,
}

/// The recorded location of the Secure-VPN server on the production box.
const VENDORED_WINDOWS: &str = r"C:\ProgramData\selfhost\securevpn\server.py";

/// The layout `scripts/securevpn/join-mac.sh` installs on a Mac, relative to the
/// user's home. That script clones the whole Secure-VPN repository into
/// `~/.securevpn/app`, so a Mac that has joined the tunnel has `server.py` sitting
/// beside the client modules, importing `crypto_core` by bare name exactly as both
/// installs do. A Mac is a client rather than a relay host, so a server is
/// normally present-but-unused there; [`Install::present`] reports what is
/// actually on disk rather than assuming either way.
const VENDORED_UNIX_SUFFIX: &str = ".securevpn/app/server.py";

impl Install {
    /// An install naming the interpreter and the server explicitly.
    ///
    /// The constructor a deployment with a non-standard layout uses, and the one
    /// the tests use to stand a harmless script in for the tunnel.
    pub fn new(
        program: impl Into<PathBuf>,
        leading_args: Vec<String>,
        server: impl Into<PathBuf>,
    ) -> Self {
        Self { program: program.into(), leading_args, server: server.into() }
    }

    /// The install this deployment already has, as recorded by the scripts that
    /// created it.
    ///
    /// Windows is the production box and its path is exact
    /// (`install-vpn-service.ps1`). Everything else takes the layout `join-mac.sh`
    /// writes, which is where a Mac's copy of the repository lands. Neither is a
    /// search: if the file is not there, [`Install::present`] says so and nothing
    /// starts.
    pub fn vendored() -> Self {
        let leading_args = vec!["-X".to_owned(), "utf8".to_owned(), "-u".to_owned()];
        if cfg!(windows) {
            Self::new("python", leading_args, VENDORED_WINDOWS)
        } else {
            let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
            Self::new("python3", leading_args, home.join(VENDORED_UNIX_SUFFIX))
        }
    }

    /// The directory the server runs in.
    ///
    /// The deployed scheduled task sets this, and it matters: the server writes
    /// its log beside itself, and a working directory inherited from whoever
    /// started the daemon would scatter those logs across the machine.
    ///
    /// An empty parent is answered as `None` rather than passed on. `Path` only
    /// splits on the separators of the platform it is compiled for, so a Windows
    /// path read on a Unix host — which is exactly what a cross-platform test or
    /// a config copied between machines produces — has a parent of `""`, and a
    /// child spawned with `""` as its working directory fails to start for a
    /// reason nobody would guess from the message.
    pub fn directory(&self) -> Option<PathBuf> {
        self.server.parent().filter(|parent| !parent.as_os_str().is_empty()).map(Path::to_path_buf)
    }

    /// Whether the server is on disk where this install says it is.
    ///
    /// Checked before a relay is started so the failure is "the implementation is
    /// not here", which names the real problem, rather than a supervised child
    /// that exits instantly and enters a restart loop reporting an interpreter's
    /// own wording about a missing file.
    pub async fn present(&self) -> bool {
        tokio::fs::metadata(&self.server).await.is_ok_and(|meta| meta.is_file())
    }
}

/// A relay's invocation: the program, and every argument in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Launch {
    /// The program to execute.
    pub program: PathBuf,
    /// Its arguments, already split — never a shell string, for the reason
    /// [`ServiceSpec::args`] gives: word-splitting differs by implementation and
    /// breaks silently on a path with a space.
    pub args: Vec<String>,
    /// The directory the child runs in.
    pub cwd: Option<PathBuf>,
}

impl Launch {
    /// The invocation as one line, for a log or a dry-run report.
    ///
    /// Display only. Nothing runs this text: the child is spawned from
    /// [`Launch::program`] and [`Launch::args`], so a quoting mistake here can
    /// mislead a reader but cannot change what executes.
    pub fn command_line(&self) -> String {
        let mut parts = vec![self.program.display().to_string()];
        parts.extend(self.args.iter().cloned());
        parts
            .into_iter()
            .map(|part| if part.contains(' ') { format!("\"{part}\"") } else { part })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Builds a relay's invocation, or says why this backend has none.
///
/// Pure: the arguments are a function of the relay, its usable roster, the install
/// and the key directory, and nothing here touches the disk. That is what lets the
/// exact command line the production box runs be asserted in a test.
///
/// `key_dir` is passed already resolved against `server.data_dir` rather than
/// derived here, because resolving it is [`crate::keys`]'s job and two places
/// deriving one path is how a relay ends up reading its keys from a directory
/// nobody inspected.
pub fn plan(
    relay: &Relay,
    roster: &Roster,
    install: &Install,
    key_dir: &Path,
) -> Result<Launch, VpnError> {
    let listen = relay.listen_addr().ok_or_else(|| VpnError::Unaddressable {
        relay: relay.name.clone(),
        field: "listen",
        value: relay.listen.clone(),
    })?;
    let forward = relay.forward_addr().ok_or_else(|| VpnError::Unaddressable {
        relay: relay.name.clone(),
        field: "forward",
        value: relay.forward.clone(),
    })?;

    let mut args = install.leading_args.clone();
    args.push(install.server.display().to_string());
    args.push("--host".to_owned());
    args.push(listen.ip().to_string());
    args.push("--port".to_owned());
    args.push(listen.port().to_string());
    // `--ssh-host`/`--ssh-port` name the *forward target*, not SSH. The names are
    // the server's own, from when it forwarded a shell rather than the proxy;
    // spelling them differently here would simply fail to parse.
    args.push("--ssh-host".to_owned());
    args.push(forward.ip().to_string());
    args.push("--ssh-port".to_owned());
    args.push(forward.port().to_string());
    args.push("--key-dir".to_owned());
    args.push(key_dir.display().to_string());
    args.push("--identity".to_owned());
    args.push(SERVER_IDENTITY.to_owned());

    // One `--peer` per *usable* entry, in roster order. A peer the roster
    // rejected is absent from this vector, which is what makes "dropped because
    // nobody could be named" an actual loss of access rather than a note in a
    // report nobody reads.
    for entry in roster.enrolled() {
        args.push("--peer".to_owned());
        args.push(entry.peer.clone());
    }

    // The identity carry, and only for the entries that asked for it. A roster
    // where nobody declared a `forward_port` produces exactly the vector the
    // production box already runs, which is what lets this change land without
    // altering a live tunnel's command line.
    for entry in roster.enrolled() {
        if let Some(forward) = entry.forward {
            args.push("--peer-forward".to_owned());
            args.push(format!("{}={forward}", entry.peer));
        }
    }

    Ok(Launch { program: install.program.clone(), args, cwd: install.directory() })
}

/// The supervised service one relay becomes.
///
/// # Why the restart policy is `Always`
///
/// The relay is the only door to the console — the console site is gated to the
/// loopback address the tunnel exits on, so a relay that is down is an operator
/// locked out of their own machine, with no second way in short of physical
/// access. A clean exit is therefore not a reason to leave it down. The crash
/// loop is still bounded: `max_restarts` is the supervisor's own default, and it
/// reports `GaveUp` rather than restarting for ever, which [`crate::state`] shows
/// as a state needing attention.
///
/// # Why it starts manually
///
/// [`StartMode::Manual`] rather than `Automatic`, so that installing a relay and
/// *arming* it stay two decisions — the same posture `enabled` and `public` take
/// in the config. `Automatic` would mean the act of loading a config binds an
/// inbound socket on a box with a real public IP.
///
/// # Why the environment is empty
///
/// Stated rather than left implicit: `docs/SECURITY.md`'s checklist forbids a
/// secret in a service environment, and the tunnel needs none — its private key
/// is a file in the key directory with the directory's permissions in front of
/// it, which is the same "the ACL is the authentication" answer the remote-desktop
/// channel uses (SCR-02).
pub fn service(relay: &Relay, launch: &Launch) -> ServiceSpec {
    let mut spec = ServiceSpec::new(service_name(&relay.name), launch.program.clone());
    spec.display_name = Some(format!("VPN relay \"{}\"", relay.name));
    spec.description = format!(
        "Secure-VPN relay: accepts mutually-authenticated sessions on {} and hands each to {}",
        relay.listen, relay.forward
    );
    spec.args = launch.args.clone();
    spec.cwd = launch.cwd.clone();
    spec.start_mode = StartMode::Manual;
    spec.restart = RestartPolicy::Always;
    // No `stop_command`: the tunnel has no documented graceful-shutdown
    // invocation, so the supervisor's own ladder applies — a signal on Unix, a
    // terminate on Windows. Sessions in flight are TCP forwards, not a database;
    // losing one costs a reconnect.
    spec
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{attributing_relay, forwarding_relay};
    use selfhost_config::vpn::Peer;

    fn install() -> Install {
        Install::new(
            "python",
            vec!["-X".into(), "utf8".into(), "-u".into()],
            r"C:\ProgramData\selfhost\securevpn\server.py",
        )
    }

    fn keys() -> PathBuf {
        PathBuf::from(r"C:\ProgramData\selfhost\securevpn\keys")
    }

    #[test]
    fn the_invocation_is_the_one_the_production_box_already_runs() {
        // Read off scripts/securevpn/install-vpn-service.ps1, with `--peer`
        // repeated as the multi-peer change made it. If this ever has to change,
        // the script has to change in the same commit — that is what the test is
        // for.
        let mut relay = forwarding_relay();
        relay.listen = "0.0.0.0:8443".into();
        relay.public = true;
        relay.peers = vec![
            Peer::new("client", "Alex", "A".repeat(43)),
            Peer::new("dad", "Dad", "B".repeat(43)),
        ];
        let roster = Roster::build(&relay);

        let launch = plan(&relay, &roster, &install(), &keys()).expect("a runnable relay");
        assert_eq!(launch.program, PathBuf::from("python"));
        assert_eq!(
            launch.args,
            vec![
                "-X",
                "utf8",
                "-u",
                r"C:\ProgramData\selfhost\securevpn\server.py",
                "--host",
                "0.0.0.0",
                "--port",
                "8443",
                "--ssh-host",
                "127.0.0.1",
                "--ssh-port",
                "443",
                "--key-dir",
                r"C:\ProgramData\selfhost\securevpn\keys",
                "--identity",
                "server",
                "--peer",
                "client",
                "--peer",
                "dad",
            ]
        );
    }

    #[test]
    fn a_peer_the_roster_rejected_is_not_admitted_by_the_tunnel() {
        // The loss of access has to be real. A peer that stays on the command
        // line while being reported as rejected is a peer that still gets in.
        let mut relay = forwarding_relay();
        relay.peers.push(Peer::new("dad-mac", "Dad!", "B".repeat(43)));
        let roster = Roster::build(&relay);

        let launch = plan(&relay, &roster, &install(), &keys()).expect("still runnable");
        assert!(launch.args.contains(&"alex-mac".to_owned()));
        assert!(!launch.args.contains(&"dad-mac".to_owned()), "{:?}", launch.args);
    }

    #[test]
    fn a_roster_with_no_per_peer_ports_produces_the_command_line_it_always_did() {
        // The regression this guards: the identity carry must not change the
        // invocation of a relay nobody has migrated. `server.py` does not know
        // `--peer-forward`, so an unconditional one would stop every deployed
        // tunnel from starting.
        let relay = forwarding_relay();
        let roster = Roster::build(&relay);
        let launch = plan(&relay, &roster, &install(), &keys()).expect("runnable");
        assert!(
            !launch.args.iter().any(|arg| arg == "--peer-forward"),
            "{:?}",
            launch.args
        );
    }

    #[test]
    fn a_peer_with_its_own_port_is_told_to_the_tunnel_as_its_own_argument() {
        // Its own flag rather than a richer `--peer` value, and the reason is
        // the failure mode of the other spelling: an old server would read
        // "alex-mac=127.0.0.1:9443" as a key-file stem, find no such .pub, and
        // refuse that one peer while coming up looking healthy.
        let relay = attributing_relay();
        let roster = Roster::build(&relay);
        let launch = plan(&relay, &roster, &install(), &keys()).expect("runnable");

        let at = launch.args.iter().position(|arg| arg == "--peer-forward").expect("emitted");
        assert_eq!(launch.args[at + 1], "alex-mac=127.0.0.1:9443");
        // The roster entry is still declared the ordinary way: the forward is an
        // addition to admission, never a replacement for it.
        assert!(launch.args.contains(&"--peer".to_owned()));
        assert!(launch.args.contains(&"alex-mac".to_owned()));
    }

    #[test]
    fn a_rejected_peer_gets_no_forward_either() {
        // A peer nobody can name must not be handed a socket that would have
        // named them.
        let mut relay = attributing_relay();
        relay.peers[0].person = "Alex/Bob".into();
        relay.peers.push(
            selfhost_config::vpn::Peer::new("dad-mac", "Dad", "B".repeat(43)).forwarded_to(9444),
        );
        let roster = Roster::build(&relay);
        let launch = plan(&relay, &roster, &install(), &keys()).expect("still runnable");
        assert!(
            !launch.args.iter().any(|arg| arg.starts_with("alex-mac=")),
            "{:?}",
            launch.args
        );
        assert!(launch.args.contains(&"dad-mac=127.0.0.1:9444".to_owned()), "{:?}", launch.args);
    }

    #[test]
    fn an_address_that_does_not_parse_is_refused_before_anything_is_spawned() {
        // Validation has already reported this; a runner that passed the text
        // through would produce a child that fails to bind, in a restart loop,
        // reporting a Python traceback.
        let mut relay = forwarding_relay();
        relay.listen = "8443".into();
        let roster = Roster::build(&relay);
        assert!(matches!(
            plan(&relay, &roster, &install(), &keys()),
            Err(VpnError::Unaddressable { field: "listen", .. })
        ));
    }

    #[test]
    fn the_service_is_named_once_and_the_same_everywhere() {
        let relay = forwarding_relay();
        let roster = Roster::build(&relay);
        let launch = plan(&relay, &roster, &install(), &keys()).expect("runnable");
        let spec = service(&relay, &launch);
        assert_eq!(spec.name, service_name(&relay.name));
        assert_eq!(spec.name, "vpn-console");
    }

    #[test]
    fn the_service_starts_manually_restarts_always_and_carries_no_secret() {
        let relay = forwarding_relay();
        let roster = Roster::build(&relay);
        let launch = plan(&relay, &roster, &install(), &keys()).expect("runnable");
        let spec = service(&relay, &launch);

        assert_eq!(spec.start_mode, StartMode::Manual, "loading a config must not bind a port");
        assert_eq!(spec.restart, RestartPolicy::Always, "the only door must come back up");
        assert!(spec.env.is_empty(), "docs/SECURITY.md: no secret in a service environment");
        // Asserted against the install rather than a literal, because `Path`
        // only splits on this platform's separators and the fixture is the
        // production box's Windows path.
        assert_eq!(spec.cwd, install().directory());
        assert!(spec.stop_command.is_none(), "the tunnel has no documented graceful shutdown");
    }

    #[test]
    fn a_server_path_with_no_directory_component_leaves_the_working_directory_alone() {
        // `""` as a working directory fails to spawn with a message nobody would
        // trace back to a path that had no parent.
        let bare = Install::new("python", Vec::new(), "server.py");
        assert_eq!(bare.directory(), None);
    }

    #[test]
    fn the_service_definition_passes_the_config_crates_own_checks() {
        // The name becomes a log filename, so `vpn-<relay>` has to survive the
        // same rules every other service is held to.
        let relay = forwarding_relay();
        let roster = Roster::build(&relay);
        let launch = plan(&relay, &roster, &install(), &keys()).expect("runnable");
        let mut problems = Vec::new();
        service(&relay, &launch).check("vpn", &[], &mut problems);
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn a_command_line_is_for_reading_and_never_for_running() {
        let relay = forwarding_relay();
        let roster = Roster::build(&relay);
        let launch = plan(&relay, &roster, &install(), &keys()).expect("runnable");
        let line = launch.command_line();
        assert!(line.starts_with("python -X utf8 -u"), "{line}");
        assert!(line.contains("--identity server"), "{line}");
    }
}
