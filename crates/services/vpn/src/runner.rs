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
//! # Who the tunnel admits
//!
//! Nobody is named on the command line. `--roster <key_dir>/roster` points the
//! server at the file enrolment writes, re-read on every handshake, so a device
//! signed in a minute ago is admitted with no restart. `server.py` pins the
//! shared `client` key when it is given no `--peer`, so [`PINNED_PEERS_ENV`] is
//! set to an empty list to pin nobody: the roster is the only way in.

use selfhost_config::vpn::Relay;
use selfhost_config::{RestartPolicy, ServiceSpec, StartMode};
use std::path::{Path, PathBuf};

use crate::VpnError;
use crate::enrol::roster_file;

/// The identity the *server* end answers to on a Secure-VPN relay.
///
/// The deployed value, and it is a fixed word rather than the relay's name on
/// purpose: it names the key file the server reads its own private key from
/// (`server.key`), and every Mac already joined to this tunnel pins that identity.
/// Renaming it per relay would invalidate every client that has already joined.
pub const SERVER_IDENTITY: &str = "server";

/// The variable `server.py` reads its pinned peers from when no `--peer` is
/// given: a comma-separated list. Unset, it pins `client`.
pub const PINNED_PEERS_ENV: &str = "SECUREVPN_SERVER_PEER";

/// A list with no names in it. Not the empty string, because Windows cannot be
/// relied on to hand a child an empty variable.
const NOBODY_PINNED: &str = ",";

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
/// Pure: the arguments are a function of the relay, the install and the key
/// directory, and nothing here touches the disk. That is what lets the
/// exact command line the production box runs be asserted in a test.
///
/// `key_dir` is passed already resolved against `server.data_dir` rather than
/// derived here, because resolving it is [`crate::keys`]'s job and two places
/// deriving one path is how a relay ends up reading its keys from a directory
/// nobody inspected.
///
/// `admin_bind` and `admin_token_path` point the server at the deployment's own
/// admin API (`crates/app/admin/src/vpn_api.rs`'s `POST /api/vpn/check-access`)
/// so a completed handshake still has to hold `vpn.access:<relay.name>` before
/// the tunnel is handed to it — see `docs/SECURITY.md` on why a valid Ed25519
/// key alone was never meant to be the whole story. `admin_token_path` is a
/// *path*, never the token's bytes, on this command line: the same posture
/// `--key-dir` already has, and the reason the service's own environment stays
/// empty (see [`service`]) — the file's permissions are the credential's real
/// protection, not process isolation.
pub fn plan(
    relay: &Relay,
    install: &Install,
    key_dir: &Path,
    admin_bind: &str,
    admin_token_path: &Path,
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
    // --account-manager is the external relay's flag name for the admin API check endpoint.
    args.push("--account-manager".to_owned());
    args.push(format!("http://{admin_bind}"));
    args.push("--account-manager-token-file".to_owned());
    args.push(admin_token_path.display().to_string());
    args.push("--location".to_owned());
    args.push(relay.name.clone());

    // Explicit rather than the server's default, so the file enrolment writes
    // and the file the tunnel reads are one path by construction.
    args.push("--roster".to_owned());
    args.push(roster_file(key_dir).display().to_string());

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
/// # Why the environment holds no secret
///
/// `docs/SECURITY.md`'s checklist forbids a secret in a service environment, and
/// the tunnel needs none — its private key is a file in the key directory. The
/// one variable set is [`PINNED_PEERS_ENV`], naming nobody, which is not a secret.
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
    spec.env.insert(PINNED_PEERS_ENV.to_owned(), NOBODY_PINNED.to_owned());
    // No `stop_command`: the tunnel has no documented graceful-shutdown
    // invocation, so the supervisor's own ladder applies — a signal on Unix, a
    // terminate on Windows. Sessions in flight are TCP forwards, not a database;
    // losing one costs a reconnect.
    spec
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::forwarding_relay;

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

    fn admin_bind() -> String {
        "127.0.0.1:9191".to_owned()
    }

    fn admin_token_path() -> PathBuf {
        PathBuf::from(r"C:\ProgramData\selfhost\admin.token")
    }

    #[test]
    fn the_invocation_is_the_one_the_production_box_already_runs() {
        // Read off scripts/securevpn/install-vpn-service.ps1, plus the
        // account-manager arguments so a completed handshake still has to clear
        // `vpn.access:<relay>`, and the roster file in place of any `--peer`.
        let mut relay = forwarding_relay();
        relay.listen = "0.0.0.0:8443".into();
        relay.public = true;

        let launch = plan(&relay, &install(), &keys(), &admin_bind(), &admin_token_path())
            .expect("a runnable relay");
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
                "--account-manager",
                "http://127.0.0.1:9191",
                "--account-manager-token-file",
                r"C:\ProgramData\selfhost\admin.token",
                "--location",
                "console",
                "--roster",
                &roster_file(&keys()).display().to_string(),
            ]
        );
    }

    #[test]
    fn nobody_is_pinned_on_the_command_line_or_by_the_servers_default() {
        // `server.py` with no `--peer` pins the shared `client` key unless this
        // variable is set to a list naming nobody.
        let relay = forwarding_relay();
        let launch = plan(&relay, &install(), &keys(), &admin_bind(), &admin_token_path()).expect("runnable");
        assert!(!launch.args.iter().any(|arg| arg == "--peer"), "{:?}", launch.args);
        let spec = service(&relay, &launch);
        assert_eq!(spec.env.get(PINNED_PEERS_ENV).map(String::as_str), Some(NOBODY_PINNED));
    }

    #[test]
    fn an_address_that_does_not_parse_is_refused_before_anything_is_spawned() {
        // Validation has already reported this; a runner that passed the text
        // through would produce a child that fails to bind, in a restart loop,
        // reporting a Python traceback.
        let mut relay = forwarding_relay();
        relay.listen = "8443".into();
        assert!(matches!(
            plan(&relay, &install(), &keys(), &admin_bind(), &admin_token_path()),
            Err(VpnError::Unaddressable { field: "listen", .. })
        ));
    }

    #[test]
    fn the_service_is_named_once_and_the_same_everywhere() {
        let relay = forwarding_relay();
        let launch = plan(&relay, &install(), &keys(), &admin_bind(), &admin_token_path()).expect("runnable");
        let spec = service(&relay, &launch);
        assert_eq!(spec.name, service_name(&relay.name));
        assert_eq!(spec.name, "vpn-console");
    }

    #[test]
    fn the_service_starts_manually_restarts_always_and_carries_no_secret() {
        let relay = forwarding_relay();
        let launch = plan(&relay, &install(), &keys(), &admin_bind(), &admin_token_path()).expect("runnable");
        let spec = service(&relay, &launch);

        assert_eq!(spec.start_mode, StartMode::Manual, "loading a config must not bind a port");
        assert_eq!(spec.restart, RestartPolicy::Always, "the only door must come back up");
        assert_eq!(spec.env.len(), 1, "docs/SECURITY.md: no secret in a service environment");
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
        let launch = plan(&relay, &install(), &keys(), &admin_bind(), &admin_token_path()).expect("runnable");
        let mut problems = Vec::new();
        service(&relay, &launch).check("vpn", &[], &mut problems);
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn a_command_line_is_for_reading_and_never_for_running() {
        let relay = forwarding_relay();
        let launch = plan(&relay, &install(), &keys(), &admin_bind(), &admin_token_path()).expect("runnable");
        let line = launch.command_line();
        assert!(line.starts_with("python -X utf8 -u"), "{line}");
        assert!(line.contains("--identity server"), "{line}");
    }
}
