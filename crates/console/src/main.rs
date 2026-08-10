//! The desktop console: one window showing everything the daemon is running.
//!
//! # Why this is a separate program
//!
//! It runs on *your* machine, not on the server. A graphical program on the
//! server would need a logged-in desktop session there — the objection that
//! removed a container runtime from this project, since the target is a machine
//! that must stay up unattended with nobody signed in. A daemon with a control
//! API and a console that connects to it has neither problem, and one console
//! can drive several machines.
//!
//! # Reaching a daemon that is not on this machine
//!
//! The control API binds loopback and refuses anything else, so there is no
//! remote mode to configure and no second authentication scheme to get wrong.
//! Tunnel it:
//!
//! ```sh
//! ssh -L 9191:127.0.0.1:9191 you@server
//! selfhost-console --token-file ~/server-admin.token
//! ```
//!
//! The encryption and the authentication are then OpenSSH's, which is a better
//! answer than anything this program could invent.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod channel;
mod client;
mod nas;
mod poller;
mod registry;
mod remote;
mod state;
mod tunnel;
mod view;

use client::Client;
use state::Snapshot;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tunnel::TunnelSpec;
use view::Console;

/// Where the daemon listens unless told otherwise.
const DEFAULT_ADDRESS: &str = "127.0.0.1:9191";

/// Where the daemon writes its token, relative to the project directory.
const DEFAULT_TOKEN_PATH: &str = "data/admin.token";

fn main() -> std::process::ExitCode {
    match start() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("selfhost-console: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Reads the arguments, connects, and runs the window until it closes.
fn start() -> Result<(), String> {
    let options = Options::parse(std::env::args().skip(1))?;
    if options.help {
        print!("{USAGE}");
        return Ok(());
    }

    let address = options.address();
    // A remote console reads its token over SSH, once, before the window opens.
    // That failure belongs on the terminal: `--ssh` is typed at one, and the
    // fix — a key to add, a host to accept — is a command to run there.
    let remote_token = match (&options.ssh, &options.token_path) {
        (Some(spec), None) => Some(tunnel::fetch_token(spec, &options.remote_token)?),
        _ => None,
    };

    // A local console does not read its token until it polls, and asks again on
    // every poll. The token is written by the daemon, so requiring it up front
    // would mean a console opened before its daemon exits instead of opening —
    // which from the Dock looks like an application that does nothing at all.
    let token_path = options.token_path.clone();
    // Shared rather than owned by the poller alone: the desktop stream opens
    // its own socket and needs the same credential, and reading the token in
    // two places would be two things to keep in step.
    let connect: view::Connector = Arc::new(move || -> Result<Client, String> {
        let token = match (&remote_token, &token_path) {
            (Some(token), _) => token.clone(),
            (None, Some(path)) => read_token(path)?,
            (None, None) => find_token()?,
        };
        Client::new(address, token)
    });

    let shared = Arc::new(Mutex::new(Snapshot::default()));
    let running = Arc::new(AtomicBool::new(true));

    let tunnel = options
        .ssh
        .clone()
        .map(|spec| tunnel::spawn(spec, Arc::clone(&shared), Arc::clone(&running)));
    let for_poller = Arc::clone(&connect);
    let poller =
        poller::spawn(move || for_poller(), Arc::clone(&shared), Arc::clone(&running));

    let via = options.ssh.as_ref().map(|spec| spec.destination.clone());
    let title = match &via {
        Some(destination) => format!("selfhost — {destination}"),
        None => format!("selfhost — {address}"),
    };
    let console =
        Console::new(Arc::clone(&shared), Arc::clone(&running), address, via).reaching(connect);
    let outcome = console.run(title).map_err(|error| error.to_string());

    // Told to stop, then waited for: a command may be half-written on a socket,
    // and dropping the process on top of it leaves the daemon reading a
    // truncated request it then has to report as malformed. The tunnel is waited
    // for too, so closing the window does not leave `ssh` forwarding a port.
    running.store(false, Ordering::Relaxed);
    let _ = poller.join();
    if let Some(tunnel) = tunnel {
        let _ = tunnel.join();
    }
    outcome
}

/// Reads the bearer token the daemon generated.
///
/// Never creates one. The token is proof of having read a file the daemon wrote
/// with mode `0600`; a console that generated its own when the file was missing
/// would authenticate against nothing and report a confusing 401 instead of the
/// real problem, which is that it is looking in the wrong place.
fn read_token(path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|error| {
        format!(
            "cannot read the admin token from {}: {error}\n\
             The daemon writes it there when it starts. Run the console from the same \
             directory as `selfhost.config.toml`, or pass --token-file.",
            path.display()
        )
    })
}

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
    locate_token(
        std::path::Path::new(DEFAULT_TOKEN_PATH),
        selfhost_config::home::recorded().as_deref(),
    )
}

/// The search itself, with both candidates supplied.
///
/// Separated from [`find_token`] so the order and the failure can be asserted
/// on. Which one wins is a decision, not a detail, and a test is the only thing
/// that stops it from being quietly reversed.
fn locate_token(
    beside_us: &std::path::Path,
    recorded: Option<&std::path::Path>,
) -> Result<String, String> {
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

/// What the console was asked to do.
#[derive(Debug)]
struct Options {
    /// Where the daemon is, when it is not reached through a tunnel.
    address: SocketAddr,
    /// The server to tunnel to, when there is one.
    ssh: Option<TunnelSpec>,
    /// Where the daemon's token is on the server, for a tunnelled console.
    remote_token: String,
    /// A token file on this machine. Overrides reading one over SSH.
    token_path: Option<PathBuf>,
    help: bool,
}

impl Options {
    /// Reads the command line.
    fn parse(arguments: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut options = Self {
            address: DEFAULT_ADDRESS.parse().expect("the default address is valid"),
            ssh: None,
            remote_token: tunnel::DEFAULT_REMOTE_TOKEN.to_owned(),
            token_path: None,
            help: false,
        };

        // The tunnel's ports are collected separately: they are meaningful only
        // with --ssh, and accepting them in any order means the operator does not
        // have to know which flag was read first.
        let mut destination: Option<String> = None;
        let mut ssh_port: Option<u16> = None;
        let mut identity: Option<PathBuf> = None;
        let mut local_port: Option<u16> = None;
        let mut remote_port: Option<u16> = None;

        let mut arguments = arguments.peekable();
        while let Some(flag) = arguments.next() {
            let mut value = |name: &str| arguments.next().ok_or(format!("{name} needs a value"));
            match flag.as_str() {
                "-h" | "--help" => options.help = true,
                "--daemon" => options.address = parse_address(&value("--daemon")?)?,
                "--token-file" => options.token_path = Some(PathBuf::from(value("--token-file")?)),
                "--ssh" => destination = Some(value("--ssh")?),
                "--ssh-port" => ssh_port = Some(parse_port(&value("--ssh-port")?, "--ssh-port")?),
                "--identity" => identity = Some(PathBuf::from(value("--identity")?)),
                "--local-port" => {
                    local_port = Some(parse_port(&value("--local-port")?, "--local-port")?);
                }
                "--remote-port" => {
                    remote_port = Some(parse_port(&value("--remote-port")?, "--remote-port")?);
                }
                "--remote-token" => options.remote_token = value("--remote-token")?,
                other => return Err(format!("unknown option {other}\n\n{USAGE}")),
            }
        }

        match destination {
            Some(destination) => {
                if destination.starts_with('-') {
                    return Err(format!(
                        "--ssh {destination:?} looks like an option, not a server. Write it as \
                         host or user@host"
                    ));
                }
                // The same port at both ends by default, since that is what the
                // daemon's own advice prints — but overridable, because a console
                // on a machine already running a daemon of its own cannot bind
                // 9191 twice.
                let remote = remote_port.unwrap_or(options.address.port());
                let mut spec = TunnelSpec::new(destination, remote);
                spec.local_port = local_port.unwrap_or(remote);
                spec.ssh_port = ssh_port;
                spec.identity = identity;
                options.ssh = Some(spec);
            }
            // Every one of these describes a tunnel. Silently ignoring them would
            // leave the console talking to a local daemon while the operator
            // believed they were looking at a server.
            None => {
                for (flag, given) in [
                    ("--ssh-port", ssh_port.is_some()),
                    ("--identity", identity.is_some()),
                    ("--local-port", local_port.is_some()),
                    ("--remote-port", remote_port.is_some()),
                ] {
                    if given {
                        return Err(format!("{flag} only means something with --ssh"));
                    }
                }
            }
        }

        Ok(options)
    }

    /// The address the console actually talks to.
    ///
    /// The near end of the tunnel when there is one, so nothing downstream has to
    /// know whether the daemon is on this machine.
    fn address(&self) -> SocketAddr {
        match &self.ssh {
            Some(spec) => spec.local_address(),
            None => self.address,
        }
    }
}

/// Reads a port number, refusing zero.
///
/// Zero means "any port" to the operating system, which for a forward would mean
/// the console could not know where to connect.
fn parse_port(value: &str, flag: &str) -> Result<u16, String> {
    match value.parse::<u16>() {
        Ok(0) | Err(_) => Err(format!("{flag} {value:?} is not a port number")),
        Ok(port) => Ok(port),
    }
}

/// Parses an address, accepting a bare port for the common tunnelled case.
///
/// `--daemon 9292` means loopback on that port. Typing the whole address is
/// what people get wrong, and the address is always loopback anyway: the API
/// refuses to bind anywhere else.
fn parse_address(value: &str) -> Result<SocketAddr, String> {
    if let Ok(port) = value.parse::<u16>() {
        return Ok(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    value
        .parse()
        .map_err(|_| format!("{value:?} is not an address like 127.0.0.1:9191 or a port number"))
}

/// What `--help` prints.
const USAGE: &str = "\
selfhost-console — the desktop console for a selfhost daemon

Usage:
  selfhost-console [--daemon <address|port>] [--token-file <path>]
  selfhost-console --ssh <[user@]host> [tunnel options]

Options:
  --daemon <address>     Where the daemon's control API is listening.
                         A bare port means loopback on that port.
                         Default: 127.0.0.1:9191
  --token-file <path>    The bearer token the daemon wrote.
                         Default: data/admin.token, or read over SSH with --ssh.
  -h, --help             Show this.

Reaching a daemon on another machine:
  --ssh <[user@]host>    Open and keep open an SSH tunnel to that server, and
                         talk to the near end of it.
  --ssh-port <port>      The port sshd listens on, if not 22.
  --identity <path>      A private key to use, instead of the agent's default.
  --remote-port <port>   The daemon's port over there.       Default: 9191
  --local-port <port>    The port it appears at here.        Default: the same
  --remote-token <path>  Where the daemon's token is on the server, relative to
                         the login directory.       Default: data/admin.token

The control API binds loopback and refuses anything else, so the tunnel is not a
convenience — it is how the encryption and the authentication stay OpenSSH's.
The console runs `ssh` in batch mode and never answers a prompt for you: an
unknown host key is reported, with the command to check and accept it yourself.
";

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Result<Options, String> {
        Options::parse(arguments.iter().map(|argument| (*argument).to_owned()))
    }

    #[test]
    fn the_defaults_point_at_a_daemon_in_the_current_project() {
        let options = parse(&[]).expect("no arguments is valid");
        assert_eq!(options.address.to_string(), DEFAULT_ADDRESS);
        assert_eq!(options.address(), options.address, "with no tunnel, it talks to the daemon directly");
        assert!(options.token_path.is_none(), "the default token path is only used when reading one");
        assert!(options.ssh.is_none());
        assert!(!options.help);
    }

    #[test]
    fn a_bare_port_means_loopback_on_that_port() {
        let options = parse(&["--daemon", "9292"]).expect("a port is an address");
        assert_eq!(options.address.to_string(), "127.0.0.1:9292");
    }

    #[test]
    fn a_full_address_is_taken_as_written() {
        let options = parse(&["--daemon", "127.0.0.1:1234"]).expect("a valid address");
        assert_eq!(options.address.to_string(), "127.0.0.1:1234");
    }

    #[test]
    fn nonsense_addresses_are_refused_with_an_example() {
        let error = parse(&["--daemon", "not-an-address"]).expect_err("should refuse");
        assert!(error.contains("127.0.0.1:9191"), "the error should show the shape wanted");
    }

    #[test]
    fn an_option_without_its_value_is_refused_rather_than_defaulted() {
        assert!(parse(&["--daemon"]).is_err());
        assert!(parse(&["--token-file"]).is_err());
    }

    #[test]
    fn an_unknown_option_is_refused_and_shows_the_usage() {
        let error = parse(&["--colour", "red"]).expect_err("should refuse");
        assert!(error.contains("Usage:"));
    }

    #[test]
    fn help_is_recognised_in_both_spellings() {
        assert!(parse(&["-h"]).expect("valid").help);
        assert!(parse(&["--help"]).expect("valid").help);
    }

    /// A directory of this test's own, holding a token at the usual place.
    fn project_with_token(name: &str, token: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!("selfhost-console-{name}-{unique}"));
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
        let token = locate_token(&here.join(DEFAULT_TOKEN_PATH), Some(&elsewhere))
            .expect("both exist");
        assert_eq!(token, "the-local-one");
        let _ = std::fs::remove_dir_all(&here);
        let _ = std::fs::remove_dir_all(&elsewhere);
    }

    #[test]
    fn the_recorded_daemon_is_used_when_there_is_nothing_beside_the_console() {
        // This is the case an icon in the Dock is in: launched by the Finder,
        // with no working directory worth resolving `data/` against.
        let elsewhere = project_with_token("dock", "the-recorded-one");
        let token = locate_token(std::path::Path::new("/no/such/admin.token"), Some(&elsewhere))
            .expect("the recorded daemon has one");
        assert_eq!(token, "the-recorded-one");
        let _ = std::fs::remove_dir_all(&elsewhere);
    }

    #[test]
    fn finding_no_token_anywhere_names_every_place_that_was_tried() {
        let error = locate_token(std::path::Path::new("data/admin.token"), None)
            .expect_err("nothing to find");
        assert!(error.contains("data/admin.token"), "{error}");
        assert!(error.contains("no running daemon has recorded itself"), "{error}");
        assert!(error.contains("selfhost daemon"), "the message should say what to run");

        let missing = std::path::Path::new("/no/such/project");
        let error = locate_token(std::path::Path::new("data/admin.token"), Some(missing))
            .expect_err("nothing to find");
        assert!(
            error.contains("/no/such/project"),
            "the recorded directory should be named when there is one: {error}"
        );
    }

    #[test]
    fn a_missing_token_file_says_where_it_looked_and_how_to_change_it() {
        let error = read_token(&PathBuf::from("/no/such/admin.token")).expect_err("should fail");
        assert!(error.contains("/no/such/admin.token"));
        assert!(error.contains("--token-file"));
    }

    #[test]
    fn the_usage_documents_the_tunnel_because_there_is_no_remote_mode() {
        assert!(USAGE.contains("--ssh"));
        assert!(USAGE.contains("loopback"), "the reason a tunnel is needed belongs in the usage");
    }

    #[test]
    fn a_tunnelled_console_talks_to_the_near_end_of_its_own_forward() {
        let options = parse(&["--ssh", "rocky@server.example"]).expect("valid");
        let spec = options.ssh.as_ref().expect("a tunnel");
        assert_eq!(spec.destination, "rocky@server.example");
        assert_eq!(spec.remote_port, 9191, "the daemon's own default");
        assert_eq!(spec.local_port, 9191);
        assert_eq!(options.address().to_string(), "127.0.0.1:9191");
    }

    #[test]
    fn the_two_ends_of_the_tunnel_can_use_different_ports() {
        // A console on a machine already running a daemon of its own cannot bind
        // 9191 a second time.
        let options = parse(&["--ssh", "server", "--local-port", "9292"]).expect("valid");
        let spec = options.ssh.as_ref().expect("a tunnel");
        assert_eq!(spec.local_port, 9292);
        assert_eq!(spec.remote_port, 9191);
        assert_eq!(options.address().to_string(), "127.0.0.1:9292");
    }

    #[test]
    fn the_daemons_port_follows_the_daemon_flag_when_the_remote_one_is_not_given() {
        let options = parse(&["--daemon", "9500", "--ssh", "server"]).expect("valid");
        let spec = options.ssh.as_ref().expect("a tunnel");
        assert_eq!(spec.remote_port, 9500);
        assert_eq!(spec.local_port, 9500);
    }

    #[test]
    fn tunnel_options_are_accepted_in_any_order() {
        let first = parse(&["--identity", "/k", "--ssh", "server", "--ssh-port", "2222"]);
        let second = parse(&["--ssh", "server", "--ssh-port", "2222", "--identity", "/k"]);
        assert_eq!(
            first.expect("valid").ssh,
            second.expect("valid").ssh,
            "the order of flags must not change what they mean"
        );
    }

    #[test]
    fn a_tunnel_option_without_a_tunnel_is_refused_rather_than_ignored() {
        // Ignoring it would leave the console talking to a local daemon while the
        // operator believed they were looking at a server.
        for flags in [
            vec!["--local-port", "9292"],
            vec!["--remote-port", "9292"],
            vec!["--identity", "/key"],
            vec!["--ssh-port", "2222"],
        ] {
            let error = parse(&flags).expect_err("should refuse");
            assert!(error.contains("--ssh"), "{error}");
        }
    }

    #[test]
    fn a_server_that_looks_like_an_option_is_refused() {
        let error = parse(&["--ssh", "-oProxyCommand=evil"]).expect_err("should refuse");
        assert!(error.contains("user@host"), "{error}");
    }

    #[test]
    fn a_port_of_zero_is_refused_because_it_names_no_port_to_connect_to() {
        assert!(parse(&["--ssh", "s", "--local-port", "0"]).is_err());
        assert!(parse(&["--ssh", "s", "--ssh-port", "70000"]).is_err());
    }

    #[test]
    fn a_token_file_given_by_hand_is_used_instead_of_reading_one_over_ssh() {
        let options = parse(&["--ssh", "server", "--token-file", "/tmp/t"]).expect("valid");
        assert_eq!(options.token_path, Some(PathBuf::from("/tmp/t")));
    }

    #[test]
    fn every_tunnel_option_needs_its_value() {
        for flag in ["--ssh", "--ssh-port", "--identity", "--local-port", "--remote-port", "--remote-token"] {
            assert!(parse(&[flag]).is_err(), "{flag} was accepted with no value");
        }
    }
}
