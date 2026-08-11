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
//!
//! # Which machine, and changing it
//!
//! Typing that at a terminal is the *first* pairing and nothing else. A machine
//! is paired once and remembered, a launch with no arguments opens the one used
//! last — which is what an application icon produces — and the window changes
//! machines without being restarted, from the overview the masthead steps back
//! to. What this file does is read the command line and open the first machine;
//! [`session`] is where a connection lives and how it is exchanged for another,
//! and [`view::machines`] is the place the operator does it from.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod channel;
mod client;
mod machines;
mod nas;
mod poller;
mod registry;
mod remote;
mod session;
mod state;
mod tunnel;
mod view;

use session::{Bound, Credential, Target};
use std::net::SocketAddr;
use std::path::PathBuf;
use tunnel::TunnelSpec;
use view::Console;

/// Where the daemon listens unless told otherwise.
const DEFAULT_ADDRESS: &str = "127.0.0.1:9191";

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

    let store_path = machines::default_path();
    if options.list {
        return list_machines(store_path.as_deref());
    }
    if let Some(name) = &options.forget {
        return forget_machine(store_path.as_deref(), name);
    }

    // Which machine this launch is for, decided before anything connects. An
    // explicit flag always wins; with no connection flag at all the console
    // opens the machine it was last on, which is the whole point — a launch from
    // the Dock carries no arguments and used to mean "look for a local daemon",
    // which on a workstation means "fail".
    let chosen = choose_machine(&options, store_path.as_deref())?;

    // A launch that names a connection outright reads its token before the
    // window opens, because that failure belongs on the terminal `--ssh` was
    // typed at: the fix — a key to add, a host to accept — is a command to run
    // there. A launch that named nothing has no terminal to report to, so its
    // token is read by the poller and a refusal reaches the window instead.
    // That distinction is the Dock: an icon click used to fail here, before any
    // window existed, and looked like an application that does nothing at all.
    let held = match (&options.ssh, &options.token_path) {
        (Some(spec), None) => Some(tunnel::fetch_token(spec, &options.remote_token)?),
        _ => None,
    };

    // Saved only now, on the far side of a token that actually arrived: a
    // pairing is a connection that has worked at least once, so a bad key or a
    // wrong address leaves the store as it was rather than adding an entry the
    // operator would have to discover was useless.
    if let Some(name) = &options.pair {
        pair_machine(store_path.as_deref(), name, &options)?;
    }

    let options = match &chosen {
        Some(machine) => options.bound_to(machine),
        None => options,
    };
    let bound = match &chosen {
        Some(machine) => Bound::of(machine),
        None => Bound::new(
            options.address(),
            options.ssh.as_ref().map(|spec| spec.destination.clone()),
        ),
    };
    let target = Target::new(options.address(), options.credential());
    let target = match held {
        Some(token) => target.holding(token),
        None => target,
    };

    let title = bound.title();
    let mut console = Console::paired(load_machines(store_path.as_deref()), store_path);
    console.open(bound, target, options.ssh.clone());
    console.run(title).map_err(|error| error.to_string())
}

/// Reads the paired-machine store, or an empty one on a machine with no home.
///
/// A store that cannot be located is not an error: the console still runs, it
/// simply cannot remember anything, which is exactly what it did before there
/// was a store at all.
fn load_machines(path: Option<&std::path::Path>) -> machines::Machines {
    path.and_then(|path| machines::Machines::load(path).ok()).unwrap_or_default()
}

/// Which machine this launch is for.
///
/// The order is the decision. `--ssh` describes a connection outright and wins.
/// `--machine` names one already paired. `--token-file` and `--daemon` say the
/// operator means a specific local daemon, so neither is overridden. Only a
/// launch that asked for nothing falls through to the machine opened last —
/// which is the launch an application icon produces.
fn choose_machine(
    options: &Options,
    store: Option<&std::path::Path>,
) -> Result<Option<machines::Machine>, String> {
    if options.ssh.is_some() {
        return Ok(None);
    }
    let paired = load_machines(store);
    if let Some(name) = &options.machine {
        return paired.get(name).cloned().map(Some).ok_or_else(|| {
            format!(
                "no machine named {name:?} is paired here. Pair one with:\n  \
                 selfhost-console --pair {name} --ssh <[user@]host>\n\n\
                 Paired now: {}",
                named(&paired)
            )
        });
    }
    if options.token_path.is_some() || options.address != default_address() {
        return Ok(None);
    }
    Ok(paired.opening().cloned())
}

/// The names of every paired machine, for a message that has to list them.
fn named(paired: &machines::Machines) -> String {
    if paired.is_empty() {
        return "nothing".into();
    }
    paired.entries().iter().map(|machine| machine.name.as_str()).collect::<Vec<_>>().join(", ")
}

/// The address the console talks to when nothing said otherwise.
fn default_address() -> SocketAddr {
    DEFAULT_ADDRESS.parse().expect("the default address is valid")
}

/// Saves a pairing that has just been proved to work.
fn pair_machine(
    store: Option<&std::path::Path>,
    name: &str,
    options: &Options,
) -> Result<(), String> {
    let path = store.ok_or("this account has no home directory, so nothing can be paired")?;
    let spec = options.ssh.as_ref().expect("--pair is refused without --ssh");
    let mut machine = machines::Machine::new(name, spec.destination.clone());
    machine.ssh_port = spec.ssh_port;
    machine.identity = spec.identity.clone();
    machine.port = spec.remote_port;
    machine.remote_token = options.remote_token.clone();

    let problems = machine.problems();
    if !problems.is_empty() {
        return Err(format!("cannot pair this machine:\n  {}", problems.join("\n  ")));
    }

    let mut paired = machines::Machines::load(path)?;
    paired.pair(machine);
    paired.opened(name);
    paired.save(path)?;
    eprintln!("selfhost-console: paired {name:?} — it opens by default from now on");
    Ok(())
}

/// Prints what is paired, and which one opens by default.
fn list_machines(store: Option<&std::path::Path>) -> Result<(), String> {
    let paired = load_machines(store);
    if paired.is_empty() {
        println!("No machines are paired yet. Pair one with:");
        println!("  selfhost-console --pair <name> --ssh <[user@]host>");
        return Ok(());
    }
    let opening = paired.opening().map(|machine| machine.name.clone());
    for machine in paired.entries() {
        let mark = if Some(&machine.name) == opening.as_ref() { "→" } else { " " };
        println!("{mark} {:<20} {}", machine.name, machine.destination);
        if let Some(identity) = &machine.identity {
            println!("    key    {}", identity.display());
        }
        println!("    port   {}", machine.port);
        println!("    token  {}", machine.remote_token);
    }
    Ok(())
}

/// Removes a pairing.
fn forget_machine(store: Option<&std::path::Path>, name: &str) -> Result<(), String> {
    let path = store.ok_or("this account has no home directory, so nothing is paired")?;
    let mut paired = machines::Machines::load(path)?;
    if paired.get(name).is_none() {
        return Err(format!("no machine named {name:?} is paired. Paired now: {}", named(&paired)));
    }
    paired.forget(name);
    paired.save(path)?;
    println!("Forgot {name:?}.");
    Ok(())
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
    /// Save the connection these flags describe under this name, once it has
    /// been proved to work, and open it.
    pair: Option<String>,
    /// Open this already-paired machine.
    machine: Option<String>,
    /// Remove this pairing and exit.
    forget: Option<String>,
    /// List what is paired and exit.
    list: bool,
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
            pair: None,
            machine: None,
            forget: None,
            list: false,
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
                "--pair" => options.pair = Some(value("--pair")?),
                "--machine" => options.machine = Some(value("--machine")?),
                "--forget" => options.forget = Some(value("--forget")?),
                "--machines" => options.list = true,
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

        // Pairing saves the connection the other flags describe, so there has to
        // be one. Without this the operator gets a pairing named after a local
        // daemon, which cannot be opened from anywhere else and is the one entry
        // this store must never hold.
        if options.pair.is_some() && options.ssh.is_none() {
            return Err(
                "--pair names the connection --ssh describes, so it needs one:\n  \
                 selfhost-console --pair <name> --ssh <[user@]host>"
                    .into(),
            );
        }
        if options.machine.is_some() && options.ssh.is_some() {
            return Err("--machine opens a paired machine; --ssh describes a new one".into());
        }

        Ok(options)
    }

    /// These options, pointed at a paired machine.
    ///
    /// Separate from parsing because the store is consulted only after the
    /// command line has been read: a flag always wins over a remembered machine,
    /// and expressing that as "parse, then bind what was not stated" keeps the
    /// precedence in one readable place instead of spread through the parser.
    fn bound_to(mut self, machine: &machines::Machine) -> Self {
        self.ssh = Some(machine.tunnel());
        self.remote_token = machine.remote_token.clone();
        self
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

    /// Where this launch's bearer token comes from.
    ///
    /// A token file named by hand wins over reading one over SSH, because
    /// naming one is an instruction and the tunnel is only a route. With
    /// neither, the console looks where a daemon on this machine would have
    /// written one — and keeps looking, poll after poll, so a console opened
    /// before its daemon connects when the daemon starts.
    fn credential(&self) -> Credential {
        match (&self.token_path, &self.ssh) {
            (Some(path), _) => Credential::File(path.clone()),
            (None, Some(spec)) => Credential::OverSsh {
                spec: spec.clone(),
                path: self.remote_token.clone(),
                pair: None,
            },
            (None, None) => Credential::Discovered,
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
  selfhost-console                            Open the machine you were last on
  selfhost-console --machine <name>           Open a paired machine
  selfhost-console --pair <name> --ssh <host> Pair a machine, then open it
  selfhost-console [--daemon <address|port>] [--token-file <path>]
  selfhost-console --ssh <[user@]host> [tunnel options]

Paired machines:
  Opened with no arguments — which is what an application icon does — the
  console opens the machine it was on last. Machines are paired once and kept
  in the platform's state directory; the file holds a destination, a port and
  the path of a key, never a token and never key material.

  None of this has to be typed. The masthead's MACHINES control steps back to
  the list of paired machines, where one is opened, forgotten, or added — the
  window changes machines without being restarted. These flags are the same
  operations from a terminal, and for the first pairing on a headless setup.

  --pair <name>          Save the connection the other flags describe under this
                         name, once it has been proved to work, and open it.
                         A pairing that cannot read the daemon's token over that
                         connection is refused rather than saved.
  --machine <name>       Open a machine already paired.
  --machines             List what is paired, marking the one that opens.
  --forget <name>        Remove a pairing.

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

    /// A store holding one machine, written where a test may write.
    fn stored(machine: machines::Machine) -> (PathBuf, machines::Machines) {
        let directory = std::env::temp_dir()
            .join(format!("selfhost-console-choose-{}-{:?}", std::process::id(), machine.name));
        let path = directory.join("machines");
        let mut paired = machines::Machines::default();
        let name = machine.name.clone();
        paired.pair(machine);
        paired.opened(&name);
        paired.save(&path).expect("the store saves");
        (path, paired)
    }

    #[test]
    fn a_launch_with_no_arguments_opens_the_machine_last_used() {
        let (path, _) = stored(machines::Machine::new("desk", "alex@10.0.0.4"));
        let options = parse(&[]).expect("no arguments is valid");
        let chosen = choose_machine(&options, Some(&path)).expect("a stored machine is found");
        assert_eq!(chosen.map(|machine| machine.destination), Some("alex@10.0.0.4".into()));
        let _ = std::fs::remove_dir_all(path.parent().expect("a parent"));
    }

    #[test]
    fn an_explicit_ssh_destination_wins_over_the_remembered_machine() {
        let (path, _) = stored(machines::Machine::new("winner", "alex@10.0.0.5"));
        let options = parse(&["--ssh", "someone@elsewhere"]).expect("valid");
        assert!(
            choose_machine(&options, Some(&path)).expect("no lookup happens").is_none(),
            "the store overrode an explicit --ssh"
        );
        let _ = std::fs::remove_dir_all(path.parent().expect("a parent"));
    }

    #[test]
    fn asking_for_a_local_daemon_is_not_overridden_by_a_remembered_machine() {
        let (path, _) = stored(machines::Machine::new("elsewhere", "alex@10.0.0.6"));
        for arguments in [vec!["--token-file", "/tmp/t"], vec!["--daemon", "9292"]] {
            let options = parse(&arguments).expect("valid");
            assert!(
                choose_machine(&options, Some(&path)).expect("no lookup").is_none(),
                "{arguments:?} was overridden by the store"
            );
        }
        let _ = std::fs::remove_dir_all(path.parent().expect("a parent"));
    }

    #[test]
    fn opening_a_machine_that_is_not_paired_says_what_is() {
        let (path, _) = stored(machines::Machine::new("real", "alex@10.0.0.7"));
        let options = parse(&["--machine", "imaginary"]).expect("valid");
        let complaint = choose_machine(&options, Some(&path)).expect_err("no such machine");
        assert!(complaint.contains("imaginary"), "{complaint}");
        assert!(complaint.contains("real"), "the message did not list what is paired: {complaint}");
        let _ = std::fs::remove_dir_all(path.parent().expect("a parent"));
    }

    #[test]
    fn a_paired_machine_becomes_the_tunnel_this_launch_uses() {
        let mut machine = machines::Machine::new("desk", "alex@10.0.0.8");
        machine.port = 9292;
        machine.remote_token = "somewhere/else.token".into();
        let options = parse(&[]).expect("valid").bound_to(&machine);
        let spec = options.ssh.as_ref().expect("a tunnel");
        assert_eq!(spec.destination, "alex@10.0.0.8");
        assert_eq!(options.address(), spec.local_address());
        assert_eq!(options.remote_token, "somewhere/else.token");
    }

    #[test]
    fn pairing_without_a_connection_to_pair_is_refused() {
        let complaint = parse(&["--pair", "desk"]).expect_err("--pair needs --ssh");
        assert!(complaint.contains("--ssh"), "{complaint}");
    }

    #[test]
    fn opening_a_paired_machine_and_describing_a_new_one_are_different_requests() {
        assert!(parse(&["--machine", "desk", "--ssh", "host"]).is_err());
    }

    #[test]
    fn the_usage_names_the_paired_machine_flags() {
        for flag in ["--pair", "--machine", "--machines", "--forget"] {
            assert!(USAGE.contains(flag), "{flag} is not in the usage text");
        }
    }
}
