//! The `selfhost` command-line interface.
//!
//! Argument parsing and error presentation only. The work lives in the library
//! crates so it stays callable from tests without going through `argv`.

mod acme_task;
mod assess;
mod audit;
mod data_dir;
mod desk_agent;
mod desk_local;
mod desk_supervisor;
mod desk_task;
mod dns_status;
mod doctor;
mod hairpin;
mod identify;
mod outside;
mod kill_switch;
mod investigate;
mod lan_dns;
mod mail_task;
mod mesh_task;
mod node_command;
mod oui;
mod people_command;
mod proxyware;
mod self_update;
mod reports_command;
mod service_install;
mod share_command;
mod site;
mod storage_command;
mod teardown;
mod watch;

use selfhost_admin::{Api, Fleet, Store, Token};
use selfhost_config::{AcmeEnvironment, Config};
use selfhost_dns::Resolver;
use selfhost_dns::authority::{Authority, DnsError};
use selfhost_supervisor::Supervisor;
use selfhost_proxy::{
    CertificateStore, Server, SniResolver, serve_http, serve_https, server_config_with_resolver,
};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

/// How often the daemon re-checks the host firewall for drift.
///
/// The firewall changes rarely and only from outside this daemon — a manual
/// `pfctl -F`, a reboot that cleared an ephemeral table, some other tool
/// rewriting the ruleset. A slow poll notices and re-asserts without adding
/// meaningful load; the authoritative apply already happened at startup.
const FIREWALL_DRIFT_INTERVAL: Duration = Duration::from_secs(300);

/// Name of the config file, looked for in the current directory and its parents.
const CONFIG_FILENAME: &str = "selfhost.config.toml";

const USAGE: &str = "\
selfhost — host websites, databases, and mail from your own hardware

Usage
  selfhost <command> [options]

Commands
  init [--email <address>]   Write a starter config into the current directory
  check                      Validate the config and report every problem
  routes                     Show which hostname maps to which site
  site <list|show|add|remove|add-domain|remove-domain>
                             List, inspect, add, or unroute a website; add or
                             remove one hostname on an existing one, which is
                             what a subdomain is

  doctor [--deep] [--scan-lan]
                             Diagnose, and chase the cause of anything broken
  watch-dns [--bind <addr>] [--upstream <addr>]
                             Answer DNS for the network and name the device
                             asking for a residential proxy service
  dns                        Show the zone this machine serves and whether it
                             is answering on port 53
  serve-dns [--bind <addr>]  Serve authoritative DNS for the configured zones in
                             the foreground (the daemon serves them too)
  lan-dns --lan-ip <ip> [--bind <addr>]
                             Serve split-horizon DNS for the LAN: configured
                             site domains answer with this machine's LAN
                             address, everything else forwards upstream
  daemon [--bind <addr>]     Run the whole deployment in the foreground:
                             websites, mail, DNS, the supervised services and
                             the control API, in one process. This is what the
                             installed service starts.
  run                        The same thing. Kept as an alias so an existing
                             service definition keeps working; do not run both
                             at once, they would each try to bind :443
  outside                    Ask the internet what it can actually reach here.
                             Nothing on this network can answer that, so each
                             check makes a third party originate the connection:
                             public resolvers witness port 53 live, and the
                             certificate on disk is a dated receipt for 80/443.
                             Ports nothing will witness are said to be
                             unwitnessed rather than guessed at
  hairpin [--client] [--apply] [--undo] [--public <ip>] [--lan <ip>]
                             Make this deployment's public address reachable
                             from inside its own network, for routers that do
                             not hairpin: a /32 loopback alias on the box and a
                             host route on each client. Lets a mail client or a
                             browser here exercise the real public address, DNS,
                             SNI and certificate. Dry-run by default; only
                             --apply changes the machine
  services                   List the installed services and what they are doing
  share <list|usage|ls>      The shares this box serves, what each one holds,
                             and what is inside one
  sync push <local-path> <share>:<path> [--apply]
  sync pull <share>:<path> <local-path> [--apply]
                             Copy files into or out of a share, through the same
                             rules the console and WebDAV write under. Dry-run by
                             default; only --apply writes.
  storage smb <plan|apply>   Reconcile the operating system's own SMB exports with
                             the [shares.smb] blocks in the config: read what the
                             host exports, diff, and print the plan. Dry-run by
                             default; only `apply` changes the machine, and it
                             never touches a share point selfhost did not create.
  storage discover [--host <label>] [--model <name>] [--address <ip>]
                             What a laptop on this network would see for the
                             browsable shares — the DNS-SD registrations and
                             records — and, honestly, whether anything on this
                             platform will publish them
  node <list|invite|join>    The machines this deployment can reach.
                             `invite <name>` mints a worker's enrolment token on
                             the owner and prints it once; `join` stores it on
                             the worker, reading it from stdin — never from an
                             argument, which would land in shell history and ps
  desktop <status|disable|enable>
                             Whether remote desktop is on and what it can see.
                             `disable` writes <data_dir>/desktop.disabled, which
                             closes every stream and refuses new ones within
                             seconds — the switch to reach for when something is
                             wrong and the console cannot be trusted.
  teardown [--everything] [--yes]
                             Stop, uninstall, and remove what the daemon created
  service <install|uninstall|status> [--system] [--yes]
                             Register this daemon with the OS service manager
                             (launchd, systemd, or a Windows scheduled task) so it
                             starts on boot and restarts if it dies
  reports <serve|projects|list|close|token>
                             The public report intake: agents anywhere POST a
                             defect, this box stores it and mails it to the
                             owner, and a subscribed checkout folds the project's
                             open reports into its own reports.dx. `serve` is
                             what the supervised service runs.
  reports project add <key>  Hold reports for a service ahead of time, e.g. `dx`
                             — filing to /report?<service> creates one anyway
  mail hash-password [<password>]
                             Hash a mailbox password for [[mail.mailboxes]] in
                             selfhost.config.toml; reads from stdin if omitted
  mail add <address> [<password>]
                             Add a mailbox; reads the password from stdin if
                             omitted. [mail] must already be configured.
  mail remove <address>      Remove a mailbox
  people <list|show|grant|allow|deny|forget|capabilities>
                             Who else may use this deployment, and exactly what
                             each of them may do. `allow <name> <cap>[,<cap>]`
                             creates an entry and adds to it; `grant` states the
                             whole set at once; `capabilities` lists every word.
                             The owner is never in this list — the owner's
                             authority is an identity, not a grant, so nothing
                             here can edit it away.
  people invite <name> [<cap>,<cap>] [--hours N]
                             Grant, then mint a one-time link that lets them
                             register their own passkey under that name — with
                             nobody present but them. The code is shown once and
                             is not stored anywhere it can be read back.
                             `invited` lists what is pending; `uninvite <name>`
                             withdraws an invitation nobody has used.
  console-password [<password>]
                             Set the web console's login password; reads it
                             twice from stdin if omitted
  help                       Show this message

Config lives in selfhost.config.toml. Everything else is derived from it.
";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let command = arguments.first().map(String::as_str).unwrap_or("help");

    let result = match command {
        "init" => init(&arguments),
        "check" => check(),
        "routes" => routes(),
        "site" => find_config().and_then(|path| site::run(&arguments, &path)),
        "doctor" => doctor_command(&arguments),
        "watch-dns" => watch_command(&arguments),
        "dns" => dns_command(&arguments),
        "serve-dns" => serve_dns_command(&arguments),
        "lan-dns" => lan_dns_command(&arguments),
        "run" => run(),
        "daemon" => daemon_command(&arguments),
        "outside" => outside_command(),
        "hairpin" => hairpin_command(&arguments),
        "services" => services_command(),
        "share" => load().and_then(|(config, dir)| share_command::share(&arguments, &config, &dir)),
        "sync" => load().and_then(|(config, dir)| share_command::sync(&arguments, &config, &dir)),
        "storage" => {
            load().and_then(|(config, dir)| storage_command::storage(&arguments, &config, &dir))
        }
        "node" => load().and_then(|(config, project_dir)| {
            let data_dir = teardown::data_dir(&config, &project_dir);
            node_command::run(&arguments, &config, &data_dir)
        }),
        "desktop" => desktop_command(&arguments),
        // Deliberately absent from USAGE: the daemon spawns this into the
        // console session, and there is nothing an operator can do with it.
        // See [`desk_agent`] for what stops it working when run by hand.
        // The one command whose exit code is *read by another program*, so it
        // does not go through the uniform success/failure below: the daemon's
        // supervisor is the only thing that ever sees this process end, and on
        // the machine this ships to there is no console, no log and no pipe yet
        // for it to say anything else on. See `selfhost_screen::Departure`.
        "desk-agent" => {
            let (departure, result) = desk_agent::depart(&arguments);
            if let Err(message) = result {
                eprintln!("\n✗ {message}");
            }
            return ExitCode::from(departure.code());
        }
        "teardown" => teardown_command(&arguments),
        "service" => service_command(&arguments),
        "reports" => load().and_then(|(config, project_dir)| {
            reports_command::run(&arguments, &config, &project_dir)
        }),
        "people" => load().and_then(|(config, project_dir)| {
            let data_dir = teardown::data_dir(&config, &project_dir);
            people_command::run(&arguments, &data_dir, &config)
        }),
        "mail" => mail_command(&arguments),
        "console-password" => console_password_command(&arguments),
        "help" | "--help" | "-h" => {
            eprint!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command \"{other}\"\n\n{USAGE}")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("\n✗ {message}");
            ExitCode::FAILURE
        }
    }
}

/// Walks up from the current directory looking for the config file.
fn find_config() -> Result<PathBuf, String> {
    let mut directory = std::env::current_dir().map_err(|e| e.to_string())?;
    loop {
        let candidate = directory.join(CONFIG_FILENAME);
        if candidate.is_file() {
            return Ok(candidate);
        }
        if !directory.pop() {
            return Err(format!(
                "no {CONFIG_FILENAME} found here or in any parent directory.\n  \
                 Run `selfhost init` to create one."
            ));
        }
    }
}

/// Loads and validates the config, returning it with its project directory.
fn load() -> Result<(Config, PathBuf), String> {
    let path = find_config()?;
    let config = Config::load(&path).map_err(|e| e.to_string())?;
    let project_dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    Ok((config, project_dir))
}

/// Writes a starter config and a page for it to serve.
fn init(arguments: &[String]) -> Result<(), String> {
    let email = arguments
        .iter()
        .position(|a| a == "--email" || a == "-e")
        .and_then(|i| arguments.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "you@example.com".to_owned());

    let path = PathBuf::from(CONFIG_FILENAME);
    if path.exists() {
        return Err(format!("{CONFIG_FILENAME} already exists here"));
    }

    // The two opt-in subsystems are emitted commented out, from the config
    // crate's own live examples rather than a copy: `commented` prefixes every
    // line, so the block a reader uncomments is byte-for-byte the block that
    // crate's tests parse. A copy here would be a second version of the truth,
    // and it would rot the first time a key was renamed.
    //
    // The kill switch is named in the desktop block deliberately. An operator
    // learns about `data/desktop.disabled` at the moment they decide to turn
    // remote desktop on — not while looking for it in an emergency.
    let desktop = format!(
        "{}#\n# The switch that turns this off without the console, and without a restart:\n\
         #   touch <data_dir>/desktop.disabled     (or: selfhost desktop disable)\n\
         # Its presence closes every stream within seconds and refuses new ones.\n",
        selfhost_config::commented(selfhost_config::desktop::EXAMPLE)
    );
    let shares = selfhost_config::commented(selfhost_config::storage::EXAMPLE);

    // Defaults are chosen so a first run cannot publish anything or burn a
    // certificate rate limit: loopback binds, self-signed certificates.
    let starter = format!(
        r#"# selfhost — one file describes the whole deployment.
version = 1

[server]
# Bound to loopback until you decide to publish. Change to 0.0.0.0 once the
# router forwards 80 and 443 to this machine.
http_bind = "127.0.0.1:8080"
https_bind = "127.0.0.1:8443"
acme_email = "{email}"
# "self-signed" needs no network and has no rate limit. Move to "staging" once
# DNS points here, and only then to "production" — production allows five
# duplicate certificates per week and a retry loop exhausts that in minutes.
acme = "self-signed"
data_dir = "./data"

# Exactly one node is the owner. It holds every stateful service, because two
# machines each with their own database is two websites, not one.
[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "hello"
domains = ["localhost"]
static_root = "./sites/hello"
spa = false

# Uncomment to let a push to your repository update selfhost itself: fetch,
# rebuild, restart. Needs this directory to be a clone of that repository.
#
# Set webhook_secret and add the same value to the repository's webhook
# (pointed at https://<a site this box serves>/.selfhost/webhook/self) to deploy
# within seconds of a push. Without it the branch is still checked on the timer
# below — a webhook makes a check happen sooner, it never replaces one.
# [self_update]
# repository = "https://github.com/you/selfhost.git"
# branch = "main"
# webhook_secret = "<a long random string, kept only in this file>"

{desktop}
{shares}"#
    );

    std::fs::write(&path, starter).map_err(|e| e.to_string())?;
    println!("• {CONFIG_FILENAME}");

    let page_dir = PathBuf::from("sites/hello");
    std::fs::create_dir_all(&page_dir).map_err(|e| e.to_string())?;
    std::fs::write(
        page_dir.join("index.html"),
        b"<!doctype html><meta charset=\"utf-8\"><title>selfhost is running</title>\
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:34rem;margin:4rem auto;padding:0 1.5rem}\
code{background:#f4f4f5;padding:.15em .4em;border-radius:4px}</style>\
<h1>selfhost is running</h1><p>Served from your own machine, by your own code.</p>\
<p>Edit <code>selfhost.config.toml</code>, then run <code>selfhost run</code>.</p>\n"
            .as_slice(),
    )
    .map_err(|e| e.to_string())?;
    println!("• sites/hello/index.html");

    println!("\n✓ initialised — run `selfhost run`");
    Ok(())
}

/// Validates the config without starting anything.
fn check() -> Result<(), String> {
    let (config, project_dir) = load()?;
    println!("✓ {CONFIG_FILENAME} is valid — {config}");

    // Validation proves the config is coherent; it cannot know whether the
    // directories it names exist, so that is reported separately as a warning.
    for site in &config.sites {
        if let Some(root) = &site.static_root {
            let resolved = project_dir.join(root);
            if !resolved.is_dir() {
                println!("  ! site \"{}\": static_root {} does not exist", site.name, resolved.display());
            }
        }
    }
    Ok(())
}

/// Prints the hostname-to-site routing table.
fn routes() -> Result<(), String> {
    let (config, _) = load()?;
    let map = config.host_map();
    if map.is_empty() {
        println!("no sites configured");
        return Ok(());
    }

    let width = map.keys().map(String::len).max().unwrap_or(0);
    for (host, site) in map {
        let target = match (&site.static_root, site.instances.len()) {
            (Some(root), 0) => format!("static {}", root.display()),
            (Some(root), n) => format!("static {} + {n} instance(s)", root.display()),
            (None, n) => format!("{n} instance(s)"),
        };
        println!("  {host:<width$}  →  {target}");
    }
    Ok(())
}

/// Runs the diagnostics and reports what to fix.
///
/// Exits non-zero when something failed, so it is usable in a script.
fn doctor_command(arguments: &[String]) -> Result<(), String> {
    let (config, project_dir) = load()?;
    let deep = arguments.iter().any(|a| a == "--deep");
    let scan_lan = arguments.iter().any(|a| a == "--scan-lan");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    let report = runtime.block_on(doctor::run(&config, &project_dir, deep, scan_lan));
    print!("{report}");

    if report.has_failures() {
        return Err("some checks failed — see the arrows above for what to do".into());
    }
    Ok(())
}

/// The value following a named option, if it was given.
fn value_of(arguments: &[String], name: &str) -> Option<String> {
    arguments.iter().position(|argument| argument == name).and_then(|at| arguments.get(at + 1)).cloned()
}

/// Watches the network's DNS to find the device behind a compromised-host listing.
///
/// Needs no config: this diagnoses the network rather than the deployment, and
/// requiring a config file would stop it running on the machine that happens to
/// be handy.
fn watch_command(arguments: &[String]) -> Result<(), String> {
    let bind: SocketAddr = match value_of(arguments, "--bind") {
        Some(given) => given.parse().map_err(|e| format!("--bind {given}: {e}"))?,
        None => "0.0.0.0:53".parse().expect("literal bind address"),
    };
    let upstream: SocketAddr = match value_of(arguments, "--upstream") {
        Some(given) => given.parse().map_err(|e| format!("--upstream {given}: {e}"))?,
        None => Resolver::system().address(),
    };

    // Forwarding to ourselves would answer every question with the question.
    if upstream.port() == bind.port()
        && (upstream.ip() == bind.ip() || Some(upstream.ip()) == investigate::local_address().map(Into::into))
    {
        return Err(format!(
            "--upstream {upstream} is this machine, so every query would be forwarded back here.\n  \
             Pass the address of a resolver outside this network, for example:\n  \
             selfhost watch-dns --upstream 1.1.1.1:53"
        ));
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    runtime.block_on(watch_dns(bind, upstream))
}

/// Serves DNS until interrupted, then reports what was seen.
async fn watch_dns(bind: SocketAddr, upstream: SocketAddr) -> Result<(), String> {
    let watch = Arc::new(Mutex::new(watch::Watch::default()));
    let here = investigate::local_address()
        .map(|address| address.to_string())
        .unwrap_or_else(|| "this machine's LAN address".to_owned());

    println!("Watching DNS on {bind}, forwarding to {upstream}.\n");
    println!("Nothing is blocked or rewritten — every query goes upstream unchanged.\n");
    println!("For this to see anything, the devices have to ask *here*:");
    println!("  1. In the router, set the DHCP DNS server to {here}.");
    println!("  2. Reboot the devices, or wait for their leases to renew.");
    println!("  3. Optionally block outbound 53 and 853 for every device except this one,");
    println!("     which closes the gap for firmware with a hardcoded resolver.\n");
    println!("Leave this running. Ctrl-C prints the conclusion.\n");

    let started = Instant::now();
    let serving = watch::serve(bind, upstream, Arc::clone(&watch));

    let outcome = tokio::select! {
        result = serving => result.map_err(|error| match error.kind() {
            std::io::ErrorKind::PermissionDenied => format!(
                "cannot bind {bind}: port 53 needs privilege.\n  \
                 Run it with sudo, or on Linux grant the capability once:\n  \
                 sudo setcap 'cap_net_bind_service=+ep' ./target/release/selfhost"
            ),
            std::io::ErrorKind::AddrInUse => format!(
                "cannot bind {bind}: something already answers DNS on this machine.\n  \
                 On macOS that is usually a VPN client or Internet Sharing."
            ),
            _ => format!("DNS watch stopped: {error}"),
        }),
        _ = tokio::signal::ctrl_c() => Ok(()),
    };

    let elapsed = started.elapsed();
    let report = watch.lock().expect("the watch mutex is never held across a panic").report();
    println!("\n─── after {} minute(s) ───\n\n{report}", elapsed.as_secs() / 60);

    outcome
}

/// Runs the whole deployment: websites, mail, DNS, services, and the control
/// API, in one process.
///
/// This and `run` are the same command now. They used to be two processes and
/// two installed OS services — `run` served websites, `daemon` ran services —
/// and that split had no upside and three costs: the box could come up half
/// working with no single thing to look at, an update had to be choreographed
/// across two independently-restarting units, and each was capable of
/// outliving the other. `run` is kept as an alias so an existing installation
/// keeps starting while its service definition is replaced.
fn daemon_command(arguments: &[String]) -> Result<(), String> {
    let (config, project_dir) = load()?;
    let config_path = project_dir.join(CONFIG_FILENAME);
    let bind = value_of(arguments, "--bind").unwrap_or_else(|| config.server.admin_bind.clone());
    let address: SocketAddr = bind.parse().map_err(|e| format!("--bind {bind}: {e}"))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    runtime.block_on(serve_everything(config, project_dir, config_path, address))
}

/// Brings up every subsystem this deployment is configured for, and serves
/// until something stops it.
///
/// # One process, deliberately
///
/// Every listener, every watcher and every supervised child lives here. That
/// buys three things a two-process split could not:
///
/// - **One boot.** The machine starts one service and everything the config
///   asks for comes up with it, in a known order. There is no arrangement in
///   which the proxy is answering and the services behind it were never
///   started.
/// - **One restart.** A self-update exits this process, so *everything*
///   restarts onto the new build together. The old split had the daemon build
///   the binary and the proxy notice the file had changed and exit separately,
///   which meant a window where two halves of the deployment were running
///   different code.
/// - **Children do not outlive it.** Supervised children are owned by a job
///   object on Windows and a process group on Unix, and both a clean shutdown
///   and an outright kill are covered on the platform this deploys to. The
///   exact per-platform guarantee — and the one case that is *not* covered, a
///   `kill -9` on macOS — is set out in [`selfhost_supervisor::child`] rather
///   than summarised optimistically here.
///
/// The cost is stated rather than hidden: a fatal error in any subsystem stops
/// all of them. That is the intended trade. A box that is half up looks healthy
/// to everything that only checks one half, and the failure this is most likely
/// to prevent — DNS silently not being served while the websites are fine — is
/// exactly the kind that goes unnoticed for days.
async fn serve_everything(
    config: Config,
    project_dir: PathBuf,
    config_path: PathBuf,
    address: SocketAddr,
) -> Result<(), String> {
    // Before any rustls configuration is built, by any subsystem: the proxy,
    // the mail server and the ACME client all construct one, and the provider
    // is process-wide.
    let _ = rustls::crypto::ring::default_provider().install_default();


    let data_dir = project_dir.join(&config.server.data_dir);
    // Created before anything reads or writes in it, and created so that only
    // this account can: the bearer token minted a few lines below, the console
    // password hash and the passkey registry all live here, and a directory
    // that inherits its permissions is a directory that hands them to whoever
    // else has an account on the box. See [`data_dir`] for what each platform
    // can actually enforce.
    let prepared = crate::data_dir::prepare(&data_dir)
        .map_err(|e| format!("cannot create {}: {e}", data_dir.display()))?;
    for note in prepared.notes(&data_dir) {
        eprintln!("{note}");
    }

    let store = Store::new(&data_dir);
    let node_names: Vec<&str> = config.nodes.iter().map(|n| n.name.as_str()).collect();
    let catalog = store.load(&node_names).map_err(|e| e.to_string())?;

    let token = Token::load_or_create(&data_dir).map_err(|e| e.to_string())?;
    let supervisor = Supervisor::new(&project_dir);

    let listener = selfhost_admin::bind(address).await.map_err(|e| e.to_string())?;

    println!("selfhost daemon");
    println!("  control api  http://{address}");
    println!("  token        {}", Token::path_in(&data_dir).display());
    println!("  catalogue    {}", store.path().display());
    if catalog.services.is_empty() {
        println!("\nNo services installed yet. Install one from the console, or add it to");
        println!("{}.", store.path().display());
    } else {
        println!("\n{} service(s):", catalog.services.len());
        for spec in &catalog.services {
            println!("  {:<20} {}", spec.name, spec.program.display());
        }
    }
    println!("\nReach this from another machine by tunnelling, never by binding publicly:");
    println!("  ssh -L {0}:127.0.0.1:{0} <this-host>", address.port());
    println!("\nCtrl-C to stop.");

    // So a console opened from the Dock can find this daemon. An application
    // launched by the Finder has no working directory to resolve `data/` against
    // — see `selfhost_config::home`. A failure here costs that convenience and
    // nothing else, so it is reported and not fatal.
    if let Err(error) = selfhost_config::home::record(&project_dir) {
        eprintln!(
            "warning: could not record where this daemon is running ({error}); a console \
             opened from the Dock will need --token-file"
        );
    }

    supervisor.load(&catalog).await;

    // Stated rather than assumed: a branch that is silently not being watched
    // looks exactly like one that has not been pushed to.
    let watches = selfhost_git::Watches::default();
    match watches.load(&supervisor, &catalog).await {
        0 => {}
        1 => println!("\nwatching 1 git branch for deployments"),
        watched => println!("\nwatching {watched} git branches for deployments"),
    }

    // Stated for the same reason: a deployment that believes it self-updates
    // but does not is indistinguishable from one nobody has pushed to.
    //
    // The nudge is the webhook's end of the same watch: it is built here, given
    // to the API below, and awaited by the watcher in the `select!` — one value,
    // so a push cannot poke a signal nothing is listening to.
    let self_update_nudge = selfhost_git::Nudge::new();
    if let Some(update) = config.self_update.as_ref().filter(|u| u.enabled) {
        println!(
            "\nself-update: watching {} ({})",
            update.repository, update.branch
        );
        match update.webhook_secret.is_some() {
            true => println!(
                "  push         https://<a site this box serves>/.selfhost/webhook/self \
                 (deploys within seconds)"
            ),
            false => println!(
                "  push         not configured — set self_update.webhook_secret and add the \
                 same secret to the repository's webhook to deploy on push instead of \
                 on the timer"
            ),
        }
        println!("  safety net   re-checks every {}s regardless", update.interval_secs);
    }

    // The firewall the daemon drives for the public listeners. Built from config,
    // reconciled once here so the ports are open (or closed) before the API is
    // reachable, then kept honest by the drift watch in the select! below.
    //
    // A firewall that could not be set is reported and non-fatal, exactly like
    // `home::record`: the daemon still supervises services, and the listeners are
    // left governed by whatever the host firewall already holds. A known-unset
    // firewall the operator can see beats a daemon that refused to start.
    let firewall = selfhost_firewall::Manager::for_config(&config);
    match firewall.reconcile().await {
        Ok(state) if state.managed => {
            println!(
                "\nfirewall: {} · {} rule(s) · inbound {}",
                state.backend.label(),
                state.rules.len(),
                if state.default_inbound_block { "default-block" } else { "default-allow" }
            );
        }
        // Unmanaged: the operator did not ask us to touch the firewall, so say
        // nothing rather than imply we are governing it.
        Ok(_) => {}
        Err(error) => eprintln!(
            "warning: could not set the firewall ({error}); the public listeners are \
             governed by whatever the host firewall already holds"
        ),
    }

    // Authoritative DNS, when the config asks for it. Built from the same
    // validated `Config` as every other service, exactly like the firewall above.
    // The public IP is discovered once to fill the apex-A default; the updater
    // (below, in the `select!`) keeps it current afterwards.
    //
    // The edge is the operator's, not ours: for the internet to reach this server
    // the router/edge must forward UDP *and* TCP port 53 to this machine. selfhost
    // never rewrites a router or firewall port-forward — that stays a deliberate
    // change the operator makes. See `crates/cli/src/dns_status.rs`.
    //
    // A DNS bind failure is fatal for the whole daemon (it returns from the
    // `select!`), matching `run`'s bind handling rather than the firewall's
    // best-effort one: the roadmap's stated worst case is a DNS server that is
    // silently not listening, so the domain and its mail stop resolving with no
    // sign why. Better to fail loudly at startup than to look healthy and be deaf.
    let dns = match config.dns.as_ref() {
        Some(_) => {
            let public_ip = doctor::discover_public_ip().await;
            let authority = lan_dns::build_authority(&config, &project_dir, public_ip);
            enable_lan_view_if_configured(&authority, &config);
            Some(authority)
        }
        None => None,
    };
    let dns_bind: Option<SocketAddr> = match config.dns.as_ref() {
        Some(dns) => Some(dns.bind.parse().map_err(|e| format!("dns.bind {}: {e}", dns.bind))?),
        None => None,
    };
    if let (Some(authority), Some(bind), Some(dns_config)) =
        (dns.as_ref(), dns_bind, config.dns.as_ref())
    {
        println!("\nauthoritative DNS on {bind}");
        for origin in authority.origins().await {
            println!("  zone         {origin}");
        }
        if dns_config.secondaries.is_empty() {
            println!("  secondaries  none — a single nameserver, see `selfhost dns`");
        } else {
            println!("  secondaries  {}", dns_config.secondaries.join(", "));
        }
        if dns_config.dynamic_ip {
            println!("  dynamic ip   on — the apex A follows this machine's WAN IP");
        }
        println!("  reachability the router/edge must forward UDP+TCP 53 here (selfhost does not touch it)");
    }

    // Console auth is read once here: a `selfhost console-password` run takes
    // effect at the next daemon restart.
    let mut api = Api::new(supervisor.clone(), store, token, watches.clone(), firewall.clone())
        .with_console_auth(&data_dir);
    // Only when the section is live: a route that answers 202 and pokes a
    // watcher that is not running would report a deployment nobody is doing.
    if config.self_update.as_ref().is_some_and(|update| update.enabled) {
        api = api.with_self_update(self_update_nudge.clone());
    }
    // Passkey (biometric) login is scoped to the console site's canonical
    // hostname — the WebAuthn relying-party id. Config is the only honest
    // source for it: the proxy's console relay forwards no Host header, and an
    // identity the client could pick would undo the origin binding. No console
    // site, no passkeys; the password and bearer paths are unchanged.
    if let Some(host) = config.sites.iter().find(|site| site.console).and_then(|site| site.domains.first())
    {
        api = api.with_console_webauthn(host, &data_dir);
        println!("\nconsole passkeys enabled for https://{host} (stored in console.passkeys)");
    }

    // Network storage. Absent `[[shares]]` means no `Volumes` at all, so every
    // storage route answers with the same uninformative 401 an unauthenticated
    // caller gets and nothing is opened, measured or advertised.
    //
    // A share that cannot be served stops the daemon here, deliberately: a root
    // that does not exist, or one nested inside `data_dir`, the TLS store or
    // this checkout, is an operator mistake with a security consequence, and the
    // moment to say so is before the API is answering rather than on the first
    // request that happens to touch it.
    if !config.shares.is_empty() {
        let volumes = open_shares(&config, &project_dir, &data_dir)?;
        println!("\n{} share(s):", volumes.len());
        for volume in volumes.all() {
            let share = volume.share();
            println!(
                "  {:<20} {} ({})",
                share.id().as_str(),
                share.root().display(),
                if share.read_only() { "read-only" } else { "writable" },
            );
        }
        api = api.with_storage(volumes);
    }

    // The peer link. Started before the desktop because the desktop's node
    // picker reports what the link knows, and a picker built against a registry
    // that does not exist yet would report "no mesh" on a box that has one.
    //
    // A worker binds nothing to do this: it dials the owner's console site on
    // the 443 that site already serves, over the tunnel it is already reached
    // through. Nothing in this arm opens a port, and if it ever appears to need
    // one the change has taken a wrong turn.
    let mesh = mesh_task::start(&config, &data_dir);
    if let Some(line) = mesh.banner() {
        println!("\n{line}");
    }

    // The owner's half of the peer link. `mesh_task` above is the *worker's*
    // half — it dials out and binds nothing — and without this the route a
    // worker dials answers 404, which is what a verification pass found: every
    // line of `crates/mesh` was unreachable in production while its own tests
    // passed, because nothing ever called this.
    //
    // Declared from `[[nodes]]` with `role = "worker"` and the token
    // `selfhost node invite` already wrote, so enrolling a machine stays one
    // command and this stays one line. Still binds nothing: a worker dials the
    // console site's existing 443, and the link arrives as an upgrade on a
    // socket the proxy already accepted.
    api = api.with_peers(selfhost_admin::Peerage::for_owner(&config.nodes, &data_dir));

    // Remote desktop. `None` unless `[desktop]` is present and `enabled = true`,
    // and `None` means the subsystem does not exist: no `Fleet` on the API, no
    // kill-switch poll, no agent, and every desktop route indistinguishable from
    // one this deployment does not serve.
    //
    // Built once, here. A `[desktop]` edit takes effect at the next daemon
    // restart, exactly like `[mail]` and `[dns]` — the config watch in `run`
    // reloads the proxy's routing table and nothing else, so there is no path
    // by which a second copy of this subsystem could come into being.
    //
    // KNOWN GAP, stated here because the picker is where it shows: the peers it
    // is handed are the *worker's* view — this machine's own dialled link — so
    // on an owner it is `None` and the picker offers only `self`. An admitted
    // link now lands in `Peerage`'s registry, but that registry and
    // `mesh_task::Peers` are different types answering different questions, and
    // bridging them is a refactor of this signature rather than an argument.
    // Until then a second machine can enrol and link, and cannot yet be picked.
    let desk = desk_task::start(&config, &data_dir, mesh.peers().cloned()).map(Arc::new);
    if let Some(desk) = desk.as_ref() {
        println!("\n{}", desk.summary());
        api = api.with_desktop(*desk.config(), Arc::clone(desk) as Arc<dyn Fleet>);
    }

    // ---- the web tier -------------------------------------------------------
    //
    // Last, and on purpose: everything above either binds loopback or binds
    // nothing, so by the time the public listeners come up the services behind
    // them are already supervised and the zones they answer for are already
    // loaded. Binding :443 first would open a window where the internet can
    // reach a proxy whose backends have not been started.
    let server = Arc::new(Server::build(&config, &project_dir));
    server.spawn_health_tasks();
    tokio::spawn(watch_config(Arc::clone(&server), config_path, project_dir.clone()));

    let certificates = CertificateStore::open(&data_dir).map_err(|e| e.to_string())?;

    // The fallback identity: served on :443 the instant the listener binds, and
    // for any SNI that has no certificate of its own. A self-signed pair is
    // generated once so the resolver always has something to answer with, even
    // on a first start with nothing on disk and before any ACME exchange has
    // completed.
    let primary = config
        .sites
        .first()
        .map(|s| s.canonical().to_owned())
        .unwrap_or_else(|| "localhost".to_owned());
    let alternates: Vec<String> = config.sites.iter().flat_map(|s| s.domains.clone()).collect();
    certificates
        .load_or_generate_self_signed(&primary, &alternates)
        .map_err(|e| e.to_string())?;

    // Per-host certificate selection via SNI. Rebuildable at runtime, so a
    // freshly issued certificate takes effect without restarting.
    let resolver =
        SniResolver::new(&certificates, &certificates.hosts(), &primary).map_err(|e| e.to_string())?;

    // For staging or production, fetch real certificates in the background. The
    // task is spawned before the listeners bind so the HTTP-01 responder on :80
    // is already answering when the CA calls back. Self-signed needs no CA, no
    // network, and no task — the resolver already holds the generated pair.
    if !matches!(config.server.acme, AcmeEnvironment::SelfSigned) {
        tokio::spawn(acme_task::issue_and_renew(
            config.clone(),
            project_dir.clone(),
            certificates.clone(),
            Arc::clone(&resolver),
        ));
    }

    // Mail shares the certificate store and resolver above rather than opening
    // its own, so `imap.example.com` presents the same certificate the proxy
    // does and a renewal reaches both at once. A no-op when `[mail]` is absent.
    mail_task::run(
        config.clone(),
        project_dir.clone(),
        certificates.clone(),
        Arc::clone(&resolver),
    )
    .await;

    let tls_config = server_config_with_resolver(resolver).map_err(|e| e.to_string())?;

    let http = TcpListener::bind(&config.server.http_bind)
        .await
        .map_err(|e| format!("cannot bind {} — {e}", config.server.http_bind))?;
    let https = TcpListener::bind(&config.server.https_bind)
        .await
        .map_err(|e| format!("cannot bind {} — {e}", config.server.https_bind))?;

    println!("\nlistening");
    println!("  http  {}  (redirects to https)", config.server.http_bind);
    println!("  https {}", config.server.https_bind);
    for site in &config.sites {
        let instances = site.instances.len();
        println!("  site  {} → {} ({instances} instance(s))", site.canonical(), site.name);
    }
    println!("\nCtrl-C to stop.");

    let mut updated_to: Option<String> = None;
    let outcome = tokio::select! {
        result = selfhost_admin::serve(listener, api) => {
            result.map_err(|e| format!("the control api stopped: {e}"))
        }
        // The public listeners. A bind failure has already been returned above;
        // reaching here means one of them stopped accepting, which is fatal for
        // the same reason the DNS arm is: the box is meant to be serving.
        result = serve_http(http, Arc::clone(&server)) => {
            result.map_err(|e| format!("http listener stopped: {e}"))
        }
        result = serve_https(https, Arc::clone(&server), tls_config) => {
            result.map_err(|e| format!("https listener stopped: {e}"))
        }
        // Re-asserts the firewall on a slow timer so an out-of-band change is
        // noticed and repaired. Never returns; this arm only exists so the daemon
        // runs it alongside the API.
        _ = watch_firewall_drift(firewall.clone()) => Ok(()),
        // Serves :53 for the configured zones. When DNS is not configured this
        // future pends forever, so the arm exists without ever firing. A bind
        // failure returns here and stops the daemon (see the note above).
        result = serve_dns(dns.clone(), dns_bind) => result,
        // Tracks the WAN IP and rewrites the apex A when it moves. Pends forever
        // when DNS or dynamic_ip is off, so it occupies an arm without firing.
        _ = track_wan_ip_if_enabled(dns.clone(), &config) => Ok(()),
        // Watches for the operator's `desktop.disabled` marker so an engaged
        // kill switch reaches every running stream without anything else having
        // to be working. Pends forever when there is no desktop subsystem, so
        // the arm exists without ever firing.
        _ = watch_kill_switch(desk.as_deref()) => Ok(()),
        // Keeps this worker's link to its owner up. Dials out and binds nothing;
        // pends forever when there is no `[mesh]` section, when it is parked, or
        // when it cannot be used, so the arm exists without ever firing.
        _ = maintain_mesh(mesh.peers()) => Ok(()),
        // Watches this daemon's own repository; resolving means a new build is
        // fetched, compiled, and installed, and this process's job is to get
        // out of its way. Pends forever when `[self_update]` is absent or off.
        commit = self_update::watch_own_repository(
            config.self_update.clone(),
            project_dir.clone(),
            self_update_nudge.clone(),
        ) => {
            updated_to = Some(commit);
            Ok(())
        }
        _ = shutdown_signal() => Ok(()),
    };

    // The note outlives nothing: a console reading it after this daemon has gone
    // would look for a token beside a daemon that is not there.
    if let Err(error) = selfhost_config::home::forget(&project_dir) {
        eprintln!("warning: could not remove the record of this daemon ({error})");
    }

    // Watches first: one that polled through the shutdown could start a
    // deployment of a service that is in the middle of being stopped.
    watches.shutdown().await;

    // The firewall rules are deliberately left in place: a firewall protecting
    // the host should outlive the daemon that set it, so a restart — or a crash —
    // never opens a window where the machine is unguarded. `teardown` removes them
    // when the operator actually wants them gone.

    // Stop children the way their specs ask rather than letting process teardown
    // orphan or kill them.
    println!("\nstopping services");
    supervisor.shutdown().await;

    // A self-update ends the process on purpose, after the graceful teardown
    // above. Nonzero so every service manager restarts it — launchd restarts
    // any exit, but systemd (on-failure) and the Scheduled Task
    // (RestartOnFailure) only restart what looks like a failure.
    if let Some(commit) = updated_to {
        println!(
            "\nself-update: now at {}; exiting so the service manager restarts the new build",
            selfhost_git::plan::short(&commit)
        );
        std::process::exit(self_update::RESTART_EXIT);
    }
    outcome
}

/// Opens every declared share, or refuses to start with the reason.
///
/// Both paths handed to [`Reserved`] are made absolute first: `data_dir` is
/// relative in the default config, and a path that cannot be compared soundly is
/// one `Reserved` refuses rather than accepts quietly — which would turn "this
/// share overlaps the deployment's secrets" into a check that silently passed.
fn open_shares(
    config: &Config,
    project_dir: &Path,
    data_dir: &Path,
) -> Result<selfhost_admin::Volumes, String> {
    let absolute = |path: &Path| {
        std::path::absolute(path)
            .map_err(|error| format!("cannot resolve {} to an absolute path: {error}", path.display()))
    };
    let reserved = selfhost_storage::share::Reserved::new(
        &absolute(data_dir)?,
        Some(&absolute(project_dir)?),
    )
    .map_err(|error| format!("cannot state what this deployment protects: {error}"))?;
    selfhost_admin::Volumes::open(&config.shares, &reserved).map_err(|error| {
        format!(
            "{error}\n  A share is declared in {CONFIG_FILENAME} and must name an existing \
             directory outside data_dir, the TLS store and this checkout."
        )
    })
}

/// Watches the desktop kill switch, or pends forever when there is no desktop.
///
/// One arm of the daemon's `select!`, the same pend-forever shape the DNS and
/// self-update arms use. It never resolves: an engaged switch stops streams, it
/// does not stop the daemon — the box is still serving websites, mail and files,
/// and taking those down because somebody revoked a screen would be a worse
/// outage than the one they were preventing.
async fn watch_kill_switch(desk: Option<&desk_task::Desk>) {
    let Some(desk) = desk else {
        return std::future::pending().await;
    };
    desk.watch().await;
}

/// Keeps the peer link up, or pends forever when this machine has none.
///
/// The same pend-forever shape as the DNS and kill-switch arms. It never
/// resolves: a link that drops is re-established, and a link that cannot be
/// established is retried — neither is a reason to stop serving websites, mail
/// and files, which is what returning from this arm would do.
async fn maintain_mesh(peers: Option<&std::sync::Arc<mesh_task::Peers>>) {
    let Some(peers) = peers else {
        return std::future::pending().await;
    };
    peers.run().await;
    // `run` only returns when the dialler gave up for a reason that will not
    // change; the daemon still has every other job to do.
    std::future::pending().await
}

/// Watches the host firewall for out-of-band changes and re-asserts the policy.
///
/// Never returns: it is a branch of the daemon's `select!`, ended only when the
/// daemon shuts down. Each tick observes the live firewall; any desired rule the
/// firewall no longer holds, or a default-inbound block that has been turned off,
/// is drift — logged so the record shows the firewall was changed from outside,
/// then repaired by `reconcile`. An unmanaged firewall (`manage = false`) is left
/// entirely alone. A reconcile that fails is reported and the watch keeps going;
/// the next tick tries again.
async fn watch_firewall_drift(firewall: selfhost_firewall::Manager) {
    let mut ticker = tokio::time::interval(FIREWALL_DRIFT_INTERVAL);
    // The first tick fires immediately; skip it, since startup already reconciled.
    ticker.tick().await;
    loop {
        ticker.tick().await;

        let observed = firewall.state().await;
        if !observed.managed {
            continue;
        }

        let missing: Vec<&str> =
            observed.rules.iter().filter(|r| !r.applied).map(|r| r.rule.tag.as_str()).collect();
        let block_lost = !observed.default_inbound_block;
        if missing.is_empty() && !block_lost {
            continue;
        }

        let mut what = String::new();
        if block_lost {
            what.push_str("default inbound block cleared");
        }
        if !missing.is_empty() {
            if !what.is_empty() {
                what.push_str("; ");
            }
            what.push_str(&format!("rule(s) {} gone", missing.join(", ")));
        }
        eprintln!("firewall drift: {what} — re-asserting");

        if let Err(error) = firewall.reconcile().await {
            eprintln!("warning: could not re-assert the firewall after drift ({error})");
        }
    }
}

/// Serves authoritative DNS for the daemon's `select!`, or pends forever.
///
/// One arm of the daemon has to run the DNS server, but DNS is opt-in — most
/// deployments have no `[dns]` section. Rather than conditionally building the
/// `select!`, this arm always exists and simply never resolves when there is
/// nothing to serve, the same pend-forever shape the updater and the firewall
/// watch use. A bind failure is surfaced as the daemon's outcome, with the same
/// privilege hint `watch-dns` prints for port 53.
async fn serve_dns(dns: Option<Authority>, bind: Option<SocketAddr>) -> Result<(), String> {
    let (Some(authority), Some(bind)) = (dns, bind) else {
        return std::future::pending().await;
    };
    authority.serve(bind).await.map_err(|error| dns_bind_error(bind, error))
}

/// Tracks the WAN IP and rewrites the apex A, or pends forever.
///
/// Gated twice — DNS present, and `dynamic_ip` on — because a static-IP
/// deployment wants its apex A left exactly as configured. When either gate is
/// closed this pends forever, occupying its `select!` arm without doing work.
/// Otherwise it hands the live [`Authority`] to the updater, which owns the poll
/// loop, the change detection, and the serial bump.
async fn track_wan_ip_if_enabled(dns: Option<Authority>, config: &Config) {
    let Some(authority) = dns else {
        return std::future::pending().await;
    };
    let dynamic = config.dns.as_ref().is_some_and(|dns| dns.dynamic_ip);
    if !dynamic {
        return std::future::pending().await;
    }
    let zones = authority.origins().await;
    selfhost_dns::updater::track_wan_ip(
        authority,
        zones,
        selfhost_dns::updater::DEFAULT_INTERVAL,
    )
    .await;
}

/// Turns a DNS bind failure into a message that says what to do about it.
///
/// Port 53 is privileged and commonly already held by a stub resolver, so the
/// two failures worth naming get the same guidance `watch-dns` gives — the whole
/// point of this daemon is to run unattended, and "permission denied" with no
/// remedy is a support ticket waiting to happen.
fn dns_bind_error(bind: SocketAddr, error: DnsError) -> String {
    match &error {
        DnsError::Bind { source, .. }
            if source.kind() == std::io::ErrorKind::PermissionDenied =>
        {
            format!(
                "cannot bind {bind}: port 53 needs privilege.\n  \
                 Run it with sudo, or on Linux grant the capability once:\n  \
                 sudo setcap 'cap_net_bind_service=+ep' ./target/release/selfhost"
            )
        }
        DnsError::Bind { source, .. } if source.kind() == std::io::ErrorKind::AddrInUse => {
            format!(
                "cannot bind {bind}: something already answers DNS on this machine.\n  \
                 On macOS that is usually a VPN client or Internet Sharing; on Linux a local\n  \
                 stub resolver such as systemd-resolved on 127.0.0.53."
            )
        }
        _ => format!("the DNS server stopped: {error}"),
    }
}

/// Dispatches `dns`'s subcommands. Only the bare form remains: this machine is
/// authoritative for every name it serves, so there is no third party holding a
/// copy of the zone to reconcile against.
fn dns_command(arguments: &[String]) -> Result<(), String> {
    match arguments.get(1).map(String::as_str) {
        None => dns_show_command(),
        Some(other) => Err(format!(
            "unknown dns subcommand \"{other}\" — use bare `dns` to show the served zone. \
             This deployment is its own nameserver; there is no registrar to sync \
             to\n\n{USAGE}"
        )),
    }
}

/// Shows the zone this machine serves and whether it is answering on port 53.
///
/// Read-only and needs no running daemon to describe the zone — the preview is
/// derived from the config the same way the server derives it — but it also
/// probes the bind so the reader learns whether the server is actually up.
fn dns_show_command() -> Result<(), String> {
    let (config, _project_dir) = load()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    runtime.block_on(dns_status::show(&config))
}

/// Asks the internet what it can actually reach here, using third parties as
/// the witnesses.
///
/// See [`outside`] for why a third party is the only honest vantage point from
/// a network with no hairpin and no machine outside it.
fn outside_command() -> Result<(), String> {
    let (config, project_dir) = load()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    runtime.block_on(outside::report(&config, &project_dir))
}

/// Prints, and optionally applies, the routing changes that make this
/// deployment's public address reachable from inside its own network.
///
/// Dry-run by default and applied only with `--apply`, the convention every
/// machine-changing command here follows — doubly so for this one, since a
/// wrong route is how a machine is made unreachable. `--client` asks for the
/// other half of the arrangement, the part that runs on a laptop rather than on
/// the box.
fn hairpin_command(arguments: &[String]) -> Result<(), String> {
    let (config, _project_dir) = load()?;
    let apply = arguments.iter().any(|argument| argument == "--apply");
    let undo = arguments.iter().any(|argument| argument == "--undo");
    let side = if arguments.iter().any(|argument| argument == "--client") {
        hairpin::Side::Client
    } else {
        hairpin::Side::Box
    };

    let public: Ipv4Addr = match value_of(arguments, "--public") {
        Some(given) => given.parse().map_err(|e| format!("--public {given}: {e}"))?,
        None => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("could not start the async runtime: {e}"))?;
            runtime.block_on(doctor::discover_public_ip()).ok_or_else(|| {
                "could not discover this network's public address; pass --public <ip>".to_owned()
            })?
        }
    };
    let lan: Ipv4Addr = match value_of(arguments, "--lan") {
        Some(given) => given.parse().map_err(|e| format!("--lan {given}: {e}"))?,
        None => config
            .dns
            .as_ref()
            .and_then(|dns| dns.lan_ip.as_ref())
            .and_then(|ip| ip.parse().ok())
            .ok_or_else(|| {
                "this config does not record the box's LAN address; pass --lan <ip>".to_owned()
            })?,
    };

    let actions = if undo {
        hairpin::undo_plan(side, public, lan)?
    } else {
        hairpin::plan(side, public, lan)?
    };

    let what = match side {
        hairpin::Side::Box => "this box (the machine holding the LAN address)",
        hairpin::Side::Client => "a LAN client (a laptop, a phone's tethered Mac)",
    };
    println!("Hairpin {} for {what}:\n", if undo { "removal" } else { "setup" });
    println!("  public address  {public}");
    println!("  box on the LAN  {lan}\n");
    for action in &actions {
        println!("  {}", action.argv.join(" "));
        println!("      {}\n", action.because);
    }

    if !apply {
        println!("Dry run — nothing was changed. Re-run with --apply to make it so.");
        println!(
            "\nRun this on the box, then with --client on every machine that should reach\n\
             the public address. Undo either with --undo."
        );
        return Ok(());
    }

    for action in &actions {
        let (program, rest) = action.argv.split_first().expect("an action names a program");
        let status = std::process::Command::new(program)
            .args(rest)
            .status()
            .map_err(|error| format!("cannot run {program}: {error}"))?;
        if !status.success() {
            return Err(format!(
                "`{}` failed ({status}) — this usually means it needs administrator rights",
                action.argv.join(" ")
            ));
        }
        println!("  ran  {}", action.argv.join(" "));
    }

    println!("\n✓ applied. Confirm with: curl -sv https://{public}/ 2>&1 | head");
    println!(
        "  This proves the public address, DNS, SNI and certificate path. It does NOT\n\
         prove the router forwards from the internet — run `selfhost outside` for that."
    );
    Ok(())
}

/// Serves authoritative DNS in the foreground, without the rest of the daemon.
///
/// The `daemon` command already serves DNS alongside everything else; this is
/// the `run`-to-`daemon` counterpart — a way to bring up and test just the
/// authority. `watch-dns` is the other DNS command and does the opposite job: it
/// *forwards* queries to diagnose the network, whereas this *answers* them
/// authoritatively for the configured zones.
fn serve_dns_command(arguments: &[String]) -> Result<(), String> {
    let (config, project_dir) = load()?;
    let Some(dns) = config.dns.as_ref() else {
        return Err(
            "no [dns] section in the config, so there is no zone to serve.\n  \
             Add one — `selfhost dns` shows what it would serve — then re-run."
                .into(),
        );
    };
    let bind: SocketAddr = match value_of(arguments, "--bind") {
        Some(given) => given.parse().map_err(|e| format!("--bind {given}: {e}"))?,
        None => dns.bind.parse().map_err(|e| format!("dns.bind {}: {e}", dns.bind))?,
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    runtime.block_on(serve_dns_foreground(config, project_dir, bind))
}

/// Serves split-horizon DNS for the LAN in the foreground.
///
/// The box's scheduled task runs `selfhost lan-dns --lan-ip 192.168.1.8`, so
/// the command name and flag names are a deployment contract — see the
/// [`lan_dns`] module docs. Renaming any of them silently kills DNS for the
/// entire LAN on the next deploy.
fn lan_dns_command(arguments: &[String]) -> Result<(), String> {
    let (config, project_dir) = load()?;
    let lan_ip: std::net::Ipv4Addr = value_of(arguments, "--lan-ip")
        .ok_or_else(|| {
            format!(
                "lan-dns needs --lan-ip <ip> — the LAN address every configured site domain \
                 should answer with, for example:\n  selfhost lan-dns --lan-ip 192.168.1.8\n\n{USAGE}"
            )
        })?
        .parse()
        .map_err(|e| format!("--lan-ip: {e}"))?;
    let bind: SocketAddr = match value_of(arguments, "--bind") {
        Some(given) => given.parse().map_err(|e| format!("--bind {given}: {e}"))?,
        None => "0.0.0.0:53".parse().expect("literal bind address"),
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    runtime.block_on(lan_dns::lan_dns_command(&config, &project_dir, lan_ip, bind))
}

/// Enables the authority's split-horizon LAN view when `[dns].lan_ip` is set.
///
/// The upstream for LAN peers' foreign queries is the system resolver, the
/// same source `lan-dns` uses. A `lan_ip` that does not parse is warned about
/// and the public view served instead — DNS staying up matters more than the
/// horizon; `selfhost check` reports the bad value properly.
fn enable_lan_view_if_configured(authority: &Authority, config: &Config) {
    let Some(lan_ip) = config.dns.as_ref().and_then(|dns| dns.lan_ip.as_ref()) else {
        return;
    };
    match lan_ip.parse() {
        Ok(lan_ip) => authority.set_lan(selfhost_dns::authority::LanView {
            lan_ip,
            upstream: selfhost_dns::Resolver::system().address(),
        }),
        Err(error) => eprintln!(
            "warning: [dns].lan_ip {lan_ip} is not an IPv4 address ({error}); \
             serving the public view to every peer"
        ),
    }
}

/// Binds the authority and serves until interrupted.
async fn serve_dns_foreground(
    config: Config,
    project_dir: std::path::PathBuf,
    bind: SocketAddr,
) -> Result<(), String> {
    let public_ip = doctor::discover_public_ip().await;
    let authority = lan_dns::build_authority(&config, &project_dir, public_ip);
    enable_lan_view_if_configured(&authority, &config);

    println!("selfhost authoritative DNS");
    println!("  bind    {bind}");
    for origin in authority.origins().await {
        println!("  zone    {origin}");
    }
    match public_ip {
        Some(address) => println!("  apex A  {address} (discovered public IP)"),
        None => println!("  apex A  unknown — could not discover this machine's public IP"),
    }
    println!(
        "\nFor the internet to reach this server, the router/edge must forward UDP+TCP 53\n\
         to this machine. selfhost does not change the router."
    );
    println!("\nCtrl-C to stop.");

    tokio::select! {
        result = authority.serve(bind) => result.map_err(|error| dns_bind_error(bind, error)),
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

/// Waits for whichever signal means "stop", so children are stopped rather than
/// orphaned.
///
/// Ctrl-C alone is not enough. The daemon's whole purpose is to run under an
/// operating-system service manager, and `systemd`, `launchd`, and the Windows
/// SCM all stop a service by sending `SIGTERM` (or its equivalent) — never by
/// sending an interrupt. A daemon that handles only Ctrl-C therefore dies without
/// running its shutdown on every *real* stop, leaving every supervised service
/// running and holding its ports, which then makes the restart fail to bind.
#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(stream) => stream,
        // Losing the handler must not take the daemon with it; Ctrl-C still works.
        Err(error) => {
            eprintln!("warning: cannot listen for SIGTERM ({error}); Ctrl-C still stops cleanly");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

/// On Windows, Ctrl-C and the SCM's stop both arrive through the console handler.
#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// Stops, uninstalls, and removes what the daemon created.
///
/// The plan is shown before anything happens and confirmed on the terminal,
/// because every argument this takes is destructive and the difference between
/// them is how much. See [`teardown`] for what it refuses to touch and why.
fn teardown_command(arguments: &[String]) -> Result<(), String> {
    let everything = arguments.iter().any(|argument| argument == "--everything");
    let assumed_yes = arguments.iter().any(|argument| argument == "--yes");

    let (config, project_dir) = load()?;
    let address: SocketAddr = config
        .server
        .admin_bind
        .parse()
        .map_err(|error| format!("admin_bind {}: {error}", config.server.admin_bind))?;
    if teardown::daemon_is_running(address) {
        return Err(teardown::refuse_because_running(address));
    }

    let data_dir = teardown::data_dir(&config, &project_dir);
    let store = Store::new(&data_dir);
    let node_names: Vec<&str> = config.nodes.iter().map(|node| node.name.as_str()).collect();
    let catalog = store.load(&node_names).map_err(|error| error.to_string())?;

    let removals = teardown::plan(&project_dir, &data_dir, &catalog, everything);
    let skipped = teardown::left_behind(&project_dir, &catalog);

    if removals.is_empty() {
        println!("Nothing to remove — this project has no daemon state on disk.");
        report_left_behind(&skipped);
        return Ok(());
    }

    println!("This will remove:\n");
    for removal in &removals {
        println!("  {:<34} {}", removal.what, removal.path.display());
    }
    if !everything {
        println!(
            "\nKeeping {} — certificates, mail, and backups live there.\n\
             Pass --everything to remove it too.",
            data_dir.display()
        );
    }
    println!("Keeping {CONFIG_FILENAME} — you wrote it, and this did not.");

    if !assumed_yes && !teardown::confirmed() {
        println!("\nNothing was removed.");
        return Ok(());
    }

    println!();
    let failures = teardown::carry_out(&removals);

    // The note is a hint about a daemon that is no longer here; removing it is
    // not optional and not worth confirming.
    if let Err(error) = selfhost_config::home::forget(&project_dir) {
        println!("  FAILED   the record of where the daemon runs — {error}");
    }

    report_left_behind(&skipped);
    if failures.is_empty() {
        println!("\n✓ torn down");
        return Ok(());
    }
    Err(format!(
        "{} item(s) could not be removed and are listed above. Everything else was.",
        failures.len()
    ))
}

/// Names any working copy the teardown deliberately did not touch.
fn report_left_behind(skipped: &[teardown::Removal]) {
    if skipped.is_empty() {
        return;
    }
    println!("\nLeft alone, because they are outside this project:");
    for removal in skipped {
        println!("  {:<34} {}", removal.what, removal.path.display());
    }
}

/// Registers, removes, or reports the daemon's OS service registration.
///
/// The subcommand is dispatched here rather than as three top-level commands so
/// `install`, `uninstall`, and `status` read as one feature and share the
/// `--system`/`--yes` flags. See [`service_install`] for what each platform gets.
fn service_command(arguments: &[String]) -> Result<(), String> {
    let system = arguments.iter().any(|argument| argument == "--system");
    let assumed_yes = arguments.iter().any(|argument| argument == "--yes");
    match arguments.get(1).map(String::as_str) {
        Some("install") => service_install_command(system, assumed_yes),
        Some("uninstall") => service_uninstall_command(system, assumed_yes),
        Some("status") => service_install::status(system),
        Some(other) => Err(format!(
            "unknown service subcommand \"{other}\" — expected install, uninstall, or status\n\n{USAGE}"
        )),
        None => Err(format!(
            "service needs a subcommand: install, uninstall, or status\n\n{USAGE}"
        )),
    }
}

/// Reports on remote desktop, and works the kill switch.
///
/// The three subcommands are deliberately unequal in weight. `status` reads and
/// changes nothing. `disable` and `enable` create and remove one file, and that
/// file — not this command — is the mechanism: `touch` and `rm` do exactly the
/// same thing, which is the whole point of a switch an operator must be able to
/// reach when the console is the thing they do not trust. See
/// [`kill_switch`] for why it fails closed.
fn desktop_command(arguments: &[String]) -> Result<(), String> {
    let (config, project_dir) = load()?;
    let data_dir = teardown::data_dir(&config, &project_dir);
    match arguments.get(1).map(String::as_str) {
        None | Some("status") => desktop_status(&config, &data_dir),
        Some("disable") => {
            // Created if it is not there. This is the command an operator runs
            // when something is wrong, possibly before the daemon has ever
            // started, and "no such directory" would be a refusal to stop.
            crate::data_dir::create_if_absent(&data_dir)
                .map_err(|error| format!("cannot create {}: {error}", data_dir.display()))?;
            kill_switch::engage(&data_dir).map_err(|error| {
                format!("cannot write {}: {error}", kill_switch::path_in(&data_dir).display())
            })?;
            // No audit line is written here, deliberately: the running daemon
            // records what it observes, whatever put the file there. See
            // [`desk_task::Desk::watch`] for why the observer and not the
            // commander is the one writer.
            println!("✓ remote desktop disabled — {}", kill_switch::path_in(&data_dir).display());
            println!(
                "  a running daemon closes every stream within {} second(s); no restart is needed",
                kill_switch::POLL_INTERVAL.as_secs()
            );
            Ok(())
        }
        Some("enable") => {
            let removed = kill_switch::release(&data_dir).map_err(|error| {
                format!("cannot remove {}: {error}", kill_switch::path_in(&data_dir).display())
            })?;
            if removed {
                println!("✓ kill switch removed — {}", kill_switch::path_in(&data_dir).display());
            } else {
                println!("the kill switch was not in place; nothing changed");
            }
            // Said every time, because removing the switch is not the same as
            // switching the feature on and an operator expecting a screen
            // deserves to learn that here rather than from a blank viewport.
            match config.desktop.as_ref() {
                Some(desktop) if desktop.enabled => {}
                _ => println!(
                    "  note: [desktop] is absent or enabled = false, so there is still no remote \
                     desktop. That is a config edit and a daemon restart, never a UI toggle."
                ),
            }
            Ok(())
        }
        Some(other) => Err(format!(
            "unknown desktop subcommand \"{other}\" — expected status, disable, or enable\n\n{USAGE}"
        )),
    }
}

/// Prints what remote desktop is configured to do and what it can actually see.
fn desktop_status(config: &Config, data_dir: &Path) -> Result<(), String> {
    let switch = kill_switch::path_in(data_dir);
    let engaged = kill_switch::present(data_dir);

    match config.desktop.as_ref() {
        None => println!("remote desktop: not configured — no [desktop] block in {CONFIG_FILENAME}"),
        Some(desktop) if !desktop.enabled => {
            println!("remote desktop: off — [desktop] enabled = false");
        }
        Some(desktop) => {
            println!("remote desktop: on");
            println!("  viewers      {} at once, per machine", desktop.max_viewers);
            println!("  frames       up to {} per second, {}px tiles", desktop.max_fps, desktop.tile);
            println!(
                "  input        {}",
                if desktop.allow_input {
                    "allowed — a viewer with the capability can type and click"
                } else {
                    "refused — view only"
                }
            );
            println!(
                "  clipboard    {}",
                if desktop.allow_clipboard { "allowed" } else { "refused" }
            );
            println!(
                "  freshness    a control ticket needs a login within {}s; a session ends after {}s",
                desktop.reauth_window_secs, desktop.max_session_secs
            );
        }
    }

    // The capture backend is only worth naming when something might use it. On
    // a deployment with no [desktop] block it would read as a promise.
    if config.desktop.as_ref().is_some_and(|desktop| desktop.enabled) {
        // The sentence is printed whether or not there is a screen behind it.
        // "CGDisplayStream" on its own is the shape of answer this seam exists
        // to prevent: it names a mechanism and says nothing about whether this
        // machine, right now, can produce a pixel through it.
        let backend = desk_task::Backend::here();
        println!("  capture      {}", backend.name);
        println!("               {}", backend.why);
    }

    if engaged {
        println!("  kill switch  ENGAGED — {}", switch.display());
        println!("               no stream will run until that file is removed");
    } else {
        println!("  kill switch  clear — create {} to stop everything", switch.display());
    }
    Ok(())
}

/// Dispatches `mail`'s subcommands.
fn mail_command(arguments: &[String]) -> Result<(), String> {
    match arguments.get(1).map(String::as_str) {
        Some("hash-password") => mail_hash_password(arguments.get(2)),
        Some("add") => mail_add(arguments),
        Some("remove") => mail_remove(arguments),
        Some(other) => Err(format!(
            "unknown mail subcommand \"{other}\" — expected hash-password, add, or remove\n\n{USAGE}"
        )),
        None => Err(format!("mail needs a subcommand: hash-password, add, or remove\n\n{USAGE}")),
    }
}

/// Adds a mailbox to `[mail].mailboxes`, hashing its password first.
///
/// `[mail]` itself is not created here — hostname, domains, and DKIM are
/// deployment decisions an operator makes once by hand; this command only
/// ever appends a `[[mail.mailboxes]]` block to a `[mail]` that already
/// exists, the same division `site add` draws around `[server]`.
fn mail_add(arguments: &[String]) -> Result<(), String> {
    let address = arguments
        .get(2)
        .ok_or_else(|| format!("mail add needs an address: `selfhost mail add <address>`\n\n{USAGE}"))?;
    let password = read_password(arguments.get(3))?;
    let password_hash = selfhost_mail::hash_password(&password).map_err(|error| error.to_string())?;

    let config_path = find_config()?;
    let source = site::read_source(&config_path)?;
    let mailbox = selfhost_config::Mailbox {
        address: address.clone(),
        password_hash,
        aliases: Vec::new(),
    };
    let updated = selfhost_config::edit::add_mailbox(&source, &mailbox)
        .map_err(|error| format!("that mailbox cannot be added:\n{error}"))?;
    site::write_atomically(&config_path, &updated)?;

    println!("✓ added mailbox \"{address}\"");
    println!("  takes effect on the next `selfhost run` or daemon restart");
    Ok(())
}

/// Removes a mailbox from `[mail].mailboxes`.
fn mail_remove(arguments: &[String]) -> Result<(), String> {
    let address = arguments.get(2).ok_or_else(|| {
        format!("mail remove needs an address: `selfhost mail remove <address>`\n\n{USAGE}")
    })?;

    let config_path = find_config()?;
    let source = site::read_source(&config_path)?;
    let updated = selfhost_config::edit::remove_mailbox(&source, address)
        .map_err(|error| format!("that mailbox cannot be removed:\n{error}"))?
        .ok_or_else(|| format!("no mailbox \"{address}\" is configured"))?;
    site::write_atomically(&config_path, &updated)?;

    println!("✓ removed mailbox \"{address}\"");
    println!("  takes effect on the next `selfhost run` or daemon restart");
    Ok(())
}

/// The password an argument supplied, or one line read from stdin.
///
/// Shared by `hash-password` and `mail add` so a real password need not sit in
/// shell history or a process listing unless the caller chooses that.
fn read_password(argument: Option<&String>) -> Result<String, String> {
    match argument {
        Some(password) => Ok(password.clone()),
        None => {
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .map_err(|error| format!("could not read the password from stdin: {error}"))?;
            Ok(line.trim_end_matches(['\r', '\n']).to_owned())
        }
    }
}

/// Sets the console login password, hashing it into `<data_dir>/console.passwd`.
///
/// Takes the password as an argument only if given one; otherwise reads it
/// twice from stdin and refuses a mismatch, so a typo cannot silently lock the
/// console out. The hash is PBKDF2, matching what the admin API verifies
/// against; the daemon reads it at startup, so a change takes effect on the
/// next daemon restart.
fn console_password_command(arguments: &[String]) -> Result<(), String> {
    let (config, project_dir) = load()?;
    let data_dir = teardown::data_dir(&config, &project_dir);

    let password = match arguments.get(1) {
        Some(password) => password.clone(),
        None => {
            eprintln!("New console password (input is echoed):");
            let first = read_password(None)?;
            eprintln!("Repeat it:");
            let second = read_password(None)?;
            if first != second {
                return Err("the passwords did not match; nothing was changed".into());
            }
            first
        }
    };
    if password.is_empty() {
        return Err("an empty console password would let anyone in; nothing was changed".into());
    }

    selfhost_admin::ConsolePassword::write(&data_dir, &password)
        .map_err(|error| error.to_string())?;
    println!(
        "✓ console password set at {}",
        selfhost_admin::ConsolePassword::path_in(&data_dir).display()
    );
    println!("  takes effect on the next daemon restart");
    Ok(())
}

/// Hashes a mailbox password for `[[mail.mailboxes]] password_hash`.
///
/// Takes the password as an argument only if given one; otherwise reads a
/// single line from stdin, so a real password need not sit in shell history
/// or a process listing. The hash is PBKDF2, matching what
/// `selfhost_mail::submission::ConfigAuthenticator` verifies against.
fn mail_hash_password(argument: Option<&String>) -> Result<(), String> {
    let password = read_password(argument)?;
    let hash = selfhost_mail::hash_password(&password).map_err(|error| error.to_string())?;
    println!("{hash}");
    Ok(())
}

/// Writes the OS unit for `selfhost daemon` and registers it, after showing it.
///
/// The whole registration — the unit's text and the commands that load it — is
/// printed and confirmed before anything is written, exactly as `teardown` shows
/// its plan first: a boot service is a deliberate change to the machine, not a
/// side effect of a typo. The daemon's executable is [`std::env::current_exe`]
/// and its working directory is the project holding `selfhost.config.toml`, so
/// the installed unit resolves `data/` the way the daemon does.
fn service_install_command(system: bool, assumed_yes: bool) -> Result<(), String> {
    let (_, project_dir) = load()?;
    let exe = std::env::current_exe()
        .map_err(|error| format!("cannot find this executable to register it: {error}"))?;
    let plan = service_install::plan(&exe, &project_dir, system)?;

    println!("This will register selfhost as a {} service:\n", plan.mechanism);
    println!("  name          {}", plan.label);
    println!("  runs          {}", plan.argv.join(" "));
    println!("  working dir   {}", plan.working_dir.display());
    println!("  unit file     {}", plan.path.display());
    if let Some((path, _)) = &plan.companion {
        println!("  wrapper       {}", path.display());
    }
    println!(
        "\nOne service runs the whole deployment: websites, mail, DNS, the\n\
         supervised services and the control API, in one process."
    );
    println!("\nThe unit that will be written:\n");
    for line in plan.contents.lines() {
        println!("  {line}");
    }
    if let Some((path, contents)) = &plan.companion {
        println!("\nAnd {}:\n", path.display());
        for line in contents.lines() {
            println!("  {line}");
        }
    }
    println!("\nThen these commands register and start it:");
    for step in &plan.activate {
        println!("  {}", step.argv.join(" "));
    }

    if !assumed_yes && !service_install::confirm("\nRegister this service?") {
        println!("\nNothing was installed.");
        return Ok(());
    }

    println!();
    service_install::carry_out(&plan)?;
    println!("\n✓ installed — the daemon will start on boot and restart if it dies");
    Ok(())
}

/// Unregisters the daemon's OS service and removes its unit file, after showing
/// what it will do.
fn service_uninstall_command(system: bool, assumed_yes: bool) -> Result<(), String> {
    let plan = service_install::uninstall_plan(system)?;

    println!("This will remove the selfhost daemon {} service:\n", plan.mechanism);
    println!("  name        {}", plan.label);
    if let Some(path) = &plan.path {
        println!("  unit file   {}", path.display());
    }
    println!("\nCommands that will run:");
    for step in &plan.steps {
        println!("  {}", step.argv.join(" "));
    }

    if !assumed_yes && !service_install::confirm("\nRemove this service?") {
        println!("\nNothing was removed.");
        return Ok(());
    }

    println!();
    service_install::carry_out_uninstall(&plan)?;
    println!("\n✓ removed — the daemon no longer starts on boot");
    Ok(())
}

/// Prints the installed services and their configured start behaviour.
///
/// Reads the catalogue directly rather than asking a running daemon, so it
/// answers even when nothing is running — which is exactly when someone asks.
fn services_command() -> Result<(), String> {
    let (config, project_dir) = load()?;
    let data_dir = project_dir.join(&config.server.data_dir);
    let store = Store::new(&data_dir);
    let node_names: Vec<&str> = config.nodes.iter().map(|n| n.name.as_str()).collect();
    let catalog = store.load(&node_names).map_err(|e| e.to_string())?;

    if catalog.services.is_empty() {
        println!("no services installed — {} does not exist yet", store.path().display());
        return Ok(());
    }

    let width = catalog.services.iter().map(|s| s.name.len()).max().unwrap_or(0).max(4);
    println!("  {:<width$}  {:<10}  PROGRAM", "NAME", "START");
    for spec in &catalog.services {
        let mode = match spec.start_mode {
            selfhost_config::StartMode::Automatic => "automatic",
            selfhost_config::StartMode::Manual => "manual",
            selfhost_config::StartMode::Disabled => "disabled",
        };
        println!("  {:<width$}  {mode:<10}  {}", spec.name, spec.program.display());
    }
    Ok(())
}

/// Starts the whole deployment and blocks until interrupted.
///
/// The same thing [`daemon_command`] does, and kept only so an installation
/// whose service definition still says `selfhost run` keeps working while that
/// definition is replaced. Both names have to lead to one process: two of them
/// would each try to bind :443.
fn run() -> Result<(), String> {
    let (config, project_dir) = load()?;
    let config_path = project_dir.join(CONFIG_FILENAME);
    let bind = config.server.admin_bind.clone();
    let address: SocketAddr =
        bind.parse().map_err(|e| format!("server.admin_bind {bind}: {e}"))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    runtime.block_on(serve_everything(config, project_dir, config_path, address))
}

/// How often the config file is checked for changes to hot-reload.
///
/// A poll rather than an OS file-watch: the dependency policy admits no watch
/// crate (see the workspace `Cargo.toml`), and a person edits this file at
/// most a handful of times a day, so a few seconds of latency costs nothing
/// real in exchange for staying dependency-free.
const CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// Watches the config file and hot-reloads the site routing table when it
/// changes and still validates.
///
/// Only the routing table reloads live today — see [`Server::reload`] for
/// exactly what that covers. A change that touches anything else (a bind
/// address, `[mail]`, `[dns]`, the firewall) is picked up by `route`/`sites`
/// on the next reload same as any other edit, but the *listeners* for those
/// stay whatever they were at startup until the process restarts; this watch
/// does not claim otherwise.
///
/// A config that fails to parse or validate is logged and left alone — the
/// previous good routing table keeps serving rather than the daemon crashing
/// on a typo, or worse, going dark mid-edit.
async fn watch_config(server: Arc<Server>, config_path: PathBuf, project_dir: PathBuf) {
    let mut last_modified = std::fs::metadata(&config_path).and_then(|m| m.modified()).ok();
    let mut ticker = tokio::time::interval(CONFIG_POLL_INTERVAL);
    // The first tick fires immediately; skip it, since `serve` just loaded
    // the config this process is already running.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        check_and_reload(&server, &config_path, &project_dir, &mut last_modified);
    }
}

/// One check-and-maybe-reload cycle, pulled out of [`watch_config`]'s timing
/// loop so it can be driven directly in a test rather than through several
/// real seconds of ticks.
///
/// `last_modified` is the caller's own state, threaded through by `&mut`
/// rather than closed over, so a test can observe it settle without needing
/// its own copy of the watch loop.
fn check_and_reload(
    server: &Server,
    config_path: &Path,
    project_dir: &Path,
    last_modified: &mut Option<std::time::SystemTime>,
) {
    let Ok(metadata) = std::fs::metadata(config_path) else { return };
    let Ok(modified) = metadata.modified() else { return };
    if Some(modified) == *last_modified {
        return;
    }
    *last_modified = Some(modified);

    match Config::load(config_path) {
        Ok(config) => {
            server.reload(&config, project_dir);
            eprintln!("config: reloaded — {} site(s) now routed", config.sites.len());
        }
        Err(error) => eprintln!(
            "config: {} changed but does not validate ({error}) — keeping the previous config \
             live",
            config_path.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    const BASE: &str = "\
version = 1

[server]
acme_email = \"a@b.com\"
acme = \"self-signed\"

[[nodes]]
name = \"home\"
role = \"owner\"
";

    /// Writes `text` to `path` and stamps an explicit modification time, so a
    /// test never depends on the filesystem's mtime resolution or a real sleep.
    fn write_config(path: &Path, text: &str, modified: SystemTime) {
        std::fs::write(path, text).expect("write the config");
        let file = std::fs::File::options().write(true).open(path).expect("reopen the config");
        file.set_modified(modified).expect("stamp the mtime");
    }

    /// A fresh temp directory holding `selfhost.config.toml`, and its path.
    fn temp_project(tag: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("selfhost-watch-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the temp project dir");
        let config_path = dir.join(CONFIG_FILENAME);
        (dir, config_path)
    }

    #[test]
    fn a_changed_config_reloads_the_routing_table() {
        let (dir, config_path) = temp_project("reload");
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        write_config(&config_path, BASE, t0);

        let config = Config::load(&config_path).unwrap();
        let server = Server::build(&config, &dir);
        let mut last_modified = Some(t0);
        assert!(server.route("example.com").is_none(), "no site yet");

        let with_site = format!(
            "{BASE}\n[[sites]]\nname = \"a\"\ndomains = [\"example.com\"]\nstatic_root = \"./x\"\n"
        );
        write_config(&config_path, &with_site, t0 + Duration::from_secs(1));
        check_and_reload(&server, &config_path, &dir, &mut last_modified);

        assert!(server.route("example.com").is_some(), "the added site is now routed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_edit_that_no_longer_validates_is_not_applied() {
        let (dir, config_path) = temp_project("invalid");
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let with_site = format!(
            "{BASE}\n[[sites]]\nname = \"a\"\ndomains = [\"example.com\"]\nstatic_root = \"./x\"\n"
        );
        write_config(&config_path, &with_site, t0);

        let config = Config::load(&config_path).unwrap();
        let server = Server::build(&config, &dir);
        let mut last_modified = Some(t0);
        assert!(server.route("example.com").is_some());

        // Two sites claiming the same hostname does not validate.
        let broken = format!(
            "{with_site}\n[[sites]]\nname = \"b\"\ndomains = [\"example.com\"]\nstatic_root = \"./y\"\n"
        );
        write_config(&config_path, &broken, t0 + Duration::from_secs(1));
        check_and_reload(&server, &config_path, &dir, &mut last_modified);

        // The previous, valid routing table is still the one live.
        assert!(server.route("example.com").is_some(), "the last-good config is still serving");
    }

    #[test]
    fn an_unchanged_file_triggers_no_reload() {
        let (dir, config_path) = temp_project("unchanged");
        let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        write_config(&config_path, BASE, t0);

        let config = Config::load(&config_path).unwrap();
        let server = Server::build(&config, &dir);
        let mut last_modified = Some(t0);

        // Nothing on disk changed since `last_modified`, so this must be a
        // no-op rather than re-reading and re-applying the same config.
        check_and_reload(&server, &config_path, &dir, &mut last_modified);
        assert_eq!(last_modified, Some(t0));
    }
}
