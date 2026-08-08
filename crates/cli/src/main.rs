//! The `selfhost` command-line interface.
//!
//! Argument parsing and error presentation only. The work lives in the library
//! crates so it stays callable from tests without going through `argv`.

mod acme_task;
mod assess;
mod dns_status;
mod doctor;
mod identify;
mod investigate;
mod mail_task;
mod oui;
mod proxyware;
mod service_install;
mod site;
mod teardown;
mod watch;

use selfhost_admin::{Api, Store, Token};
use selfhost_config::{AcmeEnvironment, Config};
use selfhost_dns::Resolver;
use selfhost_dns::authority::{Authority, DnsError};
use selfhost_supervisor::Supervisor;
use selfhost_proxy::{
    CertificateStore, Server, SniResolver, serve_http, serve_https, server_config_with_resolver,
};
use std::net::SocketAddr;
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
  site <list|show|add|remove>
                             List, inspect, add, or unroute a website

  doctor [--deep] [--scan-lan]
                             Diagnose, and chase the cause of anything broken
  watch-dns [--bind <addr>] [--upstream <addr>]
                             Answer DNS for the network and name the device
                             asking for a residential proxy service
  dns                        Show the zone this machine serves and whether it
                             is answering on port 53
  serve-dns [--bind <addr>]  Serve authoritative DNS for the configured zones in
                             the foreground (the daemon serves them too)
  run                        Start the proxy in the foreground
  daemon [--bind <addr>]     Run the services and the control API the console
                             connects to
  services                   List the installed services and what they are doing
  teardown [--everything] [--yes]
                             Stop, uninstall, and remove what the daemon created
  service <install|uninstall|status> [--system] [--yes]
                             Register this daemon with the OS service manager
                             (launchd, systemd, or a Windows scheduled task) so it
                             starts on boot and restarts if it dies
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
        "dns" => dns_command(),
        "serve-dns" => serve_dns_command(&arguments),
        "run" => run(),
        "daemon" => daemon_command(&arguments),
        "services" => services_command(),
        "teardown" => teardown_command(&arguments),
        "service" => service_command(&arguments),
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
"#
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

/// Runs the supervised services and the control API the console drives.
///
/// Separate from `run` for now: `run` serves websites, this runs services. They
/// merge once the console can drive both from one place.
fn daemon_command(arguments: &[String]) -> Result<(), String> {
    let (config, project_dir) = load()?;
    let bind = value_of(arguments, "--bind").unwrap_or_else(|| config.server.admin_bind.clone());
    let address: SocketAddr = bind.parse().map_err(|e| format!("--bind {bind}: {e}"))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    runtime.block_on(serve_daemon(config, project_dir, address))
}

/// Loads the catalogue, starts everything automatic, and serves the API.
async fn serve_daemon(
    config: Config,
    project_dir: PathBuf,
    address: SocketAddr,
) -> Result<(), String> {
    let data_dir = project_dir.join(&config.server.data_dir);
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("cannot create {}: {e}", data_dir.display()))?;

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

    // The firewall the daemon drives for the public listeners. Built from config,
    // reconciled once here so the ports are open (or closed) before the API is
    // reachable, then kept honest by the drift watch in the select! below.
    //
    // A firewall that could not be set is reported and non-fatal, exactly like
    // `home::record`: the daemon still supervises services, and the listeners are
    // left governed by whatever the host firewall already holds. A known-unset
    // firewall the operator can see beats a daemon that refused to start.
    let firewall = selfhost_firewall::Manager::for_server(&config.server);
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
            Some(Authority::for_config(&config, public_ip))
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

    let api =
        Api::new(supervisor.clone(), store, token, watches.clone(), firewall.clone());
    let outcome = tokio::select! {
        result = selfhost_admin::serve(listener, api) => {
            result.map_err(|e| format!("the control api stopped: {e}"))
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
    outcome
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

/// Shows the zone this machine serves and whether it is answering on port 53.
///
/// Read-only and needs no running daemon to describe the zone — the preview is
/// derived from the config the same way the server derives it — but it also
/// probes the bind so the reader learns whether the server is actually up.
fn dns_command() -> Result<(), String> {
    let (config, _project_dir) = load()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    runtime.block_on(dns_status::show(&config))
}

/// Serves authoritative DNS in the foreground, without the rest of the daemon.
///
/// The `daemon` command already serves DNS alongside everything else; this is
/// the `run`-to-`daemon` counterpart — a way to bring up and test just the
/// authority. `watch-dns` is the other DNS command and does the opposite job: it
/// *forwards* queries to diagnose the network, whereas this *answers* them
/// authoritatively for the configured zones.
fn serve_dns_command(arguments: &[String]) -> Result<(), String> {
    let (config, _project_dir) = load()?;
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

    runtime.block_on(serve_dns_foreground(config, bind))
}

/// Binds the authority and serves until interrupted.
async fn serve_dns_foreground(config: Config, bind: SocketAddr) -> Result<(), String> {
    let public_ip = doctor::discover_public_ip().await;
    let authority = Authority::for_config(&config, public_ip);

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

    println!("This will register the selfhost daemon as a {} service:\n", plan.mechanism);
    println!("  name          {}", plan.label);
    println!("  runs          {}", plan.argv.join(" "));
    println!("  working dir   {}", plan.working_dir.display());
    println!("  unit file     {}", plan.path.display());
    println!("\nThe unit that will be written:\n");
    for line in plan.contents.lines() {
        println!("  {line}");
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

/// Starts the proxy and blocks until interrupted.
fn run() -> Result<(), String> {
    let (config, project_dir) = load()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    runtime.block_on(serve(config, project_dir))
}

/// Binds the listeners and serves until interrupted.
async fn serve(config: Config, project_dir: PathBuf) -> Result<(), String> {
    // A process-wide crypto provider must be installed before any rustls
    // configuration is built.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let server = Arc::new(Server::build(&config, &project_dir));
    server.spawn_health_tasks();

    let data_dir = project_dir.join(&config.server.data_dir);
    let store = CertificateStore::open(&data_dir).map_err(|e| e.to_string())?;

    // The fallback identity: served on :443 the instant the daemon binds, and for
    // any SNI that has no certificate of its own. A self-signed pair is generated
    // once so the resolver always has something to answer with, even on a first
    // start with nothing on disk and before any ACME exchange has completed.
    let primary = config
        .sites
        .first()
        .map(|s| s.canonical().to_owned())
        .unwrap_or_else(|| "localhost".to_owned());
    let alternates: Vec<String> = config.sites.iter().flat_map(|s| s.domains.clone()).collect();
    store
        .load_or_generate_self_signed(&primary, &alternates)
        .map_err(|e| e.to_string())?;

    // Per-host certificate selection via SNI. Rebuildable at runtime, so a
    // freshly issued certificate takes effect without restarting the daemon.
    let resolver = SniResolver::new(&store, &store.hosts(), &primary).map_err(|e| e.to_string())?;

    // For staging or production, fetch real certificates in the background. The
    // task is spawned before the listeners bind so the HTTP-01 responder on :80
    // is already answering when the CA calls back. Self-signed needs no CA, no
    // network, and no task — the resolver already holds the generated pair.
    //
    // Staging is the safe default (config-enforced): a first run against a domain
    // that does not yet resolve here cannot burn the production rate limit.
    if !matches!(config.server.acme, AcmeEnvironment::SelfSigned) {
        tokio::spawn(acme_task::issue_and_renew(
            config.clone(),
            project_dir.clone(),
            store.clone(),
            Arc::clone(&resolver),
        ));
    }

    // Mail rides alongside the proxy rather than under `daemon`: it needs the
    // certificate store above, and — like the proxy — is meant to be up for
    // as long as `run` is. A no-op when `config.mail` is absent.
    mail_task::run(config.clone(), project_dir.clone(), store.clone()).await;

    let tls_config = server_config_with_resolver(resolver).map_err(|e| e.to_string())?;

    let http = TcpListener::bind(&config.server.http_bind)
        .await
        .map_err(|e| format!("cannot bind {} — {e}", config.server.http_bind))?;
    let https = TcpListener::bind(&config.server.https_bind)
        .await
        .map_err(|e| format!("cannot bind {} — {e}", config.server.https_bind))?;

    println!("selfhost listening");
    println!("  http  {}  (redirects to https)", config.server.http_bind);
    println!("  https {}", config.server.https_bind);
    for site in &config.sites {
        let instances = site.instances.len();
        println!("  site  {} → {} ({instances} instance(s))", site.canonical(), site.name);
    }
    println!("\nCtrl-C to stop.");

    tokio::select! {
        result = serve_http(http, Arc::clone(&server)) => {
            result.map_err(|e| format!("http listener stopped: {e}"))
        }
        result = serve_https(https, Arc::clone(&server), tls_config) => {
            result.map_err(|e| format!("https listener stopped: {e}"))
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\nstopping");
            Ok(())
        }
    }
}
