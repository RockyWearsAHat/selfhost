//! The `selfhost` command-line interface.
//!
//! Argument parsing and error presentation only. The work lives in the library
//! crates so it stays callable from tests without going through `argv`.

mod assess;
mod doctor;
mod identify;
mod investigate;
mod oui;
mod proxyware;
mod watch;

use selfhost_config::{AcmeEnvironment, Config};
use selfhost_dns::Resolver;
use selfhost_proxy::{CertificateStore, Server, serve_http, serve_https, server_config};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::net::TcpListener;

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
  doctor [--deep] [--scan-lan]
                             Diagnose, and chase the cause of anything broken
  watch-dns [--bind <addr>] [--upstream <addr>]
                             Answer DNS for the network and name the device
                             asking for a residential proxy service
  run                        Start the proxy in the foreground
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
        "doctor" => doctor_command(&arguments),
        "watch-dns" => watch_command(&arguments),
        "run" => run(),
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
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let server = Arc::new(Server::build(&config, &project_dir));
    server.spawn_health_tasks();

    let data_dir = project_dir.join(&config.server.data_dir);
    let store = CertificateStore::open(&data_dir).map_err(|e| e.to_string())?;

    // One certificate covering every configured hostname. Per-host selection via
    // SNI arrives with the ACME client, which is the next piece of work.
    let primary = config
        .sites
        .first()
        .map(|s| s.canonical().to_owned())
        .unwrap_or_else(|| "localhost".to_owned());
    let alternates: Vec<String> = config.sites.iter().flat_map(|s| s.domains.clone()).collect();

    let (chain, key) = match config.server.acme {
        AcmeEnvironment::SelfSigned => store
            .load_or_generate_self_signed(&primary, &alternates)
            .map_err(|e| e.to_string())?,
        other => {
            return Err(format!(
                "ACME mode {other:?} is not implemented yet — the ACME client is the next piece \
                 of work. Use acme = \"self-signed\" until then."
            ));
        }
    };

    let tls_config = server_config(chain, key).map_err(|e| e.to_string())?;

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
