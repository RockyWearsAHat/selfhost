//! The `selfhost` command-line interface.
//!
//! Argument parsing and error presentation only. The work lives in the library
//! crates so it stays callable from tests without going through `argv`.

mod doctor;

use selfhost_config::{AcmeEnvironment, Config};
use selfhost_proxy::{CertificateStore, Server, serve_http, serve_https, server_config};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
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
  doctor [--deep]            Diagnose the deployment and say how to fix it
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

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    let report = runtime.block_on(doctor::run(&config, &project_dir, deep));
    print!("{report}");

    if report.has_failures() {
        return Err("some checks failed — see the arrows above for what to do".into());
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
