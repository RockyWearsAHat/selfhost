//! `selfhost reports` — the public report intake, and the database behind it.
//!
//! Six words, one verb:
//!
//! ```text
//! selfhost reports serve [--port N] [--route /report] [--project dx] [--no-mail]
//! selfhost reports project add <key>      make a service reports may be filed against
//! selfhost reports projects               what this box holds reports for
//! selfhost reports list [<project>]       the open reports, newest sighting first
//! selfhost reports close <project> <id>   a fixed report leaves the database
//! selfhost reports token [--new]          the token a subscribed checkout reads the feed with
//! ```
//!
//! `serve` is what a supervised service runs; everything else is an operator at a terminal.
//! [`selfhost_reports`] is the authority on what the intake accepts and what it bounds — this
//! module only turns arguments into that crate's values, and it deliberately holds no rules of
//! its own.
//!
//! `project add` is now a convenience rather than a precondition: a service comes into
//! existence when the first report is filed to `…/report?<service>`, which is what lets a tool
//! nobody here has configured reach the people who fix it.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use selfhost_config::Config;
use selfhost_reports::service::{self, Service};
use selfhost_reports::{Mailbox, Store};

/// Where the intake listens when nothing says otherwise.
///
/// Loopback, and a port outside the range the console's app sites use, so a box that adds the
/// intake without editing anything else does not collide with an application.
const DEFAULT_PORT: u16 = 4003;

/// The file the owner's feed token lives in, inside the data directory.
const TOKEN_FILE: &str = "reports.token";

/// The directory the database lives in, inside the data directory.
const STORE_DIR: &str = "reports";

/// Runs `selfhost reports …`.
///
/// # Errors
/// Returns a sentence naming what to do differently: an unknown word, a missing argument, a
/// bind that is not loopback, or a store that cannot be written.
pub fn run(arguments: &[String], config: &Config, project_dir: &Path) -> Result<(), String> {
    let data_dir = crate::teardown::data_dir(config, project_dir);
    let store = Store::open(&data_dir.join(STORE_DIR)).map_err(|error| error.to_string())?;

    match arguments.get(1).map(String::as_str).unwrap_or("list") {
        "serve" => serve(arguments, config, &data_dir, store),
        "project" => project(arguments, &store),
        "projects" => projects(&store),
        "list" => list(arguments.get(2).map(String::as_str), &store),
        "close" => close(arguments, &store),
        "token" => token(arguments, &data_dir),
        other => Err(format!(
            "`{other}` is not a reports command — it is serve, project, projects, list, close, \
             or token"
        )),
    }
}

/// `selfhost reports serve` — bind the intake and answer until stopped.
fn serve(
    arguments: &[String],
    config: &Config,
    data_dir: &Path,
    store: Store,
) -> Result<(), String> {
    // A supervised service is told its port through the environment, exactly as an app site's
    // backend is (`selfhost_app_deploy`), so the config's instance port and the port bound here
    // are one number that cannot drift.
    let port: u16 =
        match crate::value_of(arguments, "--port").or_else(|| std::env::var("PORT").ok()) {
            Some(given) => given
                .trim()
                .parse()
                .map_err(|error| format!("--port {given}: {error}"))?,
            None => DEFAULT_PORT,
        };
    let bind = crate::value_of(arguments, "--bind").unwrap_or_else(|| "127.0.0.1".to_string());
    let address: SocketAddr = format!("{bind}:{port}")
        .parse()
        .map_err(|error| format!("--bind {bind} --port {port}: {error}"))?;

    let mut settings = service::Config {
        route: crate::value_of(arguments, "--route").unwrap_or_else(|| "/report".to_string()),
        token: read_token(data_dir)?,
        ..service::Config::default()
    };
    if let Some(project) = crate::value_of(arguments, "--project") {
        settings.default_project = selfhost_reports::report::project_key(&project)
            .map_err(|refusal| refusal.message().to_string())?;
    }
    // The default project always exists, so a fresh box accepts the reports it was set up for
    // rather than refusing them until an operator remembers a second command.
    store
        .add_project(&settings.default_project)
        .map_err(|error| error.to_string())?;

    settings.mail = if arguments.iter().any(|argument| argument == "--no-mail") {
        None
    } else {
        mailbox(arguments, config)?
    };

    let store_dir = store.directory().to_path_buf();
    let intake = Arc::new(Service::new(store, settings.clone()));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("could not start the async runtime: {error}"))?;

    runtime.block_on(async move {
        let listener = service::bind(address)
            .await
            .map_err(|error| format!("could not bind {address}: {error}"))?;
        println!(
            "report intake listening\n  http  {address}{}\n  store {}\n  mail  {}",
            settings.route,
            store_dir.display(),
            settings
                .mail
                .as_ref()
                .map_or_else(|| "off".to_string(), |mailbox| mailbox.to.clone())
        );
        tokio::spawn(service::retry_forever(Arc::clone(&intake)));
        service::serve(listener, intake)
            .await
            .map_err(|error| format!("the intake stopped: {error}"))
    })
}

/// The mailbox notifications go to, from the flags or from `[mail]` in the config.
///
/// A box with a mailbox of its own needs no flags: the first configured mailbox is the owner's,
/// and the sender is `reports@` in the mail hostname's domain, which is a local address this
/// box is authoritative for.
fn mailbox(arguments: &[String], config: &Config) -> Result<Option<Mailbox>, String> {
    let configured = config.mail.as_ref();
    let to = crate::value_of(arguments, "--mail-to").or_else(|| {
        configured.and_then(|mail| mail.mailboxes.first().map(|box_| box_.address.clone()))
    });
    let Some(to) = to else {
        // Not an error: an intake with nowhere to send is still an intake, and the feed is the
        // route that matters for a checkout. Said out loud so it is never a silent surprise.
        eprintln!(
            "reports: no mailbox to notify — configure [mail] or pass --mail-to, or pass \
             --no-mail to stop saying this"
        );
        return Ok(None);
    };
    let hostname = configured.map_or_else(|| "localhost".to_string(), |mail| mail.hostname.clone());
    let domain = to.rsplit('@').next().unwrap_or("localhost").to_string();
    let from =
        crate::value_of(arguments, "--mail-from").unwrap_or_else(|| format!("reports@{domain}"));
    let smtp = crate::value_of(arguments, "--smtp").unwrap_or_else(|| "127.0.0.1:25".to_string());
    let (host, port) = match smtp.rsplit_once(':') {
        Some((host, port)) => (
            host.to_string(),
            port.parse::<u16>()
                .map_err(|error| format!("--smtp {smtp}: {error}"))?,
        ),
        None => (smtp.clone(), 25),
    };
    Mailbox::new(&from, &to, &hostname, &host, port).map(Some)
}

/// `selfhost reports project add <key>`.
fn project(arguments: &[String], store: &Store) -> Result<(), String> {
    match arguments.get(2).map(String::as_str) {
        Some("add") => {
            let named = arguments.get(3).ok_or(
                "`reports project add` needs a key, e.g. `selfhost reports project add dx`",
            )?;
            let key = selfhost_reports::report::project_key(named)
                .map_err(|refusal| refusal.message().to_string())?;
            store.add_project(&key).map_err(|error| error.to_string())?;
            println!("reports about `{key}` are now accepted");
            Ok(())
        }
        _ => Err("`reports project` takes `add <key>`".to_string()),
    }
}

/// `selfhost reports projects`.
fn projects(store: &Store) -> Result<(), String> {
    let keys = store.projects().map_err(|error| error.to_string())?;
    if keys.is_empty() {
        println!("no project accepts reports yet — `selfhost reports project add dx`");
        return Ok(());
    }
    for key in keys {
        let open = store.count(&key).map_err(|error| error.to_string())?;
        println!("{key:<20} {open} open");
    }
    Ok(())
}

/// `selfhost reports list [<project>]`.
fn list(named: Option<&str>, store: &Store) -> Result<(), String> {
    let keys = match named {
        Some(named) => vec![
            selfhost_reports::report::project_key(named)
                .map_err(|refusal| refusal.message().to_string())?,
        ],
        None => store.projects().map_err(|error| error.to_string())?,
    };
    for key in keys {
        let entries = store.list(&key).map_err(|error| error.to_string())?;
        println!("{key} — {} open", entries.len());
        for entry in entries {
            println!(
                "  {} {:<11} {} — seen {}, last {}{}",
                entry.id,
                entry.kind.as_str(),
                entry.title,
                entry.sightings,
                entry.last_at,
                if entry.delivered {
                    ""
                } else {
                    " · not yet mailed"
                }
            );
        }
    }
    Ok(())
}

/// `selfhost reports close <project> <id>`.
fn close(arguments: &[String], store: &Store) -> Result<(), String> {
    let project = arguments
        .get(2)
        .ok_or("`reports close` needs a project and an id, e.g. `… close dx report-1a2b3c4d`")?;
    let id = arguments
        .get(3)
        .ok_or("`reports close` needs the report id, e.g. `… close dx report-1a2b3c4d`")?;
    let key = selfhost_reports::report::project_key(project)
        .map_err(|refusal| refusal.message().to_string())?;
    store.close(&key, id).map_err(|error| error.to_string())?;
    println!("closed {id} in {key}");
    Ok(())
}

/// `selfhost reports token [--new]` — the credential a subscribed checkout reads the feed with.
///
/// Printed rather than mailed or displayed in a UI, because the one place it has to arrive is a
/// terminal on the machine that holds the checkout, and that machine already reaches this one
/// over SSH.
fn token(arguments: &[String], data_dir: &Path) -> Result<(), String> {
    let path = data_dir.join(TOKEN_FILE);
    let fresh = arguments.iter().any(|argument| argument == "--new");
    if fresh || !path.exists() {
        let token = mint()?;
        std::fs::create_dir_all(data_dir)
            .map_err(|error| format!("could not create {}: {error}", data_dir.display()))?;
        std::fs::write(&path, format!("{token}\n"))
            .map_err(|error| format!("could not write {}: {error}", path.display()))?;
        restrict(&path);
        println!("{token}");
        eprintln!(
            "stored in {} — restart the intake to load it",
            path.display()
        );
        return Ok(());
    }
    println!("{}", read_token(data_dir)?.unwrap_or_default());
    Ok(())
}

/// The owner's feed token, when the box has one.
fn read_token(data_dir: &Path) -> Result<Option<String>, String> {
    let path = data_dir.join(TOKEN_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let token = text.trim().to_string();
            Ok((!token.is_empty()).then_some(token))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("could not read {}: {error}", path.display())),
    }
}

/// A fresh 256-bit token, hex encoded.
fn mint() -> Result<String, String> {
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "the system random source refused to seed a token".to_string())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Restricts a secret to its owner where the platform has such a concept.
fn restrict(path: &PathBuf) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}
