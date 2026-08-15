//! `selfhost reports` — the public report intake, and the database behind it.
//!
//! ```text
//! selfhost reports serve [--port N] [--route /report] [--project dx] [--no-mail]
//!                         [--accounts --public-base-url URL [--rp-id HOST] [--site-name NAME]
//!                          --verify-from ADDR]
//! selfhost reports project add <key>      make a service reports may be filed against
//! selfhost reports projects               what this box holds reports for
//! selfhost reports list [<project>]       the open reports, newest sighting first
//! selfhost reports close <project> <id>   a fixed report leaves the database
//! selfhost reports token [--new]          the token a subscribed checkout reads the feed with
//! selfhost reports oauth add|list|remove  the "sign in with…" providers accounts offers
//! selfhost reports invite <name> [--hours N]   a one-time code linking a reports account to
//!                                               a `PersonName` `selfhost people` already knows
//! selfhost reports invited                who has one pending, until when
//! selfhost reports uninvite <name>        withdraw an invitation nobody has redeemed
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
//!
//! # The account subsystem is off unless `--accounts` says otherwise
//!
//! `selfhost_reports::service::Config::accounts` defaults to `None`, and `serve` only builds one
//! when `--accounts` is on the command line — so a deployment that has never touched this flag
//! keeps behaving exactly as it did before this subsystem existed, on every redeploy. Turning it
//! on needs `--public-base-url` (this box's own address — the flag exists because nothing this
//! service sees tells it whether the proxy in front of it terminated TLS); `--rp-id` additionally
//! enables the passkey routes (unset, they answer the same `404` an unconfigured token route
//! does); OAuth providers come from `selfhost reports oauth add`, not a flag, because a client
//! secret does not belong on a command line a process list can see.
//!
//! # `reports invite` links an account to a name; it never grants anything
//!
//! `selfhost_reports::invite::Invites` is its own store, separate from `crates/admin/src/
//! invite.rs`'s console invitations — a reports account and a console passkey are different
//! credentials for possibly the same human. `selfhost reports invite <name>` only mints a code
//! that a reports account can redeem (`POST <route>/invite/redeem`) to become linked to `name`;
//! it never touches `selfhost people`'s grants, which stay exactly `selfhost people allow/grant/
//! deny`'s job, made before or after this command runs in either order.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use selfhost_config::Config;
use selfhost_json::Json;
use selfhost_reports::oauth::Provider;
use selfhost_reports::service::{self, AccountsConfig, Service};
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

/// The directory the account subsystem's own stores live in, inside the data directory —
/// deliberately a sibling of [`STORE_DIR`] rather than inside it; see
/// `selfhost_reports::service::AccountsConfig::data_dir` for why.
const ACCOUNTS_DIR: &str = "reports-accounts";

/// The file the configured OAuth providers live in, inside [`ACCOUNTS_DIR`]. CLI-managed like
/// `TOKEN_FILE`, and for the same reason: a client secret does not belong in
/// `selfhost.config.toml`, which this repository's own convention keeps free of credentials.
const OAUTH_PROVIDERS_FILE: &str = "oauth-providers.json";

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
        "oauth" => oauth_command(arguments, &data_dir.join(ACCOUNTS_DIR)),
        "invite" => invite(arguments, &data_dir.join(ACCOUNTS_DIR)),
        "invited" => invited(&data_dir.join(ACCOUNTS_DIR)),
        "uninvite" => uninvite(&data_dir.join(ACCOUNTS_DIR), invite_name_argument(arguments)?),
        other => Err(format!(
            "`{other}` is not a reports command — it is serve, project, projects, list, close, \
             token, oauth, invite, invited, or uninvite"
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

    let accounts_on = arguments.iter().any(|argument| argument == "--accounts");
    settings.accounts = if accounts_on {
        Some(accounts_config(arguments, data_dir)?)
    } else {
        None
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
            "report intake listening\n  http     {address}{}\n  store    {}\n  mail     {}\n  accounts {}",
            settings.route,
            store_dir.display(),
            settings
                .mail
                .as_ref()
                .map_or_else(|| "off".to_string(), |mailbox| mailbox.to.clone()),
            settings.accounts.as_ref().map_or_else(
                || "off".to_string(),
                |accounts| format!(
                    "on — {} ({} provider(s), passkeys {})",
                    accounts.public_base_url,
                    accounts.oauth_providers.len(),
                    if accounts.rp_id.is_some() { "on" } else { "off" }
                )
            )
        );
        tokio::spawn(service::retry_forever(Arc::clone(&intake)));
        service::serve(listener, intake)
            .await
            .map_err(|error| format!("the intake stopped: {error}"))
    })
}

/// Builds [`AccountsConfig`] from `serve`'s flags and this box's persisted OAuth providers.
///
/// # Errors
/// A sentence naming the missing or malformed flag: `--accounts` needs `--public-base-url` at
/// minimum, and it must be an absolute `http(s)://` address with no trailing slash.
fn accounts_config(arguments: &[String], data_dir: &Path) -> Result<AccountsConfig, String> {
    let public_base_url = crate::value_of(arguments, "--public-base-url").ok_or(
        "`--accounts` needs `--public-base-url https://your.domain` — this box's own public \
         address, used to build verification links and OAuth redirects",
    )?;
    let public_base_url = public_base_url.trim_end_matches('/').to_string();
    if !public_base_url.starts_with("http://") && !public_base_url.starts_with("https://") {
        return Err(format!(
            "--public-base-url {public_base_url}: must start with http:// or https://"
        ));
    }
    let accounts_dir = data_dir.join(ACCOUNTS_DIR);
    let verify_from = crate::value_of(arguments, "--verify-from").ok_or(
        "`--accounts` needs `--verify-from reports@your.domain` — the sender address on a \
         verification email",
    )?;
    Ok(AccountsConfig {
        data_dir: accounts_dir.clone(),
        site_name: crate::value_of(arguments, "--site-name")
            .unwrap_or_else(|| "this box's reports".to_string()),
        public_base_url,
        rp_id: crate::value_of(arguments, "--rp-id"),
        oauth_providers: load_oauth_providers(&accounts_dir)?,
        verify_helo: crate::value_of(arguments, "--verify-helo").unwrap_or_else(|| {
            verify_from
                .rsplit('@')
                .next()
                .unwrap_or("localhost")
                .to_string()
        }),
        verify_from,
        // The daemon's own data directory — the same tree its outbound mail sweep already
        // drains. Set unconditionally: harmless if this box's `[mail]` is never configured
        // (nothing ever drains the spool, so accounts still work, just never send a
        // verification email — the same degraded shape `--no-mail` gives report notifications)
        // and correct the moment it is, with no restart-order dependency to get right.
        mail_data_dir: Some(data_dir.to_path_buf()),
        // Five attempts, then one every twelve seconds: generous for a person mistyping a
        // password, a wall for a script trying many.
        per_action: selfhost_reports::Rate::new(5, 5.0),
        // The box's own top-level data directory — *not* `accounts_dir` above, which is this
        // subsystem's own sibling. `POST <route>/me` and `POST <route>/invite/redeem` read
        // `selfhost_identity::People` from here, the same file `selfhost people` writes, so a
        // grant made through that command is the grant this door reads back.
        identity_data_dir: data_dir.to_path_buf(),
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

/// `selfhost reports oauth add|list|remove` — the "sign in with…" providers `serve --accounts`
/// offers. Its own subcommand rather than flags on `serve`, because a client secret is a
/// credential and a credential does not belong on a command line a process list can see, or in
/// `selfhost.config.toml`, which this repository keeps free of them by the same convention
/// `[mail]`'s own secrets follow.
fn oauth_command(arguments: &[String], accounts_dir: &Path) -> Result<(), String> {
    match arguments.get(2).map(String::as_str) {
        Some("add") => oauth_add(arguments, accounts_dir),
        Some("list") | None => oauth_list(accounts_dir),
        Some("remove") => oauth_remove(arguments, accounts_dir),
        Some(other) => Err(format!(
            "`reports oauth {other}` — it is add, list, or remove"
        )),
    }
}

/// `selfhost reports oauth add <provider> --authorize-url U --token-url U --userinfo-url U
/// --client-id X --client-secret Y [--scope S] [--subject-field F] [--email-field F]
/// [--email-verified-field F]`.
///
/// Adding a provider that already exists replaces it — an operator rotating a client secret
/// runs this again rather than removing and re-adding, the same "mint again supersedes" shape
/// `crates/admin/src/invite.rs` gives an invitation.
fn oauth_add(arguments: &[String], accounts_dir: &Path) -> Result<(), String> {
    let name = arguments
        .get(3)
        .filter(|name| !name.starts_with("--"))
        .ok_or("`reports oauth add` needs a provider name, e.g. `… add google`")?
        .to_string();
    let need = |flag: &str| -> Result<String, String> {
        crate::value_of(arguments, flag).ok_or_else(|| format!("`reports oauth add` needs {flag}"))
    };
    let provider = Provider {
        name: name.clone(),
        authorize_url: need("--authorize-url")?,
        token_url: need("--token-url")?,
        userinfo_url: need("--userinfo-url")?,
        client_id: need("--client-id")?,
        client_secret: need("--client-secret")?,
        scope: crate::value_of(arguments, "--scope").unwrap_or_else(|| "openid email".to_string()),
        subject_field: crate::value_of(arguments, "--subject-field")
            .unwrap_or_else(|| "sub".to_string()),
        email_field: crate::value_of(arguments, "--email-field")
            .unwrap_or_else(|| "email".to_string()),
        email_verified_field: crate::value_of(arguments, "--email-verified-field"),
    };
    let mut providers = load_oauth_providers(accounts_dir)?;
    providers.retain(|existing| existing.name != name);
    providers.push(provider);
    save_oauth_providers(accounts_dir, &providers)?;
    println!("provider `{name}` saved — restart `selfhost reports serve --accounts …` to load it");
    Ok(())
}

/// `selfhost reports oauth list` — names and URLs only; a client secret is never printed once
/// it has been written, the same write-only shape the console password and every credential
/// file in `crates/admin` already take.
fn oauth_list(accounts_dir: &Path) -> Result<(), String> {
    let providers = load_oauth_providers(accounts_dir)?;
    if providers.is_empty() {
        println!("no sign-in provider is configured — `selfhost reports oauth add <name> …`");
        return Ok(());
    }
    for provider in providers {
        println!(
            "{:<12} authorize {}\n{:<12} token     {}\n{:<12} userinfo  {}",
            provider.name,
            provider.authorize_url,
            "",
            provider.token_url,
            "",
            provider.userinfo_url
        );
    }
    Ok(())
}

/// `selfhost reports oauth remove <provider>`.
fn oauth_remove(arguments: &[String], accounts_dir: &Path) -> Result<(), String> {
    let name = arguments
        .get(3)
        .ok_or("`reports oauth remove` needs a provider name")?;
    let mut providers = load_oauth_providers(accounts_dir)?;
    let before = providers.len();
    providers.retain(|provider| &provider.name != name);
    if providers.len() == before {
        return Err(format!("no such provider `{name}`"));
    }
    save_oauth_providers(accounts_dir, &providers)?;
    println!("provider `{name}` removed");
    Ok(())
}

/// `selfhost reports invite <name> [--hours N]` — mints a one-time code that lets whoever holds
/// it link a reports account to `name`.
///
/// Deliberately does not touch `selfhost people`'s registry: this command produces the
/// *credential* a reports account proves the link with, and nothing here decides what `name`
/// may do once linked — that stays `selfhost people allow/grant/deny`'s job entirely, run before
/// or after this one in either order. See this module's own documentation for why the two are
/// kept apart, the same reasoning `crates/admin/src/invite.rs` gives its own console invitation.
fn invite(arguments: &[String], accounts_dir: &Path) -> Result<(), String> {
    let name = invite_name_argument(arguments)?;
    let hours = invite_hours_argument(arguments)?;
    let code = selfhost_reports::invite::Invites::load(accounts_dir)
        .mint(&name, hours)
        .map_err(|error| format!("could not write the invitation: {error}"))?;

    println!("an invitation for {name}, good for {hours} hours and usable once");
    println!();
    println!("  Their code is:");
    println!();
    println!("    {code}");
    println!();
    println!(
        "  Send them <this box's public address><route>/ (`<route>` is whatever `selfhost \
         reports serve` was given as `--route` — `/report` unless it was changed) — that page \
         has a \"have an invite code?\" field that POSTs it for them. No account for them yet? \
         They paste the code alongside a fresh email and password; already have one? They sign \
         in first and paste the code alone."
    );
    println!();
    println!(
        "  Driving it by hand instead: with no reports account yet, POST \
         `<route>/invite/redeem` with {{\"code\":\"{code}\",\"email\":…,\"password\":…}} and it \
         creates one, linked, and signed in. Already signed in to one, the body is just \
         {{\"code\":\"{code}\"}} and it links the account that is already there."
    );
    println!();
    println!(
        "  The code works once and is not stored anywhere it can be read back, so send it now \
         — if it is lost, run this again and the old one stops working."
    );
    println!();
    println!(
        "  A running `selfhost reports serve --accounts …` loaded its invitations once, at \
         startup, and does not watch this file — this code is invisible to it until it \
         restarts, the same as a freshly added `reports oauth` provider."
    );
    Ok(())
}

/// `selfhost reports invited` — who has an invitation pending, and until when.
fn invited(accounts_dir: &Path) -> Result<(), String> {
    let outstanding = selfhost_reports::invite::Invites::load(accounts_dir).outstanding();
    if outstanding.is_empty() {
        println!("No invitation is pending.");
        println!();
        println!("  selfhost reports invite <name>");
        println!();
        println!("mints one, and prints the code to send.");
        return Ok(());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);
    for entry in &outstanding {
        let left = entry.expires_unix.saturating_sub(now);
        println!();
        println!("{}", entry.name);
        println!("  expires in {} hours", left / 3_600);
    }
    println!();
    println!(
        "{} pending. The codes themselves are not stored and cannot be shown again.",
        outstanding.len()
    );
    Ok(())
}

/// `selfhost reports uninvite <name>` — withdraws an invitation nobody has redeemed.
fn uninvite(accounts_dir: &Path, name: selfhost_identity::PersonName) -> Result<(), String> {
    match selfhost_reports::invite::Invites::load(accounts_dir).revoke(&name) {
        Ok(true) => {
            println!("the invitation for {name} is withdrawn and its code opens nothing");
            Ok(())
        }
        Ok(false) => Err(format!("{name} has no invitation pending; nothing changed")),
        Err(error) => Err(format!("could not write the invitations: {error}")),
    }
}

/// The person named by the third argument to `reports invite`/`reports uninvite`, validated.
fn invite_name_argument(arguments: &[String]) -> Result<selfhost_identity::PersonName, String> {
    let text = arguments
        .get(2)
        .ok_or("which person? e.g. `selfhost reports invite mom`")?;
    selfhost_identity::PersonName::parse(text).map_err(|_| {
        format!(
            "\"{text}\" is not a usable person name: lower-case letters, digits and dashes, and \
             never the owner's own name, which names an authority that is not granted"
        )
    })
}

/// The `--hours N` pair on `reports invite`, or [`selfhost_reports::invite::DEFAULT_TTL_HOURS`]
/// when it is not given.
fn invite_hours_argument(arguments: &[String]) -> Result<u64, String> {
    let Some(index) = arguments.iter().position(|word| word == "--hours") else {
        return Ok(selfhost_reports::invite::DEFAULT_TTL_HOURS);
    };
    let text = arguments
        .get(index + 1)
        .ok_or_else(|| "--hours needs a number of hours after it".to_owned())?;
    let hours: u64 = text
        .parse()
        .map_err(|_| format!("\"{text}\" is not a number of hours"))?;
    if hours == 0 {
        return Err("an invitation that lasts no time cannot be used".to_owned());
    }
    Ok(hours.min(selfhost_reports::invite::MAX_TTL_HOURS))
}

/// Where the OAuth provider file lives for a given accounts directory.
fn oauth_providers_path(accounts_dir: &Path) -> PathBuf {
    accounts_dir.join(OAUTH_PROVIDERS_FILE)
}

/// Loads every configured provider. A missing file is an empty list; a malformed one is an
/// error naming the file, rather than silently discarding an operator's configuration — unlike
/// the daemon's own credential stores, this file is never written by anything but this command,
/// so a malformed one is this operator's own typo to fix, not a stranger's input to fail closed
/// against.
///
/// # Errors
/// A sentence naming the file and what could not be read or parsed.
fn load_oauth_providers(accounts_dir: &Path) -> Result<Vec<Provider>, String> {
    let path = oauth_providers_path(accounts_dir);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("could not read {}: {error}", path.display())),
    };
    let value =
        selfhost_json::parse(&text).map_err(|error| format!("{}: {error}", path.display()))?;
    let items = value
        .get("providers")
        .and_then(Json::as_array)
        .ok_or_else(|| format!("{}: expected a `providers` array", path.display()))?;
    let field = |item: &Json, key: &str| -> Result<String, String> {
        item.get(key)
            .and_then(Json::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("{}: `{key}` is missing on a provider", path.display()))
    };
    let mut providers = Vec::new();
    for item in items {
        providers.push(Provider {
            name: field(item, "name")?,
            authorize_url: field(item, "authorizeUrl")?,
            token_url: field(item, "tokenUrl")?,
            userinfo_url: field(item, "userinfoUrl")?,
            client_id: field(item, "clientId")?,
            client_secret: field(item, "clientSecret")?,
            scope: field(item, "scope")?,
            subject_field: field(item, "subjectField")?,
            email_field: field(item, "emailField")?,
            email_verified_field: item
                .get("emailVerifiedField")
                .and_then(Json::as_str)
                .map(str::to_string),
        });
    }
    Ok(providers)
}

/// Writes every configured provider, owner-only, via a temporary file and rename — the same
/// atomic-replace shape every credential file in this workspace uses.
///
/// # Errors
/// A sentence naming the directory or file that could not be written.
fn save_oauth_providers(accounts_dir: &Path, providers: &[Provider]) -> Result<(), String> {
    std::fs::create_dir_all(accounts_dir)
        .map_err(|error| format!("could not create {}: {error}", accounts_dir.display()))?;
    let value = Json::object([(
        "providers",
        Json::array(providers.iter().map(|provider| {
            Json::object([
                ("name", Json::string(&provider.name)),
                ("authorizeUrl", Json::string(&provider.authorize_url)),
                ("tokenUrl", Json::string(&provider.token_url)),
                ("userinfoUrl", Json::string(&provider.userinfo_url)),
                ("clientId", Json::string(&provider.client_id)),
                ("clientSecret", Json::string(&provider.client_secret)),
                ("scope", Json::string(&provider.scope)),
                ("subjectField", Json::string(&provider.subject_field)),
                ("emailField", Json::string(&provider.email_field)),
                (
                    "emailVerifiedField",
                    provider
                        .email_verified_field
                        .as_ref()
                        .map_or(Json::Null, Json::string),
                ),
            ])
        })),
    )]);
    let path = oauth_providers_path(accounts_dir);
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, value.to_text())
        .map_err(|error| format!("could not write {}: {error}", temporary.display()))?;
    restrict(&temporary);
    std::fs::rename(&temporary, &path)
        .map_err(|error| format!("could not store {}: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "selfhost-cli-reports-oauth-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn a_provider_with_no_secrets_file_is_an_empty_list() {
        let dir = scratch("empty");
        assert!(load_oauth_providers(&dir).expect("empty list").is_empty());
    }

    #[test]
    fn adding_and_listing_a_provider_round_trips_every_field() {
        let dir = scratch("roundtrip");
        let provider = Provider {
            name: "google".to_string(),
            authorize_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo".to_string(),
            client_id: "client-123".to_string(),
            client_secret: "secret-456".to_string(),
            scope: "openid email".to_string(),
            subject_field: "sub".to_string(),
            email_field: "email".to_string(),
            email_verified_field: Some("email_verified".to_string()),
        };
        save_oauth_providers(&dir, std::slice::from_ref(&provider)).expect("saved");
        let loaded = load_oauth_providers(&dir).expect("loaded");
        assert_eq!(loaded, vec![provider]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn saving_the_same_name_twice_replaces_rather_than_duplicates() {
        let dir = scratch("replace");
        let arguments = |secret: &str| {
            vec![
                "reports".to_string(),
                "oauth".to_string(),
                "add".to_string(),
                "google".to_string(),
                "--authorize-url".to_string(),
                "https://a".to_string(),
                "--token-url".to_string(),
                "https://t".to_string(),
                "--userinfo-url".to_string(),
                "https://u".to_string(),
                "--client-id".to_string(),
                "id".to_string(),
                "--client-secret".to_string(),
                secret.to_string(),
            ]
        };
        oauth_add(&arguments("first-secret"), &dir).expect("added");
        oauth_add(&arguments("rotated-secret"), &dir).expect("added again");
        let loaded = load_oauth_providers(&dir).expect("loaded");
        assert_eq!(loaded.len(), 1, "one provider, not two");
        assert_eq!(loaded[0].client_secret, "rotated-secret");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn removing_an_unknown_provider_is_refused_by_name() {
        let dir = scratch("remove-unknown");
        let error = oauth_remove(
            &[
                "reports".to_string(),
                "oauth".to_string(),
                "remove".to_string(),
                "nope".to_string(),
            ],
            &dir,
        )
        .expect_err("refused");
        assert!(error.contains("no such provider"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_oauth_provider_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        save_oauth_providers(&dir, &[]).expect("saved");
        let mode = std::fs::metadata(oauth_providers_path(&dir))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "no group or world access: mode {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
