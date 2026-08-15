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
//! service sees tells it whether the proxy in front of it terminated TLS). The passkey routes
//! need no flag of their own: `--rp-id` is *derived* from `--public-base-url`'s host, because
//! that host is the only value a ceremony could ever verify against — see [`relying_party_id`],
//! which refuses a mismatch and declines to derive one from an address literal (`127.0.0.1`,
//! `[::1]`), since a relying party id must be a domain name. The ceremony's expected **origin**
//! is a different value and comes from the whole of `--public-base-url` — scheme, host and port
//! — so a box served at `http://localhost:8080` works. OAuth providers come from `selfhost
//! reports oauth add`, not a flag, because a client secret does not belong on a command line a
//! process list can see.
//!
//! # No invite code — see `crates/reports/src/service.rs`'s module documentation
//!
//! A reports account is never linked to a `selfhost_identity::PersonName` and never carries any
//! grant. Nothing this subsystem shows an account is visible to anyone but that account, so
//! there is nothing an invite would need to gate. Invite codes exist only for *direct server
//! access* — the NAS, the VPN, the admin console, the mesh — through `selfhost people invite`,
//! entirely separate from this command.

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
        other => Err(format!(
            "`{other}` is not a reports command — it is serve, project, projects, list, close, \
             token, or oauth"
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
/// minimum, and it must be an absolute `http(s)://` address with no trailing slash. See
/// [`check_public_base_url`] and [`relying_party_id`] for the two refusals that are about
/// security rather than spelling.
fn accounts_config(arguments: &[String], data_dir: &Path) -> Result<AccountsConfig, String> {
    let public_base_url = crate::value_of(arguments, "--public-base-url").ok_or(
        "`--accounts` needs `--public-base-url https://your.domain` — this box's own public \
         address, used to build verification links and OAuth redirects",
    )?;
    let public_base_url = public_base_url.trim_end_matches('/').to_string();
    let host = check_public_base_url(&public_base_url)?;
    let rp_id = relying_party_id(arguments, host)?;
    if rp_id.is_none() {
        // The only way to get here is an address literal — see `relying_party_id`. Said out
        // loud rather than left to the banner's "passkeys off", because "off" is the answer to
        // a question the operator did not ask and the reason is not guessable from it.
        eprintln!(
            "reports: passkeys are off — {host} is an IP address and a WebAuthn relying party \
             id must be a domain name. Reach this box by a name to turn them on."
        );
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
        rp_id,
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
        //
        // Five is only survivable because nothing at page-load frequency spends it — a signed-in
        // person's `me`/`mine`/`download` are on the page-visit budget, deliberately, so that
        // reloading an account page can never lock somebody out of signing in. The two
        // state-changing `POST`s a session makes (`me/password`, `mine/withdraw`) *are* on this
        // bucket, because replacing a credential and destroying a record are attempts at the
        // account door whatever cookie they carry. See the reports crate's "Four budgets".
        per_action: selfhost_reports::Rate::new(5, 5.0),
        // And what everybody together may attempt: two hundred at once, then two a second.
        // Deliberately far wider than one source's allowance — it is the wall against a
        // thousand sources each staying inside theirs, not a second copy of that wall, and a
        // shared bucket the size of one visitor's would refuse the third person to sign in this
        // minute.
        global_action: selfhost_reports::Rate::new(200, 120.0),
    })
}

/// Checks `--public-base-url` and answers the host inside it.
///
/// # `http://` is refused on anything but loopback
///
/// This box has a real public IP, and `docs/SECURITY.md` §3.2 is the rule this enforces: the
/// session cookie's `Secure` attribute is derived from exactly this URL (see
/// `selfhost_reports::service::Service::cookies_secure`), so `--accounts --public-base-url
/// http://reports.example.com` ships every account's session cookie with no `Secure` at all,
/// over a scheme that carries it in clear text to anyone on the path. Nothing in the running
/// service can notice — it binds loopback and never sees TLS either way — so the only place this
/// can be caught is here, before the door opens. `http://localhost` and `http://127.0.0.1` stay
/// allowed because a cookie that never leaves the machine has nothing to be stolen off of, and
/// developing against this subsystem otherwise needs a certificate.
///
/// # Errors
/// A sentence naming the flag and why the value cannot be used.
fn check_public_base_url(public_base_url: &str) -> Result<&str, String> {
    let (scheme, rest) = public_base_url
        .split_once("://")
        .filter(|(scheme, _)| *scheme == "http" || *scheme == "https")
        .ok_or_else(|| {
            format!("--public-base-url {public_base_url}: must start with http:// or https://")
        })?;
    let host = host_of_authority(rest.split('/').next().unwrap_or_default());
    if host.is_empty() {
        return Err(format!(
            "--public-base-url {public_base_url}: names no host"
        ));
    }
    if scheme == "http" && !is_loopback_host(host) {
        return Err(format!(
            "--public-base-url {public_base_url}: refusing to run `--accounts` over plain \
             http:// on {host}. This box has a real public IP, and the session cookie's \
             `Secure` attribute is taken from this URL — over http:// every account's cookie \
             would be sent in clear text and stealable by anyone on the path. Use https:// \
             (the reverse proxy terminates TLS on 443), or http://localhost for local \
             development."
        ));
    }
    Ok(host)
}

/// The host out of a URL authority, dropping a `:port` — and never mistaking an IPv6 literal's
/// own colons for one, which is why this is not a bare `rsplit_once(':')`.
fn host_of_authority(authority: &str) -> &str {
    if let Some(end) = authority.find(']') {
        return &authority[..=end];
    }
    match authority.rsplit_once(':') {
        Some((host, port))
            if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            host
        }
        _ => authority,
    }
}

/// Whether `host` is this machine talking to itself, which is the one place a cookie with no
/// `Secure` attribute has nothing to be stolen off of.
fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1")
        || host.ends_with(".localhost")
        || host.starts_with("127.")
}

/// The WebAuthn relying party id: `--rp-id` when given, otherwise `--public-base-url`'s own
/// host — and `None`, meaning the passkey routes stay off, when that host cannot be one.
///
/// # These two are one value, and disagreeing is unexplainable at runtime
///
/// The browser sends the relying party id back inside the authenticator data, as a hash, and
/// `selfhost_reports::webauthn::Webauthn` compares it against exactly this value. It is a
/// **bare host** — the specification's RP ID is a domain string, so it carries no scheme and no
/// port — and the page it runs on is `--public-base-url`, because that is the address this box
/// hands out. When the two disagree, *every* passkey ceremony fails, and it fails inside the
/// uniform "the passkey ceremony could not be verified" refusal that a forged assertion also
/// gets, because that refusal is deliberately the same for every cause. There is no log line to
/// find and no difference to observe: the door is simply, permanently shut. So a mismatch is
/// refused here, where the two values are both in hand and a sentence can say which one to
/// change.
///
/// The ceremony's expected **origin** is a different value and is no longer derived from this
/// one: `selfhost_reports` reads it whole out of `--public-base-url` (scheme, host and port).
/// Rebuilding it as `https://<rp_id>` is what broke `http://localhost:8080` — the address this
/// file's own `check_public_base_url` recommends for development — and it broke it in the
/// silent way described above.
///
/// # An IP literal is not a relying party id, and pretending otherwise switches on a dead door
///
/// WebAuthn's RP ID must be a valid domain string. `127.0.0.1`, `[::1]` and any other address
/// literal are not, and a browser refuses the ceremony before this box is ever asked — so
/// deriving one from `--public-base-url http://127.0.0.1:8080` would turn the passkey routes on
/// with a value that can never work, which is strictly worse than the clean `404` they give
/// when they are off. Derived from an IP literal, the answer is therefore `None` (and
/// [`accounts_config`] says so on the way past). Asked for *explicitly* as `--rp-id 127.0.0.1`,
/// it is an error: the operator named a value that cannot work, and silently ignoring a flag
/// somebody typed is its own kind of lie. `localhost` is a domain string, is what browsers
/// special-case as a secure context, and keeps working.
///
/// The one thing this refuses that WebAuthn itself permits is a registrable-suffix relying party
/// (`--rp-id example.com` for a page on `reports.example.com`). That is legal in the standard,
/// but this crate's RP-ID check is an exact compare, so accepting it here would produce
/// the very failure this function exists to prevent.
///
/// # Errors
/// A sentence naming both values when `--rp-id` disagrees with the public base URL's host, or
/// naming the literal when `--rp-id` is an IP address.
fn relying_party_id(arguments: &[String], host: &str) -> Result<Option<String>, String> {
    match crate::value_of(arguments, "--rp-id") {
        Some(rp_id) if rp_id != host => Err(format!(
            "--rp-id {rp_id} does not match --public-base-url's host {host}. A passkey ceremony \
             is bound to the relying party id and the browser reports the host the page was \
             served from, so these two disagreeing makes every passkey sign-in fail with an \
             error nobody can explain. Pass --rp-id {host}, or leave it off — it is derived \
             from --public-base-url."
        )),
        Some(rp_id) if !is_domain_string(&rp_id) => Err(format!(
            "--rp-id {rp_id} is an IP address, and a WebAuthn relying party id must be a domain \
             name. A browser refuses the ceremony before this box is ever asked, so turning the \
             passkey routes on with this value would give you a door that can never open. Reach \
             this box by a name (http://localhost for development), or drop --rp-id and \
             --public-base-url's host will be used when it is a name."
        )),
        Some(rp_id) => Ok(Some(rp_id)),
        None if !is_domain_string(host) => Ok(None),
        None => Ok(Some(host.to_string())),
    }
}

/// Whether `host` can be a WebAuthn relying party id — that is, whether it is a name rather than
/// an address literal.
///
/// Deliberately a *shape* test and not a resolvability test: this runs at startup with no
/// network, and the question is only whether a browser will accept the value as a domain string.
/// A bracketed IPv6 literal and anything made entirely of digits and dots are the two forms that
/// are not.
fn is_domain_string(host: &str) -> bool {
    if host.starts_with('[') {
        return false;
    }
    !host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
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

    /// `serve --accounts` derives the session cookie's `Secure` attribute from this URL, so a
    /// plain-`http://` public address on a box with a real public IP ships every account's
    /// cookie in the clear. Nothing downstream can notice; this is the only place it can be
    /// refused.
    #[test]
    fn plain_http_is_refused_as_a_public_address_but_allowed_on_loopback() {
        let refused = check_public_base_url("http://reports.example.com").expect_err("refused");
        assert!(refused.contains("--public-base-url"), "{refused}");
        assert!(refused.contains("Secure"), "{refused}");
        assert!(refused.contains("clear text"), "{refused}");

        assert_eq!(
            check_public_base_url("https://reports.example.com"),
            Ok("reports.example.com")
        );
        assert_eq!(
            check_public_base_url("http://localhost:8080"),
            Ok("localhost")
        );
        assert_eq!(
            check_public_base_url("http://127.0.0.1:8080"),
            Ok("127.0.0.1")
        );
        assert_eq!(check_public_base_url("http://[::1]:8080"), Ok("[::1]"));

        assert!(
            check_public_base_url("reports.example.com").is_err(),
            "no scheme"
        );
        assert!(check_public_base_url("ftp://reports.example.com").is_err());
        assert!(check_public_base_url("https://").is_err(), "no host");
    }

    /// A relying party id that disagrees with the address the page is served from fails every
    /// passkey ceremony, inside a refusal that is deliberately the same for every cause — so
    /// there is nothing to debug at runtime and it has to be caught here.
    #[test]
    fn the_relying_party_id_is_the_public_hosts_or_it_is_refused() {
        let none: Vec<String> = Vec::new();
        assert_eq!(
            relying_party_id(&none, "reports.example.com"),
            Ok(Some("reports.example.com".to_string())),
            "derived rather than left off, which used to turn passkeys silently off"
        );

        let agreeing = vec!["--rp-id".to_string(), "reports.example.com".to_string()];
        assert_eq!(
            relying_party_id(&agreeing, "reports.example.com"),
            Ok(Some("reports.example.com".to_string()))
        );

        let disagreeing = vec!["--rp-id".to_string(), "example.com".to_string()];
        let error = relying_party_id(&disagreeing, "reports.example.com").expect_err("refused");
        assert!(error.contains("example.com"), "{error}");
        assert!(error.contains("reports.example.com"), "{error}");
        assert!(error.contains("--rp-id reports.example.com"), "{error}");
    }

    /// A relying party id must be a domain string. Derived from an address literal it is left
    /// off — the clean `404` the passkey routes give when they are not configured — rather than
    /// switched on with a value no browser will accept, which is a door that cannot open and
    /// says nothing about why. Named explicitly it is an error, because silently ignoring a
    /// flag somebody typed is its own kind of lie.
    #[test]
    fn an_address_literal_is_not_a_relying_party_id() {
        let none: Vec<String> = Vec::new();
        for literal in ["127.0.0.1", "[::1]", "192.168.1.8"] {
            assert_eq!(
                relying_party_id(&none, literal),
                Ok(None),
                "{literal} derived a relying party id a browser will refuse"
            );
        }

        for literal in ["127.0.0.1", "[::1]"] {
            let asked = vec!["--rp-id".to_string(), literal.to_string()];
            let error = relying_party_id(&asked, literal).expect_err("refused");
            assert!(error.contains(literal), "{error}");
            assert!(error.contains("domain name"), "{error}");
        }

        // `localhost` is a domain string, is what browsers special-case as a secure context,
        // and is the address this file's own `check_public_base_url` recommends for
        // development. It keeps working, port or no port.
        assert_eq!(
            relying_party_id(&none, "localhost"),
            Ok(Some("localhost".to_string()))
        );
    }

    /// The relying party id is a bare host and the WebAuthn origin is a whole origin, and
    /// deriving the second from the first is what shut the passkey door on every deployment not
    /// served on 443. `crates/reports` reads the origin out of `public_base_url`; these are the
    /// values it gets, from the exact flags a person would type.
    #[test]
    fn the_ceremony_origin_carries_the_scheme_and_port_the_relying_party_id_drops() {
        let dir = scratch("origin-derivation");
        for (base, host, origin) in [
            (
                "https://reports.example.com",
                "reports.example.com",
                "https://reports.example.com",
            ),
            // The development address `check_public_base_url` itself recommends: a different
            // scheme *and* a port, both of which `https://<rp_id>` threw away.
            (
                "http://localhost:8080",
                "localhost",
                "http://localhost:8080",
            ),
            (
                "https://localhost:8443",
                "localhost",
                "https://localhost:8443",
            ),
        ] {
            let arguments = vec!["--public-base-url".to_string(), base.to_string()];
            let config = accounts_config(&arguments_with_from(&arguments), &dir).expect("config");
            assert_eq!(config.rp_id.as_deref(), Some(host), "{base}: relying party");
            assert_eq!(
                selfhost_reports::service::origin_of(&config.public_base_url).as_deref(),
                Some(origin),
                "{base}: ceremony origin"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `--verify-from` is required by `accounts_config` and is not what the test above is
    /// about, so it is appended rather than repeated at every call.
    fn arguments_with_from(arguments: &[String]) -> Vec<String> {
        let mut out = arguments.to_vec();
        out.push("--verify-from".to_string());
        out.push("reports@example.com".to_string());
        out
    }

    #[test]
    fn a_port_is_not_part_of_the_host_and_an_ipv6_literals_colons_are_not_a_port() {
        assert_eq!(
            host_of_authority("reports.example.com"),
            "reports.example.com"
        );
        assert_eq!(
            host_of_authority("reports.example.com:8443"),
            "reports.example.com"
        );
        assert_eq!(host_of_authority("[::1]"), "[::1]");
        assert_eq!(host_of_authority("[::1]:8080"), "[::1]");
        assert_eq!(host_of_authority("host:notaport"), "host:notaport");
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
