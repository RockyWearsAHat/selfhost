//! `selfhost repo` — the repositories the GitHub App can see, and what this
//! deployment has done with each one.
//!
//! The GitHub App increments (`crates/services/github-app`, wired into
//! `crates/app/proxy/src/server.rs`) give a box a webhook receiver and a
//! TOML-backed [`selfhost_github_app::Store`] recording which accounts have
//! installed the App and which repositories it can see. Nothing before this
//! module reads that store back out for an operator — `selfhost repo` is the
//! front door onto it: `list` joins it against the daemon-owned service
//! catalogue to show what, if anything, each tracked repo deploys as; `logs`
//! shows a repo's webhook receipts and, where one exists, its running
//! service's process log; `configure` turns a tracked repo into a running
//! application, the same way `selfhost app deploy` would if the application
//! already existed.
//!
//! # Why `configure` always needs a running daemon
//!
//! `selfhost app deploy` has two paths — through a running daemon, or locally
//! when none is running — because *redeploying* an already-installed service
//! only ever means "stop it, update it, start it again", and a command line
//! can safely do that to nothing it does not already know is unsupervised.
//! `configure` is different: it *installs a service that has never run
//! before*, and the daemon's `PUT /api/services/<name>` route is the only
//! place that both writes the catalogue and hands the new service to a
//! running supervisor in one step. A local install would either write the
//! catalogue without starting anything (a service the next `selfhost health`
//! reports as down, for no reason an operator could see) or start a second,
//! unsupervised supervisor purely to promptly kill it again — which is
//! exactly the trap `app deploy`'s module docs describe for redeploys, and
//! worse here because nothing was ever safely running to protect. So
//! `configure` refuses cleanly when no daemon answers, rather than guessing.

use selfhost_app_deploy::AppSpec;
use selfhost_config::Config;
use selfhost_github_app::{InstallationState, Store, TrackedRepo};
use std::net::SocketAddr;
use std::path::Path;

use crate::app_command::{self, Daemon};

/// How many log lines `repo logs` shows by default.
const DEFAULT_LOG_LINES: usize = 50;

/// The most log lines ever fetched from the daemon in one request, before this
/// command trims to the requested `--lines` count itself.
///
/// The admin API's `/logs` route answers "everything after sequence N", oldest
/// first, not "the last N lines" — there is no route for that. Asking for a
/// generous cap and keeping only the tail client-side is simpler than adding a
/// second query shape to that route for the one caller that wants it.
const LOG_FETCH_CAP: usize = 5_000;

/// The words this command accepts after `repo`, and what each one is for.
pub const USAGE: &str = "\
Usage
  selfhost repo list                             Every repo the GitHub App can
                                                  see, and what it deploys as
  selfhost repo logs <owner>/<repo> [--lines N]   Webhook receipts and, if a
                                                  service is configured, its
                                                  process log (default: 50)
  selfhost repo configure <owner>/<repo> --node <node> --port <port>
                          --serve <cmd...> [--build <cmd...>]
                          [--domain <host>]...
                                                  Install a tracked repo as a
                                                  running application

`configure` always asks the running daemon — see the module docs for why there
is no local-only path here, unlike `selfhost app deploy`.

Private repositories are cloned over plain HTTPS in this release; the GitHub
App's installation token is not wired into the clone yet (a follow-up).
";

/// Runs the command. `arguments[0]` is the word `repo`.
pub fn run(arguments: &[String], config: &Config, project_dir: &Path) -> Result<(), String> {
    let data_dir = project_dir.join(&config.server.data_dir);
    match arguments.get(1).map(String::as_str) {
        None | Some("list") => list(config, &data_dir),
        Some("logs") => logs(arguments, config, &data_dir),
        Some("configure") => configure(arguments, config, &data_dir),
        Some(other) => Err(format!("unknown repo subcommand \"{other}\"\n\n{USAGE}")),
    }
}

/// Loads the GitHub App installation store, or explains why there is none.
fn open_store(config: &Config, data_dir: &Path) -> Result<Store, String> {
    if config.github_app.is_none() {
        return Err(
            "no [github_app] section is configured — nothing is tracked yet. Install the GitHub \
             App on github.com and add [github_app] to selfhost.config.toml first."
                .to_owned(),
        );
    }
    let path = selfhost_github_app::store_path(data_dir);
    Store::load(path).map_err(|error| error.to_string())
}

/// `selfhost repo list`.
fn list(config: &Config, data_dir: &Path) -> Result<(), String> {
    let store = match open_store(config, data_dir) {
        Ok(store) => store,
        Err(message) => {
            println!("{message}");
            return Ok(());
        }
    };
    let state = store.state().map_err(|error| error.to_string())?;

    if state.installations.iter().all(|installation| installation.repos.is_empty()) {
        println!(
            "the GitHub App is configured but no installation has selected any repositories yet"
        );
        return Ok(());
    }

    let admin_store = selfhost_admin::Store::new(data_dir);
    let node_names: Vec<&str> = config.nodes.iter().map(|n| n.name.as_str()).collect();
    let catalog = admin_store.load(&node_names).map_err(|error| error.to_string())?;

    let rows = rows_for(&state, &catalog);
    let account_width = rows.iter().map(|(a, _, _)| a.len()).max().unwrap_or(7).max(7);
    let repo_width = rows.iter().map(|(_, r, _)| r.len()).max().unwrap_or(10).max(10);
    println!("  {:<account_width$}  {:<repo_width$}  STATUS", "ACCOUNT", "OWNER/REPO");
    for (account, repo, status) in rows {
        println!("  {account:<account_width$}  {repo:<repo_width$}  {status}");
    }
    Ok(())
}

/// Builds the printable rows for `repo list`: one per tracked repo, joined
/// against the service catalogue for its status.
///
/// Pure and separate from [`list`] so the join logic — the part with any real
/// judgment in it — is exercised without a store or a catalogue file on disk.
fn rows_for(state: &InstallationState, catalog: &selfhost_config::ServiceCatalog) -> Vec<(String, String, String)> {
    let mut rows = Vec::new();
    for installation in &state.installations {
        for repo in &installation.repos {
            let installed = catalog.services.iter().any(|spec| {
                spec.git.as_ref().is_some_and(|watch| {
                    selfhost_github_app::repository_matches(&watch.repository, &repo.owner, &repo.name)
                })
            });
            rows.push((
                installation.account_login.clone(),
                format!("{}/{}", repo.owner, repo.name),
                status_of(installed, repo.last_deploy_outcome.as_deref()),
            ));
        }
    }
    rows
}

/// The one-line status a tracked repo shows in `repo list`.
///
/// `installed` means a service in the catalogue has a Git watch pointed at
/// this repo — i.e. `repo configure` (or a hand-edited `data/services.toml`)
/// has already turned it into an application. `last_deploy_outcome` comes
/// straight from the installation store, which only a push webhook or
/// `record_deploy_outcome` ever sets, so its presence alone is what tells
/// "configured but never pushed to" apart from "deployed at least once".
fn status_of(installed: bool, last_deploy_outcome: Option<&str>) -> String {
    if !installed {
        return "installed (no config)".to_owned();
    }
    match last_deploy_outcome {
        None => "configured (never deployed)".to_owned(),
        Some(outcome) => format!("configured (live, last deploy: {outcome})"),
    }
}

/// Splits `owner/repo` into its two parts, or explains the expected shape.
fn split_owner_repo(argument: &str) -> Result<(String, String), String> {
    match argument.split_once('/') {
        Some((owner, repo)) if !owner.is_empty() && !repo.is_empty() && !repo.contains('/') => {
            Ok((owner.to_owned(), repo.to_owned()))
        }
        _ => Err(format!("expected \"owner/repo\", got \"{argument}\"")),
    }
}

/// Finds one tracked repo by owner/name across every installation.
fn find_tracked<'a>(state: &'a InstallationState, owner: &str, name: &str) -> Option<&'a TrackedRepo> {
    state
        .installations
        .iter()
        .flat_map(|installation| installation.repos.iter())
        .find(|tracked| tracked.owner.eq_ignore_ascii_case(owner) && tracked.name.eq_ignore_ascii_case(name))
}

/// `selfhost repo logs <owner>/<repo> [--lines N]`.
fn logs(arguments: &[String], config: &Config, data_dir: &Path) -> Result<(), String> {
    let target = arguments
        .get(2)
        .ok_or_else(|| format!("repo logs needs \"owner/repo\"\n\n{USAGE}"))?;
    let (owner, repo) = split_owner_repo(target)?;
    let lines = value_of(arguments, "--lines")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| format!("--lines {value}: not a number"))
        })
        .transpose()?
        .unwrap_or(DEFAULT_LOG_LINES);

    let store = open_store(config, data_dir)?;
    let state = store.state().map_err(|error| error.to_string())?;
    let tracked = find_tracked(&state, &owner, &repo).ok_or_else(|| {
        format!(
            "\"{owner}/{repo}\" is not tracked by the GitHub App — `selfhost repo list` shows what is"
        )
    })?;

    println!("webhook receipt for {owner}/{repo}:");
    match tracked.last_push_unix {
        Some(at) => println!("  last push        {}", human_time(at)),
        None => println!("  last push         none received yet"),
    }
    match &tracked.last_deploy_outcome {
        Some(outcome) => println!("  last deploy outcome  {outcome}"),
        None => println!("  last deploy outcome  none recorded yet"),
    }

    let admin_store = selfhost_admin::Store::new(data_dir);
    let node_names: Vec<&str> = config.nodes.iter().map(|n| n.name.as_str()).collect();
    let catalog = admin_store.load(&node_names).map_err(|error| error.to_string())?;
    let service = catalog.services.iter().find(|spec| {
        spec.git
            .as_ref()
            .is_some_and(|watch| selfhost_github_app::repository_matches(&watch.repository, &owner, &repo))
    });

    println!();
    match service {
        None => println!(
            "no service is configured for this repo yet — there is no process log. \
             `selfhost repo configure {owner}/{repo} ...` installs one."
        ),
        Some(spec) => {
            println!("process log for service \"{}\" (last {lines} line(s)):", spec.name);
            print_process_log(&spec.name, lines, config, data_dir)?;
        }
    }
    Ok(())
}

/// Fetches and prints a service's tail of process output from the running
/// daemon's admin API.
///
/// There is no on-disk log file to fall back to: `selfhost_supervisor`'s log
/// ring lives only in the running daemon's memory (see
/// `crates/foundation/supervisor/src/logs.rs`) — nothing in this workspace
/// ever writes it to a file. So unlike `app deploy`, there is no local
/// fallback here either; a stopped daemon means no process log is available at
/// all, and this says so rather than pretending to have looked somewhere.
fn print_process_log(name: &str, lines: usize, config: &Config, data_dir: &Path) -> Result<(), String> {
    let address: SocketAddr = config
        .server
        .admin_bind
        .parse()
        .map_err(|error| format!("server.admin_bind {}: {error}", config.server.admin_bind))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("could not start the async runtime: {error}"))?;

    runtime.block_on(async {
        let path = format!("/api/services/{name}/logs?from=0&limit={LOG_FETCH_CAP}");
        let raw = app_command::admin_request("GET", &path, &[], address, data_dir).await.map_err(|error| {
            match error {
                Daemon::Absent => format!(
                    "nothing is answering on {address} — the process log lives only in a running \
                     daemon's memory, so there is nothing to read while it is down"
                ),
                Daemon::Said(message) => message,
            }
        })?;
        let parsed = selfhost_http::IncomingResponse::parse(&raw)
            .map_err(|error| format!("the daemon's answer is not a response: {error}"))?;
        if parsed.response.status.0 != 200 {
            return Err(format!(
                "the daemon refused this request: {} {}",
                parsed.response.status.0,
                parsed.response.status.reason()
            ));
        }
        let body = String::from_utf8_lossy(raw.get(parsed.consumed..).unwrap_or_default());
        let value = selfhost_json::parse(body.trim()).map_err(|error| error.to_string())?;
        let all_lines: Vec<selfhost_json::Json> = value
            .get("lines")
            .and_then(selfhost_json::Json::as_array)
            .map(|slice| slice.to_vec())
            .unwrap_or_default();
        let tail: Vec<&selfhost_json::Json> = all_lines.iter().rev().take(lines).collect();
        if tail.is_empty() {
            println!("  (no output captured yet)");
        }
        for line in tail.into_iter().rev() {
            let stream = line.get("stream").and_then(selfhost_json::Json::as_str).unwrap_or("?");
            let text = line.get("text").and_then(selfhost_json::Json::as_str).unwrap_or("");
            println!("  [{stream}] {text}");
        }
        Ok(())
    })
}

/// A Unix timestamp as a human-readable UTC stamp, with no timezone database
/// pulled in for it.
///
/// Good enough for "how long ago was this webhook received" without adding a
/// dependency this crate has no other reason to carry.
fn human_time(unix: u64) -> String {
    let days_since_epoch = unix / 86_400;
    let seconds_of_day = unix % 86_400;
    let (year, month, day) = civil_from_days(days_since_epoch as i64);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60
    )
}

/// Howard Hinnant's `civil_from_days`: days since the Unix epoch to a
/// proleptic-Gregorian (year, month, day), with no leap-second or timezone
/// handling — exactly what a Unix timestamp needs and no more.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `selfhost repo configure <owner>/<repo> --node <node> --port <port> --serve
/// <cmd...> [--build <cmd...>] [--domain <host>]...`
fn configure(arguments: &[String], config: &Config, data_dir: &Path) -> Result<(), String> {
    let target = arguments
        .get(2)
        .ok_or_else(|| format!("repo configure needs \"owner/repo\"\n\n{USAGE}"))?;
    let (owner, repo) = split_owner_repo(target)?;

    let store = open_store(config, data_dir)?;
    let state = store.state().map_err(|error| error.to_string())?;
    if find_tracked(&state, &owner, &repo).is_none() {
        return Err(format!(
            "\"{owner}/{repo}\" is not tracked by the GitHub App yet — install the App on this \
             repository at github.com first, then it will appear in `selfhost repo list`"
        ));
    }

    let node = value_of(arguments, "--node")
        .ok_or_else(|| format!("repo configure needs --node <name>\n\n{USAGE}"))?;
    let port = value_of(arguments, "--port")
        .ok_or_else(|| format!("repo configure needs --port <number>\n\n{USAGE}"))?
        .parse::<u16>()
        .map_err(|_| "--port: not a number between 1 and 65535".to_owned())?;
    let serve = words_after(arguments, "--serve");
    if serve.is_empty() {
        return Err(format!(
            "repo configure needs --serve <command...> — this release does not inspect a remote \
             repository's tree to guess one; that needs an extra network round trip this \
             increment does not add\n\n{USAGE}"
        ));
    }
    let build = words_after(arguments, "--build");
    let domains = values_of(arguments, "--domain");

    let app = compose_configure(&owner, &repo, &node, port, serve, build, domains)?;

    let node_names: Vec<&str> = config.nodes.iter().map(|n| n.name.as_str()).collect();
    let problems: Vec<String> = app
        .check(&node_names)
        .into_iter()
        .filter(|problem| !app.domains.is_empty() || !matches!(problem.field.as_str(), "app.domains" | "app.port"))
        .map(|problem| format!("  {}: {}", problem.field, problem.message))
        .collect();
    if !problems.is_empty() {
        return Err(format!("\"{}\" cannot be configured as it stands:\n{}", app.name, problems.join("\n")));
    }

    let address: SocketAddr = config
        .server
        .admin_bind
        .parse()
        .map_err(|error| format!("server.admin_bind {}: {error}", config.server.admin_bind))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("could not start the async runtime: {error}"))?;

    runtime.block_on(install(&app, address, data_dir))
}

/// Composes the [`AppSpec`] `repo configure` installs, from its flags.
///
/// Pure — no I/O, no daemon — so the shape it produces (with and without a
/// domain) is exercised directly. `repository` is always the plain HTTPS clone
/// URL: cloning a private repository through the GitHub App's installation
/// token is explicitly out of scope for this increment (see the module docs
/// and `USAGE`), so a private repo configured here needs its checkout made
/// reachable some other way (a deploy key, a public mirror) until that lands.
fn compose_configure(
    owner: &str,
    repo: &str,
    node: &str,
    port: u16,
    serve: Vec<String>,
    build: Vec<String>,
    domains: Vec<String>,
) -> Result<AppSpec, String> {
    let repository = format!("https://github.com/{owner}/{repo}.git");
    let mut app = AppSpec::new(repo, domains, repository, serve, node, port);
    if !build.is_empty() {
        app.build = Some(build);
    }
    Ok(app)
}

/// Installs a composed application through the running daemon's admin API,
/// and adds its site route to the config file when a domain was given.
///
/// The same two writes `selfhost site add` and a running daemon's `Install`
/// route each already know how to make; this reuses both rather than
/// re-implementing either. See the module docs for why there is no path here
/// that installs without a daemon.
async fn install(app: &AppSpec, address: SocketAddr, data_dir: &Path) -> Result<(), String> {
    let body = selfhost_supervisor::state::spec_to_json(&app.service()).to_text();
    let raw = app_command::admin_request("PUT", &format!("/api/services/{}", app.name), body.as_bytes(), address, data_dir)
        .await
        .map_err(|error| match error {
            Daemon::Absent => format!(
                "nothing is answering on {address} — `repo configure` needs a running daemon to \
                 install a new service; start it first (`selfhost daemon`)"
            ),
            Daemon::Said(message) => message,
        })?;
    app_command::accepted(&raw)?;

    println!("✓ installed \"{}\" from {} on node \"{}\", port {}", app.name, app.repository, app.node, app.port);

    if !app.domains.is_empty() {
        let config_path = find_config_path().ok_or_else(|| {
            "installed the service, but could not find selfhost.config.toml to add the site".to_owned()
        })?;
        let source = std::fs::read_to_string(&config_path)
            .map_err(|error| format!("cannot read {}: {error}", config_path.display()))?;
        let updated = selfhost_config::edit::add_site(&source, &app.site()).map_err(|error| {
            format!("the service is installed, but its site could not be added:\n{error}")
        })?;
        let temporary = config_path.with_extension("toml.new");
        std::fs::write(&temporary, &updated)
            .map_err(|error| format!("cannot write {}: {error}", temporary.display()))?;
        std::fs::rename(&temporary, &config_path)
            .map_err(|error| format!("cannot replace {}: {error}", config_path.display()))?;

        println!("✓ routed {} → this service", app.domains.join(", "));
        println!(
            "  deploys are now push-triggered: a push to this repo reaches the App's webhook and \
             redeploys automatically, rather than waiting on a poll interval"
        );
    }

    Ok(())
}

/// Walks up from the current directory to find `selfhost.config.toml`, the
/// same search `main`'s own `find_config` makes.
///
/// Duplicated rather than imported because `main::find_config` is private to
/// the binary crate's root module; this is the one place under `repo_command`
/// that needs it, to reach [`selfhost_config::edit::add_site`] the same way
/// `selfhost site add` does.
fn find_config_path() -> Option<std::path::PathBuf> {
    let mut directory = std::env::current_dir().ok()?;
    loop {
        let candidate = directory.join("selfhost.config.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !directory.pop() {
            return None;
        }
    }
}

// --- small argument helpers, matching `site.rs`'s conventions ---

/// The value immediately following the first occurrence of `name`.
fn value_of(arguments: &[String], name: &str) -> Option<String> {
    arguments.iter().position(|argument| argument == name).and_then(|at| arguments.get(at + 1)).cloned()
}

/// Every value given for a repeatable option.
fn values_of(arguments: &[String], name: &str) -> Vec<String> {
    let mut values = Vec::new();
    for (i, argument) in arguments.iter().enumerate() {
        if argument == name
            && let Some(value) = arguments.get(i + 1)
        {
            values.push(value.clone());
        }
    }
    values
}

/// The `repo configure` options that can follow a `--serve`/`--build` command
/// line. Stopping at one of these specific names — rather than at any
/// argument that merely starts with `-` — is what lets a served or built
/// command carry its own single-dash flags (`-s dist -l $PORT`, `-p 3000`,
/// `npm run build -- --mode production`) without truncating silently.
const CONFIGURE_FLAGS: &[&str] = &["--node", "--port", "--serve", "--build", "--domain"];

/// Every word following the first occurrence of `name`, up to the next
/// recognized `repo configure` flag (see [`CONFIGURE_FLAGS`]) or the end of
/// the arguments.
///
/// `--serve` and `--build` each take a whole command line, not one value —
/// `--serve node server.js` needs both words. Stopping at a *known* flag name
/// instead of any leading `-` is deliberate: the served/built command is
/// someone else's CLI, and commands like `npx serve -s dist -l $PORT` are the
/// normal case, not the exception.
fn words_after(arguments: &[String], name: &str) -> Vec<String> {
    let Some(at) = arguments.iter().position(|argument| argument == name) else {
        return Vec::new();
    };
    arguments[at + 1..]
        .iter()
        .take_while(|argument| !CONFIGURE_FLAGS.contains(&argument.as_str()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_config::ServiceSpec;
    use selfhost_github_app::Installation;

    fn state_with(repos: Vec<TrackedRepo>) -> InstallationState {
        InstallationState { installations: vec![Installation { installation_id: 1, account_login: "octocat".into(), repos }] }
    }

    // --- owner/repo parsing ---

    #[test]
    fn splits_a_well_formed_owner_repo() {
        assert_eq!(split_owner_repo("octocat/hello-world"), Ok(("octocat".to_owned(), "hello-world".to_owned())));
    }

    #[test]
    fn refuses_a_target_with_no_slash() {
        assert!(split_owner_repo("hello-world").is_err());
    }

    #[test]
    fn refuses_a_target_with_two_slashes() {
        assert!(split_owner_repo("a/b/c").is_err());
    }

    #[test]
    fn parses_owner_repo_out_of_a_watch_url_without_dot_git() {
        assert_eq!(
            selfhost_github_app::parse_owner_repo("https://github.com/octocat/hello-world"),
            Some(("octocat".to_owned(), "hello-world".to_owned()))
        );
    }

    #[test]
    fn parses_owner_repo_out_of_a_watch_url_with_dot_git() {
        assert_eq!(
            selfhost_github_app::parse_owner_repo("https://github.com/octocat/hello-world.git"),
            Some(("octocat".to_owned(), "hello-world".to_owned()))
        );
    }

    #[test]
    fn parses_owner_repo_case_insensitively() {
        assert_eq!(
            selfhost_github_app::parse_owner_repo("https://github.com/OctoCat/Hello-World.git"),
            Some(("octocat".to_owned(), "hello-world".to_owned()))
        );
    }

    // --- status join logic ---

    #[test]
    fn a_repo_with_no_matching_service_is_installed_no_config() {
        assert_eq!(status_of(false, None), "installed (no config)");
        assert_eq!(status_of(false, Some("Updated abc")), "installed (no config)");
    }

    #[test]
    fn a_configured_repo_with_no_deploy_yet_says_so() {
        assert_eq!(status_of(true, None), "configured (never deployed)");
    }

    #[test]
    fn a_configured_repo_with_a_deploy_shows_its_outcome() {
        assert_eq!(status_of(true, Some("Updated 3f2a1c")), "configured (live, last deploy: Updated 3f2a1c)");
    }

    #[test]
    fn rows_for_joins_tracked_repos_against_the_catalogue() {
        let state = state_with(vec![
            TrackedRepo { owner: "octocat".into(), name: "site-a".into(), last_push_unix: None, last_deploy_outcome: None },
            TrackedRepo {
                owner: "octocat".into(),
                name: "site-b".into(),
                last_push_unix: Some(1),
                last_deploy_outcome: Some("Updated deadbeef".into()),
            },
        ]);

        let mut spec = ServiceSpec::new("site-b", "node");
        spec.git = Some(selfhost_config::GitWatch::new("https://github.com/octocat/site-b.git", "checkouts/site-b"));
        let catalog = selfhost_config::ServiceCatalog { version: 1, services: vec![spec] };

        let rows = rows_for(&state, &catalog);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|(_, repo, status)| repo == "octocat/site-a" && status == "installed (no config)"));
        assert!(rows.iter().any(|(_, repo, status)| repo == "octocat/site-b"
            && status == "configured (live, last deploy: Updated deadbeef)"));
    }

    #[test]
    fn find_tracked_matches_case_insensitively() {
        let state = state_with(vec![TrackedRepo {
            owner: "OctoCat".into(),
            name: "Hello-World".into(),
            last_push_unix: None,
            last_deploy_outcome: None,
        }]);
        assert!(find_tracked(&state, "octocat", "hello-world").is_some());
    }

    // --- AppSpec composition ---

    #[test]
    fn composing_without_a_domain_yields_a_backend_only_spec() {
        let app = compose_configure(
            "octocat",
            "hello-world",
            "home",
            5050,
            vec!["node".into(), "server.js".into()],
            vec![],
            vec![],
        )
        .expect("composes");

        assert_eq!(app.name, "hello-world");
        assert_eq!(app.repository, "https://github.com/octocat/hello-world.git");
        assert_eq!(app.serve, vec!["node".to_owned(), "server.js".to_owned()]);
        assert_eq!(app.node, "home");
        assert_eq!(app.port, 5050);
        assert!(app.domains.is_empty());
        assert_eq!(app.build, None);
    }

    #[test]
    fn composing_with_a_domain_and_build_step_carries_both() {
        let app = compose_configure(
            "octocat",
            "hello-world",
            "home",
            5050,
            vec!["node".into(), "server.js".into()],
            vec!["npm".into(), "ci".into()],
            vec!["blog.example.com".into()],
        )
        .expect("composes");

        assert_eq!(app.domains, vec!["blog.example.com".to_owned()]);
        assert_eq!(app.build, Some(vec!["npm".to_owned(), "ci".to_owned()]));
    }

    // --- flag parsing ---

    #[test]
    fn words_after_stops_at_the_next_flag() {
        let arguments: Vec<String> =
            ["repo", "configure", "o/r", "--serve", "node", "server.js", "--build", "npm", "ci"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert_eq!(words_after(&arguments, "--serve"), vec!["node".to_owned(), "server.js".to_owned()]);
        assert_eq!(words_after(&arguments, "--build"), vec!["npm".to_owned(), "ci".to_owned()]);
    }

    #[test]
    fn a_served_commands_own_single_dash_flags_are_not_mistaken_for_repo_configure_flags() {
        let arguments: Vec<String> = [
            "repo", "configure", "o/r", "--serve", "npx", "serve", "-s", "dist", "-l", "$PORT", "--domain",
            "example.com",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            words_after(&arguments, "--serve"),
            vec!["npx".to_owned(), "serve".to_owned(), "-s".to_owned(), "dist".to_owned(), "-l".to_owned(), "$PORT".to_owned()]
        );
        assert_eq!(values_of(&arguments, "--domain"), vec!["example.com".to_owned()]);
    }

    #[test]
    fn words_after_an_absent_flag_is_empty() {
        let arguments: Vec<String> = ["repo", "configure", "o/r"].iter().map(|s| s.to_string()).collect();
        assert_eq!(words_after(&arguments, "--serve"), Vec::<String>::new());
    }

    #[test]
    fn values_of_collects_every_repeated_domain() {
        let arguments: Vec<String> =
            ["repo", "configure", "o/r", "--domain", "a.example.com", "--domain", "b.example.com"]
                .iter()
                .map(|s| s.to_string())
                .collect();
        assert_eq!(values_of(&arguments, "--domain"), vec!["a.example.com".to_owned(), "b.example.com".to_owned()]);
    }

    #[test]
    fn human_time_renders_a_known_timestamp() {
        // 2024-01-15 12:00:00 UTC
        assert_eq!(human_time(1_705_320_000), "2024-01-15 12:00:00 UTC");
    }
}
