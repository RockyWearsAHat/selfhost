//! The `selfhost site` command: list, show, add, and remove websites.
//!
//! This is the operator's front door to the `[[sites]]` section of
//! `selfhost.config.toml`. It parses a handful of flags into a
//! [`Site`](selfhost_config::Site), validates the *whole* resulting config, and
//! only then writes the file — atomically, and preserving every comment and
//! untouched section, via [`selfhost_config::edit`].
//!
//! # Why it edits the config file directly
//!
//! A site is a piece of the deployment a person owns, so it lives in the
//! hand-authored config, next to the server and node settings — not in the
//! daemon-owned `data/services.toml`. The daemon reads this file at startup and
//! does not watch it, so a change here takes effect on the next `selfhost run`
//! or daemon restart, and the command says so rather than implying a live edit.
//!
//! # What `remove` will and will not do
//!
//! Removing a site *unroutes* it: the `[[sites]]` block is excised and the
//! hostname no longer maps anywhere. It does **not** delete the site's static
//! files — that content was put there deliberately and may be a working tree.
//! `--delete-content` opts into removing the `static_root` directory as well,
//! and because that is destructive it is confirmed on the terminal (or with
//! `--yes`) and refused outright for any directory outside the project.

use selfhost_config::{Config, Health, Instance, Site};
use std::path::{Path, PathBuf};

use crate::teardown;

/// Dispatches `selfhost site <subcommand>`.
///
/// `config_path` is the located `selfhost.config.toml`; the project directory —
/// against which `static_root` and the data directory resolve — is its parent.
pub fn run(arguments: &[String], config_path: &Path) -> Result<(), String> {
    let project_dir = config_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    match arguments.get(1).map(String::as_str) {
        Some("list") | None => list(config_path, &project_dir),
        Some("show") => show(arguments, config_path),
        Some("add") => add(arguments, config_path),
        Some("remove") => remove(arguments, config_path, &project_dir),
        Some(other) => Err(format!(
            "unknown site subcommand \"{other}\" — expected list, show, add, or remove\n\n{USAGE}"
        )),
    }
}

/// Usage for the `site` command, shown on a malformed invocation.
const USAGE: &str = "\
selfhost site — manage the websites the proxy serves

Usage
  selfhost site list
  selfhost site show <name>
  selfhost site add <name> --domain <d1[,d2…]> [options]
  selfhost site remove <name> [--delete-content] [--yes]

Add options
  --domain <list>         Hostnames for the site; repeatable and comma-separated.
                          The first is canonical.
  --static <dir>          Serve static files from this directory.
  --spa                   Serve index.html for unmatched paths (implies --static).
  --instance <node:port>  An application instance to balance across; repeatable.
                          Its presence makes this an app (or, with --static, a
                          mixed) site.
  --app-path <prefix>     A path prefix routed to the application rather than to
                          static files; repeatable. Needs at least one instance.
  --no-canonical-redirect Do not redirect the other domains to the first one.

A change takes effect on the next `selfhost run` or daemon restart.
";

/// Loads and validates the config at `path`.
fn load(path: &Path) -> Result<Config, String> {
    Config::load(path).map_err(|error| error.to_string())
}

/// Reads the config source as text, for the edit functions that transform it.
pub(crate) fn read_source(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))
}

/// Prints every site as domain → kind → status.
///
/// Read-only and needs nothing running: the kind is structural (static, app, or
/// both) and the status is what can be known from disk — whether a static root
/// exists, and how many instances an app declares.
fn list(config_path: &Path, project_dir: &Path) -> Result<(), String> {
    let config = load(config_path)?;
    if config.sites.is_empty() {
        println!("no sites configured — add one with `selfhost site add`");
        return Ok(());
    }

    let rows: Vec<(String, &'static str, String)> = config
        .sites
        .iter()
        .map(|site| (domain_column(site), kind_of(site), status_of(site, project_dir)))
        .collect();

    let domain_width = rows.iter().map(|(d, _, _)| d.len()).max().unwrap_or(6).max(6);
    let kind_width = rows.iter().map(|(_, k, _)| k.len()).max().unwrap_or(4).max(4);
    println!("  {:<domain_width$}  {:<kind_width$}  STATUS", "DOMAIN", "KIND");
    for (domain, kind, status) in rows {
        println!("  {domain:<domain_width$}  {kind:<kind_width$}  {status}");
    }
    Ok(())
}

/// The canonical hostname, noting how many further aliases the site has.
fn domain_column(site: &Site) -> String {
    match site.domains.len() {
        0 | 1 => site.canonical().to_owned(),
        n => format!("{} (+{})", site.canonical(), n - 1),
    }
}

/// Whether a site serves files, an application, or both.
fn kind_of(site: &Site) -> &'static str {
    match (site.static_root.is_some(), site.instances.is_empty()) {
        (true, true) => "static",
        (false, false) => "app",
        (true, false) => "mixed",
        // Neither a static root nor an instance: validation refuses this, so it
        // is only reachable for a config edited by hand into an invalid state.
        (false, true) => "empty",
    }
}

/// What can be said about a site's readiness without a running daemon.
fn status_of(site: &Site, project_dir: &Path) -> String {
    let mut notes = Vec::new();
    if let Some(root) = &site.static_root {
        let resolved = project_dir.join(root);
        if resolved.is_dir() {
            notes.push("root ready".to_owned());
        } else {
            notes.push(format!("root missing ({})", root.display()));
        }
    }
    if !site.instances.is_empty() {
        notes.push(format!("{} instance(s)", site.instances.len()));
    }
    if notes.is_empty() {
        return "serves nothing".to_owned();
    }
    notes.join(", ")
}

/// Prints one site's full definition.
fn show(arguments: &[String], config_path: &Path) -> Result<(), String> {
    let name = positional(arguments).ok_or_else(|| {
        format!("site show needs a name: `selfhost site show <name>`\n\n{USAGE}")
    })?;
    let config = load(config_path)?;
    let site = config
        .sites
        .iter()
        .find(|site| site.name == name)
        .ok_or_else(|| unknown_site(&name, &config))?;

    println!("  name                 {}", site.name);
    println!("  domains              {}", site.domains.join(", "));
    println!("  kind                 {}", kind_of(site));
    if let Some(root) = &site.static_root {
        println!("  static_root          {}", root.display());
        println!("  spa                  {}", site.spa);
    }
    if !site.app_paths.is_empty() {
        println!("  app_paths            {}", site.app_paths.join(", "));
    }
    for instance in &site.instances {
        println!("  instance             {}:{}", instance.node, instance.port);
    }
    println!("  canonical_redirect   {}", site.canonical_redirect);
    Ok(())
}

/// Builds a site from the flags and writes it into the config.
fn add(arguments: &[String], config_path: &Path) -> Result<(), String> {
    let name = positional(arguments)
        .ok_or_else(|| format!("site add needs a name: `selfhost site add <name> …`\n\n{USAGE}"))?;

    let domains = domains_from(arguments);
    if domains.is_empty() {
        return Err(format!(
            "site add needs at least one --domain, or the site answers on no hostname\n\n{USAGE}"
        ));
    }

    let static_root = value_of(arguments, "--static").map(PathBuf::from);
    let spa = flag(arguments, "--spa");
    // --spa is meaningless without files to fall back to; treat it as implying a
    // static root rather than silently doing nothing, and say what was assumed.
    let static_root = match (static_root, spa) {
        (Some(root), _) => Some(root),
        (None, true) => {
            return Err(
                "--spa serves index.html for unmatched paths, so it needs --static <dir>\n\n"
                    .to_owned()
                    + USAGE,
            );
        }
        (None, false) => None,
    };

    let instances = instances_from(arguments)?;
    let app_paths = values_of(arguments, "--app-path");
    let canonical_redirect = !flag(arguments, "--no-canonical-redirect");

    let site = Site {
        name: name.clone(),
        domains,
        static_root,
        spa,
        app_paths,
        instances,
        health: Health::default(),
        canonical_redirect,
        allowed_cidrs: vec![],
        console: false,
    };

    let source = read_source(config_path)?;
    let updated = selfhost_config::edit::add_site(&source, &site).map_err(|error| {
        format!("that site cannot be added:\n{error}")
    })?;
    write_atomically(config_path, &updated)?;

    println!("✓ added site \"{name}\" — {}", describe(&site));
    println!("  takes effect on the next `selfhost run` or daemon restart");
    Ok(())
}

/// Removes a site's routing, and optionally its static content.
fn remove(arguments: &[String], config_path: &Path, project_dir: &Path) -> Result<(), String> {
    let name = positional(arguments).ok_or_else(|| {
        format!("site remove needs a name: `selfhost site remove <name>`\n\n{USAGE}")
    })?;
    let assumed_yes = flag(arguments, "--yes");
    let delete_content = flag(arguments, "--delete-content");

    let config = load(config_path)?;
    let site = config
        .sites
        .iter()
        .find(|site| site.name == name)
        .ok_or_else(|| unknown_site(&name, &config))?;

    // Decide about the content *before* editing the config, so a refused or
    // declined deletion never leaves the site unrouted with its files orphaned
    // behind a config that no longer mentions them.
    let content_dir = delete_content
        .then(|| site.static_root.as_ref().map(|root| project_dir.join(root)))
        .flatten();
    if delete_content && content_dir.is_none() {
        return Err(format!(
            "--delete-content was given but site \"{name}\" has no static_root to delete"
        ));
    }
    if let Some(dir) = &content_dir {
        if !within(project_dir, dir) {
            return Err(format!(
                "refusing to delete {} — it is outside this project.\n  \
                 Remove it yourself if you mean to; this only deletes content it created.",
                dir.display()
            ));
        }
        println!("This will unroute site \"{name}\" and delete its content:\n");
        println!("  {}", dir.display());
        if !assumed_yes && !teardown::confirmed() {
            println!("\nNothing was changed.");
            return Ok(());
        }
    }

    let source = read_source(config_path)?;
    let updated = selfhost_config::edit::remove_site(&source, &name)
        .map_err(|error| format!("could not remove the site:\n{error}"))?
        .ok_or_else(|| format!("no site named \"{name}\""))?;
    write_atomically(config_path, &updated)?;
    println!("✓ unrouted site \"{name}\"");

    if let Some(dir) = &content_dir {
        match std::fs::remove_dir_all(dir) {
            Ok(()) => println!("  deleted {}", dir.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                // The routing is already gone and that is the part that matters;
                // report the content that could not be removed rather than fail
                // the whole command after a successful unroute.
                println!("  ! could not delete {} — {error}", dir.display());
            }
        }
    }

    println!("  takes effect on the next `selfhost run` or daemon restart");
    Ok(())
}

/// A one-line summary of what a site serves, for the success message.
fn describe(site: &Site) -> String {
    let kind = kind_of(site);
    let where_ = site.domains.first().map(String::as_str).unwrap_or("(no domain)");
    format!("{kind} · {where_}")
}

/// Writes `text` to `path` atomically: a temporary file, then a rename.
///
/// The same discipline the admin store uses (see [`selfhost_admin::store`]): a
/// crash or a full disk midway through leaves the previous config intact rather
/// than a truncated one, because `rename` within a directory is atomic.
pub(crate) fn write_atomically(path: &Path, text: &str) -> Result<(), String> {
    let temporary = path.with_extension("toml.new");
    std::fs::write(&temporary, text)
        .map_err(|error| format!("cannot write {}: {error}", temporary.display()))?;
    std::fs::rename(&temporary, path)
        .map_err(|error| format!("cannot replace {}: {error}", path.display()))
}

/// Whether `path` resolves to a location inside `root`.
///
/// Canonicalised on both sides so a `static_root` of `../../elsewhere` cannot
/// slip past a plain prefix comparison — the same check `teardown` makes before
/// it removes anything.
fn within(root: &Path, path: &Path) -> bool {
    let (Ok(root), Ok(path)) = (std::fs::canonicalize(root), std::fs::canonicalize(path)) else {
        return false;
    };
    path.starts_with(&root) && path != root
}

/// An error naming the missing site and listing the ones that do exist.
fn unknown_site(name: &str, config: &Config) -> String {
    let known: Vec<&str> = config.sites.iter().map(|site| site.name.as_str()).collect();
    if known.is_empty() {
        format!("no site named \"{name}\" — there are no sites configured")
    } else {
        format!("no site named \"{name}\" — configured sites are: {}", known.join(", "))
    }
}

/// Flags that consume the argument following them, so `positional` knows to
/// skip that value rather than mistake it for the name.
const VALUE_FLAGS: &[&str] = &["--domain", "--instance", "--app-path", "--static"];

/// The first argument after the subcommand that is not itself an option.
///
/// `site add blog --domain …` yields `blog`, and `site add --domain a.com
/// blog` also yields `blog` — a flag's own value is skipped along with the
/// flag, so a name is never confused with an option or an option's argument.
fn positional(arguments: &[String]) -> Option<String> {
    let mut rest = arguments.iter().skip(2);
    while let Some(argument) = rest.next() {
        if !argument.starts_with('-') {
            return Some(argument.clone());
        }
        if VALUE_FLAGS.contains(&argument.as_str()) {
            rest.next();
        }
    }
    None
}

/// Whether a bare flag is present.
fn flag(arguments: &[String], name: &str) -> bool {
    arguments.iter().any(|argument| argument == name)
}

/// The value immediately following the first occurrence of `name`.
fn value_of(arguments: &[String], name: &str) -> Option<String> {
    arguments
        .iter()
        .position(|argument| argument == name)
        .and_then(|at| arguments.get(at + 1))
        .cloned()
}

/// Every value given for a repeatable option.
fn values_of(arguments: &[String], name: &str) -> Vec<String> {
    let mut values = Vec::new();
    for (i, argument) in arguments.iter().enumerate() {
        if argument == name {
            if let Some(value) = arguments.get(i + 1) {
                values.push(value.clone());
            }
        }
    }
    values
}

/// All domains from `--domain`, allowing the flag to repeat and each occurrence
/// to be a comma-separated list, with surrounding whitespace trimmed.
fn domains_from(arguments: &[String]) -> Vec<String> {
    values_of(arguments, "--domain")
        .iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Parses each `--instance node:port` into an [`Instance`].
///
/// The `node:port` shape is required because an instance is meaningless without
/// both — which machine, and which port on it — and a value missing either is
/// refused with the offending text named rather than guessed at.
fn instances_from(arguments: &[String]) -> Result<Vec<Instance>, String> {
    let mut instances = Vec::new();
    for raw in values_of(arguments, "--instance") {
        let (node, port) = raw.rsplit_once(':').ok_or_else(|| {
            format!("--instance {raw}: expected node:port, for example home:5050")
        })?;
        if node.is_empty() {
            return Err(format!("--instance {raw}: the node name before ':' is empty"));
        }
        let port: u16 = port
            .parse()
            .map_err(|_| format!("--instance {raw}: \"{port}\" is not a port between 1 and 65535"))?;
        if port == 0 {
            return Err(format!("--instance {raw}: port 0 is not a real port"));
        }
        instances.push(Instance { node: node.to_owned(), port });
    }
    Ok(instances)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn domains_split_on_commas_and_across_repeats() {
        let a = args(&["site", "add", "blog", "--domain", "a.com, b.com", "--domain", "c.com"]);
        assert_eq!(domains_from(&a), vec!["a.com", "b.com", "c.com"]);
    }

    #[test]
    fn a_leading_flag_is_not_taken_for_the_name() {
        let a = args(&["site", "add", "--domain", "a.com", "blog"]);
        assert_eq!(positional(&a).as_deref(), Some("blog"));
    }

    #[test]
    fn an_instance_parses_into_node_and_port() {
        let a = args(&["site", "add", "api", "--instance", "home:5050"]);
        let parsed = instances_from(&a).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].node, "home");
        assert_eq!(parsed[0].port, 5050);
    }

    #[test]
    fn a_malformed_instance_is_refused_with_its_text() {
        for bad in ["home", "home:", "home:notaport", "home:0", ":5050"] {
            let a = args(&["site", "add", "api", "--instance", bad]);
            assert!(instances_from(&a).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn kind_reflects_what_a_site_serves() {
        let mut site = Site {
            name: "s".into(),
            domains: vec!["s.com".into()],
            static_root: Some(PathBuf::from("./s")),
            spa: false,
            app_paths: vec![],
            instances: vec![],
            health: Health::default(),
            canonical_redirect: true,
            allowed_cidrs: vec![],
            console: false,
        };
        assert_eq!(kind_of(&site), "static");

        site.instances = vec![Instance { node: "home".into(), port: 1 }];
        assert_eq!(kind_of(&site), "mixed");

        site.static_root = None;
        assert_eq!(kind_of(&site), "app");
    }

    #[test]
    fn repeatable_options_collect_every_value() {
        let a = args(&["site", "add", "s", "--app-path", "/api", "--app-path", "/ws"]);
        assert_eq!(values_of(&a, "--app-path"), vec!["/api", "/ws"]);
    }
}
