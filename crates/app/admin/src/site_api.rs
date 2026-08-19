//! `/api/sites`: the door onto `selfhost.config.toml`'s `[[sites]]` section
//! that does not require a shell on the box.
//!
//! # Why this exists
//!
//! `selfhost site add|add-domain|remove` (`crates/app/cli/src/site.rs`) has
//! always been able to do everything this module does — it edits the same
//! file through the same [`selfhost_config::edit`] functions. What it could
//! not do is run anywhere but on the box itself, because it opens the config
//! file by a local path. An agent, or an operator's own machine reaching the
//! box over `--remote`, has no such path — only the admin API. This module is
//! that door, gated by [`selfhost_identity::Capability::SiteAdmin`], the
//! capability [`selfhost_identity::Capability::is_honoured`]'s own
//! documentation named as a kept promise the day these routes existed.
//!
//! # Why a caller here may never choose an arbitrary `static_root`
//!
//! `selfhost site add --static <dir>` trusts the path an operator types
//! because an operator typing it already has a shell on the box — the
//! capability to point a hostname at an arbitrary directory is one they
//! already hold by another door. A caller of this API holds only whatever
//! [`selfhost_identity::Grants`] it was scoped to, and `SiteAdmin` is meant to
//! mean "may manage sites", not "may read or serve any file on this
//! filesystem by naming its path". So a site created here that wants static
//! content is given one, and exactly one, possible root:
//! `<data_dir>/sites/<name>/` — a directory this module allocates itself and
//! that a caller never gets to name. This is the same shape of rule
//! `crates/services/storage/src/lib.rs`'s module documentation draws between a
//! static root (operator-authored, trusted by construction) and a NAS share
//! (caller-authored, and therefore in need of every rule the operator-authored
//! case does not) — here the site itself is the caller-authored case.
//!
//! # File routes reuse the storage subsystem's safe primitives
//!
//! `crates/services/storage::fs::Dir` and its `Upload` type already do the
//! hard part correctly — symlink-refusing directory descriptor walks, an
//! exclusive-create collision oracle that closes the case-folding bug
//! documented on [`selfhost_storage::fs::Upload::begin`], atomic replace. This
//! module opens a site's managed directory as a `Dir` and asks it to do
//! exactly what a share's routes already ask the same type to do, scoped by
//! `Capability::SiteAdmin` and a site name instead of `FilesRead`/`FilesWrite`
//! and a [`selfhost_identity::ShareId`].
//!
//! # A known, deliberate scope cut: file uploads are not yet streamed
//!
//! `POST /api/storage/shares/<id>/sessions` and its resumable-session pair
//! exist because a share upload has to survive gigabytes arriving on a socket
//! (see `storage_api`'s module documentation) — the request body is streamed
//! straight to disk, never buffered whole, through machinery wired in at the
//! connection layer *before* [`crate::Api::handle`] ever sees a body. Site
//! file uploads here do **not** have that wiring yet: `PUT
//! /api/sites/<name>/files/entry` receives the same already-buffered body
//! every ordinary JSON route does, capped at [`crate::MAX_BODY`] (64 KiB). That
//! is enough for HTML, CSS, JS and small images and not enough for a video or
//! a large photo library. Closing that gap means giving site file uploads the
//! same socket-level special case `storage_api`'s sessions have — a real
//! follow-up, stated here rather than silently worked around with an
//! undersized cap nobody documented.

use selfhost_config::{Config, Health, Instance, Site};
use selfhost_http::{Response, Status};
use selfhost_json::Json;
use selfhost_storage::fs::{Dir, Existing, OpenError, Upload, WriteError};
use selfhost_storage::listing::Kind;
use selfhost_storage::path;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::{MAX_BODY, json, problem};

/// What this daemon needs to administer sites over the API: where the config
/// lives, and where an API-created site's managed content lives.
#[derive(Clone)]
pub struct Wiring {
    config_path: PathBuf,
    data_dir: PathBuf,
}

impl Wiring {
    /// `config_path` is the same `selfhost.config.toml` the CLI's `site`
    /// command edits. `data_dir` is the daemon's own data directory, under
    /// which `sites/<name>/` is this module's managed-content root.
    pub fn new(config_path: PathBuf, data_dir: PathBuf) -> Self {
        Self { config_path, data_dir }
    }

    /// The server-owned root a site created over this API may use for static
    /// content — never a path a caller chose. See this module's documentation.
    fn managed_root(&self, name: &str) -> PathBuf {
        self.data_dir.join("sites").join(name)
    }
}

/// Refuses any change to the site that serves the admin console.
///
/// # The escalation this closes
///
/// Every route here is reachable by an unattended agent credential scoped to
/// `SiteAdmin` and nothing else, and `SiteAdmin` was written to mean "may manage
/// sites". The console site is not one of those in any useful sense — it is the
/// door the caller's own operator authenticates at, and it was reachable by name
/// like any other. Two ordinary calls were enough:
/// `DELETE /api/sites/admin/domains/admin.example.com`, then
/// `POST /api/sites/<its-own>/domains` claiming that hostname — validation only
/// refuses a hostname claimed *twice*, so releasing it first makes the second
/// call legal. The console's own `allowed_cidrs` gate survives that, but the
/// gate is not what was attacked: after it, the operator opening the console
/// through the tunnel would reach agent-authored content, served over the real
/// certificate at the exact name where they type a password or present a
/// passkey. `remove` was worse still and simpler — one call and the console
/// stops being served at all.
///
/// So the rule is flat, and deliberately not a capability: **a site with
/// `console = true` is not manageable through this API**, by any caller, however
/// scoped. Minting a wider grant cannot reach it; only somebody with a shell on
/// the box and the config file in front of them can change the console's
/// routing, which is exactly who could already.
///
/// The refusal is legible rather than a uniform 404: the caller has already
/// passed the capability check and can see the site in `sites_list`, so hiding
/// the reason would teach it nothing except that this API is unreliable.
fn refuse_if_console(wiring: &Wiring, name: &str) -> Option<Response> {
    let config = load(wiring).ok()?;
    let site = config.sites.iter().find(|site| site.name == name)?;
    site.console.then(|| {
        problem(
            Status(403),
            "that site serves the admin console, and the console is not manageable through \
             this API — its routing is changed with a shell on the box, by somebody who \
             already holds the authority it protects",
        )
    })
}

/// Loads the config, or the 500 a caller should see for a config this daemon
/// itself cannot read.
fn load(wiring: &Wiring) -> Result<Config, Response> {
    Config::load(&wiring.config_path)
        .map_err(|error| problem(Status(500), &format!("cannot read the site configuration: {error}")))
}

/// Reads the config's source text, for the [`selfhost_config::edit`] functions
/// that transform it without losing comments or untouched sections.
fn read_source(wiring: &Wiring) -> Result<String, Response> {
    std::fs::read_to_string(&wiring.config_path).map_err(|error| {
        problem(Status(500), &format!("cannot read the site configuration: {error}"))
    })
}

/// Writes `text` to the config path atomically: a temporary file, then a
/// rename — the same discipline `crates/app/cli/src/site.rs::write_atomically`
/// uses, so an API-driven edit and a local `selfhost site` edit fail the same
/// way if the disk does.
fn write_atomically(path: &Path, text: &str) -> Result<(), Response> {
    let temporary = path.with_extension("toml.new");
    std::fs::write(&temporary, text).map_err(|error| {
        problem(Status(500), &format!("cannot write the site configuration: {error}"))
    })?;
    std::fs::rename(&temporary, path).map_err(|error| {
        problem(Status(500), &format!("cannot replace the site configuration: {error}"))
    })
}

/// A site as the wire renders it: everything a caller needs to know what it
/// serves, nothing about the daemon's own filesystem layout beyond whether
/// content exists.
fn site_json(site: &Site) -> Json {
    Json::object([
        ("name", Json::string(&site.name)),
        ("domains", Json::array(site.domains.iter().map(Json::string))),
        ("hasStaticContent", Json::Bool(site.static_root.is_some())),
        ("spa", Json::Bool(site.spa)),
        ("appPaths", Json::array(site.app_paths.iter().map(Json::string))),
        (
            "instances",
            Json::array(site.instances.iter().map(|instance| {
                Json::object([
                    ("node", Json::string(&instance.node)),
                    ("port", Json::Number(instance.port as f64)),
                ])
            })),
        ),
        ("canonicalRedirect", Json::Bool(site.canonical_redirect)),
    ])
}

/// Answers `GET /api/sites`.
pub fn list(wiring: &Wiring) -> Response {
    let config = match load(wiring) {
        Ok(config) => config,
        Err(refusal) => return refusal,
    };
    json(
        Status(200),
        Json::object([
            ("sites", Json::array(config.sites.iter().map(site_json))),
            ("count", Json::Number(config.sites.len() as f64)),
        ]),
    )
}

/// Answers `GET /api/sites/<name>`.
pub fn show(wiring: &Wiring, name: &str) -> Response {
    let config = match load(wiring) {
        Ok(config) => config,
        Err(refusal) => return refusal,
    };
    match config.sites.iter().find(|site| site.name == name) {
        Some(site) => json(Status(200), site_json(site)),
        None => not_found(name, &config),
    }
}

/// A submitted `POST /api/sites` body, parsed and validated before anything
/// is written.
struct AddRequest {
    name: String,
    domains: Vec<String>,
    static_content: bool,
    spa: bool,
    app_paths: Vec<String>,
    instances: Vec<Instance>,
}

/// Parses and validates a `POST /api/sites` body.
///
/// `static: true` is a request for a managed content directory, never a path —
/// see this module's documentation for why a path is never accepted here.
fn parse_add(body: &[u8]) -> Result<AddRequest, String> {
    let text = std::str::from_utf8(body).map_err(|_| "the body is not UTF-8".to_owned())?;
    let document = selfhost_json::parse(text).map_err(|_| "the body is not JSON".to_owned())?;

    let name = document
        .get("name")
        .and_then(Json::as_str)
        .ok_or("the body needs a \"name\" string")?
        .to_owned();
    if name.is_empty() || name.len() > 63 || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(
            "\"name\" must be 1-63 characters of letters, digits and dashes".to_owned()
        );
    }

    let domains: Vec<String> = document
        .get("domains")
        .and_then(Json::as_array)
        .ok_or("the body needs a \"domains\" array of at least one hostname")?
        .iter()
        .map(|value| value.as_str().map(str::to_owned).ok_or("every domain must be a string"))
        .collect::<Result<_, _>>()?;
    if domains.is_empty() {
        return Err("\"domains\" needs at least one hostname, or the site answers on none".to_owned());
    }

    let static_content = document.get("static").and_then(Json::as_bool).unwrap_or(false);
    let spa = document.get("spa").and_then(Json::as_bool).unwrap_or(false);
    if spa && !static_content {
        return Err("\"spa\" serves index.html for unmatched paths, so it needs \"static\": true".to_owned());
    }

    let app_paths: Vec<String> = match document.get("appPaths").and_then(Json::as_array) {
        Some(values) => values
            .iter()
            .map(|value| value.as_str().map(str::to_owned).ok_or("every app path must be a string"))
            .collect::<Result<_, _>>()?,
        None => Vec::new(),
    };

    let instances: Vec<Instance> = match document.get("instances").and_then(Json::as_array) {
        Some(values) => values
            .iter()
            .map(|value| {
                let node = value
                    .get("node")
                    .and_then(Json::as_str)
                    .ok_or("every instance needs a \"node\" string")?
                    .to_owned();
                let port = value
                    .get("port")
                    .and_then(Json::as_f64)
                    .ok_or("every instance needs a \"port\" number")?;
                if !(1.0..=65535.0).contains(&port) || port.fract() != 0.0 {
                    return Err("\"port\" must be a whole number between 1 and 65535".to_owned());
                }
                Ok(Instance { node, port: port as u16 })
            })
            .collect::<Result<_, _>>()?,
        None => Vec::new(),
    };

    if !static_content && instances.is_empty() {
        return Err("a site needs \"static\": true, at least one instance, or both".to_owned());
    }

    Ok(AddRequest { name, domains, static_content, spa, app_paths, instances })
}

/// Answers `POST /api/sites`.
pub fn add(wiring: &Wiring, body: &[u8]) -> Response {
    let request = match parse_add(body) {
        Ok(request) => request,
        Err(message) => return problem(Status(400), &message),
    };

    let static_root = if request.static_content {
        let root = wiring.managed_root(&request.name);
        if let Err(error) = std::fs::create_dir_all(&root) {
            return problem(
                Status(500),
                &format!("could not create this site's content directory: {error}"),
            );
        }
        // Absolute, so the proxy's `project_dir.join(root)` resolves to this
        // exact directory regardless of where the project checkout lives —
        // `PathBuf::join` discards its base when the joined path is absolute.
        match std::fs::canonicalize(&root) {
            Ok(canonical) => Some(canonical),
            Err(error) => {
                return problem(Status(500), &format!("could not resolve the content directory: {error}"));
            }
        }
    } else {
        None
    };

    let site = Site {
        name: request.name.clone(),
        domains: request.domains,
        static_root,
        spa: request.spa,
        app_paths: request.app_paths,
        instances: request.instances,
        health: Health::default(),
        canonical_redirect: true,
        allowed_cidrs: Vec::new(),
        console: false,
    };

    let source = match read_source(wiring) {
        Ok(source) => source,
        Err(refusal) => return refusal,
    };
    let updated = match selfhost_config::edit::add_site(&source, &site) {
        Ok(updated) => updated,
        Err(error) => return problem(Status(400), &format!("that site cannot be added:\n{error}")),
    };
    if let Err(refusal) = write_atomically(&wiring.config_path, &updated) {
        return refusal;
    }
    json(Status(200), site_json(&site))
}

/// Answers `DELETE /api/sites/<name>`.
///
/// Unroutes only — never deletes content. Deleting a site's managed content
/// directory, if it has one, stays a decision an operator makes with a
/// filesystem tool or a local `selfhost site remove --delete-content`; a
/// remote token silently destroying a directory tree on this box is a
/// different kind of power than "managing sites", and this route does not
/// carry it.
pub fn remove(wiring: &Wiring, name: &str) -> Response {
    if let Some(refusal) = refuse_if_console(wiring, name) {
        return refusal;
    }
    let source = match read_source(wiring) {
        Ok(source) => source,
        Err(refusal) => return refusal,
    };
    match selfhost_config::edit::remove_site(&source, name) {
        Ok(Some(updated)) => match write_atomically(&wiring.config_path, &updated) {
            Ok(()) => json(Status(200), Json::object([("removed", Json::string(name))])),
            Err(refusal) => refusal,
        },
        Ok(None) => problem(Status(404), &format!("no site named \"{name}\"")),
        Err(error) => problem(Status(400), &format!("could not remove the site:\n{error}")),
    }
}

/// A submitted `POST /api/sites/<name>/domains` body.
fn parse_hostname(body: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(body).map_err(|_| "the body is not UTF-8".to_owned())?;
    let document = selfhost_json::parse(text).map_err(|_| "the body is not JSON".to_owned())?;
    document
        .get("hostname")
        .and_then(Json::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "the body needs a \"hostname\" string".to_owned())
}

/// Answers `POST /api/sites/<name>/domains`.
pub fn add_domain(wiring: &Wiring, name: &str, body: &[u8]) -> Response {
    if let Some(refusal) = refuse_if_console(wiring, name) {
        return refusal;
    }
    let hostname = match parse_hostname(body) {
        Ok(hostname) => hostname,
        Err(message) => return problem(Status(400), &message),
    };
    let source = match read_source(wiring) {
        Ok(source) => source,
        Err(refusal) => return refusal,
    };
    match selfhost_config::edit::add_domain(&source, name, &hostname) {
        Ok(Some(updated)) => match write_atomically(&wiring.config_path, &updated) {
            Ok(()) => json(Status(200), Json::object([("added", Json::string(&hostname))])),
            Err(refusal) => refusal,
        },
        Ok(None) => problem(Status(404), &format!("no site named \"{name}\"")),
        Err(error) => problem(Status(400), &format!("that hostname cannot be added:\n{error}")),
    }
}

/// Answers `DELETE /api/sites/<name>/domains/<hostname>`.
pub fn remove_domain(wiring: &Wiring, name: &str, hostname: &str) -> Response {
    if let Some(refusal) = refuse_if_console(wiring, name) {
        return refusal;
    }
    let source = match read_source(wiring) {
        Ok(source) => source,
        Err(refusal) => return refusal,
    };
    match selfhost_config::edit::remove_domain(&source, name, hostname) {
        Ok(Some(updated)) => match write_atomically(&wiring.config_path, &updated) {
            Ok(()) => json(Status(200), Json::object([("removed", Json::string(hostname))])),
            Err(refusal) => refusal,
        },
        Ok(None) => problem(Status(404), &format!("no site named \"{name}\"")),
        Err(error) => problem(Status(400), &format!("that hostname cannot be removed:\n{error}")),
    }
}

/// The error a caller should see for a config the loader itself refused.
fn not_found(name: &str, config: &Config) -> Response {
    let known: Vec<&str> = config.sites.iter().map(|site| site.name.as_str()).collect();
    let detail = if known.is_empty() {
        "there are no sites configured".to_owned()
    } else {
        format!("configured sites are: {}", known.join(", "))
    };
    problem(Status(404), &format!("no site named \"{name}\" — {detail}"))
}

// ---------------------------------------------------------------------------
// Site-scoped file routes. See this module's documentation for the deliberate
// scope cut (buffered, not streamed) and the safety rationale (every write
// goes through `selfhost_storage::fs::Dir`, the same symlink-refusing,
// collision-checked primitive a share's routes use).
// ---------------------------------------------------------------------------

/// Opens a site's managed content directory, or the response a caller should
/// see for why it could not be reached.
///
/// A site with no managed content (an app-only site, or one whose `static`
/// flag was never set) has no such directory, and that is reported as `404`
/// rather than an empty listing: there is nothing here to list, mkdir into, or
/// upload to, and pretending there is an empty directory would let a caller
/// believe an upload had somewhere to land.
fn open_managed_dir(wiring: &Wiring, name: &str) -> Result<Dir, Response> {
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(problem(Status(404), "no such site"));
    }
    let root = wiring.managed_root(name);
    Dir::open_root(&root).map_err(|error| match error {
        OpenError::NotFound => problem(
            Status(404),
            "this site has no managed content directory — create it with \"static\": true",
        ),
        other => problem(Status(500), &format!("could not open this site's content: {other}")),
    })
}

/// Answers `GET /api/sites/<name>/files/list?path=…`. `path` is optional and
/// defaults to the content root.
pub fn list_files(wiring: &Wiring, name: &str, query: &str) -> Response {
    let dir = match open_managed_dir(wiring, name) {
        Ok(dir) => dir,
        Err(refusal) => return refusal,
    };
    let requested = crate::query_value(query, "path").unwrap_or("");
    let resolved = match path::resolve(Path::new("/"), requested) {
        Ok(resolved) => resolved,
        Err(refusal) => return problem(Status(400), &format!("bad path: {refusal:?}")),
    };
    let target = match dir.walk(resolved.relative()) {
        Ok(target) => target,
        Err(error) => return open_error(error),
    };
    match target.entries() {
        Ok(entries) => json(
            Status(200),
            Json::array(entries.iter().map(|entry| {
                Json::object([
                    ("name", Json::string(&entry.name)),
                    ("kind", Json::string(match entry.kind {
                        Kind::File => "file",
                        Kind::Directory => "directory",
                    })),
                    ("size", Json::Number(entry.size as f64)),
                    ("reachable", Json::Bool(entry.blocked.is_none())),
                ])
            })),
        ),
        Err(error) => open_error(error),
    }
}

/// A submitted `POST /api/sites/<name>/files/mkdir` body.
fn parse_path(body: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(body).map_err(|_| "the body is not UTF-8".to_owned())?;
    let document = selfhost_json::parse(text).map_err(|_| "the body is not JSON".to_owned())?;
    document
        .get("path")
        .and_then(Json::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "the body needs a \"path\" string".to_owned())
}

/// Answers `POST /api/sites/<name>/files/mkdir`.
pub fn mkdir(wiring: &Wiring, name: &str, body: &[u8]) -> Response {
    if let Some(refusal) = refuse_if_console(wiring, name) {
        return refusal;
    }
    let dir = match open_managed_dir(wiring, name) {
        Ok(dir) => dir,
        Err(refusal) => return refusal,
    };
    let requested = match parse_path(body) {
        Ok(path) => path,
        Err(message) => return problem(Status(400), &message),
    };
    let resolved = match path::resolve(Path::new("/"), &requested) {
        Ok(resolved) => resolved,
        Err(refusal) => return problem(Status(400), &format!("bad path: {refusal:?}")),
    };
    let Some((parent, leaf)) = split(&resolved) else {
        return problem(Status(400), "\"path\" needs a directory name, not the content root");
    };
    let parent = match dir.walk(&parent) {
        Ok(parent) => parent,
        Err(error) => return open_error(error),
    };
    match parent.create_dir(&leaf) {
        Ok(_) => json(Status(200), Json::object([("created", Json::string(&requested))])),
        Err(error) => write_error(error),
    }
}

/// Answers `PUT /api/sites/<name>/files/entry?path=…`.
///
/// See this module's documentation for the deliberate scope cut: the body
/// arrives already buffered by the ordinary API path, capped at
/// [`crate::MAX_BODY`].
pub fn put_file(wiring: &Wiring, name: &str, query: &str, body: &[u8]) -> Response {
    if let Some(refusal) = refuse_if_console(wiring, name) {
        return refusal;
    }
    if body.len() > MAX_BODY {
        // Unreachable today — `read_body` already refuses this before any
        // route sees the bytes — but stated rather than assumed, so a future
        // change to that cap cannot silently widen what this route accepts
        // without this line being touched too.
        return problem(Status(413), "request too large");
    }
    let dir = match open_managed_dir(wiring, name) {
        Ok(dir) => dir,
        Err(refusal) => return refusal,
    };
    let requested = crate::query_value(query, "path").unwrap_or("");
    let resolved = match path::resolve(Path::new("/"), requested) {
        Ok(resolved) => resolved,
        Err(refusal) => return problem(Status(400), &format!("bad path: {refusal:?}")),
    };
    let Some((parent, leaf)) = split(&resolved) else {
        return problem(Status(400), "\"path\" needs a file name, not the content root");
    };
    let parent = match dir.walk(&parent) {
        Ok(parent) => parent,
        Err(error) => return open_error(error),
    };
    let mut upload = match Upload::begin(&parent, &leaf, Existing::Replace) {
        Ok(upload) => upload,
        Err(error) => return write_error(error),
    };
    if let Err(error) = upload.file().write_all(body) {
        return problem(Status(500), &format!("could not write the file: {error}"));
    }
    match upload.commit() {
        Ok(()) => json(
            Status(200),
            Json::object([("path", Json::string(requested)), ("bytes", Json::Number(body.len() as f64))]),
        ),
        Err(error) => problem(Status(500), &format!("could not finish the write: {error}")),
    }
}

/// Answers `DELETE /api/sites/<name>/files/entry?path=…`.
pub fn delete_file(wiring: &Wiring, name: &str, query: &str) -> Response {
    if let Some(refusal) = refuse_if_console(wiring, name) {
        return refusal;
    }
    let dir = match open_managed_dir(wiring, name) {
        Ok(dir) => dir,
        Err(refusal) => return refusal,
    };
    let requested = crate::query_value(query, "path").unwrap_or("");
    let resolved = match path::resolve(Path::new("/"), requested) {
        Ok(resolved) => resolved,
        Err(refusal) => return problem(Status(400), &format!("bad path: {refusal:?}")),
    };
    let Some((parent, leaf)) = split(&resolved) else {
        return problem(Status(400), "\"path\" names the content root, which cannot be deleted here");
    };
    let parent = match dir.walk(&parent) {
        Ok(parent) => parent,
        Err(error) => return open_error(error),
    };
    let outcome = match parent.stat(&leaf) {
        Ok(attributes) if attributes.kind == Kind::Directory => parent.remove_dir(&leaf),
        Ok(_) => parent.remove_file(&leaf),
        Err(OpenError::NotFound) => return problem(Status(404), "no such file or directory"),
        Err(error) => return open_error(error),
    };
    match outcome {
        Ok(()) => json(Status(200), Json::object([("deleted", Json::string(requested))])),
        Err(error) => write_error(error),
    }
}

/// Splits a resolved path into the directory to walk and the leaf name to
/// act on within it. `None` for the content root itself, which every file
/// route here refuses to name directly — mkdir, put and delete all act on a
/// leaf, never the root they are confined to.
fn split(resolved: &path::Resolved) -> Option<(selfhost_storage::path::RelativePath, String)> {
    let relative = resolved.relative();
    let leaf = relative.file_name()?.to_owned();
    Some((relative.parent(), leaf))
}

/// Turns a directory-open refusal into the response a caller should see.
fn open_error(error: OpenError) -> Response {
    match error {
        OpenError::NotFound => problem(Status(404), "no such file or directory"),
        OpenError::NotADirectory => problem(Status(400), "that path is a file, not a directory"),
        OpenError::NotAFile => problem(Status(400), "that path is a directory, not a file"),
        OpenError::Symlink => problem(Status(400), "refusing to follow a symlink"),
        _ => problem(Status(500), &format!("could not open that path: {error}")),
    }
}

/// Turns a write refusal into the response a caller should see.
fn write_error(error: WriteError) -> Response {
    match error {
        WriteError::NameTaken => problem(Status(409), "something already exists at that name"),
        WriteError::Collides { existing } => {
            problem(Status(409), &format!("that name collides with the existing \"{existing}\""))
        }
        _ => problem(Status(500), &format!("could not write: {error}")),
    }
}
