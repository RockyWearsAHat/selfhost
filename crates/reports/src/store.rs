//! The database: one directory per project, one file per defect.
//!
//! # Why a directory and not a table
//!
//! This workspace has no database dependency and is not going to acquire one for an intake
//! that receives a few reports a day. What a database would buy here is atomic replacement of
//! one record, and a rename already provides that — the same guarantee
//! [`selfhost_mail::store`] relies on for delivering a message. Each record is a small JSON
//! object written to `<id>.json.tmp` and renamed over `<id>.json`, so a reader sees the record
//! as it was or as it now is, never half of it.
//!
//! # A service is the unit a checkout subscribes to, and filing is how one is born
//!
//! `data/reports/<service>/` holds one service's defects. A service exists because a report was
//! filed to `…/report?<service>` — that is the whole of registering one, and it is why the
//! service is in the address rather than in a form somebody has to fill in first. An operator
//! can still create one ahead of time (`selfhost reports project add dx`), which changes
//! nothing except the order.
//!
//! Creating on demand is a door, so it is a bounded one: [`MAX_PROJECTS`] caps how many
//! services this box will hold, and passing it refuses in a sentence rather than filling the
//! disk with directories a stranger named. Within one service the record cap does the same job.
//! A checkout still asks for one key's open reports and folds them into its own `reports.dx`.
//!
//! # One record per defect, however many times it is reported
//!
//! A record is keyed by [`Report::id`] — the fingerprint of kind, title and route — so the same
//! defect reported by forty agents is one row with forty sightings rather than forty rows. That
//! is what makes the count meaningful, and it is the intake's first line against a flood: a
//! repeat costs an update, never a new file.
//!
//! # Everything here is bounded
//!
//! The caller is anonymous and unlimited, so the store is not: [`MAX_RECORDS`] bounds how many
//! defects one project can hold, [`MAX_SIGHTINGS_KEPT`] bounds how much history one record
//! carries, and [`MAX_RECORD_BYTES`] bounds one record's size — a record about to exceed it
//! sheds the detail of its oldest sightings, then the oldest sightings themselves. The sighting
//! *count* is never reduced by shedding: what is lost is history, never the fact that it
//! happened.

use std::fs;
use std::path::{Path, PathBuf};

use selfhost_json::Json;

use crate::report::{Kind, Report};

/// How many distinct defects one project will hold. Reaching it refuses new reports and says
/// so; sightings of defects already known keep working, because those cost no new file.
pub const MAX_RECORDS: usize = 10_000;
/// How many services this box will hold. Filing to an unknown service creates it, so this is
/// the bound on that door: reaching it refuses the *new* service and says so, while every
/// service already here keeps taking reports.
pub const MAX_PROJECTS: usize = 100;
/// How many sightings one record keeps in full. Older ones are dropped from the history.
pub const MAX_SIGHTINGS_KEPT: usize = 50;
/// How large one record file may be before its oldest history is shed.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
/// How many records one feed request may carry, so a subscriber's answer is always bounded.
pub const MAX_FEED: usize = 200;

/// Why a store operation could not be carried out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// No such project on this box. The sentence names how to create one.
    NoProject(String),
    /// The project is at [`MAX_RECORDS`].
    Full(String),
    /// The filesystem refused, and this names the path and the reason.
    Io(String),
    /// A record is not one this crate wrote, or the id names nothing. It is left where it is.
    Unreadable(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoProject(message)
            | Self::Full(message)
            | Self::Io(message)
            | Self::Unreadable(message) => out.write_str(message),
        }
    }
}

impl std::error::Error for StoreError {}

/// One sighting of a defect: who saw it, when, and what they said about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    /// When this box accepted it, ISO-8601 UTC.
    pub at: String,
    /// The reporter and its version.
    pub tool: String,
    /// The operating system it happened on.
    pub platform: String,
    /// The name of the folder the reporter was working in.
    pub workspace: String,
    /// The one-way source hash, for spotting a flood from one place.
    pub source: String,
    /// This reporter's own words, empty once shed by the size bound.
    pub detail: String,
}

/// One defect, as the database holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The project this defect is against.
    pub project: String,
    /// The fingerprint id, which is also the file name and the block id a checkout uses.
    pub id: String,
    /// What kind of thing it is.
    pub kind: Kind,
    /// The title the first reporter gave it.
    pub title: String,
    /// The first reporter's detail.
    pub detail: String,
    /// The tool or surface involved.
    pub route: String,
    /// The first reporter's reproduction, when there was one.
    pub repro: String,
    /// When it was first reported here.
    pub first_at: String,
    /// When it was last reported here.
    pub last_at: String,
    /// How many times it has been reported — never reduced by shedding history.
    pub sightings: usize,
    /// The kept history, oldest first.
    pub seen: Vec<Sighting>,
    /// Whether the owner's mailbox has been told about the latest sighting.
    pub delivered: bool,
    /// The account that filed this defect *first*, when one was signed in. Never changed by a
    /// later sighting — the same "first reporter's words win" rule [`Entry::title`] and
    /// [`Entry::detail`] already follow, so a stranger re-filing a known bug can never claim an
    /// account's report, and an account's own bug reported anonymously by someone else later
    /// stays theirs.
    pub account_id: Option<String>,
}

/// What one [`Store::record`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recorded {
    /// The record as it now stands.
    pub entry: Entry,
    /// True when this call created the record — a defect nobody had reported before.
    pub fresh: bool,
}

/// The report database rooted at one directory.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

impl Store {
    /// Opens — creating if needed — the store at `dir`.
    ///
    /// # Errors
    /// [`StoreError::Io`] naming the directory when it cannot be created.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        fs::create_dir_all(dir).map_err(|error| {
            StoreError::Io(format!("could not create {}: {error}", dir.display()))
        })?;
        restrict(dir);
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// The directory this store lives in.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.dir
    }

    /// Creates the project `key`, so reports about it are accepted. Creating one twice is not
    /// an error — the operator's intent is the same either way.
    ///
    /// # Errors
    /// [`StoreError::Io`] when the directory cannot be created.
    pub fn add_project(&self, key: &str) -> Result<(), StoreError> {
        let dir = self.project_dir(key);
        fs::create_dir_all(&dir).map_err(|error| {
            StoreError::Io(format!("could not create {}: {error}", dir.display()))
        })?;
        restrict(&dir);
        Ok(())
    }

    /// Whether `key` is a project this box accepts reports about.
    #[must_use]
    pub fn has_project(&self, key: &str) -> bool {
        self.project_dir(key).is_dir()
    }

    /// Every project key, alphabetically.
    ///
    /// # Errors
    /// [`StoreError::Io`] when the store directory cannot be listed.
    pub fn projects(&self) -> Result<Vec<String>, StoreError> {
        let listing = fs::read_dir(&self.dir).map_err(|error| {
            StoreError::Io(format!("could not read {}: {error}", self.dir.display()))
        })?;
        let mut keys: Vec<String> = listing
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_dir())
            .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
            .filter(|name| crate::report::project_key(name).is_ok_and(|key| &key == name))
            .collect();
        keys.sort();
        Ok(keys)
    }

    /// Files `report`, creating its record or adding a sighting to the one that exists — and
    /// creating the service itself when this is the first report filed to it.
    ///
    /// # Errors
    /// [`StoreError::Full`] when a new service would pass [`MAX_PROJECTS`] or a *new* defect
    /// would pass [`MAX_RECORDS`], [`StoreError::Io`] when the record cannot be written. A
    /// record that exists but cannot be read is replaced rather than refused — the reporter is
    /// not made to pay for corruption here — and the unreadable bytes are kept beside it as
    /// `<id>.json.broken`.
    pub fn record(&self, report: &Report) -> Result<Recorded, StoreError> {
        if !self.has_project(&report.project) {
            if self.projects()?.len() >= MAX_PROJECTS {
                return Err(StoreError::Full(format!(
                    "this box already holds {MAX_PROJECTS} services, so `{}` cannot be added — \
                     file to one that exists, or ask the owner to retire an unused one",
                    report.project
                )));
            }
            self.add_project(&report.project)?;
        }
        let id = report.id();
        let path = self.record_path(&report.project, &id);
        let existing = match fs::read_to_string(&path) {
            Ok(text) => match selfhost_json::parse(&text)
                .ok()
                .and_then(|value| entry(&report.project, &id, &value))
            {
                Some(entry) => Some(entry),
                None => {
                    let _ = fs::rename(&path, path.with_extension("json.broken"));
                    None
                }
            },
            Err(_) => None,
        };

        let fresh = existing.is_none();
        if fresh && self.count(&report.project)? >= MAX_RECORDS {
            return Err(StoreError::Full(format!(
                "`{}` already holds {MAX_RECORDS} open reports — close some before new ones can \
                 be filed",
                report.project
            )));
        }

        let sighting = Sighting {
            at: report.at.clone(),
            tool: report.tool.clone(),
            platform: report.platform.clone(),
            workspace: report.workspace.clone(),
            source: report.source.clone(),
            detail: report.detail.clone(),
        };
        let entry = match existing {
            Some(mut held) => {
                held.last_at = report.at.clone();
                held.sightings = held.sightings.saturating_add(1);
                held.seen.push(sighting);
                // Seen again is news again: the owner is told once more, and the notifier's own
                // throttle decides whether that becomes a message now.
                held.delivered = false;
                held
            }
            None => Entry {
                project: report.project.clone(),
                id: id.clone(),
                kind: report.kind,
                title: report.title.clone(),
                detail: report.detail.clone(),
                route: report.route.clone(),
                repro: report.repro.clone(),
                first_at: report.at.clone(),
                last_at: report.at.clone(),
                sightings: 1,
                seen: vec![sighting],
                delivered: false,
                account_id: report.account_id.clone(),
            },
        };

        let entry = self.write(entry)?;
        Ok(Recorded { entry, fresh })
    }

    /// Every open record for `project`, newest sighting first, at most [`MAX_FEED`].
    ///
    /// This is what a subscribed checkout reads: it is the whole of the project's open
    /// reports, so folding it into a document is idempotent — a report already carried is
    /// recognised by its id, and one that was closed here is simply absent.
    ///
    /// # Errors
    /// [`StoreError::NoProject`] when the key names nothing, [`StoreError::Io`] when the
    /// directory cannot be listed. A single unreadable record is skipped rather than failing
    /// the listing — one bad file must not hide the rest.
    pub fn list(&self, project: &str) -> Result<Vec<Entry>, StoreError> {
        if !self.has_project(project) {
            return Err(StoreError::NoProject(format!(
                "no project `{project}` on this box"
            )));
        }
        let mut entries: Vec<Entry> = self
            .records(project)?
            .into_iter()
            .filter_map(|path| self.read(project, &path).ok())
            .collect();
        entries.sort_by(|a, b| b.last_at.cmp(&a.last_at).then_with(|| a.id.cmp(&b.id)));
        entries.truncate(MAX_FEED);
        Ok(entries)
    }

    /// Records the owner's mailbox has not been told about, across every project, oldest first.
    ///
    /// # Errors
    /// [`StoreError::Io`] when a directory cannot be listed.
    pub fn undelivered(&self, limit: usize) -> Result<Vec<Entry>, StoreError> {
        let mut waiting = Vec::new();
        for project in self.projects()? {
            for path in self.records(&project)? {
                if let Ok(entry) = self.read(&project, &path) {
                    if !entry.delivered {
                        waiting.push(entry);
                    }
                }
            }
        }
        waiting.sort_by(|a, b| a.last_at.cmp(&b.last_at).then_with(|| a.id.cmp(&b.id)));
        waiting.truncate(limit);
        Ok(waiting)
    }

    /// Marks `id` as delivered to the owner's mailbox.
    ///
    /// # Errors
    /// [`StoreError::Unreadable`] when there is no such record, [`StoreError::Io`] when it
    /// cannot be rewritten.
    pub fn mark_delivered(&self, project: &str, id: &str) -> Result<(), StoreError> {
        let mut entry = self.read(project, &self.record_path(project, id))?;
        entry.delivered = true;
        self.write(entry)?;
        Ok(())
    }

    /// Deletes the record for `id` — how a fixed defect is closed.
    ///
    /// # Errors
    /// [`StoreError::Unreadable`] when no such record exists, so a typo is not silence.
    pub fn close(&self, project: &str, id: &str) -> Result<(), StoreError> {
        let path = self.record_path(project, id);
        if !path.exists() {
            return Err(StoreError::Unreadable(format!(
                "`{project}` holds no report `{}`",
                safe_id(id)
            )));
        }
        fs::remove_file(&path).map_err(|error| {
            StoreError::Io(format!("could not remove {}: {error}", path.display()))
        })
    }

    /// How many distinct defects `project` holds.
    ///
    /// # Errors
    /// [`StoreError::Io`] when the directory cannot be listed.
    pub fn count(&self, project: &str) -> Result<usize, StoreError> {
        Ok(self.records(project)?.len())
    }

    /// Reads one record by its project and id — the accessor `crate::service`'s account routes
    /// use to check who filed a report before letting its own account withdraw it, without
    /// reading every record in the project the way [`Self::list`] does.
    ///
    /// # Errors
    /// [`StoreError::Unreadable`] when no such record exists, [`StoreError::Io`] when it exists
    /// but cannot be read.
    pub fn get(&self, project: &str, id: &str) -> Result<Entry, StoreError> {
        let path = self.record_path(project, id);
        if !path.exists() {
            return Err(StoreError::Unreadable(format!(
                "`{project}` holds no report `{}`",
                safe_id(id)
            )));
        }
        self.read(project, &path)
    }

    /// Reads one record.
    fn read(&self, project: &str, path: &Path) -> Result<Entry, StoreError> {
        let text = fs::read_to_string(path).map_err(|error| {
            StoreError::Io(format!("could not read {}: {error}", path.display()))
        })?;
        let value = selfhost_json::parse(&text)
            .map_err(|error| StoreError::Unreadable(format!("{}: {error}", path.display())))?;
        let id = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_default();
        entry(project, id, &value).ok_or_else(|| {
            StoreError::Unreadable(format!("{} is not a report record", path.display()))
        })
    }

    /// Writes `entry`, shedding history until it fits [`MAX_RECORD_BYTES`], and returns what was
    /// actually stored.
    fn write(&self, mut entry: Entry) -> Result<Entry, StoreError> {
        if entry.seen.len() > MAX_SIGHTINGS_KEPT {
            let excess = entry.seen.len() - MAX_SIGHTINGS_KEPT;
            entry.seen.drain(..excess);
        }
        let mut encoded = to_json(&entry).to_text();
        let mut oldest = 0;
        while encoded.len() > MAX_RECORD_BYTES && oldest < entry.seen.len() {
            // Detail first: the fact that a sighting happened is worth more than its prose.
            entry.seen[oldest].detail.clear();
            oldest += 1;
            encoded = to_json(&entry).to_text();
        }
        while encoded.len() > MAX_RECORD_BYTES && entry.seen.len() > 1 {
            entry.seen.remove(0);
            encoded = to_json(&entry).to_text();
        }

        let path = self.record_path(&entry.project, &entry.id);
        let temporary = path.with_extension("json.tmp");
        fs::write(&temporary, format!("{encoded}\n")).map_err(|error| {
            StoreError::Io(format!("could not write {}: {error}", temporary.display()))
        })?;
        restrict(&temporary);
        fs::rename(&temporary, &path).map_err(|error| {
            let _ = fs::remove_file(&temporary);
            StoreError::Io(format!("could not store {}: {error}", path.display()))
        })?;
        Ok(entry)
    }

    /// Every record file in one project.
    fn records(&self, project: &str) -> Result<Vec<PathBuf>, StoreError> {
        let dir = self.project_dir(project);
        let listing = fs::read_dir(&dir).map_err(|error| {
            StoreError::Io(format!("could not read {}: {error}", dir.display()))
        })?;
        let mut paths: Vec<PathBuf> = listing
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
                    && path
                        .file_stem()
                        .and_then(|stem| stem.to_str())
                        .is_some_and(is_record_id)
            })
            .collect();
        paths.sort();
        Ok(paths)
    }

    /// The directory one project's records live in.
    ///
    /// Joined through [`safe_key`] rather than trusted: a key also arrives from a command line
    /// and from a URL, and a path built from an unchecked string is how a store becomes a write
    /// primitive.
    fn project_dir(&self, project: &str) -> PathBuf {
        self.dir.join(safe_key(project))
    }

    /// The file one id is stored in.
    fn record_path(&self, project: &str, id: &str) -> PathBuf {
        self.project_dir(project)
            .join(format!("{}.json", safe_id(id)))
    }
}

/// The key with every character that is not `[a-z0-9._-]` replaced and every `..` broken, so it
/// can only ever name a directory directly inside the store.
///
/// [`crate::report::project_key`] has already refused anything this would have to repair; this
/// is the second lock on the same door, because the argument also arrives from a command line
/// and a path built from an unchecked string is a write primitive.
fn safe_key(key: &str) -> String {
    let cleaned: String = key
        .chars()
        .map(|character| match character {
            'a'..='z' | '0'..='9' | '-' | '_' | '.' => character,
            'A'..='Z' => character.to_ascii_lowercase(),
            _ => '-',
        })
        .take(crate::report::MAX_PROJECT)
        .collect();
    let mut broken = cleaned;
    while broken.contains("..") {
        broken = broken.replace("..", "-");
    }
    let trimmed = broken.trim_matches(['-', '.']).to_string();
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed
    }
}

/// The id with every character that is not `[a-z0-9-]` replaced — no separator, no `..`, no
/// drive letter, no NUL.
fn safe_id(id: &str) -> String {
    let cleaned: String = id
        .chars()
        .map(|character| match character {
            'a'..='z' | '0'..='9' | '-' => character,
            'A'..='Z' => character.to_ascii_lowercase(),
            _ => '-',
        })
        .take(64)
        .collect();
    if cleaned.is_empty() {
        "report-unnamed".to_string()
    } else {
        cleaned
    }
}

/// Whether a file stem is one of this crate's record ids.
fn is_record_id(stem: &str) -> bool {
    stem.starts_with("report-") && stem == safe_id(stem)
}

/// Restricts `path` to its owner where the platform has such a concept.
///
/// A report can carry whatever a stranger typed, and the store sits inside the daemon's data
/// directory, which `docs/SECURITY.md` requires to be owner-only. On Windows the directory
/// inherits the parent's ACL, which is the same intent expressed by the platform that has no
/// mode bits; failure is not fatal, because a store that exists is better than no intake.
fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if path.is_dir() { 0o700 } else { 0o600 };
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// One record as JSON — also exactly what a subscriber reads, so a checkout can rebuild the
/// report without a second shape to keep in step.
#[must_use]
pub fn to_json(entry: &Entry) -> Json {
    Json::object([
        ("project", Json::string(&entry.project)),
        ("id", Json::string(&entry.id)),
        ("kind", Json::string(entry.kind.as_str())),
        ("title", Json::string(&entry.title)),
        ("detail", Json::string(&entry.detail)),
        ("route", Json::string(&entry.route)),
        ("repro", Json::string(&entry.repro)),
        ("first_at", Json::string(&entry.first_at)),
        ("last_at", Json::string(&entry.last_at)),
        ("sightings", Json::Number(entry.sightings as f64)),
        ("delivered", Json::Bool(entry.delivered)),
        (
            "account_id",
            entry.account_id.as_ref().map_or(Json::Null, Json::string),
        ),
        (
            "seen",
            Json::array(entry.seen.iter().map(|sighting| {
                Json::object([
                    ("at", Json::string(&sighting.at)),
                    ("tool", Json::string(&sighting.tool)),
                    ("platform", Json::string(&sighting.platform)),
                    ("workspace", Json::string(&sighting.workspace)),
                    ("source", Json::string(&sighting.source)),
                    ("detail", Json::string(&sighting.detail)),
                ])
            })),
        ),
    ])
}

/// One record from JSON, or `None` when the value is not one.
fn entry(project: &str, id: &str, value: &Json) -> Option<Entry> {
    let text = |key: &str| {
        value
            .get(key)
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let title = text("title");
    if title.is_empty() {
        return None;
    }
    let kind = Kind::parse(&text("kind")).ok()?;
    let seen = value
        .get("seen")
        .and_then(Json::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    let field = |key: &str| {
                        item.get(key)
                            .and_then(Json::as_str)
                            .unwrap_or_default()
                            .to_string()
                    };
                    Sighting {
                        at: field("at"),
                        tool: field("tool"),
                        platform: field("platform"),
                        workspace: field("workspace"),
                        source: field("source"),
                        detail: field("detail"),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    Some(Entry {
        project: project.to_string(),
        id: id.to_string(),
        kind,
        title,
        detail: text("detail"),
        route: text("route"),
        repro: text("repro"),
        first_at: text("first_at"),
        last_at: text("last_at"),
        sightings: value.get("sightings").and_then(Json::as_u64).unwrap_or(1) as usize,
        seen,
        delivered: value
            .get("delivered")
            .and_then(Json::as_bool)
            .unwrap_or(false),
        account_id: value
            .get("account_id")
            .and_then(Json::as_str)
            .map(str::to_string),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> Store {
        let dir = std::env::temp_dir().join(format!("selfhost-reports-{label}"));
        let _ = fs::remove_dir_all(&dir);
        let store = Store::open(&dir).expect("store");
        store.add_project("dx").expect("project");
        store
    }

    fn report(title: &str, detail: &str) -> Report {
        Report {
            project: "dx".to_string(),
            kind: Kind::Bug,
            title: title.to_string(),
            detail: detail.to_string(),
            route: "dx_search".to_string(),
            repro: String::new(),
            tool: "dx 0.1.0".to_string(),
            platform: "macos".to_string(),
            workspace: "DOC".to_string(),
            at: "2026-08-11T00:00:00Z".to_string(),
            source: "abcd1234".to_string(),
            account_id: None,
        }
    }

    /// Filing is registration: a service exists because a report named it.
    #[test]
    fn a_report_about_a_service_nobody_declared_creates_that_service() {
        let store = scratch("unknown-project");
        let mut elsewhere = report("t", "d");
        elsewhere.project = "billing".to_string();
        let recorded = store.record(&elsewhere).expect("filed");
        assert!(recorded.fresh);
        assert!(store.has_project("billing"));
        assert_eq!(store.list("billing").expect("list").len(), 1);
    }

    /// The bound on that door: a stranger may bring a service into existence, but not an
    /// unbounded number of them, and the refusal says what to do.
    #[test]
    fn a_new_service_past_the_cap_is_refused_while_the_ones_here_keep_working() {
        let store = scratch("project-cap");
        for nth in 0..MAX_PROJECTS {
            store.add_project(&format!("svc{nth}")).expect("project");
        }
        let mut fresh = report("t", "d");
        fresh.project = "one-too-many".to_string();
        let error = store.record(&fresh).expect_err("refused");
        assert!(matches!(error, StoreError::Full(_)));
        assert!(error.to_string().contains("services"), "{error}");
        assert!(!store.has_project("one-too-many"));

        let mut known = report("t", "d");
        known.project = "svc0".to_string();
        store
            .record(&known)
            .expect("a service that exists still takes reports");
    }

    #[test]
    fn one_defect_reported_twice_is_one_record_with_two_sightings() {
        let store = scratch("twice");
        let first = store
            .record(&report("a search misses", "once"))
            .expect("first");
        assert!(first.fresh);
        assert_eq!(first.entry.sightings, 1);

        let mut again = report("a search misses", "and again");
        again.at = "2026-08-12T00:00:00Z".to_string();
        let second = store.record(&again).expect("second");
        assert!(
            !second.fresh,
            "the same defect must not create a second record"
        );
        assert_eq!(second.entry.sightings, 2);
        assert_eq!(second.entry.last_at, "2026-08-12T00:00:00Z");
        assert_eq!(store.count("dx").expect("count"), 1);
        assert_eq!(second.entry.seen.len(), 2);
        assert_eq!(
            second.entry.detail, "once",
            "the first words are the record's words"
        );
    }

    #[test]
    fn projects_are_separate_databases() {
        let store = scratch("projects");
        store.add_project("self-host").expect("second project");
        store.record(&report("shared title", "d")).expect("dx");
        let mut other = report("shared title", "d");
        other.project = "self-host".to_string();
        store.record(&other).expect("self-host");

        assert_eq!(store.list("dx").expect("dx").len(), 1);
        assert_eq!(store.list("self-host").expect("self-host").len(), 1);
        assert_eq!(store.projects().expect("projects"), vec!["dx", "self-host"]);
    }

    #[test]
    fn a_record_survives_a_reopen_and_lists_newest_first() {
        let store = scratch("reopen");
        store.record(&report("older", "d")).expect("older");
        let mut newer = report("newer", "d");
        newer.at = "2026-09-01T00:00:00Z".to_string();
        store.record(&newer).expect("newer");

        let reopened = Store::open(store.directory()).expect("reopen");
        let listing = reopened.list("dx").expect("list");
        assert_eq!(listing.len(), 2);
        assert_eq!(listing[0].title, "newer");
    }

    #[test]
    fn delivery_state_is_what_the_retry_reads() {
        let store = scratch("delivery");
        let recorded = store.record(&report("undelivered", "d")).expect("record");
        assert_eq!(store.undelivered(10).expect("waiting").len(), 1);

        store
            .mark_delivered("dx", &recorded.entry.id)
            .expect("mark");
        assert!(store.undelivered(10).expect("waiting").is_empty());

        // A repeat sighting is news again, so it goes back on the queue.
        store
            .record(&report("undelivered", "again"))
            .expect("again");
        assert_eq!(store.undelivered(10).expect("waiting").len(), 1);
    }

    #[test]
    fn a_much_reported_defect_stays_a_record_rather_than_a_log() {
        let store = scratch("bounded");
        let long = "x".repeat(4_000);
        for nth in 0..(MAX_SIGHTINGS_KEPT + 20) {
            let mut again = report("floods", &long);
            again.at = format!("2026-08-11T00:{:02}:00Z", nth % 60);
            store.record(&again).expect("record");
        }
        let entry = &store.list("dx").expect("list")[0];
        assert_eq!(
            entry.sightings,
            MAX_SIGHTINGS_KEPT + 20,
            "the count is never reduced"
        );
        assert!(entry.seen.len() <= MAX_SIGHTINGS_KEPT);

        let size = fs::metadata(store.record_path("dx", &entry.id))
            .expect("size")
            .len();
        assert!(
            size as usize <= MAX_RECORD_BYTES + 1_024,
            "record grew to {size} bytes"
        );
    }

    #[test]
    fn neither_a_key_nor_an_id_can_leave_the_store() {
        let store = scratch("traversal");
        let path = store.record_path("../../etc", "../../passwd");
        assert!(path.starts_with(store.directory()));
        assert!(!path.to_string_lossy().contains(".."));
        assert!(
            !store.has_project("../../etc"),
            "traversal must not resolve to a project"
        );
    }

    #[test]
    fn closing_a_report_that_does_not_exist_says_so() {
        let store = scratch("close");
        let error = store
            .close("dx", "report-deadbeef")
            .expect_err("no such report");
        assert!(error.to_string().contains("holds no report"), "{error}");

        let recorded = store.record(&report("closable", "d")).expect("record");
        store.close("dx", &recorded.entry.id).expect("closed");
        assert!(store.list("dx").expect("list").is_empty());
    }

    #[test]
    fn a_corrupt_record_is_kept_beside_the_one_that_replaces_it() {
        let store = scratch("corrupt");
        let filed = report("corrupted", "d");
        let path = store.record_path("dx", &filed.id());
        fs::write(&path, "{ this is not json").expect("write");

        let recorded = store.record(&filed).expect("recorded anyway");
        assert!(recorded.fresh);
        assert!(
            path.with_extension("json.broken").exists(),
            "the bad bytes are kept"
        );
    }

    #[test]
    fn a_feed_answer_is_bounded_however_many_reports_exist() {
        let store = scratch("bounded-feed");
        for nth in 0..(MAX_FEED + 5) {
            store
                .record(&report(&format!("defect {nth}"), "d"))
                .expect("record");
        }
        assert_eq!(store.list("dx").expect("list").len(), MAX_FEED);
    }

    #[test]
    fn the_first_reporters_account_owns_a_record_and_a_later_anonymous_sighting_does_not_change_that()
     {
        let store = scratch("account-ownership");
        let mut first = report("owned bug", "d");
        first.account_id = Some("acct-1".to_string());
        let recorded = store.record(&first).expect("filed");
        assert_eq!(recorded.entry.account_id, Some("acct-1".to_string()));

        // Somebody else — anonymous, or a different account — reports the same defect. The
        // record still belongs to whoever filed it first.
        let mut again = report("owned bug", "and again");
        again.account_id = None;
        let second = store.record(&again).expect("second sighting");
        assert_eq!(
            second.entry.account_id,
            Some("acct-1".to_string()),
            "ownership does not move"
        );
        let _ = std::fs::remove_dir_all(store.directory());
    }

    #[test]
    fn get_reads_one_record_by_id_and_names_a_missing_one() {
        let store = scratch("get-one");
        let recorded = store.record(&report("gettable", "d")).expect("filed");
        let found = store.get("dx", &recorded.entry.id).expect("found");
        assert_eq!(found.title, "gettable");

        let error = store
            .get("dx", "report-deadbeef")
            .expect_err("no such report");
        assert!(matches!(error, StoreError::Unreadable(_)));
        let _ = std::fs::remove_dir_all(store.directory());
    }

    #[test]
    fn a_record_round_trips_through_the_json_a_subscriber_reads() {
        let store = scratch("round-trip");
        let recorded = store
            .record(&report("round trip", "the words"))
            .expect("record");
        let encoded = to_json(&recorded.entry).to_text();
        let decoded = entry(
            "dx",
            &recorded.entry.id,
            &selfhost_json::parse(&encoded).expect("json"),
        )
        .expect("record");
        assert_eq!(decoded, recorded.entry);
    }
}
