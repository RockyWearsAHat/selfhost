//! Persistence for which GitHub accounts have installed this App and which
//! repositories are selected.
//!
//! This module is increment (c) of the Netlify-style deploy bot: it gives a
//! later increment (proxy wiring, receiving webhooks) somewhere to record
//! installation/repo state that survives a restart, and gives a later `selfhost
//! repo list` CLI command somewhere to read it from. Nothing here is wired into
//! `crates/app/proxy`, `crates/app/admin`, or `crates/foundation/config` yet —
//! this crate still has zero external callers, which is expected.
//!
//! This module does not know about `data_dir` or any other daemon directory
//! layout concept; the caller decides the file's path (matching how
//! `AppSpec`/`GitWatch` in `crates/foundation/config` stay agnostic of where
//! the daemon keeps its own state).
//!
//! # Atomicity and concurrent writers
//!
//! Every write reads the whole file, modifies it, and writes it back to a
//! temporary file before renaming over the real one — the same
//! read-modify-write-then-atomic-rename shape `selfhost_admin::store::Store`
//! uses for `services.toml`, for the same reason: `rename` is atomic within a
//! directory, so a crash or a full disk mid-write leaves the previous state
//! intact rather than truncated. An in-process `Mutex` serialises the
//! read-modify-write sequence itself, because two writers racing between their
//! own read and their own write could otherwise each read the same starting
//! state and the second write would silently discard the first one's change —
//! again matching `selfhost_admin::store::Store`'s reasoning; `rename`'s
//! atomicity alone only protects the file from being observed half-written, it
//! does not serialise two writers against each other.
//!
//! [`Store::state`] re-reads the file from disk on every call rather than
//! caching in memory, matching the reasoning `crates/app/proxy/src/server.rs`
//! gives for its own `lookup_webhook_secret`: a value read fresh from disk
//! stays correct even when some other process (later, a CLI) is the one that
//! changed it, whereas an in-memory cache would need its own invalidation
//! story to avoid serving stale data across process boundaries.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::webhook::RepoRef;

/// The installation-store file's name, fixed relative to a deployment's data
/// directory.
///
/// One constant rather than the literal typed twice: `crates/app/proxy/src/server.rs`
/// opens the store a running daemon writes to, and `selfhost repo` (in
/// `crates/app/cli`) opens the very same file to read it — those two paths
/// disagreeing, even by a typo, would mean the CLI silently reads an empty
/// store forever while the daemon writes somewhere else.
const STORE_FILENAME: &str = "github-installations.toml";

/// Where the installation store lives under a deployment's data directory.
///
/// The one place this join happens — see the module docs on why the same path
/// must be shared rather than reconstructed at each call site.
pub fn store_path(data_dir: &Path) -> PathBuf {
    data_dir.join(STORE_FILENAME)
}

/// Splits a repository clone URL into a lowercased `(owner, name)` pair.
///
/// Handles the shapes a [`crate::webhook::RepoRef`]-tracked repository and a
/// `GitWatch.repository` both take: `https://github.com/<owner>/<repo>`, the
/// same with a trailing `.git`, and a trailing slash. Only the last two path
/// segments are read, so this also tolerates `git@github.com:<owner>/<repo>.git`
/// — the `:` before `owner` is not a `/`, but `rsplitn` only looks at the last
/// two segments and does not care what came before them.
///
/// Returns `None` when there are not two non-empty segments to read — a
/// malformed or unexpected URL shape should not be silently matched against
/// the wrong repository.
pub fn parse_owner_repo(repository: &str) -> Option<(String, String)> {
    let trimmed = repository.trim().trim_end_matches('/');
    let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    let (owner, name) = trimmed.rsplit_once(['/', ':'])?;
    if name.is_empty() || owner.is_empty() {
        return None;
    }
    // `owner` may still carry a scheme/host prefix if there was only one `/` or
    // `:` in the whole string (e.g. bare "owner:repo" with no host) — take only
    // the trailing path segment of it, the same way the two-slash case does.
    let owner = owner.rsplit(['/', ':']).next().unwrap_or(owner);
    if owner.is_empty() {
        return None;
    }
    Some((owner.to_ascii_lowercase(), name.to_ascii_lowercase()))
}

/// Whether a `GitWatch`/tracked-repo `repository` clone URL points at
/// `owner/name`, case-insensitively and whether or not it carries a trailing
/// `.git`.
///
/// Shared by `crates/app/proxy/src/server.rs`'s `lookup_service_for_repo` (a
/// push webhook, deciding which service to redeploy) and `selfhost repo list`
/// (deciding which tracked repo already has a live service) — the same
/// question asked from two different directions, so it is answered once.
pub fn repository_matches(repository: &str, owner: &str, name: &str) -> bool {
    match parse_owner_repo(repository) {
        Some((repo_owner, repo_name)) => {
            repo_owner == owner.to_ascii_lowercase() && repo_name == name.to_ascii_lowercase()
        }
        None => false,
    }
}

/// The full set of GitHub App installations this box knows about.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct InstallationState {
    /// One entry per GitHub account (user or org) that has installed this App.
    #[serde(default)]
    pub installations: Vec<Installation>,
}

/// One GitHub account's installation of this App, and the repos it exposes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Installation {
    /// The installation's numeric id, as GitHub assigns it.
    pub installation_id: u64,
    /// The login of the account (user or org) the App is installed on.
    pub account_login: String,
    /// The repositories this installation currently exposes to the App.
    #[serde(default)]
    pub repos: Vec<TrackedRepo>,
}

/// One repository this App can see, and what is known about its last push
/// and deploy.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrackedRepo {
    /// The repository owner's login.
    pub owner: String,
    /// The repository's name, without the owner prefix.
    pub name: String,
    /// Unix timestamp of the last push webhook seen for this repo, if any.
    #[serde(default)]
    pub last_push_unix: Option<u64>,
    /// Free text describing the outcome of the last deploy attempt (e.g.
    /// `"Updated 3f2a1c"`, `"BuildFailed: npm ci exit 1"`). A later increment
    /// populates this; this one only carries the field.
    #[serde(default)]
    pub last_deploy_outcome: Option<String>,
}

/// Everything that can go wrong reading or writing an [`InstallationState`].
#[derive(Debug)]
pub enum StoreError {
    /// The file could not be read or written (permissions, disk full, ...).
    Io(String),
    /// The file's contents were not valid TOML for [`InstallationState`].
    Parse(String),
    /// The state could not be serialised back to TOML (should not normally
    /// happen, since every field is a plain, serialisable type).
    Serialize(String),
    /// A write targeted an installation id not present in the stored state.
    UnknownInstallation(u64),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(detail) => write!(f, "installation store I/O failed: {detail}"),
            StoreError::Parse(detail) => write!(f, "installation store is not valid TOML: {detail}"),
            StoreError::Serialize(detail) => write!(f, "could not serialise installation store: {detail}"),
            StoreError::UnknownInstallation(id) => {
                write!(f, "installation {id} is not known to this store — repos-added event for an unregistered installation")
            }
        }
    }
}

impl std::error::Error for StoreError {}

/// Reads and writes the on-disk record of GitHub App installations and their
/// tracked repositories.
///
/// See the module docs for the atomicity and freshness guarantees this type
/// provides.
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    guard: Mutex<()>,
}

impl Store {
    /// Opens a store backed by the TOML file at `path`.
    ///
    /// The file is not read or created here — a missing file is not an error
    /// until someone actually asks for [`Store::state`], at which point it is
    /// treated as an empty [`InstallationState`] rather than a failure. This
    /// matches the "absent means the subsystem does not exist yet" posture
    /// `selfhost.config.toml`'s commented-out `[desktop]` section documents
    /// elsewhere in this repo.
    pub fn load(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        Ok(Self { path: path.into(), guard: Mutex::new(()) })
    }

    /// Reads the current state fresh from disk.
    ///
    /// A missing file reads as an empty [`InstallationState`]; a malformed
    /// file is reported as [`StoreError::Parse`] rather than silently
    /// discarded, so a corrupted store cannot masquerade as "no installations".
    pub fn state(&self) -> Result<InstallationState, StoreError> {
        self.read_locked()
    }

    /// Reads the file with no locking of its own (callers under `guard` use
    /// this directly; [`Store::state`] is the unlocked public entry point).
    fn read_locked(&self) -> Result<InstallationState, StoreError> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(InstallationState::default());
            }
            Err(error) => return Err(StoreError::Io(error.to_string())),
        };
        toml::from_str(&text).map_err(|error| StoreError::Parse(error.to_string()))
    }

    /// Writes `state` atomically: to a temporary file beside `path`, then
    /// renamed over it.
    fn write(&self, state: &InstallationState) -> Result<(), StoreError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|error| StoreError::Io(error.to_string()))?;
        }
        let text = toml::to_string_pretty(state).map_err(|error| StoreError::Serialize(error.to_string()))?;
        let temporary = self.path.with_extension("toml.new");
        std::fs::write(&temporary, text).map_err(|error| StoreError::Io(error.to_string()))?;
        std::fs::rename(&temporary, &self.path).map_err(|error| StoreError::Io(error.to_string()))
    }

    /// Records that `installation_id` belongs to `account_login`.
    ///
    /// Idempotent: if the installation is already known, only its
    /// `account_login` is updated in place (its repos are left alone); else a
    /// new [`Installation`] is appended with an empty repo list.
    pub fn upsert_installation(&self, installation_id: u64, account_login: &str) -> Result<(), StoreError> {
        let _held = self.guard.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = self.read_locked()?;
        match state.installations.iter_mut().find(|installation| installation.installation_id == installation_id) {
            Some(installation) => installation.account_login = account_login.to_owned(),
            None => state.installations.push(Installation {
                installation_id,
                account_login: account_login.to_owned(),
                repos: Vec::new(),
            }),
        }
        self.write(&state)
    }

    /// Removes an installation entirely (its repos go with it).
    ///
    /// Handles the `installation` webhook's `deleted` action. A no-op if the
    /// installation was not known.
    pub fn remove_installation(&self, installation_id: u64) -> Result<(), StoreError> {
        let _held = self.guard.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = self.read_locked()?;
        state.installations.retain(|installation| installation.installation_id != installation_id);
        self.write(&state)
    }

    /// Adds `repos` to `installation_id`'s tracked list, skipping any already
    /// present (matched by owner/name).
    ///
    /// Errors with [`StoreError::UnknownInstallation`] if `installation_id`
    /// is not known — a repos-added event for an installation this store has
    /// never seen is a real inconsistency, not something to silently ignore.
    pub fn add_repos(&self, installation_id: u64, repos: &[RepoRef]) -> Result<(), StoreError> {
        let _held = self.guard.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = self.read_locked()?;
        let installation = state
            .installations
            .iter_mut()
            .find(|installation| installation.installation_id == installation_id)
            .ok_or(StoreError::UnknownInstallation(installation_id))?;
        for repo in repos {
            let already_tracked = installation
                .repos
                .iter()
                .any(|tracked| tracked.owner == repo.owner && tracked.name == repo.name);
            if !already_tracked {
                installation.repos.push(TrackedRepo {
                    owner: repo.owner.clone(),
                    name: repo.name.clone(),
                    last_push_unix: None,
                    last_deploy_outcome: None,
                });
            }
        }
        self.write(&state)
    }

    /// Removes `repos` from `installation_id`'s tracked list (matched by
    /// owner/name). A no-op for any not present.
    pub fn remove_repos(&self, installation_id: u64, repos: &[RepoRef]) -> Result<(), StoreError> {
        let _held = self.guard.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = self.read_locked()?;
        if let Some(installation) =
            state.installations.iter_mut().find(|installation| installation.installation_id == installation_id)
        {
            installation
                .repos
                .retain(|tracked| !repos.iter().any(|repo| repo.owner == tracked.owner && repo.name == tracked.name));
        }
        self.write(&state)
    }

    /// Records that a push landed on `owner/repo` at `at_unix`.
    ///
    /// Finds the repo across all installations by owner/name. A repo that is
    /// not tracked is not an error here — a later increment's caller decides
    /// whether that is log-worthy; this layer just tolerates it.
    pub fn record_push(&self, owner: &str, repo: &str, at_unix: u64) -> Result<(), StoreError> {
        let _held = self.guard.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = self.read_locked()?;
        if let Some(tracked) = find_repo_mut(&mut state, owner, repo) {
            tracked.last_push_unix = Some(at_unix);
        }
        self.write(&state)
    }

    /// Records the outcome of the last deploy attempt for `owner/repo`.
    ///
    /// Same lookup as [`Store::record_push`]; a no-op if the repo is not
    /// tracked.
    pub fn record_deploy_outcome(&self, owner: &str, repo: &str, outcome: &str) -> Result<(), StoreError> {
        let _held = self.guard.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut state = self.read_locked()?;
        if let Some(tracked) = find_repo_mut(&mut state, owner, repo) {
            tracked.last_deploy_outcome = Some(outcome.to_owned());
        }
        self.write(&state)
    }
}

/// Finds a tracked repo by owner/name across every installation.
fn find_repo_mut<'a>(state: &'a mut InstallationState, owner: &str, repo: &str) -> Option<&'a mut TrackedRepo> {
    state
        .installations
        .iter_mut()
        .flat_map(|installation| installation.repos.iter_mut())
        .find(|tracked| tracked.owner == owner && tracked.name == repo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_path_joins_the_fixed_filename() {
        assert_eq!(store_path(Path::new("/var/lib/selfhost/data")), Path::new("/var/lib/selfhost/data/github-installations.toml"));
    }

    #[test]
    fn parses_owner_repo_from_a_plain_https_url() {
        assert_eq!(
            parse_owner_repo("https://github.com/octocat/hello-world"),
            Some(("octocat".to_owned(), "hello-world".to_owned()))
        );
    }

    #[test]
    fn parses_owner_repo_with_a_dot_git_suffix() {
        assert_eq!(
            parse_owner_repo("https://github.com/octocat/hello-world.git"),
            Some(("octocat".to_owned(), "hello-world".to_owned()))
        );
    }

    #[test]
    fn parses_owner_repo_case_insensitively() {
        assert_eq!(
            parse_owner_repo("https://GitHub.com/OctoCat/Hello-World.git"),
            Some(("octocat".to_owned(), "hello-world".to_owned()))
        );
    }

    #[test]
    fn parses_owner_repo_from_an_ssh_style_url() {
        assert_eq!(
            parse_owner_repo("git@github.com:octocat/hello-world.git"),
            Some(("octocat".to_owned(), "hello-world".to_owned()))
        );
    }

    #[test]
    fn parses_owner_repo_with_a_trailing_slash() {
        assert_eq!(
            parse_owner_repo("https://github.com/octocat/hello-world/"),
            Some(("octocat".to_owned(), "hello-world".to_owned()))
        );
    }

    #[test]
    fn a_url_with_no_owner_segment_does_not_parse() {
        assert_eq!(parse_owner_repo("hello-world"), None);
        assert_eq!(parse_owner_repo(""), None);
    }

    #[test]
    fn repository_matches_ignores_case_and_git_suffix() {
        assert!(repository_matches("https://github.com/octocat/hello-world.git", "OctoCat", "Hello-World"));
        assert!(repository_matches("https://github.com/octocat/hello-world", "octocat", "hello-world"));
        assert!(!repository_matches("https://github.com/octocat/other-repo.git", "octocat", "hello-world"));
    }

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir()
            .join(format!("selfhost-github-app-store-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path.join("github-installations.toml")
    }

    #[test]
    fn loading_a_nonexistent_file_reads_as_empty_state() {
        let path = scratch("missing");
        let store = Store::load(&path).unwrap();
        assert!(store.state().unwrap().installations.is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn upsert_then_state_round_trips() {
        let path = scratch("roundtrip");
        let store = Store::load(&path).unwrap();
        store.upsert_installation(42, "octocat").unwrap();

        let state = store.state().unwrap();
        assert_eq!(state.installations.len(), 1);
        assert_eq!(state.installations[0].installation_id, 42);
        assert_eq!(state.installations[0].account_login, "octocat");
        assert!(state.installations[0].repos.is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn upsert_on_an_existing_id_updates_login_in_place() {
        let path = scratch("upsert-update");
        let store = Store::load(&path).unwrap();
        store.upsert_installation(1, "old-login").unwrap();
        store.add_repos(1, &[RepoRef { owner: "octocat".into(), name: "hello-world".into() }]).unwrap();
        store.upsert_installation(1, "new-login").unwrap();

        let state = store.state().unwrap();
        assert_eq!(state.installations.len(), 1);
        assert_eq!(state.installations[0].account_login, "new-login");
        assert_eq!(state.installations[0].repos.len(), 1, "repos survive a login update");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn add_repos_on_unknown_installation_errors() {
        let path = scratch("unknown-install");
        let store = Store::load(&path).unwrap();
        let result = store.add_repos(999, &[RepoRef { owner: "a".into(), name: "b".into() }]);
        assert!(matches!(result, Err(StoreError::UnknownInstallation(999))));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn add_repos_is_idempotent() {
        let path = scratch("idempotent");
        let store = Store::load(&path).unwrap();
        store.upsert_installation(1, "octocat").unwrap();
        let repos = [RepoRef { owner: "octocat".into(), name: "hello-world".into() }];
        store.add_repos(1, &repos).unwrap();
        store.add_repos(1, &repos).unwrap();

        let state = store.state().unwrap();
        assert_eq!(state.installations[0].repos.len(), 1, "adding the same repo twice must not duplicate it");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn remove_installation_drops_it_and_its_repos() {
        let path = scratch("remove-install");
        let store = Store::load(&path).unwrap();
        store.upsert_installation(1, "octocat").unwrap();
        store.add_repos(1, &[RepoRef { owner: "octocat".into(), name: "hello-world".into() }]).unwrap();
        store.remove_installation(1).unwrap();

        let state = store.state().unwrap();
        assert!(state.installations.is_empty());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn remove_repos_removes_matching_entries_only() {
        let path = scratch("remove-repos");
        let store = Store::load(&path).unwrap();
        store.upsert_installation(1, "octocat").unwrap();
        store
            .add_repos(
                1,
                &[
                    RepoRef { owner: "octocat".into(), name: "hello-world".into() },
                    RepoRef { owner: "octocat".into(), name: "keep-me".into() },
                ],
            )
            .unwrap();
        store.remove_repos(1, &[RepoRef { owner: "octocat".into(), name: "hello-world".into() }]).unwrap();

        let state = store.state().unwrap();
        assert_eq!(state.installations[0].repos.len(), 1);
        assert_eq!(state.installations[0].repos[0].name, "keep-me");
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn record_push_and_deploy_outcome_update_the_right_repo_across_installations() {
        let path = scratch("record");
        let store = Store::load(&path).unwrap();
        store.upsert_installation(1, "octocat").unwrap();
        store.upsert_installation(2, "other-org").unwrap();
        store.add_repos(1, &[RepoRef { owner: "octocat".into(), name: "site-a".into() }]).unwrap();
        store.add_repos(2, &[RepoRef { owner: "other-org".into(), name: "site-b".into() }]).unwrap();

        store.record_push("other-org", "site-b", 1_700_000_000).unwrap();
        store.record_deploy_outcome("other-org", "site-b", "Updated 3f2a1c").unwrap();

        let state = store.state().unwrap();
        let a = state.installations.iter().find(|i| i.installation_id == 1).unwrap();
        let b = state.installations.iter().find(|i| i.installation_id == 2).unwrap();
        assert_eq!(a.repos[0].last_push_unix, None, "installation 1's repo must be untouched");
        assert_eq!(b.repos[0].last_push_unix, Some(1_700_000_000));
        assert_eq!(b.repos[0].last_deploy_outcome.as_deref(), Some("Updated 3f2a1c"));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn record_push_on_an_untracked_repo_is_not_an_error() {
        let path = scratch("record-untracked");
        let store = Store::load(&path).unwrap();
        assert!(store.record_push("nobody", "nothing", 1).is_ok());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn two_sequential_writers_do_not_clobber_each_others_changes() {
        // A lightweight stand-in for true concurrency: proves the
        // read-modify-write sequence in each call reads the *latest* state
        // rather than one captured at store construction time, which is the
        // property that keeps two real concurrent writers from racing.
        let path = scratch("sequential-writers");
        let store = Store::load(&path).unwrap();
        store.upsert_installation(1, "octocat").unwrap();
        store.upsert_installation(2, "other-org").unwrap();

        let state = store.state().unwrap();
        assert_eq!(state.installations.len(), 2);
        assert!(state.installations.iter().any(|i| i.installation_id == 1));
        assert!(state.installations.iter().any(|i| i.installation_id == 2));
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
