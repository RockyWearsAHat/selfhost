//! Deploying a service when a Git branch it watches moves.
//!
//! [`check_once`] is the whole of a deployment check: read the remote branch
//! tip, compare it to the working copy, and if it moved, stop the service,
//! update the working copy, run the build step, and start the service again.
//! What each of those means is in [`plan`] (what to run, and what the answer
//! means), [`run`] (running it), and [`deploy`] (the sequence).
//!
//! There is no background poller here any more. `check_once` is driven
//! entirely on demand: by the GitHub App webhook (`/.selfhost/webhook/app`,
//! wired in `crates/app/proxy`) on a verified `push`, or by an operator's own
//! `POST /api/services/<name>/deploy` (`selfhost_admin::Api::deploy_now`). See
//! `selfhost_config::git`'s module docs for why a timer no longer runs
//! underneath those two triggers.
//!
//! # Why `git` is a program here rather than a protocol we implement
//!
//! Everything this project serves on a wire is written here — HTTP, TLS framing,
//! SMTP, DNS — because a lenient parser is a security bug and an upstream binary
//! is an unattended machine's dependency on a desktop session. Git is neither.
//! It is not in the data path: nothing a visitor sends reaches it, and it runs
//! only when an operator's own branch moves. Reimplementing the pack protocol
//! would buy no independence — the repository is GitHub's either way — while
//! costing the exact correctness this project's other protocol work is for. The
//! same reasoning made the console tunnel over the system `ssh`.
//!
//! What that costs is honest: `git` must be installed on the server, and a
//! missing one is reported as such in the service's own output rather than
//! guessed at.
//!
//! # Shape
//!
//! ```no_run
//! use selfhost_git::check_once;
//! use selfhost_supervisor::Supervisor;
//!
//! # async fn example(supervisor: Supervisor, spec: selfhost_config::ServiceSpec, watch: selfhost_config::GitWatch) {
//! check_once(&supervisor, &spec, &watch).await.ok();
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod deploy;
pub mod nudge;
pub mod plan;
pub mod run;

use selfhost_config::{GitWatch, ServiceSpec};
use selfhost_supervisor::Supervisor;
use std::future::Future;
use std::pin::Pin;

pub use deploy::Outcome;
pub use nudge::Nudge;
pub use plan::Step;

/// A source of short-lived, authenticated fetch URLs for a watch's
/// repository, so a private `github.com` repository can be pulled without a
/// static SSH deploy key.
///
/// Implemented outside this crate by whoever holds the GitHub App's
/// installation store and token cache (`selfhost_github_app`) — this crate
/// only asks "do you have a URL for this repository?" and gets back `None`
/// when there is nothing to add, which leaves today's unauthenticated/SSH
/// behaviour exactly as it was for any repository the App does not track.
/// Kept as a trait rather than a concrete dependency so this crate does not
/// need to know about GitHub Apps at all — see `crate::plan::parse_github_owner_repo`
/// for the one thing it does need to recognize about a repository string.
pub trait CredentialSource: Send + Sync {
    /// Returns a fresh authenticated HTTPS URL for `repository` (a watch's
    /// configured remote, in either SSH or HTTPS form), or `None` if this
    /// source has nothing for it.
    fn authenticated_url(&self, repository: &str) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>>;
}

/// Checks a watched branch once and acts on what it finds.
///
/// This is the whole of a deployment check, called directly by whatever asked
/// for one: the GitHub App webhook route, on a verified push, or the manual
/// `POST /api/services/<name>/deploy`/`POST /api/self-update/deploy` doors.
/// There is no background task that calls this on a timer any more — see the
/// module docs. The error is what to tell the operator, already phrased for
/// them.
pub async fn check_once(
    supervisor: &Supervisor,
    spec: &ServiceSpec,
    watch: &GitWatch,
) -> Result<Outcome, String> {
    check_once_with_credential(supervisor, spec, watch, None, false).await
}

/// Same as [`check_once`], but re-runs the update and build even when the
/// branch tip has not moved.
///
/// This is specifically the "someone asked for a redeploy right now" path —
/// [`crate::deploy`]'s stop/pull/build/start sequence runs again against
/// whatever the branch currently points at, which matters when the working
/// copy's *code* is unchanged but its *build output* needs redoing (a stale
/// `node_modules`, a fixed build script that produced a
/// [`selfhost_supervisor::state::ServiceState::BuildFailed`] last time). It is
/// never what the background poller calls on its own timer — an unattended
/// poll must still treat an unmoved branch as nothing to do, or "redeploy"
/// and "check" become the same word.
pub async fn check_once_forced(
    supervisor: &Supervisor,
    spec: &ServiceSpec,
    watch: &GitWatch,
) -> Result<Outcome, String> {
    check_once_with_credential(supervisor, spec, watch, None, true).await
}

/// Same as [`check_once`], but `credential` — a freshly-minted authenticated
/// URL for `watch.repository`, if the caller has one — is used for the actual
/// `git` transfer in place of `watch.repository`. Never logged: see
/// `plan::repository_url`'s doc for why. `force` skips the "nothing to do"
/// short-circuit exactly as [`check_once_forced`] does.
///
/// Exposed so a caller that holds a [`CredentialSource`] (the control API,
/// wiring the GitHub App's installation token) can authenticate a check
/// triggered by a webhook or a manual deploy, exactly as the removed
/// background poller once did.
pub async fn check_once_with_credential(
    supervisor: &Supervisor,
    spec: &ServiceSpec,
    watch: &GitWatch,
    credential: Option<&str>,
    force: bool,
) -> Result<Outcome, String> {
    let base = supervisor.base_dir().to_path_buf();
    let path = deploy::working_copy(&base, watch);

    let local = local_commit(&path, &base).await;
    let remote = remote_commit(watch, &base, credential).await?;
    let step = plan::decide_forced(watch, local.as_deref(), &remote, force);

    // A disabled service is one somebody switched off deliberately. Updating its
    // working copy would be harmless; starting it again would override that
    // decision, so the whole deployment waits for it to be switched back on.
    if step.acts()
        && let Some(status) = supervisor.status(&spec.name).await
        && deploy::is_operator_stopped(&status.state)
    {
        return Err(format!(
            "{} is waiting to be deployed, but this service is disabled",
            plan::short(&remote)
        ));
    }

    Ok(deploy::carry_out(supervisor, spec, watch, &step, credential).await)
}

/// The commit a working copy is on, or `None` if there is not one yet.
async fn local_commit(path: &std::path::Path, base: &std::path::Path) -> Option<String> {
    if !path.join(".git").is_dir() {
        return None;
    }
    let ran = run::git(&plan::head_args(path), base, run::LS_REMOTE_TIMEOUT).await.ok()?;
    ran.succeeded().then(|| plan::parse_head(&ran.stdout)).flatten()
}

/// The commit a watched remote branch points at.
async fn remote_commit(watch: &GitWatch, base: &std::path::Path, credential: Option<&str>) -> Result<String, String> {
    let ran = run::git(&plan::ls_remote_args(watch, credential), base, run::LS_REMOTE_TIMEOUT)
        .await
        .map_err(|error| format!("cannot check {}: {error}", watch.repository))?;

    if !ran.succeeded() {
        return Err(format!(
            "cannot check {} {}: {}",
            watch.repository,
            watch.branch,
            ran.complaint()
        ));
    }

    plan::commit_for_ref(&ran.stdout, &watch.remote_ref()).ok_or_else(|| {
        format!(
            "{} has no branch {} — the watch is following a branch that does not exist",
            watch.repository, watch.branch
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_config::StartMode;

    fn watched_service(name: &str) -> ServiceSpec {
        let mut spec = ServiceSpec::new(name, "/bin/true");
        spec.start_mode = StartMode::Manual;
        // A branch that does not exist: check_once reports it rather than
        // touching anything on disk.
        let watch = GitWatch::new("https://example.invalid/repo.git", "checkouts/site");
        spec.git = Some(watch);
        spec
    }

    #[tokio::test]
    async fn an_unreachable_remote_is_reported_once_rather_than_every_interval() {
        let supervisor = Supervisor::new(std::env::temp_dir());
        let spec = watched_service("site");
        supervisor.install(spec.clone()).await;

        let watch = spec.git.clone().expect("a watch");

        let first = check_once(&supervisor, &spec, &watch)
            .await
            .expect_err("the remote does not resolve");
        let second = check_once(&supervisor, &spec, &watch).await.expect_err("still does not");
        assert_eq!(first, second, "the same failure must read the same, so it can be deduplicated");
        assert!(first.contains("example.invalid"), "{first}");
    }
}
