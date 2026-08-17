//! Carrying out one deployment: stop, update, build, start.
//!
//! # Why the service is stopped rather than restarted
//!
//! The obvious sequence — pull, then ask the supervisor to restart — has a race
//! that only shows up under load. Updating a working copy under a running process
//! rewrites the files it is executing, and a process that then exits (because its
//! own file changed, or because the build replaced a native module) looks to the
//! supervisor exactly like a crash. The restart policy then fights the deployment
//! for the process, and a service that is mid-`npm install` when its old copy
//! exits reads as a crash loop and can exhaust its restart budget.
//!
//! So a deployment takes the process away first and gives it back at the end.
//! The window is honest downtime — visible in the console, reported in the log —
//! rather than a restart that sometimes works.
//!
//! # What is reported, and where
//!
//! Every step is written into the service's own captured output, tagged `[git]`.
//! The console tails that already, so a deployment is visible in the place the
//! operator is already looking, and no second log has to be correlated with it.

use selfhost_config::{GitWatch, ServiceSpec};
use selfhost_supervisor::Supervisor;
use selfhost_supervisor::state::ServiceState;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::plan::{self, Step};
use crate::run::{self, BUILD_TIMEOUT, TRANSFER_TIMEOUT};

/// How much longer than its own stop timeout a service is given to stop.
///
/// The supervisor's stop ladder ends in a kill after `stop_timeout_secs`, so this
/// is only the time for that ladder to be walked, not a second grace period.
const STOP_SLACK: Duration = Duration::from_secs(5);

/// The tag every line this module writes carries.
pub const TAG: &str = "[git]";

/// How a deployment ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing needed doing.
    NothingToDo,
    /// The working copy is on a new commit and the service is running again.
    Deployed {
        /// The commit now checked out.
        commit: String,
    },
    /// The branch moved but this watch may only report it.
    Reported,
    /// Something failed. The service is left stopped rather than half-updated.
    Failed {
        /// Which step, in an operator's words.
        step: &'static str,
        /// What went wrong.
        reason: String,
    },
}

impl Outcome {
    /// Whether the deployment finished the way it intended to.
    pub fn succeeded(&self) -> bool {
        !matches!(self, Self::Failed { .. })
    }
}

/// Where a watch's working copy lives, resolved against the supervisor's base.
///
/// Relative paths resolve the same way a service's `cwd` does, so a service and
/// the checkout it runs from can name the same directory.
pub fn working_copy(base_dir: &Path, watch: &GitWatch) -> PathBuf {
    base_dir.join(&watch.path)
}

/// Carries out whatever [`Step`] a poll decided on.
///
/// Returns what happened, having already written every step into the service's
/// captured output.
pub async fn carry_out(
    supervisor: &Supervisor,
    spec: &ServiceSpec,
    watch: &GitWatch,
    step: &Step,
) -> Outcome {
    let name = &spec.name;
    match step {
        Step::UpToDate => Outcome::NothingToDo,
        Step::Behind { .. } => {
            note(supervisor, name, step.describe()).await;
            Outcome::Reported
        }
        Step::Clone { to } | Step::Deploy { to, .. } => {
            note(supervisor, name, step.describe()).await;
            update(supervisor, spec, watch, to).await
        }
    }
}

/// The sequence itself: stop, update the working copy, build, start.
async fn update(
    supervisor: &Supervisor,
    spec: &ServiceSpec,
    watch: &GitWatch,
    commit: &str,
) -> Outcome {
    let name = &spec.name;
    let base = supervisor.base_dir().to_path_buf();
    let path = working_copy(&base, watch);

    let was_running = supervisor
        .status(name)
        .await
        .is_some_and(|status| status.state.is_live());
    if was_running {
        note(supervisor, name, "stopping the service before updating it").await;
        supervisor.stop(name).await;
        let settled = selfhost_supervisor::await_state(
            supervisor,
            name,
            Duration::from_secs(spec.stop_timeout_secs) + STOP_SLACK,
            |state| !state.is_live(),
        )
        .await;
        if settled.is_none() {
            // Updating the files under a process that is still running is how a
            // deployment corrupts a half-written tree, so it stops here.
            return failed(supervisor, name, "stop", "the service did not stop".to_owned()).await;
        }
    }

    if let Err(reason) = fetch_into(&path, watch, &base).await {
        return failed(supervisor, name, "update", reason).await;
    }

    if let Some(command) = &watch.post_pull {
        note(supervisor, name, format!("running {}", command.join(" "))).await;
        match run::build_step(command, &path, BUILD_TIMEOUT).await {
            Ok(ran) if ran.succeeded() => {}
            Ok(ran) => {
                // Left stopped on purpose: starting a service on a tree whose
                // build failed runs the previous build against the new code.
                return failed(supervisor, name, "build", ran.complaint()).await;
            }
            Err(error) => return failed(supervisor, name, "build", error.to_string()).await,
        }
    }

    note(supervisor, name, format!("deployed {}, starting", plan::short(commit))).await;
    supervisor.start(name).await;
    Outcome::Deployed { commit: commit.to_owned() }
}

/// Brings the working copy onto the watched branch's newest commit.
///
/// Clones when there is nothing there yet, and fetches then hard-resets when
/// there is. Returns the reason on failure, already fit to show an operator.
async fn fetch_into(path: &Path, watch: &GitWatch, base: &Path) -> Result<(), String> {
    if path.join(".git").is_dir() {
        for args in [plan::fetch_args(watch, path), plan::reset_args(path)] {
            match run::git(&args, base, TRANSFER_TIMEOUT).await {
                Ok(ran) if ran.succeeded() => {}
                Ok(ran) => return Err(ran.complaint()),
                Err(error) => return Err(error.to_string()),
            }
        }
        return Ok(());
    }

    // A directory that exists but holds no repository is not something to clone
    // over: it is either the wrong path or a previous clone that failed halfway,
    // and both want a person rather than another attempt.
    if path.exists() {
        return Err(format!(
            "{} exists but is not a git working copy; move it aside or point the watch \
             somewhere else",
            path.display()
        ));
    }
    if let Some(parent) = path.parent()
        && let Err(error) = tokio::fs::create_dir_all(parent).await
    {
        return Err(format!("cannot create {}: {error}", parent.display()));
    }

    match run::git(&plan::clone_args(watch, path), base, TRANSFER_TIMEOUT).await {
        Ok(ran) if ran.succeeded() => Ok(()),
        Ok(ran) => Err(ran.complaint()),
        Err(error) => Err(error.to_string()),
    }
}

/// Reports a failed step in the service's output and answers the outcome.
async fn failed(
    supervisor: &Supervisor,
    name: &str,
    step: &'static str,
    reason: String,
) -> Outcome {
    note(supervisor, name, format!("{step} failed: {reason}")).await;
    note(supervisor, name, "the service is left stopped; fix the cause and start it").await;
    Outcome::Failed { step, reason }
}

/// Writes one tagged line into a service's captured output.
pub async fn note(supervisor: &Supervisor, name: &str, line: impl AsRef<str>) {
    supervisor.note(name, format!("{TAG} {}", line.as_ref())).await;
}

/// Whether a service is in a state a deployment may leave it in.
///
/// Used by the poller to avoid starting a deployment while the operator has the
/// service deliberately stopped: a push should update the working copy, not
/// override a decision somebody made on purpose.
pub fn is_operator_stopped(state: &ServiceState) -> bool {
    matches!(state, ServiceState::Disabled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_config::StartMode;

    fn watch() -> GitWatch {
        GitWatch::new("https://example.com/repo.git", "checkouts/site")
    }

    #[test]
    fn a_relative_working_copy_resolves_against_the_daemons_base_directory() {
        let path = working_copy(Path::new("/srv/selfhost"), &watch());
        assert_eq!(path, PathBuf::from("/srv/selfhost/checkouts/site"));
    }

    #[test]
    fn an_absolute_working_copy_is_taken_as_written() {
        let mut watch = watch();
        watch.path = PathBuf::from("/var/www/site");
        assert_eq!(working_copy(Path::new("/srv/selfhost"), &watch), PathBuf::from("/var/www/site"));
    }

    #[test]
    fn a_failure_is_not_a_success_and_names_the_step() {
        let failure = Outcome::Failed { step: "build", reason: "npm ci: exit 1".into() };
        assert!(!failure.succeeded());
        assert!(Outcome::Deployed { commit: "abc1234".into() }.succeeded());
        assert!(Outcome::NothingToDo.succeeded());
    }

    #[tokio::test]
    async fn a_working_copy_that_is_not_a_repository_is_refused_rather_than_cloned_over() {
        let base = std::env::temp_dir().join(format!("selfhost-git-{}", std::process::id()));
        let occupied = base.join("checkouts/site");
        tokio::fs::create_dir_all(&occupied).await.expect("a directory to get in the way");
        tokio::fs::write(occupied.join("important.txt"), b"not ours")
            .await
            .expect("a file to protect");

        let error = fetch_into(&occupied, &watch(), &base).await.expect_err("should refuse");
        assert!(error.contains("not a git working copy"), "{error}");
        assert!(occupied.join("important.txt").exists(), "it must not have been destroyed");

        tokio::fs::remove_dir_all(&base).await.expect("clean up");
    }

    #[tokio::test]
    async fn a_deployment_of_an_unmoved_branch_touches_nothing() {
        let supervisor = Supervisor::new(std::env::temp_dir());
        let mut spec = ServiceSpec::new("site", "/bin/true");
        spec.start_mode = StartMode::Manual;
        spec.git = Some(watch());
        supervisor.install(spec.clone()).await;

        let outcome = carry_out(&supervisor, &spec, &watch(), &Step::UpToDate).await;
        assert_eq!(outcome, Outcome::NothingToDo);

        let logs = supervisor.logs("site", 0, 100).await.expect("the service exists");
        assert!(
            !logs.lines.iter().any(|line| line.text.contains(TAG)),
            "a no-op poll must not write anything: {:?}",
            logs.lines
        );
    }

    #[tokio::test]
    async fn a_watch_that_may_only_report_says_so_in_the_services_own_output() {
        let supervisor = Supervisor::new(std::env::temp_dir());
        let mut spec = ServiceSpec::new("reporting", "/bin/true");
        spec.start_mode = StartMode::Manual;
        supervisor.install(spec.clone()).await;

        let mut watch = watch();
        watch.auto_update = false;
        let step = Step::Behind { from: Some("1111111".into()), to: "2222222".into() };
        assert_eq!(carry_out(&supervisor, &spec, &watch, &step).await, Outcome::Reported);

        let logs = supervisor.logs("reporting", 0, 100).await.expect("the service exists");
        let text: String = logs.lines.iter().map(|line| line.text.clone()).collect();
        assert!(text.contains("2222222"), "{text}");
        assert!(text.contains(TAG), "{text}");
    }
}
