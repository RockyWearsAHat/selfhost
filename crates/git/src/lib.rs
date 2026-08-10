//! Watching Git branches, so a push redeploys the service built from it.
//!
//! One task per watched service polls its branch, and when the branch moves it
//! stops the service, updates the working copy, runs the build step, and starts
//! the service again. What each of those means is in [`plan`] (what to run, and
//! what the answer means), [`run`] (running it), and [`deploy`] (the sequence).
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
//! use selfhost_git::Watches;
//! use selfhost_supervisor::Supervisor;
//!
//! # async fn example(supervisor: Supervisor, catalog: selfhost_config::ServiceCatalog) {
//! let watches = Watches::default();
//! watches.load(&supervisor, &catalog).await;
//! # }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod deploy;
pub mod plan;
pub mod run;

use selfhost_config::{GitWatch, ServiceCatalog, ServiceSpec};
use selfhost_supervisor::Supervisor;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

pub use deploy::Outcome;
pub use plan::Step;

/// Every watch currently being polled, one task each.
///
/// Cheap to clone, like the supervisor: the daemon and the control API hold the
/// same set rather than two that can disagree about what is being watched.
///
/// The set is keyed by service name, and installing a service replaces its task
/// rather than adding a second one. Two tasks polling one branch would both see
/// it move and both start a deployment, and the second would find the first's
/// working copy half-updated.
#[derive(Debug, Clone, Default)]
pub struct Watches {
    tasks: Arc<Mutex<BTreeMap<String, JoinHandle<()>>>>,
}

impl Watches {
    /// Starts a poller for every service in a catalogue that has an active watch.
    ///
    /// Returns how many are now being watched, which the daemon prints at startup:
    /// a deployment that silently is not being watched is the failure this whole
    /// module exists to prevent, so the count is stated rather than assumed.
    pub async fn load(&self, supervisor: &Supervisor, catalog: &ServiceCatalog) -> usize {
        let mut started = 0;
        for spec in &catalog.services {
            if self.follow(supervisor, spec).await {
                started += 1;
            }
        }
        started
    }

    /// Watches one service, replacing any watch already running for it.
    ///
    /// Answers whether it is now being polled — `false` for a service with no
    /// watch, or one whose watch is switched off.
    ///
    /// A replacement aborts the previous task, which may be mid-deployment. That
    /// is the intended reading of "the definition changed": the deployment in
    /// flight is for a definition that no longer exists, and its child processes
    /// are killed with it rather than left running against a stale checkout.
    pub async fn follow(&self, supervisor: &Supervisor, spec: &ServiceSpec) -> bool {
        let mut tasks = self.tasks.lock().await;
        if let Some(previous) = tasks.remove(&spec.name) {
            previous.abort();
        }

        let Some(watch) = spec.active_watch() else {
            return false;
        };

        let poller = Poller {
            supervisor: supervisor.clone(),
            spec: spec.clone(),
            watch: watch.clone(),
        };
        tasks.insert(spec.name.clone(), tokio::spawn(poller.run()));
        true
    }

    /// Stops watching one service. Returns whether it was being watched.
    pub async fn forget(&self, name: &str) -> bool {
        match self.tasks.lock().await.remove(name) {
            Some(task) => {
                task.abort();
                true
            }
            None => false,
        }
    }

    /// How many services are being watched.
    pub async fn count(&self) -> usize {
        self.tasks.lock().await.len()
    }

    /// Stops every watch.
    pub async fn shutdown(&self) {
        let taken = std::mem::take(&mut *self.tasks.lock().await);
        for task in taken.into_values() {
            task.abort();
        }
    }
}

/// Checks a watched branch once and acts on what it finds.
///
/// This is the whole of what a poll does, exposed on its own so that a
/// deployment can be driven directly — by a test, and by whatever asks for one
/// on demand later — without waiting out an interval. The error is what to tell
/// the operator, already phrased for them.
pub async fn check_once(
    supervisor: &Supervisor,
    spec: &ServiceSpec,
    watch: &GitWatch,
) -> Result<Outcome, String> {
    let base = supervisor.base_dir().to_path_buf();
    let path = deploy::working_copy(&base, watch);

    let local = local_commit(&path, &base).await;
    let remote = remote_commit(watch, &base).await?;
    let step = plan::decide(watch, local.as_deref(), &remote);

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

    Ok(deploy::carry_out(supervisor, spec, watch, &step).await)
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
async fn remote_commit(watch: &GitWatch, base: &std::path::Path) -> Result<String, String> {
    let ran = run::git(&plan::ls_remote_args(watch), base, run::LS_REMOTE_TIMEOUT)
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

/// The task that polls one service's branch.
struct Poller {
    supervisor: Supervisor,
    spec: ServiceSpec,
    watch: GitWatch,
}

impl Poller {
    /// Polls until the task is aborted or the service disappears.
    ///
    /// The first poll happens immediately rather than after one interval. A daemon
    /// that was down while the branch moved should deploy when it comes back, not
    /// a minute later — and on a watch checked hourly, "not yet" is a long time to
    /// look like nothing is working.
    async fn run(self) {
        let interval = Duration::from_secs(
            self.watch.interval_secs.max(selfhost_config::git::MIN_INTERVAL_SECS),
        );
        // A failure repeated every interval would fill the log with one fact. The
        // last one is remembered so only a *change* is worth a line — including
        // the change back to working.
        let mut last_complaint: Option<String> = None;

        loop {
            match check_once(&self.supervisor, &self.spec, &self.watch).await.map(|_| ()) {
                Ok(()) => {
                    if last_complaint.take().is_some() {
                        deploy::note(&self.supervisor, &self.spec.name, "the branch is reachable again")
                            .await;
                    }
                }
                Err(reason) => {
                    if last_complaint.as_deref() != Some(reason.as_str()) {
                        deploy::note(&self.supervisor, &self.spec.name, &reason).await;
                        last_complaint = Some(reason);
                    }
                }
            }

            // A service that has been uninstalled has nothing to deploy to, and
            // its task would otherwise poll a remote forever.
            if self.supervisor.status(&self.spec.name).await.is_none() {
                return;
            }
            tokio::time::sleep(interval).await;
        }
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_config::StartMode;

    fn watched_service(name: &str) -> ServiceSpec {
        let mut spec = ServiceSpec::new(name, "/bin/true");
        spec.start_mode = StartMode::Manual;
        // A branch that does not exist: the poller reports it and keeps polling,
        // which is what these tests want — a task that stays alive and touches
        // nothing on disk.
        let mut watch = GitWatch::new("https://example.invalid/repo.git", "checkouts/site");
        watch.interval_secs = 3_600;
        spec.git = Some(watch);
        spec
    }

    #[tokio::test]
    async fn only_services_with_an_active_watch_are_polled() {
        let supervisor = Supervisor::new(std::env::temp_dir());
        let watches = Watches::default();

        let plain = ServiceSpec::new("plain", "/bin/true");
        supervisor.install(plain.clone()).await;
        assert!(!watches.follow(&supervisor, &plain).await);

        let mut switched_off = watched_service("off");
        switched_off.git.as_mut().expect("a watch").enabled = false;
        supervisor.install(switched_off.clone()).await;
        assert!(!watches.follow(&supervisor, &switched_off).await);

        let watched = watched_service("site");
        supervisor.install(watched.clone()).await;
        assert!(watches.follow(&supervisor, &watched).await);
        assert_eq!(watches.count().await, 1);

        watches.shutdown().await;
        assert_eq!(watches.count().await, 0);
    }

    #[tokio::test]
    async fn installing_a_service_again_replaces_its_watch_rather_than_adding_one() {
        // Two pollers on one branch would both see it move and both deploy, and
        // the second would find the first's working copy half-updated.
        let supervisor = Supervisor::new(std::env::temp_dir());
        let watches = Watches::default();
        let spec = watched_service("site");
        supervisor.install(spec.clone()).await;

        watches.follow(&supervisor, &spec).await;
        watches.follow(&supervisor, &spec).await;
        assert_eq!(watches.count().await, 1);

        assert!(watches.forget("site").await);
        assert!(!watches.forget("site").await);
        assert_eq!(watches.count().await, 0);
    }

    #[tokio::test]
    async fn a_catalogue_is_loaded_and_says_how_many_are_watched() {
        let supervisor = Supervisor::new(std::env::temp_dir());
        let catalog = ServiceCatalog {
            version: 1,
            services: vec![
                watched_service("one"),
                ServiceSpec::new("two", "/bin/true"),
                watched_service("three"),
            ],
        };
        supervisor.load(&catalog).await;

        let watches = Watches::default();
        assert_eq!(watches.load(&supervisor, &catalog).await, 2);
        watches.shutdown().await;
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
