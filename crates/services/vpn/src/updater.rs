//! The meta-service that owns Secure-VPN's build-then-swap auto-update.
//!
//! # The hazard this sidesteps
//!
//! [`selfhost_git::deploy::update`] always runs stop → fetch → build
//! (`post_pull`) → start, in that order, against whatever [`ServiceSpec`] owns
//! the [`GitWatch`] it is driving. That is correct for an ordinary web
//! backend — a service under a running process that a build might corrupt —
//! but it is the wrong shape for `vpn-console`/`vpn-ssh`: they are this
//! deployment's only remote-access path (`docs/VPN.md`), and a `GitWatch`
//! attached to either of them directly would take the tunnel down *before*
//! the build/KAT-test gate ran. A build failure would then leave the relay
//! stopped with nobody able to reach the box to fix it.
//!
//! So the watch is attached to a **third, separate** service instead —
//! [`SERVICE_NAME`], `vpn-updater` — whose only job is to own the `GitWatch`.
//! `deploy.rs`'s stop-first step therefore stops *this* service, which is
//! never live for more than the few seconds its own run takes (see below), so
//! the stop is almost always a no-op. `vpn-console` and `vpn-ssh` are never
//! touched until the very last step, and only on success.
//!
//! # The pipeline
//!
//! 1. A push to `https://github.com/RockyWearsAHat/Secure-VPN.git` arrives —
//!    the GitHub App webhook, exactly like any other watched service; there is
//!    no poll underneath it (`selfhost_config::git`'s module docs explain why
//!    a timer was removed). This is the **one and only** automatic trigger for
//!    Secure-VPN's server-side code; see `docs/VPN.md` for the explicit
//!    statement of that.
//! 2. `deploy.rs` stops `vpn-updater` (almost always already stopped), fetches
//!    into [`Updater::staging_path`] — a checkout that is **not** the live
//!    install — and runs `post_pull`: [`Updater::watch`]'s command, which is
//!    `scripts/securevpn/update-and-verify.ps1` run *inside* the staging
//!    checkout. That script builds and runs the `mlkem768` KAT test suite,
//!    builds the wheel, and installs it into a **staging** venv that the live
//!    relay never reads. A non-zero exit here aborts the deployment; the
//!    staging tree is left for a human to inspect, and — critically —
//!    `vpn-console`/`vpn-ssh` were never touched.
//! 3. Only if step 2 exits `0` does `deploy.rs` call `supervisor.start(name)`
//!    on `vpn-updater`. Its "program" is
//!    `scripts/securevpn/update-and-swap.ps1` — the atomic swap: move the
//!    now-verified staging install over the live one, then restart
//!    `vpn-console` and `vpn-ssh` through this box's own `selfhost vpn`
//!    verbs. `vpn-updater` then exits `0` and stays `Exited` until the next
//!    push — [`RestartPolicy::Never`], because there is nothing to keep
//!    running between deployments.
//!
//! End state: `vpn-console`/`vpn-ssh` are stopped for exactly the length of
//! one restart, once, and only after a build- and KAT-test-verified version is
//! already staged and ready to swap in. Every failure before that point —
//! fetch, build, test — leaves both of them completely untouched and running.

use std::path::PathBuf;

use selfhost_config::{GitWatch, RestartPolicy, ServiceSpec, StartMode};

/// The supervised name of the update-and-swap meta-service.
///
/// Under the same `vpn-` prefix `runner::SERVICE_PREFIX` uses for a relay, for
/// the identical reason: kept out of the `selfhost-` namespace the Windows
/// firewall reconciler adopts and deletes rules from. This is a *service*
/// name, not a firewall rule, but keeping every Secure-VPN-related supervised
/// name under one prefix is what makes `selfhost service list` group them for
/// a reader.
pub const SERVICE_NAME: &str = "vpn-updater";

/// The upstream Secure-VPN repository. The same one `docs/VPN.md` and
/// `crates/services/vpn/src/runner.rs` already name.
pub const REPOSITORY: &str = "https://github.com/RockyWearsAHat/Secure-VPN.git";

/// The branch a deployment follows when it does not say otherwise.
pub const DEFAULT_BRANCH: &str = "main";

/// Where this repository's own tree lives on the production box, so the
/// verify/swap scripts can be named by an absolute path even though they run
/// with their `cwd` set to the *staging* checkout — a different repository
/// entirely. Mirrors the reasoning `runner::VENDORED_WINDOWS` already gives
/// for a similarly-hardcoded, recorded-rather-than-searched-for path: this is
/// the box's actual layout (`scripts/windows/install-service.ps1` registers
/// the scheduled task from this exact directory), not a guess.
pub const SELF_HOST_TREE_WINDOWS: &str = r"C:\Users\Alex\Self-Host";

/// One update pipeline: where the staged checkout lives, and the two scripts
/// that gate and then carry out the swap.
///
/// Kept as a plain struct with public fields, like `app-deploy`'s `AppSpec`,
/// so a deployment with a non-default layout can override any of them without
/// this crate growing a builder nobody needed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Updater {
    /// Where the staging checkout lives, relative to the daemon's base
    /// directory — the same resolution rule [`GitWatch::path`] documents.
    ///
    /// Never the live install directory. That is the entire point: this tree
    /// can be stopped, fetched into, built and tested without the running
    /// relay ever noticing, because nothing here is what it reads from.
    pub staging_path: PathBuf,

    /// The verify script, run with its `cwd` set to the staging checkout
    /// after every successful fetch. Absolute, because the staging checkout
    /// is a clone of a *different* repository (Secure-VPN, not this one) and
    /// cannot be relied on to carry a copy of it.
    pub verify_script: PathBuf,

    /// The swap script `vpn-updater`'s own `start` runs — reached only after
    /// [`Updater::verify_script`] has already exited `0` for the commit now
    /// sitting in the staging checkout.
    pub swap_script: PathBuf,

    /// The branch watched.
    pub branch: String,
}

impl Updater {
    /// An updater for the default Secure-VPN repository, pointed at the given
    /// staging directory and scripts.
    pub fn new(
        staging_path: impl Into<PathBuf>,
        verify_script: impl Into<PathBuf>,
        swap_script: impl Into<PathBuf>,
    ) -> Self {
        Self {
            staging_path: staging_path.into(),
            verify_script: verify_script.into(),
            swap_script: swap_script.into(),
            branch: DEFAULT_BRANCH.to_owned(),
        }
    }

    /// The updater with this box's recorded script locations
    /// ([`SELF_HOST_TREE_WINDOWS`]) and the default staging path,
    /// `vpn-updater/staging` under the daemon's base directory.
    pub fn vendored() -> Self {
        let tree = PathBuf::from(SELF_HOST_TREE_WINDOWS);
        Self::new(
            PathBuf::from("vpn-updater").join("staging"),
            tree.join("scripts").join("securevpn").join("update-and-verify.ps1"),
            tree.join("scripts").join("securevpn").join("update-and-swap.ps1"),
        )
    }

    /// The Git watch: fetches the staging checkout, then gates on
    /// [`Updater::verify_script`] — build the KAT suite, build the wheel,
    /// install it into a staging venv. Never touches the live install.
    ///
    /// No `webhook_secret` is set here — that is a per-deployment credential a
    /// box configures once it has wired up the GitHub App, exactly as any
    /// other watched service does (`services_repo_configure`). Whichever of
    /// the webhook or the manual `POST /api/services/vpn-updater/deploy` door
    /// a deployment ends up using, it is still the **one** trigger this watch
    /// answers to: there is no background poll underneath either of them
    /// (`selfhost_config::git`'s module docs), and this crate adds no second
    /// one of its own.
    pub fn watch(&self) -> GitWatch {
        let mut watch = GitWatch::new(REPOSITORY, self.staging_path.clone());
        watch.branch = self.branch.clone();
        watch.post_pull = Some(vec![
            "powershell".to_owned(),
            "-NoProfile".to_owned(),
            "-ExecutionPolicy".to_owned(),
            "Bypass".to_owned(),
            "-File".to_owned(),
            self.verify_script.display().to_string(),
        ]);
        watch
    }

    /// The meta-service itself.
    ///
    /// `start_mode = Manual` for the same reason every relay is: installing
    /// the definition and arming it are two decisions. `restart = Never`
    /// because this is a one-shot swap, not something meant to keep running —
    /// the supervisor's `ServiceState::Exited` is exactly what a successful
    /// swap settles into between pushes, with `total_restarts` staying `0`.
    pub fn service(&self) -> ServiceSpec {
        let mut spec = ServiceSpec::new(SERVICE_NAME, "powershell");
        spec.display_name = Some("Secure-VPN staged update + swap".to_owned());
        spec.description = "Owns the Secure-VPN GitWatch. Never the relay itself: a push \
             fetches into a staging checkout and gates on a build + KAT-test verify script \
             before this service's own start runs the atomic swap and restarts vpn-console \
             and vpn-ssh. See crates/services/vpn/src/updater.rs."
            .to_owned();
        spec.args = vec![
            "-NoProfile".to_owned(),
            "-ExecutionPolicy".to_owned(),
            "Bypass".to_owned(),
            "-File".to_owned(),
            self.swap_script.display().to_string(),
        ];
        spec.start_mode = StartMode::Manual;
        spec.restart = RestartPolicy::Never;
        spec.git = Some(self.watch());
        spec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_supervisor::state::ServiceState;
    use selfhost_supervisor::{Supervisor, await_state};
    use std::time::Duration;

    fn updater() -> Updater {
        Updater::new(
            PathBuf::from("vpn-updater").join("staging"),
            PathBuf::from(r"C:\fake\scripts\securevpn\update-and-verify.ps1"),
            PathBuf::from(r"C:\fake\scripts\securevpn\update-and-swap.ps1"),
        )
    }

    #[test]
    fn the_watch_points_at_the_staging_checkout_never_the_live_install() {
        let watch = updater().watch();
        assert_eq!(watch.repository, REPOSITORY);
        assert_eq!(watch.path, PathBuf::from("vpn-updater").join("staging"));
        assert_eq!(watch.branch, "main");
    }

    #[test]
    fn post_pull_runs_the_verify_script_by_its_absolute_path() {
        let watch = updater().watch();
        let post_pull = watch.post_pull.expect("a verify gate");
        assert!(post_pull.iter().any(|arg| arg.ends_with("update-and-verify.ps1")), "{post_pull:?}");
    }

    #[test]
    fn the_service_starts_manually_and_never_restarts_itself() {
        let spec = updater().service();
        assert_eq!(spec.name, SERVICE_NAME);
        assert_eq!(spec.start_mode, StartMode::Manual);
        assert_eq!(spec.restart, RestartPolicy::Never);
        assert!(spec.git.is_some(), "the watch is what makes this the update owner");
    }

    #[test]
    fn the_services_own_start_runs_the_swap_script_by_its_absolute_path() {
        let spec = updater().service();
        assert!(
            spec.args.iter().any(|arg| arg.ends_with("update-and-swap.ps1")),
            "{:?}",
            spec.args
        );
    }

    #[test]
    fn the_service_definition_passes_the_config_crates_own_checks() {
        let mut problems = Vec::new();
        updater().service().check("vpn-updater", &[], &mut problems);
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn the_vendored_updater_names_the_recorded_box_layout() {
        let updater = Updater::vendored();
        assert!(updater.verify_script.starts_with(SELF_HOST_TREE_WINDOWS));
        assert!(updater.swap_script.starts_with(SELF_HOST_TREE_WINDOWS));
        assert_eq!(updater.staging_path, PathBuf::from("vpn-updater").join("staging"));
    }

    // The core safety property this module exists for: `deploy.rs`'s stop
    // step only fires when the service that owns the `GitWatch` is currently
    // live, and a one-shot `RestartPolicy::Never` service is not live between
    // runs — so a deployment finds nothing to stop, and never reaches for
    // `vpn-console`/`vpn-ssh` at all.
    #[tokio::test]
    async fn a_one_shot_updater_settles_as_exited_and_is_not_live_between_runs() {
        let base = std::env::temp_dir()
            .join(format!("selfhost-vpn-updater-test-{}", std::process::id()));
        std::fs::create_dir_all(&base).expect("a base directory for the supervisor to run in");
        let supervisor = Supervisor::new(&base);

        let mut spec = selfhost_supervisor::scripted_service(SERVICE_NAME, "exit 0");
        spec.start_mode = StartMode::Manual;
        spec.restart = RestartPolicy::Never;

        supervisor.install(spec).await;
        supervisor.start(SERVICE_NAME).await;

        let state = await_state(&supervisor, SERVICE_NAME, Duration::from_secs(15), |s| {
            matches!(s, ServiceState::Exited { .. })
        })
        .await
        .expect("the one-shot settles as Exited");
        assert_eq!(state, ServiceState::Exited { code: Some(0) });
        assert!(!state.is_live(), "not live between runs, so deploy.rs finds nothing to stop");

        supervisor.shutdown().await;
        let _ = std::fs::remove_dir_all(&base);
    }
}
