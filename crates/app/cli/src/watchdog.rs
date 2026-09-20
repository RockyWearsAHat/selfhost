//! `selfhost watchdog` — the recovery path index.dx rule 9 requires: a small
//! process that watches the daemon and the SSH relay, and that nothing it
//! watches can ever break by breaking.
//!
//! # Why this cannot be a feature of the daemon
//!
//! A watchdog living inside the process it watches is not a watchdog — it
//! goes down in exactly the failure it exists to catch. This module is run
//! from its own copy of the binary (`selfhost-watchdog`, installed by
//! [`crate::service_install::watchdog_plan`]), registered as its own
//! scheduled task/launchd job/systemd unit, never restarted by a self-update
//! (`crate::self_update` never touches [`crate::service_install::WATCHDOG_TASK_NAME`]),
//! and never asks the People registry or the daemon's own admin API anything
//! — the same independence [`crate::breakglass`] gives the SSH relay's key
//! pinning, applied here to "is the daemon alive at all".
//!
//! # What actually went down twice
//!
//! First: `selfhost-vpn-ssh`'s Windows Job Object ties its life to the
//! daemon's (`selfhost_supervisor::job::Job::kill_on_drop`), so the daemon
//! dying takes the relay with it, silently. Second — the reason this module
//! carries a build-from-source path at all — the daemon died *mid
//! self-update*: its exe was renamed aside for a rebuild
//! (`crate::self_update::build_and_swap`'s first step) and the process
//! carrying that rename out did not survive to finish it, leaving nothing
//! runnable at the daemon's own path and nothing alive to fetch, build, or
//! restart. A watchdog that only ever restarts a registered task cannot
//! recover from either box: an Ed25519 key with nothing to answer its
//! handshake, or a task pointed at a file that is not there. This module's
//! escalation ladder ([`Machine::step`]) is built to reach both.
//!
//! # The ladder
//!
//! Every tick, [`observe`] answers two questions with no daemon involvement at
//! all — a set of HTTP/HTTPS/control-API probes
//! ([`crate::health::probe_all`], already careful to distinguish "genuinely
//! down" from "not deployed here") and a loopback TCP connect to each enabled
//! relay's own port, never the box's public interface. [`Machine::step`] is
//! pure: given that observation and its own small amount of memory (a
//! consecutive-failure count and a stage), it decides one [`Action`] and
//! nothing else — no I/O, so the whole ladder is provable with fabricated
//! observations and no real daemon, exactly [`crate::self_update`]'s
//! `verify_after_restart_with` pattern. [`act`] is the only place that touches
//! the outside world: it restarts the registered task
//! ([`crate::service_install::restart_steps`]), restores
//! `selfhost.prev` (`crate::self_update::restore_previous_binary` — reused,
//! not copied), or — when the exe is missing outright or a restore did not
//! bring it back — fetches, fast-forwards, and rebuilds the deploy branch
//! itself with the same primitives `crate::self_update` already has
//! (`selfhost_git::run`/`plan`, `crate::self_update::{fast_forwards,
//! built_binary_path, install_atomically}`) and installs the result
//! atomically before restarting the task. When the exe is missing and a
//! `selfhost.prev` exists, that restore runs *first* — best effort, before the
//! rebuild even starts — so the box is serving the last known-good code again
//! while the rebuild is still running, rather than staying down for however
//! long a `cargo build --release` takes.
//!
//! # What this module does not do
//!
//! It binds no socket and opens no listener of any kind — every network use
//! here is an outbound connect (the loopback relay probe) or an HTTP client
//! request already made by [`crate::health::probe_all`]. It never reads the
//! People registry or any grant. It never touches
//! [`crate::service_install::TASK_NAME`]'s registration or
//! [`crate::service_install::WATCHDOG_TASK_NAME`]'s own — only *restarts* the
//! former by name, the same external `schtasks`/`launchctl`/`systemctl` verbs
//! `selfhost service` itself would use. It does not fix the two rule-9 gaps
//! `crate::breakglass`'s own module docs record (the SSH relay's
//! `--account-manager` capability check, and break-glass keys not yet being
//! wired into `runner::plan`'s `--peer` argv) — a watchdog that restarts a
//! healthy relay process is orthogonal to whether that process would accept a
//! break-glass peer once restarted.

use crate::service_install;
use selfhost_config::Config;
use selfhost_git::plan;
use selfhost_git::run::{self, BUILD_TIMEOUT, LS_REMOTE_TIMEOUT, TRANSFER_TIMEOUT};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const USAGE: &str = "\
Usage
  selfhost watchdog [--interval-secs N] [--failure-threshold K]

Runs in the foreground, forever, watching the daemon and its configured
Secure-VPN relays. Meant to be registered as its own scheduled task/launchd
job/systemd unit (`selfhost service install` does this alongside the daemon's
own registration) — running it by hand is for diagnosing the watchdog itself,
not for production use.

Every N seconds (default 30) it probes the daemon's health and each enabled
relay's loopback port. After K consecutive unhealthy observations (default 3)
it restarts the registered daemon task; if that does not help, it restores
selfhost.prev; if that does not help either — or the daemon's binary is
missing outright — it fetches, fast-forwards, and rebuilds the deploy branch
itself and installs the result. See the module documentation in watchdog.rs
for why this exists and what it deliberately does not touch.
";

/// How often [`run`] observes the world, absent `--interval-secs`.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// How many consecutive unhealthy observations [`run`] tolerates before
/// escalating, absent `--failure-threshold`.
pub const DEFAULT_THRESHOLD: u32 = 3;

/// How long a single loopback connect attempt may take before counting as
/// unreachable — short, because a relay that is actually up answers a local
/// connect in microseconds; this is a liveness probe, not a load test.
const RELAY_PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// One tick's worth of fact, gathered with no daemon involvement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    /// Whether the daemon and every enabled relay looked healthy this tick.
    pub healthy: bool,
    /// Whether the daemon's own binary exists at all at its installed path.
    pub exe_exists: bool,
    /// Whether a `selfhost.prev` — a still-installed previous build — exists
    /// beside it.
    pub prev_exists: bool,
}

/// What [`Machine::step`] decided to do about one [`Observation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Everything looked healthy, or not enough consecutive failures have
    /// been seen yet to act.
    None,
    /// Ask the service manager to restart the registered daemon task.
    RestartTask,
    /// A restart did not help: restore `selfhost.prev` over the daemon's exe,
    /// then restart the task.
    RestoreThenRestart,
    /// The exe is missing outright, or a restore did not help either: fetch,
    /// fast-forward, and rebuild the deploy branch, install the result, and
    /// restart the task. (If the exe is missing and a previous build exists,
    /// [`act`] restores it first, best-effort, before the rebuild begins.)
    RebuildThenRestart,
}

/// How far up [`Machine`]'s escalation ladder the last unhealthy run climbed.
///
/// A healthy observation resets this to `Watching` — the ladder does not
/// remember a past incident once things recover, so a box that was unhealthy
/// once yesterday is not one restart away from a rebuild today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Counting consecutive failures; nothing has been tried yet.
    Watching,
    /// A restart was just tried; the next unhealthy tick escalates further.
    Restarted,
    /// A restore was just tried; the next unhealthy tick escalates further.
    Restored,
    /// A rebuild was tried and the box is still unhealthy; keep retrying the
    /// rebuild rather than looping back to a restart that already failed.
    Rebuilding,
}

/// The pure decision core: given one [`Observation`] and its own small amount
/// of memory, decides exactly one [`Action`]. No I/O anywhere in this type —
/// see the module docs for why that is what makes the ladder provable.
pub struct Machine {
    threshold: u32,
    failures: u32,
    stage: Stage,
}

impl Machine {
    /// A fresh machine that has seen nothing yet. `threshold` of `0` is
    /// treated as `1` — "escalate on the very first failure" is a real policy
    /// an operator might ask for; "never escalate" is not one this type
    /// offers, since a watchdog that never acts is not a watchdog.
    pub fn new(threshold: u32) -> Self {
        Self { threshold: threshold.max(1), failures: 0, stage: Stage::Watching }
    }

    /// Feeds one observation in and returns what to do about it.
    pub fn step(&mut self, observation: Observation) -> Action {
        if observation.healthy {
            self.failures = 0;
            self.stage = Stage::Watching;
            return Action::None;
        }

        // A missing exe can never be fixed by asking the service manager to
        // restart a task that points at a file that is not there — that is
        // not a stage of the ordinary ladder, it is a fact that skips the
        // early rungs entirely.
        if !observation.exe_exists {
            self.stage = Stage::Rebuilding;
            self.failures = 0;
            return Action::RebuildThenRestart;
        }

        self.failures += 1;
        match self.stage {
            Stage::Watching => {
                if self.failures >= self.threshold {
                    self.failures = 0;
                    self.stage = Stage::Restarted;
                    Action::RestartTask
                } else {
                    Action::None
                }
            }
            Stage::Restarted => {
                self.stage = Stage::Restored;
                Action::RestoreThenRestart
            }
            Stage::Restored | Stage::Rebuilding => {
                self.stage = Stage::Rebuilding;
                Action::RebuildThenRestart
            }
        }
    }
}

/// Where this watchdog process's own binary lives, and therefore — via
/// [`service_install::daemon_exe_from_watchdog`] — where the daemon's does.
fn daemon_exe() -> Result<PathBuf, String> {
    let this = std::env::current_exe()
        .map_err(|error| format!("cannot locate this process's own binary: {error}"))?;
    Ok(service_install::daemon_exe_from_watchdog(&this))
}

/// Gathers one [`Observation`] with no daemon involvement: [`crate::health::probe_all`]
/// for the daemon itself, and a loopback connect for each enabled relay.
async fn observe(config: &Config, project_dir: &Path, daemon_exe: &Path) -> Observation {
    let daemon_ok = if daemon_exe.exists() {
        let probes = crate::health::probe_all(config, project_dir).await;
        !probes.iter().any(|probe| probe.serving.is_fault())
    } else {
        false
    };
    let relays_ok = relays_reachable(config).await;
    Observation {
        healthy: daemon_ok && relays_ok,
        exe_exists: daemon_exe.exists(),
        prev_exists: crate::self_update::prev_path(daemon_exe).exists(),
    }
}

/// Whether every *enabled* relay accepts a plain TCP connect on its own port,
/// reached over loopback — never the relay's own (possibly public) `listen`
/// host. A connect, never a bind: this is the one place this module touches
/// the network at all, and it only ever originates a client connection.
async fn relays_reachable(config: &Config) -> bool {
    for relay in config.vpn.iter().filter(|relay| relay.enabled) {
        let Some(configured) = relay.listen_addr() else { continue };
        let loopback = SocketAddr::from((Ipv4Addr::LOCALHOST, configured.port()));
        let reachable = tokio::time::timeout(RELAY_PROBE_TIMEOUT, tokio::net::TcpStream::connect(loopback))
            .await
            .map(|connected| connected.is_ok())
            .unwrap_or(false);
        if !reachable {
            return false;
        }
    }
    true
}

/// Carries out one [`Action`] — the only part of this module that touches the
/// outside world.
async fn act(action: Action, config: &Config, project_dir: &Path, daemon_exe: &Path) {
    match action {
        Action::None => {}
        Action::RestartTask => {
            println!(
                "watchdog: the daemon looks unhealthy; restarting {}",
                service_install::TASK_NAME
            );
            report(service_install::run_steps(&service_install::restart_steps(
                service_install::TASK_NAME,
            )));
        }
        Action::RestoreThenRestart => {
            println!(
                "watchdog: still unhealthy after a restart; restoring the previous binary over {}",
                daemon_exe.display()
            );
            if let Err(error) = crate::self_update::restore_previous_binary(daemon_exe) {
                eprintln!("watchdog: restore failed: {error}");
            }
            report(service_install::run_steps(&service_install::restart_steps(
                service_install::TASK_NAME,
            )));
        }
        Action::RebuildThenRestart => {
            if !daemon_exe.exists() {
                let prev = crate::self_update::prev_path(daemon_exe);
                if prev.exists() {
                    println!(
                        "watchdog: {} is missing; restoring {} first so something is serving \
                         while a rebuild runs",
                        daemon_exe.display(),
                        prev.display()
                    );
                    if let Err(error) = crate::self_update::restore_previous_binary(daemon_exe) {
                        eprintln!("watchdog: restore failed: {error}");
                    } else {
                        report(service_install::run_steps(&service_install::restart_steps(
                            service_install::TASK_NAME,
                        )));
                    }
                } else {
                    eprintln!(
                        "watchdog: {} is missing and there is no {} to restore first",
                        daemon_exe.display(),
                        crate::self_update::prev_path(daemon_exe).display()
                    );
                }
            }
            println!("watchdog: rebuilding {} from source", project_dir.display());
            match rebuild_from_source(config, project_dir, daemon_exe).await {
                Ok(()) => {
                    println!("watchdog: rebuild installed; restarting {}", service_install::TASK_NAME);
                    report(service_install::run_steps(&service_install::restart_steps(
                        service_install::TASK_NAME,
                    )));
                }
                Err(error) => eprintln!("watchdog: rebuild failed: {error}"),
            }
        }
    }
}

/// Logs a step-execution failure; a restart or a restore that fails leaves
/// the box exactly as unhealthy as it was, which the next tick will observe
/// and escalate from — this is a report, not a second decision.
fn report(result: Result<(), String>) {
    if let Err(error) = result {
        eprintln!("watchdog: {error}");
    }
}

/// Fetches, fast-forwards, builds, and installs the configured deploy branch
/// — composed from the same primitives `crate::self_update` uses for its own
/// build, reused rather than copied. Unlike `crate::self_update::build_and_swap`,
/// there is no running process's own exe to rename aside first: by the time
/// this runs, the daemon is already down (that is why the watchdog is here),
/// so the built binary is simply installed atomically over whatever is or is
/// not at `daemon_exe`.
async fn rebuild_from_source(
    config: &Config,
    project_dir: &Path,
    daemon_exe: &Path,
) -> Result<(), String> {
    let update = config
        .self_update
        .as_ref()
        .ok_or_else(|| "no [self_update] repository is configured; cannot rebuild the daemon \
                         from source"
            .to_string())?;
    let watch = update.as_watch();

    let remote = {
        let output =
            crate::self_update::git(&plan::ls_remote_args(&watch, None), project_dir, LS_REMOTE_TIMEOUT)
                .await?;
        plan::commit_for_ref(&output, &watch.remote_ref())
            .ok_or_else(|| format!("{} has no branch {}", update.repository, update.branch))?
    };
    let local = {
        let output =
            crate::self_update::git(&plan::head_args(project_dir), project_dir, LS_REMOTE_TIMEOUT).await?;
        plan::parse_head(&output).ok_or_else(|| {
            format!(
                "{} is not a git working copy; the watchdog cannot rebuild it from source",
                project_dir.display()
            )
        })?
    };

    if local != remote {
        let status =
            crate::self_update::git(&plan::status_args(project_dir), project_dir, LS_REMOTE_TIMEOUT)
                .await?;
        if !status.trim().is_empty() {
            return Err(format!(
                "{} has modified tracked files; refusing to discard them by resetting to {}",
                project_dir.display(),
                plan::short(&remote)
            ));
        }
        crate::self_update::git(&plan::fetch_args(&watch, project_dir, None), project_dir, TRANSFER_TIMEOUT)
            .await?;
        if !crate::self_update::fast_forwards(project_dir, &local).await? {
            return Err(format!(
                "{} has commits that are not on {}; refusing to discard them",
                project_dir.display(),
                update.branch
            ));
        }
        crate::self_update::git(&plan::reset_args(project_dir), project_dir, TRANSFER_TIMEOUT).await?;
    }

    let command = update.build_command();
    let ran = run::build_step(&command, project_dir, BUILD_TIMEOUT)
        .await
        .map_err(|error| error.to_string())?;
    if !ran.succeeded() {
        return Err(ran.complaint());
    }

    let built = crate::self_update::built_binary_path(project_dir);
    crate::self_update::install_atomically(&built, daemon_exe)
        .map_err(|error| format!("cannot install {} as {}: {error}", built.display(), daemon_exe.display()))
}

/// Runs forever: observe, decide, act, sleep. The real entry point
/// `selfhost watchdog` runs — see [`Machine::step`] for the part of this that
/// is actually tested, and this module's docs for why the loop itself is not
/// (it is a thin, untestable-by-design composition of already-tested pieces,
/// exactly the split `crate::self_update::verify_after_restart` makes around
/// `verify_after_restart_with`).
pub async fn run(config: Config, project_dir: PathBuf, interval: Duration, threshold: u32) -> String {
    let daemon_exe = match daemon_exe() {
        Ok(path) => path,
        Err(error) => return error,
    };
    println!(
        "watchdog: watching {} (daemon exe {}) every {}s, escalating after {} consecutive failures",
        project_dir.display(),
        daemon_exe.display(),
        interval.as_secs(),
        threshold
    );
    let mut machine = Machine::new(threshold);
    loop {
        let observation = observe(&config, &project_dir, &daemon_exe).await;
        let action = machine.step(observation);
        act(action, &config, &project_dir, &daemon_exe).await;
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> Observation {
        Observation { healthy: true, exe_exists: true, prev_exists: true }
    }

    fn unhealthy() -> Observation {
        Observation { healthy: false, exe_exists: true, prev_exists: true }
    }

    fn unhealthy_no_prev() -> Observation {
        Observation { healthy: false, exe_exists: true, prev_exists: false }
    }

    fn missing_exe(prev_exists: bool) -> Observation {
        Observation { healthy: false, exe_exists: false, prev_exists }
    }

    #[test]
    fn a_healthy_observation_never_acts() {
        let mut machine = Machine::new(3);
        for _ in 0..10 {
            assert_eq!(machine.step(healthy()), Action::None);
        }
    }

    #[test]
    fn nothing_happens_before_the_threshold_is_reached() {
        let mut machine = Machine::new(3);
        assert_eq!(machine.step(unhealthy()), Action::None);
        assert_eq!(machine.step(unhealthy()), Action::None);
    }

    #[test]
    fn the_task_is_restarted_exactly_at_the_threshold() {
        let mut machine = Machine::new(3);
        assert_eq!(machine.step(unhealthy()), Action::None);
        assert_eq!(machine.step(unhealthy()), Action::None);
        assert_eq!(machine.step(unhealthy()), Action::RestartTask);
    }

    #[test]
    fn a_threshold_of_zero_still_escalates_on_the_first_failure() {
        // "Never escalate" is not a policy this type offers.
        let mut machine = Machine::new(0);
        assert_eq!(machine.step(unhealthy()), Action::RestartTask);
    }

    #[test]
    fn a_restart_that_does_not_help_escalates_to_a_restore() {
        let mut machine = Machine::new(1);
        assert_eq!(machine.step(unhealthy()), Action::RestartTask);
        assert_eq!(machine.step(unhealthy()), Action::RestoreThenRestart);
    }

    #[test]
    fn a_restore_that_does_not_help_escalates_to_a_rebuild() {
        let mut machine = Machine::new(1);
        assert_eq!(machine.step(unhealthy()), Action::RestartTask);
        assert_eq!(machine.step(unhealthy()), Action::RestoreThenRestart);
        assert_eq!(machine.step(unhealthy()), Action::RebuildThenRestart);
    }

    #[test]
    fn a_rebuild_that_does_not_help_keeps_rebuilding_rather_than_looping_back() {
        let mut machine = Machine::new(1);
        assert_eq!(machine.step(unhealthy()), Action::RestartTask);
        assert_eq!(machine.step(unhealthy()), Action::RestoreThenRestart);
        assert_eq!(machine.step(unhealthy()), Action::RebuildThenRestart);
        assert_eq!(machine.step(unhealthy()), Action::RebuildThenRestart);
        assert_eq!(machine.step(unhealthy()), Action::RebuildThenRestart);
    }

    #[test]
    fn a_missing_exe_skips_straight_to_a_rebuild_even_on_the_very_first_tick() {
        // Restarting a task that points at a file which is not there cannot
        // ever help — this is the exact box a daemon dying mid self-update
        // leaves behind.
        let mut machine = Machine::new(3);
        assert_eq!(machine.step(missing_exe(true)), Action::RebuildThenRestart);
        assert_eq!(machine.step(missing_exe(true)), Action::RebuildThenRestart);
    }

    #[test]
    fn a_missing_exe_with_no_previous_binary_still_asks_for_a_rebuild() {
        // `act` is the one that knows there is nothing to restore first; the
        // decision layer always asks for a rebuild when the exe is gone.
        let mut machine = Machine::new(3);
        assert_eq!(machine.step(missing_exe(false)), Action::RebuildThenRestart);
    }

    #[test]
    fn recovering_resets_the_ladder_entirely() {
        let mut machine = Machine::new(1);
        assert_eq!(machine.step(unhealthy()), Action::RestartTask);
        assert_eq!(machine.step(healthy()), Action::None);
        // Back at the bottom rung, not mid-ladder.
        assert_eq!(machine.step(unhealthy()), Action::RestartTask);
    }

    #[test]
    fn a_missing_prev_does_not_change_the_stage_the_ladder_climbs_through() {
        // `prev_exists` only ever changes what `act` does with a
        // `RebuildThenRestart`, never which `Action` `Machine::step` picks.
        let mut machine = Machine::new(1);
        assert_eq!(machine.step(unhealthy_no_prev()), Action::RestartTask);
        assert_eq!(machine.step(unhealthy_no_prev()), Action::RestoreThenRestart);
        assert_eq!(machine.step(unhealthy_no_prev()), Action::RebuildThenRestart);
    }

    #[test]
    fn the_daemon_and_watchdog_exe_helper_agree_with_service_install() {
        let watchdog_exe = Path::new("/opt/selfhost/selfhost-watchdog");
        assert_eq!(
            service_install::daemon_exe_from_watchdog(watchdog_exe),
            PathBuf::from("/opt/selfhost/selfhost")
        );
    }
}
