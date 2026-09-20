//! Updating selfhost itself when its own repository moves.
//!
//! The `[self_update]` section of the config names the repository this
//! deployment is a clone of. When a push to that branch is reported, the
//! daemon fetches, hard-resets the project directory, runs the build, swaps
//! the binary in, and exits so the service manager restarts the new build.
//!
//! # What makes it notice
//!
//! Exactly one trigger: a [`Nudge`] — a signal carrying nothing at all, so the
//! request body can never influence *what* gets deployed — poked by the
//! GitHub App webhook (`/.selfhost/webhook/app`) or the legacy
//! `self_update.webhook_secret` webhook (`/.selfhost/webhook/self`) on a
//! verified push, or by an operator's own `POST /api/self-update/deploy`.
//! There is no timer underneath it: see `selfhost_config::git`'s module docs
//! for why a poll safety net was removed rather than kept. Every nudge runs
//! the identical check: read the real branch tip with `git ls-remote`,
//! compare it to `HEAD`, act only on a genuine difference. A deployment with
//! no webhook configured and nobody pressing the manual button simply never
//! updates automatically — the manual door is the fallback, not a poll.
//!
//! # Who restarts whom
//!
//! Nothing here re-executes itself, and nothing here calls into
//! `crate::service_install` to ask for a restart either — the one mechanism
//! that restarts this process belongs entirely to whatever `crate::
//! service_install` registered under its `TASK_NAME`/label/unit name, and
//! this module's only interaction with it is exiting a process that
//! registration is watching. Every installed deployment already runs under a
//! supervisor that restarts a dead process: launchd's `KeepAlive` (restarts
//! any exit), systemd's `Restart=on-failure`, or — on Windows — the keep-alive
//! `.cmd` wrapper `service_install::keep_alive_script` generates, which
//! restarts on *any* exit after a pause. That indirection exists because
//! Windows Task Scheduler's own `RestartOnFailure` only restarts a task that
//! failed to *launch*, never one that ran and exited on purpose — see
//! `service_install.rs`'s own module docs — so a box registered the old way,
//! pointed straight at the daemon, would never come back from this module's
//! own deliberate exit. The exit code is [`RESTART_EXIT`], nonzero on purpose:
//! launchd restarts any exit, systemd restarts a failure, and the wrapper does
//! not look at the code at all.
//!
//! There is exactly one process to restart. When the proxy ran separately it
//! could not build (two builders racing over one tree would corrupt it), so it
//! watched the binary on disk and exited once the daemon had replaced it —
//! which meant a window where the two halves of the deployment were running
//! different code. One process removes the window and the mechanism together:
//! the process that builds the update is the process that exits, and
//! everything it was running comes back on the new build with it.
//!
//! # Why the running binary is renamed aside before the build
//!
//! Windows will not let `cargo` replace the executable of a live process, but
//! it will let that file be *renamed*. So the running image moves to
//! [`prev_path`]'s single canonical name — `selfhost.prev` beside the exe,
//! never a name that varies per attempt — the build writes a fresh binary at
//! the original path, and the old `selfhost.prev`, if any, is dropped first so
//! the rename never fails merely because one was already sitting there. That
//! canonical name is deliberate, not incidental: [`verify_after_restart`]
//! restores from exactly this path if the new build does not prove itself, so
//! there must always be exactly one place a rollback reads from, never a
//! leftover pile from every attempt that ever ran. On macOS and Linux the
//! rename is unnecessary but harmless, and one sequence everywhere beats two
//! that are each "usually" exercised.
//!
//! # What refuses an update
//!
//! A dirty working copy — modified *tracked* files, as untracked ones belong to
//! the deployment — skips the deployment and says so. The hard reset would
//! destroy those edits, and edits in a deployment's tree mean a person is doing
//! something deliberate; a deployment must not race them. A failed build rolls
//! the tree back to the running commit and restores the binary, so the next
//! poll retries the whole update instead of reporting up to date — a failed
//! build never stops the binary that is already running; see the doc comment
//! on [`build_and_swap`].
//!
//! # Proving the restart worked
//!
//! A build that compiles is not a deployment that serves — the 2026-09-19
//! outage was a swap with no restart path and nothing checking what came back.
//! So a successful swap does not mark its Deploy [`DeployResult::Succeeded`];
//! it writes a pending-verification marker ([`write_pending`]) recording the
//! Deploy id and the two commits either side of the swap, then exits with
//! [`RESTART_EXIT`] exactly as before. The *next* process to boot —
//! necessarily the new build, on whatever registration actually restarts a
//! [`RESTART_EXIT`] exit (the Windows Scheduled Task `service_install`
//! registers under its `TASK_NAME`, launchd's `KeepAlive`, or systemd's
//! `Restart=on-failure`; this module restarts nothing itself, matching "who
//! restarts whom" above) — calls [`verify_after_restart`] once its listeners
//! are already bound. That reads and removes the marker (so an ordinary boot
//! with nothing pending costs one failed file read) and probes with the exact
//! function `selfhost health` uses, [`crate::health::probe_all`] — never a
//! second, cheaper implementation that could disagree with it.
//!
//! Healthy inside the deadline: the Deploy is finished [`DeployResult::Succeeded`]
//! now, for the first time. Still unhealthy at the deadline: [`prev_path`]'s
//! binary and the previous commit are restored, the Deploy is finished
//! [`DeployResult::Failed`] with what was actually observed, and the caller
//! exits with [`RESTART_EXIT`] again so the very same restart mechanism brings
//! the *restored* build back — the box never sits on a build proven broken.

use selfhost_admin::deploys::{DeployId, DeployResult, Deploys, Trigger};
use selfhost_config::{Config, SelfUpdate};
use selfhost_git::Nudge;
use selfhost_git::plan;
use selfhost_git::run::{self, BUILD_TIMEOUT, LS_REMOTE_TIMEOUT, TRANSFER_TIMEOUT};
use selfhost_json::Json;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// The name of the pending-verification marker inside the data directory —
/// see this module's "Proving the restart worked" documentation.
const PENDING_VERIFICATION_FILENAME: &str = "self-update.pending";

/// How long a probe may go unhealthy before it is retried, while
/// [`verify_after_restart`] waits for a freshly restarted deployment to prove
/// itself. Short relative to [`VERIFY_DEADLINE`] so a build that is genuinely
/// fine is confirmed within a couple of rounds, not held to the whole budget.
const VERIFY_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How long a fresh restart has to prove itself healthy before
/// [`verify_after_restart`] rolls it back. Generous next to a single probe's
/// own three-second budget (`health.rs`'s `PROBE_DEADLINE`) — a listener can
/// take a moment to accept its first connection after a restart — but still
/// short enough that a genuinely broken build does not leave the box down for
/// minutes waiting to be told so.
const VERIFY_DEADLINE: Duration = Duration::from_secs(30);

/// This watcher's Deploy target name, for the same reason
/// `selfhost_config::git::SELF_UPDATE_WEBHOOK_NAME` names it on the webhook
/// side: the daemon's own repository is not in the service catalogue, so it
/// needs a name of its own rather than borrowing a service's.
const SELF_UPDATE_TARGET: &str = "self-update";

/// The exit code of a restart-on-purpose.
///
/// Nonzero so every service manager restarts it (see the module docs), and
/// distinctive so a person reading an exit status can tell "installed an
/// update" from a crash. 75 is BSD's `EX_TEMPFAIL`: try again.
pub const RESTART_EXIT: i32 = 75;

/// What one poll of the daemon's own repository concluded.
enum Progress {
    /// The deployment is on the branch's commit; nothing to do.
    UpToDate,
    /// The branch moved, and the update is built and in place.
    Updated {
        /// The commit that was running before this swap — what a rollback
        /// after an unhealthy restart restores.
        from: String,
        /// The commit now deployed.
        to: String,
    },
}

/// Watches the daemon's own repository and installs what a push delivers.
///
/// Pends forever when the section is absent or disabled, so it can occupy a
/// `select!` arm unconditionally. Otherwise it checks only when `nudge` is
/// poked, and returns only after an update has been fetched, built, and
/// swapped in. Errors and skips are reported to stderr and retried, never
/// fatal. The returned commit is what runs the moment the caller exits with
/// [`RESTART_EXIT`] and the service manager restarts the process.
///
/// Every check runs [`poll_once`], which reads the branch tip itself rather
/// than trusting anything the nudge carried — nothing about a check depends
/// on *why* it started, so a forged nudge can never deploy anything other
/// than what is really at the tip of the watched branch.
///
/// `deploys`, when wired, gets one [`Deploys::start`] per pass round this
/// loop, tagged [`Trigger::SelfUpdate`] — the Deploy record for a self-update
/// lives here rather than in the HTTP handler that nudges this watcher
/// (`Api::self_update_now`), because that handler only ever asks for a check;
/// the check, and therefore the only place an outcome exists to record,
/// happens in this loop, at a time the handler has already returned `202` and
/// moved on. A no-op or a failed check calls [`Deploys::finish`] here and now,
/// its write awaited before this function moves on. A *successful* swap does
/// not: it is still running unverified code, so [`Deploys::finish`] for it is
/// deferred to [`verify_after_restart`], in the process that boots next — see
/// this module's "Proving the restart worked" documentation.
pub async fn watch_own_repository(
    update: Option<SelfUpdate>,
    project_dir: PathBuf,
    data_dir: PathBuf,
    nudge: Nudge,
    deploys: Option<Arc<Deploys>>,
) -> String {
    let Some(update) = update.filter(|u| u.enabled) else { return std::future::pending().await };

    // A repeated failure (an unreachable remote, a dirty tree left dirty) would
    // otherwise say the same thing every interval, forever.
    let mut already_said = String::new();
    loop {
        // A nudge that lands *during* a check is remembered by `Nudge`, so the
        // push that arrives mid-build is not lost — it is served by the very
        // next pass round this loop.
        nudge.poked().await;
        println!("self-update: a push was announced; checking now");
        let deploy_id = deploys.as_ref().map(|store| store.start(SELF_UPDATE_TARGET, Trigger::SelfUpdate));
        match poll_once(&update, &project_dir).await {
            Ok(Progress::UpToDate) => {
                already_said.clear();
                if let (Some(store), Some(id)) = (&deploys, &deploy_id) {
                    store.finish(id, DeployResult::Succeeded, None, "nothing to do; already at the tip");
                }
            }
            Ok(Progress::Updated { from, to }) => {
                let pending = PendingVerification {
                    deploy_id: deploy_id.as_ref().map(|id| id.as_str().to_owned()),
                    previous_commit: from,
                    new_commit: to.clone(),
                };
                if let Err(error) = write_pending(&data_dir, &pending) {
                    // Not fatal to the swap itself — the binary is already in
                    // place — but the boot that follows will have no marker to
                    // read, so it skips verification entirely rather than
                    // failing partway through it. Said loudly because it means
                    // this restart's outcome will never be recorded at all.
                    eprintln!(
                        "self-update: built and swapped to {to}, but could not record a pending \
                         verification ({error}); the next boot will not health-check this \
                         restart and this Deploy will show as stalled rather than succeeded"
                    );
                }
                return to;
            }
            Err(reason) => {
                if let (Some(store), Some(id)) = (&deploys, &deploy_id) {
                    store.finish(id, DeployResult::Failed, None, reason.clone());
                }
                if reason != already_said {
                    eprintln!("self-update: {reason}");
                    already_said = reason;
                }
            }
        }
    }
}

/// One poll: read the branch tip, compare, and deploy if it moved.
async fn poll_once(update: &SelfUpdate, project_dir: &Path) -> Result<Progress, String> {
    let watch = update.as_watch();

    let remote = {
        let ran = git(&plan::ls_remote_args(&watch, None), project_dir, LS_REMOTE_TIMEOUT).await?;
        plan::commit_for_ref(&ran, &watch.remote_ref())
            .ok_or_else(|| format!("{} has no branch {}", update.repository, update.branch))?
    };
    let local = {
        let ran = git(&plan::head_args(project_dir), project_dir, LS_REMOTE_TIMEOUT).await?;
        plan::parse_head(&ran).ok_or_else(|| {
            format!(
                "{} is not a git working copy; self-update needs the deployment to be a \
                 clone of {}",
                project_dir.display(),
                update.repository
            )
        })?
    };
    if local == remote {
        return Ok(Progress::UpToDate);
    }

    let status = git(&plan::status_args(project_dir), project_dir, LS_REMOTE_TIMEOUT).await?;
    if !status.trim().is_empty() {
        return Err(format!(
            "{} → {} is ready, but tracked files in {} are modified — deploying would \
             destroy those edits; commit or discard them",
            plan::short(&local),
            plan::short(&remote),
            project_dir.display()
        ));
    }

    println!(
        "self-update: {} → {}: fetching and building",
        plan::short(&local),
        plan::short(&remote)
    );
    git(&plan::fetch_args(&watch, project_dir, None), project_dir, TRANSFER_TIMEOUT).await?;

    // Only ever fast-forward. A local HEAD that is not an ancestor of the
    // fetched tip holds commits the branch does not — a developer working in
    // the deployment's own tree — and the hard reset below would discard them.
    if !fast_forwards(project_dir, &local).await? {
        return Err(format!(
            "{} has commits that are not on {}; refusing to discard them — push or \
             remove them",
            project_dir.display(),
            update.branch
        ));
    }
    git(&plan::reset_args(project_dir), project_dir, TRANSFER_TIMEOUT).await?;

    build_and_swap(update, project_dir, &local).await?;
    Ok(Progress::Updated { from: local, to: remote })
}

/// Builds the new binary with the running one renamed aside, and puts the
/// result where the service manager expects to find it.
///
/// On failure the binary is renamed back and the tree is rolled back to
/// `previous`, so the deployment keeps running — and keeps being retried —
/// exactly as it was. This is what makes a failed build harmless: nothing
/// here stops or replaces the running process until a build has *already*
/// succeeded, so a build that never finishes, or fails outright, leaves the
/// live daemon exactly as it was found.
async fn build_and_swap(
    update: &SelfUpdate,
    project_dir: &Path,
    previous: &str,
) -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|error| format!("cannot locate this process's own binary: {error}"))?;
    let prev = prev_path(&exe);
    // Best-effort: a `selfhost.prev` from a past update, or a `.rollback-old`
    // left behind by a rollback whose discard could not be deleted while that
    // process was still running it, cannot block this rename just by sitting
    // there.
    let _ = std::fs::remove_file(&prev);
    let _ = std::fs::remove_file(rollback_discard_path(&exe));
    if let Err(error) = std::fs::rename(&exe, &prev) {
        // The tree is already on the new commit; leaving it there would make
        // the next poll read "up to date" while the old binary keeps running.
        let reason =
            format!("cannot move {} aside for the new build: {error}", exe.display());
        return Err(roll_back(project_dir, previous, &exe, &prev, reason).await);
    }

    let command = update.build_command();
    let failure = match run::build_step(&command, project_dir, BUILD_TIMEOUT).await {
        Ok(ran) if ran.succeeded() => None,
        Ok(ran) => Some(ran.complaint()),
        Err(error) => Some(error.to_string()),
    };
    if let Some(reason) = failure {
        return Err(roll_back(project_dir, previous, &exe, &prev, format!("build failed: {reason}")).await);
    }

    // The usual deployment runs from `target/release`, where the build already
    // put the fresh binary at `exe`'s own path. An install that runs the binary
    // from somewhere else gets the built one copied over — permissions ride
    // along with the copy.
    if !exe.exists() {
        let built = built_binary_path(project_dir);
        if let Err(error) = std::fs::copy(&built, &exe) {
            let reason = format!("cannot install {} as {}: {error}", built.display(), exe.display());
            return Err(roll_back(project_dir, previous, &exe, &prev, reason).await);
        }
    }
    Ok(())
}

/// Undoes a failed update — binary back in place, tree back on `previous` —
/// and returns the reason, annotated with any undo that itself failed.
async fn roll_back(
    project_dir: &Path,
    previous: &str,
    exe: &Path,
    prev: &Path,
    reason: String,
) -> String {
    let mut report = format!("{reason}; still running {}", plan::short(previous));
    if !exe.exists()
        && let Err(error) = std::fs::rename(prev, exe)
    {
        report.push_str(&format!(
            " — and the running binary could not be renamed back from {}: {error}",
            prev.display()
        ));
    }
    if let Err(error) =
        git(&plan::reset_to_args(project_dir, previous), project_dir, TRANSFER_TIMEOUT).await
    {
        report.push_str(&format!(" — and the tree could not be rolled back: {error}"));
    }
    report
}

/// Whether moving the working copy from `local` to what was fetched only adds
/// commits — `git merge-base --is-ancestor`'s three-way answer, made explicit.
async fn fast_forwards(project_dir: &Path, local: &str) -> Result<bool, String> {
    match run::git(&plan::is_ancestor_args(project_dir, local), project_dir, LS_REMOTE_TIMEOUT)
        .await
    {
        Ok(ran) if ran.succeeded() => Ok(true),
        Ok(ran) if ran.code == Some(1) => Ok(false),
        Ok(ran) => Err(ran.complaint()),
        Err(error) => Err(error.to_string()),
    }
}

/// The single canonical place the previously-running binary is kept — the one
/// place a rollback ([`restore_previous_binary`]) ever restores from. See this
/// module's "Why the running binary is renamed aside before the build"
/// documentation for why this is one fixed name rather than one per attempt.
fn prev_path(exe: &Path) -> PathBuf {
    exe.with_file_name(format!("selfhost.prev{}", std::env::consts::EXE_SUFFIX))
}

/// Where an unhealthy new build is moved once [`restore_previous_binary`] has
/// put [`prev_path`]'s binary back in its place.
///
/// Not deleted on the spot: this process is that unhealthy build, still
/// running from this very file at the moment it renames itself here, and
/// Windows will not delete a file its own running image still holds open — the
/// same lock [`prev_path`]'s own doc comment describes. [`build_and_swap`]
/// makes a best-effort attempt to delete whatever is here at the start of the
/// *next* update, once this process is long gone and the lock with it.
fn rollback_discard_path(exe: &Path) -> PathBuf {
    exe.with_file_name(format!("selfhost.rollback-old{}", std::env::consts::EXE_SUFFIX))
}

/// Restores [`prev_path`]'s binary over the running one, for
/// [`verify_after_restart`]'s rollback path.
///
/// The same rename trick [`build_and_swap`] uses for the forward swap, run in
/// reverse: the unhealthy build cannot be deleted or overwritten while this
/// process is running it, but it can be renamed out of the way
/// ([`rollback_discard_path`]), which frees the original path for
/// [`prev_path`]'s binary to take.
fn restore_previous_binary(exe: &Path) -> Result<(), String> {
    let prev = prev_path(exe);
    if !prev.exists() {
        return Err(format!("no previous binary at {} to restore", prev.display()));
    }
    let discard = rollback_discard_path(exe);
    let _ = std::fs::remove_file(&discard);
    std::fs::rename(exe, &discard).map_err(|error| {
        format!("cannot move the unhealthy build aside ({}): {error}", exe.display())
    })?;
    std::fs::rename(&prev, exe)
        .map_err(|error| format!("cannot restore {} from {}: {error}", exe.display(), prev.display()))
}

/// What a successful swap hands the next boot to verify, before this process
/// exits with [`RESTART_EXIT`] — see this module's "Proving the restart
/// worked" documentation.
struct PendingVerification {
    /// The Deploy [`verify_after_restart`] must finish, if one was started —
    /// `None` only when this watcher ran with no [`Deploys`] wired at all.
    deploy_id: Option<String>,
    /// What a rollback restores the tree to.
    previous_commit: String,
    /// What [`Deploys::finish`] records as this Deploy's commit once verified.
    new_commit: String,
}

/// Writes the pending-verification marker to `<data_dir>/self-update.pending`.
fn write_pending(data_dir: &Path, pending: &PendingVerification) -> std::io::Result<()> {
    let json = Json::object([
        (
            "deployId",
            match &pending.deploy_id {
                Some(id) => Json::string(id),
                None => Json::Null,
            },
        ),
        ("previousCommit", Json::string(&pending.previous_commit)),
        ("newCommit", Json::string(&pending.new_commit)),
    ]);
    std::fs::create_dir_all(data_dir)?;
    std::fs::write(data_dir.join(PENDING_VERIFICATION_FILENAME), json.to_text())
}

/// Reads and removes the pending-verification marker. Removed on read, not
/// just on a verdict, so a crash partway through verifying cannot repeat the
/// same check forever on every following boot — the ordinary case, a boot with
/// nothing pending, is unaffected either way.
fn take_pending(data_dir: &Path) -> Option<PendingVerification> {
    let path = data_dir.join(PENDING_VERIFICATION_FILENAME);
    let text = std::fs::read_to_string(&path).ok()?;
    let _ = std::fs::remove_file(&path);
    let value = selfhost_json::parse(&text).ok()?;
    Some(PendingVerification {
        deploy_id: value.get("deployId").and_then(|v| v.as_str()).map(str::to_owned),
        previous_commit: value.get("previousCommit")?.as_str()?.to_owned(),
        new_commit: value.get("newCommit")?.as_str()?.to_owned(),
    })
}

/// What checking a freshly-restarted deployment concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// This boot was not preceded by a self-update; nothing to verify. The
    /// overwhelming majority of boots.
    NothingPending,
    /// The new build proved itself within the deadline. The Deploy this
    /// update started is now recorded [`DeployResult::Succeeded`].
    Verified,
    /// It did not serve within the deadline. [`prev_path`]'s binary and the
    /// previous commit are already restored, and the Deploy is recorded
    /// [`DeployResult::Failed`] with `detail`. The caller must still exit with
    /// [`RESTART_EXIT`] so the service manager brings the restored build back
    /// — this function never exits the process itself, so its decision stays
    /// provable without a real restart (see the tests below).
    RolledBack {
        /// What was observed, and what the rollback itself did or did not
        /// manage — the same string recorded as the Deploy's log.
        detail: String,
    },
}

/// Checks whether a self-update that just restarted this process is actually
/// serving, and rolls it back if it is not.
///
/// Meant to be spawned once, early in startup, after the listeners it is
/// about to grade are already bound — a probe run any earlier would only ever
/// report [`crate::health::Serving::Untestable`]. Fire-and-forget rather than
/// awaited: a rollback it decides on exits the whole process on its own, and
/// the ordinary case — nothing pending — returns almost immediately having
/// cost one failed file read.
pub async fn verify_after_restart(
    data_dir: PathBuf,
    project_dir: PathBuf,
    config: Config,
    deploys: Option<Arc<Deploys>>,
) -> VerifyResult {
    let result = verify_after_restart_with(
        &data_dir,
        &project_dir,
        deploys.as_deref(),
        || probe_config(&config, &project_dir),
        VERIFY_POLL_INTERVAL,
        VERIFY_DEADLINE,
    )
    .await;
    if let VerifyResult::RolledBack { detail } = &result {
        eprintln!("self-update: {detail}");
    }
    result
}

/// One probe pass, reduced to the yes/no [`verify_after_restart_with`] polls
/// on — reusing [`crate::health::probe_all`], the exact function `selfhost
/// health` reports from, rather than a second implementation of the same
/// question.
async fn probe_config(config: &Config, project_dir: &Path) -> Result<(), String> {
    let probes = crate::health::probe_all(config, project_dir).await;
    match probes.into_iter().find(|probe| probe.serving.is_fault()) {
        None => Ok(()),
        Some(probe) => Err(format!("{} not serving: {}", probe.component.label(), probe.detail)),
    }
}

/// [`verify_after_restart`] with the probe and the timing injected, so the
/// decision it makes — healthy in time, or rolled back — is provable without a
/// real daemon, real sockets, or a real restart. `probe_once` resolves
/// `Ok(())` once the deployment is serving and `Err(detail)` for as long as it
/// is not.
async fn verify_after_restart_with<F, Fut>(
    data_dir: &Path,
    project_dir: &Path,
    deploys: Option<&Deploys>,
    mut probe_once: F,
    interval: Duration,
    deadline: Duration,
) -> VerifyResult
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    let Some(pending) = take_pending(data_dir) else { return VerifyResult::NothingPending };
    let finish = |result: DeployResult, commit: Option<String>, log: String| {
        if let (Some(store), Some(id)) = (deploys, pending.deploy_id.as_ref()) {
            store.finish(&DeployId::from_stored(id.clone()), result, commit, log);
        }
    };

    let start = tokio::time::Instant::now();
    loop {
        match probe_once().await {
            Ok(()) => {
                finish(DeployResult::Succeeded, Some(pending.new_commit.clone()), "verified serving after restart".to_owned());
                return VerifyResult::Verified;
            }
            Err(detail) => {
                if start.elapsed() < deadline {
                    tokio::time::sleep(interval).await;
                    continue;
                }
                let mut detail = format!("unhealthy after restart: {detail}");
                match std::env::current_exe() {
                    Ok(exe) => {
                        if let Err(error) = restore_previous_binary(&exe) {
                            detail.push_str(&format!(
                                " — and the previous binary could not be restored: {error}"
                            ));
                        }
                    }
                    Err(error) => detail.push_str(&format!(
                        " — and this process's own binary could not be located to roll back: {error}"
                    )),
                }
                if let Err(error) = git(
                    &plan::reset_to_args(project_dir, &pending.previous_commit),
                    project_dir,
                    TRANSFER_TIMEOUT,
                )
                .await
                {
                    detail.push_str(&format!(" — and the tree could not be rolled back: {error}"));
                }
                finish(DeployResult::Failed, None, detail.clone());
                return VerifyResult::RolledBack { detail };
            }
        }
    }
}

/// Where the configured build writes the binary, for an install running from
/// somewhere other than `target/release`.
fn built_binary_path(project_dir: &Path) -> PathBuf {
    project_dir
        .join("target")
        .join("release")
        .join(format!("selfhost{}", std::env::consts::EXE_SUFFIX))
}

/// Runs one git invocation and answers its stdout, or why it could not.
async fn git(args: &[String], in_dir: &Path, deadline: Duration) -> Result<String, String> {
    match run::git(args, in_dir, deadline).await {
        Ok(ran) if ran.succeeded() => Ok(ran.stdout),
        Ok(ran) => Err(ran.complaint()),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh temp dir this process owns alone, cleaned up by the caller.
    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("selfhost-selfup-{label}-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        dir
    }

    #[test]
    fn the_prev_path_is_one_fixed_name_beside_the_exe() {
        // Fixed, not per-attempt: `restore_previous_binary` must always find
        // the one real previous build at the one name a rollback ever reads.
        // The suffix tracks this platform's own `EXE_SUFFIX` (`.exe` on
        // Windows, nothing on macOS/Linux) rather than a hard-coded one, so
        // this test proves the same thing whichever platform runs it.
        let suffix = std::env::consts::EXE_SUFFIX;
        let exe = PathBuf::from(format!("/srv/target/release/selfhost{suffix}"));
        assert_eq!(prev_path(&exe), PathBuf::from(format!("/srv/target/release/selfhost.prev{suffix}")));
        // Same call twice is the same path — nothing here is unique per process
        // or per attempt the way the old pid-suffixed name was.
        assert_eq!(prev_path(&exe), prev_path(&exe));
    }

    #[test]
    fn the_rollback_discard_path_differs_from_prev_path() {
        // If these ever collided, `restore_previous_binary` would rename the
        // unhealthy build onto the very file it is about to restore from.
        let exe = Path::new("/srv/selfhost");
        assert_ne!(prev_path(exe), rollback_discard_path(exe));
    }

    #[test]
    fn restoring_with_no_previous_binary_is_refused_rather_than_guessed_at() {
        let dir = temp_dir("no-prev");
        let exe = dir.join(format!("selfhost{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&exe, b"currently running").expect("a fake exe");
        let outcome = restore_previous_binary(&exe);
        assert!(outcome.is_err(), "nothing to restore from must be an error, not a silent no-op");
        assert!(exe.exists(), "the running binary must not be touched on a refused restore");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restoring_swaps_the_previous_binary_back_and_discards_the_bad_one() {
        let dir = temp_dir("restore");
        let exe = dir.join(format!("selfhost{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&exe, b"unhealthy new build").expect("a fake exe");
        std::fs::write(prev_path(&exe), b"the build that was serving").expect("a fake prev");

        restore_previous_binary(&exe).expect("both files are ordinary, unlocked files");

        assert_eq!(std::fs::read(&exe).expect("restored"), b"the build that was serving");
        assert!(!prev_path(&exe).exists(), "prev_path is consumed by a restore, not copied");
        assert_eq!(
            std::fs::read(rollback_discard_path(&exe)).expect("the bad build was kept, not deleted"),
            b"unhealthy new build"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pending_verification_round_trips_through_the_data_dir_and_is_removed_on_read() {
        let dir = temp_dir("pending-roundtrip");
        let pending = PendingVerification {
            deploy_id: Some("abc123".to_owned()),
            previous_commit: "aaaa".to_owned(),
            new_commit: "bbbb".to_owned(),
        };
        write_pending(&dir, &pending).expect("an ordinary, writable temp dir");

        let read_back = take_pending(&dir).expect("the marker that was just written");
        assert_eq!(read_back.deploy_id.as_deref(), Some("abc123"));
        assert_eq!(read_back.previous_commit, "aaaa");
        assert_eq!(read_back.new_commit, "bbbb");

        // Removed by the read above: a crash mid-verification must not repeat
        // the same check — and the same rollback — on every boot after.
        assert!(take_pending(&dir).is_none(), "the marker must be consumed, not merely read");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pending_verification_with_no_deploy_wired_stores_no_id() {
        // `watch_own_repository` runs with `deploys: None` in a deployment that
        // never wired a `Deploys` store at all — the marker must still round
        // trip, just with nothing for `verify_after_restart` to `finish`.
        let dir = temp_dir("pending-no-id");
        let pending =
            PendingVerification { deploy_id: None, previous_commit: "a".into(), new_commit: "b".into() };
        write_pending(&dir, &pending).expect("an ordinary, writable temp dir");
        let read_back = take_pending(&dir).expect("the marker that was just written");
        assert_eq!(read_back.deploy_id, None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_pending_marker_is_reported_as_nothing_pending_not_an_error() {
        let dir = temp_dir("no-marker");
        assert!(take_pending(&dir).is_none(), "an ordinary boot has nothing to verify");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn verify_after_restart_with_no_pending_marker_does_nothing() {
        let dir = temp_dir("verify-nothing-pending");
        let outcome = verify_after_restart_with(
            &dir,
            Path::new("."),
            None,
            || async { panic!("a probe must never run when nothing is pending") },
            Duration::from_millis(1),
            Duration::from_millis(5),
        )
        .await;
        assert_eq!(outcome, VerifyResult::NothingPending);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_deployment_that_becomes_healthy_within_the_deadline_is_verified_and_recorded() {
        let dir = temp_dir("verify-healthy");
        let deploys = Deploys::in_dir(&dir);
        let id = deploys.start(SELF_UPDATE_TARGET, Trigger::SelfUpdate);
        write_pending(
            &dir,
            &PendingVerification {
                deploy_id: Some(id.as_str().to_owned()),
                previous_commit: "aaaa".to_owned(),
                new_commit: "bbbb".to_owned(),
            },
        )
        .expect("an ordinary, writable temp dir");

        // Unhealthy for the first two probes, then healthy — proving this polls
        // rather than deciding on the very first answer.
        let attempt = std::sync::atomic::AtomicU32::new(0);
        let outcome = verify_after_restart_with(
            &dir,
            Path::new("."),
            Some(&deploys),
            || {
                let n = attempt.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move { if n < 2 { Err("not yet".to_owned()) } else { Ok(()) } }
            },
            Duration::from_millis(1),
            Duration::from_secs(5),
        )
        .await;

        assert_eq!(outcome, VerifyResult::Verified);
        let deploy = deploys.get(id.as_str()).expect("the deploy this update started");
        assert_eq!(deploy.result, DeployResult::Succeeded);
        assert_eq!(deploy.commit.as_deref(), Some("bbbb"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_deployment_that_stays_unhealthy_is_rolled_back_and_recorded_as_failed() {
        let dir = temp_dir("verify-unhealthy");
        // `restore_previous_binary` inside `verify_after_restart_with` reads
        // `std::env::current_exe()` — this test binary — and there is
        // ordinarily no `selfhost.prev` beside it, so the restore step itself
        // fails and folds its own complaint into `detail`; the rename
        // mechanics of a restore that *can* succeed are already proven by
        // `restoring_swaps_the_previous_binary_back_and_discards_the_bad_one`
        // above. What this test drives is everything around that: the
        // deadline expiring, the tree-rollback attempt, and the Deploy being
        // finished `Failed` with a real log rather than left `Running`.
        let deploys = Deploys::in_dir(&dir);
        let id = deploys.start(SELF_UPDATE_TARGET, Trigger::SelfUpdate);
        write_pending(
            &dir,
            &PendingVerification {
                deploy_id: Some(id.as_str().to_owned()),
                previous_commit: "aaaa".to_owned(),
                new_commit: "bbbb".to_owned(),
            },
        )
        .expect("an ordinary, writable temp dir");

        // A directory with no `.git` — the tree-rollback step fails and its
        // failure must be folded into the report, not silently dropped, the
        // same discipline `roll_back` already holds itself to.
        let outcome = verify_after_restart_with(
            &dir,
            &dir,
            Some(&deploys),
            || async { Err("control-api not serving: connection refused".to_owned()) },
            Duration::from_millis(1),
            Duration::from_millis(20),
        )
        .await;

        let VerifyResult::RolledBack { detail } = outcome else {
            panic!("an always-failing probe must roll back, not verify");
        };
        assert!(detail.contains("unhealthy after restart"), "{detail}");
        assert!(detail.contains("control-api not serving"), "{detail}");

        let deploy = deploys.get(id.as_str()).expect("the deploy this update started");
        assert_eq!(deploy.result, DeployResult::Failed);
        assert_eq!(deploy.commit, None, "a rolled-back deploy is not the new commit");
        assert_eq!(deploy.log, detail);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_absent_self_update_section_pends_rather_than_polling() {
        let watch = watch_own_repository(None, PathBuf::from("."), PathBuf::from("."), Nudge::new(), None);
        let outcome = tokio::time::timeout(Duration::from_millis(50), watch).await;
        assert!(outcome.is_err(), "no config must mean no polling");
    }

    #[tokio::test]
    async fn a_disabled_self_update_ignores_a_nudge_rather_than_deploying() {
        // The switch has to hold against the *push* path too, not just the
        // timer: `enabled = false` during an incident must mean nothing
        // deploys, however loudly the repository announces itself.
        let mut update = selfhost_config::SelfUpdate::new("https://127.0.0.1:1/none.git");
        update.enabled = false;
        let nudge = Nudge::new();
        nudge.poke();

        let watch =
            watch_own_repository(Some(update), PathBuf::from("."), PathBuf::from("."), nudge, None);
        let outcome = tokio::time::timeout(Duration::from_millis(100), watch).await;
        assert!(outcome.is_err(), "a disabled watch must not act on a push");
    }

    #[tokio::test]
    async fn a_deployment_that_is_not_a_clone_reports_itself_rather_than_deploying() {
        let dir = std::env::temp_dir().join(format!("selfhost-selfup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temp dir");
        // A repository URL that answers instantly and exists: the temp dir has
        // no .git, so the local-head read must fail before anything acts. The
        // remote read fails first here (the URL is not a repository), which is
        // the same honest outcome: an error, no action.
        let update = selfhost_config::SelfUpdate::new("https://127.0.0.1:1/none.git");
        let outcome = poll_once(&update, &dir).await;
        assert!(outcome.is_err(), "nothing to deploy from must be an error, not a deploy");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
