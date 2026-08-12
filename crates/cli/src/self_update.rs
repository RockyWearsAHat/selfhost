//! Updating selfhost itself when its own repository moves.
//!
//! The `[self_update]` section of the config names the repository this
//! deployment is a clone of. When that branch moves, the daemon fetches,
//! hard-resets the project directory, runs the build, swaps the binary in, and
//! exits so the service manager restarts the new build.
//!
//! # What makes it notice
//!
//! Two triggers, for the reason `selfhost_config::git` sets out in full: a
//! webhook carries the latency (a push deploys in about a second) and the poll
//! interval underneath it is the safety net that catches a hook which never
//! arrived. The webhook arrives here as a [`Nudge`] — a signal carrying nothing
//! at all — so the request body can never influence *what* gets deployed. Both
//! triggers run the identical check: read the real branch tip with
//! `git ls-remote`, compare it to `HEAD`, act only on a genuine difference.
//!
//! # Who restarts whom
//!
//! Nothing here re-executes itself. Every installed deployment already runs
//! under a supervisor that restarts a dead process — launchd (`KeepAlive`),
//! systemd (`Restart=on-failure`), or a Windows Scheduled Task
//! (`RestartOnFailure`) — so the correct restart is simply to exit and let the
//! machinery that owns the process do its one job. The exit code is
//! [`RESTART_EXIT`], nonzero on purpose: launchd restarts any exit, but systemd
//! and the Scheduled Task only restart a failure.
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
//! `<exe>.old`, the build writes a fresh binary at the original path, and the
//! leftover is deleted at the next startup ([`sweep_aside`]) — deleting it
//! immediately would fail on Windows for the same lock. On macOS and Linux the
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
//! poll retries the whole update instead of reporting up to date.

use selfhost_config::SelfUpdate;
use selfhost_git::Nudge;
use selfhost_git::plan;
use selfhost_git::run::{self, BUILD_TIMEOUT, LS_REMOTE_TIMEOUT, TRANSFER_TIMEOUT};
use std::path::{Path, PathBuf};
use std::time::Duration;

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
        /// The commit now deployed.
        to: String,
    },
}

/// Watches the daemon's own repository and installs what a push delivers.
///
/// Pends forever when the section is absent or disabled, so it can occupy a
/// `select!` arm unconditionally. Otherwise it checks whenever `nudge` is poked
/// *or* the configured interval elapses — whichever comes first — and returns
/// only after an update has been fetched, built, and swapped in. Errors and
/// skips are reported to stderr and retried, never fatal. The returned commit
/// is what runs the moment the caller exits with [`RESTART_EXIT`] and the
/// service manager restarts the process.
///
/// The two triggers are deliberately indistinguishable from here: both run
/// [`poll_once`], which reads the branch tip itself. Nothing about a check
/// depends on *why* it started, so the webhook cannot deploy anything the
/// timer would not have deployed a few minutes later.
pub async fn watch_own_repository(
    update: Option<SelfUpdate>,
    project_dir: PathBuf,
    nudge: Nudge,
) -> String {
    let Some(update) = update.filter(|u| u.enabled) else { return std::future::pending().await };
    sweep_aside();

    let mut ticker = tokio::time::interval(Duration::from_secs(
        update.interval_secs.max(selfhost_config::git::MIN_INTERVAL_SECS),
    ));
    // A repeated failure (an unreachable remote, a dirty tree left dirty) would
    // otherwise say the same thing every interval, forever.
    let mut already_said = String::new();
    loop {
        // A nudge that lands *during* a check is remembered by `Nudge`, so the
        // push that arrives mid-build is not lost — it is served by the very
        // next pass round this loop.
        let pushed = tokio::select! {
            _ = ticker.tick() => false,
            _ = nudge.poked() => true,
        };
        if pushed {
            println!("self-update: a push was announced; checking now");
        }
        match poll_once(&update, &project_dir).await {
            Ok(Progress::UpToDate) => already_said.clear(),
            Ok(Progress::Updated { to }) => return to,
            Err(reason) => {
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
        let ran = git(&plan::ls_remote_args(&watch), project_dir, LS_REMOTE_TIMEOUT).await?;
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
    git(&plan::fetch_args(&watch, project_dir), project_dir, TRANSFER_TIMEOUT).await?;

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
    Ok(Progress::Updated { to: remote })
}

/// Builds the new binary with the running one renamed aside, and puts the
/// result where the service manager expects to find it.
///
/// On failure the binary is renamed back and the tree is rolled back to
/// `previous`, so the deployment keeps running — and keeps being retried —
/// exactly as it was.
async fn build_and_swap(
    update: &SelfUpdate,
    project_dir: &Path,
    previous: &str,
) -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|error| format!("cannot locate this process's own binary: {error}"))?;
    let aside = aside_path(&exe);
    if let Err(error) = std::fs::rename(&exe, &aside) {
        // The tree is already on the new commit; leaving it there would make
        // the next poll read "up to date" while the old binary keeps running.
        let reason =
            format!("cannot move {} aside for the new build: {error}", exe.display());
        return Err(roll_back(project_dir, previous, &exe, &aside, reason).await);
    }

    let command = update.build_command();
    let failure = match run::build_step(&command, project_dir, BUILD_TIMEOUT).await {
        Ok(ran) if ran.succeeded() => None,
        Ok(ran) => Some(ran.complaint()),
        Err(error) => Some(error.to_string()),
    };
    if let Some(reason) = failure {
        return Err(roll_back(project_dir, previous, &exe, &aside, format!("build failed: {reason}")).await);
    }

    // The usual deployment runs from `target/release`, where the build already
    // put the fresh binary at `exe`'s own path. An install that runs the binary
    // from somewhere else gets the built one copied over — permissions ride
    // along with the copy.
    if !exe.exists() {
        let built = built_binary_path(project_dir);
        if let Err(error) = std::fs::copy(&built, &exe) {
            let reason = format!("cannot install {} as {}: {error}", built.display(), exe.display());
            return Err(roll_back(project_dir, previous, &exe, &aside, reason).await);
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
    aside: &Path,
    reason: String,
) -> String {
    let mut report = format!("{reason}; still running {}", plan::short(previous));
    if !exe.exists()
        && let Err(error) = std::fs::rename(aside, exe)
    {
        report.push_str(&format!(
            " — and the running binary could not be renamed back from {}: {error}",
            aside.display()
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

/// Where the leftover previous binary goes while its process still runs.
///
/// Suffixed with this process's id rather than a bare `.old`: the *previous*
/// update's aside file can still be locked by a sibling process running the
/// older image, and Windows will not rename onto a locked file — so every
/// update takes a fresh name, and [`sweep_aside`] deletes whichever have been
/// released.
fn aside_path(exe: &Path) -> PathBuf {
    let mut name = exe.as_os_str().to_owned();
    name.push(format!(".old.{}", std::process::id()));
    PathBuf::from(name)
}

/// Deletes every renamed-aside previous binary that has been released.
///
/// Runs at watcher startup — after a restart, when this process's predecessor
/// is gone and its lock with it. A sibling still running an older image keeps
/// its aside file locked; that failure is expected and quiet-by-name: the next
/// restart's sweep gets it.
fn sweep_aside() {
    let Ok(exe) = std::env::current_exe() else { return };
    let (Some(dir), Some(file)) = (exe.parent(), exe.file_name()) else { return };
    let prefix = format!("{}.old", file.to_string_lossy());
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with(&prefix)
            && let Err(error) = std::fs::remove_file(entry.path())
        {
            eprintln!(
                "self-update: could not delete the previous binary {} ({error}) — harmless \
                 while another selfhost process still runs the previous build; the next \
                 restart's sweep gets it",
                entry.path().display()
            );
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

    #[test]
    fn the_aside_path_keeps_the_full_name_and_is_unique_to_this_process() {
        // The full name survives (`selfhost.exe.old.…`, not `selfhost.old.…`)
        // and the process id makes it a name no still-locked leftover holds.
        let aside = aside_path(Path::new("/srv/target/release/selfhost.exe"));
        let name = aside.file_name().expect("a file name").to_string_lossy().into_owned();
        assert!(name.starts_with("selfhost.exe.old."), "{name}");
        assert!(name.ends_with(&std::process::id().to_string()), "{name}");
    }

    #[tokio::test]
    async fn an_absent_self_update_section_pends_rather_than_polling() {
        let watch = watch_own_repository(None, PathBuf::from("."), Nudge::new());
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

        let watch = watch_own_repository(Some(update), PathBuf::from("."), nudge);
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
