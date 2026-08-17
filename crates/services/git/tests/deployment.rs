//! A whole deployment against a real repository.
//!
//! The unit tests decide what to run and what an answer means without running
//! anything. This runs it: a repository is created on disk, a service is
//! installed that serves a file out of the checkout, and a commit to the branch
//! has to reach that running service.
//!
//! # Why the repository is a local path
//!
//! `selfhost_config::GitWatch::check` refuses a local path, and rightly: a
//! repository URL arriving over the control API must not name a program or a file
//! on the daemon's own disk. That rule governs *what an operator may install*.
//! What is under test here is the machinery underneath it — clone, fetch, reset,
//! build, restart — which has to work identically whatever the transport is, and
//! which cannot be exercised offline any other way. The watch is therefore built
//! directly rather than parsed from a catalogue.

use selfhost_config::{GitWatch, RestartPolicy, ServiceSpec, StartMode};
use selfhost_git::{Outcome, check_once};
use selfhost_supervisor::{Supervisor, await_state};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Runs `git` in `at`, failing the test with its own message if it refuses.
fn git(at: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(at)
        .env("GIT_AUTHOR_NAME", "selfhost tests")
        .env("GIT_AUTHOR_EMAIL", "tests@example.invalid")
        .env("GIT_COMMITTER_NAME", "selfhost tests")
        .env("GIT_COMMITTER_EMAIL", "tests@example.invalid")
        .output()
        .expect("git must be installed to run these tests");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// A directory of this test's own, removed and recreated so a previous run
/// cannot make this one pass.
fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("selfhost-git-test-{name}"));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("a scratch directory");
    path
}

/// Creates a repository holding one file, on branch `main`.
fn repository_with(at: &Path, contents: &str) {
    std::fs::create_dir_all(at).expect("the repository directory");
    git(at, &["init", "--initial-branch=main"]);
    // Written with its newline: the supervisor captures output line by line, so a
    // file without one is not printed until the process that printed it exits.
    std::fs::write(at.join("version.txt"), format!("{contents}\n")).expect("the tracked file");
    git(at, &["add", "version.txt"]);
    git(at, &["commit", "-m", "first"]);
}

/// Commits a change to the file, moving the branch.
fn commit_change(at: &Path, contents: &str) -> String {
    std::fs::write(at.join("version.txt"), format!("{contents}\n")).expect("the tracked file");
    git(at, &["add", "version.txt"]);
    git(at, &["commit", "-m", "change"]);
    git(at, &["rev-parse", "HEAD"]).trim().to_owned()
}

/// A service that prints the checked-out file and then stays running.
fn service_reading(checkout: &str) -> ServiceSpec {
    let mut spec = selfhost_supervisor::scripted_service(
        "site",
        "cat version.txt; while true; do sleep 1; done",
    );
    spec.cwd = Some(PathBuf::from(checkout));
    spec.start_mode = StartMode::Manual;
    spec.restart = RestartPolicy::Never;
    spec.stop_timeout_secs = 2;
    spec
}

/// The process id the service is running under, once it has one.
///
/// Waits, because "started" and "has a process id" are a moment apart: the
/// supervisor reports `Starting` while it spawns, and a test that read the pid
/// at that instant would compare `None` against a real process.
async fn await_pid(supervisor: &Supervisor) -> Option<u32> {
    let state = await_state(supervisor, "site", Duration::from_secs(10), |state| {
        matches!(state, selfhost_supervisor::state::ServiceState::Running { .. })
    })
    .await?;
    match state {
        selfhost_supervisor::state::ServiceState::Running { pid, .. } => Some(pid),
        _ => None,
    }
}

/// Everything the service has printed and everything written about it.
async fn output(supervisor: &Supervisor) -> String {
    supervisor
        .logs("site", 0, 500)
        .await
        .expect("the service exists")
        .lines
        .iter()
        .map(|line| format!("{}\n", line.text))
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_push_reaches_the_running_service() {
    let base = scratch("push");
    let origin = base.join("origin");
    repository_with(&origin, "v1");

    let mut watch = GitWatch::new(origin.display().to_string(), "checkout");
    watch.post_pull = Some(vec![
        "/bin/sh".into(),
        "-c".into(),
        "echo built >> build-count.txt".into(),
    ]);

    let supervisor = Supervisor::new(&base);
    let spec = service_reading("checkout");
    supervisor.install(spec.clone()).await;

    // First check: nothing on disk yet, so it clones, builds, and starts.
    let outcome = check_once(&supervisor, &spec, &watch).await.expect("the first deployment");
    assert!(matches!(outcome, Outcome::Deployed { .. }), "{outcome:?}");
    assert_eq!(
        std::fs::read_to_string(base.join("checkout/version.txt")).expect("the checkout").trim(),
        "v1"
    );

    let state = await_state(&supervisor, "site", Duration::from_secs(10), |state| state.is_live())
        .await;
    assert!(state.is_some(), "the service should be running after a deployment");
    assert!(
        base.join("checkout/build-count.txt").exists(),
        "the post-pull step should have run in the working copy"
    );

    // A second check with nothing new must not touch the running service: the
    // process it is running has to be the same one, not a restarted equivalent.
    let before = await_pid(&supervisor).await;
    assert_eq!(
        check_once(&supervisor, &spec, &watch).await.expect("a second check"),
        Outcome::NothingToDo
    );
    assert_eq!(await_pid(&supervisor).await, before, "an unmoved branch must not restart it");

    // Now the branch moves.
    let commit = commit_change(&origin, "v2");
    let outcome = check_once(&supervisor, &spec, &watch).await.expect("the second deployment");
    assert_eq!(outcome, Outcome::Deployed { commit: commit.clone() });
    assert_eq!(
        std::fs::read_to_string(base.join("checkout/version.txt")).expect("the checkout").trim(),
        "v2",
        "the working copy should be on the new commit"
    );

    let state = await_state(&supervisor, "site", Duration::from_secs(10), |state| state.is_live())
        .await;
    assert!(state.is_some(), "the service should be running again");

    // The service itself has to have seen the new file, not just the disk.
    let seen = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if output(&supervisor).await.contains("v2") {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(seen.is_ok(), "the restarted service should have printed v2:\n{}", output(&supervisor).await);

    // And the deployment reported itself where the operator is already looking.
    let text = output(&supervisor).await;
    assert!(text.contains("[git]"), "{text}");
    assert!(text.contains(&commit[..7]), "{text}");

    supervisor.shutdown().await;
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_build_leaves_the_service_stopped_rather_than_running_old_code() {
    let base = scratch("failed-build");
    let origin = base.join("origin");
    repository_with(&origin, "v1");

    let mut watch = GitWatch::new(origin.display().to_string(), "checkout");
    watch.post_pull = Some(vec!["/bin/sh".into(), "-c".into(), "echo no >&2; exit 1".into()]);

    let supervisor = Supervisor::new(&base);
    let spec = service_reading("checkout");
    supervisor.install(spec.clone()).await;

    let outcome = check_once(&supervisor, &spec, &watch).await.expect("a check");
    match outcome {
        Outcome::Failed { step, reason } => {
            assert_eq!(step, "build");
            assert!(reason.contains("no"), "{reason}");
        }
        other => panic!("expected the build to fail the deployment, got {other:?}"),
    }

    // Nothing should be running: starting the service would run the previous
    // build against code that did not build.
    let state = supervisor.status("site").await.expect("installed").state;
    assert!(!state.is_live(), "left {state:?}");

    let text = output(&supervisor).await;
    assert!(text.contains("left stopped"), "the operator has to be told why:\n{text}");

    supervisor.shutdown().await;
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test(flavor = "multi_thread")]
async fn untracked_files_survive_a_deployment() {
    // node_modules, a build cache, and an .env the operator put there all live
    // untracked in the working copy. A deployment that removes them is one that
    // also has to put them back.
    let base = scratch("untracked");
    let origin = base.join("origin");
    repository_with(&origin, "v1");

    let watch = GitWatch::new(origin.display().to_string(), "checkout");
    let supervisor = Supervisor::new(&base);
    let mut spec = service_reading("checkout");
    spec.git = Some(watch.clone());
    supervisor.install(spec.clone()).await;

    check_once(&supervisor, &spec, &watch).await.expect("the first deployment");
    let secret = base.join("checkout/.env");
    std::fs::write(&secret, "TOKEN=keep-me").expect("an untracked file");

    commit_change(&origin, "v2");
    check_once(&supervisor, &spec, &watch).await.expect("the second deployment");

    assert_eq!(
        std::fs::read_to_string(&secret).expect("the untracked file should still be there"),
        "TOKEN=keep-me"
    );

    supervisor.shutdown().await;
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_branch_that_does_not_exist_is_reported_rather_than_guessed_at() {
    let base = scratch("no-branch");
    let origin = base.join("origin");
    repository_with(&origin, "v1");

    let mut watch = GitWatch::new(origin.display().to_string(), "checkout");
    watch.branch = "release".into();

    let supervisor = Supervisor::new(&base);
    let spec = service_reading("checkout");
    supervisor.install(spec.clone()).await;

    let error = check_once(&supervisor, &spec, &watch).await.expect_err("there is no such branch");
    assert!(error.contains("release"), "{error}");
    assert!(!base.join("checkout").exists(), "nothing should have been cloned");

    supervisor.shutdown().await;
    let _ = std::fs::remove_dir_all(&base);
}
