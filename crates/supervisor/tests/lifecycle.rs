//! Supervision against real processes.
//!
//! The pure decision logic is unit-tested inside the crate. These tests exist for
//! the part that unit tests cannot reach: that an actual child is actually
//! spawned, actually reaped, actually restarted, and that its output actually
//! arrives. A supervisor that passes its own policy tests and still leaks
//! processes has not been tested.

use selfhost_config::{RestartPolicy, ServiceSpec, StartMode};
use selfhost_supervisor::state::ServiceState;
use selfhost_supervisor::{Supervisor, await_state, scripted_service};
use std::time::Duration;

/// A service that stays up until it is stopped.
fn long_running(name: &str) -> ServiceSpec {
    let script = if cfg!(windows) { "ping -n 31 127.0.0.1 >NUL" } else { "sleep 30" };
    quick(scripted_service(name, script))
}

/// A service that exits non-zero the moment it starts.
fn fails_immediately(name: &str) -> ServiceSpec {
    quick(scripted_service(name, "exit 3"))
}

/// A service that exits zero the moment it starts.
fn succeeds_immediately(name: &str) -> ServiceSpec {
    quick(scripted_service(name, "exit 0"))
}

/// Shortens every delay so a test does not have to wait out production defaults.
fn quick(mut spec: ServiceSpec) -> ServiceSpec {
    spec.start_mode = StartMode::Manual;
    spec.restart_delay_secs = 1;
    spec.stop_timeout_secs = 2;
    spec.max_restarts = 2;
    spec
}

/// A supervisor rooted at a scratch directory that cleans itself up.
fn supervisor() -> (Supervisor, tempdir::TempDir) {
    let dir = tempdir::TempDir::new();
    (Supervisor::new(dir.path()), dir)
}

const PATIENCE: Duration = Duration::from_secs(15);

#[tokio::test]
async fn starts_a_service_and_reports_it_running() {
    let (supervisor, _dir) = supervisor();
    supervisor.install(long_running("up")).await;
    supervisor.start("up").await;

    let state = await_state(&supervisor, "up", PATIENCE, |s| matches!(s, ServiceState::Running { .. }))
        .await
        .expect("should reach Running");

    match state {
        ServiceState::Running { pid, .. } => assert!(pid > 0, "a running service has a pid"),
        other => panic!("expected Running, got {other:?}"),
    }

    supervisor.shutdown().await;
}

#[tokio::test]
async fn uptime_grows_while_a_service_stays_up() {
    // The bug this guards: uptime baked into the state at spawn, which reports
    // whatever it was at that instant — always zero — for the service's whole life.
    let (supervisor, _dir) = supervisor();
    supervisor.install(long_running("clock")).await;
    supervisor.start("clock").await;
    await_state(&supervisor, "clock", PATIENCE, |s| matches!(s, ServiceState::Running { .. }))
        .await
        .expect("should start");

    tokio::time::sleep(Duration::from_millis(1200)).await;
    match supervisor.status("clock").await.expect("installed").state {
        ServiceState::Running { uptime_secs, .. } => {
            assert!(uptime_secs >= 1, "uptime should advance, got {uptime_secs}");
        }
        other => panic!("expected Running, got {other:?}"),
    }

    // A stopped service must not report the uptime of its previous run.
    supervisor.stop("clock").await;
    await_state(&supervisor, "clock", PATIENCE, |s| matches!(s, ServiceState::Stopped))
        .await
        .expect("should stop");
    assert_eq!(supervisor.status("clock").await.unwrap().state, ServiceState::Stopped);

    supervisor.shutdown().await;
}

#[tokio::test]
async fn stops_a_service_when_asked() {
    let (supervisor, _dir) = supervisor();
    supervisor.install(long_running("up")).await;
    supervisor.start("up").await;
    await_state(&supervisor, "up", PATIENCE, |s| matches!(s, ServiceState::Running { .. }))
        .await
        .expect("should start");

    supervisor.stop("up").await;
    await_state(&supervisor, "up", PATIENCE, |s| matches!(s, ServiceState::Stopped))
        .await
        .expect("should stop");

    supervisor.shutdown().await;
}

#[tokio::test]
async fn an_automatic_service_starts_without_being_asked() {
    let (supervisor, _dir) = supervisor();
    let mut spec = long_running("auto");
    spec.start_mode = StartMode::Automatic;
    supervisor.install(spec).await;

    await_state(&supervisor, "auto", PATIENCE, |s| matches!(s, ServiceState::Running { .. }))
        .await
        .expect("automatic services start on install");

    supervisor.shutdown().await;
}

#[tokio::test]
async fn a_disabled_service_refuses_to_start() {
    let (supervisor, _dir) = supervisor();
    let mut spec = long_running("off");
    spec.start_mode = StartMode::Disabled;
    supervisor.install(spec).await;
    supervisor.start("off").await;

    // Give it room to wrongly start before concluding that it did not.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let status = supervisor.status("off").await.expect("installed");
    assert_eq!(status.state, ServiceState::Disabled);

    supervisor.shutdown().await;
}

#[tokio::test]
async fn a_failing_service_is_restarted_then_given_up_on() {
    let (supervisor, _dir) = supervisor();
    let mut spec = fails_immediately("flapper");
    spec.restart = RestartPolicy::OnFailure;
    spec.max_restarts = 2;
    supervisor.install(spec).await;
    supervisor.start("flapper").await;

    let state = await_state(&supervisor, "flapper", PATIENCE, |s| {
        matches!(s, ServiceState::GaveUp { .. })
    })
    .await
    .expect("should exhaust its budget and give up");

    match state {
        ServiceState::GaveUp { attempts, .. } => assert_eq!(attempts, 2),
        other => panic!("expected GaveUp, got {other:?}"),
    }

    // Giving up is not the same as never having tried.
    let status = supervisor.status("flapper").await.unwrap();
    assert_eq!(status.total_restarts, 2);

    supervisor.shutdown().await;
}

#[tokio::test]
async fn a_clean_exit_is_left_alone_under_the_default_policy() {
    let (supervisor, _dir) = supervisor();
    let mut spec = succeeds_immediately("oneshot");
    spec.restart = RestartPolicy::OnFailure;
    supervisor.install(spec).await;
    supervisor.start("oneshot").await;

    let state = await_state(&supervisor, "oneshot", PATIENCE, |s| {
        matches!(s, ServiceState::Exited { .. })
    })
    .await
    .expect("should settle as Exited");

    assert_eq!(state, ServiceState::Exited { code: Some(0) });
    assert_eq!(supervisor.status("oneshot").await.unwrap().total_restarts, 0);

    supervisor.shutdown().await;
}

#[tokio::test]
async fn a_failing_service_is_left_alone_when_the_policy_says_never() {
    let (supervisor, _dir) = supervisor();
    let mut spec = fails_immediately("once");
    spec.restart = RestartPolicy::Never;
    supervisor.install(spec).await;
    supervisor.start("once").await;

    let state =
        await_state(&supervisor, "once", PATIENCE, |s| matches!(s, ServiceState::Exited { .. }))
            .await
            .expect("should settle as Exited");

    assert_eq!(state, ServiceState::Exited { code: Some(3) });
    assert_eq!(supervisor.status("once").await.unwrap().total_restarts, 0);

    supervisor.shutdown().await;
}

#[tokio::test]
async fn a_program_that_does_not_exist_says_so_instead_of_looping() {
    // The bug this guards: feeding a bad path into the restart cycle, which
    // burns the whole budget rediscovering the same thing and buries the one
    // message that would have told the operator what is wrong.
    let (supervisor, _dir) = supervisor();
    let mut spec = ServiceSpec::new("ghost", "/definitely/not/a/real/program");
    spec.start_mode = StartMode::Manual;
    supervisor.install(spec).await;
    supervisor.start("ghost").await;

    let state = await_state(&supervisor, "ghost", PATIENCE, |s| {
        matches!(s, ServiceState::Unstartable { .. })
    })
    .await
    .expect("should report it cannot start");

    match state {
        ServiceState::Unstartable { reason } => {
            assert!(reason.contains("not found"), "should explain itself: {reason}");
        }
        other => panic!("expected Unstartable, got {other:?}"),
    }
    assert_eq!(supervisor.status("ghost").await.unwrap().total_restarts, 0);

    supervisor.shutdown().await;
}

#[tokio::test]
async fn captures_what_a_service_writes() {
    let (supervisor, _dir) = supervisor();
    let script = if cfg!(windows) {
        "echo hello from the service&& ping -n 31 127.0.0.1 >NUL"
    } else {
        "echo hello from the service; sleep 30"
    };
    supervisor.install(quick(scripted_service("chatty", script))).await;
    supervisor.start("chatty").await;

    let mut found = false;
    for _ in 0..200 {
        let slice = supervisor.logs("chatty", 0, 500).await.expect("installed");
        if slice.lines.iter().any(|l| l.text.contains("hello from the service")) {
            found = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(found, "the service's output should reach the log ring");

    supervisor.shutdown().await;
}

#[tokio::test]
async fn restarting_replaces_the_process() {
    let (supervisor, _dir) = supervisor();
    supervisor.install(long_running("cycle")).await;
    supervisor.start("cycle").await;

    let first = await_state(&supervisor, "cycle", PATIENCE, |s| {
        matches!(s, ServiceState::Running { .. })
    })
    .await
    .expect("should start");
    let first_pid = match first {
        ServiceState::Running { pid, .. } => pid,
        other => panic!("expected Running, got {other:?}"),
    };

    supervisor.restart("cycle").await;

    let mut second_pid = first_pid;
    for _ in 0..300 {
        if let Some(status) = supervisor.status("cycle").await
            && let ServiceState::Running { pid, .. } = status.state
            && pid != first_pid
        {
            second_pid = pid;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_ne!(second_pid, first_pid, "a restart should produce a new process");

    supervisor.shutdown().await;
}

#[tokio::test]
async fn an_operator_start_clears_a_spent_restart_budget() {
    // Pressing Start after a service gave up must actually try again. Inheriting
    // the old counter would make the button appear to do nothing.
    let (supervisor, _dir) = supervisor();
    supervisor.install(fails_immediately("stubborn")).await;
    supervisor.start("stubborn").await;
    await_state(&supervisor, "stubborn", PATIENCE, |s| matches!(s, ServiceState::GaveUp { .. }))
        .await
        .expect("should give up first");

    supervisor.start("stubborn").await;
    let state = await_state(&supervisor, "stubborn", PATIENCE, |s| {
        matches!(s, ServiceState::Backoff { .. } | ServiceState::Starting)
    })
    .await;
    assert!(state.is_some(), "starting a service that gave up should try again");

    supervisor.shutdown().await;
}

#[tokio::test]
async fn shutdown_stops_every_child() {
    let (supervisor, _dir) = supervisor();
    supervisor.install(long_running("a")).await;
    supervisor.install(long_running("b")).await;
    supervisor.start("a").await;
    supervisor.start("b").await;

    for name in ["a", "b"] {
        await_state(&supervisor, name, PATIENCE, |s| matches!(s, ServiceState::Running { .. }))
            .await
            .unwrap_or_else(|| panic!("{name} should start"));
    }

    supervisor.shutdown().await;
    assert!(supervisor.statuses().await.is_empty(), "shutdown forgets every service");
}

#[tokio::test]
async fn installing_over_a_running_service_replaces_it() {
    let (supervisor, _dir) = supervisor();
    supervisor.install(long_running("swap")).await;
    supervisor.start("swap").await;
    await_state(&supervisor, "swap", PATIENCE, |s| matches!(s, ServiceState::Running { .. }))
        .await
        .expect("should start");

    // The replacement is manual-start, so a supervisor that left the old process
    // running would still report Running here.
    supervisor.install(long_running("swap")).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let status = supervisor.status("swap").await.expect("still installed");
    assert!(!status.state.is_live(), "the old process should not survive a replacement");
    assert_eq!(supervisor.statuses().await.len(), 1, "and there is only one of it");

    supervisor.shutdown().await;
}

/// Stopping a service must stop everything it started, not just the process we
/// spawned.
///
/// Nearly every real service is launched through a wrapper — a shell script, a
/// language launcher, `npm start` — and the wrapper forks the program that
/// actually binds the port. Signalling only the direct child kills the wrapper
/// and reparents the real worker to init, still running and still holding the
/// port, so the next start fails to bind and blames the wrong thing.
///
/// The worker here is a grandchild that appends to a file forever. If the tree
/// really stopped, the file stops growing.
#[cfg(unix)]
#[tokio::test]
async fn stopping_a_service_also_stops_the_children_it_started() {
    let (supervisor, dir) = supervisor();
    let ticks = dir.path().join("ticks");
    let script = format!(
        "sh -c 'while true; do echo tick >> {} ; sleep 0.05; done' & wait",
        ticks.display()
    );

    supervisor.install(quick(scripted_service("tree", &script))).await;
    supervisor.start("tree").await;
    await_state(&supervisor, "tree", PATIENCE, |s| matches!(s, ServiceState::Running { .. }))
        .await
        .expect("should start");

    // Wait until the grandchild is demonstrably alive and writing.
    let mut grew = false;
    for _ in 0..200 {
        if std::fs::metadata(&ticks).map(|m| m.len() > 0).unwrap_or(false) {
            grew = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(grew, "the grandchild should be writing before we test stopping it");

    supervisor.stop("tree").await;
    await_state(&supervisor, "tree", PATIENCE, |s| matches!(s, ServiceState::Stopped))
        .await
        .expect("should stop");

    // Let anything that survived keep writing, then check that it did not.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let settled = std::fs::metadata(&ticks).map(|m| m.len()).unwrap_or(0);
    tokio::time::sleep(Duration::from_millis(600)).await;
    let after = std::fs::metadata(&ticks).map(|m| m.len()).unwrap_or(0);

    assert_eq!(
        settled, after,
        "a descendant outlived the stop and is still writing — the process group was not killed"
    );

    supervisor.shutdown().await;
}

/// A scratch directory that removes itself when dropped.
///
/// Written here rather than taken as a dependency: it is a dozen lines, it is
/// only used by tests, and the alternative is a crate in the tree for the sake
/// of `mkdir`.
mod tempdir {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new() -> Self {
            let unique = format!(
                "selfhost-supervisor-test-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            let path = std::env::temp_dir().join(unique);
            std::fs::create_dir_all(&path).expect("create scratch directory");
            Self(path)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
