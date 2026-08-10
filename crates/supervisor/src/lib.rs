//! Starts services, keeps them running, and captures their output.
//!
//! A *service* is any long-running program on the machine — MongoDB, a NAS
//! daemon, a site's own backend. The supervisor's job is the one a person cannot
//! do reliably: notice that something died at four in the morning and start it
//! again, without turning a crash loop into a fork bomb.
//!
//! # Shape
//!
//! One task per service, owning that service's child process, driven by commands
//! on a channel. Nothing shares a process handle, so "stop" and "the process just
//! exited" cannot race over who reaps it — the same task observes both.
//!
//! The interesting decisions are deliberately *not* in that task, because a
//! decision buried in a `select!` cannot be tested:
//!
//! - [`policy`] decides whether and when to restart. Pure, exhaustively tested.
//! - [`logs`] holds the output tail and reports gaps. Pure, exhaustively tested.
//! - [`child`] spawns and stops one process, and owns the one platform difference
//!   that matters — Unix can ask a process to stop, Windows cannot.
//!
//! # Example
//!
//! ```no_run
//! use selfhost_config::ServiceSpec;
//! use selfhost_supervisor::Supervisor;
//!
//! # async fn example() {
//! let supervisor = Supervisor::new(".");
//! supervisor.install(ServiceSpec::new("mongod", "/usr/bin/mongod")).await;
//! supervisor.start("mongod").await;
//! # }
//! ```

#![warn(missing_docs)]

pub mod child;
pub mod logs;
pub mod policy;
pub mod state;

use selfhost_config::{ServiceCatalog, ServiceSpec, StartMode};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, mpsc};

use child::{Captured, Running};
use logs::{LogRing, LogSlice, Stream};
use policy::{Exit, FailureCounter, Outcome};
use state::{ServiceState, ServiceStatus};

/// How many lines of output are kept per service.
///
/// Enough that a console opened after a crash still shows what led to it, and
/// bounded so a chatty service cannot exhaust memory. Anything older has already
/// gone to the service's log file on disk.
const LOG_CAPACITY: usize = 5_000;

/// What an operator asked of a service.
#[derive(Debug)]
enum Command {
    Start,
    Stop,
    Restart,
    Shutdown,
}

/// State shared between a service's task and anyone reading its status.
#[derive(Debug)]
struct Shared {
    state: Mutex<ServiceState>,
    logs: Mutex<LogRing>,
    total_restarts: AtomicU64,
    /// When the current process started, for uptime.
    ///
    /// Kept beside the state rather than inside it because uptime is a moving
    /// number: baking it into `Running` at spawn would report whatever it was at
    /// that instant — which is always zero — for the rest of the service's life.
    started: Mutex<Option<Instant>>,
}

impl Shared {
    fn new(initial: ServiceState) -> Self {
        Self {
            state: Mutex::new(initial),
            logs: Mutex::new(LogRing::new(LOG_CAPACITY)),
            total_restarts: AtomicU64::new(0),
            started: Mutex::new(None),
        }
    }

    async fn set(&self, state: ServiceState) {
        // Only a live process has a start time; anything else must clear it so a
        // stopped service cannot report the uptime of its previous run.
        if !state.is_live() {
            *self.started.lock().await = None;
        }
        *self.state.lock().await = state;
    }

    /// Marks a process as started now, for uptime.
    async fn mark_started(&self, at: Instant) {
        *self.started.lock().await = Some(at);
    }

    /// The state with its uptime brought up to date.
    async fn current_state(&self) -> ServiceState {
        let state = self.state.lock().await.clone();
        match (state, *self.started.lock().await) {
            (ServiceState::Running { pid, .. }, Some(started)) => {
                ServiceState::Running { pid, uptime_secs: started.elapsed().as_secs() }
            }
            (other, _) => other,
        }
    }

    /// Records a line of the supervisor's own commentary in the service's log.
    ///
    /// Mixed into the same stream as the process output on purpose: "exited with
    /// code 1" and "restarting in 20s" belong next to the output that preceded
    /// them, not in a separate place the operator has to correlate by timestamp.
    async fn note(&self, message: impl Into<String>) {
        self.logs.lock().await.push(Stream::Stderr, format!("[supervisor] {}", message.into()));
    }
}

/// One installed service: its definition, its live state, and its task.
#[derive(Debug)]
struct Handle {
    spec: ServiceSpec,
    shared: Arc<Shared>,
    commands: mpsc::UnboundedSender<Command>,
}

/// Runs and watches every installed service.
///
/// Cheap to clone: all state is shared, so the admin API and the daemon hold the
/// same supervisor rather than coordinating two.
#[derive(Debug, Clone)]
pub struct Supervisor {
    base_dir: PathBuf,
    services: Arc<Mutex<BTreeMap<String, Handle>>>,
}

impl Supervisor {
    /// A supervisor whose services resolve relative paths against `base_dir`.
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self { base_dir: base_dir.into(), services: Arc::new(Mutex::new(BTreeMap::new())) }
    }

    /// Installs every service in a catalogue, starting the automatic ones.
    pub async fn load(&self, catalog: &ServiceCatalog) {
        for spec in &catalog.services {
            self.install(spec.clone()).await;
        }
    }

    /// Installs a service, or replaces an existing one with the same name.
    ///
    /// Replacing stops the old process first: the new definition may point at a
    /// different program or port, and leaving the old one running would mean the
    /// console shows the new definition while the machine runs the old one.
    pub async fn install(&self, spec: ServiceSpec) {
        let name = spec.name.clone();
        self.remove(&name).await;

        let initial = if spec.start_mode == StartMode::Disabled {
            ServiceState::Disabled
        } else {
            ServiceState::Stopped
        };

        let shared = Arc::new(Shared::new(initial));
        let (commands, receiver) = mpsc::unbounded_channel();

        let task = ServiceTask {
            spec: spec.clone(),
            shared: Arc::clone(&shared),
            base_dir: self.base_dir.clone(),
        };
        let starts_now = spec.starts_automatically();
        tokio::spawn(task.run(receiver));

        self.services
            .lock()
            .await
            .insert(name.clone(), Handle { spec, shared, commands });

        if starts_now {
            self.start(&name).await;
        }
    }

    /// Stops and forgets a service. Returns whether it was installed.
    pub async fn remove(&self, name: &str) -> bool {
        let handle = self.services.lock().await.remove(name);
        match handle {
            Some(handle) => {
                let _ = handle.commands.send(Command::Shutdown);
                true
            }
            None => false,
        }
    }

    /// Asks a service to start. Returns whether it is installed.
    pub async fn start(&self, name: &str) -> bool {
        self.send(name, Command::Start).await
    }

    /// Asks a service to stop. Returns whether it is installed.
    pub async fn stop(&self, name: &str) -> bool {
        self.send(name, Command::Stop).await
    }

    /// Asks a service to stop and start again. Returns whether it is installed.
    pub async fn restart(&self, name: &str) -> bool {
        self.send(name, Command::Restart).await
    }

    async fn send(&self, name: &str, command: Command) -> bool {
        match self.services.lock().await.get(name) {
            Some(handle) => handle.commands.send(command).is_ok(),
            None => false,
        }
    }

    /// The definition of one installed service.
    pub async fn spec(&self, name: &str) -> Option<ServiceSpec> {
        self.services.lock().await.get(name).map(|h| h.spec.clone())
    }

    /// The current state of one service.
    pub async fn status(&self, name: &str) -> Option<ServiceStatus> {
        let services = self.services.lock().await;
        let handle = services.get(name)?;
        Some(status_of(handle).await)
    }

    /// The current state of every installed service, ordered by name.
    pub async fn statuses(&self) -> Vec<ServiceStatus> {
        let services = self.services.lock().await;
        let mut out = Vec::with_capacity(services.len());
        for handle in services.values() {
            out.push(status_of(handle).await);
        }
        out
    }

    /// Captured output for one service, from sequence `from` onwards.
    pub async fn logs(&self, name: &str, from: u64, limit: usize) -> Option<LogSlice> {
        let services = self.services.lock().await;
        let handle = services.get(name)?;
        Some(handle.shared.logs.lock().await.since(from, limit))
    }

    /// Records a line in a service's captured output. Returns whether it exists.
    ///
    /// For things that happen *to* a service without being printed *by* it — a
    /// deployment pulling new code, a watch that could not reach its remote. They
    /// belong in the same stream as the process output and the supervisor's own
    /// commentary, because "pulled 4f3a1c9, restarting" is only meaningful next to
    /// the output that follows it; a separate place to look is a place where the
    /// operator has to correlate two logs by timestamp to learn one fact.
    ///
    /// The line is recorded exactly as given, so the caller says who it is from —
    /// the supervisor's own notes are tagged `[supervisor]`, a deployment's `[git]`.
    pub async fn note(&self, name: &str, line: impl Into<String>) -> bool {
        match self.services.lock().await.get(name) {
            Some(handle) => {
                handle.shared.logs.lock().await.push(Stream::Stderr, line.into());
                true
            }
            None => false,
        }
    }

    /// Stops every service and forgets them all.
    ///
    /// Called on daemon shutdown so children stop the way their specs ask,
    /// rather than being orphaned or killed by process teardown.
    pub async fn shutdown(&self) {
        let taken = std::mem::take(&mut *self.services.lock().await);
        let handles: Vec<Handle> = taken.into_values().collect();
        for handle in &handles {
            let _ = handle.commands.send(Command::Shutdown);
        }
        // Give each task the chance to run its stop ladder before the runtime
        // goes away underneath it.
        for handle in &handles {
            let deadline = Duration::from_secs(handle.spec.stop_timeout_secs.max(1) + 2);
            let _ = tokio::time::timeout(deadline, async {
                while !handle.commands.is_closed() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await;
        }
    }
}

/// Builds the status of one service, computing live uptime as it goes.
async fn status_of(handle: &Handle) -> ServiceStatus {
    ServiceStatus {
        name: handle.spec.name.clone(),
        display_name: handle.spec.label().to_owned(),
        description: handle.spec.description.clone(),
        state: handle.shared.current_state().await,
        start_mode: handle.spec.start_mode,
        total_restarts: handle.shared.total_restarts.load(Ordering::Relaxed),
        log_seq: handle.shared.logs.lock().await.next_seq(),
    }
}

/// The per-service task: owns the child process and reacts to commands.
struct ServiceTask {
    spec: ServiceSpec,
    shared: Arc<Shared>,
    base_dir: PathBuf,
}

/// Where a service currently is, from its own task's point of view.
enum Phase {
    /// No process, and none wanted until asked.
    Idle,
    /// No process, waiting out a delay before trying again.
    Backoff(Instant),
    /// A process is running.
    Live(Box<Running>),
}

impl ServiceTask {
    async fn run(mut self, mut commands: mpsc::UnboundedReceiver<Command>) {
        let (capture, mut captured) = mpsc::unbounded_channel::<Captured>();

        // Drain captured output into the ring on its own task, so a service
        // writing faster than anyone reads cannot block its own supervision.
        let sink = Arc::clone(&self.shared);
        tokio::spawn(async move {
            while let Some(line) = captured.recv().await {
                sink.logs.lock().await.push(line.stream, line.text);
            }
        });

        let mut counter = FailureCounter::default();
        let mut phase = Phase::Idle;

        loop {
            match phase {
                Phase::Idle => match commands.recv().await {
                    Some(Command::Start) | Some(Command::Restart) => {
                        counter.reset();
                        phase = self.spawn(&capture).await;
                    }
                    Some(Command::Stop) => phase = Phase::Idle,
                    Some(Command::Shutdown) | None => return,
                },

                Phase::Backoff(until) => {
                    let wait = until.saturating_duration_since(Instant::now());
                    tokio::select! {
                        _ = tokio::time::sleep(wait) => {
                            phase = self.spawn(&capture).await;
                        }
                        command = commands.recv() => match command {
                            Some(Command::Start) | Some(Command::Restart) => {
                                counter.reset();
                                phase = self.spawn(&capture).await;
                            }
                            Some(Command::Stop) => {
                                self.shared.note("restart cancelled").await;
                                self.shared.set(ServiceState::Stopped).await;
                                phase = Phase::Idle;
                            }
                            Some(Command::Shutdown) | None => return,
                        },
                    }
                }

                Phase::Live(mut running) => {
                    tokio::select! {
                        exited = running.child.wait() => {
                            let uptime = running.started.elapsed();
                            let status = exited.ok();
                            phase = self.handle_exit(status, uptime, &mut counter).await;
                        }
                        command = commands.recv() => match command {
                            Some(Command::Stop) => {
                                phase = self.stop_running(*running).await;
                            }
                            Some(Command::Restart) => {
                                self.stop_running(*running).await;
                                counter.reset();
                                phase = self.spawn(&capture).await;
                            }
                            Some(Command::Start) => {
                                // Already up. Starting again would either be a
                                // no-op or a second copy fighting for the port.
                                phase = Phase::Live(running);
                            }
                            Some(Command::Shutdown) | None => {
                                self.stop_running(*running).await;
                                return;
                            }
                        },
                    }
                }
            }
        }
    }

    /// Starts the process, reporting whichever state resulted.
    async fn spawn(&mut self, capture: &mpsc::UnboundedSender<Captured>) -> Phase {
        if self.spec.start_mode == StartMode::Disabled {
            self.shared.set(ServiceState::Disabled).await;
            return Phase::Idle;
        }

        self.shared.set(ServiceState::Starting).await;

        match child::spawn(&self.spec, &self.base_dir, capture.clone()) {
            Ok(running) => {
                self.shared.note(format!("started, pid {}", running.pid)).await;
                self.shared
                    .set(ServiceState::Running { pid: running.pid, uptime_secs: 0 })
                    .await;
                // After `set`, which clears the start time for anything not live.
                self.shared.mark_started(running.started).await;
                Phase::Live(Box::new(running))
            }
            Err(error) => {
                // A bad path or a missing execute bit will not fix itself, so
                // this does not enter the restart cycle — it would burn the
                // budget rediscovering the same thing and bury the real message.
                let reason = error.to_string();
                self.shared.note(&reason).await;
                self.shared.set(ServiceState::Unstartable { reason }).await;
                Phase::Idle
            }
        }
    }

    /// Runs the stop ladder and reports the service stopped.
    async fn stop_running(&self, mut running: Running) -> Phase {
        self.shared.set(ServiceState::Stopping).await;
        let outcome = child::stop(&mut running, &self.spec, &self.base_dir).await;
        self.shared.note(outcome.to_string()).await;
        self.shared.set(ServiceState::Stopped).await;
        Phase::Idle
    }

    /// Decides what to do about a process that exited on its own.
    async fn handle_exit(
        &self,
        status: Option<std::process::ExitStatus>,
        uptime: Duration,
        counter: &mut FailureCounter,
    ) -> Phase {
        let exit = status.map(Exit::of).unwrap_or(Exit::Failed);
        let code = status.and_then(|s| s.code());

        counter.note_uptime(
            uptime,
            policy::healthy_window(
                Duration::from_secs(self.spec.restart_delay_secs),
                self.spec.max_restarts,
            ),
        );

        let described = match code {
            Some(code) => format!("exited with code {code}"),
            None => "was killed".to_owned(),
        };
        self.shared.note(format!("{described} after {}s", uptime.as_secs())).await;

        let outcome = policy::decide(
            self.spec.restart,
            exit,
            counter.consecutive(),
            self.spec.max_restarts,
            Duration::from_secs(self.spec.restart_delay_secs.max(1)),
        );

        match outcome {
            Outcome::Stay => {
                self.shared.set(ServiceState::Exited { code }).await;
                Phase::Idle
            }
            Outcome::GaveUp => {
                let attempts = counter.consecutive();
                self.shared
                    .note(format!(
                        "giving up after {attempts} consecutive restarts — start it again \
                         once the cause is fixed"
                    ))
                    .await;
                self.shared
                    .set(ServiceState::GaveUp { attempts, reason: described })
                    .await;
                Phase::Idle
            }
            Outcome::RestartAfter(delay) => {
                counter.record_restart();
                self.shared.total_restarts.fetch_add(1, Ordering::Relaxed);
                self.shared.note(format!("restarting in {}s", delay.as_secs())).await;
                self.shared
                    .set(ServiceState::Backoff {
                        retry_in_secs: delay.as_secs(),
                        attempt: counter.consecutive(),
                    })
                    .await;
                Phase::Backoff(Instant::now() + delay)
            }
        }
    }
}

/// A shell invocation that runs `script`, spelled for the host platform.
///
/// Exposed for tests and for the console's "run a one-off command" affordance.
/// Services themselves take a program and arguments rather than a command line,
/// so nothing in normal operation depends on a shell being present.
pub fn shell_command(script: &str) -> (PathBuf, Vec<String>) {
    if cfg!(windows) {
        (PathBuf::from("cmd"), vec!["/C".to_owned(), script.to_owned()])
    } else {
        (PathBuf::from("/bin/sh"), vec!["-c".to_owned(), script.to_owned()])
    }
}

/// Builds a service that runs a shell script, for tests and quick one-offs.
pub fn scripted_service(name: &str, script: &str) -> ServiceSpec {
    let (program, args) = shell_command(script);
    let mut spec = ServiceSpec::new(name, program);
    spec.args = args;
    spec
}

/// Waits for a service to reach a state the predicate accepts.
///
/// Returns the state it settled on, or `None` if it never did within `timeout`.
/// Supervision is asynchronous by nature — a caller that wants to observe an
/// outcome has to wait for it, and polling by hand in every test invites the
/// flakiness this avoids.
pub async fn await_state(
    supervisor: &Supervisor,
    name: &str,
    timeout: Duration,
    accept: impl Fn(&ServiceState) -> bool,
) -> Option<ServiceState> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = supervisor.status(name).await
            && accept(&status.state)
        {
            return Some(status.state);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    None
}

impl Supervisor {
    /// The directory relative paths in service definitions resolve against.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}
