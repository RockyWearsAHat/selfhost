//! Bringing what this box is actually doing back to what it is declared to do,
//! continuously, and writing down every time it had to.
//!
//! # The requirement, and the decision it forced
//!
//! The operator's requirement is that all parts of the service come up together
//! so the deployment is never in a broken state, and that if it is, it repairs
//! itself. There are two ways to build that and they are not equivalent:
//!
//! 1. **Start together.** Make the set unstartable in halves — one unit, one
//!    boot, one restart.
//! 2. **Converge together.** Keep comparing what is actually being served
//!    against what the config declares, and repair the difference for as long as
//!    the box is up.
//!
//! **This module chooses convergence, and the reason is the incident itself.**
//! `selfhost-lan-dns` had been started correctly. It came up at boot with
//! everything else, served DNS perfectly, and died seventy-two hours later
//! because Task Scheduler's default `ExecutionTimeLimit` killed it. A
//! start-together design protects exactly one instant — the boot — and this
//! failure happened three days after that instant, with the boot having been a
//! complete success. Nothing about starting as a unit would have caught it.
//!
//! The second reason is that the set *cannot* be reduced to one unit today, and
//! saying otherwise in code would be a lie the next person builds on:
//!
//! - `selfhost-lan-dns` runs `selfhost lan-dns --lan-ip <ip>`, which serves DNS
//!   by synthesising a zone per registrable domain the config claims. The
//!   daemon's own `:53` arm serves only zones an explicit `[dns]` section names,
//!   and the production box has no `[dns]` section — so folding DNS into the
//!   daemon is real work with a real behaviour change behind it, which
//!   `service_install.rs` already refuses to pretend has happened.
//! - `selfhost-vpn` runs a Python server that is not this binary at all, and is
//!   a documented trust-anchor exception (`docs/VPN.md`). It will never be
//!   in-process.
//!
//! # So the shape is a hybrid, and the boundary is stated
//!
//! - **In-process components start together as a unit.** The proxy's two
//!   listeners, the control API, mail, the supervised children and the DNS arm
//!   all live in one `select!` in [`crate::serve_everything`]. Any of them
//!   returning ends the process, and the service manager — via the keep-alive
//!   wrapper on Windows, `KeepAlive` on launchd, `Restart=` on systemd — brings
//!   the whole set back. That is genuine start-together and it already existed.
//! - **Out-of-process components are converged.** This loop probes them
//!   functionally ([`crate::health`]), restarts the ones that are registered
//!   separately, and escalates the ones it cannot fix.
//! - **This loop does not restart the process it runs in.** An in-process
//!   component that fails its probe is recorded and escalated, never
//!   self-restarted. A supervisor that kills its own process on the strength of
//!   its own measurement is indistinguishable from a crash loop, and there is
//!   already a correct path for that case: if a listener genuinely stops, its
//!   arm returns and the daemon exits, which is the restart. Adding a second,
//!   opinion-driven path to the same outcome would mean two things that can
//!   restart the box and no single place to read why it happened.
//!
//! # Bounded, and loud when the bound is spent
//!
//! [`decide`] is a pure function and the whole escalation policy lives in it. A
//! component gets [`MAX_ATTEMPTS`] repairs; after that the loop stops acting and
//! records an escalation, which `selfhost doctor` reads back and reports as a
//! failure. A service silently restarted four hundred times is a worse outcome
//! than one that stopped and said so, because the first is an outage nobody can
//! see and the second is an outage with a cause attached.
//!
//! The counter is **not** reset by a successful repair. It is reset by
//! [`selfhost_supervisor::policy::FailureCounter::note_uptime`] once the
//! component has been serving continuously for [`HEALTHY_WINDOW`] — the same
//! rule, and the same code, the process supervisor uses. Resetting on a
//! successful repair is what turns "restart it when it breaks" into "restart it
//! every minute forever", because each restart looks like a success and the
//! budget never runs down.
//!
//! # Every repair is written down
//!
//! [`Ledger`] appends one line per *transition* — a fault appearing, a repair
//! attempted, a repair working or not, an escalation, a recovery — to
//! `<data_dir>/repair.log`. Not one line per pass: a loop that logged every
//! sixty seconds would produce a file nobody reads, which is the same as no
//! record. An unrecorded self-repair is indistinguishable from the bug never
//! having happened, and a deployment that quietly fixes itself teaches its
//! operator that it never breaks.

use crate::health::{self, Component, Probe, Serving};
use crate::service_install;
use selfhost_config::Config;
use selfhost_identity::audit::escape_field;
use selfhost_supervisor::policy::{FailureCounter, backoff};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// How many repairs one component gets before the loop stops acting and says so.
///
/// Three, matching the `RestartOnFailure` count every one of this project's
/// service registrations already uses. A component that has ignored three
/// restarts is not going to answer the fourth, and the useful thing at that
/// point is a record with a cause in it rather than more restarts.
pub const MAX_ATTEMPTS: u32 = 3;

/// How long a component must serve *continuously* before its failure budget is
/// refilled.
///
/// Five minutes, so a component that flaps every minute accumulates towards the
/// bound instead of clearing it on every cycle. See the module documentation for
/// why a successful repair deliberately does not reset the counter.
pub const HEALTHY_WINDOW: Duration = Duration::from_secs(300);

/// How long between convergence passes.
///
/// A minute. The failure this exists to catch left DNS dead for days, so the
/// difference between noticing in one minute and five is not what matters; what
/// matters is that the cost of a pass — four loopback round trips — stays far
/// below anything an operator would notice.
pub const PASS_INTERVAL: Duration = Duration::from_secs(60);

/// The first pause between acting on a component and re-probing it.
///
/// Doubled per attempt by [`selfhost_supervisor::policy::backoff`], the same
/// curve the process supervisor uses, so a component that needs a moment to bind
/// its socket is not declared unrepaired before it has had one.
const SETTLE_BASE: Duration = Duration::from_secs(5);

/// How often the installed service registrations are checked for drift.
///
/// Six hours. This is the check that would have caught the original outage
/// *months* before it bit: the task's `ExecutionTimeLimit` was wrong from the
/// day it was created, and nothing ever looked. Slow, because a scheduled task's
/// settings change only when a person changes them, and each check spawns the
/// platform's own query tool.
pub const DRIFT_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

/// The file every repair is recorded in, inside the data directory.
pub const LEDGER_FILENAME: &str = "repair.log";

/// The format marker every ledger line begins with.
///
/// Present for the reason `selfhost_identity::audit`'s is: so a reader can tell
/// which format it is looking at, and so the day the fields change there is
/// somewhere to say so rather than a silent reinterpretation of old lines.
pub const LEDGER_FORMAT: &str = "selfhost-repair/1";

/// What the loop should do about a component this pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Response {
    /// It is serving. Nothing to do.
    Rest,
    /// Repair it, wait `settle`, and probe it again.
    Repair {
        /// Which attempt this is, counting from one, for the record.
        attempt: u32,
        /// How long to wait after acting before believing the answer.
        settle: Duration,
    },
    /// The budget is spent. Stop acting and record it loudly.
    Escalate {
        /// How many repairs were attempted before giving up.
        after: u32,
    },
    /// Already escalated, and still not serving. Say nothing further.
    ///
    /// Distinct from [`Response::Escalate`] so the escalation is recorded
    /// exactly once rather than once a minute for as long as the fault lasts —
    /// a log that repeats itself is one nobody reads.
    Silent,
}

/// Decides what to do about one component, given how many repairs it has already
/// had.
///
/// Pure and total, because this is the decision that is easy to get subtly wrong
/// and impossible to notice: a bound that is off by one restarts forever, and a
/// bound that triggers early gives up on a component that would have come back.
/// It is tested directly rather than through the loop, exactly as
/// [`selfhost_supervisor::policy::decide`] is.
pub fn decide(fault: bool, consecutive: u32, escalated: bool) -> Response {
    if !fault {
        return Response::Rest;
    }
    if escalated {
        return Response::Silent;
    }
    if consecutive >= MAX_ATTEMPTS {
        return Response::Escalate { after: consecutive };
    }
    Response::Repair { attempt: consecutive + 1, settle: backoff(SETTLE_BASE, consecutive) }
}

/// What one component's history looks like to the loop.
#[derive(Debug, Default)]
struct Watch {
    failures: FailureCounter,
    /// When it was last observed serving without interruption since.
    serving_since: Option<Instant>,
    /// Whether the budget has been spent and the escalation already recorded.
    escalated: bool,
    /// Whether the last observation was a fault, so a recovery can be noticed.
    faulted: bool,
}

/// The loop's memory: one [`Watch`] per component.
///
/// Separated from the loop that owns the sockets so the whole escalation
/// behaviour — including the case that matters, a component that never comes
/// back — is testable without a network, a clock, or a service manager.
#[derive(Debug, Default)]
pub struct Supervision {
    watches: BTreeMap<Component, Watch>,
}

/// What an observation turned out to mean, for the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observed {
    /// What to do about it.
    pub response: Response,
    /// Whether this observation is the moment a fault appeared, so the fault is
    /// recorded once rather than on every pass.
    pub newly_faulted: bool,
    /// Whether this observation is the moment it started working again.
    pub recovered: bool,
}

impl Supervision {
    /// A fresh supervision state with no history.
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds one probe result into a component's history and says what follows.
    ///
    /// `now` is passed in rather than read here so a test can advance time
    /// without sleeping — the healthy-window rule is the one piece of this whose
    /// bug would take five minutes of wall clock to observe.
    pub fn observe(&mut self, component: Component, fault: bool, now: Instant) -> Observed {
        let watch = self.watches.entry(component).or_default();

        if !fault {
            let recovered = watch.faulted;
            watch.faulted = false;
            let since = *watch.serving_since.get_or_insert(now);
            // The budget refills only after a real stretch of service. A repair
            // that appeared to work is not evidence — see the module docs.
            watch.failures.note_uptime(now.saturating_duration_since(since), HEALTHY_WINDOW);
            if watch.failures.consecutive() == 0 {
                watch.escalated = false;
            }
            return Observed { response: Response::Rest, newly_faulted: false, recovered };
        }

        let newly_faulted = !watch.faulted;
        watch.faulted = true;
        watch.serving_since = None;

        let response = decide(true, watch.failures.consecutive(), watch.escalated);
        match response {
            Response::Repair { .. } => watch.failures.record_restart(),
            Response::Escalate { .. } => watch.escalated = true,
            Response::Rest | Response::Silent => {}
        }
        Observed { response, newly_faulted, recovered: false }
    }
}

/// What happened, in the words the ledger records it in.
///
/// A closed set rather than free text so a reader — a person or the console —
/// can group lines without parsing English, and so a new kind of event has to be
/// named here rather than smuggled into a detail string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A component that was serving stopped serving.
    Fault,
    /// A repair was carried out.
    Repaired,
    /// A repair was carried out and the component still is not serving.
    StillFailing,
    /// There was nothing this loop could do, and it stopped trying.
    Escalated,
    /// It is serving again.
    Recovered,
    /// An installed service registration did not match what it was meant to be.
    Drift,
    /// A registration's settings were rewritten to what they were meant to be.
    DriftRepaired,
}

impl Event {
    /// The word this event is written as.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fault => "fault",
            Self::Repaired => "repaired",
            Self::StillFailing => "still-failing",
            Self::Escalated => "escalated",
            Self::Recovered => "recovered",
            Self::Drift => "drift",
            Self::DriftRepaired => "drift-repaired",
        }
    }

}

/// One line of the repair record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// When, in seconds since the Unix epoch. Wall clock, because the record
    /// outlives the process and an operator correlating an incident needs a
    /// time of day rather than an uptime.
    pub at_unix: u64,
    /// Which component.
    pub component: String,
    /// What happened.
    pub event: Event,
    /// What was actually observed or done, free text.
    pub detail: String,
}

impl Entry {
    /// A record about a probed component, stamped now.
    pub fn now(component: Component, event: Event, detail: impl Into<String>) -> Self {
        Self::about(component.label(), event, detail)
    }

    /// A record about something named that is not one of the probed components.
    ///
    /// Registration drift is recorded against the *unit* — `selfhost-lan-dns`,
    /// `selfhost-vpn` — rather than against a component, because a task whose
    /// settings are wrong is a fault of that registration and not of whatever it
    /// happens to serve. Filing a drifted VPN task under "dns" would put the
    /// wrong name in front of whoever reads the ledger during an incident.
    pub fn about(component: &str, event: Event, detail: impl Into<String>) -> Self {
        Self {
            at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|since| since.as_secs())
                .unwrap_or(0),
            component: component.to_owned(),
            event,
            detail: detail.into(),
        }
    }

    /// The entry as exactly one line, without its terminating newline.
    ///
    /// The escaping is [`selfhost_identity::audit::escape_field`]'s and this
    /// module adds none of its own: that function states the small set of bytes
    /// a field may contain and percent-encodes every byte outside it, so a
    /// detail carrying a newline — a service manager's error message, say —
    /// cannot turn one repair into two records. One opinion about escaping, in
    /// the crate that already had to get it right.
    pub fn line(&self) -> String {
        format!(
            "{LEDGER_FORMAT} at={} component={} event={} detail={}",
            self.at_unix,
            escape_field(&self.component),
            self.event.as_str(),
            escape_field(&self.detail),
        )
    }

    /// Reads a line back, or `None` if it is not one of ours.
    ///
    /// Tolerant of an unknown event word and of extra fields, so a ledger
    /// written by a newer build is still readable by an older one rather than
    /// making `doctor` fail on a log file.
    pub fn parse(line: &str) -> Option<Self> {
        let rest = line.strip_prefix(LEDGER_FORMAT)?;
        let mut at_unix = 0;
        let mut component = String::new();
        let mut event = None;
        let mut detail = String::new();
        for field in rest.split_whitespace() {
            let (name, value) = field.split_once('=')?;
            match name {
                "at" => at_unix = value.parse().ok()?,
                "component" => component = unescape_field(value),
                "event" => {
                    event = [
                        Event::Fault,
                        Event::Repaired,
                        Event::StillFailing,
                        Event::Escalated,
                        Event::Recovered,
                        Event::Drift,
                        Event::DriftRepaired,
                    ]
                    .into_iter()
                    .find(|candidate| candidate.as_str() == value);
                }
                "detail" => detail = unescape_field(value),
                _ => {}
            }
        }
        Some(Self { at_unix, component, event: event?, detail })
    }
}

/// Reverses [`escape_field`]'s percent-encoding.
///
/// Decoding is the reader's problem by design — nothing ever writes an
/// unescaped byte — so a caller that forgets this sees mangled text rather than
/// being fooled by it. A malformed escape is left as written rather than
/// guessed at.
fn unescape_field(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let hex = bytes.get(index + 1..index + 3);
        match (byte, hex.and_then(|hex| u8::from_str_radix(&String::from_utf8_lossy(hex), 16).ok()))
        {
            (b'%', Some(decoded)) => {
                out.push(decoded);
                index += 3;
            }
            _ => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The append-only record of what supervision did.
///
/// Holds a path rather than a handle, for [`selfhost_identity::audit::AuditLog`]'s
/// reason: an `O_APPEND` write of one short line lands whole, and a handle held
/// open for the life of the daemon is a handle that outlives a log rotation.
#[derive(Debug, Clone)]
pub struct Ledger {
    path: PathBuf,
}

impl Ledger {
    /// The ledger inside a deployment's data directory.
    pub fn in_dir(data_dir: &Path) -> Self {
        Self { path: data_dir.join(LEDGER_FILENAME) }
    }

    /// Where it is, so an operator can be told rather than made to guess.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one entry.
    ///
    /// A failed write is returned rather than swallowed, and the daemon prints
    /// it — but it never stops a repair from happening. A box whose disk has
    /// filled should still bring its DNS back; a self-healing system that
    /// refused to heal because it could not write about healing would be an
    /// outage caused by its own diagnostics.
    pub fn append(&self, entry: &Entry) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(file, "{}", entry.line())
    }

    /// Every entry in the file, oldest first.
    ///
    /// A missing file is an empty ledger, not an error: a deployment that has
    /// never had to repair anything is the good case.
    pub fn entries(&self) -> Vec<Entry> {
        std::fs::read_to_string(&self.path)
            .unwrap_or_default()
            .lines()
            .filter_map(Entry::parse)
            .collect()
    }

    /// The components that are currently given up on, with the escalation that
    /// said so.
    ///
    /// "Currently" is what makes this useful rather than historical: an
    /// escalation followed by a recovery for the same component is a fault that
    /// was dealt with, and reporting it forever would make the report a list of
    /// everything that has ever gone wrong.
    pub fn outstanding(&self) -> Vec<Entry> {
        let mut latest: BTreeMap<String, Entry> = BTreeMap::new();
        for entry in self.entries() {
            match entry.event {
                Event::Escalated => {
                    latest.insert(entry.component.clone(), entry);
                }
                Event::Recovered | Event::Repaired | Event::DriftRepaired => {
                    latest.remove(&entry.component);
                }
                _ => {}
            }
        }
        latest.into_values().collect()
    }
}

/// Converges the deployment towards its declared state, for as long as the
/// daemon runs.
///
/// Never returns. Occupies one arm of the daemon's `select!` in the same way the
/// firewall drift watch does, which is deliberate: this loop must not be a
/// separate registration, or it would be one more thing that can die quietly and
/// leave everything looking fine — the exact failure it exists to catch.
pub async fn converge_forever(config: Config, project_dir: PathBuf, data_dir: PathBuf) -> ! {
    let mut loop_ = ConvergeLoop::new(&data_dir);
    loop {
        // The first pass waits, so the components the daemon has just started
        // have bound their sockets before anything measures them.
        tokio::time::sleep(PASS_INTERVAL).await;
        loop_.pass(&config, &project_dir, DRIFT_INTERVAL).await;
    }
}

/// The convergence loop's state, held across passes.
///
/// Extracted from [`converge_forever`] so that the same passes can be driven from
/// the foreground by `selfhost converge`, against the same registrations, with the
/// same ledger. That is not a convenience: the whole of this loop is Windows
/// service-manager code that had never executed anywhere, and a supervisor whose
/// only entry point is "run the production daemon for an hour" is a supervisor
/// that gets proved by argument rather than by running it. One implementation,
/// two drivers — the daemon's, which never stops, and the operator's, which is
/// bounded and prints what it is doing.
#[derive(Debug)]
pub struct ConvergeLoop {
    /// Where transitions are written.
    ledger: Ledger,
    /// Per-component failure budgets and the last state each was seen in.
    supervision: Supervision,
    /// When the registrations are next compared against what they were installed
    /// as. Immediately, on the first pass, so a drift that is already there is
    /// reported by the first thing that looks.
    next_drift_check: Instant,
}

impl ConvergeLoop {
    /// A loop with an empty budget table, writing to `<data_dir>/repair.log`.
    pub fn new(data_dir: &Path) -> Self {
        Self {
            ledger: Ledger::in_dir(data_dir),
            supervision: Supervision::new(),
            next_drift_check: Instant::now(),
        }
    }

    /// One pass: check registration drift if it is due, then probe every
    /// component and act on what came back.
    ///
    /// Nothing is slept here — the caller owns the pacing, because the daemon
    /// sleeps *before* its first pass so that components it has just started have
    /// bound their sockets, and a foreground run started by a person wants its
    /// first pass now.
    pub async fn pass(&mut self, config: &Config, project_dir: &Path, drift_interval: Duration) {
        if Instant::now() >= self.next_drift_check {
            check_registration_drift(&self.ledger).await;
            self.next_drift_check = Instant::now() + drift_interval;
        }

        for probe in health::probe_all(config, project_dir).await {
            handle(&mut self.supervision, &self.ledger, config, project_dir, probe).await;
        }
    }
}

/// Acts on one probe result: record what changed, repair what can be repaired,
/// and verify with the same probe that found the fault.
async fn handle(
    supervision: &mut Supervision,
    ledger: &Ledger,
    config: &Config,
    project_dir: &Path,
    probe: Probe,
) {
    let component = probe.component;
    let observed = supervision.observe(component, probe.serving.is_fault(), Instant::now());

    if observed.recovered {
        record(ledger, Entry::now(component, Event::Recovered, probe.detail.clone()));
    }
    if observed.newly_faulted {
        record(ledger, Entry::now(component, Event::Fault, probe.detail.clone()));
    }

    match observed.response {
        Response::Rest | Response::Silent => {}
        Response::Escalate { after } => record(
            ledger,
            Entry::now(
                component,
                Event::Escalated,
                format!(
                    "{after} repair(s) did not bring it back, so supervision has stopped trying \
                     and is saying so instead; last observation: {}",
                    probe.detail
                ),
            ),
        ),
        Response::Repair { attempt, settle } => {
            let action = repair_for(component, config);
            match action {
                Repair::Unavailable { because } => {
                    // Not repairable is not the same as not recorded. The
                    // attempt is spent either way, so the bound still runs down
                    // and the component still escalates — with a reason.
                    record(
                        ledger,
                        Entry::now(
                            component,
                            Event::StillFailing,
                            format!("attempt {attempt} of {MAX_ATTEMPTS}: {because}"),
                        ),
                    );
                }
                Repair::Restart { what, steps } => {
                    let carried = service_install::run_steps(&steps);
                    tokio::time::sleep(settle).await;
                    let after = health::probe(component, config, project_dir).await;
                    let outcome = match (&carried, after.serving) {
                        (Err(error), _) => Entry::now(
                            component,
                            Event::StillFailing,
                            format!("attempt {attempt} of {MAX_ATTEMPTS}: restarting {what} failed: {error}"),
                        ),
                        (Ok(()), Serving::Yes) => Entry::now(
                            component,
                            Event::Repaired,
                            format!(
                                "attempt {attempt} of {MAX_ATTEMPTS}: restarted {what}; it is \
                                 serving again ({})",
                                after.detail
                            ),
                        ),
                        (Ok(()), _) => Entry::now(
                            component,
                            Event::StillFailing,
                            format!(
                                "attempt {attempt} of {MAX_ATTEMPTS}: restarted {what} and it is \
                                 still not serving ({})",
                                after.detail
                            ),
                        ),
                    };
                    record(ledger, outcome);
                }
            }
        }
    }
}

/// Writes an entry, complaining on stderr if it cannot.
///
/// Never returns an error to its caller: see [`Ledger::append`] for why a
/// failure to record must not stop the repair it was about to describe.
fn record(ledger: &Ledger, entry: Entry) {
    // Also to stdout, because on the box this deploys to the daemon's stdout is
    // appended to `data/selfhost-daemon.log` by the keep-alive wrapper — so a
    // repair appears both in the ledger a tool reads and in the log a person
    // tails during an incident.
    println!("converge: {} {} — {}", entry.component, entry.event.as_str(), entry.detail);
    if let Err(error) = ledger.append(&entry) {
        eprintln!("warning: could not write {}: {error}", ledger.path().display());
    }
}

/// What can be done about a component that is not serving.
#[derive(Debug)]
pub enum Repair {
    /// Restart a separately-registered service.
    Restart {
        /// What is being restarted, for the record.
        what: String,
        /// The service manager commands that do it.
        steps: Vec<service_install::Step>,
    },
    /// Nothing this loop may do, and why.
    Unavailable {
        /// The reason, written for the operator who reads it in the ledger.
        because: String,
    },
}

/// Chooses the repair for a component, on this platform, for this config.
///
/// The one interesting case is DNS, and it is interesting because the answer is
/// not a platform constant. DNS is served by a separate registration only where
/// there is one: on Windows, where `selfhost-lan-dns` runs the synthesising path
/// because the box has no `[dns]` section. A deployment that *does* write
/// `[dns]` serves DNS from the daemon's own arm, in-process, and restarting a
/// task in that case would either do nothing or start a second server to fight
/// over `:53`. So the question is asked of the machine — does that registration
/// exist — rather than assumed from `cfg!`.
pub fn repair_for(component: Component, config: &Config) -> Repair {
    if component.in_process() {
        return Repair::Unavailable {
            because: format!(
                "{} runs inside this daemon's own process, which supervision does not restart \
                 from within — a listener that genuinely stopped ends the process and the \
                 service manager brings the whole deployment back together",
                component.label()
            ),
        };
    }

    match component {
        Component::Dns => {
            if config.dns.is_some() {
                return Repair::Unavailable {
                    because: "this deployment has a [dns] section, so DNS is served by the \
                              daemon's own :53 arm rather than by a separate registration"
                        .to_owned(),
                };
            }
            match service_install::separate_dns_registration() {
                Some(name) => Repair::Restart {
                    what: name.clone(),
                    steps: service_install::restart_steps(&name),
                },
                None => Repair::Unavailable {
                    because: format!(
                        "nothing is serving DNS and there is no separate registration named {} \
                         to restart — install one, or give this deployment a [dns] section so \
                         the daemon serves :53 itself",
                        service_install::LAN_DNS_TASK_NAME
                    ),
                },
            }
        }
        Component::Http | Component::Https | Component::ControlApi => {
            Repair::Unavailable { because: "handled above".to_owned() }
        }
    }
}

/// Compares every installed service registration against what it was meant to be
/// and repairs the difference.
///
/// This is the check that would have caught the original outage months before it
/// bit. The task was created with Windows' default `ExecutionTimeLimit` of
/// seventy-two hours and `RestartCount` of zero, and it was wrong from the first
/// day — but a task in the `Ready` state with a correct action looks perfect to
/// everything except a comparison against what it was supposed to say.
async fn check_registration_drift(ledger: &Ledger) {
    for audit in service_install::audit_installed(false) {
        if audit.faults.is_empty() {
            continue;
        }
        let summary = audit.faults.join("; ");
        record(
            ledger,
            Entry::about(
                &audit.label,
                Event::Drift,
                format!("does not match what it was installed as: {summary}"),
            ),
        );
        match service_install::repair_settings(&audit.label) {
            Ok(true) => record(
                ledger,
                Entry::about(
                    &audit.label,
                    Event::DriftRepaired,
                    "its settings were rewritten to what they were meant to be; what it runs is \
                     unchanged",
                ),
            ),
            Ok(false) => {}
            // Not `StillFailing`: on launchd and systemd this refusal is
            // deliberate — see `repair_settings` — and recording it as a failed
            // repair would read as something having been tried and gone wrong.
            Err(error) => {
                record(ledger, Entry::about(&audit.label, Event::Drift, format!("not repaired: {error}")))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_config::{AcmeEnvironment, Firewall, Node, Role, Server};

    /// The smallest config that parses, for the repair-choice tests.
    ///
    /// Written here rather than borrowed from another module's tests because
    /// what these assertions turn on is exactly two fields — whether `[dns]` is
    /// present, and nothing else — and a shared fixture that grew a `[dns]`
    /// section for somebody else's test would silently invert them.
    fn config() -> Config {
        Config {
            version: 1,
            server: Server {
                http_bind: "0.0.0.0:80".into(),
                https_bind: "0.0.0.0:443".into(),
                acme_email: "a@b.com".into(),
                acme: AcmeEnvironment::SelfSigned,
                data_dir: std::path::PathBuf::from("./data"),
                admin_bind: "127.0.0.1:9191".into(),
                firewall: Firewall::default(),
            },
            nodes: vec![Node { name: "home".into(), role: Role::Owner, mesh_ip: None }],
            sites: Vec::new(),
            dns: None,
            mail: None,
            self_update: None,
            shares: Vec::new(),
            desktop: None,
            mesh: None,
            vpn: Vec::new(),
        }
    }

    #[test]
    fn a_serving_component_is_left_alone() {
        assert_eq!(decide(false, 0, false), Response::Rest);
        // Even one that has been given up on: a recovery is a recovery.
        assert_eq!(decide(false, 9, true), Response::Rest);
    }

    #[test]
    fn a_fault_is_repaired_up_to_the_bound_and_then_escalated() {
        // The bound is the whole point: something that keeps failing has to
        // become a loud recorded state rather than a restart every minute for
        // the rest of the year.
        for attempt in 0..MAX_ATTEMPTS {
            assert!(
                matches!(decide(true, attempt, false), Response::Repair { .. }),
                "attempt {attempt} should still be tried"
            );
        }
        assert_eq!(decide(true, MAX_ATTEMPTS, false), Response::Escalate { after: MAX_ATTEMPTS });
        assert_eq!(decide(true, 400, false), Response::Escalate { after: 400 });
    }

    #[test]
    fn an_escalated_component_is_never_repaired_again_and_never_re_announced() {
        // Two failures rolled into one: restarting after giving up would make
        // the bound meaningless, and re-recording the escalation once a minute
        // would make the ledger unreadable.
        assert_eq!(decide(true, MAX_ATTEMPTS, true), Response::Silent);
        assert_eq!(decide(true, 0, true), Response::Silent);
    }

    #[test]
    fn the_settle_delay_grows_with_each_attempt() {
        let delays: Vec<Duration> = (0..MAX_ATTEMPTS)
            .map(|attempt| match decide(true, attempt, false) {
                Response::Repair { settle, .. } => settle,
                other => panic!("expected a repair, got {other:?}"),
            })
            .collect();
        assert_eq!(delays, vec![SETTLE_BASE, SETTLE_BASE * 2, SETTLE_BASE * 4]);
    }

    #[test]
    fn a_component_that_never_comes_back_is_repaired_exactly_three_times() {
        // The simulation the bound exists for. A hundred passes of a dead
        // component must produce three repairs, one escalation, and nothing
        // else — not a hundred restarts.
        let mut supervision = Supervision::new();
        let start = Instant::now();
        let mut repairs = 0;
        let mut escalations = 0;
        for pass in 0..100u32 {
            let now = start + PASS_INTERVAL * pass;
            match supervision.observe(Component::Dns, true, now).response {
                Response::Repair { .. } => repairs += 1,
                Response::Escalate { .. } => escalations += 1,
                Response::Silent => {}
                Response::Rest => panic!("a dead component must not be rested on"),
            }
        }
        assert_eq!(repairs, MAX_ATTEMPTS, "the repair budget is spent exactly once");
        assert_eq!(escalations, 1, "and the escalation is recorded exactly once");
    }

    #[test]
    fn a_fault_is_recorded_once_rather_than_on_every_pass() {
        let mut supervision = Supervision::new();
        let start = Instant::now();
        let first = supervision.observe(Component::Dns, true, start);
        let second = supervision.observe(Component::Dns, true, start + PASS_INTERVAL);
        assert!(first.newly_faulted, "the moment it broke is worth a line");
        assert!(!second.newly_faulted, "the fact it is still broken is not");
    }

    #[test]
    fn a_repair_that_appears_to_work_does_not_refill_the_budget() {
        // The failure this encodes: a component that breaks every minute and is
        // "successfully repaired" every minute would reset its counter on each
        // cycle and be restarted forever, which is the four-hundred-restarts
        // outcome the bound exists to prevent.
        let mut supervision = Supervision::new();
        let start = Instant::now();
        let mut repairs = 0;
        for pass in 0..40u32 {
            // Alternating: broken, then serving briefly, then broken again.
            let now = start + PASS_INTERVAL * pass;
            let fault = pass % 2 == 0;
            if let Response::Repair { .. } = supervision.observe(Component::Dns, fault, now).response
            {
                repairs += 1;
            }
        }
        assert_eq!(repairs, MAX_ATTEMPTS, "flapping must escalate, not restart forever");
    }

    #[test]
    fn the_budget_refills_only_after_a_real_stretch_of_service() {
        let mut supervision = Supervision::new();
        let start = Instant::now();
        supervision.observe(Component::Dns, true, start);
        supervision.observe(Component::Dns, true, start + PASS_INTERVAL);

        // Serving, but not for long enough to count as a recovery.
        supervision.observe(Component::Dns, false, start + PASS_INTERVAL * 2);
        supervision.observe(Component::Dns, false, start + PASS_INTERVAL * 3);
        assert!(
            matches!(
                supervision.observe(Component::Dns, true, start + PASS_INTERVAL * 4).response,
                Response::Repair { attempt: 3, .. }
            ),
            "two minutes of service must not wipe two failures"
        );

        // Past the healthy window, the history is genuinely cleared.
        let later = start + PASS_INTERVAL * 5;
        supervision.observe(Component::Dns, false, later);
        supervision.observe(Component::Dns, false, later + HEALTHY_WINDOW);
        assert!(matches!(
            supervision.observe(Component::Dns, true, later + HEALTHY_WINDOW * 2).response,
            Response::Repair { attempt: 1, .. }
        ));
    }

    #[test]
    fn an_escalated_component_that_recovers_is_supervised_again() {
        // An operator who fixes the underlying problem must not have to restart
        // the daemon to get supervision back.
        let mut supervision = Supervision::new();
        let start = Instant::now();
        for pass in 0..=MAX_ATTEMPTS {
            supervision.observe(Component::Dns, true, start + PASS_INTERVAL * pass);
        }
        assert_eq!(
            supervision.observe(Component::Dns, true, start + PASS_INTERVAL * 9).response,
            Response::Silent,
            "it has been given up on"
        );

        let base = start + PASS_INTERVAL * 10;
        let recovery = supervision.observe(Component::Dns, false, base);
        assert!(recovery.recovered, "the moment it came back is worth a line");
        supervision.observe(Component::Dns, false, base + HEALTHY_WINDOW);
        assert!(matches!(
            supervision.observe(Component::Dns, true, base + HEALTHY_WINDOW * 2).response,
            Response::Repair { attempt: 1, .. }
        ));
    }

    #[test]
    fn components_do_not_share_a_budget() {
        // One dead component must not spend another's attempts, or a box with
        // one broken part would stop repairing everything else.
        let mut supervision = Supervision::new();
        let start = Instant::now();
        for pass in 0..=MAX_ATTEMPTS {
            supervision.observe(Component::Dns, true, start + PASS_INTERVAL * pass);
        }
        assert_eq!(
            supervision.observe(Component::Dns, true, start + PASS_INTERVAL * 9).response,
            Response::Silent
        );
        assert!(matches!(
            supervision.observe(Component::Http, true, start).response,
            Response::Repair { attempt: 1, .. }
        ));
    }

    #[test]
    fn a_ledger_line_survives_a_round_trip() {
        let entry = Entry {
            at_unix: 1_785_089_368,
            component: "dns".into(),
            event: Event::Escalated,
            detail: "3 repair(s) did not bring it back".into(),
        };
        let line = entry.line();
        assert!(line.starts_with(LEDGER_FORMAT), "{line}");
        assert_eq!(Entry::parse(&line), Some(entry));
    }

    #[test]
    fn a_detail_containing_a_newline_cannot_become_two_records() {
        // A service manager's error message is arbitrary text and lands here
        // verbatim. One repair has to stay one line, or the ledger is a place
        // a failing component writes its own history.
        let entry = Entry {
            at_unix: 1,
            component: "dns".into(),
            event: Event::StillFailing,
            detail: "schtasks said:\nERROR: access denied\nselfhost-repair/1 at=0".into(),
        };
        let line = entry.line();
        assert_eq!(line.lines().count(), 1, "{line}");
        assert_eq!(Entry::parse(&line).map(|parsed| parsed.detail), Some(entry.detail));
    }

    #[test]
    fn a_line_from_another_format_is_ignored_rather_than_misread() {
        assert_eq!(Entry::parse(""), None);
        assert_eq!(Entry::parse("selfhost-audit/1 id=abc at=1"), None);
        // Ours, but with no event word this build knows.
        assert_eq!(Entry::parse("selfhost-repair/1 at=1 component=dns event=danced"), None);
    }

    #[test]
    fn an_escalation_that_was_recovered_from_is_no_longer_outstanding() {
        let directory = std::env::temp_dir().join(format!(
            "selfhost-converge-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&directory).expect("a temporary directory");
        let ledger = Ledger::in_dir(&directory);

        ledger
            .append(&Entry::now(Component::Dns, Event::Escalated, "gave up"))
            .expect("the ledger is writable");
        assert_eq!(ledger.outstanding().len(), 1, "an unresolved escalation is reported");

        ledger
            .append(&Entry::now(Component::Dns, Event::Recovered, "answering again"))
            .expect("the ledger is writable");
        assert!(
            ledger.outstanding().is_empty(),
            "a report that listed every fault ever seen would be a report nobody reads"
        );

        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn an_in_process_component_is_never_restarted_by_this_loop() {
        // The design decision, asserted: supervision that killed the process it
        // runs in would be indistinguishable from a crash loop, and the service
        // manager already covers that case.
        let config = config();
        for component in [Component::Http, Component::Https, Component::ControlApi] {
            assert!(
                matches!(repair_for(component, &config), Repair::Unavailable { .. }),
                "{} must not be restartable from inside itself",
                component.label()
            );
        }
    }

    /// A throwaway data directory for a ledger, named after the calling line so
    /// two tests in this file cannot collide.
    fn scratch(line: u32) -> PathBuf {
        let directory =
            std::env::temp_dir().join(format!("selfhost-converge-{}-{line}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("a temporary directory");
        directory
    }

    /// One ordinary website — a registrable name served over HTTP, with DNS
    /// hosted at a registrar. The shape `selfhost init` writes.
    fn ordinary_site() -> selfhost_config::Site {
        selfhost_config::Site {
            name: "hello".into(),
            domains: vec!["example.com".into()],
            static_root: Some(PathBuf::from("./sites/hello")),
            spa: false,
            app_paths: Vec::new(),
            instances: Vec::new(),
            health: selfhost_config::Health::default(),
            canonical_redirect: true,
            allowed_cidrs: Vec::new(),
            console: false,
        }
    }

    #[tokio::test]
    async fn a_deployment_that_never_declared_dns_is_never_repaired_for_not_serving_it() {
        // **The defect this whole change exists for, asserted at the loop rather
        // than at the probe** — because the probe's verdict was only half the
        // damage. A deployment with an ordinary site name and no DNS declaration
        // was read as a broken nameserver, and this loop then spent all three
        // repair attempts restarting something the deployment never asked for
        // and escalated. A supervisor that repeatedly restarts an undeclared
        // service manufactures the outage it exists to prevent.
        //
        // Two hundred passes, which is more than three hours of a running box:
        // the ledger must stay completely empty. Not "no restarts" — no lines at
        // all, because there is nothing here that is wrong.
        let mut config = config();
        config.sites = vec![ordinary_site()];
        let directory = scratch(line!());
        let ledger = Ledger::in_dir(&directory);
        let mut supervision = Supervision::new();

        let probe = health::probe(Component::Dns, &config, Path::new(".")).await;
        assert!(
            !probe.serving.is_fault(),
            "an undeclared component is not a fault: {}",
            probe.detail
        );
        for _ in 0..200 {
            handle(&mut supervision, &ledger, &config, Path::new("."), probe.clone()).await;
        }

        assert!(
            ledger.entries().is_empty(),
            "supervision must have nothing to say about a component this deployment never \
             declared, and said: {:?}",
            ledger.entries().iter().map(|entry| entry.line()).collect::<Vec<_>>()
        );
        assert!(ledger.outstanding().is_empty(), "and must never escalate one");
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[tokio::test]
    async fn dns_a_deployment_does_declare_is_still_faulted_repaired_and_escalated() {
        // The half the fix must not blind, asserted at the loop for the same
        // reason. A `[dns]` section is a promise to serve `:53`; a nameserver
        // that is silent is the original incident, and the loop must still
        // record the fault, spend its bounded attempts, and give up loudly.
        //
        // `repair_for` returns `Unavailable` here — a `[dns]` deployment serves
        // DNS in-process, and there is no separate task to restart — so what is
        // being asserted is the *bound and the record*, with no service manager
        // touched, which is exactly what makes this runnable on any machine.
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("an ephemeral loopback port");
        let silent = listener.local_addr().expect("a bound address").port();
        drop(listener);

        let mut config = config();
        config.sites = vec![ordinary_site()];
        config.dns = Some(selfhost_config::Dns {
            bind: format!("127.0.0.1:{silent}"),
            secondaries: Vec::new(),
            dynamic_ip: false,
            lan_ip: None,
            zones: Vec::new(),
        });

        let directory = scratch(line!());
        let ledger = Ledger::in_dir(&directory);
        let mut supervision = Supervision::new();

        let probe = health::probe(Component::Dns, &config, Path::new(".")).await;
        assert_eq!(probe.serving, Serving::No, "{}", probe.detail);
        for _ in 0..20 {
            handle(&mut supervision, &ledger, &config, Path::new("."), probe.clone()).await;
        }

        let count = |event: Event| {
            ledger.entries().into_iter().filter(|entry| entry.event == event).count()
        };
        assert_eq!(count(Event::Fault), 1, "the moment it broke, once");
        assert_eq!(
            count(Event::StillFailing),
            MAX_ATTEMPTS as usize,
            "the repair budget is spent, and only once"
        );
        assert_eq!(count(Event::Escalated), 1, "and the giving-up is recorded, loudly and once");
        assert_eq!(ledger.outstanding().len(), 1, "`doctor` must report this as a failure");
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn dns_served_by_the_daemon_itself_is_not_repaired_by_restarting_a_task() {
        // Restarting `selfhost-lan-dns` on a box whose daemon serves :53 would
        // start a second server to fight over the port.
        let mut config = config();
        config.dns = Some(selfhost_config::Dns {
            bind: "0.0.0.0:53".into(),
            secondaries: Vec::new(),
            dynamic_ip: false,
            lan_ip: None,
            zones: Vec::new(),
        });
        assert!(matches!(repair_for(Component::Dns, &config), Repair::Unavailable { .. }));
    }
}
