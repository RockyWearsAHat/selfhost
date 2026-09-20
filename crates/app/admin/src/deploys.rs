//! A record of every Deploy this daemon has run: one entry per repo→build→
//! publish attempt, however it was asked for.
//!
//! # Why this exists
//!
//! Before this store, a deploy's outcome lived nowhere: `deploy_now` spawned
//! [`selfhost_git::check_once_with_credential`] and threw its
//! `Result<Outcome, String>` away (`let _ = ...await;`), and self-update's
//! `watch_own_repository` only ever printed its own progress to stderr. A
//! caller that got back `202 Accepted` — the webhook relay, `selfhost repo
//! deploy`, the console's deploy button, the self-update watcher's own nudge —
//! had no way to ask afterwards whether the thing it asked for actually
//! happened, short of reading the service's live log at the right moment. A
//! build that failed silently was, from outside, indistinguishable from one
//! that never ran.
//!
//! This closes that gap with one bounded, in-process record: [`Deploys::start`]
//! is called the instant a deploy is accepted, before any work begins, and
//! [`Deploys::finish`] is called with whatever really happened, however long
//! that takes. `GET /api/deploys` and `GET /api/deploys/<id>` read this record
//! rather than infer anything from a service's log tail — a deploy that is
//! still `running` when asked about is still running, unless it has sat there
//! past [`STALLED_DEPLOY_TIMEOUT_SECS`] with nothing to show for it, in which
//! case the read itself is what corrects the record (see [`Deploys::get`]);
//! a deploy that is `failed` says exactly what step failed and why, in
//! [`Deploy::log`].
//!
//! # A different shape from [`crate::agent_store`], deliberately
//!
//! [`crate::agent_store::AgentStore`] reads its file fresh on every call
//! because its writer (`selfhost agent add|revoke`) is a different process
//! from the daemon verifying tokens. A Deploy record has no such split: the
//! only process that ever starts or finishes one is this daemon itself, in
//! the same `deploy_now`/`watch_own_repository` call that is already running.
//! So [`Deploys`] holds its entries in memory behind a [`std::sync::Mutex`],
//! the way the supervisor holds service state, and persists to disk after
//! every mutation purely so a restart does not lose the last few deploys'
//! history — never re-reading its own file to answer a query.
//!
//! # Bounded, and fails open on a write
//!
//! At most [`MAX_DEPLOYS`] entries are kept; the oldest is dropped once a new
//! one would exceed it, the same "small, hand-bounded list" reasoning
//! [`crate::agent_store::MAX_AGENTS`] documents. A persist failure is printed
//! to stderr and does not fail the caller — mirroring `converge.rs`'s
//! `Ledger::append` — because losing the *written record* of a deploy must
//! never be the reason a deploy itself is refused or rolled back.

use selfhost_json::Json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// The name of the deploy-record file inside the data directory.
pub const DEPLOY_STORE_FILENAME: &str = "console.deploys";

/// The most deploy records this store will keep. Old history is dropped, not
/// archived: this is a recent-activity record for "did my push land", not an
/// audit log — [`crate::audit_api`] is the store for anything that needs to
/// outlive a long tail of ordinary deploys.
pub const MAX_DEPLOYS: usize = 200;

/// How long a Deploy may sit at [`DeployResult::Running`] before this store
/// stops trusting that and reports it as [`DeployResult::Failed`] instead.
///
/// Twenty minutes is generously above the slowest step this daemon ever
/// blocks on (`cargo build --release`, still under ten on this box) so a
/// deploy that is genuinely still working is never reaped out from under it.
/// A deploy still `running` past this point almost certainly outlived
/// whatever was going to call [`Deploys::finish`] for it: the spawned task
/// panicked or was killed without unwinding through it, or — see
/// [`Deploys::in_dir`] — the daemon itself restarted mid-deploy and took the
/// in-memory task with it.
pub const STALLED_DEPLOY_TIMEOUT_SECS: u64 = 20 * 60;

/// The [`Deploy::log`] a stall is recorded with, whichever of the two ways
/// above reaped it — see [`STALLED_DEPLOY_TIMEOUT_SECS`].
const STALL_LOG: &str = "stalled: no result was ever recorded for this deploy; the task that was \
    supposed to finish it crashed, was killed, or the daemon restarted before it could";

/// Bytes of entropy in a deploy id. No secret is derived from it — it only
/// has to be unguessable enough that one caller cannot enumerate another's
/// deploy ids, the same bar [`crate::token`]'s tickets hold themselves to.
const ID_BYTES: usize = 16;

/// A Deploy's identity — opaque, url-safe hex, never reused.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeployId(String);

impl DeployId {
    /// The id as it appears in `GET /api/deploys/<id>` and in the JSON body
    /// of every deploy record.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn random() -> std::io::Result<Self> {
        Ok(Self(crate::token::hex(&crate::token::random_bytes(ID_BYTES)?)))
    }

    /// Reconstructs a `DeployId` from its stored string form.
    ///
    /// [`DeployId::random`] is the only other constructor, and it is called
    /// exactly once, the instant [`Deploys::start`] accepts a deploy. This one
    /// exists for the one case an id has to survive a process boundary: a
    /// self-update's post-restart health verification
    /// (`selfhost_cli::self_update::verify_after_restart`) runs in a
    /// *different process* from the one whose [`Deploys::start`] minted the
    /// id — the update exited on purpose so the service manager could restart
    /// it — so the id crosses that boundary as the plain string persisted to
    /// a pending-verification marker, with no live `DeployId` to hand along.
    pub fn from_stored(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for DeployId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What asked for this Deploy to run.
///
/// Three values, not four: the webhook relay, `selfhost repo deploy`, and the
/// console's own deploy button all arrive at [`crate::deploy_now`] over the
/// identical wire shape (an empty-body `POST .../deploy`, told apart only by
/// the webhook relay's own `?via=webhook` marker — see that function's
/// documentation) — `docs/surfaces.dx` already groups CLI, console button and
/// manual API as one mechanism, "the button", distinct from "the webhook" and
/// "the self-update". Folding CLI into `Api` reflects that grouping rather
/// than inventing a distinction the wire protocol does not make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// A verified push delivery, relayed from the public webhook path.
    Webhook,
    /// `selfhost repo deploy`, the console's deploy button, or any other
    /// direct `POST /api/services/<name>/deploy` call.
    Api,
    /// This daemon's own repository, checked by `watch_own_repository` on a
    /// nudge (itself woken by a webhook push to the self-update branch, or by
    /// `POST /api/self-update/deploy`).
    SelfUpdate,
}

impl Trigger {
    /// The wire word this trigger is stored and reported as.
    pub fn wire(self) -> &'static str {
        match self {
            Self::Webhook => "webhook",
            Self::Api => "api",
            Self::SelfUpdate => "self-update",
        }
    }

    fn parse(word: &str) -> Option<Self> {
        match word {
            "webhook" => Some(Self::Webhook),
            "api" => Some(Self::Api),
            "self-update" => Some(Self::SelfUpdate),
            _ => None,
        }
    }
}

/// Where a Deploy stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployResult {
    /// Started; no outcome yet. A caller polling `GET /api/deploys/<id>` sees
    /// this until [`Deploys::finish`] is called, or until
    /// [`STALLED_DEPLOY_TIMEOUT_SECS`] passes with no result — see
    /// [`Deploys::get`]/[`Deploys::list`] — whichever comes first, so a task
    /// that never gets to call `finish` does not leave this at `running`
    /// forever.
    Running,
    /// Finished with nothing wrong — including "nothing to do; already at the
    /// tip", which is success, not failure: no silent failure means a
    /// no-op is a recorded no-op, not an unrecorded one.
    Succeeded,
    /// Finished with a step that did not complete. [`Deploy::log`] says which
    /// step and why.
    Failed,
}

impl DeployResult {
    fn wire(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    fn parse(word: &str) -> Option<Self> {
        match word {
            "running" => Some(Self::Running),
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// One Deploy: a repo→build→publish attempt, from acceptance to outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deploy {
    /// This deploy's identity — what `GET /api/deploys/<id>` is keyed on.
    pub id: DeployId,
    /// What was deployed: a Service's name, or `"self-update"` for the
    /// daemon's own repository.
    pub target: String,
    /// What asked for this deploy.
    pub trigger: Trigger,
    /// When this deploy was accepted, Unix seconds.
    pub started_unix: u64,
    /// When this deploy reached a result, Unix seconds. `None` while
    /// [`DeployResult::Running`].
    pub finished_unix: Option<u64>,
    /// Where the deploy stands.
    pub result: DeployResult,
    /// The commit deployed, when one was. Absent for a still-`running` deploy,
    /// a `succeeded` no-op that found nothing to do, and every `failed` one.
    pub commit: Option<String>,
    /// A short, human-readable account of what happened — "deployed
    /// a1b2c3d", "nothing to do; already at the tip", "build failed: cargo
    /// build exited 101". Not the service's full build output, which stays
    /// where it always has, behind `GET /api/services/<name>/logs`; this is
    /// the one line that answers "what happened to this deploy".
    pub log: String,
}

impl Deploy {
    /// This deploy as the JSON object `GET /api/deploys` and
    /// `GET /api/deploys/<id>` report.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("id", Json::string(self.id.as_str())),
            ("target", Json::string(&self.target)),
            ("trigger", Json::string(self.trigger.wire())),
            ("started", Json::Number(self.started_unix as f64)),
            (
                "finished",
                match self.finished_unix {
                    Some(secs) => Json::Number(secs as f64),
                    None => Json::Null,
                },
            ),
            ("result", Json::string(self.result.wire())),
            (
                "commit",
                match &self.commit {
                    Some(commit) => Json::string(commit),
                    None => Json::Null,
                },
            ),
            ("log", Json::string(&self.log)),
        ])
    }
}

/// The Deploy record store: a bounded, in-memory list of recent deploys,
/// persisted to disk after every mutation. See this module's documentation
/// for why this differs from [`crate::agent_store::AgentStore`]'s
/// read-fresh-every-call shape.
#[derive(Debug)]
pub struct Deploys {
    path: PathBuf,
    entries: Mutex<Vec<Deploy>>,
}

impl Deploys {
    /// Loads `<data_dir>/console.deploys` once. A missing or malformed file
    /// starts empty rather than failing — a deployment's first deploy must
    /// not be blocked on a record of deploys that came before it.
    ///
    /// Any entry loaded as still [`DeployResult::Running`] is immediately
    /// reaped as [`DeployResult::Failed`]: the only process that could ever
    /// call [`Deploys::finish`] for it is this daemon, and this daemon is
    /// only reading this file from disk because it just (re)started — the
    /// in-memory task that would have finished it is gone along with the
    /// process that held it. See this module's documentation.
    pub fn in_dir(data_dir: &Path) -> Self {
        let path = data_dir.join(DEPLOY_STORE_FILENAME);
        let mut entries = std::fs::read_to_string(&path).ok().and_then(|text| parse(&text)).unwrap_or_default();
        let reaped = reap_on_restart(&mut entries);
        let store = Self { path, entries: Mutex::new(entries) };
        if reaped {
            store.persist(&store.entries.lock().unwrap_or_else(|p| p.into_inner()));
        }
        store
    }

    /// Records a Deploy as accepted and [`DeployResult::Running`], returning
    /// its id. Call this before the work begins — the whole point is that a
    /// deploy `GET /api/deploys` can see is one that has already been
    /// recorded, not one that will be recorded if it happens to succeed.
    pub fn start(&self, target: &str, trigger: Trigger) -> DeployId {
        // A random source this starved is a daemon with a deeper problem than
        // one unrecorded deploy; falling back to a lower-entropy but always
        // available id (the current entry count plus a timestamp) keeps the
        // deploy itself from being refused over it, matching this module's
        // own "a persist failure never blocks a deploy" rule.
        let id = DeployId::random().unwrap_or_else(|_| {
            DeployId(format!("fallback-{}-{}", now_unix(), self.entries.lock().unwrap_or_else(|p| p.into_inner()).len()))
        });
        let deploy = Deploy {
            id: id.clone(),
            target: target.to_owned(),
            trigger,
            started_unix: now_unix(),
            finished_unix: None,
            result: DeployResult::Running,
            commit: None,
            log: String::new(),
        };
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.insert(0, deploy);
        entries.truncate(MAX_DEPLOYS);
        self.persist(&entries);
        id
    }

    /// Records a Deploy's outcome. A no-op if `id` is not a deploy this store
    /// started (already dropped past [`MAX_DEPLOYS`], or an id from before a
    /// restart lost the in-memory list — the on-disk history still shows it,
    /// only its live tracking is gone).
    pub fn finish(&self, id: &DeployId, result: DeployResult, commit: Option<String>, log: impl Into<String>) {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(deploy) = entries.iter_mut().find(|deploy| &deploy.id == id) {
            deploy.result = result;
            deploy.commit = commit;
            deploy.log = log.into();
            deploy.finished_unix = Some(now_unix());
        }
        self.persist(&entries);
    }

    /// One Deploy by id, for `GET /api/deploys/<id>`. Reaps stalled entries
    /// first — see [`STALLED_DEPLOY_TIMEOUT_SECS`] — so a caller polling this
    /// id is what corrects a `running` record nothing else was going to.
    pub fn get(&self, id: &str) -> Option<Deploy> {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        if reap_stalled(&mut entries) {
            self.persist(&entries);
        }
        entries.iter().find(|deploy| deploy.id.as_str() == id).cloned()
    }

    /// Every held Deploy, newest first, for `GET /api/deploys`. Reaps stalled
    /// entries first — see [`Deploys::get`].
    pub fn list(&self) -> Vec<Deploy> {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        if reap_stalled(&mut entries) {
            self.persist(&entries);
        }
        entries.clone()
    }

    /// Writes the store owner-only through a temporary file and a rename, the
    /// same shape [`crate::agent_store::AgentStore::persist`] uses. Printed
    /// to stderr and swallowed on failure — see this module's documentation
    /// for why a lost write must never fail the deploy that triggered it.
    fn persist(&self, entries: &[Deploy]) {
        if let Err(error) = self.try_persist(entries) {
            eprintln!("admin: could not record deploy history to {}: {error}", self.path.display());
        }
    }

    fn try_persist(&self, entries: &[Deploy]) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = self.path.with_extension("deploys.new");
        crate::token::write_private(&temporary, &to_json(entries).to_text())?;
        std::fs::rename(&temporary, &self.path)
    }
}

/// Seconds since the Unix epoch, or zero on a clock set before it.
fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|since| since.as_secs()).unwrap_or(0)
}

/// Marks every still-[`DeployResult::Running`] entry as [`DeployResult::Failed`]
/// unconditionally, for [`Deploys::in_dir`]'s restart case — see there for why
/// age does not matter for this one. Returns whether anything changed.
fn reap_on_restart(entries: &mut [Deploy]) -> bool {
    let now = now_unix();
    let mut changed = false;
    for deploy in entries.iter_mut() {
        if deploy.result == DeployResult::Running {
            deploy.result = DeployResult::Failed;
            deploy.finished_unix = Some(now);
            deploy.log = STALL_LOG.to_owned();
            changed = true;
        }
    }
    changed
}

/// Marks every [`DeployResult::Running`] entry older than
/// [`STALLED_DEPLOY_TIMEOUT_SECS`] as [`DeployResult::Failed`], for
/// [`Deploys::get`]/[`Deploys::list`]'s same-process case, where a still-live
/// daemon just never heard back from the task it spawned. Returns whether
/// anything changed.
fn reap_stalled(entries: &mut [Deploy]) -> bool {
    let now = now_unix();
    let mut changed = false;
    for deploy in entries.iter_mut() {
        if deploy.result == DeployResult::Running && now.saturating_sub(deploy.started_unix) >= STALLED_DEPLOY_TIMEOUT_SECS {
            deploy.result = DeployResult::Failed;
            deploy.finished_unix = Some(now);
            deploy.log = STALL_LOG.to_owned();
            changed = true;
        }
    }
    changed
}

/// The stored shape: `{"deploys":[{id, target, trigger, startedUnix,
/// finishedUnix, result, commit, log}]}` — newest first, matching in-memory
/// order.
fn to_json(entries: &[Deploy]) -> Json {
    Json::object([(
        "deploys",
        Json::array(entries.iter().map(|deploy| {
            let mut fields: BTreeMap<String, Json> = BTreeMap::new();
            fields.insert("id".into(), Json::string(deploy.id.as_str()));
            fields.insert("target".into(), Json::string(&deploy.target));
            fields.insert("trigger".into(), Json::string(deploy.trigger.wire()));
            fields.insert("startedUnix".into(), Json::Number(deploy.started_unix as f64));
            fields.insert(
                "finishedUnix".into(),
                match deploy.finished_unix {
                    Some(secs) => Json::Number(secs as f64),
                    None => Json::Null,
                },
            );
            fields.insert("result".into(), Json::string(deploy.result.wire()));
            fields.insert(
                "commit".into(),
                match &deploy.commit {
                    Some(commit) => Json::string(commit),
                    None => Json::Null,
                },
            );
            fields.insert("log".into(), Json::string(&deploy.log));
            Json::Object(fields)
        })),
    )])
}

/// Parses the stored file, or `None` for anything at all that is malformed —
/// the whole document is refused rather than partially read, matching
/// [`crate::agent_store`]'s own parse discipline.
fn parse(text: &str) -> Option<Vec<Deploy>> {
    let value = selfhost_json::parse(text).ok()?;
    let items = value.get("deploys")?.as_array()?;
    if items.len() > MAX_DEPLOYS {
        return None;
    }
    let mut entries = Vec::with_capacity(items.len());
    for item in items {
        let id = DeployId(item.get("id")?.as_str()?.to_owned());
        let target = item.get("target")?.as_str()?.to_owned();
        let trigger = Trigger::parse(item.get("trigger")?.as_str()?)?;
        let started_unix = item.get("startedUnix")?.as_u64()?;
        let finished_unix = match item.get("finishedUnix") {
            Some(value) if value.is_null() => None,
            Some(value) => Some(value.as_u64()?),
            None => None,
        };
        let result = DeployResult::parse(item.get("result")?.as_str()?)?;
        let commit = match item.get("commit") {
            Some(value) if value.is_null() => None,
            Some(value) => Some(value.as_str()?.to_owned()),
            None => None,
        };
        let log = item.get("log")?.as_str()?.to_owned();
        entries.push(Deploy { id, target, trigger, started_unix, finished_unix, result, commit, log });
    }
    Some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("selfhost-deploys-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        path
    }

    #[test]
    fn a_started_deploy_is_immediately_visible_as_running() {
        let store = Deploys::in_dir(&scratch("start"));
        let id = store.start("mysite", Trigger::Api);
        let deploy = store.get(id.as_str()).expect("just started");
        assert_eq!(deploy.result, DeployResult::Running);
        assert_eq!(deploy.trigger, Trigger::Api);
        assert!(deploy.finished_unix.is_none());
    }

    #[test]
    fn finishing_records_the_outcome() {
        let store = Deploys::in_dir(&scratch("finish"));
        let id = store.start("mysite", Trigger::Webhook);
        store.finish(&id, DeployResult::Succeeded, Some("abc1234".into()), "deployed abc1234");
        let deploy = store.get(id.as_str()).expect("still there");
        assert_eq!(deploy.result, DeployResult::Succeeded);
        assert_eq!(deploy.commit.as_deref(), Some("abc1234"));
        assert_eq!(deploy.log, "deployed abc1234");
        assert!(deploy.finished_unix.is_some());
    }

    #[test]
    fn a_failed_deploy_is_recorded_not_dropped() {
        let store = Deploys::in_dir(&scratch("failed"));
        let id = store.start("self-update", Trigger::SelfUpdate);
        store.finish(&id, DeployResult::Failed, None, "build failed: cargo build exited 101");
        let deploy = store.get(id.as_str()).expect("failures are recorded too");
        assert_eq!(deploy.result, DeployResult::Failed);
        assert!(deploy.commit.is_none());
    }

    #[test]
    fn listing_is_newest_first() {
        let store = Deploys::in_dir(&scratch("order"));
        let first = store.start("a", Trigger::Api);
        let second = store.start("b", Trigger::Api);
        let listed = store.list();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, second);
        assert_eq!(listed[1].id, first);
    }

    #[test]
    fn the_cap_drops_the_oldest() {
        let store = Deploys::in_dir(&scratch("cap"));
        for i in 0..(MAX_DEPLOYS + 5) {
            store.start(&format!("service-{i}"), Trigger::Api);
        }
        let listed = store.list();
        assert_eq!(listed.len(), MAX_DEPLOYS);
        // Newest first: the very last one started is still there.
        assert_eq!(listed[0].target, format!("service-{}", MAX_DEPLOYS + 4));
    }

    #[test]
    fn a_second_handle_reloads_what_was_persisted() {
        let dir = scratch("reload");
        let writer = Deploys::in_dir(&dir);
        let id = writer.start("mysite", Trigger::Api);
        writer.finish(&id, DeployResult::Succeeded, Some("deadbeef".into()), "deployed deadbeef");

        let reader = Deploys::in_dir(&dir);
        let deploy = reader.get(id.as_str()).expect("persisted across a fresh load");
        assert_eq!(deploy.result, DeployResult::Succeeded);
        assert_eq!(deploy.commit.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn a_malformed_store_starts_empty_rather_than_failing() {
        let dir = scratch("malformed");
        std::fs::write(dir.join(DEPLOY_STORE_FILENAME), "not json at all").unwrap();
        let store = Deploys::in_dir(&dir);
        assert_eq!(store.list().len(), 0);
    }

    #[test]
    fn an_unknown_id_finishes_as_a_no_op() {
        let store = Deploys::in_dir(&scratch("unknown"));
        // Nothing to assert beyond "does not panic": finishing an id this
        // store never started (e.g. one from before a restart) must not crash
        // the caller that raced a persist with a lost in-memory entry.
        store.finish(&DeployId("does-not-exist".into()), DeployResult::Failed, None, "irrelevant");
    }

    /// Regression for a `running` deploy left behind by a crashed daemon: a
    /// fresh `Deploys::in_dir` over the same directory must not resurrect it
    /// as still in progress forever — it should read back as `failed`.
    #[test]
    fn a_running_deploy_from_before_a_restart_is_marked_failed_on_reload() {
        let dir = scratch("restart");
        let writer = Deploys::in_dir(&dir);
        let id = writer.start("mysite", Trigger::Webhook);
        // Simulate the daemon exiting mid-deploy: `writer` is dropped without
        // ever calling `finish`, exactly like a crash or a kill.
        drop(writer);

        let reader = Deploys::in_dir(&dir);
        let deploy = reader.get(id.as_str()).expect("still on disk");
        assert_eq!(deploy.result, DeployResult::Failed);
        assert!(deploy.finished_unix.is_some());
        assert!(!deploy.log.is_empty());

        // The correction itself is durable, not just in this handle's memory.
        let reader_again = Deploys::in_dir(&dir);
        assert_eq!(reader_again.get(id.as_str()).unwrap().result, DeployResult::Failed);
    }

    /// A deploy that finished normally before a restart must reload exactly
    /// as it finished — only still-`running` entries are reaped.
    #[test]
    fn a_finished_deploy_survives_a_restart_untouched() {
        let dir = scratch("restart-finished");
        let writer = Deploys::in_dir(&dir);
        let id = writer.start("mysite", Trigger::Api);
        writer.finish(&id, DeployResult::Succeeded, Some("cafef00d".into()), "deployed cafef00d");
        drop(writer);

        let reader = Deploys::in_dir(&dir);
        let deploy = reader.get(id.as_str()).unwrap();
        assert_eq!(deploy.result, DeployResult::Succeeded);
        assert_eq!(deploy.log, "deployed cafef00d");
    }

    /// Regression for a deploy whose spawned task crashed without ever
    /// calling `finish`, in a daemon that itself kept running: once the
    /// deploy has sat `running` past the timeout, reading it is what
    /// corrects the record — no restart required.
    #[test]
    fn a_stalled_running_deploy_is_reaped_on_read() {
        let store = Deploys::in_dir(&scratch("stalled"));
        let id = store.start("mysite", Trigger::Api);
        // Back-date the start so it reads as long past the stall timeout,
        // standing in for real time passing with no call to `finish`.
        {
            let mut entries = store.entries.lock().unwrap();
            entries[0].started_unix = entries[0].started_unix.saturating_sub(STALLED_DEPLOY_TIMEOUT_SECS + 1);
        }

        let deploy = store.get(id.as_str()).expect("still recorded");
        assert_eq!(deploy.result, DeployResult::Failed);
        assert!(deploy.finished_unix.is_some());

        // list() reaps the same way.
        let listed = store.list();
        assert_eq!(listed[0].result, DeployResult::Failed);
    }

    /// A deploy that is `running` but well within the timeout must not be
    /// touched — only genuinely stalled entries are reaped.
    #[test]
    fn a_recent_running_deploy_is_left_alone() {
        let store = Deploys::in_dir(&scratch("recent"));
        let id = store.start("mysite", Trigger::Api);
        let deploy = store.get(id.as_str()).unwrap();
        assert_eq!(deploy.result, DeployResult::Running);
    }
}
