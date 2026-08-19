//! The people this deployment knows, and what each of them may do.
//!
//! # What this file is, shaped on the one that came before it
//!
//! `<data_dir>/console.people` is the durable half of the permission model: a
//! JSON document, owner-only on disk, holding one entry per person with the
//! capabilities the operator has granted them. It is shaped deliberately —
//! almost line for line — on `Passkeys` in `crates/admin/src/webauthn.rs`,
//! which is the store this one sits beside and shares a lifecycle with. A
//! cheap-clone handle over an `Arc<Mutex<_>>`, because [`crate::Policy`]'s
//! callers are clones of one API and a grant made through one of them must be
//! visible through all. A missing file is an empty store. Persistence is a
//! write to a temporary sibling followed by a rename, so a crash mid-write
//! leaves the previous file rather than half of the new one. A non-revealing
//! `Debug`, because a list of who has access to what is a target list even
//! though it holds no secret.
//!
//! It departs from that store in one place, and the departure is the important
//! sentence in this file: the handle is **not** a snapshot. It re-reads
//! `console.people` whenever the file has changed underneath it, because the
//! daemon is not the only writer — `selfhost people` is a separate process that
//! writes this file directly and deliberately. See [`Stored`] for the defect
//! that made the difference, and for why it mattered more here than it did in
//! the invite store where the same shape was fixed first.
//!
//! And, most importantly, the same fail-closed reading of a file it cannot
//! understand: a malformed `console.people` loads as **empty**, says so once on
//! stderr, and leaves every person holding nothing. For a credential store that
//! is the obvious direction. For a *permission* store it is worth stating out
//! loud, because the alternative — carrying on with whatever entries happened to
//! parse — means a truncated write or a botched hand-edit could leave a person
//! holding a capability from a document that no longer says what it meant to.
//! The owner is unaffected either way: [`crate::Policy::decide`] never consults
//! a grant set for the owner, precisely so that a broken permission file cannot
//! lock the operator out of the console they would use to fix it.
//!
//! # Why the private write is injected rather than implemented here
//!
//! "Owner-only on disk" is a claim about the operating system, and on Windows —
//! where this deployment actually runs — honouring it means building an explicit
//! DACL through raw `advapi32` calls, because a file created with the standard
//! library simply inherits whatever the parent directory hands down. That
//! implementation already exists, once, in `crates/admin/src/token.rs`, and this
//! crate sits *below* `crates/admin` in the dependency graph and forbids
//! `unsafe` outright. Copying it here would make a fifth copy of a security
//! primitive that the security review has already flagged for having four
//! (`docs/SECURITY.md`, SEC-07: a primitive with four implementations gets fixed
//! one at a time, which is exactly how the Windows no-op survived).
//!
//! So the writer is a parameter. [`write_owner_only`] is this crate's own
//! implementation and is honest about its limits: `0600` at creation on unix,
//! and a plain error on every other platform rather than a write that would
//! quietly land under an inherited ACL. [`People::with_writer`] is the seam the
//! daemon uses to hand in the platform-correct writer it already owns. A
//! Windows deployment that has not passed one in can read this file and cannot
//! write it, which is the right way round for that gap to fail.

use crate::capability::Capability;
use crate::credential::Credential;
use crate::identity::{Identity, PersonName};
use crate::policy::{Caller, Grants, TooManyGrants};
use selfhost_json::Json;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// The name of the people file inside the data directory.
pub const PEOPLE_FILENAME: &str = "console.people";

/// The most people the registry will hold.
///
/// Matched to the passkey store's own cap: every person in here authenticates
/// with a passkey, so a registry larger than the credential store beside it
/// could only hold entries nobody can log in as. A loop that adds people is
/// refused, not stored.
pub const MAX_PEOPLE: usize = 32;

/// How a person's grants are written to disk, privately.
///
/// A plain function pointer rather than a trait object: there is exactly one
/// operation, it has no state, and the deployment picks one implementation at
/// start-up. See this module's documentation for why it is injected.
pub type PrivateWrite = fn(path: &Path, contents: &str) -> io::Result<()>;

/// Writes `contents` to `path` so that only its owner can read it.
///
/// On unix the file is created `0600` from the outset — created, not chmod'ed
/// afterwards, because the gap between those two steps is exactly when a shared
/// machine gets to read it. Any file already at `path` is removed first, since
/// a mode given to `open` applies only at creation and a leftover temporary from
/// a previous crash would otherwise keep its old permissions.
///
/// On every other platform this returns an error rather than writing. That is
/// not an oversight and it is not a stub: a `std::fs::write` on Windows inherits
/// the parent directory's DACL, which inside a user profile tree routinely
/// includes the interactive user, and a permission file that anyone can rewrite
/// is worse than one that cannot be written at all. The deployment supplies a
/// platform-correct writer through [`People::with_writer`]; see the module
/// documentation.
pub fn write_owner_only(path: &Path, contents: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = contents;
        Err(io::Error::other(format!(
            "refusing to write {} without a platform-private writer: on this platform a file \
             inherits its parent directory's permissions, and a permission registry that other \
             accounts can rewrite is worse than one that cannot be written; pass the \
             deployment's own writer to People::with_writer",
            path.display()
        )))
    }
}

/// One person and the capabilities they hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    /// Who they are. The same name their passkey is registered under, which is
    /// what makes a verified assertion resolve to this entry.
    pub name: PersonName,
    /// What the operator has granted them.
    pub grants: Grants,
    /// When the entry was first created, as seconds since the Unix epoch —
    /// wall-clock rather than `Instant` because it survives restarts on disk.
    pub added_unix: u64,
}

/// The durable registry: `<data_dir>/console.people`, owner-only, JSON.
#[derive(Clone)]
pub struct People {
    path: PathBuf,
    state: Arc<Mutex<Stored>>,
    write_private: PrivateWrite,
}

/// What the registry holds in memory: the entries, and enough about the file
/// they were read from to notice somebody else rewriting it.
///
/// The second field is the whole of the fix for a defect this file shipped
/// with. A registry handle is built **once**, when the daemon starts, and lives
/// for the life of the process — but it is not the only writer. `selfhost
/// people grant|allow|deny|forget` is a separate process that writes this same
/// file directly and by design (`crates/app/cli/src/people_command.rs` states
/// why: an operator must be able to fix permissions on a box whose console they
/// cannot reach). With a plain snapshot, that other process's write was invisible
/// to the running daemon until it was restarted, which made the CLI's own
/// closing line — *takes effect on the daemon's next read of the registry* —
/// untrue, and made the failure asymmetric in the dangerous direction: a
/// **grant** that did not appear is an operator filing a bug, and a **revocation**
/// that did not appear is somebody still holding a power that was taken away an
/// hour ago.
///
/// `crates/app/admin/src/invite.rs` had the identical defect and was fixed in
/// e50918a; this is the same shape applied to the file that decides what people
/// may do, which is the one where it mattered more.
struct Stored {
    /// The registry as last read or written.
    entries: Vec<Person>,
    /// The modified time and length of the file those entries came from, or
    /// `None` when the file was absent or unreadable. Compared before every
    /// operation; a difference means re-read.
    seen: Option<(SystemTime, u64)>,
}

impl People {
    /// Loads the registry from `<data_dir>/console.people`, using this crate's
    /// own [`write_owner_only`] for persistence.
    ///
    /// The right constructor for tests and for unix deployments. A Windows
    /// deployment should use [`People::with_writer`]; with this one it will
    /// read the file and refuse to write it.
    pub fn load(data_dir: &Path) -> Self {
        Self::with_writer(data_dir, write_owner_only)
    }

    /// Loads the registry, persisting through the writer the deployment owns.
    ///
    /// What this reads is a starting point, not a snapshot the handle keeps: see
    /// [`Stored`] and [`Self::lock`] for why every operation re-reads a file that
    /// has changed underneath it.
    pub fn with_writer(data_dir: &Path, write_private: PrivateWrite) -> Self {
        let path = Self::path_in(data_dir);
        let (entries, seen) = read_entries(&path);
        Self { path, state: Arc::new(Mutex::new(Stored { entries, seen })), write_private }
    }

    /// Where the people file lives for a given data directory.
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(PEOPLE_FILENAME)
    }

    /// Whether nobody is registered.
    pub fn is_empty(&self) -> bool {
        self.lock().entries.is_empty()
    }

    /// How many people are registered.
    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    /// Everyone registered, for the console's people list.
    pub fn list(&self) -> Vec<Person> {
        self.lock().entries.clone()
    }

    /// The entry for one person, if they have one.
    pub fn find(&self, name: &PersonName) -> Option<Person> {
        self.lock().entries.iter().find(|entry| &entry.name == name).cloned()
    }

    /// What `identity` holds.
    ///
    /// The owner is answered with [`Grants::none`], and that is not a mistake:
    /// the owner's authority does not come from this file and cannot be edited
    /// through it, so there is nothing here to report.
    /// [`crate::Policy::decide`] never reads an owner's grant set — see the
    /// second deliberate asymmetry documented on [`crate::Policy`]. A person
    /// with no entry is likewise answered with nothing, so being unknown and
    /// being known-but-ungranted are the same authority and produce the same
    /// uninformative refusal.
    ///
    /// The machine is answered the same way and for a stricter reason: the
    /// bearer token's authority is a fixed list in the policy, so an entry in
    /// this file naming the machine must buy nothing at all. A
    /// [`PersonName`] cannot spell it, so no such entry can be written through
    /// the console; answering `none` here is what makes a hand-edited one inert
    /// as well.
    ///
    /// An agent is answered `none` too, and for the same shape of reason as the
    /// machine: an agent's authority lives in `console.agents`
    /// (`selfhost_admin::agent_store`), not here, so this registry has nothing
    /// to say about one and must not be asked to guess. `crates/app/admin`'s
    /// `Api::caller()` never routes an agent credential through this method —
    /// it builds that `Caller` directly from the agent store's own lookup — so
    /// this arm exists only to keep the match exhaustive and to fail safely if
    /// a future caller ever does ask it the wrong question.
    pub fn grants_for(&self, identity: &Identity) -> Grants {
        match identity {
            Identity::Owner | Identity::Machine | Identity::Agent(_) => Grants::none(),
            Identity::Person(name) => {
                self.find(name).map(|person| person.grants).unwrap_or_else(Grants::none)
            }
        }
    }

    /// Builds the [`Caller`] for an authenticated request.
    ///
    /// This is the seam `crates/admin`'s `Api::caller()` ends at: the API
    /// decides *who* from the credential the request presented, and this method
    /// attaches *what they may do* by looking the identity up here, so that
    /// [`crate::Policy::decide`] is handed everything it needs and stays pure.
    pub fn caller(&self, identity: Identity, credential: Credential) -> Caller {
        let grants = self.grants_for(&identity);
        Caller::new(identity, credential, grants)
    }

    /// Sets exactly what one person holds, creating the entry if needed, and
    /// persists.
    ///
    /// Deliberately a whole-set write rather than a grant-one/revoke-one pair:
    /// the console renders a person's capabilities as a set of toggles and
    /// submits the set, and a permission change that is applied as a sequence of
    /// increments is a permission change that can be half-applied.
    ///
    /// A person's name can never be the owner's — [`PersonName`] refuses that
    /// spelling in every casing — so there is no entry here that could revoke
    /// the operator's own authority, and no need for this method to defend
    /// against one.
    pub fn set_grants(&self, name: &PersonName, grants: Grants) -> io::Result<()> {
        let mut state = self.lock();
        match state.entries.iter_mut().find(|entry| &entry.name == name) {
            Some(entry) => entry.grants = grants,
            None => {
                if state.entries.len() >= MAX_PEOPLE {
                    return Err(io::Error::other(format!(
                        "at most {MAX_PEOPLE} people may be registered"
                    )));
                }
                state.entries.push(Person { name: name.clone(), grants, added_unix: now_unix() });
            }
        }
        self.persist(&state.entries)?;
        self.mark_written(&mut state);
        Ok(())
    }

    /// Forgets a person entirely, persisting; false if they were unknown.
    ///
    /// Removing an entry is the same authority as clearing its grants — both
    /// leave the person holding nothing — but it is the honest one when the
    /// operator means "this person is gone", because an entry with no grants
    /// still renders as a row in the console.
    pub fn remove(&self, name: &PersonName) -> io::Result<bool> {
        let mut state = self.lock();
        let before = state.entries.len();
        state.entries.retain(|entry| &entry.name != name);
        if state.entries.len() == before {
            return Ok(false);
        }
        self.persist(&state.entries)?;
        self.mark_written(&mut state);
        Ok(true)
    }

    /// Writes the registry owner-only via a temporary file and a rename.
    ///
    /// Creates the data directory if it is not there yet, exactly as the token
    /// and password stores this file was shaped on do. The first grant on a
    /// deployment is routinely made *before* the daemon has ever run — that is
    /// the whole point of the CLI's `people` command — and a permission tool
    /// that fails with "No such file or directory" on a fresh box is one an
    /// operator cannot use at the only moment they need it.
    fn persist(&self, entries: &[Person]) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = people_to_json(entries).to_text();
        let temporary = self.path.with_extension("people.new");
        (self.write_private)(&temporary, &text)?;
        std::fs::rename(&temporary, &self.path)
    }

    /// The entries as they are on disk **right now**, with lock poisoning
    /// treated as fatal, as in `crates/admin`'s session and passkey stores.
    ///
    /// A poisoned lock means a panic happened while the registry was held;
    /// limping on with permissions in an unknown state is worse than stopping.
    ///
    /// The re-read is not an optimisation and it is not caching: it is what
    /// makes this handle answer for the file rather than for the moment it was
    /// constructed. See [`Stored`] for the second writer that makes it
    /// necessary. The cost is one `stat` per authorisation decision, paid so
    /// that a revocation is a revocation.
    fn lock(&self) -> std::sync::MutexGuard<'_, Stored> {
        let mut state = self.state.lock().expect("the people registry lock was poisoned");
        let current = file_stamp(&self.path);
        if current != state.seen {
            let (entries, seen) = read_entries(&self.path);
            state.entries = entries;
            state.seen = seen;
        }
        state
    }

    /// Records what was just written, so the next operation does not re-read
    /// this handle's own write back off the disk.
    fn mark_written(&self, state: &mut Stored) {
        state.seen = file_stamp(&self.path);
    }
}

/// The file's identity for change detection: modified time and length.
///
/// `None` when the file is absent or cannot be stated, which is itself a value
/// that compares unequal to a present file — so a registry whose file appears,
/// or disappears, notices either way.
fn file_stamp(path: &Path) -> Option<(SystemTime, u64)> {
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.modified().ok()?, metadata.len()))
}

/// Reads and parses the people file, failing closed.
///
/// A missing file is an empty registry. A malformed one is *also* an empty
/// registry — every person holds nothing, rather than some unknown subset of
/// them holding something — and says so. The owner is unaffected either way:
/// their authority does not come from this file.
fn read_entries(path: &Path) -> (Vec<Person>, Option<(SystemTime, u64)>) {
    // Stamp first, so a write landing between the read and the stat is noticed
    // on the next call rather than being mistaken for what was just read.
    let stamp = file_stamp(path);
    let entries = match std::fs::read_to_string(path) {
        Ok(text) => match parse_people(&text) {
            Some(entries) => entries,
            None => {
                eprintln!(
                    "identity: {} is not a valid people file; every person holds nothing \
                     until it is repaired or removed (the owner is unaffected)",
                    path.display()
                );
                Vec::new()
            }
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            eprintln!(
                "identity: could not read {}: {error}; every person holds nothing",
                path.display()
            );
            Vec::new()
        }
    };
    (entries, stamp)
}

// Deliberately not a revealing `Debug`: the registry holds no secret, but who
// may drive which machine is a target list, and a target list in a log line is
// a shopping list.
impl std::fmt::Debug for People {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "People({} registered)", self.lock().entries.len())
    }
}

/// Seconds since the Unix epoch, or zero if the clock is before it.
///
/// A clock behind the epoch is a misconfigured machine, not an error worth
/// failing a permission change over; the timestamp is a display field.
fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|since| since.as_secs()).unwrap_or(0)
}

/// The stored file's JSON shape:
/// `{"people": [{name, grants: ["files.read:vault", …], addedUnix}]}`.
///
/// Grants are written in their wire form ([`Capability`]'s `Display`), which is
/// the same spelling the console sends and the audit log records — one
/// vocabulary for one idea, so a capability cannot be renamed in one place and
/// silently mean something else in another.
fn people_to_json(entries: &[Person]) -> Json {
    Json::object([(
        "people",
        Json::array(entries.iter().map(|entry| {
            Json::object([
                ("name", Json::string(entry.name.as_str())),
                (
                    "grants",
                    Json::array(entry.grants.iter().map(|c| Json::string(c.to_string()))),
                ),
                ("addedUnix", Json::Number(entry.added_unix as f64)),
            ])
        })),
    )])
}

/// Parses the stored file, or `None` for anything at all that is malformed.
///
/// "Anything at all" is the whole point, and every one of these is a refusal of
/// the entire document rather than of one entry: a name that is not a valid
/// [`PersonName`], a grant string this build does not understand, a grant list
/// over the cap, a duplicate name, more than [`MAX_PEOPLE`] entries, a missing
/// field. A permission file that is partly understood is a permission file
/// whose meaning depends on which build is reading it, and the direction to
/// fail in is obvious.
///
/// An unknown grant word deserves a note: it is what a *downgrade* looks like,
/// where a file written by a newer build names a capability this one has never
/// heard of. Refusing the document means the downgraded daemon grants nothing
/// rather than granting the subset it happens to recognise — which, if the newer
/// build had split one capability into two, would be a silent widening.
fn parse_people(text: &str) -> Option<Vec<Person>> {
    let value = selfhost_json::parse(text).ok()?;
    let items = value.get("people")?.as_array()?;
    if items.len() > MAX_PEOPLE {
        return None;
    }
    let mut entries: Vec<Person> = Vec::new();
    for item in items {
        let name = PersonName::parse(item.get("name")?.as_str()?).ok()?;
        if entries.iter().any(|entry| entry.name == name) {
            return None;
        }
        let mut capabilities = Vec::new();
        for grant in item.get("grants")?.as_array()? {
            capabilities.push(Capability::parse(grant.as_str()?)?);
        }
        let grants = match Grants::new(capabilities) {
            Ok(grants) => grants,
            Err(TooManyGrants) => return None,
        };
        entries.push(Person { name, grants, added_unix: item.get("addedUnix")?.as_u64()? });
    }
    Some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{NodeName, ShareId};

    /// A scratch directory unique to one test, as in the sibling stores.
    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir()
            .join(format!("selfhost-identity-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        path
    }

    fn person(name: &str) -> PersonName {
        PersonName::parse(name).expect("a valid name")
    }

    fn read_grants() -> Grants {
        Grants::new([Capability::FilesRead(ShareId::parse("vault").unwrap())]).unwrap()
    }

    #[test]
    fn a_handle_answers_for_the_file_and_not_for_the_moment_it_was_built() {
        // The defect this store shipped with, stated as the property that now
        // holds. The daemon builds one `People` at start-up and keeps it for the
        // life of the process; `selfhost people grant|deny|forget` is a
        // *separate process* that writes this file directly and by design. A
        // handle that snapshotted meant the running daemon never saw either
        // half of that — and the dangerous half is not the grant that failed to
        // appear, which an operator notices and reports. It is the revocation
        // that failed to appear, which nobody notices, because everything keeps
        // working exactly as it did before somebody's access was taken away.
        let dir = scratch("second-writer");
        let daemon = People::load(&dir);
        daemon.set_grants(&person("Mom"), read_grants()).expect("the first write");
        assert!(!daemon.grants_for(&Identity::parse("Mom").unwrap()).is_empty());

        // The other process, holding its own handle over the same file.
        let cli = People::load(&dir);
        assert!(
            !cli.grants_for(&Identity::parse("Mom").unwrap()).is_empty(),
            "the second process should read what the first one wrote",
        );

        // It grants something new. The daemon must see it without a restart.
        let widened =
            Grants::new([Capability::ConsoleRead, Capability::FilesRead(ShareId::parse("vault").unwrap())]).unwrap();
        cli.set_grants(&person("Mom"), widened).expect("the CLI's write");
        assert!(
            daemon.grants_for(&Identity::parse("Mom").unwrap()).holds(&Capability::ConsoleRead),
            "a grant made by another process was invisible to the running daemon",
        );

        // And — the half that matters — it takes it all away again.
        cli.set_grants(&person("Mom"), Grants::none()).expect("the revocation");
        assert!(
            daemon.grants_for(&Identity::parse("Mom").unwrap()).is_empty(),
            "a revocation made by another process was still being honoured by the \
             running daemon: the person kept every power that had just been taken away",
        );

        // Forgetting them entirely is the same property by the other route.
        daemon.set_grants(&person("Mom"), read_grants()).expect("granted again");
        assert!(cli.remove(&person("Mom")).expect("the CLI forgets them"));
        assert!(
            daemon.find(&person("Mom")).is_none(),
            "a person forgotten by another process was still in the running daemon's registry",
        );
        assert!(daemon.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_absent_file_is_an_empty_registry_and_grants_nothing() {
        let dir = scratch("absent");
        let people = People::load(&dir);
        assert!(people.is_empty());
        assert_eq!(people.len(), 0);
        assert!(people.grants_for(&Identity::parse("Mom").unwrap()).is_empty());
        assert!(people.find(&person("Mom")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn grants_survive_a_reload_from_disk() {
        let dir = scratch("reload");
        let first = People::load(&dir);
        first.set_grants(&person("Mom"), read_grants()).expect("persists");

        let reloaded = People::load(&dir);
        let grants = reloaded.grants_for(&Identity::Person(person("Mom")));
        assert!(grants.holds(&Capability::FilesRead(ShareId::parse("vault").unwrap())));
        assert_eq!(reloaded.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn setting_grants_replaces_the_whole_set_rather_than_merging() {
        let dir = scratch("replace");
        let people = People::load(&dir);
        let node = NodeName::parse("alex-desktop").unwrap();
        people
            .set_grants(
                &person("Mom"),
                Grants::new([Capability::DesktopView(node.clone()), Capability::ConsoleRead])
                    .unwrap(),
            )
            .expect("persists");
        people.set_grants(&person("Mom"), Grants::new([Capability::ConsoleRead]).unwrap()).unwrap();

        let held = people.grants_for(&Identity::Person(person("Mom")));
        assert!(held.holds(&Capability::ConsoleRead));
        assert!(!held.holds(&Capability::DesktopView(node)), "the removed toggle is gone");
        assert_eq!(people.len(), 1, "the person was updated, not duplicated");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn removing_a_person_forgets_them_and_removing_again_is_a_no_op() {
        let dir = scratch("remove");
        let people = People::load(&dir);
        people.set_grants(&person("Mom"), read_grants()).unwrap();
        assert!(people.remove(&person("Mom")).expect("removes"));
        assert!(!people.remove(&person("Mom")).expect("a second remove is a no-op"));
        assert!(people.is_empty());
        assert!(People::load(&dir).is_empty(), "and it stayed removed on disk");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clones_share_one_registry() {
        let dir = scratch("clones");
        let people = People::load(&dir);
        let clone = people.clone();
        people.set_grants(&person("Mom"), read_grants()).unwrap();
        assert_eq!(clone.len(), 1, "a grant made through one handle is visible through another");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_owner_is_never_an_entry_and_never_reads_grants_from_here() {
        let dir = scratch("owner");
        let people = People::load(&dir);
        // The registry cannot even express the owner: the name does not parse.
        assert!(PersonName::parse("owner").is_err());
        assert!(people.grants_for(&Identity::Owner).is_empty());
        // And the caller it builds for the owner carries the owner identity,
        // which `Policy::decide` allows regardless of this empty set.
        let caller = people.caller(Identity::Owner, Credential::Bearer);
        assert!(caller.identity().is_owner());
        assert!(caller.grants().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_registry_is_capped() {
        let dir = scratch("cap");
        let people = People::load(&dir);
        for index in 0..MAX_PEOPLE {
            people.set_grants(&person(&format!("p{index}")), Grants::none()).expect("under the cap");
        }
        let overflow = people.set_grants(&person("one-too-many"), Grants::none());
        assert!(overflow.is_err(), "a loop that adds people hits a wall");
        assert_eq!(people.len(), MAX_PEOPLE);
        // An existing person can still be edited at capacity: the cap is on
        // entries, not on changes.
        people.set_grants(&person("p0"), read_grants()).expect("editing still works");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_file_grants_nothing_rather_than_grants_some() {
        let dir = scratch("malformed");
        let path = People::path_in(&dir);
        let bad = [
            "not json",
            r#"{}"#,
            r#"{"people":{}}"#,
            r#"{"people":[{"name":"Mom"}]}"#,                              // no grants
            r#"{"people":[{"name":"owner","grants":[],"addedUnix":1}]}"#,  // the reserved name
            r#"{"people":[{"name":"Mom ","grants":[],"addedUnix":1}]}"#,   // an invalid name
            r#"{"people":[{"name":"Mom","grants":["console.write"],"addedUnix":1}]}"#, // unknown
            r#"{"people":[{"name":"Mom","grants":["files.read"],"addedUnix":1}]}"#, // no target
            r#"{"people":[{"name":"Mom","grants":[],"addedUnix":1},
                          {"name":"Mom","grants":[],"addedUnix":2}]}"#,    // duplicate
        ];
        for text in bad {
            std::fs::write(&path, text).expect("writes the fixture");
            assert!(People::load(&dir).is_empty(), "{text} must load as empty");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_file_round_trips_through_its_own_parser() {
        let node = NodeName::parse("alex-desktop").unwrap();
        let entries = vec![
            Person {
                name: person("Mary-Anne"),
                grants: Grants::new([
                    Capability::ConsoleRead,
                    Capability::DesktopControl(node),
                    Capability::FilesAdmin,
                ])
                .unwrap(),
                added_unix: 1_754_000_000,
            },
            Person { name: person("Mom"), grants: Grants::none(), added_unix: 1 },
        ];
        let text = people_to_json(&entries).to_text();
        assert_eq!(parse_people(&text).as_deref(), Some(entries.as_slice()));
        assert!(text.contains("desktop.control:alex-desktop"), "grants keep their wire spelling");
    }

    #[cfg(unix)]
    #[test]
    fn the_people_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        let people = People::load(&dir);
        people.set_grants(&person("Mom"), read_grants()).expect("persists");
        let mode = std::fs::metadata(People::path_in(&dir)).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "no group or world access: mode {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_failing_writer_leaves_the_previous_file_intact() {
        // The injected-writer seam, exercised the way a platform without a
        // private write behaves: the change is refused and nothing on disk
        // changes underneath it.
        fn refuse(_path: &Path, _contents: &str) -> io::Result<()> {
            Err(io::Error::other("no private write on this platform"))
        }
        let dir = scratch("refusing-writer");
        People::load(&dir).set_grants(&person("Mom"), read_grants()).expect("the first write");

        let refusing = People::with_writer(&dir, refuse);
        assert!(refusing.set_grants(&person("Mom"), Grants::none()).is_err());
        let on_disk = People::load(&dir);
        assert!(
            on_disk
                .grants_for(&Identity::Person(person("Mom")))
                .holds(&Capability::FilesRead(ShareId::parse("vault").unwrap())),
            "the previous file survived the refused write"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_persons_grants_are_what_the_policy_is_handed() {
        let dir = scratch("caller");
        let people = People::load(&dir);
        people.set_grants(&person("Mom"), read_grants()).unwrap();
        let caller = people.caller(Identity::Person(person("Mom")), Credential::Passkey);
        assert_eq!(caller.credential(), Credential::Passkey);
        assert!(caller.grants().holds(&Capability::FilesRead(ShareId::parse("vault").unwrap())));
        // Somebody with no entry is handed nothing, which is the same authority
        // as an entry with nothing in it.
        let stranger = people.caller(Identity::Person(person("Nobody")), Credential::Passkey);
        assert!(stranger.grants().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
