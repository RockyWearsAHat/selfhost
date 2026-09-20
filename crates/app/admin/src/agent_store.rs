//! Scoped, revocable credentials for trusted machines: an AI agent, a script,
//! a second box of Alex's — anything that is not a person at a keyboard and
//! not this box's own fixed automation, but that Alex has explicitly decided
//! to hand a bounded slice of authority.
//!
//! # Why this exists at all
//!
//! Before this store, exactly two nameless credentials could act on this
//! deployment: the console password (`Identity::Owner`, whose authority is
//! unconditional — see [`selfhost_identity::Policy::decide`]) and the bearer
//! token (`Identity::Machine`, whose authority is the *fixed* list the CLI and
//! the native console actually call, never a grant). Neither is safe to hand
//! an unattended agent process. The owner credential is too much — an agent
//! that only needs to manage sites should not also be able to touch storage,
//! the mesh, or the desktop, and a leaked owner password takes the whole box.
//! The bearer token is the wrong *shape* — its list is fixed in code, not
//! editable per-caller, so widening it for one agent widens it for the CLI and
//! the SSH-tunnelled console too, and it cannot be revoked without rotating
//! the file every other automated caller on the box also reads.
//!
//! So an agent gets its own identity ([`selfhost_identity::Identity::Agent`]),
//! its own credential shape (`agent:<name>:<secret>`, verified against this
//! store), and its own grant list — exactly the capabilities `selfhost agent
//! add <name> --grant <word>...` gave it, checked the same way a person's
//! grants are, through [`selfhost_identity::Policy::decide`]'s ordinary "hold
//! exactly what you were granted" rule. Nothing here is a blanket allow.
//!
//! # Read fresh on every verification, deliberately
//!
//! Mirrors [`crate::device_password`]'s design and for the identical reason:
//! the writer is `selfhost agent add|revoke`, a different process from the
//! daemon that verifies tokens on every request. A store loaded once and held
//! would mean a freshly minted agent is refused until the daemon restarts, and
//! a revoked one keeps working until it does — exactly the invite-flow bug
//! `docs/labs/first-run-lab.dx` already recorded once for a different store. So
//! [`AgentStore`] holds a path and nothing else, and every method reads the
//! file. The cost is the same as `device_password`'s: a few hundred bytes of
//! disk read in front of a comparison, on a request path that is not hot.
//!
//! # What is stored, and why a hash rather than the raw secret
//!
//! Each entry holds `sha256(secret)`, not `secret` itself — narrower exposure
//! if this file is ever read by something that should not (a backup, a bug
//! report, a second share of `data_dir`) across however many agents are
//! enrolled, the same reasoning `console.passwd` and `console.devicepw` apply
//! to a *person's* secret. It deliberately does **not** reuse
//! `selfhost_login::password`'s PBKDF2, though: that function's whole point is
//! defending a human-chosen, comparatively low-entropy password against
//! offline guessing, and it cost is ~70ms per verification for exactly that
//! reason. An agent's secret is never human-chosen — it is
//! [`crate::token::random_bytes`], the same 256-bit CSPRNG output
//! `admin.token` itself is — so slow-hashing it defends against a threat that
//! does not exist here and would instead tax every agent-authenticated
//! request by two orders of magnitude for nothing. A fast hash plus a
//! constant-time comparison (see [`crate::token::constant_time_eq`]) is the
//! right tool for a secret this large; `admin.token` makes the same choice by
//! storing its secret unhashed under a permissions boundary; hashing here is
//! one more knowingly-cheap step for a value that lives inside a JSON file
//! alongside other agents' rather than alone.
//!
//! # Fail-closed, and quiet about which half was wrong
//!
//! A missing file means no agent exists: every lookup answers "no entry", and
//! every route demanding an agent's grants is refused the ordinary
//! uninformative 401. A malformed file is treated as empty rather than
//! partially parsed — the same rule [`crate::device_password`] and
//! `selfhost_identity::registry` apply to their own stores, for the same
//! reason: a credential store that is partly understood is one whose meaning
//! depends on which build is reading it.
//!
//! Verification reports only true or false. An unknown name and a wrong
//! secret are indistinguishable from outside, the same rule every other door
//! in this deployment follows.

use selfhost_identity::{AgentName, Capability, Grants, PersonName};
use selfhost_json::Json;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The name of the agent-credential file inside the data directory.
pub const AGENT_STORE_FILENAME: &str = "console.agents";

/// The most agents this store will hold.
///
/// Small and deliberate: this is a short, hand-maintained list of machines
/// Alex has personally decided to trust, not a general user base. Anyone
/// needing more than this many distinct trusted machines is past what a flat
/// file and a CLI command are the right shape for.
pub const MAX_AGENTS: usize = 16;

/// Bytes of entropy in a minted agent secret. Matches [`crate::token::Token`]'s
/// own [`crate::token::TOKEN_BYTES`]-equivalent choice: 256 bits, the same
/// unguessability this deployment already trusts its root credential to.
const SECRET_BYTES: usize = 32;

/// The scoped, revocable agent credentials, as a handle onto the file.
///
/// Cheap to clone and holds no secret in memory — see this module's
/// documentation for why every method reads the file fresh.
#[derive(Debug, Clone)]
pub struct AgentStore {
    path: PathBuf,
}

/// One Agent as the operator audits it — everything stored except the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    /// The name it authenticates as.
    pub name: AgentName,
    /// What it was minted with. What it may *do* is this narrowed to its
    /// Person's current Grants — see [`Agent::effective_grants`].
    pub grants: Grants,
    /// When it was minted.
    pub created_unix: u64,
    /// The Person it acts for; `None` only for an entry written before Agents
    /// were bound to a Person, which holds nothing until it is re-minted.
    pub person: Option<PersonName>,
}

impl Agent {
    /// What this Agent may do right now: its minted Grants narrowed to what
    /// its Person holds in `people` at this moment.
    ///
    /// This one function is the whole confinement rule. An unbound Agent, or
    /// one whose Person is no longer registered, holds nothing; a Grant taken
    /// from the Person is gone from the Agent on the same read.
    pub fn effective_grants(&self, people: &selfhost_identity::People) -> Grants {
        match self.person.as_ref().and_then(|person| people.find(person)) {
            Some(person) => self.grants.within(&person.grants),
            None => Grants::none(),
        }
    }
}

/// Why an Agent could not be minted for a Person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintRefused {
    /// Nobody of that name is in the People registry.
    NoSuchPerson(PersonName),
    /// The Person does not hold these capabilities, so their Agent may not.
    BeyondPerson(PersonName, Vec<Capability>),
}

impl std::fmt::Display for MintRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSuchPerson(person) => write!(
                f,
                "\"{person}\" is not a registered Person; add them first with `selfhost people grant`"
            ),
            Self::BeyondPerson(person, beyond) => {
                let words: Vec<String> = beyond.iter().map(crate::people_api::wire_word).collect();
                write!(
                    f,
                    "\"{person}\" does not hold {}; an Agent can never hold more than its Person",
                    words.join(", ")
                )
            }
        }
    }
}

impl std::error::Error for MintRefused {}

/// Checks that `grants` may be minted for `person`: the Person is registered
/// and holds every capability asked for. The same ceiling
/// [`Agent::effective_grants`] applies on every request, checked up front so
/// the operator is told instead of handed a token that silently does less.
pub fn check_mint(
    people: &selfhost_identity::People,
    person: &PersonName,
    grants: &Grants,
) -> Result<(), MintRefused> {
    let registered = people.find(person).ok_or_else(|| MintRefused::NoSuchPerson(person.clone()))?;
    let beyond = grants.beyond(&registered.grants);
    if beyond.is_empty() {
        Ok(())
    } else {
        Err(MintRefused::BeyondPerson(person.clone(), beyond))
    }
}

/// One agent's stored entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    /// The name this agent authenticates as — `Identity::Agent(name)`.
    name: AgentName,
    /// `sha256(secret)`, lowercase hex. See this module's documentation for
    /// why a fast hash is the right choice for this credential.
    secret_hash: String,
    /// What this agent was granted. Checked exactly as a person's grants are,
    /// through `Policy::decide`'s "hold exactly what you were granted" rule —
    /// never a blanket allow, and never consulted for anything this agent was
    /// not explicitly given.
    grants: Grants,
    /// When this agent was minted, for `selfhost agent list`. Not a security
    /// field.
    created_unix: u64,
    /// The Person this Agent acts for. Enforced, not decorative: see
    /// [`Agent::effective_grants`] (the ceiling) and
    /// [`AgentStore::revoke_for_person`] (forgetting the Person). `None` only
    /// for an entry written before this field existed.
    person: Option<PersonName>,
}

impl Entry {
    fn into_agent(self) -> Agent {
        Agent { name: self.name, grants: self.grants, created_unix: self.created_unix, person: self.person }
    }
}

/// Why a submitted grant word could not be stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidGrant {
    /// The text is not a capability this deployment has a word for, or names
    /// one with a target it does not take.
    Unknown(String),
}

impl std::fmt::Display for InvalidGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown(text) => write!(
                f,
                "\"{text}\" is not a capability this deployment knows; \
                 see `selfhost people vocabulary` for every word"
            ),
        }
    }
}

impl std::error::Error for InvalidGrant {}

/// A freshly minted agent's whole token, shown to the operator exactly once.
///
/// A distinct type from a plain `String` so a caller cannot accidentally log
/// or persist it under a name that does not say what it is — the same
/// discipline [`crate::token::Token`]'s deliberately unrevealing [`std::fmt::Debug`]
/// applies, given a stronger enforcement here because this value is meant to
/// be printed exactly once and never stored by this process at all.
#[derive(Clone)]
pub struct MintedToken(String);

impl MintedToken {
    /// The token as it belongs in `SELFHOST_AGENT_TOKEN` or
    /// `~/.selfhost/agent-token` on the trusted machine — `agent:<name>:<secret>`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for MintedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MintedToken(<redacted>)")
    }
}

impl AgentStore {
    /// A handle onto `<data_dir>/console.agents`. Does not read anything and
    /// cannot fail, for the same reason [`crate::device_password::DevicePasswords::in_dir`]
    /// cannot: a deployment with no agents yet must not be an error.
    pub fn in_dir(data_dir: &Path) -> Self {
        Self { path: Self::path_in(data_dir) }
    }

    /// Where the file lives for a given data directory.
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(AGENT_STORE_FILENAME)
    }

    /// Verifies a presented `(name, secret)` pair and answers the Agent if it
    /// matches. The caller narrows it with [`Agent::effective_grants`].
    ///
    /// `None` for an unknown name, a wrong secret, an unreadable or malformed
    /// store alike — see this module's documentation for why that is a
    /// deliberate uniformity rather than a missing case. Constant-time against
    /// the stored hash once a candidate entry is found, via
    /// [`crate::token::constant_time_eq`].
    pub fn verify(&self, name: &AgentName, secret: &str) -> Option<Agent> {
        let entry = self.entries().into_iter().find(|entry| &entry.name == name)?;
        let candidate = hash_secret(secret);
        if crate::token::constant_time_eq(entry.secret_hash.as_bytes(), candidate.as_bytes()) {
            Some(entry.into_agent())
        } else {
            None
        }
    }

    /// Every agent this store holds, for `selfhost agent list`. Never the
    /// secret — only what the operator needs to audit who can do what.
    pub fn list(&self) -> Vec<Agent> {
        self.entries().into_iter().map(Entry::into_agent).collect()
    }

    /// Mints a new agent, replacing any existing entry of the same name, and
    /// returns the whole token — shown to the operator exactly once, never
    /// stored by this process beyond the return value.
    ///
    /// # Errors
    ///
    /// A store already at [`MAX_AGENTS`] with no entry for this name, a random
    /// source that refuses to produce a secret, or a write that fails. The
    /// write goes to a temporary sibling and is renamed over the file, so a
    /// crash mid-write leaves the previous credentials rather than half of the
    /// new ones.
    pub fn mint(&self, name: &AgentName, grants: Grants, person: &PersonName) -> io::Result<MintedToken> {
        let secret = crate::token::hex(&crate::token::random_bytes(SECRET_BYTES)?);
        let secret_hash = hash_secret(&secret);

        let mut entries = self.entries();
        match entries.iter_mut().find(|entry| &entry.name == name) {
            Some(entry) => {
                entry.secret_hash = secret_hash;
                entry.grants = grants;
                entry.created_unix = now_unix();
                entry.person = Some(person.clone());
            }
            None => {
                if entries.len() >= MAX_AGENTS {
                    return Err(io::Error::other(format!(
                        "at most {MAX_AGENTS} agents may be enrolled — revoke one first with \
                         `selfhost agent revoke <name>`"
                    )));
                }
                entries.push(Entry {
                    name: name.clone(),
                    secret_hash,
                    grants,
                    created_unix: now_unix(),
                    person: Some(person.clone()),
                });
            }
        }
        self.persist(&entries)?;
        Ok(MintedToken(format!("agent:{name}:{secret}")))
    }

    /// Revokes one agent's credential; `true` if it had one.
    ///
    /// Every request that agent's token authenticates stops working on the
    /// daemon's very next verification, per this store's read-fresh
    /// discipline — there is nothing to restart.
    pub fn revoke(&self, name: &AgentName) -> io::Result<bool> {
        let mut entries = self.entries();
        let before = entries.len();
        entries.retain(|entry| &entry.name != name);
        if entries.len() == before {
            return Ok(false);
        }
        self.persist(&entries)?;
        Ok(true)
    }

    /// Revokes every Agent acting for `person`, answering how many there were.
    /// Called when the Person is forgotten, so no credential outlives them.
    pub fn revoke_for_person(&self, person: &PersonName) -> io::Result<usize> {
        let mut entries = self.entries();
        let before = entries.len();
        entries.retain(|entry| entry.person.as_ref() != Some(person));
        let revoked = before - entries.len();
        if revoked > 0 {
            self.persist(&entries)?;
        }
        Ok(revoked)
    }

    /// The stored entries, or none at all if the file is missing or malformed.
    fn entries(&self) -> Vec<Entry> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
            Err(error) => {
                eprintln!(
                    "admin: could not read {}: {error}; no agent token opens anything",
                    self.path.display()
                );
                return Vec::new();
            }
        };
        match parse(&text) {
            Some(entries) => entries,
            None => {
                eprintln!(
                    "admin: {} is not a valid agent-store file; no agent token opens anything \
                     until it is repaired or removed",
                    self.path.display()
                );
                Vec::new()
            }
        }
    }

    /// Writes the store owner-only through a temporary file and a rename.
    fn persist(&self, entries: &[Entry]) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = self.path.with_extension("agents.new");
        crate::token::write_private(&temporary, &to_json(entries).to_text())?;
        std::fs::rename(&temporary, &self.path)
    }
}

/// Parses one capability word into a [`Capability`], for `selfhost agent add
/// --grant <word>`. A thin, named wrapper so the CLI's error carries this
/// module's own message rather than a bare `None`.
pub fn parse_grant(word: &str) -> Result<Capability, InvalidGrant> {
    Capability::parse(word).ok_or_else(|| InvalidGrant::Unknown(word.to_owned()))
}

/// `sha256(secret)`, lowercase hex. See this module's documentation for why a
/// fast hash — not PBKDF2 — is the right tool for a CSPRNG-generated secret.
fn hash_secret(secret: &str) -> String {
    crate::token::hex(&sha256(secret.as_bytes()))
}

/// SHA-256, via `ring` — already the whole workspace's TLS provider (see
/// `crates/app/cli/src/remote_client.rs`), so this reaches for no new
/// dependency.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// Seconds since the Unix epoch, or zero on a clock set before it.
fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|since| since.as_secs()).unwrap_or(0)
}

/// The stored shape: `{"agents":[{name, secretHash, grants, createdUnix, person}]}`.
fn to_json(entries: &[Entry]) -> Json {
    Json::object([(
        "agents",
        Json::array(entries.iter().map(|entry| {
            Json::object([
                ("name", Json::string(entry.name.as_str())),
                ("secretHash", Json::string(&entry.secret_hash)),
                (
                    "grants",
                    Json::array(entry.grants.iter().map(|capability| {
                        Json::string(crate::people_api::wire_word(capability))
                    })),
                ),
                ("createdUnix", Json::Number(entry.created_unix as f64)),
                (
                    "person",
                    entry.person.as_ref().map_or(Json::Null, |person| Json::string(person.as_str())),
                ),
            ])
        })),
    )])
}

/// Parses the stored file, or `None` for anything at all that is malformed.
///
/// A name that is not a valid [`AgentName`], a duplicate name, a missing
/// field, more than [`MAX_AGENTS`] entries, a grant word this build does not
/// know, a hash that is not 64 lowercase hex characters, or a `person` that is
/// not a valid [`PersonName`] — every one of them refuses the whole document,
/// for the reason this module's own documentation gives.
///
/// An *absent* `person` is not malformed: it is what every entry written
/// before Agents were bound to a Person looks like. Such an entry is kept
/// (refusing the document would let the next mint overwrite every one of them)
/// and holds nothing until re-minted with `--person`.
fn parse(text: &str) -> Option<Vec<Entry>> {
    let value = selfhost_json::parse(text).ok()?;
    let items = value.get("agents")?.as_array()?;
    if items.len() > MAX_AGENTS {
        return None;
    }
    let mut entries: Vec<Entry> = Vec::new();
    for item in items {
        let name = AgentName::parse(item.get("name")?.as_str()?).ok()?;
        if entries.iter().any(|entry| entry.name == name) {
            return None;
        }
        let secret_hash = item.get("secretHash")?.as_str()?.to_owned();
        if !is_sha256_hex(&secret_hash) {
            return None;
        }
        let grant_words = item.get("grants")?.as_array()?;
        let mut capabilities = Vec::with_capacity(grant_words.len());
        for word in grant_words {
            capabilities.push(Capability::parse(word.as_str()?)?);
        }
        let grants = Grants::new(capabilities).ok()?;
        let created_unix = item.get("createdUnix")?.as_u64()?;
        let person = match item.get("person") {
            None | Some(Json::Null) => None,
            Some(value) => Some(PersonName::parse(value.as_str()?).ok()?),
        };
        entries.push(Entry { name, secret_hash, grants, created_unix, person });
    }
    Some(entries)
}

/// Whether `text` is 64 lowercase hex characters — exactly what [`hash_secret`]
/// produces. Checked at parse time so a hand-edited file that put something
/// else in `secretHash` is a refused document rather than a hash that never
/// matches and takes an afternoon to explain.
fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_identity::Capability;

    fn scratch(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("selfhost-agentstore-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        path
    }

    fn person(name: &str) -> PersonName {
        PersonName::parse(name).expect("a valid person name")
    }

    fn agent(name: &str) -> AgentName {
        AgentName::parse(name).expect("a valid name")
    }

    #[test]
    fn a_minted_agent_verifies_with_its_own_token_and_nothing_else() {
        let dir = scratch("roundtrip");
        let store = AgentStore::in_dir(&dir);
        let grants = Grants::new([Capability::SiteAdmin]).unwrap();
        let minted = store.mint(&agent("claude-mac"), grants.clone(), &person("Alex")).expect("mints");

        let (name, secret) = split(minted.as_str());
        assert_eq!(store.verify(&agent(&name), &secret).map(|agent| agent.grants), Some(grants));
        assert!(store.verify(&agent(&name), "wrong-secret").is_none());
        assert!(store.verify(&agent("somebody-else"), &secret).is_none());
    }

    #[test]
    fn a_revoked_agent_stops_verifying_immediately() {
        let dir = scratch("revoke");
        let store = AgentStore::in_dir(&dir);
        let minted = store.mint(&agent("claude-mac"), Grants::none(), &person("Alex")).expect("mints");
        let (name, secret) = split(minted.as_str());

        assert!(store.verify(&agent(&name), &secret).is_some());
        assert!(store.revoke(&agent("claude-mac")).expect("revokes"));
        assert!(store.verify(&agent(&name), &secret).is_none(), "revoked immediately, no restart");
        assert!(!store.revoke(&agent("claude-mac")).expect("a second revoke is not an error"));
    }

    #[test]
    fn a_second_process_sees_a_mint_without_being_told() {
        // The whole reason this store reads fresh: the writer (`selfhost agent
        // add`) and the reader (the daemon verifying a request) are different
        // processes, exactly as `device_password`'s module documentation
        // argues for the same shape of store.
        let dir = scratch("cross-process");
        let writer = AgentStore::in_dir(&dir);
        let reader = AgentStore::in_dir(&dir);
        assert_eq!(reader.list().len(), 0);

        let minted = writer.mint(&agent("claude-mac"), Grants::none(), &person("Alex")).expect("mints");
        let (name, secret) = split(minted.as_str());
        assert!(reader.verify(&agent(&name), &secret).is_some(), "the second handle sees it too");
    }

    #[test]
    fn a_malformed_store_opens_nothing_rather_than_half_of_it() {
        let dir = scratch("malformed");
        std::fs::write(AgentStore::path_in(&dir), "not json at all").unwrap();
        let store = AgentStore::in_dir(&dir);
        assert_eq!(store.list().len(), 0);
        assert!(store.verify(&agent("claude-mac"), "anything").is_none());
    }

    #[test]
    fn listing_never_reveals_a_secret() {
        let dir = scratch("list");
        let store = AgentStore::in_dir(&dir);
        let grants = Grants::new([Capability::SiteAdmin]).unwrap();
        let minted = store.mint(&agent("claude-mac"), grants, &person("Alex")).expect("mints");
        let (name, secret) = split(minted.as_str());

        let listed = store.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name.as_str(), name);
        assert_eq!(listed[0].person, Some(person("Alex")));
        // The token itself, and therefore the secret, appears nowhere the
        // listing could leak it — only in the one `MintedToken` handed back at
        // mint time.
        assert!(!format!("{listed:?}").contains(&secret));
    }

    #[test]
    fn more_than_the_cap_is_refused() {
        let dir = scratch("cap");
        let store = AgentStore::in_dir(&dir);
        for i in 0..MAX_AGENTS {
            store.mint(&agent(&format!("agent-{i}")), Grants::none(), &person("Alex")).expect("under the cap");
        }
        assert!(store.mint(&agent("one-too-many"), Grants::none(), &person("Alex")).is_err());
    }

    #[test]
    fn a_store_written_before_agents_had_a_person_is_kept_not_erased() {
        // Regression: a missing `person` key used to refuse the whole
        // document, so the next mint overwrote every pre-existing Agent.
        let dir = scratch("legacy");
        let hash = "a".repeat(64);
        std::fs::write(
            AgentStore::path_in(&dir),
            format!(
                r#"{{"agents":[{{"name":"old-bot","secretHash":"{hash}","grants":["site.admin"],"createdUnix":1}}]}}"#
            ),
        )
        .unwrap();
        let store = AgentStore::in_dir(&dir);
        assert_eq!(store.list().len(), 1);
        assert_eq!(store.list()[0].person, None);

        store.mint(&agent("new-bot"), Grants::none(), &person("Alex")).expect("mints");
        let names: Vec<String> = store.list().iter().map(|a| a.name.as_str().to_owned()).collect();
        assert_eq!(names, ["old-bot", "new-bot"], "the old entry survives a mint and a rewrite");
        assert_eq!(store.list()[0].person, None, "and round-trips as still unbound");
    }

    #[test]
    fn an_agent_holds_only_what_its_person_holds_right_now() {
        let dir = scratch("ceiling");
        let people = selfhost_identity::People::load(&dir);
        let store = AgentStore::in_dir(&dir);
        let alex = person("Alex");
        people.set_grants(&alex, Grants::new([Capability::SiteAdmin, Capability::ConsoleRead]).unwrap()).unwrap();
        store
            .mint(&agent("bot"), Grants::new([Capability::SiteAdmin, Capability::ConsoleRead]).unwrap(), &alex)
            .unwrap();
        let bot = store.list().remove(0);
        assert!(bot.effective_grants(&people).holds(&Capability::SiteAdmin));

        // A Grant taken from the Person is gone from the Agent.
        people.set_grants(&alex, Grants::new([Capability::ConsoleRead]).unwrap()).unwrap();
        let narrowed = bot.effective_grants(&people);
        assert!(!narrowed.holds(&Capability::SiteAdmin));
        assert!(narrowed.holds(&Capability::ConsoleRead));

        // A forgotten Person leaves the Agent nothing, and an unbound one too.
        people.remove(&alex).unwrap();
        assert!(bot.effective_grants(&people).is_empty());
        let unbound = Agent { person: None, ..bot };
        assert!(unbound.effective_grants(&people).is_empty());
    }

    #[test]
    fn minting_is_refused_for_an_unknown_person_or_beyond_their_grants() {
        let dir = scratch("check-mint");
        let people = selfhost_identity::People::load(&dir);
        let intern = person("intern");
        let wanted = Grants::new([Capability::SiteAdmin]).unwrap();
        assert_eq!(check_mint(&people, &intern, &wanted), Err(MintRefused::NoSuchPerson(intern.clone())));

        people.set_grants(&intern, Grants::new([Capability::ConsoleRead]).unwrap()).unwrap();
        assert_eq!(
            check_mint(&people, &intern, &wanted),
            Err(MintRefused::BeyondPerson(intern.clone(), vec![Capability::SiteAdmin]))
        );
        assert_eq!(check_mint(&people, &intern, &Grants::new([Capability::ConsoleRead]).unwrap()), Ok(()));
    }

    #[test]
    fn forgetting_a_person_revokes_exactly_their_agents() {
        let dir = scratch("revoke-for-person");
        let store = AgentStore::in_dir(&dir);
        store.mint(&agent("a1"), Grants::none(), &person("Alex")).unwrap();
        store.mint(&agent("a2"), Grants::none(), &person("Alex")).unwrap();
        store.mint(&agent("c1"), Grants::none(), &person("Claude")).unwrap();
        assert_eq!(store.revoke_for_person(&person("Alex")).unwrap(), 2);
        let left = store.list();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].name.as_str(), "c1");
        assert_eq!(store.revoke_for_person(&person("Alex")).unwrap(), 0);
    }

    /// Splits a minted token's `agent:<name>:<secret>` shape for a test that
    /// wants to present the two halves the way a request would.
    fn split(token: &str) -> (String, String) {
        let rest = token.strip_prefix("agent:").expect("mint always produces this prefix");
        let (name, secret) = rest.split_once(':').expect("mint always produces this shape");
        (name.to_owned(), secret.to_owned())
    }
}
