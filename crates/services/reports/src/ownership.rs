//! Who owns a service, what their plan lets them hold, and the reader token scoped to it.
//!
//! The box's owner token reads every service's feed, which is exactly right for the operator
//! and exactly wrong for anyone else: the moment another person's service lives here, handing
//! them that token would hand them the whole database. This module is the scoped alternative —
//! a registered account *claims* a service at creation and holds a reader token that opens
//! `feed`/`close` for that one service and nothing else. The owner token never has to leave
//! the operator again.
//!
//! # Digest-only, like the verification tokens
//!
//! The store keeps the SHA-256 of a reader token, never the token itself — the same rule
//! [`crate::verify`] follows, and for the same reason: a file nobody can read a working
//! credential out of is worth more than one that can be stolen whole. The plaintext is
//! answered exactly once, at creation or rotation, and is otherwise unrecoverable.
//!
//! # A plan is a word with caps, fail-closed
//!
//! [`Account::plan`](crate::accounts::Account::plan) has always been a stored word with
//! nothing behind it; [`Plan`] is what it now means. An unknown word parses as [`Plan::Free`]
//! — the smaller allowance — so a typo in an operator-edited file can never widen anyone's
//! limits. Nothing here charges anyone: the caps are what a later billing integration prices.
//!
//! # The store is one file, like the sibling credential stores
//!
//! `<data_dir>/services.json` beside `accounts.json`, loaded whole, rewritten owner-only by
//! temporary file and rename. It is bounded by the same [`crate::store::MAX_PROJECTS`] that
//! bounds the report database itself, so this file can never outgrow the thing it describes.

use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use selfhost_json::Json;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// The name of the ownership file inside the accounts data directory.
pub const SERVICES_FILENAME: &str = "services.json";

/// How many services one free account may own.
pub const FREE_SERVICES: usize = 2;
/// How many distinct defects one free service may hold before a fresh one is refused.
pub const FREE_RECORDS: usize = 500;
/// How many bytes one free service may hold before a fresh defect is refused.
pub const FREE_BYTES: u64 = 25 * 1024 * 1024;
/// How many services one pro account may own.
pub const PRO_SERVICES: usize = 20;
/// How many distinct defects one pro service may hold — the box's own per-service cap.
pub const PRO_RECORDS: usize = crate::store::MAX_RECORDS;
/// How many bytes one pro service may hold before a fresh defect is refused.
pub const PRO_BYTES: u64 = 500 * 1024 * 1024;

/// What a stored plan word means. Parsed fresh at every enforcement point, so changing an
/// account's word changes its limits on the next request with no restart and no migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// The default: enough to run a small project's intake, not enough to cost the box much.
    Free,
    /// The paid tier — wider on every axis, still bounded by the box's own caps.
    Pro,
}

/// The limits one plan grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// How many services an account on this plan may own.
    pub services: usize,
    /// How many distinct defects each of its services may hold.
    pub records_per_service: usize,
    /// How many bytes each of its services may hold.
    pub bytes_per_service: u64,
}

impl Plan {
    /// The plan a stored word names. Anything that is not exactly `pro` is [`Plan::Free`] —
    /// fail-closed, so corruption or a typo can only ever narrow an allowance, never widen it.
    #[must_use]
    pub fn parse(word: &str) -> Self {
        if word.trim().eq_ignore_ascii_case("pro") {
            Self::Pro
        } else {
            Self::Free
        }
    }

    /// This plan's limits.
    #[must_use]
    pub fn caps(self) -> Caps {
        match self {
            Self::Free => Caps {
                services: FREE_SERVICES,
                records_per_service: FREE_RECORDS,
                bytes_per_service: FREE_BYTES,
            },
            Self::Pro => Caps {
                services: PRO_SERVICES,
                records_per_service: PRO_RECORDS,
                bytes_per_service: PRO_BYTES,
            },
        }
    }

    /// The word this plan is stored and shown as.
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Pro => "pro",
        }
    }
}

/// One owned service, as the file holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owned {
    /// The service key, exactly as it names a directory in the report store.
    pub service: String,
    /// The owning account's id.
    pub owner: String,
    /// Lowercase hex SHA-256 of the reader token — never the token itself.
    pub reader_digest: String,
    /// When the service was claimed, seconds since the Unix epoch.
    pub created_unix: u64,
}

/// The ownership store rooted at one accounts data directory.
#[derive(Clone)]
pub struct Owners {
    path: PathBuf,
    entries: Arc<Mutex<Vec<Owned>>>,
}

impl Owners {
    /// Loads the store from `<data_dir>/services.json`.
    ///
    /// A missing file is an empty store. A malformed one loads empty and says so once — the
    /// fail-closed shape every credential file in this workspace takes, and safe here because
    /// the plaintext tokens are elsewhere: losing this file costs each owner one rotation,
    /// never a leak.
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join(SERVICES_FILENAME);
        let entries = match std::fs::read_to_string(&path) {
            Ok(text) => match parse_owned(&text) {
                Some(entries) => entries,
                None => {
                    eprintln!(
                        "reports: {} is not a valid service-ownership file; owned services are \
                         unreadable until it is repaired or removed",
                        path.display()
                    );
                    Vec::new()
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => {
                eprintln!(
                    "reports: could not read {}: {error}; owned services are unreadable",
                    path.display()
                );
                Vec::new()
            }
        };
        Self {
            path,
            entries: Arc::new(Mutex::new(entries)),
        }
    }

    /// Claims `service` for `owner`, minting its reader token — returned exactly once; only
    /// its digest is stored.
    ///
    /// # Errors
    /// A sentence when the service is already claimed, the store is at
    /// [`crate::store::MAX_PROJECTS`], the system's random source refuses, or the file cannot
    /// be written.
    pub fn claim(&self, service: &str, owner: &str) -> Result<String, String> {
        let mut entries = self.lock();
        if entries.iter().any(|entry| entry.service == service) {
            return Err(format!("`{service}` is already claimed"));
        }
        if entries.len() >= crate::store::MAX_PROJECTS {
            return Err(format!(
                "this box already holds {} services, so `{service}` cannot be added",
                crate::store::MAX_PROJECTS
            ));
        }
        let token = mint_token()?;
        entries.push(Owned {
            service: service.to_string(),
            owner: owner.to_string(),
            reader_digest: digest_hex(&token),
            created_unix: now_unix(),
        });
        self.persist(&entries)
            .map_err(|error| format!("could not write {}: {error}", self.path.display()))?;
        Ok(token)
    }

    /// The account that owns `service`, if anyone does. A service with no row here is the
    /// operator's own — grandfathered, metered by the box's global caps alone.
    #[must_use]
    pub fn owner_of(&self, service: &str) -> Option<String> {
        self.lock()
            .iter()
            .find(|entry| entry.service == service)
            .map(|entry| entry.owner.clone())
    }

    /// Every service `owner` holds, alphabetically.
    #[must_use]
    pub fn owned_by(&self, owner: &str) -> Vec<String> {
        let mut services: Vec<String> = self
            .lock()
            .iter()
            .filter(|entry| entry.owner == owner)
            .map(|entry| entry.service.clone())
            .collect();
        services.sort();
        services
    }

    /// Every row, for the operator's own listing.
    #[must_use]
    pub fn entries(&self) -> Vec<Owned> {
        self.lock().clone()
    }

    /// Rotates `service`'s reader token — only for its owner. `None` for an unknown service
    /// *and* for someone else's, deliberately the same answer, so a rotation probe cannot sort
    /// service names by who owns them.
    ///
    /// # Errors
    /// A sentence when the random source refuses or the file cannot be written.
    pub fn rotate(&self, service: &str, owner: &str) -> Result<Option<String>, String> {
        let mut entries = self.lock();
        let Some(entry) = entries
            .iter_mut()
            .find(|entry| entry.service == service && entry.owner == owner)
        else {
            return Ok(None);
        };
        let token = mint_token()?;
        entry.reader_digest = digest_hex(&token);
        self.persist(&entries)
            .map_err(|error| format!("could not write {}: {error}", self.path.display()))?;
        Ok(Some(token))
    }

    /// Whether `offered` is `service`'s reader token.
    ///
    /// The whole table is walked and both comparisons accumulate rather than short-circuit —
    /// the stated project convention for credential lookups — so timing does not sort service
    /// names into claimed and unclaimed.
    #[must_use]
    pub fn verify_reader(&self, service: &str, offered: &str) -> bool {
        let offered_digest = digest_hex(offered);
        let mut matched = false;
        for entry in self.lock().iter() {
            let service_matches = constant_time_eq(entry.service.as_bytes(), service.as_bytes());
            let digest_matches =
                constant_time_eq(entry.reader_digest.as_bytes(), offered_digest.as_bytes());
            matched |= service_matches && digest_matches;
        }
        matched
    }

    /// Writes the store owner-only via a temporary file and rename, like every sibling
    /// credential store.
    fn persist(&self, entries: &[Owned]) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = owned_to_json(entries).to_text();
        let temporary = self.path.with_extension("json.tmp");
        std::fs::write(&temporary, &text)?;
        restrict(&temporary);
        std::fs::rename(&temporary, &self.path)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Owned>> {
        self.entries
            .lock()
            .expect("the ownership store lock was poisoned")
    }
}

// The digests are one-way, but the owner column is still a join from service names to account
// ids nobody asked to put in a log line.
impl std::fmt::Debug for Owners {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "Owners({} claimed)", self.lock().len())
    }
}

/// The stored file's JSON shape: `{"services": [{service, owner, readerDigest, createdUnix}]}`.
fn owned_to_json(entries: &[Owned]) -> Json {
    Json::object([(
        "services",
        Json::array(entries.iter().map(|entry| {
            Json::object([
                ("service", Json::string(&entry.service)),
                ("owner", Json::string(&entry.owner)),
                ("readerDigest", Json::string(&entry.reader_digest)),
                ("createdUnix", Json::Number(entry.created_unix as f64)),
            ])
        })),
    )])
}

/// Parses the stored file. `None` for anything malformed — a duplicate service included, since
/// that could only be corruption and would let one name answer to two owners.
fn parse_owned(text: &str) -> Option<Vec<Owned>> {
    let value = selfhost_json::parse(text).ok()?;
    let items = value.get("services")?.as_array()?;
    if items.len() > crate::store::MAX_PROJECTS {
        return None;
    }
    let mut entries: Vec<Owned> = Vec::new();
    for item in items {
        let service = item.get("service")?.as_str()?.to_owned();
        if entries.iter().any(|entry| entry.service == service) {
            return None;
        }
        entries.push(Owned {
            service,
            owner: item.get("owner")?.as_str()?.to_owned(),
            reader_digest: item.get("readerDigest")?.as_str()?.to_owned(),
            created_unix: item.get("createdUnix")?.as_f64()? as u64,
        });
    }
    Some(entries)
}

/// A fresh 256-bit reader token, lowercase hex.
///
/// # Errors
/// A sentence when the operating system's random source refuses.
fn mint_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "the system random source refused to mint a token".to_string())?;
    Ok(hex(&bytes))
}

/// Lowercase hex SHA-256 of `token` — what the store keeps instead of the token.
fn digest_hex(token: &str) -> String {
    hex(digest(&SHA256, token.as_bytes()).as_ref())
}

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            out.push_str(&format!("{byte:02x}"));
            out
        })
}

/// Byte-wise equality that spends the same time on a mismatch at any position.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Seconds since the Unix epoch, or zero on a clock set before it.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Restricts a file to its owner, where the platform has such a concept.
fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("selfhost-reports-ownership-tests")
            .join(format!("{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    #[test]
    fn a_claim_round_trips_through_the_file_and_the_token_is_digest_only_at_rest() {
        let dir = scratch("claim");
        let owners = Owners::load(&dir);
        let token = owners.claim("myapp", "acct-1").expect("claim");
        assert_eq!(token.len(), 64, "256 bits of hex");

        let stored = std::fs::read_to_string(dir.join(SERVICES_FILENAME)).expect("file");
        assert!(!stored.contains(&token), "the plaintext is never at rest");
        assert!(stored.contains(&digest_hex(&token)));

        let reloaded = Owners::load(&dir);
        assert_eq!(reloaded.owner_of("myapp").as_deref(), Some("acct-1"));
        assert!(reloaded.verify_reader("myapp", &token));
    }

    #[test]
    fn a_reader_token_opens_its_own_service_and_nothing_else() {
        let dir = scratch("scope");
        let owners = Owners::load(&dir);
        let mine = owners.claim("mine", "acct-1").expect("claim");
        let theirs = owners.claim("theirs", "acct-2").expect("claim");
        assert!(owners.verify_reader("mine", &mine));
        assert!(!owners.verify_reader("theirs", &mine));
        assert!(!owners.verify_reader("mine", &theirs));
        assert!(!owners.verify_reader("mine", ""));
        assert!(!owners.verify_reader("unclaimed", &mine));
    }

    #[test]
    fn a_service_cannot_be_claimed_twice() {
        let dir = scratch("twice");
        let owners = Owners::load(&dir);
        owners.claim("myapp", "acct-1").expect("claim");
        let refused = owners
            .claim("myapp", "acct-2")
            .expect_err("already claimed");
        assert!(refused.contains("already claimed"), "{refused}");
    }

    #[test]
    fn rotation_is_the_owners_alone_and_kills_the_old_token() {
        let dir = scratch("rotate");
        let owners = Owners::load(&dir);
        let old = owners.claim("myapp", "acct-1").expect("claim");

        assert_eq!(owners.rotate("myapp", "acct-2").expect("rotate"), None);
        assert_eq!(owners.rotate("ghost", "acct-1").expect("rotate"), None);

        let fresh = owners
            .rotate("myapp", "acct-1")
            .expect("rotate")
            .expect("owner rotates");
        assert!(!owners.verify_reader("myapp", &old));
        assert!(owners.verify_reader("myapp", &fresh));
    }

    #[test]
    fn owned_by_lists_alphabetically_and_only_the_owners_own() {
        let dir = scratch("owned-by");
        let owners = Owners::load(&dir);
        owners.claim("zeta", "acct-1").expect("claim");
        owners.claim("alpha", "acct-1").expect("claim");
        owners.claim("other", "acct-2").expect("claim");
        assert_eq!(owners.owned_by("acct-1"), vec!["alpha", "zeta"]);
        assert_eq!(owners.owned_by("acct-3"), Vec::<String>::new());
    }

    #[test]
    fn a_malformed_file_loads_empty_rather_than_half_parsed() {
        let dir = scratch("malformed");
        std::fs::write(dir.join(SERVICES_FILENAME), "not json").expect("write");
        assert!(Owners::load(&dir).entries().is_empty());
        // A duplicate service name is corruption, not data.
        std::fs::write(
            dir.join(SERVICES_FILENAME),
            r#"{"services":[
                {"service":"a","owner":"x","readerDigest":"d","createdUnix":1},
                {"service":"a","owner":"y","readerDigest":"d","createdUnix":1}
            ]}"#,
        )
        .expect("write");
        assert!(Owners::load(&dir).entries().is_empty());
    }

    #[test]
    fn an_unknown_plan_word_is_free_and_the_caps_are_ordered() {
        assert_eq!(Plan::parse("pro"), Plan::Pro);
        assert_eq!(Plan::parse("  PRO "), Plan::Pro);
        assert_eq!(Plan::parse("free"), Plan::Free);
        assert_eq!(Plan::parse("supporter"), Plan::Free, "unknown narrows");
        assert_eq!(Plan::parse(""), Plan::Free);

        let free = Plan::Free.caps();
        let pro = Plan::Pro.caps();
        assert!(free.services < pro.services);
        assert!(free.records_per_service < pro.records_per_service);
        assert!(free.bytes_per_service < pro.bytes_per_service);
        assert!(pro.records_per_service <= crate::store::MAX_RECORDS);
    }
}
