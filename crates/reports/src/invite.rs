//! The one-time code that links a reports account to a name `crates/identity` already knows.
//!
//! # The gap this closes, stated so nobody re-derives it
//!
//! A reports account (`crate::accounts::Account`) is an email address that can log in and see
//! its own filed reports. `selfhost_identity::People` is what decides what a *named person* may
//! do elsewhere on this box — the NAS, the remote desktop, the console. Until this module
//! existed, the two never met: an account had no way to become the "Mom" that
//! `selfhost people allow mom files.read:vault` already granted something to, so signing up for
//! reports and being a person this deployment knows were two unrelated facts about the same
//! human. `crates/admin/src/invite.rs` solved exactly this shape once already, for the console's
//! own passkeys, and the shape here is deliberately the same one: a high-entropy code, bound to
//! one name the owner chose in advance, valid once, expiring on its own.
//!
//! # What an invite is, and what it very deliberately is not
//!
//! An invite authorises **exactly one act**: linking the reports account that redeems it to the
//! name written inside it. It is not a grant and it confers no capability of its own — it is the
//! missing wire between an account and a name that may, separately, already hold capabilities or
//! may hold nothing at all. Minting an invite and granting a capability stay two decisions made
//! through two different doors (`selfhost people allow`, never this module) for the same reason
//! `crates/admin/src/invite.rs` keeps them apart: an invite that carried grants would collapse
//! "prove you are this person" and "this person may do that" into one file, and a mistake in
//! either would look like a mistake in both.
//!
//! That is also why redemption takes the name from **here** and never from whoever is holding
//! the code: an invite for `mom` can only ever link an account to `mom`, however the code
//! travelled to get there.
//!
//! # Why the code is stored as a digest
//!
//! `<data_dir>/invites.json` — `data_dir` being the same directory `crate::accounts::Accounts`,
//! `crate::sessions::Sessions` and `crate::verify::Verifications` already share — holds the
//! SHA-256 of each code, never the code itself, for the reason every credential store in this
//! crate and its siblings gives: a backup of the data directory must not be a set of live
//! invitations. A lost code is a re-mint, not a lookup.
//!
//! The code itself is 24 random bytes rendered as lowercase hex rather than base64url. This
//! crate already hex-encodes random bytes the same way in `crate::accounts` and `crate::report`;
//! introducing a second encoding for one more store would be a second thing to get right for no
//! reader's benefit — hex is exactly as URL-safe, needs no escaping, and reads back with the
//! smallest possible decoder.
//!
//! # The bounds, and why each one is here
//!
//! An invite expires ([`DEFAULT_TTL_HOURS`], capped at [`MAX_TTL_HOURS`]) because an invitation
//! nobody is watching is a credential outstanding for no reason. Minting again for a name that
//! already has one outstanding *supersedes* it rather than adding a second, so "I lost the code,
//! send another" cannot leave two live codes for one name. The store is capped at
//! [`MAX_INVITES`], the same number `crates/admin/src/invite.rs` uses for the same reason: an
//! invite exists to produce a linked account, and the people registry behind it is bounded too.

use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use selfhost_identity::PersonName;
use selfhost_json::Json;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// The name of the invite file inside the accounts data directory.
pub const INVITES_FILENAME: &str = "invites.json";

/// The most outstanding invites the store will hold.
///
/// An arbitrary-but-sane small cap, not tied to `crates/admin`'s own store: reused here because
/// there is no reason for this door to allow more outstanding invitations than the console's.
pub const MAX_INVITES: usize = 32;

/// How long an invite lasts when the caller does not say.
///
/// Two days: long enough to send a message and have somebody read it on their own schedule,
/// short enough that a forgotten invitation closes itself.
pub const DEFAULT_TTL_HOURS: u64 = 48;

/// The longest life an invite may be given.
pub const MAX_TTL_HOURS: u64 = 24 * 14;

/// Bytes of entropy in a code: 192 bits, the same size `crates/admin/src/invite.rs` and
/// `crate::verify` both use.
const CODE_BYTES: usize = 24;

/// One outstanding invitation.
#[derive(Clone)]
pub struct Invite {
    /// The name a redeeming account will be linked to. Chosen by the owner when the invite was
    /// minted, and the reason redemption never reads a name from the request.
    pub name: PersonName,
    /// SHA-256 of the code. The code itself is not stored — see the module documentation.
    digest: Vec<u8>,
    /// When it was minted, as seconds since the Unix epoch.
    pub issued_unix: u64,
    /// When it stops being redeemable, as seconds since the Unix epoch.
    pub expires_unix: u64,
}

impl Invite {
    /// Whether this invite is still redeemable at `now` (Unix seconds).
    #[must_use]
    pub fn live_at(&self, now: u64) -> bool {
        now < self.expires_unix
    }
}

/// The durable invite store: `<data_dir>/invites.json`, owner-only, JSON.
///
/// A cheap-clone handle over shared state, like every other store in this crate: an invite
/// minted through one clone must be redeemable through another. A missing file is an empty
/// store; a malformed one loads empty and says so once, which fails closed — no invite can be
/// redeemed rather than some unknown subset being live.
#[derive(Clone)]
pub struct Invites {
    path: PathBuf,
    entries: Arc<Mutex<Vec<Invite>>>,
}

impl Invites {
    /// Loads the store from `<data_dir>/invites.json`.
    #[must_use]
    pub fn load(data_dir: &Path) -> Self {
        let path = Self::path_in(data_dir);
        let entries = match std::fs::read_to_string(&path) {
            Ok(text) => match parse_invites(&text) {
                Some(entries) => entries,
                None => {
                    eprintln!(
                        "reports: {} is not a valid invite file; no invitation can be redeemed \
                         until it is repaired or removed",
                        path.display()
                    );
                    Vec::new()
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => {
                eprintln!(
                    "reports: could not read {}: {error}; no invitation can be redeemed",
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

    /// Where the invite file lives for a given data directory.
    #[must_use]
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(INVITES_FILENAME)
    }

    /// Mints an invitation for `name`, returning the code — the only time it exists in a form
    /// anybody can read.
    ///
    /// `ttl_hours` is clamped to [`MAX_TTL_HOURS`] and treated as [`DEFAULT_TTL_HOURS`] when
    /// zero. Any outstanding invite for the same name is replaced rather than joined, so
    /// re-sending an invitation never leaves two live codes for one name.
    ///
    /// # Errors
    /// An [`io::Error`] naming what the random source or the write refused, or that
    /// [`MAX_INVITES`] is already outstanding.
    pub fn mint(&self, name: &PersonName, ttl_hours: u64) -> io::Result<String> {
        let code = hex(&random_bytes(CODE_BYTES)?);
        let hours = match ttl_hours {
            0 => DEFAULT_TTL_HOURS,
            given => given.min(MAX_TTL_HOURS),
        };
        let now = now_unix();
        let invite = Invite {
            name: name.clone(),
            digest: sha256(&code),
            issued_unix: now,
            expires_unix: now.saturating_add(hours.saturating_mul(3_600)),
        };

        let mut entries = self.lock();
        // Drop this name's previous invitation and anything already expired, so the cap is a
        // bound on *live* invitations rather than on history.
        entries.retain(|entry| entry.name != invite.name && entry.live_at(now));
        if entries.len() >= MAX_INVITES {
            return Err(io::Error::other(format!(
                "at most {MAX_INVITES} invitations may be outstanding at once"
            )));
        }
        entries.push(invite);
        self.persist(&entries)?;
        Ok(code)
    }

    /// The name `code` was minted for, without spending it; `None` for a code that is unknown or
    /// expired.
    ///
    /// `POST <route>/invite/redeem` needs this before it creates anything: the no-session half
    /// of that route must refuse a dead code with a `400` *before* hashing a password and
    /// inserting an account, and it must not have spent the code by the time that refusal is
    /// possible to reach — an account-creation failure (a taken email, a weak password, the
    /// store at its cap) must leave the invitation exactly as live as it was, so the person it
    /// was sent to can simply try again. [`Self::redeem`] is called only once account creation
    /// has actually succeeded.
    ///
    /// That ordering is also why "single-use" is stated precisely as *a code stops working once
    /// it has successfully produced a link* rather than once it has been looked at: two requests
    /// racing one code can only ever produce two accounts linked to the *same* invited name, and
    /// the second [`Self::redeem`] call simply finds nothing left to spend.
    ///
    /// Constant-time and total, like [`Self::redeem`].
    #[must_use]
    pub fn name_for(&self, code: &str) -> Option<PersonName> {
        let presented = sha256(code);
        let now = now_unix();
        let mut found = None;
        for entry in self.lock().iter() {
            if entry.live_at(now) && constant_time_eq(&entry.digest, &presented) {
                found = Some(entry.name.clone());
            }
        }
        found
    }

    /// Redeems `code`, returning the name it was minted for; `None` for a code that is unknown,
    /// expired, or already used.
    ///
    /// Single-use: a successful redemption removes the entry and persists, which is what makes
    /// an intercepted code worthless the moment the person it was sent to has used it. Every way
    /// of failing is the same `None`, so probing this store teaches nothing about which names
    /// exist.
    ///
    /// The comparison is constant-time and the walk visits every entry rather than returning
    /// early, like every credential check in this crate.
    #[must_use]
    pub fn redeem(&self, code: &str) -> Option<PersonName> {
        let presented = sha256(code);
        let now = now_unix();
        let mut entries = self.lock();
        let mut redeemed: Option<PersonName> = None;
        entries.retain(|entry| {
            let hit = entry.live_at(now) && constant_time_eq(&entry.digest, &presented);
            if hit {
                redeemed = Some(entry.name.clone());
            }
            !hit
        });
        let redeemed = redeemed?;
        // An expired entry swept on the way past is worth persisting even though it changed no
        // decision; a failed write must not, however, turn a successful redemption into a
        // refusal the caller cannot retry — the name is already resolved by the time this
        // matters.
        if let Err(error) = self.persist(&entries) {
            eprintln!("reports: could not update {}: {error}", self.path.display());
        }
        Some(redeemed)
    }

    /// Every invitation that has not expired, newest last.
    ///
    /// Carries no code and cannot: the store holds digests. This is what `selfhost reports
    /// invited` shows — who has been invited and until when, never a credential.
    #[must_use]
    pub fn outstanding(&self) -> Vec<Invite> {
        let now = now_unix();
        self.lock()
            .iter()
            .filter(|entry| entry.live_at(now))
            .cloned()
            .collect()
    }

    /// Withdraws the invitation for `name`, persisting; false if there was none.
    ///
    /// # Errors
    /// An [`io::Error`] naming what the write refused.
    pub fn revoke(&self, name: &PersonName) -> io::Result<bool> {
        let mut entries = self.lock();
        let before = entries.len();
        entries.retain(|entry| &entry.name != name);
        if entries.len() == before {
            return Ok(false);
        }
        self.persist(&entries)?;
        Ok(true)
    }

    /// Writes the store owner-only via a temporary file and a rename, like every sibling
    /// credential store in this crate: a crash mid-write leaves the previous file.
    fn persist(&self, entries: &[Invite]) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = invites_to_json(entries).to_text();
        let temporary = self.path.with_extension("json.tmp");
        std::fs::write(&temporary, &text)?;
        restrict(&temporary);
        std::fs::rename(&temporary, &self.path)
    }

    /// The entries, with lock poisoning treated as fatal, as in the sibling stores: a panic
    /// while invitations were held leaves them in an unknown state, and limping on is worse
    /// than stopping.
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Invite>> {
        self.entries
            .lock()
            .expect("the invite store lock was poisoned")
    }
}

// Deliberately not a revealing `Debug`: the digests are not codes, but a list of who has a
// pending invitation is a target list, and one in a log line is a shopping list — the same
// reasoning every credential store in this crate gives its own `Debug`.
impl std::fmt::Debug for Invites {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "Invites({} outstanding)", self.outstanding().len())
    }
}

/// SHA-256 of a code, as the stored digest.
fn sha256(code: &str) -> Vec<u8> {
    digest(&SHA256, code.as_bytes()).as_ref().to_vec()
}

/// Compares two byte strings without leaking, through timing, how far the match ran — the same
/// helper every credential check in this crate carries its own copy of.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |differences, (a, b)| differences | (a ^ b))
        == 0
}

/// `count` bytes from the operating system's entropy.
fn random_bytes(count: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0u8; count];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("the system random source was unavailable"))?;
    Ok(bytes)
}

/// Lowercase hex of `bytes` — the same helper `crate::accounts` and `crate::report` each carry
/// their own copy of, rather than a second encoding entering for one more store.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            out.push_str(&format!("{byte:02x}"));
            out
        })
}

/// The bytes a lowercase hex string encodes, or `None` for anything that is not one — an odd
/// length, or a character outside `0-9a-f`.
fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(text.get(index..index + 2)?, 16).ok())
        .collect()
}

/// Seconds since the Unix epoch, or zero if the clock is before it.
///
/// A clock behind the epoch is a misconfigured machine. Zero makes every invite look freshly
/// minted rather than making every invite look expired, and the direction matters: the
/// alternative silently refuses invitations on a box whose clock has not yet synchronised at
/// boot.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

/// The stored file's JSON shape: `{"invites": [{name, digest, issuedUnix, expiresUnix}]}`.
fn invites_to_json(entries: &[Invite]) -> Json {
    Json::object([(
        "invites",
        Json::array(entries.iter().map(|entry| {
            Json::object([
                ("name", Json::string(entry.name.as_str())),
                ("digest", Json::string(hex(&entry.digest))),
                ("issuedUnix", Json::Number(entry.issued_unix as f64)),
                ("expiresUnix", Json::Number(entry.expires_unix as f64)),
            ])
        })),
    )])
}

/// Parses the stored file, or `None` for anything at all that is malformed.
///
/// Whole-document refusal, for the reason every credential store in this crate gives: a file
/// that is partly understood is one whose meaning depends on which build is reading it. A
/// digest of the wrong length is included in that — it could never match a real code, so it can
/// only be corruption.
fn parse_invites(text: &str) -> Option<Vec<Invite>> {
    let value = selfhost_json::parse(text).ok()?;
    let items = value.get("invites")?.as_array()?;
    if items.len() > MAX_INVITES {
        return None;
    }
    let mut entries: Vec<Invite> = Vec::new();
    for item in items {
        let name = PersonName::parse(item.get("name")?.as_str()?).ok()?;
        if entries.iter().any(|entry| entry.name == name) {
            return None;
        }
        let digest = hex_decode(item.get("digest")?.as_str()?)?;
        if digest.len() != ring::digest::SHA256_OUTPUT_LEN {
            return None;
        }
        entries.push(Invite {
            name,
            digest,
            issued_unix: item.get("issuedUnix")?.as_u64()?,
            expires_unix: item.get("expiresUnix")?.as_u64()?,
        });
    }
    Some(entries)
}

/// Restricts `path` to its owner where the platform has such a concept — the same helper every
/// store in this crate carries its own copy of.
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

    /// A scratch directory unique to one test, as in the sibling stores.
    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "selfhost-reports-invite-test-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        path
    }

    fn person(name: &str) -> PersonName {
        PersonName::parse(name).expect("a valid name")
    }

    #[test]
    fn a_minted_code_redeems_once_and_names_the_person_it_was_minted_for() {
        let dir = scratch("redeem");
        let invites = Invites::load(&dir);
        let code = invites.mint(&person("mom"), 1).expect("mints");

        assert_eq!(invites.redeem(&code), Some(person("mom")));
        // The failure this prevents: an intercepted code that keeps working after the person
        // it was sent to has used it.
        assert_eq!(invites.redeem(&code), None, "an invitation is single-use");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_code_is_not_in_the_file_that_records_the_invitation() {
        // The whole reason the digest is stored: a backup of the data directory must not be a
        // set of live invitations.
        let dir = scratch("digest-only");
        let code = Invites::load(&dir).mint(&person("mom"), 1).expect("mints");
        let stored = std::fs::read_to_string(Invites::path_in(&dir)).expect("the file");
        assert!(
            !stored.contains(&code),
            "the code itself must never be written down"
        );
        assert!(stored.contains("mom"), "but the name it was minted for is");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_code_is_lowercase_hex() {
        let dir = scratch("hex");
        let code = Invites::load(&dir).mint(&person("mom"), 1).expect("mints");
        assert_eq!(code.len(), CODE_BYTES * 2, "{code}");
        assert!(
            code.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "{code}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn name_for_answers_without_spending_the_code() {
        let dir = scratch("peek");
        let invites = Invites::load(&dir);
        let code = invites.mint(&person("mom"), 1).expect("mints");

        assert_eq!(invites.name_for(&code), Some(person("mom")), "a live code peeks");
        assert_eq!(
            invites.name_for(&code),
            Some(person("mom")),
            "peeking again still finds it — nothing was spent"
        );
        assert_eq!(
            invites.redeem(&code),
            Some(person("mom")),
            "the code is still there to actually redeem"
        );
        assert_eq!(invites.name_for(&code), None, "and now it is gone for good");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unknown_or_empty_code_is_refused_without_saying_why() {
        let dir = scratch("unknown");
        let invites = Invites::load(&dir);
        invites.mint(&person("mom"), 1).expect("mints");
        assert_eq!(invites.redeem("not-a-code"), None);
        assert_eq!(invites.redeem(""), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_expired_invitation_is_not_redeemable_and_is_not_listed() {
        let dir = scratch("expired");
        let invites = Invites::load(&dir);
        let code = invites.mint(&person("mom"), 1).expect("mints");
        // Reach past the clock rather than sleeping an hour: the entry is rewritten to have
        // expired one second ago.
        {
            let mut entries = invites.lock();
            entries[0].expires_unix = now_unix().saturating_sub(1);
            let entries = entries.clone();
            invites.persist(&entries).expect("persists");
        }
        assert_eq!(
            invites.redeem(&code),
            None,
            "a lapsed invitation opens nothing"
        );
        assert!(
            invites.outstanding().is_empty(),
            "and it is not shown as pending"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn re_inviting_the_same_person_supersedes_the_first_code() {
        // "I lost the code, send another" must not leave two live credentials for one name.
        let dir = scratch("supersede");
        let invites = Invites::load(&dir);
        let first = invites.mint(&person("mom"), 1).expect("mints");
        let second = invites.mint(&person("mom"), 1).expect("mints again");

        assert_eq!(invites.outstanding().len(), 1, "one invitation per person");
        assert_eq!(invites.redeem(&first), None, "the first code is dead");
        assert_eq!(invites.redeem(&second), Some(person("mom")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invitations_survive_a_reload_from_disk() {
        let dir = scratch("reload");
        let code = Invites::load(&dir).mint(&person("mom"), 1).expect("mints");
        assert_eq!(Invites::load(&dir).redeem(&code), Some(person("mom")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn revoking_withdraws_the_invitation_and_revoking_again_is_a_no_op() {
        let dir = scratch("revoke");
        let invites = Invites::load(&dir);
        let code = invites.mint(&person("mom"), 1).expect("mints");
        assert!(invites.revoke(&person("mom")).expect("revokes"));
        assert!(
            !invites.revoke(&person("mom")).expect("a second revoke is a no-op")
        );
        assert_eq!(
            invites.redeem(&code),
            None,
            "a withdrawn invitation opens nothing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_file_redeems_nothing_rather_than_redeems_some() {
        let dir = scratch("malformed");
        let path = Invites::path_in(&dir);
        let good = hex(&[0u8; 32]);
        let bad = [
            "not json".to_owned(),
            r#"{}"#.to_owned(),
            r#"{"invites":{}}"#.to_owned(),
            // The reserved name, which no invitation may ever carry.
            format!(
                r#"{{"invites":[{{"name":"owner","digest":"{good}","issuedUnix":1,"expiresUnix":2}}]}}"#
            ),
            // A digest that is not SHA-256 sized: it could never match.
            r#"{"invites":[{"name":"mom","digest":"AAAA","issuedUnix":1,"expiresUnix":2}]}"#
                .to_owned(),
            // A missing field.
            format!(r#"{{"invites":[{{"name":"mom","digest":"{good}","issuedUnix":1}}]}}"#),
            // A duplicate name.
            format!(
                r#"{{"invites":[{{"name":"mom","digest":"{good}","issuedUnix":1,"expiresUnix":2}},
                                {{"name":"mom","digest":"{good}","issuedUnix":1,"expiresUnix":2}}]}}"#
            ),
        ];
        for text in bad {
            std::fs::write(&path, &text).expect("writes the fixture");
            assert!(
                Invites::load(&dir).outstanding().is_empty(),
                "{text} must load as empty"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_owner_can_never_be_invited() {
        // Not a check this module performs — `PersonName` refuses the spelling, so there is no
        // path by which an invitation could link an account to the owner's own name. Asserted
        // here because that is the property this store depends on and it lives in another
        // crate.
        assert!(PersonName::parse("owner").is_err());
        assert!(PersonName::parse("Owner").is_err());
    }

    #[test]
    fn a_life_is_clamped_and_a_zero_means_the_default() {
        let dir = scratch("ttl");
        let invites = Invites::load(&dir);
        invites.mint(&person("a"), 0).expect("mints");
        invites.mint(&person("b"), u64::MAX).expect("mints");
        let outstanding = invites.outstanding();
        let life = |name: &str| {
            let entry = outstanding
                .iter()
                .find(|e| e.name.as_str() == name)
                .expect("the entry");
            entry.expires_unix - entry.issued_unix
        };
        assert_eq!(life("a"), DEFAULT_TTL_HOURS * 3_600, "zero means the default");
        assert_eq!(
            life("b"),
            MAX_TTL_HOURS * 3_600,
            "and no invitation outlives the cap"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn outstanding_invitations_are_capped() {
        let dir = scratch("cap");
        let invites = Invites::load(&dir);
        for index in 0..MAX_INVITES {
            invites
                .mint(&person(&format!("p{index}")), 1)
                .expect("under the cap");
        }
        assert!(
            invites.mint(&person("one-too-many"), 1).is_err(),
            "a loop hits a wall"
        );
        assert_eq!(invites.outstanding().len(), MAX_INVITES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hex_round_trips_through_its_own_decoder() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        assert_eq!(hex_decode(&hex(&bytes)).as_deref(), Some(bytes.as_slice()));
        assert_eq!(hex_decode("abc"), None, "an odd length is not hex");
        assert_eq!(hex_decode("zz"), None, "not a hex digit");
    }

    #[cfg(unix)]
    #[test]
    fn the_invite_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        Invites::load(&dir).mint(&person("mom"), 1).expect("mints");
        let mode = std::fs::metadata(Invites::path_in(&dir))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "no group or world access: mode {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
