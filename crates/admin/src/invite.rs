//! The one-time code that lets somebody who is not the owner register a passkey.
//!
//! # The gap this closes, stated so nobody re-derives it
//!
//! `crates/identity` decides what a person may do and
//! [`crate::people_api`] lets the owner write it down, but until this module
//! existed neither could produce a person who could actually *log in*. A grant
//! names somebody; a passkey is how they prove they are that somebody. The
//! registration routes are [`crate::Demand::OwnerOnly`] — deliberately, and that
//! does not change here — so the only way to create a second person's credential
//! was for the owner to be sitting at the browser console, logged in, with the
//! other person's device in their hand. "Download it and log in" could not
//! happen without the owner present, which is the whole of what made a
//! permission model nobody else could reach.
//!
//! An invite is the missing step, and it is deliberately the *smallest* thing
//! that closes it: a high-entropy code, bound to one name the owner chose in
//! advance, valid once, and expiring on its own.
//!
//! # What an invite is, and what it very deliberately is not
//!
//! An invite authorises **exactly one act**: registering a passkey under the
//! name written inside it. It is not a session, it is not a capability, and it
//! confers no power of its own. Somebody who redeems an invite for `mom` becomes
//! able to prove they are `mom` — and then holds precisely whatever the owner
//! put in `console.people` for that name, which may be nothing at all. The two
//! halves are separate on purpose: minting a credential and granting a power are
//! different decisions, made in different files, and an invite that carried
//! grants would collapse them into one.
//!
//! That is also why the redemption route takes the name from **here** and never
//! from the request body. [`crate::webauthn::Webauthn::register`] reads `user`
//! out of what the browser posted, which is right for a route only the owner can
//! reach; it would be a hole in this one, where the caller is a stranger holding
//! a code. An invite for `mom` can only ever produce a passkey named `mom`.
//!
//! # Why the code is stored as a digest
//!
//! `<data_dir>/console.invites` holds the SHA-256 of each code, never the code
//! itself, exactly as `crates/admin/src/passwd.rs` holds no password. The code
//! exists in one place — the operator's terminal or the console screen that
//! minted it — and this file cannot reproduce it. Losing it is therefore a
//! re-mint rather than a lookup, which is the correct shape: a file that could
//! hand out live invitations is a file that turns a backup into an account.
//!
//! Comparison is constant-time and the walk visits every entry, like every other
//! credential check in this crate. The file is written owner-only through the
//! same platform-correct [`crate::token::write_private`] the passkey store uses,
//! so on Windows it lands under an explicit DACL rather than an inherited one.
//!
//! # The bounds, and why each one is here
//!
//! An invite expires ([`DEFAULT_TTL_HOURS`], capped at [`MAX_TTL_HOURS`])
//! because an invitation that outlives the reason it was sent is a credential
//! nobody is watching. Minting for a name that already has an outstanding invite
//! *supersedes* it rather than adding a second, so "I lost the code, send
//! another" cannot leave two live codes for one person. The store is capped at
//! [`MAX_INVITES`], matching the registry and the passkey store beside it.

use crate::token::{constant_time_eq, random_bytes, write_private};
use ring::digest;
use selfhost_identity::PersonName;
use selfhost_json::Json;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// The name of the invite file inside the data directory.
pub const INVITES_FILENAME: &str = "console.invites";

/// The most outstanding invites the store will hold.
///
/// Matched to the people registry's own cap: an invite exists to create a
/// person, so more live invites than the registry can hold could only produce
/// entries that are refused on arrival.
pub const MAX_INVITES: usize = 32;

/// How long an invite lasts when the operator does not say.
///
/// Two days: long enough to send a message and have somebody read it on their
/// own schedule, short enough that a forgotten invitation closes itself.
pub const DEFAULT_TTL_HOURS: u64 = 48;

/// The longest life an invite may be given.
pub const MAX_TTL_HOURS: u64 = 24 * 14;

/// The entropy behind a code: 192 bits, rendered as 32 base64url characters.
///
/// Sized to be unguessable while still being something a person can be read
/// over a phone or pasted from a message. The failure gate in
/// [`crate::session::FailureGate`] bounds online guessing regardless; this is
/// the offline margin.
const CODE_BYTES: usize = 24;

/// One outstanding invitation.
#[derive(Clone)]
pub struct Invite {
    /// The name the redeemed passkey will be registered under. Chosen by the
    /// owner when the invite was minted, and the reason the redemption route
    /// never reads a name from the request.
    pub name: PersonName,
    /// SHA-256 of the code. The code itself is not stored — see the module
    /// documentation.
    digest: Vec<u8>,
    /// When it was minted, as seconds since the Unix epoch.
    pub issued_unix: u64,
    /// When it stops being redeemable, as seconds since the Unix epoch.
    pub expires_unix: u64,
}

impl Invite {
    /// Whether this invite is still redeemable at `now` (Unix seconds).
    pub fn live_at(&self, now: u64) -> bool {
        now < self.expires_unix
    }
}

/// The durable invite store: `<data_dir>/console.invites`, owner-only, JSON.
///
/// A cheap-clone handle over shared state, like every other store the `Api`
/// carries: an invite minted through one clone must be redeemable through
/// another. A missing file is an empty store; a malformed one loads empty and
/// says so once, which fails closed — no invite can be redeemed rather than some
/// unknown subset being live.
#[derive(Clone)]
pub struct Invites {
    path: PathBuf,
    state: Arc<Mutex<Stored>>,
}

/// What the store holds in memory: the entries, and enough about the file they
/// were read from to notice somebody else rewriting it.
struct Stored {
    /// The invitations as last read or written.
    entries: Vec<Invite>,
    /// The modified time and length of the file those entries came from, or
    /// `None` when the file was absent or unreadable. Compared before every
    /// operation; a difference means re-read.
    seen: Option<(SystemTime, u64)>,
}

impl Invites {
    /// Loads the store from `<data_dir>/console.invites`.
    ///
    /// The entries this reads are a starting point, not a snapshot the handle
    /// keeps: see [`Self::refreshed`] for why every operation re-reads a file
    /// that has changed underneath it.
    pub fn load(data_dir: &Path) -> Self {
        let path = Self::path_in(data_dir);
        let (entries, seen) = read_entries(&path, true);
        Self { path, state: Arc::new(Mutex::new(Stored { entries, seen })) }
    }

    /// Where the invite file lives for a given data directory.
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(INVITES_FILENAME)
    }

    /// Mints an invitation for `name`, returning the code — the only time it
    /// exists in a form anybody can read.
    ///
    /// `ttl_hours` is clamped to [`MAX_TTL_HOURS`] and treated as
    /// [`DEFAULT_TTL_HOURS`] when zero. Any outstanding invite for the same
    /// person is replaced rather than joined, so re-sending an invitation never
    /// leaves two live codes for one name.
    ///
    /// The bytes come from the operating system's entropy; a failure there is an
    /// error and never a weaker code.
    pub fn mint(&self, name: &PersonName, ttl_hours: u64) -> io::Result<String> {
        let code = crate::webauthn::b64url_encode(&random_bytes(CODE_BYTES)?);
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

        let mut state = self.refreshed();
        // Drop this person's previous invitation and anything already expired,
        // so the cap is a bound on *live* invitations rather than on history.
        state.entries.retain(|entry| entry.name != invite.name && entry.live_at(now));
        if state.entries.len() >= MAX_INVITES {
            return Err(io::Error::other(format!(
                "at most {MAX_INVITES} invitations may be outstanding at once"
            )));
        }
        state.entries.push(invite);
        self.persist(&state.entries)?;
        self.mark_written(&mut state);
        Ok(code)
    }

    /// The name `code` was minted for, without spending it; `None` for a code
    /// that is unknown or expired.
    ///
    /// The invite door needs this before the ceremony rather than after: a
    /// browser cannot call `navigator.credentials.create()` without a name to
    /// put in the passkey it is about to make, and that name must come from the
    /// invitation rather than from whoever is holding it. So the door asks here
    /// to build the challenge and calls [`Self::redeem`] only once the
    /// authenticator has actually produced a credential.
    ///
    /// That ordering is deliberate and it is the reason "single-use" is stated
    /// precisely as *a code stops working once it has successfully registered
    /// something*. Spending the invitation first would mean a mistyped PIN or a
    /// cancelled biometric prompt burned the invitation and locked out the
    /// person it was sent to, which is a far more likely event than the thing it
    /// would prevent: two ceremonies racing one code can only ever produce two
    /// passkeys for the *same invited name* — the same person's two devices,
    /// bounded by the passkey store's own cap.
    ///
    /// Constant-time and total, like [`Self::redeem`].
    pub fn name_for(&self, code: &str) -> Option<PersonName> {
        let presented = sha256(code);
        let now = now_unix();
        let mut found = None;
        for entry in self.refreshed().entries.iter() {
            if entry.live_at(now) && constant_time_eq(&entry.digest, &presented) {
                found = Some(entry.name.clone());
            }
        }
        found
    }

    /// Redeems `code`, returning the name it was minted for; `None` for a code
    /// that is unknown, expired, or already used.
    ///
    /// Single-use: a successful redemption removes the entry and persists, which
    /// is what makes an intercepted code worthless the moment the person it was
    /// sent to has used it. Every way of failing is the same `None`, so probing
    /// this store teaches nothing about which names exist.
    ///
    /// The comparison is constant-time and the walk visits every entry rather
    /// than returning early, like every credential check in this crate.
    pub fn redeem(&self, code: &str) -> Option<PersonName> {
        let presented = sha256(code);
        let now = now_unix();
        let mut state = self.refreshed();
        let mut redeemed: Option<PersonName> = None;
        state.entries.retain(|entry| {
            let hit = entry.live_at(now) && constant_time_eq(&entry.digest, &presented);
            if hit {
                redeemed = Some(entry.name.clone());
            }
            !hit
        });
        let redeemed = redeemed?;
        // An expired entry swept on the way past is worth persisting even
        // though it changed no decision; a failed write must not, however, turn
        // a successful redemption into a refusal the caller cannot retry — the
        // credential is already minted by the time this matters.
        if let Err(error) = self.persist(&state.entries) {
            eprintln!("admin: could not update {}: {error}", self.path.display());
        }
        self.mark_written(&mut state);
        Some(redeemed)
    }

    /// Every invitation that has not expired, newest last.
    ///
    /// Carries no code and cannot: the store holds digests. This is what the
    /// console and `selfhost people list` show — who has been invited and until
    /// when, never a credential.
    pub fn outstanding(&self) -> Vec<Invite> {
        let now = now_unix();
        self.refreshed().entries.iter().filter(|entry| entry.live_at(now)).cloned().collect()
    }

    /// Withdraws the invitation for `name`, persisting; false if there was none.
    pub fn revoke(&self, name: &PersonName) -> io::Result<bool> {
        let mut state = self.refreshed();
        let before = state.entries.len();
        state.entries.retain(|entry| &entry.name != name);
        if state.entries.len() == before {
            return Ok(false);
        }
        self.persist(&state.entries)?;
        self.mark_written(&mut state);
        Ok(true)
    }

    /// Writes the store owner-only via a temporary file and a rename, like the
    /// passkey store and the token: a crash mid-write leaves the previous file.
    ///
    /// Creates the data directory if it is absent, because the first invitation
    /// on a deployment is routinely minted by the CLI before the daemon has ever
    /// run — the same reason the people registry does it.
    fn persist(&self, entries: &[Invite]) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = invites_to_json(entries).to_text();
        let temporary = self.path.with_extension("invites.new");
        write_private(&temporary, &text)?;
        std::fs::rename(&temporary, &self.path)
    }

    /// The entries, re-read first if the file changed since this handle last
    /// looked at it.
    ///
    /// # Why this re-reads instead of trusting what it loaded
    ///
    /// **This store has two writers in two different processes.** The daemon
    /// holds one handle for the lifetime of the process; `selfhost people
    /// invite` opens its own, writes, and exits — deliberately, because a
    /// permission tool that needs a working console to let somebody into the
    /// console has a cycle in it (see `crates/cli/src/people_command.rs`).
    ///
    /// A handle that kept the entries it loaded at start-up therefore answered
    /// out of a snapshot taken before the invitation existed. The operator minted
    /// a code, sent it, and the person got the same uniform `401` a wrong code
    /// gets — indistinguishable from a typo, on a door whose whole job is to
    /// admit somebody holding nothing else. The invite flow could only ever have
    /// worked on a deployment restarted between minting and redeeming, which is
    /// why every test passed and nobody had completed the ceremony on real
    /// hardware. Found 2026-08-15, on the first attempt to use it live.
    ///
    /// Re-reading also closes the write half of the same bug: [`Self::redeem`]
    /// and [`Self::revoke`] persist the whole list, so a stale handle would have
    /// erased any invitation minted by the other process since it loaded.
    ///
    /// The check is a stat, not a read — modified time and length — so the
    /// common case costs one `metadata` call on a file of a few hundred bytes,
    /// and both routes that reach it are already behind the shared failure gate.
    ///
    /// Lock poisoning is fatal, as in the sibling stores: a panic while
    /// invitations were held leaves them in an unknown state, and limping on is
    /// worse than stopping.
    fn refreshed(&self) -> std::sync::MutexGuard<'_, Stored> {
        let mut state = self.state.lock().expect("the invite store lock was poisoned");
        let current = file_stamp(&self.path);
        if current != state.seen {
            // Announce a file that has become unreadable or malformed, but only
            // when it changes: this runs on every lookup, and a broken file must
            // not turn the log into the thing that fills the disk.
            let (entries, seen) = read_entries(&self.path, true);
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
/// that compares unequal to a present file — so a store whose file appears, or
/// disappears, notices either way.
fn file_stamp(path: &Path) -> Option<(SystemTime, u64)> {
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.modified().ok()?, metadata.len()))
}

/// Reads and parses the invite file, failing closed.
///
/// A missing file is an empty store. A malformed one is *also* an empty store —
/// no invitation can be redeemed, rather than some unknown subset of them being
/// live — and says so when `announce` is set.
fn read_entries(path: &Path, announce: bool) -> (Vec<Invite>, Option<(SystemTime, u64)>) {
    // Stamp first, so a write landing between the read and the stat is noticed
    // on the next call rather than being mistaken for what was just read.
    let stamp = file_stamp(path);
    let entries = match std::fs::read_to_string(path) {
        Ok(text) => match parse_invites(&text) {
            Some(entries) => entries,
            None => {
                if announce {
                    eprintln!(
                        "admin: {} is not a valid invite file; no invitation can be \
                         redeemed until it is repaired or removed",
                        path.display()
                    );
                }
                Vec::new()
            }
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(error) => {
            if announce {
                eprintln!(
                    "admin: could not read {}: {error}; no invitation can be redeemed",
                    path.display()
                );
            }
            Vec::new()
        }
    };
    (entries, stamp)
}

// Deliberately not a revealing `Debug`: the digests are not codes, but a list of
// who has a pending invitation is a target list, and one in a log line is a
// shopping list — the same reasoning the people registry gives.
impl std::fmt::Debug for Invites {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Invites({} outstanding)", self.outstanding().len())
    }
}

/// SHA-256 of a code, as the stored digest.
fn sha256(code: &str) -> Vec<u8> {
    digest::digest(&digest::SHA256, code.as_bytes()).as_ref().to_vec()
}

/// Seconds since the Unix epoch, or zero if the clock is before it.
///
/// A clock behind the epoch is a misconfigured machine. Zero makes every invite
/// look freshly minted rather than making every invite look expired, and the
/// direction matters: the alternative silently refuses invitations on a box
/// whose clock has not yet synchronised at boot.
fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|since| since.as_secs()).unwrap_or(0)
}

/// The stored file's JSON shape:
/// `{"invites": [{name, digest, issuedUnix, expiresUnix}]}`.
fn invites_to_json(entries: &[Invite]) -> Json {
    Json::object([(
        "invites",
        Json::array(entries.iter().map(|entry| {
            Json::object([
                ("name", Json::string(entry.name.as_str())),
                ("digest", Json::string(crate::webauthn::b64url_encode(&entry.digest))),
                ("issuedUnix", Json::Number(entry.issued_unix as f64)),
                ("expiresUnix", Json::Number(entry.expires_unix as f64)),
            ])
        })),
    )])
}

/// Parses the stored file, or `None` for anything at all that is malformed.
///
/// Whole-document refusal, for the reason the people registry gives: a
/// credential file that is partly understood is one whose meaning depends on
/// which build is reading it. A digest of the wrong length is included in that —
/// it could never match a real code, so it can only be corruption.
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
        let digest = crate::webauthn::b64url_decode(item.get("digest")?.as_str()?)?;
        if digest.len() != digest::SHA256_OUTPUT_LEN {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory unique to one test, as in the sibling stores.
    fn scratch(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("selfhost-invite-test-{}-{name}", std::process::id()));
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
        // The failure this prevents: an intercepted code that keeps working
        // after the person it was sent to has used it.
        assert_eq!(invites.redeem(&code), None, "an invitation is single-use");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_code_is_not_in_the_file_that_records_the_invitation() {
        // The whole reason the digest is stored: a backup of the data directory
        // must not be a set of live invitations.
        let dir = scratch("digest-only");
        let code = Invites::load(&dir).mint(&person("mom"), 1).expect("mints");
        let stored = std::fs::read_to_string(Invites::path_in(&dir)).expect("the file");
        assert!(!stored.contains(&code), "the code itself must never be written down");
        assert!(stored.contains("mom"), "but the name it was minted for is");
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
        // Reach past the clock rather than sleeping an hour: the entry is
        // rewritten to have expired one second ago.
        {
            let mut state = invites.refreshed();
            state.entries[0].expires_unix = now_unix().saturating_sub(1);
            let entries = state.entries.clone();
            invites.persist(&entries).expect("persists");
            invites.mark_written(&mut state);
        }
        assert_eq!(invites.redeem(&code), None, "a lapsed invitation opens nothing");
        assert!(invites.outstanding().is_empty(), "and it is not shown as pending");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn re_inviting_the_same_person_supersedes_the_first_code() {
        // "I lost the code, send another" must not leave two live credentials
        // for one name.
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
        assert!(!invites.revoke(&person("mom")).expect("a second revoke is a no-op"));
        assert_eq!(invites.redeem(&code), None, "a withdrawn invitation opens nothing");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_file_redeems_nothing_rather_than_redeems_some() {
        let dir = scratch("malformed");
        let path = Invites::path_in(&dir);
        let good = crate::webauthn::b64url_encode(&[0u8; 32]);
        let bad = [
            "not json".to_owned(),
            r#"{}"#.to_owned(),
            r#"{"invites":{}}"#.to_owned(),
            // The reserved name, which no invitation may ever carry.
            format!(r#"{{"invites":[{{"name":"owner","digest":"{good}","issuedUnix":1,"expiresUnix":2}}]}}"#),
            // A digest that is not SHA-256 sized: it could never match.
            r#"{"invites":[{"name":"mom","digest":"AAAA","issuedUnix":1,"expiresUnix":2}]}"#.to_owned(),
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
            assert!(Invites::load(&dir).outstanding().is_empty(), "{text} must load as empty");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_owner_can_never_be_invited() {
        // Not a check this module performs — `PersonName` refuses the spelling,
        // so there is no path by which an invitation could mint a credential
        // that authenticates as the operator. Asserted here because that is the
        // property this store depends on and it lives in another crate.
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
            let entry =
                outstanding.iter().find(|e| e.name.as_str() == name).expect("the entry");
            entry.expires_unix - entry.issued_unix
        };
        assert_eq!(life("a"), DEFAULT_TTL_HOURS * 3_600, "zero means the default");
        assert_eq!(life("b"), MAX_TTL_HOURS * 3_600, "and no invitation outlives the cap");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn outstanding_invitations_are_capped() {
        let dir = scratch("cap");
        let invites = Invites::load(&dir);
        for index in 0..MAX_INVITES {
            invites.mint(&person(&format!("p{index}")), 1).expect("under the cap");
        }
        assert!(invites.mint(&person("one-too-many"), 1).is_err(), "a loop hits a wall");
        assert_eq!(invites.outstanding().len(), MAX_INVITES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_code_minted_by_another_process_is_redeemable_by_a_handle_that_predates_it() {
        // The two handles are the two processes this store really has: `daemon`
        // is opened at start-up and lives forever, `cli` is `selfhost people
        // invite` opening the file, writing, and exiting.
        //
        // This is the shipped bug. The daemon answered out of the entries it
        // read at start-up, so an invitation minted afterwards did not exist as
        // far as the invite door was concerned, and the person it was sent to
        // got the same uniform 401 a wrong code gets.
        let dir = scratch("cross-process");
        let daemon = Invites::load(&dir);
        assert!(daemon.outstanding().is_empty(), "nothing pending at start-up");

        let cli = Invites::load(&dir);
        let code = cli.mint(&person("dad"), 48).expect("the CLI mints");

        assert_eq!(
            daemon.name_for(&code).map(|name| name.to_string()),
            Some("dad".to_owned()),
            "the running daemon must see an invitation minted after it started"
        );
        assert_eq!(
            daemon.redeem(&code).map(|name| name.to_string()),
            Some("dad".to_owned()),
            "and must be able to spend it"
        );
        assert!(daemon.redeem(&code).is_none(), "still single-use");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_handle_that_writes_does_not_erase_what_another_process_added() {
        // The write half of the same bug: redeem and revoke persist the whole
        // list, so a handle holding a stale snapshot would have written back a
        // list that never contained the other process's invitation.
        let dir = scratch("no-lost-update");
        let daemon = Invites::load(&dir);
        let first = daemon.mint(&person("alex"), 48).expect("mints");

        let cli = Invites::load(&dir);
        let second = cli.mint(&person("dad"), 48).expect("the CLI mints a second");

        // The daemon spends its own invitation, rewriting the file.
        assert!(daemon.redeem(&first).is_some(), "spends the first");

        // The one the other process added must have survived that write.
        assert_eq!(
            daemon.name_for(&second).map(|name| name.to_string()),
            Some("dad".to_owned()),
            "redeeming one invitation must not erase another process's"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_invitation_withdrawn_by_the_cli_stops_opening_the_door() {
        // `people uninvite` is the remedy the emailed-invitation path names for
        // a code sent to the wrong address. It is worth nothing if the running
        // daemon keeps honouring the code it just withdrew.
        let dir = scratch("withdrawn");
        let daemon = Invites::load(&dir);
        let code = Invites::load(&dir).mint(&person("dad"), 48).expect("mints");
        assert!(daemon.name_for(&code).is_some(), "live before it is withdrawn");

        Invites::load(&dir).revoke(&person("dad")).expect("the CLI withdraws it");
        assert!(
            daemon.name_for(&code).is_none(),
            "a withdrawn invitation must stop working without a restart"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_invite_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        Invites::load(&dir).mint(&person("mom"), 1).expect("mints");
        let mode = std::fs::metadata(Invites::path_in(&dir)).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "no group or world access: mode {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
