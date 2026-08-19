//! Per-person storage passwords: the credential that lets a share be mounted by
//! somebody who is not the operator.
//!
//! # Why this file exists at all
//!
//! A WebDAV client does not do cookie logins and cannot do WebAuthn. Finder,
//! the Windows Mini-Redirector and every CLI client speak HTTP authentication or
//! nothing, so `/dav` had exactly one door and behind it was
//! `<data_dir>/console.passwd` — the deployment's own password. Anyone who could
//! mount anything mounted *everything*, and the per-share capabilities in
//! `selfhost_identity` had no identity to be enforced against.
//! `crates/identity/src/credential.rs` names the gap in
//! `Credential::is_a_password_login`: *"closing it means per-person WebDAV
//! credentials, which is its own piece of work."* This is that work.
//!
//! One entry per person, keyed on the [`PersonName`] they are registered under
//! in `console.people`, holding the same PBKDF2 hash format
//! `selfhost_login::password` produces for every other password in this
//! workspace. Setting one is `selfhost people device-password <name>`.
//!
//! # This store is read fresh on every verification, deliberately
//!
//! Every other credential store here is loaded once and held: a cheap-clone
//! handle over an `Arc<Mutex<_>>`, shared by every clone of the API. That is
//! right for a store whose only writer is the daemon itself. It is wrong for
//! this one, because **the writer is the CLI, in a different process.** The
//! invite flow already shipped that bug once and it made the feature dead on
//! every running box: a snapshot taken at start-up cannot see what another
//! process wrote a minute ago, and the operator who has just set a password
//! would be told it is wrong until the daemon is restarted.
//!
//! So [`DevicePasswords`] holds a path and nothing else, and reads the file each
//! time it is asked. The cost is a few hundred bytes of disk read in front of a
//! verification that is 70 ms of PBKDF2 by construction, on a path that
//! `selfhost_storage::auth` already caches for a minute and already limits to two
//! concurrent cold verifications — so the read is unmeasurable next to what it
//! precedes. A new password works on the next request, on a running daemon, with
//! nothing to restart.
//!
//! # Fail-closed, and quiet about which half was wrong
//!
//! A missing file means nobody has a device password: every lookup answers "no
//! entry", and `Door::for_name` then sends that name to the deployment's door,
//! where the console password still opens shares as the owner. A malformed file
//! is treated as **empty** rather than partially parsed, for the reason
//! `selfhost_identity::registry` gives about its own file: a credential store
//! that is partly understood is one whose meaning depends on which build is
//! reading it.
//!
//! Nothing here reports *why* a verification failed. A caller learns only true or
//! false, so an unknown name and a wrong password are indistinguishable from
//! outside — the same rule `/dav`'s single `401` follows.

use selfhost_identity::PersonName;
use selfhost_json::Json;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The name of the device-password file inside the data directory.
pub const DEVICE_PASSWORD_FILENAME: &str = "console.devicepw";

/// The most entries the store will hold.
///
/// Matched to `selfhost_identity::registry::MAX_PEOPLE`: an entry that names
/// nobody in the people registry can never open anything, because
/// `Policy::decide` answers an unregistered person with an empty grant set. A
/// store larger than the registry could only hold credentials for nobody.
pub const MAX_ENTRIES: usize = 32;

/// The shortest password this will store.
///
/// Sixteen characters. Longer than a console password would be asked for, and
/// deliberately: this credential is typed once into an operating system's
/// mount dialogue and then replayed out of a keychain forever, so nobody ever has
/// to remember it, and the usual argument for a short password does not apply.
/// It is also the one credential in this deployment that is presented to a
/// network service on every request, which is where a short one is worth
/// guessing at.
pub const MIN_PASSWORD_LENGTH: usize = 16;

/// The per-person storage passwords, as a handle onto the file.
///
/// Cheap to clone and holds no secret in memory: every method reads the file. See
/// this module's documentation for why that is the design rather than an
/// oversight.
#[derive(Debug, Clone)]
pub struct DevicePasswords {
    path: PathBuf,
}

/// One person's stored credential.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    /// Who it belongs to. The same name their registry entry uses, which is what
    /// makes a Basic user name resolve to a person's grants.
    name: PersonName,
    /// The stored `pbkdf2-sha256$<iterations>$<salt>$<derived>` line.
    hash: String,
    /// When it was set, for the console's people list. Not a security field.
    set_unix: u64,
}

impl DevicePasswords {
    /// A handle onto `<data_dir>/console.devicepw`.
    ///
    /// Does not read anything and cannot fail: a store whose constructor failed
    /// on a missing file would make a deployment where nobody has a device
    /// password an error rather than the ordinary case.
    pub fn in_dir(data_dir: &Path) -> Self {
        Self { path: Self::path_in(data_dir) }
    }

    /// Where the file lives for a given data directory.
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(DEVICE_PASSWORD_FILENAME)
    }

    /// Whether this person has a device password at all.
    ///
    /// The predicate `selfhost_storage::auth::Door::for_name` asks. It is
    /// separate from [`DevicePasswords::verify`] because the *door* has to be
    /// decided before any password is checked — the door is part of the cache
    /// key — and deciding it must not depend on whether the guess was right.
    pub fn holds(&self, name: &PersonName) -> bool {
        self.entries().iter().any(|entry| &entry.name == name)
    }

    /// Whether `password` is this person's device password.
    ///
    /// `false` for an unknown person, an empty store, an unreadable file and a
    /// wrong password alike. The comparison inside
    /// `selfhost_login::password::verify` is constant time.
    ///
    /// # A person with no entry costs no PBKDF2
    ///
    /// Returning early here is a timing difference — a stranger can learn that a
    /// name is unknown by how fast the refusal comes — and it is kept knowingly.
    /// The set of names is not the secret: `selfhost people list` prints it to
    /// the operator, the console renders it, and an invitation carries it. The
    /// alternative is spending 70 ms of a core per unknown name, which is a
    /// denial-of-service primitive a stranger drives by making names up.
    pub fn verify(&self, name: &PersonName, password: &str) -> bool {
        match self.entries().into_iter().find(|entry| &entry.name == name) {
            Some(entry) => selfhost_login::password::verify(&entry.hash, password),
            None => false,
        }
    }

    /// Everybody who holds a device password, and when it was set.
    ///
    /// For `selfhost people list` and the console's people plate, so an operator
    /// can see who can mount a share without reading a file of hashes.
    pub fn holders(&self) -> Vec<(PersonName, u64)> {
        self.entries().into_iter().map(|entry| (entry.name, entry.set_unix)).collect()
    }

    /// Sets one person's device password, replacing any they had, and persists.
    ///
    /// # Errors
    ///
    /// A password shorter than [`MIN_PASSWORD_LENGTH`], a store already at
    /// [`MAX_ENTRIES`] with no entry for this person, a random source that
    /// refuses to salt, or a write that fails. The write goes to a temporary
    /// sibling and is renamed over the file, so a crash mid-write leaves the
    /// previous credentials rather than half of the new ones.
    pub fn set(&self, name: &PersonName, password: &str) -> io::Result<()> {
        if password.chars().count() < MIN_PASSWORD_LENGTH {
            return Err(io::Error::other(format!(
                "a device password must be at least {MIN_PASSWORD_LENGTH} characters: it is \
                 typed once and then replayed by a keychain on every request, so there is no \
                 reason for it to be short enough to remember"
            )));
        }
        let hash = selfhost_login::password::hash(password)?;
        let mut entries = self.entries();
        match entries.iter_mut().find(|entry| &entry.name == name) {
            Some(entry) => {
                entry.hash = hash;
                entry.set_unix = now_unix();
            }
            None => {
                if entries.len() >= MAX_ENTRIES {
                    return Err(io::Error::other(format!(
                        "at most {MAX_ENTRIES} people may hold a device password"
                    )));
                }
                entries.push(Entry { name: name.clone(), hash, set_unix: now_unix() });
            }
        }
        self.persist(&entries)
    }

    /// Forgets one person's device password; false if they had none.
    ///
    /// Every mount that person has, on every machine, stops working at the next
    /// request — which is the point. It does not touch their registry entry:
    /// revoking a credential and revoking authority are separate acts, and this
    /// is the first.
    pub fn clear(&self, name: &PersonName) -> io::Result<bool> {
        let mut entries = self.entries();
        let before = entries.len();
        entries.retain(|entry| &entry.name != name);
        if entries.len() == before {
            return Ok(false);
        }
        self.persist(&entries)?;
        Ok(true)
    }

    /// The stored entries, or none at all if the file is missing or malformed.
    fn entries(&self) -> Vec<Entry> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
            Err(error) => {
                eprintln!(
                    "admin: could not read {}: {error}; no device password opens anything",
                    self.path.display()
                );
                return Vec::new();
            }
        };
        match parse(&text) {
            Some(entries) => entries,
            None => {
                eprintln!(
                    "admin: {} is not a valid device-password file; no device password opens \
                     anything until it is repaired or removed",
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
        let temporary = self.path.with_extension("devicepw.new");
        crate::token::write_private(&temporary, &to_json(entries).to_text())?;
        std::fs::rename(&temporary, &self.path)
    }
}

/// Seconds since the Unix epoch, or zero on a clock set before it.
fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|since| since.as_secs()).unwrap_or(0)
}

/// The stored shape: `{"devicePasswords":[{name, hash, setUnix}]}`.
fn to_json(entries: &[Entry]) -> Json {
    Json::object([(
        "devicePasswords",
        Json::array(entries.iter().map(|entry| {
            Json::object([
                ("name", Json::string(entry.name.as_str())),
                ("hash", Json::string(&entry.hash)),
                ("setUnix", Json::Number(entry.set_unix as f64)),
            ])
        })),
    )])
}

/// Parses the stored file, or `None` for anything at all that is malformed.
///
/// A name that is not a valid [`PersonName`], a duplicate name, a missing field,
/// more than [`MAX_ENTRIES`] entries, a hash that is not this workspace's format
/// — every one of them refuses the whole document. See this module's
/// documentation for why a credential store fails closed and whole.
fn parse(text: &str) -> Option<Vec<Entry>> {
    let value = selfhost_json::parse(text).ok()?;
    let items = value.get("devicePasswords")?.as_array()?;
    if items.len() > MAX_ENTRIES {
        return None;
    }
    let mut entries: Vec<Entry> = Vec::new();
    for item in items {
        let name = PersonName::parse(item.get("name")?.as_str()?).ok()?;
        if entries.iter().any(|entry| entry.name == name) {
            return None;
        }
        let hash = item.get("hash")?.as_str()?.to_owned();
        // Checked here rather than at verification time so a hand-edited file
        // that put a plaintext password in the `hash` field is a refused
        // document rather than a credential that never matches anything and
        // takes an afternoon to explain.
        if !selfhost_login::password::is_stored_hash(&hash) {
            return None;
        }
        entries.push(Entry { name, hash, set_unix: item.get("setUnix")?.as_u64()? });
    }
    Some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir()
            .join(format!("selfhost-devicepw-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        path
    }

    fn person(name: &str) -> PersonName {
        PersonName::parse(name).expect("a valid name")
    }

    /// A password long enough for the store to accept.
    const GOOD: &str = "correct-horse-battery-staple";

    #[test]
    fn a_set_password_verifies_and_a_wrong_one_does_not() {
        let dir = scratch("roundtrip");
        let store = DevicePasswords::in_dir(&dir);
        store.set(&person("Mom"), GOOD).expect("stored");

        assert!(store.holds(&person("Mom")));
        assert!(store.verify(&person("Mom"), GOOD));
        assert!(!store.verify(&person("Mom"), "wrong-but-long-enough"));
        assert!(!store.verify(&person("Mom"), ""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The property the whole file exists for: one person's credential is not
    /// another's, and neither is the deployment's.
    #[test]
    fn one_persons_password_opens_nothing_of_anybody_elses() {
        let dir = scratch("distinct");
        let store = DevicePasswords::in_dir(&dir);
        store.set(&person("Mom"), GOOD).unwrap();
        store.set(&person("Dad"), "a-different-long-password").unwrap();

        assert!(store.verify(&person("Mom"), GOOD));
        assert!(!store.verify(&person("Dad"), GOOD), "Mom's password is not Dad's");
        assert!(!store.verify(&person("Nobody"), GOOD), "and it is nobody else's either");
        assert!(!store.holds(&person("Nobody")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The bug the invite flow shipped once: a handle that snapshotted the file
    /// could not see what the CLI wrote in another process.
    #[test]
    fn a_password_set_through_one_handle_is_live_through_another() {
        let dir = scratch("two-handles");
        let daemon = DevicePasswords::in_dir(&dir);
        let cli = DevicePasswords::in_dir(&dir);

        assert!(!daemon.verify(&person("Mom"), GOOD), "nothing set yet");
        cli.set(&person("Mom"), GOOD).expect("the CLI writes");
        assert!(
            daemon.verify(&person("Mom"), GOOD),
            "a handle built before the write must still see it — no restart"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clearing_a_password_stops_it_at_once_and_clearing_again_is_a_no_op() {
        let dir = scratch("clear");
        let store = DevicePasswords::in_dir(&dir);
        store.set(&person("Mom"), GOOD).unwrap();
        assert!(store.clear(&person("Mom")).expect("cleared"));
        assert!(!store.verify(&person("Mom"), GOOD));
        assert!(!store.holds(&person("Mom")));
        assert!(!store.clear(&person("Mom")).expect("a second clear is a no-op"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_store_holds_nobody_and_verifies_nothing() {
        let dir = scratch("missing");
        let store = DevicePasswords::in_dir(&dir);
        assert!(!store.holds(&person("Mom")));
        assert!(!store.verify(&person("Mom"), GOOD));
        assert!(store.holders().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_short_password_is_refused_rather_than_stored() {
        let dir = scratch("short");
        let store = DevicePasswords::in_dir(&dir);
        let refused = store.set(&person("Mom"), "hunter2");
        assert!(refused.is_err());
        assert!(!store.holds(&person("Mom")), "and nothing was written");
        // Exactly at the boundary is accepted.
        store.set(&person("Mom"), &"x".repeat(MIN_PASSWORD_LENGTH)).expect("the boundary");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_file_opens_nothing_rather_than_opening_some() {
        let dir = scratch("malformed");
        let path = DevicePasswords::path_in(&dir);
        let real = selfhost_login::password::hash(GOOD).unwrap();
        let bad = [
            "not json".to_owned(),
            "{}".to_owned(),
            r#"{"devicePasswords":{}}"#.to_owned(),
            // No hash field.
            r#"{"devicePasswords":[{"name":"Mom","setUnix":1}]}"#.to_owned(),
            // The reserved names, in a file somebody hand-edited.
            format!(r#"{{"devicePasswords":[{{"name":"owner","hash":"{real}","setUnix":1}}]}}"#),
            format!(r#"{{"devicePasswords":[{{"name":"machine","hash":"{real}","setUnix":1}}]}}"#),
            // A plaintext password left in the hash field.
            r#"{"devicePasswords":[{"name":"Mom","hash":"hunter2","setUnix":1}]}"#.to_owned(),
            // The same person twice, which would make "which entry" a question.
            format!(
                r#"{{"devicePasswords":[{{"name":"Mom","hash":"{real}","setUnix":1}},
                                        {{"name":"Mom","hash":"{real}","setUnix":2}}]}}"#
            ),
        ];
        for text in bad {
            std::fs::write(&path, &text).expect("writes the fixture");
            let store = DevicePasswords::in_dir(&dir);
            assert!(!store.holds(&person("Mom")), "{text} must load as empty");
            assert!(!store.verify(&person("Mom"), GOOD), "{text} must verify nothing");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_store_is_capped() {
        let dir = scratch("cap");
        let store = DevicePasswords::in_dir(&dir);
        for index in 0..MAX_ENTRIES {
            store.set(&person(&format!("p{index}")), GOOD).expect("under the cap");
        }
        assert!(store.set(&person("one-too-many"), GOOD).is_err());
        // An existing person can still be changed at capacity.
        store.set(&person("p0"), "another-long-password").expect("editing still works");
        assert!(store.verify(&person("p0"), "another-long-password"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_file_round_trips_through_its_own_parser() {
        let entries = vec![
            Entry {
                name: person("Mary-Anne"),
                hash: selfhost_login::password::hash(GOOD).unwrap(),
                set_unix: 1_754_000_000,
            },
            Entry {
                name: person("Mom"),
                hash: selfhost_login::password::hash("another-long-password").unwrap(),
                set_unix: 1,
            },
        ];
        let text = to_json(&entries).to_text();
        assert_eq!(parse(&text).as_deref(), Some(entries.as_slice()));
    }

    #[cfg(unix)]
    #[test]
    fn the_store_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        DevicePasswords::in_dir(&dir).set(&person("Mom"), GOOD).expect("stored");
        let mode = std::fs::metadata(DevicePasswords::path_in(&dir)).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "no group or world access: mode {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_temporary_file_is_left_behind() {
        let dir = scratch("atomic");
        DevicePasswords::in_dir(&dir).set(&person("Mom"), GOOD).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".new"))
            .collect();
        assert!(leftovers.is_empty(), "temporary files left behind: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
