//! Per-person login passwords: the credential behind a real email-and-password
//! sign-in, as opposed to the single shared console password every operator
//! used to type.
//!
//! # Why this is not [`crate::device_password::DevicePasswords`] wearing a new name
//!
//! The two stores are shaped alike on purpose — same file layout, same
//! fail-closed parsing, same "read fresh on every verification" design, for
//! all the reasons `crates/app/admin/src/device_password.rs` gives — but they
//! answer different questions. A device password is typed once into an
//! operating system's mount dialogue and then replayed by a keychain forever;
//! nobody is at the keyboard when it is presented. A login password is typed
//! by a person, at a login form, right now, and it is what
//! [`selfhost_identity::Opening::PersonPassword`] exists to name: a session it
//! opens carries that identity as fact, not as a shared secret's guess, which
//! is what lets it fall through
//! [`selfhost_identity::Policy::decide`]'s console-password demotion
//! untouched — see that type's documentation for the mechanism. Conflating the
//! two stores would conflate an unattended credential with an attended one,
//! which is exactly the distinction the demotion rule exists to preserve.
//!
//! The shorter minimum length below is the other half of that distinction:
//! [`MIN_PASSWORD_LENGTH`] is eight, not sixteen, because a human has to
//! remember this one.
//!
//! # What this store does not do
//!
//! It does not know a person's email. Login is a two-step lookup by design:
//! `selfhost_identity::People::find_by_email` resolves an email to a
//! [`PersonName`], and only then is this store asked to verify a password
//! under that name — the same "who, then how" split every other credential in
//! this deployment follows. Keeping the split means an email can be changed,
//! or never set at all, without this store's file format ever needing to
//! change.
//!
//! It also does not create accounts. Setting a login password on a name the
//! people registry does not know is a credential nobody can ever use, but it
//! is not this crate's place to enforce that — `crates/app/admin/src/lib.rs`
//! checks the registry before it ever reaches this store, the same way it does
//! before writing a device password.

use selfhost_identity::PersonName;
use selfhost_json::Json;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The name of the login-password file inside the data directory.
pub const PERSON_PASSWORD_FILENAME: &str = "console.loginpw";

/// The most entries the store will hold.
///
/// Matched to `selfhost_identity::registry::MAX_PEOPLE`: an entry that names
/// nobody in the people registry can never sign anyone in, because
/// `Policy::decide` answers an unregistered person with an empty grant set. A
/// store larger than the registry could only hold credentials for nobody.
pub const MAX_ENTRIES: usize = 32;

/// The shortest password this will store.
///
/// Eight characters — matched to the reports service's own login accounts
/// (`crates/services/reports/src/accounts.rs`, `MIN_PASSWORD`), which is the
/// one other place in this workspace that already asks a human to type a
/// password at a login form rather than an operating system replaying one
/// from a keychain. See this module's documentation for why that is a
/// materially different credential than
/// [`crate::device_password::MIN_PASSWORD_LENGTH`]'s sixteen.
pub const MIN_PASSWORD_LENGTH: usize = 8;

/// The per-person login passwords, as a handle onto the file.
///
/// Cheap to clone and holds no secret in memory: every method reads the file
/// fresh, for the identical reason `DevicePasswords` does — see this module's
/// sibling for the incident that made a cached snapshot the wrong design for
/// a store the CLI can also write.
#[derive(Debug, Clone)]
pub struct PersonPasswords {
    path: PathBuf,
}

/// One person's stored login credential.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    /// Who it belongs to. The same name their registry entry uses.
    name: PersonName,
    /// The stored `pbkdf2-sha256$<iterations>$<salt>$<derived>` line.
    hash: String,
    /// When it was set, for the console's people list. Not a security field.
    set_unix: u64,
}

impl PersonPasswords {
    /// A handle onto `<data_dir>/console.loginpw`.
    ///
    /// Does not read anything and cannot fail: a store whose constructor
    /// failed on a missing file would make a deployment where nobody has a
    /// login password an error rather than the ordinary case — which is every
    /// deployment today, since this door is new.
    pub fn in_dir(data_dir: &Path) -> Self {
        Self { path: Self::path_in(data_dir) }
    }

    /// Where the file lives for a given data directory.
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(PERSON_PASSWORD_FILENAME)
    }

    /// Whether this person has a login password at all.
    pub fn holds(&self, name: &PersonName) -> bool {
        self.entries().iter().any(|entry| &entry.name == name)
    }

    /// Whether `password` is this person's login password.
    ///
    /// `false` for an unknown person, an empty store, an unreadable file and a
    /// wrong password alike — the caller learns only true or false, the same
    /// rule the console's other login doors already share. See
    /// `crate::device_password::DevicePasswords::verify` for why a person with
    /// no entry is answered just as fast as a wrong password rather than
    /// spending a PBKDF2 round on a name nobody holds: the same
    /// denial-of-service argument applies here unchanged.
    pub fn verify(&self, name: &PersonName, password: &str) -> bool {
        match self.entries().into_iter().find(|entry| &entry.name == name) {
            Some(entry) => selfhost_login::password::verify(&entry.hash, password),
            None => false,
        }
    }

    /// Everybody who holds a login password, and when it was set.
    ///
    /// For the console's people plate, so an operator can see who can sign in
    /// with a password without reading a file of hashes.
    pub fn holders(&self) -> Vec<(PersonName, u64)> {
        self.entries().into_iter().map(|entry| (entry.name, entry.set_unix)).collect()
    }

    /// Sets one person's login password, replacing any they had, and persists.
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
                "a login password must be at least {MIN_PASSWORD_LENGTH} characters"
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
                        "at most {MAX_ENTRIES} people may hold a login password"
                    )));
                }
                entries.push(Entry { name: name.clone(), hash, set_unix: now_unix() });
            }
        }
        self.persist(&entries)
    }

    /// Forgets one person's login password; false if they had none.
    ///
    /// Does not touch their registry entry or their email: revoking a
    /// credential and revoking authority are separate acts, as
    /// `DevicePasswords::clear` already establishes for the mount door.
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
                    "admin: could not read {}: {error}; no login password signs anyone in",
                    self.path.display()
                );
                return Vec::new();
            }
        };
        match parse(&text) {
            Some(entries) => entries,
            None => {
                eprintln!(
                    "admin: {} is not a valid login-password file; no login password signs \
                     anyone in until it is repaired or removed",
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
        let temporary = self.path.with_extension("loginpw.new");
        crate::token::write_private(&temporary, &to_json(entries).to_text())?;
        std::fs::rename(&temporary, &self.path)
    }
}

/// Seconds since the Unix epoch, or zero on a clock set before it.
fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|since| since.as_secs()).unwrap_or(0)
}

/// The stored shape: `{"loginPasswords":[{name, hash, setUnix}]}`.
fn to_json(entries: &[Entry]) -> Json {
    Json::object([(
        "loginPasswords",
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
/// A name that is not a valid [`PersonName`], a duplicate name, a missing
/// field, more than [`MAX_ENTRIES`] entries, a hash that is not this
/// workspace's format — every one of them refuses the whole document, exactly
/// as `crate::device_password`'s own parser does.
fn parse(text: &str) -> Option<Vec<Entry>> {
    let value = selfhost_json::parse(text).ok()?;
    let items = value.get("loginPasswords")?.as_array()?;
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
            .join(format!("selfhost-loginpw-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        path
    }

    fn person(name: &str) -> PersonName {
        PersonName::parse(name).expect("a valid name")
    }

    /// A password long enough for the store to accept.
    const GOOD: &str = "hunter22";

    #[test]
    fn a_set_password_verifies_and_a_wrong_one_does_not() {
        let dir = scratch("roundtrip");
        let store = PersonPasswords::in_dir(&dir);
        store.set(&person("Mom"), GOOD).expect("stored");

        assert!(store.holds(&person("Mom")));
        assert!(store.verify(&person("Mom"), GOOD));
        assert!(!store.verify(&person("Mom"), "wrong-guess"));
        assert!(!store.verify(&person("Mom"), ""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_persons_password_opens_nothing_of_anybody_elses() {
        let dir = scratch("distinct");
        let store = PersonPasswords::in_dir(&dir);
        store.set(&person("Mom"), GOOD).unwrap();
        store.set(&person("Dad"), "dad-password").unwrap();

        assert!(store.verify(&person("Mom"), GOOD));
        assert!(!store.verify(&person("Dad"), GOOD), "Mom's password is not Dad's");
        assert!(!store.verify(&person("Nobody"), GOOD), "and it is nobody else's either");
        assert!(!store.holds(&person("Nobody")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_password_set_through_one_handle_is_live_through_another() {
        let dir = scratch("two-handles");
        let daemon = PersonPasswords::in_dir(&dir);
        let cli = PersonPasswords::in_dir(&dir);

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
        let store = PersonPasswords::in_dir(&dir);
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
        let store = PersonPasswords::in_dir(&dir);
        assert!(!store.holds(&person("Mom")));
        assert!(!store.verify(&person("Mom"), GOOD));
        assert!(store.holders().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_short_password_is_refused_rather_than_stored() {
        let dir = scratch("short");
        let store = PersonPasswords::in_dir(&dir);
        let refused = store.set(&person("Mom"), "sh0rt");
        assert!(refused.is_err());
        assert!(!store.holds(&person("Mom")), "and nothing was written");
        store.set(&person("Mom"), &"x".repeat(MIN_PASSWORD_LENGTH)).expect("the boundary");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_file_signs_nobody_in_rather_than_signing_some_in() {
        let dir = scratch("malformed");
        let path = PersonPasswords::path_in(&dir);
        let real = selfhost_login::password::hash(GOOD).unwrap();
        let bad = [
            "not json".to_owned(),
            "{}".to_owned(),
            r#"{"loginPasswords":{}}"#.to_owned(),
            r#"{"loginPasswords":[{"name":"Mom","setUnix":1}]}"#.to_owned(),
            format!(r#"{{"loginPasswords":[{{"name":"owner","hash":"{real}","setUnix":1}}]}}"#),
            format!(r#"{{"loginPasswords":[{{"name":"machine","hash":"{real}","setUnix":1}}]}}"#),
            r#"{"loginPasswords":[{"name":"Mom","hash":"hunter2","setUnix":1}]}"#.to_owned(),
            format!(
                r#"{{"loginPasswords":[{{"name":"Mom","hash":"{real}","setUnix":1}},
                                       {{"name":"Mom","hash":"{real}","setUnix":2}}]}}"#
            ),
        ];
        for text in bad {
            std::fs::write(&path, &text).expect("writes the fixture");
            let store = PersonPasswords::in_dir(&dir);
            assert!(!store.holds(&person("Mom")), "{text} must load as empty");
            assert!(!store.verify(&person("Mom"), GOOD), "{text} must verify nothing");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_store_is_capped() {
        let dir = scratch("cap");
        let store = PersonPasswords::in_dir(&dir);
        for index in 0..MAX_ENTRIES {
            store.set(&person(&format!("p{index}")), GOOD).expect("under the cap");
        }
        assert!(store.set(&person("one-too-many"), GOOD).is_err());
        store.set(&person("p0"), "another-password").expect("editing still works");
        assert!(store.verify(&person("p0"), "another-password"));
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
                hash: selfhost_login::password::hash("another-password").unwrap(),
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
        PersonPasswords::in_dir(&dir).set(&person("Mom"), GOOD).expect("stored");
        let mode = std::fs::metadata(PersonPasswords::path_in(&dir)).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "no group or world access: mode {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_temporary_file_is_left_behind() {
        let dir = scratch("atomic");
        PersonPasswords::in_dir(&dir).set(&person("Mom"), GOOD).unwrap();
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
