//! Report Filers: who filed a report, and how they prove it later.
//!
//! Filing itself stays anonymous by default — [`crate::service`]'s open `POST` door is
//! unchanged. A report filer is what lets the *same* person come back, see the reports they filed,
//! and manage them, without changing anything about the door a stranger with no filer credentials
//! still walks through.
//!
//! # Email is the identity; the id is not
//!
//! A report filer is created with an email address and keyed by a random id (`acct-` and 32 hex
//! digits) rather than by the email itself, so a later email change never has to rewrite every
//! [`crate::store::Entry::account_id`] that already points at this filer. Lookup by email
//! re-parses the stored address and compares with [`selfhost_mail::Address::matches`] — the same
//! case-folding rule the mail crate uses for routing — rather than a raw string compare, so
//! `Alice@example.com` and `alice@Example.com` are one filer exactly as they are one mailbox.
//!
//! # The store is one file, like the sibling credential stores
//!
//! `<data_dir>/reports/accounts.json`, loaded whole into memory and rewritten by temporary file
//! and rename — the same shape as `crates/admin/src/webauthn.rs`'s `Passkeys` and
//! `crates/admin/src/invite.rs`'s `Invites`. A report's own database is a directory of many
//! records because there can be tens of thousands of them and each is looked up by its own id;
//! an account list this box will ever hold is small enough that "read it all, scan it in memory"
//! is the honest shape, not a premature one.
//!
//! # Passwords go through `selfhost_login`
//!
//! The PBKDF2 hashing/verification below used to be a byte-identical copy of
//! `crates/admin/src/passwd.rs`, on the reasoning that pulling in `selfhost-admin` — WebAuthn,
//! DACL-writing Windows FFI, the whole console — to verify one password was worse than the
//! duplication. `selfhost-login` removes that tradeoff: it is only ever password hashing and
//! session cookies, so both crates depend on it instead of each carrying their own copy.
//!
//! # What a plan is, today
//!
//! [`ReportFiler::plan`] is a free-form, capped word — `"free"` unless something else writes it.
//! Nothing in this crate charges anyone anything; the field exists so a later billing
//! integration has somewhere to write `"supporter"` rather than a schema migration to add one.

use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use selfhost_json::Json;
use selfhost_mail::Address;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// The name of the account file inside `<data_dir>/reports/`.
pub const ACCOUNTS_FILENAME: &str = "accounts.json";

/// The most accounts this box will hold. Registration is a door open to the internet, so it is
/// bounded like every other one: past this, registration is refused in a sentence rather than
/// growing the file without end.
pub const MAX_ACCOUNTS: usize = 10_000;

/// The most OAuth identities one account may carry linked. Nobody has more than a handful of
/// sign-in providers; this is a wall against a loop, not a real limit anyone should hit.
pub const MAX_OAUTH_LINKS: usize = 8;

/// The most report references one account's `filed` list keeps. This is a dashboard's "recent
/// reports" list, not the database of record — [`crate::store::Store`] still holds every report
/// in full; past this cap the oldest reference is dropped and the report itself is unaffected,
/// still reachable through the owner's feed like any other.
pub const MAX_FILED_PER_ACCOUNT: usize = 500;

/// The shortest accepted password. PBKDF2 at 600,000 iterations already does the expensive
/// work; this exists only to refuse the handful of passwords too short to be a password at all.
pub const MIN_PASSWORD: usize = 8;

/// The longest accepted password. A cap independent of any one route's body limit, so this
/// module's own behaviour is bounded no matter what calls it.
pub const MAX_PASSWORD: usize = 200;

/// Bytes of entropy in an account id.
const ACCOUNT_ID_BYTES: usize = 16;

/// Why an account operation could not be carried out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountError {
    /// An account already exists for this email.
    EmailTaken,
    /// The box already holds [`MAX_ACCOUNTS`].
    Full,
    /// The password is shorter than [`MIN_PASSWORD`] or longer than [`MAX_PASSWORD`].
    WeakPassword,
    /// The email did not parse as one, named with the *reason* it did not.
    ///
    /// Deliberately never the address itself. `crate::service`'s module documentation states
    /// that a refusal from this box "names the field that was wrong, never the value", and this
    /// message is rendered straight into the register page's error line — an earlier draft
    /// interpolated the caller's own text here, which handed an anonymous `POST` a way to put
    /// bytes of its choosing in front of somebody else's browser. The parse reason
    /// ([`selfhost_mail::AddressError`]) is a fixed sentence from a fixed set, so it carries
    /// everything a person mistyping their address needs and nothing an attacker chose.
    BadEmail(String),
    /// No account carries this id.
    NotFound,
    /// The filesystem refused, named with the reason.
    Io(String),
}

impl std::fmt::Display for AccountError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmailTaken => out.write_str("an account already exists for this email"),
            Self::Full => out.write_str(&format!("this box already holds {MAX_ACCOUNTS} accounts")),
            Self::WeakPassword => out.write_str(&format!(
                "a password must be {MIN_PASSWORD} to {MAX_PASSWORD} characters"
            )),
            Self::BadEmail(message) => out.write_str(message),
            Self::NotFound => out.write_str("no such account"),
            Self::Io(message) => out.write_str(message),
        }
    }
}

impl std::error::Error for AccountError {}

/// One OAuth identity linked to a report filer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilingOAuthLink {
    /// The provider's configured name — `"google"`, `"github"` — matching
    /// [`crate::oauth::Provider::name`].
    pub provider: String,
    /// The provider's own subject identifier for this person, stable for their filing identity there.
    pub subject: String,
}

/// A reference to one report this filer filed — enough to look it up in
/// [`crate::store::Store`], never a copy of its content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiledReport {
    /// The project the report is about.
    pub project: String,
    /// The report's own id.
    pub id: String,
}

/// One registered report filer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportFiler {
    /// `acct-` and 32 hex digits, random and never reused.
    pub id: String,
    /// The address this filer was registered with, in [`Address`]'s canonical form.
    pub email: String,
    /// Whether that address has been confirmed reachable — by a clicked verification link, or
    /// because an OAuth provider vouched for it at sign-in.
    pub email_verified: bool,
    /// The PBKDF2 hash of this filer's password, or `None` when it has none — a passkey- or
    /// OAuth-only filer is not weaker for lacking one.
    pub password: Option<String>,
    /// Every OAuth identity that may sign in as this filer.
    pub oauth_links: Vec<FilingOAuthLink>,
    /// The reports this filer filed while signed in, newest last, capped at
    /// [`MAX_FILED_PER_ACCOUNT`]. The dashboard's "my reports" list reads this and then asks
    /// [`crate::store::Store::get`] for each one's current content.
    pub filed: Vec<FiledReport>,
    /// When this filer was created, seconds since the Unix epoch.
    pub created_unix: u64,
    /// A free-form, capped word naming what this filer's plan is. `"free"` until
    /// something else writes it — see the module documentation.
    pub plan: String,
}

impl ReportFiler {
    /// Whether anybody ever *proved* that whoever holds this filer account also holds the address on
    /// it — as opposed to merely having typed that address in.
    ///
    /// This is the question [`crate::service::Service::oauth_account`] must ask before it lets a
    /// sign-in provider merge a new identity into a filer it found **by email address alone**,
    /// and it is a different question from "does this filer have a credential". Every door
    /// into this store — [`ReportFilers::create_with_password`], [`ReportFilers::create_pending`], an
    /// [`ReportFilers::create_with_oauth`] from a provider that does not vouch — lets a stranger name
    /// any address at all, including one that is not theirs, and hang their own password or
    /// passkey off it. Exactly two things write [`ReportFiler::email_verified`], and both are proof:
    /// [`ReportFilers::mark_verified`], reached only by clicking a link this box mailed *to that
    /// address*, and [`ReportFilers::create_with_oauth`] with a provider's own verified-email claim.
    ///
    /// So the flag is the whole answer, and this method exists to say so by name at the one call
    /// site where being wrong is a filer takeover rather than a cosmetic bug.
    #[must_use]
    pub fn email_proven(&self) -> bool {
        self.email_verified
    }
}

/// The durable report filer store: `<data_dir>/reports/accounts.json`, owner-only, JSON.
///
/// A cheap-clone handle over shared state, like `crates/admin`'s `Passkeys`/`Invites`: every
/// clone reads and writes the same file through the same lock, so a registration made through
/// one handle is visible to a lookup through another in the same process.
#[derive(Clone)]
pub struct ReportFilers {
    path: PathBuf,
    entries: Arc<Mutex<Vec<ReportFiler>>>,
}

impl ReportFilers {
    /// Loads the store from `<data_dir>/accounts.json`.
    ///
    /// A missing file is an empty store. A malformed one loads empty and says so once, the same
    /// fail-closed shape every credential file in this workspace takes: a filer store nobody
    /// can read a stranger's password out of is worth more than one that limps on half-parsed.
    pub fn load(data_dir: &Path) -> Self {
        let path = Self::path_in(data_dir);
        let entries = match std::fs::read_to_string(&path) {
            Ok(text) => match parse_filers(&text) {
                Some(entries) => entries,
                None => {
                    eprintln!(
                        "reports: {} is not a valid filer file; filers are unreachable \
                         until it is repaired or removed",
                        path.display()
                    );
                    Vec::new()
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => {
                eprintln!(
                    "reports: could not read {}: {error}; filers are unreachable",
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

    /// Where the account file lives for a given data directory.
    #[must_use]
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(ACCOUNTS_FILENAME)
    }

    /// The filer with this id, if any.
    #[must_use]
    pub fn find_by_id(&self, id: &str) -> Option<ReportFiler> {
        self.lock().iter().find(|entry| entry.id == id).cloned()
    }

    /// The filer registered under this email, if any — compared the way
    /// [`selfhost_mail::Address::matches`] compares, never as raw strings.
    #[must_use]
    pub fn find_by_email(&self, email: &Address) -> Option<ReportFiler> {
        self.lock()
            .iter()
            .find(|entry| Address::parse(&entry.email).is_ok_and(|stored| stored.matches(email)))
            .cloned()
    }

    /// The filer linked to this OAuth identity, if any.
    #[must_use]
    pub fn find_by_oauth(&self, provider: &str, subject: &str) -> Option<ReportFiler> {
        self.lock()
            .iter()
            .find(|entry| {
                entry
                    .oauth_links
                    .iter()
                    .any(|link| link.provider == provider && link.subject == subject)
            })
            .cloned()
    }

    /// Creates a filer with `email` and `password`, hashed here.
    ///
    /// # Errors
    /// [`AccountError::BadEmail`] when the address does not parse, [`AccountError::WeakPassword`]
    /// outside [`MIN_PASSWORD`]..=[`MAX_PASSWORD`], [`AccountError::EmailTaken`] when a filer
    /// already answers to this address, [`AccountError::Full`] at [`MAX_ACCOUNTS`].
    pub fn create_with_password(
        &self,
        email: &str,
        password: &str,
    ) -> Result<ReportFiler, AccountError> {
        let address = Address::parse(email.trim()).map_err(|error| {
            AccountError::BadEmail(format!("`email` is not an address: {error}"))
        })?;
        let characters = password.chars().count();
        if !(MIN_PASSWORD..=MAX_PASSWORD).contains(&characters) {
            return Err(AccountError::WeakPassword);
        }
        let hashed =
            hash_password(password).map_err(|error| AccountError::Io(error.to_string()))?;
        self.insert(ReportFiler {
            id: String::new(), // filled in by `insert`
            email: address.to_string(),
            email_verified: false,
            password: Some(hashed),
            oauth_links: Vec::new(),
            filed: Vec::new(),
            created_unix: now_unix(),
            plan: "free".to_string(),
        })
    }

    /// Creates a filer linked to one OAuth identity, with no password.
    ///
    /// `email_verified` is the provider's own claim, passed in rather than assumed — see
    /// [`crate::oauth`] for what this box requires before it trusts it.
    ///
    /// # Errors
    /// The same as [`Self::create_with_password`], minus the password checks.
    pub fn create_with_oauth(
        &self,
        email: &str,
        email_verified: bool,
        provider: &str,
        subject: &str,
    ) -> Result<ReportFiler, AccountError> {
        let address = Address::parse(email.trim()).map_err(|error| {
            AccountError::BadEmail(format!("`email` is not an address: {error}"))
        })?;
        self.insert(ReportFiler {
            id: String::new(),
            email: address.to_string(),
            email_verified,
            password: None,
            oauth_links: vec![FilingOAuthLink {
                provider: provider.to_string(),
                subject: subject.to_string(),
            }],
            filed: Vec::new(),
            created_unix: now_unix(),
            plan: "free".to_string(),
        })
    }

    /// Creates a filer with `email` and no credential at all yet — the passkey self-service
    /// door, which mints the filer first and adds the passkey once the ceremony that proves it
    /// succeeds. See `crate::webauthn`.
    ///
    /// # Errors
    /// The same as [`Self::create_with_password`], minus the password checks.
    pub fn create_pending(&self, email: &str) -> Result<ReportFiler, AccountError> {
        let address = Address::parse(email.trim()).map_err(|error| {
            AccountError::BadEmail(format!("`email` is not an address: {error}"))
        })?;
        self.insert(ReportFiler {
            id: String::new(),
            email: address.to_string(),
            email_verified: false,
            password: None,
            oauth_links: Vec::new(),
            filed: Vec::new(),
            created_unix: now_unix(),
            plan: "free".to_string(),
        })
    }

    /// Links `provider`/`subject` to the filer `id`, so a later OAuth login with the same
    /// identity finds it. A link already present for this provider is left as it was rather
    /// than duplicated.
    ///
    /// # Errors
    /// [`AccountError::NotFound`] when `id` names no filer, or an [`AccountError::Io`] naming
    /// what could not be persisted.
    pub fn link_oauth(&self, id: &str, provider: &str, subject: &str) -> Result<(), AccountError> {
        self.update(id, |filer| {
            if filer
                .oauth_links
                .iter()
                .any(|link| link.provider == provider)
            {
                return Ok(());
            }
            if filer.oauth_links.len() >= MAX_OAUTH_LINKS {
                return Err(AccountError::Io(format!(
                    "a filer may link at most {MAX_OAUTH_LINKS} sign-in providers"
                )));
            }
            filer.oauth_links.push(FilingOAuthLink {
                provider: provider.to_string(),
                subject: subject.to_string(),
            });
            Ok(())
        })
    }

    /// Marks the filer's email verified.
    ///
    /// # Errors
    /// [`AccountError::NotFound`] or an [`AccountError::Io`].
    pub fn mark_verified(&self, id: &str) -> Result<(), AccountError> {
        self.update(id, |filer| {
            filer.email_verified = true;
            Ok(())
        })
    }

    /// Replaces the filer's password.
    ///
    /// # Errors
    /// [`AccountError::WeakPassword`], [`AccountError::NotFound`], or an [`AccountError::Io`].
    pub fn set_password(&self, id: &str, password: &str) -> Result<(), AccountError> {
        let characters = password.chars().count();
        if !(MIN_PASSWORD..=MAX_PASSWORD).contains(&characters) {
            return Err(AccountError::WeakPassword);
        }
        let hashed =
            hash_password(password).map_err(|error| AccountError::Io(error.to_string()))?;
        self.update(id, |filer| {
            filer.password = Some(hashed);
            Ok(())
        })
    }

    /// Records that this filer filed `project`/`id` — called once, when the report is fresh;
    /// see `crate::store::Entry::account_id` for why a repeat sighting never calls this again.
    /// Past [`MAX_FILED_PER_ACCOUNT`] the oldest reference is dropped; the report itself is
    /// unaffected and stays reachable through the owner's feed.
    ///
    /// # Errors
    /// [`AccountError::NotFound`] or an [`AccountError::Io`].
    pub fn record_filed(
        &self,
        account_id: &str,
        project: &str,
        id: &str,
    ) -> Result<(), AccountError> {
        self.update(account_id, |filer| {
            filer.filed.push(FiledReport {
                project: project.to_string(),
                id: id.to_string(),
            });
            if filer.filed.len() > MAX_FILED_PER_ACCOUNT {
                let excess = filer.filed.len() - MAX_FILED_PER_ACCOUNT;
                filer.filed.drain(..excess);
            }
            Ok(())
        })
    }

    /// Removes `project`/`id` from this filer's filed list — called when its own report is
    /// withdrawn, so a closed report does not linger in a dashboard's list.
    ///
    /// # Errors
    /// [`AccountError::NotFound`] or an [`AccountError::Io`].
    pub fn remove_filed(
        &self,
        account_id: &str,
        project: &str,
        id: &str,
    ) -> Result<(), AccountError> {
        self.update(account_id, |filer| {
            filer
                .filed
                .retain(|reference| !(reference.project == project && reference.id == id));
            Ok(())
        })
    }

    /// Whether `password` matches the filer's stored hash. `false` for a filer with no
    /// password set — a passkey- or OAuth-only filer never has a password to guess.
    #[must_use]
    pub fn verify_password(&self, filer: &ReportFiler, password: &str) -> bool {
        match &filer.password {
            Some(stored) => selfhost_login::password::verify(stored, password),
            None => false,
        }
    }

    /// Inserts `filer`, assigning it a fresh id, enforcing [`MAX_ACCOUNTS`] and the one
    /// filer per email rule, and persisting.
    fn insert(&self, mut filer: ReportFiler) -> Result<ReportFiler, AccountError> {
        let mut entries = self.lock();
        let address = Address::parse(&filer.email).expect("just parsed by the caller");
        if entries
            .iter()
            .any(|entry| Address::parse(&entry.email).is_ok_and(|stored| stored.matches(&address)))
        {
            return Err(AccountError::EmailTaken);
        }
        if entries.len() >= MAX_ACCOUNTS {
            return Err(AccountError::Full);
        }
        filer.id = fresh_id().map_err(|error| AccountError::Io(error.to_string()))?;
        entries.push(filer.clone());
        self.persist(&entries)
            .map_err(|error| AccountError::Io(error.to_string()))?;
        Ok(filer)
    }

    /// Applies `change` to the filer named `id` and persists.
    fn update(
        &self,
        id: &str,
        change: impl FnOnce(&mut ReportFiler) -> Result<(), AccountError>,
    ) -> Result<(), AccountError> {
        let mut entries = self.lock();
        let filer = entries
            .iter_mut()
            .find(|entry| entry.id == id)
            .ok_or(AccountError::NotFound)?;
        change(filer)?;
        self.persist(&entries)
            .map_err(|error| AccountError::Io(error.to_string()))
    }

    /// Writes the store owner-only via a temporary file and rename, like every sibling
    /// credential store.
    fn persist(&self, entries: &[ReportFiler]) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = filers_to_json(entries).to_text();
        let temporary = self.path.with_extension("json.tmp");
        std::fs::write(&temporary, &text)?;
        restrict(&temporary);
        std::fs::rename(&temporary, &self.path)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<ReportFiler>> {
        self.entries
            .lock()
            .expect("the filer store lock was poisoned")
    }
}

// Deliberately not a revealing `Debug`: a password hash in a log line is a head start for an
// offline guesser, and an email list is a target list.
impl std::fmt::Debug for ReportFilers {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "ReportFilers({} registered)", self.lock().len())
    }
}

/// A fresh account id: `acct-` and 32 hex digits from the operating system's entropy.
fn fresh_id() -> io::Result<String> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; ACCOUNT_ID_BYTES];
    rng.fill(&mut bytes)
        .map_err(|_| io::Error::other("the system random source was unavailable"))?;
    Ok(format!("acct-{}", hex(&bytes)))
}

/// Seconds since the Unix epoch, or zero on a clock set before it — the same convention
/// `crate::report` and the sibling admin stores use, so a report and the account that filed it
/// never disagree about the direction "before" points.
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

/// Hashes a password as `pbkdf2-sha256$<iterations>$<salt>$<derived>` via `selfhost_login`.
fn hash_password(password: &str) -> io::Result<String> {
    selfhost_login::password::hash(password)
}

/// Restricts `path` to its owner where the platform has such a concept — the same helper every
/// store in this crate and its siblings in `crates/admin` carry their own copy of.
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

/// Lowercase hex of `bytes`.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            out.push_str(&format!("{byte:02x}"));
            out
        })
}

/// Lowercase hex of the SHA-256 of `bytes` — used by callers that need to fingerprint something
/// (an email, for a log line that must not carry the address itself) without storing it.
#[must_use]
pub fn email_fingerprint(email: &str) -> String {
    digest(&SHA256, email.as_bytes())
        .as_ref()
        .iter()
        .take(4)
        .fold(String::new(), |mut out, byte| {
            out.push_str(&format!("{byte:02x}"));
            out
        })
}

/// The stored file's JSON shape: `{"accounts": [{id, email, emailVerified, password,
/// oauthLinks: [{provider, subject}], createdUnix, plan}]}`.
/// Field names match the original for wire format compatibility.
fn filers_to_json(entries: &[ReportFiler]) -> Json {
    Json::object([(
        "accounts",
        Json::array(entries.iter().map(|filer| {
            Json::object([
                ("id", Json::string(&filer.id)),
                ("email", Json::string(&filer.email)),
                ("emailVerified", Json::Bool(filer.email_verified)),
                (
                    "password",
                    filer.password.as_ref().map_or(Json::Null, Json::string),
                ),
                (
                    "oauthLinks",
                    Json::array(filer.oauth_links.iter().map(|link| {
                        Json::object([
                            ("provider", Json::string(&link.provider)),
                            ("subject", Json::string(&link.subject)),
                        ])
                    })),
                ),
                (
                    "filed",
                    Json::array(filer.filed.iter().map(|reference| {
                        Json::object([
                            ("project", Json::string(&reference.project)),
                            ("id", Json::string(&reference.id)),
                        ])
                    })),
                ),
                ("createdUnix", Json::Number(filer.created_unix as f64)),
                ("plan", Json::string(&filer.plan)),
            ])
        })),
    )])
}

/// Parses the stored file. `None` for anything malformed — a duplicate email or id included,
/// since either could only be corruption and both would otherwise let one email answer to two
/// filers.
fn parse_filers(text: &str) -> Option<Vec<ReportFiler>> {
    let value = selfhost_json::parse(text).ok()?;
    let items = value.get("accounts")?.as_array()?;
    if items.len() > MAX_ACCOUNTS {
        return None;
    }
    let mut entries: Vec<ReportFiler> = Vec::new();
    for item in items {
        let id = item.get("id")?.as_str()?.to_owned();
        let email = item.get("email")?.as_str()?.to_owned();
        if Address::parse(&email).is_err() {
            return None;
        }
        if entries
            .iter()
            .any(|entry| entry.id == id || entry.email == email)
        {
            return None;
        }
        let oauth_links = item
            .get("oauthLinks")
            .and_then(Json::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        Some(FilingOAuthLink {
                            provider: item.get("provider")?.as_str()?.to_owned(),
                            subject: item.get("subject")?.as_str()?.to_owned(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let filed = item
            .get("filed")
            .and_then(Json::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        Some(FiledReport {
                            project: item.get("project")?.as_str()?.to_owned(),
                            id: item.get("id")?.as_str()?.to_owned(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        entries.push(ReportFiler {
            id,
            email,
            email_verified: item
                .get("emailVerified")
                .and_then(Json::as_bool)
                .unwrap_or(false),
            password: item
                .get("password")
                .and_then(Json::as_str)
                .map(str::to_string),
            oauth_links,
            filed,
            created_unix: item.get("createdUnix")?.as_u64()?,
            plan: item
                .get("plan")
                .and_then(Json::as_str)
                .unwrap_or("free")
                .to_string(),
        });
    }
    Some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "selfhost-reports-accounts-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn a_registered_filer_verifies_its_own_password_and_no_other() {
        let dir = scratch("password");
        let filers = ReportFilers::load(&dir);
        let filer = filers
            .create_with_password("Alice@example.com", "hunter2fish")
            .expect("registers");
        assert!(filer.id.starts_with("acct-"));
        assert!(!filer.email_verified);
        assert!(filers.verify_password(&filer, "hunter2fish"));
        assert!(!filers.verify_password(&filer, "wrong"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_filer_with_no_password_never_verifies_one() {
        let dir = scratch("no-password");
        let filers = ReportFilers::load(&dir);
        let filer = filers
            .create_with_oauth("alex@example.com", true, "google", "sub-1")
            .expect("registers");
        assert!(!filers.verify_password(&filer, ""));
        assert!(!filers.verify_password(&filer, "anything"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn email_lookup_folds_case_the_way_the_mail_crate_routes() {
        let dir = scratch("case");
        let filers = ReportFilers::load(&dir);
        filers
            .create_with_password("Alice@Example.com", "hunter2fish")
            .expect("registers");
        let found = filers
            .find_by_email(&Address::parse("alice@example.com").unwrap())
            .expect("found despite different case");
        assert_eq!(
            found.email, "Alice@example.com",
            "the original case is kept in storage"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_filers_cannot_share_one_email() {
        let dir = scratch("taken");
        let filers = ReportFilers::load(&dir);
        filers
            .create_with_password("alice@example.com", "hunter2fish")
            .expect("first registers");
        let error = filers
            .create_with_password("Alice@Example.com", "differentpw")
            .expect_err("refused");
        assert_eq!(error, AccountError::EmailTaken);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_password_outside_the_bounds_is_refused_before_anything_is_hashed() {
        let dir = scratch("weak");
        let filers = ReportFilers::load(&dir);
        assert_eq!(
            filers
                .create_with_password("a@example.com", "short")
                .unwrap_err(),
            AccountError::WeakPassword
        );
        assert_eq!(
            filers
                .create_with_password("a@example.com", &"x".repeat(MAX_PASSWORD + 1))
                .unwrap_err(),
            AccountError::WeakPassword
        );
        assert!(
            filers
                .find_by_email(&Address::parse("a@example.com").unwrap())
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_address_that_is_not_an_address_is_refused_by_name() {
        let dir = scratch("bad-email");
        let filers = ReportFilers::load(&dir);
        let error = filers
            .create_with_password("not an address", "hunter2fish")
            .expect_err("refused");
        assert!(matches!(error, AccountError::BadEmail(_)), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `crate::service`'s module documentation promises a refusal "names the field that was
    /// wrong, never the value". Every door that parses an address must keep that promise, or an
    /// anonymous `POST` gets to choose bytes that land in somebody else's browser.
    #[test]
    fn a_refused_address_names_the_field_and_never_repeats_what_was_sent() {
        let dir = scratch("bad-email-not-echoed");
        let filers = ReportFilers::load(&dir);
        let payload = "<script>alert(1)</script>";
        let refusals = [
            filers
                .create_with_password(payload, "hunter2fish")
                .expect_err("refused"),
            filers
                .create_with_oauth(payload, true, "google", "sub-1")
                .expect_err("refused"),
            filers.create_pending(payload).expect_err("refused"),
        ];
        for error in refusals {
            let message = error.to_string();
            assert!(
                !message.contains(payload),
                "the refusal echoed what was sent: {message}"
            );
            assert!(
                message.starts_with("`email` is not an address"),
                "{message}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The seam a filer takeover ran through: "this filer has a credential" is not
    /// "somebody proved this address is theirs", and only the second may be merged into by
    /// address alone.
    #[test]
    fn an_address_counts_as_proven_only_once_something_actually_proved_it() {
        let dir = scratch("email-proven");
        let filers = ReportFilers::load(&dir);

        let squatted = filers
            .create_pending("victim@example.com")
            .expect("registers");
        assert!(
            !squatted.email_proven(),
            "naming an address is not proving it"
        );

        let with_password = filers
            .create_with_password("typed-it-in@example.com", "hunter2fish")
            .expect("registers");
        assert!(
            !with_password.email_proven(),
            "a password proves a password, not an address"
        );

        let unvouched = filers
            .create_with_oauth("unvouched@example.com", false, "example", "sub-1")
            .expect("registers");
        assert!(!unvouched.email_proven());

        let vouched = filers
            .create_with_oauth("vouched@example.com", true, "example", "sub-2")
            .expect("registers");
        assert!(vouched.email_proven(), "the provider checked");

        filers.mark_verified(&squatted.id).expect("verified");
        assert!(
            filers
                .find_by_id(&squatted.id)
                .expect("still there")
                .email_proven(),
            "a clicked verification link is the other proof"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oauth_linking_finds_the_filer_back_by_provider_and_subject() {
        let dir = scratch("oauth-link");
        let filers = ReportFilers::load(&dir);
        let filer = filers
            .create_pending("alex@example.com")
            .expect("registers");
        filers
            .link_oauth(&filer.id, "google", "sub-42")
            .expect("linked");
        let found = filers
            .find_by_oauth("google", "sub-42")
            .expect("found by the link");
        assert_eq!(found.id, filer.id);
        assert!(filers.find_by_oauth("google", "sub-99").is_none());
        assert!(
            filers.find_by_oauth("github", "sub-42").is_none(),
            "the provider must match too"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn linking_the_same_provider_twice_does_not_duplicate() {
        let dir = scratch("oauth-relink");
        let filers = ReportFilers::load(&dir);
        let filer = filers
            .create_pending("alex@example.com")
            .expect("registers");
        filers
            .link_oauth(&filer.id, "google", "sub-1")
            .expect("linked");
        filers
            .link_oauth(&filer.id, "google", "sub-1")
            .expect("linked again is a no-op");
        let reloaded = filers.find_by_id(&filer.id).expect("found");
        assert_eq!(reloaded.oauth_links.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn filed_reports_are_recorded_and_withdrawn_ones_are_removed() {
        let dir = scratch("filed");
        let filers = ReportFilers::load(&dir);
        let filer = filers
            .create_pending("alex@example.com")
            .expect("registers");
        filers
            .record_filed(&filer.id, "dx", "report-aaaa1111")
            .expect("recorded");
        filers
            .record_filed(&filer.id, "dx", "report-bbbb2222")
            .expect("recorded");
        let reloaded = filers.find_by_id(&filer.id).expect("found");
        assert_eq!(reloaded.filed.len(), 2);

        filers
            .remove_filed(&filer.id, "dx", "report-aaaa1111")
            .expect("removed");
        let after = filers.find_by_id(&filer.id).expect("found");
        assert_eq!(after.filed.len(), 1);
        assert_eq!(after.filed[0].id, "report-bbbb2222");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_filed_list_is_capped_and_drops_the_oldest() {
        let dir = scratch("filed-cap");
        let filers = ReportFilers::load(&dir);
        let filer = filers
            .create_pending("alex@example.com")
            .expect("registers");
        for nth in 0..(MAX_FILED_PER_ACCOUNT + 10) {
            filers
                .record_filed(&filer.id, "dx", &format!("report-{nth:08x}"))
                .expect("recorded");
        }
        let reloaded = filers.find_by_id(&filer.id).expect("found");
        assert_eq!(reloaded.filed.len(), MAX_FILED_PER_ACCOUNT);
        assert_eq!(
            reloaded.filed.last().unwrap().id,
            format!("report-{:08x}", MAX_FILED_PER_ACCOUNT + 9),
            "the most recent reference is kept"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verifying_an_email_and_setting_a_password_persist_across_a_reload() {
        let dir = scratch("persist");
        let filers = ReportFilers::load(&dir);
        let filer = filers
            .create_pending("alex@example.com")
            .expect("registers");
        filers.mark_verified(&filer.id).expect("verified");
        filers
            .set_password(&filer.id, "brandnewpassword")
            .expect("password set");

        let reloaded = ReportFilers::load(&dir);
        let found = reloaded
            .find_by_id(&filer.id)
            .expect("found after reload");
        assert!(found.email_verified);
        assert!(reloaded.verify_password(&found, "brandnewpassword"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_filer_file_written_before_the_plan_field_existed_still_parses() {
        // `plan` did not exist when the filer store's format was first written; a stored
        // filer with no such field must still load rather than being treated as corruption.
        let dir = scratch("pre-plan");
        std::fs::write(
            ReportFilers::path_in(&dir),
            r#"{"accounts":[
                {"id":"acct-1","email":"a@example.com","emailVerified":false,"password":null,"oauthLinks":[],"createdUnix":1}
            ]}"#,
        )
        .unwrap();
        let found = ReportFilers::load(&dir)
            .find_by_id("acct-1")
            .expect("still parses");
        assert_eq!(found.plan, "free");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unknown_id_is_refused_by_name_rather_than_panicking() {
        let dir = scratch("not-found");
        let filers = ReportFilers::load(&dir);
        assert_eq!(
            filers.mark_verified("acct-deadbeef").unwrap_err(),
            AccountError::NotFound
        );
        assert_eq!(
            filers
                .set_password("acct-deadbeef", "longenoughpassword")
                .unwrap_err(),
            AccountError::NotFound
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn registration_past_the_cap_is_refused_while_existing_filers_keep_working() {
        let dir = scratch("cap");
        // Seeded directly at `MAX_ACCOUNTS - 1` in one write, rather than by looping
        // `create_*` that many times: `insert` rewrites the whole file on every call, so a
        // tight loop to the cap pays for that rewrite ten thousand times over just to reach
        // the boundary this test actually cares about. One seed write plus the two calls
        // at the boundary prove the same bound `insert` enforces.
        let filers = ReportFilers::load(&dir);
        let seeded = (0..MAX_ACCOUNTS - 1).map(|nth| ReportFiler {
            id: format!("acct-{nth:028x}"),
            email: format!("user{nth}@example.com"),
            email_verified: false,
            password: None,
            oauth_links: Vec::new(),
            filed: Vec::new(),
            created_unix: 0,
            plan: "free".to_string(),
        });
        filers.lock().extend(seeded);

        filers
            .create_pending("last-one-under-the-cap@example.com")
            .expect("the final slot is still open");
        let error = filers
            .create_pending("one-too-many@example.com")
            .expect_err("refused");
        assert_eq!(error, AccountError::Full);
        assert!(
            filers
                .find_by_email(&Address::parse("user0@example.com").unwrap())
                .is_some(),
            "filers already registered keep working"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_filer_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        ReportFilers::load(&dir)
            .create_with_password("alex@example.com", "hunter2fish")
            .expect("registers");
        let mode = std::fs::metadata(ReportFilers::path_in(&dir))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "no group or world access: mode {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_malformed_filer_file_loads_empty_rather_than_half_open() {
        let dir = scratch("malformed");
        std::fs::write(ReportFilers::path_in(&dir), "not json").unwrap();
        assert!(ReportFilers::load(&dir).find_by_id("acct-anything").is_none());
        // A duplicate email is corruption, not a legal state: it must load empty.
        std::fs::write(
            ReportFilers::path_in(&dir),
            r#"{"accounts":[
                {"id":"acct-1","email":"a@example.com","emailVerified":false,"password":null,"oauthLinks":[],"createdUnix":1,"plan":"free"},
                {"id":"acct-2","email":"a@example.com","emailVerified":false,"password":null,"oauthLinks":[],"createdUnix":1,"plan":"free"}
            ]}"#,
        )
        .unwrap();
        assert!(ReportFilers::load(&dir).find_by_id("acct-1").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_hash_matches_the_admin_crates_stored_format() {
        let hashed = hash_password("pw").unwrap();
        let parts: Vec<&str> = hashed.split('$').collect();
        assert_eq!(parts.len(), 4, "{hashed}");
        assert_eq!(parts[0], "pbkdf2-sha256");
        assert_eq!(parts[1], selfhost_login::password::ITERATIONS.to_string());
        assert_eq!(
            selfhost_login::password::b64_decode(parts[3])
                .unwrap()
                .len(),
            selfhost_login::password::KEY_LEN
        );
    }

    #[test]
    fn an_unrecognised_hash_format_fails_closed() {
        assert!(!selfhost_login::password::verify(
            "plaintextpassword",
            "plaintextpassword"
        ));
        assert!(!selfhost_login::password::verify(
            "md5$deadbeef",
            "anything"
        ));
    }
}
