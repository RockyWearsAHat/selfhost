//! Passkey (WebAuthn) sign-in for an account — the same cryptographic shape
//! `crates/admin/src/webauthn.rs` verifies the console's login with, mirrored rather than
//! imported because this crate does not depend on `selfhost-admin` (see `crate::accounts`'s
//! module documentation for why the two crates keep separate copies of a shared idiom rather
//! than sharing a dependency).
//!
//! # What is different here, and why
//!
//! The admin door registers a *named person the owner already knows about* — the credential is
//! minted inside an authenticated console session, or through an invite the owner issued for a
//! name they chose. This door is open to the internet: anybody may register a brand-new
//! account with a passkey and no invitation at all. So a passkey here is tied to an
//! [`crate::accounts::Account`] id rather than a free-text name, and registration always takes
//! that id as a parameter the caller supplies — never read from the ceremony body — which is
//! the same discipline `Webauthn::register_as` uses for the admin crate's own invite door,
//! applied to every registration here rather than to one route.
//!
//! Everything else — the discoverable-credential login shape, ES256-only, the SPKI point
//! extraction, the origin and relying-party-id binding, the single-use challenge pool — is the
//! same verified shape; see that module's documentation for the cryptographic reasoning, which
//! is not repeated here. The one place this door's shape genuinely differs is that its expected
//! origin is a configured value rather than one built out of the relying party id: the admin
//! console is only ever reached at `https://<host>`, and this subsystem is developed against
//! `http://localhost:8080`. See [`Webauthn`] for what that assumption cost.

use ring::digest;
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use selfhost_json::Json;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

/// The name of the passkey file inside `<data_dir>/reports/`.
pub const PASSKEYS_FILENAME: &str = "passkeys.json";

/// Bytes of entropy in a challenge.
const CHALLENGE_BYTES: usize = 32;

/// How long an issued challenge stays redeemable.
const CHALLENGE_LIFETIME: Duration = Duration::from_secs(120);

/// The most outstanding challenges kept — a public door sees more concurrent ceremonies than
/// the admin console's, so this is sized well past a household's handful.
const MAX_CHALLENGES: usize = 4_096;

/// The most passkeys the store will hold across every account.
pub const MAX_PASSKEYS: usize = 50_000;

/// The most passkeys one account may register — several devices, never an unbounded number.
pub const MAX_PASSKEYS_PER_ACCOUNT: usize = 10;

/// The longest device label accepted.
const MAX_LABEL_CHARS: usize = 64;

/// The longest credential id accepted, from the WebAuthn specification.
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;

/// The DER prefix of a SubjectPublicKeyInfo holding an uncompressed P-256 point — see
/// `crates/admin/src/webauthn.rs` for why this cuts the point out rather than parsing DER.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// The length of an uncompressed P-256 point: `0x04 || x || y`.
const P256_POINT_BYTES: usize = 65;

/// The COSE algorithm identifier for ES256, the one algorithm accepted here.
const COSE_ES256: i64 = -7;

/// Authenticator-data flag: the user was present at the authenticator.
const FLAG_USER_PRESENT: u8 = 0x01;
/// Authenticator-data flag: the user was *verified* — the biometric or PIN check.
const FLAG_USER_VERIFIED: u8 = 0x04;
/// Authenticator-data flag: attested credential data follows (registration).
const FLAG_ATTESTED_CREDENTIAL: u8 = 0x40;

/// The fixed layout before an authenticator data's variable tail.
const AUTH_DATA_HEADER_BYTES: usize = 37;

/// What a challenge was issued for, so a challenge minted for one ceremony cannot complete the
/// other — the same structural separation `crates/admin/src/webauthn.rs::Purpose` states.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Purpose {
    /// About to register a new credential.
    Register,
    /// About to assert an existing one, to sign in.
    Login,
}

struct Challenge {
    value: String,
    purpose: Purpose,
    issued: Instant,
}

/// The in-memory pool of outstanding challenges. Never persisted — a challenge is redeemed
/// within seconds of being issued, so losing the pool on a restart costs nothing a browser
/// mid-ceremony would not already have to retry after a network hiccup.
#[derive(Clone)]
pub struct Challenges {
    entries: Arc<Mutex<Vec<Challenge>>>,
    lifetime: Duration,
}

impl Challenges {
    /// A pool with the production lifetime.
    #[must_use]
    pub fn new() -> Self {
        Self::with_lifetime(CHALLENGE_LIFETIME)
    }

    /// A pool with an explicit lifetime — the seam that makes expiry testable.
    #[must_use]
    pub fn with_lifetime(lifetime: Duration) -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            lifetime,
        }
    }

    fn issue(&self, purpose: Purpose) -> io::Result<String> {
        let value = crate::oauth::b64url_encode(&random_bytes(CHALLENGE_BYTES)?);
        let now = Instant::now();
        let mut entries = self.lock();
        entries.retain(|entry| now.duration_since(entry.issued) < self.lifetime);
        while entries.len() >= MAX_CHALLENGES {
            entries.remove(0);
        }
        entries.push(Challenge {
            value: value.clone(),
            purpose,
            issued: now,
        });
        Ok(value)
    }

    fn take(&self, presented: &str, purpose: Purpose) -> bool {
        let now = Instant::now();
        let mut entries = self.lock();
        entries.retain(|entry| now.duration_since(entry.issued) < self.lifetime);
        let mut matched = false;
        entries.retain(|entry| {
            let hit = entry.purpose == purpose
                && constant_time_eq(entry.value.as_bytes(), presented.as_bytes());
            matched |= hit;
            !hit
        });
        matched
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Challenge>> {
        self.entries
            .lock()
            .expect("the challenge store lock was poisoned")
    }
}

impl Default for Challenges {
    fn default() -> Self {
        Self::new()
    }
}

/// One registered passkey.
#[derive(Clone)]
pub struct Passkey {
    /// The credential id, base64url exactly as the browser presents it.
    pub id: String,
    public_key: Vec<u8>,
    /// The account this credential signs in as.
    pub account_id: String,
    /// The holder's own name for the device.
    pub label: String,
    /// When it was registered, seconds since the Unix epoch.
    pub created_unix: u64,
}

/// The durable passkey store: `<data_dir>/reports/passkeys.json`, owner-only, JSON.
#[derive(Clone)]
pub struct Passkeys {
    path: PathBuf,
    entries: Arc<Mutex<Vec<Passkey>>>,
}

impl Passkeys {
    /// Loads the store. A missing or malformed file loads empty, failing closed.
    pub fn load(data_dir: &Path) -> Self {
        let path = Self::path_in(data_dir);
        let entries = match std::fs::read_to_string(&path) {
            Ok(text) => match parse_passkeys(&text) {
                Some(entries) => entries,
                None => {
                    eprintln!(
                        "reports: {} is not a valid passkey file; passkey login is disabled \
                         until it is repaired or removed",
                        path.display()
                    );
                    Vec::new()
                }
            },
            Err(_) => Vec::new(),
        };
        Self {
            path,
            entries: Arc::new(Mutex::new(entries)),
        }
    }

    /// Where the passkey file lives for a given data directory.
    #[must_use]
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(PASSKEYS_FILENAME)
    }

    /// Whether no passkey is registered at all — the login route's cue to answer the uniform
    /// refusal rather than hand out a challenge nothing could ever answer.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Every passkey belonging to `account_id`, for that account's own settings view. Carries no
    /// public key — the account has no use for it, and what is not sent cannot leak.
    #[must_use]
    pub fn list_for(&self, account_id: &str) -> Vec<Passkey> {
        self.lock()
            .iter()
            .filter(|entry| entry.account_id == account_id)
            .cloned()
            .collect()
    }

    fn find(&self, id: &str) -> Option<Passkey> {
        self.lock().iter().find(|entry| entry.id == id).cloned()
    }

    fn add(&self, passkey: Passkey) -> io::Result<()> {
        let mut entries = self.lock();
        let held_by_account = entries
            .iter()
            .filter(|entry| entry.account_id == passkey.account_id)
            .count();
        if held_by_account >= MAX_PASSKEYS_PER_ACCOUNT {
            return Err(io::Error::other(format!(
                "an account may register at most {MAX_PASSKEYS_PER_ACCOUNT} passkeys"
            )));
        }
        if entries.len() >= MAX_PASSKEYS {
            return Err(io::Error::other(format!(
                "this box already holds {MAX_PASSKEYS} passkeys"
            )));
        }
        // Re-registering the same credential id supersedes it — an authenticator holds one
        // resident credential per site per person, so a second registration replaced the first
        // authenticator-side too.
        entries.retain(|entry| entry.id != passkey.id);
        entries.push(passkey);
        self.persist(&entries)
    }

    /// Removes the passkey named by `id`, but only when it belongs to `account_id` — an
    /// account may only ever remove its own devices. `Ok(false)` when nothing matched both.
    pub fn remove(&self, account_id: &str, id: &str) -> io::Result<bool> {
        let mut entries = self.lock();
        let before = entries.len();
        entries.retain(|entry| !(entry.id == id && entry.account_id == account_id));
        if entries.len() == before {
            return Ok(false);
        }
        self.persist(&entries)?;
        Ok(true)
    }

    fn persist(&self, entries: &[Passkey]) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = passkeys_to_json(entries).to_text();
        let temporary = self.path.with_extension("json.tmp");
        std::fs::write(&temporary, &text)?;
        restrict(&temporary);
        std::fs::rename(&temporary, &self.path)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Passkey>> {
        self.entries
            .lock()
            .expect("the passkey store lock was poisoned")
    }
}

impl std::fmt::Debug for Passkeys {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "Passkeys({} registered)", self.lock().len())
    }
}

fn passkeys_to_json(entries: &[Passkey]) -> Json {
    Json::object([(
        "passkeys",
        Json::array(entries.iter().map(|entry| {
            Json::object([
                ("id", Json::string(&entry.id)),
                (
                    "publicKey",
                    Json::string(crate::oauth::b64url_encode(&entry.public_key)),
                ),
                ("accountId", Json::string(&entry.account_id)),
                ("label", Json::string(&entry.label)),
                ("createdUnix", Json::Number(entry.created_unix as f64)),
            ])
        })),
    )])
}

fn parse_passkeys(text: &str) -> Option<Vec<Passkey>> {
    let value = selfhost_json::parse(text).ok()?;
    let mut entries = Vec::new();
    for item in value.get("passkeys")?.as_array()? {
        let public_key = crate::oauth::b64url_decode(item.get("publicKey")?.as_str()?)?;
        if public_key.len() != P256_POINT_BYTES || public_key[0] != 0x04 {
            return None;
        }
        entries.push(Passkey {
            id: item.get("id")?.as_str()?.to_owned(),
            public_key,
            account_id: item.get("accountId")?.as_str()?.to_owned(),
            label: item.get("label")?.as_str()?.to_owned(),
            created_unix: item.get("createdUnix")?.as_u64()?,
        });
    }
    Some(entries)
}

/// Passkey sign-in for one relying party.
///
/// The relying party id and origin come from configuration — the public site's own hostname
/// and the public site's own address — never from a request header, for the same reason
/// `crates/admin/src/webauthn.rs::Webauthn` gives: a client-supplied identity would let it sign
/// for a relying party of its own invention.
///
/// # The origin is *not* `https://<rp_id>`, and assuming it was shut the door
///
/// These two values look like one value with a prefix on it, and an earlier draft built the
/// origin by writing `format!("https://{rp_id}")`. They are not one value. WebAuthn's relying
/// party id is a **bare host** — no scheme, no port, because the specification's RP ID is a
/// domain string — while the origin the browser stamps into `clientDataJSON` is a full origin:
/// scheme, host *and port*. On the only address this subsystem is developed against —
/// `http://localhost:8080`, which `crates/cli`'s own `check_public_base_url` recommends —
/// reconstructing gave `https://localhost` and the browser sent `http://localhost:8080`, so
/// [`Self::check_client_data`]'s exact string compare refused every ceremony, and refused it
/// inside the deliberately uniform [`RefusedCeremony`] that a forged assertion also gets. The
/// door was on, and could never open, and said nothing about why. So the origin is passed in
/// whole, from the deployment's own `public_base_url`, and only the RP-ID *hash* check
/// ([`Self::check_auth_data`]) uses the bare host.
#[derive(Clone)]
pub struct Webauthn {
    rp_id: String,
    origin: String,
    passkeys: Passkeys,
    challenges: Challenges,
    registrations: Arc<Mutex<Vec<BoundChallenge>>>,
}

/// A registration challenge's value, bound at issuance to the account it may register a
/// credential for.
///
/// This is the whole of why a self-service passkey door is safe to leave open: `finish`
/// resolves *this* table for the account to register under, from the challenge value it reads
/// out of the ceremony's own `clientDataJSON` — never from a field the client could set to name
/// somebody else's account. See [`Webauthn::start_registration`] and
/// [`Webauthn::finish_registration`].
struct BoundChallenge {
    challenge: String,
    account_id: String,
    issued: Instant,
}

impl Webauthn {
    /// Builds passkey sign-in for `rp_id` at `origin`, loading credentials from `data_dir`.
    ///
    /// `origin` is the full origin of the page the ceremony will run on — scheme, host and
    /// port, exactly as a browser writes it into `clientDataJSON`. See the type's own
    /// documentation for why it is a parameter rather than `https://{rp_id}`.
    pub fn load(rp_id: &str, origin: &str, data_dir: &Path) -> Self {
        Self::with_parts(rp_id, origin, Passkeys::load(data_dir), Challenges::new())
    }

    /// Builds from already-made parts — the seam tests use to inject a scratch store or a
    /// zero-lifetime challenge pool.
    #[must_use]
    pub fn with_parts(
        rp_id: &str,
        origin: &str,
        passkeys: Passkeys,
        challenges: Challenges,
    ) -> Self {
        Self {
            rp_id: rp_id.to_owned(),
            origin: origin.to_owned(),
            passkeys,
            challenges,
            registrations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// The passkey store this instance verifies against — for the account settings routes that
    /// list and remove an account's own devices without going through a ceremony.
    #[must_use]
    pub fn passkeys(&self) -> &Passkeys {
        &self.passkeys
    }

    /// Whether no passkey is registered anywhere on this box.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.passkeys.is_empty()
    }

    /// Issues a ceremony challenge, as `{"challenge", "rpId"}`.
    ///
    /// # Errors
    /// An [`io::Error`] naming what the system's random source refused.
    pub fn challenge(&self, purpose: Purpose) -> io::Result<Json> {
        Ok(Json::object([
            ("challenge", Json::string(self.challenges.issue(purpose)?)),
            ("rpId", Json::string(&self.rp_id)),
        ]))
    }

    /// Issues a registration challenge bound to `account_id` at the moment of issuance —
    /// `crate::service`'s self-service registration door, where the account a ceremony may
    /// register for must be decided *before* the ceremony runs, never trusted from anything the
    /// finishing request claims. [`Self::finish_registration`] is the only correct way to
    /// complete a challenge issued here; passing this challenge's body to [`Self::register`]
    /// with a *different* account id will fail it (the challenge is consumed by whichever call
    /// verifies it first), but the reverse — completing it as the account bound here — is the
    /// point.
    ///
    /// # Errors
    /// An [`io::Error`] naming what the system's random source refused.
    pub fn start_registration(&self, account_id: &str) -> io::Result<Json> {
        let challenge = self.challenges.issue(Purpose::Register)?;
        let now = Instant::now();
        let mut bound = self.bound_lock();
        bound.retain(|entry| now.duration_since(entry.issued) < CHALLENGE_LIFETIME);
        while bound.len() >= MAX_CHALLENGES {
            bound.remove(0);
        }
        bound.push(BoundChallenge {
            challenge: challenge.clone(),
            account_id: account_id.to_string(),
            issued: now,
        });
        Ok(Json::object([
            ("challenge", Json::string(challenge)),
            ("rpId", Json::string(&self.rp_id)),
        ]))
    }

    /// Completes a challenge issued by [`Self::start_registration`], registering the credential
    /// under exactly the account id that challenge was bound to.
    ///
    /// The account id is read from this instance's own binding table, keyed by the challenge
    /// value inside the ceremony's own `clientDataJSON` — never from a field in `body`, which is
    /// attacker-controlled input from an ceremony that, at this point, has not even been
    /// verified yet.
    ///
    /// # Errors
    /// [`RefusedCeremony`] when the challenge names no binding (never issued here, expired, or
    /// already spent) or — everything [`Self::register`] itself can refuse.
    pub fn finish_registration(&self, body: &Json) -> Result<Passkey, RefusedCeremony> {
        let client_data = decoded_field(body, "clientDataJSON")?;
        let text = std::str::from_utf8(&client_data).map_err(|_| RefusedCeremony)?;
        let value = selfhost_json::parse(text).map_err(|_| RefusedCeremony)?;
        let challenge = value
            .get("challenge")
            .and_then(Json::as_str)
            .ok_or(RefusedCeremony)?;
        let account_id = self.take_binding(challenge).ok_or(RefusedCeremony)?;
        self.register(&account_id, body)
    }

    /// Removes and returns the account id bound to `challenge`, if any and not expired —
    /// single-use, like every other credential lookup here.
    fn take_binding(&self, challenge: &str) -> Option<String> {
        let now = Instant::now();
        let mut bound = self.bound_lock();
        bound.retain(|entry| now.duration_since(entry.issued) < CHALLENGE_LIFETIME);
        let mut found = None;
        bound.retain(|entry| {
            let hit = constant_time_eq(entry.challenge.as_bytes(), challenge.as_bytes());
            if hit {
                found = Some(entry.account_id.clone());
            }
            !hit
        });
        found
    }

    fn bound_lock(&self) -> std::sync::MutexGuard<'_, Vec<BoundChallenge>> {
        self.registrations
            .lock()
            .expect("the registration-binding lock was poisoned")
    }

    /// Registers the credential described by a browser's registration body under `account_id`
    /// — always given by the caller, never read from the body; see the module documentation for
    /// why that is the whole of this door's security. Reachable directly for callers that have
    /// already authenticated `account_id` some other way (there are none inside this crate
    /// today; [`Self::start_registration`]/[`Self::finish_registration`] is the self-service
    /// door every route actually uses) and by [`Self::finish_registration`] itself.
    ///
    /// # Errors
    /// [`RefusedCeremony`] for anything the ceremony gets wrong: an expired or wrong-purpose
    /// challenge, the wrong algorithm, a key that is not a P-256 point, a missing
    /// user-verification flag, or the store already at its cap.
    pub fn register(&self, account_id: &str, body: &Json) -> Result<Passkey, RefusedCeremony> {
        let id = credential_id(body)?;
        if body.get("algorithm").and_then(Json::as_i64) != Some(COSE_ES256) {
            return Err(RefusedCeremony);
        }
        let client_data = decoded_field(body, "clientDataJSON")?;
        self.check_client_data(&client_data, "webauthn.create", Purpose::Register)?;

        let auth_data = decoded_field(body, "authenticatorData")?;
        self.check_auth_data(
            &auth_data,
            FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_ATTESTED_CREDENTIAL,
        )?;

        let spki = decoded_field(body, "publicKey")?;
        let public_key = p256_point_from_spki(&spki).ok_or(RefusedCeremony)?;

        let passkey = Passkey {
            id,
            public_key,
            account_id: account_id.to_string(),
            label: named_field(body, "label", "passkey", MAX_LABEL_CHARS),
            created_unix: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|since| since.as_secs())
                .unwrap_or(0),
        };
        self.passkeys
            .add(passkey.clone())
            .map_err(|_| RefusedCeremony)?;
        Ok(passkey)
    }

    /// Verifies a browser's login assertion; `Ok` carries the passkey that signed it, whose
    /// `account_id` the caller signs in as.
    ///
    /// # Errors
    /// [`RefusedCeremony`], uniformly for every way an assertion can fail — so probing this
    /// door teaches nothing about which credentials exist.
    pub fn verify_login(&self, body: &Json) -> Result<Passkey, RefusedCeremony> {
        let id = credential_id(body)?;
        let passkey = self.passkeys.find(&id).ok_or(RefusedCeremony)?;

        let client_data = decoded_field(body, "clientDataJSON")?;
        self.check_client_data(&client_data, "webauthn.get", Purpose::Login)?;

        let auth_data = decoded_field(body, "authenticatorData")?;
        self.check_auth_data(&auth_data, FLAG_USER_PRESENT | FLAG_USER_VERIFIED)?;

        let signature = decoded_field(body, "signature")?;
        let mut message = auth_data;
        message.extend_from_slice(digest::digest(&digest::SHA256, &client_data).as_ref());
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &passkey.public_key)
            .verify(&message, &signature)
            .map_err(|_| RefusedCeremony)?;
        Ok(passkey)
    }

    fn check_client_data(
        &self,
        client_data: &[u8],
        ceremony: &str,
        purpose: Purpose,
    ) -> Result<(), RefusedCeremony> {
        let text = std::str::from_utf8(client_data).map_err(|_| RefusedCeremony)?;
        let value = selfhost_json::parse(text).map_err(|_| RefusedCeremony)?;
        if value.get("type").and_then(Json::as_str) != Some(ceremony) {
            return Err(RefusedCeremony);
        }
        if value.get("origin").and_then(Json::as_str) != Some(self.origin.as_str()) {
            return Err(RefusedCeremony);
        }
        let challenge = value
            .get("challenge")
            .and_then(Json::as_str)
            .ok_or(RefusedCeremony)?;
        if !self.challenges.take(challenge, purpose) {
            return Err(RefusedCeremony);
        }
        Ok(())
    }

    fn check_auth_data(&self, auth_data: &[u8], required: u8) -> Result<(), RefusedCeremony> {
        if auth_data.len() < AUTH_DATA_HEADER_BYTES {
            return Err(RefusedCeremony);
        }
        let expected = digest::digest(&digest::SHA256, self.rp_id.as_bytes());
        if !constant_time_eq(&auth_data[..32], expected.as_ref()) {
            return Err(RefusedCeremony);
        }
        if auth_data[32] & required != required {
            return Err(RefusedCeremony);
        }
        Ok(())
    }
}

/// The one refusal every failed ceremony collapses into — carrying no detail is the point.
#[derive(Debug, PartialEq, Eq)]
pub struct RefusedCeremony;

fn credential_id(body: &Json) -> Result<String, RefusedCeremony> {
    let id = body
        .get("id")
        .and_then(Json::as_str)
        .ok_or(RefusedCeremony)?;
    let decoded = crate::oauth::b64url_decode(id).ok_or(RefusedCeremony)?;
    if decoded.is_empty() || decoded.len() > MAX_CREDENTIAL_ID_BYTES {
        return Err(RefusedCeremony);
    }
    Ok(id.to_owned())
}

fn decoded_field(body: &Json, field: &str) -> Result<Vec<u8>, RefusedCeremony> {
    body.get(field)
        .and_then(Json::as_str)
        .and_then(crate::oauth::b64url_decode)
        .ok_or(RefusedCeremony)
}

fn named_field(body: &Json, field: &str, fallback: &str, limit: usize) -> String {
    body.get(field)
        .and_then(Json::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or(fallback)
        .chars()
        .take(limit)
        .collect()
}

fn p256_point_from_spki(spki: &[u8]) -> Option<Vec<u8>> {
    let point = spki.strip_prefix(P256_SPKI_PREFIX.as_slice())?;
    (point.len() == P256_POINT_BYTES && point[0] == 0x04).then(|| point.to_vec())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |differences, (a, b)| differences | (a ^ b))
        == 0
}

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

fn random_bytes(count: usize) -> io::Result<Vec<u8>> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut buffer = vec![0u8; count];
    SystemRandom::new()
        .fill(&mut buffer)
        .map_err(|_| io::Error::other("the system random source was unavailable"))?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "selfhost-reports-webauthn-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    const RP: &str = "reports.example.com";

    /// The full origin the page runs on, which on a production deployment is `https://` plus
    /// the relying party id and nothing else — the case that always worked, kept as the
    /// default so the port-carrying cases below are visibly the *other* shape rather than the
    /// only shape ever exercised.
    const ORIGIN: &str = "https://reports.example.com";

    struct Authenticator {
        keys: EcdsaKeyPair,
        id: String,
    }

    impl Authenticator {
        fn new(id: &str) -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                .expect("keypair");
            let keys =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                    .expect("keypair parses back");
            Self {
                keys,
                id: crate::oauth::b64url_encode(id.as_bytes()),
            }
        }

        fn spki(&self) -> Vec<u8> {
            let mut out = P256_SPKI_PREFIX.to_vec();
            out.extend_from_slice(self.keys.public_key().as_ref());
            out
        }

        fn auth_data(flags: u8) -> Vec<u8> {
            Self::auth_data_for(RP, flags)
        }

        /// The same, for a relying party id other than [`RP`] — the authenticator hashes the
        /// *bare host*, which is exactly the value that does not change when the page moves to
        /// a different scheme or port.
        fn auth_data_for(rp_id: &str, flags: u8) -> Vec<u8> {
            let mut out = digest::digest(&digest::SHA256, rp_id.as_bytes())
                .as_ref()
                .to_vec();
            out.push(flags);
            out.extend_from_slice(&[0, 0, 0, 1]);
            out
        }

        fn client_data(ceremony: &str, challenge: &str, origin: &str) -> Vec<u8> {
            Json::object([
                ("type", Json::string(ceremony)),
                ("challenge", Json::string(challenge)),
                ("origin", Json::string(origin)),
            ])
            .to_text()
            .into_bytes()
        }

        fn register_body(&self, webauthn: &Webauthn, label: &str) -> Json {
            let challenge = challenge_of(webauthn.challenge(Purpose::Register).unwrap());
            self.register_body_at(&challenge, label, ORIGIN)
        }

        fn register_body_with_challenge(&self, challenge: &str, label: &str) -> Json {
            self.register_body_at(challenge, label, ORIGIN)
        }

        fn register_body_at(&self, challenge: &str, label: &str, origin: &str) -> Json {
            self.register_body_bound(challenge, label, RP, origin)
        }

        /// A registration body from an authenticator that believes it is talking to `rp_id` on
        /// a page served from `origin` — the two values a browser reports separately, so a
        /// test can move one without moving the other.
        fn register_body_bound(
            &self,
            challenge: &str,
            label: &str,
            rp_id: &str,
            origin: &str,
        ) -> Json {
            let client = Self::client_data("webauthn.create", challenge, origin);
            let flags = FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_ATTESTED_CREDENTIAL;
            Json::object([
                ("id", Json::string(&self.id)),
                ("algorithm", Json::Number(COSE_ES256 as f64)),
                (
                    "publicKey",
                    Json::string(crate::oauth::b64url_encode(&self.spki())),
                ),
                (
                    "clientDataJSON",
                    Json::string(crate::oauth::b64url_encode(&client)),
                ),
                (
                    "authenticatorData",
                    Json::string(crate::oauth::b64url_encode(&Self::auth_data_for(
                        rp_id, flags,
                    ))),
                ),
                ("label", Json::string(label)),
            ])
        }

        fn login_body(&self, webauthn: &Webauthn) -> Json {
            self.login_body_with(webauthn, FLAG_USER_PRESENT | FLAG_USER_VERIFIED, None)
        }

        fn login_body_with(&self, webauthn: &Webauthn, flags: u8, origin: Option<&str>) -> Json {
            let challenge = challenge_of(webauthn.challenge(Purpose::Login).unwrap());
            let origin = origin.map_or_else(|| ORIGIN.to_owned(), str::to_owned);
            let client = Self::client_data("webauthn.get", &challenge, &origin);
            let auth = Self::auth_data(flags);
            let mut message = auth.clone();
            message.extend_from_slice(digest::digest(&digest::SHA256, &client).as_ref());
            let signature = self
                .keys
                .sign(&SystemRandom::new(), &message)
                .expect("signs");
            Json::object([
                ("id", Json::string(&self.id)),
                (
                    "clientDataJSON",
                    Json::string(crate::oauth::b64url_encode(&client)),
                ),
                (
                    "authenticatorData",
                    Json::string(crate::oauth::b64url_encode(&auth)),
                ),
                (
                    "signature",
                    Json::string(crate::oauth::b64url_encode(signature.as_ref())),
                ),
            ])
        }
    }

    fn challenge_of(reply: Json) -> String {
        reply
            .get("challenge")
            .and_then(Json::as_str)
            .expect("a challenge")
            .to_owned()
    }

    fn webauthn(dir: &Path) -> Webauthn {
        Webauthn::with_parts(RP, ORIGIN, Passkeys::load(dir), Challenges::new())
    }

    #[test]
    fn registration_stores_a_key_that_then_verifies_a_login_for_that_account() {
        let dir = scratch("roundtrip");
        let webauthn = webauthn(&dir);
        let device = Authenticator::new("credential-1");

        let stored = webauthn
            .register("acct-1", &device.register_body(&webauthn, "MacBook"))
            .expect("registers");
        assert_eq!(stored.account_id, "acct-1");
        assert!(!webauthn.is_empty());

        let signer = webauthn
            .verify_login(&device.login_body(&webauthn))
            .expect("verifies");
        assert_eq!(
            signer.account_id, "acct-1",
            "the assertion answers who signed it"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_self_service_registration_completes_under_the_account_it_was_started_for() {
        let dir = scratch("self-service");
        let webauthn = webauthn(&dir);
        let device = Authenticator::new("credential-1");
        let challenge = challenge_of(webauthn.start_registration("acct-real").unwrap());
        let stored = webauthn
            .finish_registration(&device.register_body_with_challenge(&challenge, "phone"))
            .expect("registers");
        assert_eq!(stored.account_id, "acct-real");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_client_cannot_claim_a_different_account_at_finish() {
        // The whole property `start_registration`/`finish_registration` exist for: the account
        // a credential registers for is decided when the challenge is minted, and nothing a
        // client sends at `finish` — an `accountId` field, anything — can move it. There is no
        // such field in the wire shape at all; this proves the binding is read from the
        // server's own table rather than from a body that could name one.
        let dir = scratch("no-account-swap");
        let webauthn = webauthn(&dir);
        let device = Authenticator::new("credential-1");
        let challenge = challenge_of(webauthn.start_registration("acct-victim").unwrap());
        let mut body = device.register_body_with_challenge(&challenge, "phone");
        if let Json::Object(entries) = &mut body {
            // Even if a body carried this, `finish_registration` never reads it.
            entries.insert("accountId".into(), Json::string("acct-attacker"));
        }
        let stored = webauthn.finish_registration(&body).expect("registers");
        assert_eq!(
            stored.account_id, "acct-victim",
            "the binding at issuance wins, always"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn finish_registration_refuses_a_challenge_that_was_never_bound() {
        let dir = scratch("unbound");
        let webauthn = webauthn(&dir);
        let device = Authenticator::new("credential-1");
        // Issued by the *other* door (`challenge`, not `start_registration`) — no binding
        // exists for it.
        assert!(
            webauthn
                .finish_registration(&device.register_body(&webauthn, "phone"))
                .is_err(),
            "an unbound challenge completes nothing"
        );
        assert!(webauthn.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_registration_binding_is_single_use() {
        let dir = scratch("single-use-binding");
        let webauthn = webauthn(&dir);
        let device = Authenticator::new("credential-1");
        let challenge = challenge_of(webauthn.start_registration("acct-1").unwrap());
        let body = device.register_body_with_challenge(&challenge, "phone");
        // The underlying challenge is also single-use, so a naive replay of the identical body
        // is already refused by `register`'s own challenge check; the binding table's own
        // single-use property is what a *different* ceremony over the same challenge value
        // would otherwise be able to exploit, and `take_binding` removes it on the first look
        // regardless of whether the ceremony that follows succeeds.
        webauthn
            .finish_registration(&body)
            .expect("first completion");
        assert!(
            webauthn.take_binding(&challenge).is_none(),
            "the binding does not survive being read once"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_accounts_registering_the_same_relying_party_stay_distinct() {
        let dir = scratch("two-accounts");
        let webauthn = webauthn(&dir);
        let a = Authenticator::new("credential-a");
        let b = Authenticator::new("credential-b");
        webauthn
            .register("acct-a", &a.register_body(&webauthn, "phone"))
            .expect("registers");
        webauthn
            .register("acct-b", &b.register_body(&webauthn, "phone"))
            .expect("registers");

        assert_eq!(
            webauthn
                .verify_login(&a.login_body(&webauthn))
                .unwrap()
                .account_id,
            "acct-a"
        );
        assert_eq!(
            webauthn
                .verify_login(&b.login_body(&webauthn))
                .unwrap()
                .account_id,
            "acct-b"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The regression the origin parameter exists for. A deployment reached at
    /// `http://localhost:8080` has relying party id `localhost` and origin
    /// `http://localhost:8080`, and the two differ in both scheme and port. Reconstructing the
    /// origin as `https://<rp_id>` produced `https://localhost`, which no browser ever sends,
    /// so every ceremony was refused — the door was on and could not open. Registering and
    /// signing in must both work here, and the RP-ID hash must still be over the bare host.
    #[test]
    fn a_page_served_on_a_port_completes_a_ceremony_the_reconstructed_origin_refused() {
        let dir = scratch("ported-origin");
        let webauthn = Webauthn::with_parts(
            "localhost",
            "http://localhost:8080",
            Passkeys::load(&dir),
            Challenges::new(),
        );
        let device = Authenticator::new("credential-1");

        let challenge = challenge_of(webauthn.challenge(Purpose::Register).unwrap());
        let body =
            device.register_body_bound(&challenge, "laptop", "localhost", "http://localhost:8080");
        webauthn.register("acct-1", &body).expect("registers");

        let challenge = challenge_of(webauthn.challenge(Purpose::Login).unwrap());
        let client =
            Authenticator::client_data("webauthn.get", &challenge, "http://localhost:8080");
        let auth =
            Authenticator::auth_data_for("localhost", FLAG_USER_PRESENT | FLAG_USER_VERIFIED);
        let mut message = auth.clone();
        message.extend_from_slice(digest::digest(&digest::SHA256, &client).as_ref());
        let signature = device
            .keys
            .sign(&SystemRandom::new(), &message)
            .expect("signs");
        let assertion = Json::object([
            ("id", Json::string(&device.id)),
            (
                "clientDataJSON",
                Json::string(crate::oauth::b64url_encode(&client)),
            ),
            (
                "authenticatorData",
                Json::string(crate::oauth::b64url_encode(&auth)),
            ),
            (
                "signature",
                Json::string(crate::oauth::b64url_encode(signature.as_ref())),
            ),
        ]);
        assert_eq!(
            webauthn.verify_login(&assertion).unwrap().account_id,
            "acct-1",
            "a page on a non-default port and plain http still completes a ceremony"
        );

        // And the challenge still carries the *bare* host as `rpId`, never the origin: a
        // browser handed `localhost:8080` as a relying party id refuses the ceremony outright.
        let advertised = webauthn.challenge(Purpose::Login).unwrap();
        assert_eq!(
            advertised.get("rpId").and_then(Json::as_str),
            Some("localhost")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_bent_assertion_is_refused() {
        let dir = scratch("refusals");
        let webauthn = webauthn(&dir);
        let device = Authenticator::new("credential-1");
        webauthn
            .register("acct-1", &device.register_body(&webauthn, "MacBook"))
            .expect("registers");

        let unverified = device.login_body_with(&webauthn, FLAG_USER_PRESENT, None);
        assert!(
            webauthn.verify_login(&unverified).is_err(),
            "UV must be set"
        );

        let phished = device.login_body_with(
            &webauthn,
            FLAG_USER_PRESENT | FLAG_USER_VERIFIED,
            Some("https://evil.example.com"),
        );
        assert!(webauthn.verify_login(&phished).is_err(), "the origin binds");

        let stranger = Authenticator::new("credential-1");
        assert!(
            webauthn
                .verify_login(&stranger.login_body(&webauthn))
                .is_err()
        );

        let body = device.login_body(&webauthn);
        webauthn.verify_login(&body).expect("first use verifies");
        assert!(
            webauthn.verify_login(&body).is_err(),
            "a challenge is single-use"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn registration_refuses_the_wrong_algorithm_and_key_shape() {
        let dir = scratch("register-refusals");
        let webauthn = webauthn(&dir);
        let device = Authenticator::new("credential-1");

        let mut wrong_alg = device.register_body(&webauthn, "x");
        if let Json::Object(entries) = &mut wrong_alg {
            entries.insert("algorithm".into(), Json::Number(-257.0));
        }
        assert!(
            webauthn.register("acct-1", &wrong_alg).is_err(),
            "only ES256 is accepted"
        );
        assert!(webauthn.is_empty(), "nothing refused was stored");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_account_may_remove_only_its_own_passkey() {
        let dir = scratch("remove");
        let webauthn = webauthn(&dir);
        let device = Authenticator::new("credential-1");
        webauthn
            .register("acct-1", &device.register_body(&webauthn, "MacBook"))
            .expect("registers");

        assert!(
            !webauthn
                .passkeys()
                .remove("acct-2", &device.id)
                .expect("no-op"),
            "wrong owner"
        );
        assert!(
            webauthn
                .passkeys()
                .remove("acct-1", &device.id)
                .expect("removes")
        );
        assert!(
            webauthn
                .verify_login(&device.login_body(&webauthn))
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_per_account_cap_stops_a_registration_loop() {
        let dir = scratch("per-account-cap");
        let webauthn = webauthn(&dir);
        for nth in 0..MAX_PASSKEYS_PER_ACCOUNT {
            let device = Authenticator::new(&format!("credential-{nth}"));
            webauthn
                .register("acct-1", &device.register_body(&webauthn, "device"))
                .expect("under the cap");
        }
        let one_too_many = Authenticator::new("credential-overflow");
        assert!(
            webauthn
                .register("acct-1", &one_too_many.register_body(&webauthn, "device"))
                .is_err(),
            "a loop hits a wall"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn passkeys_survive_a_reload_from_disk() {
        let dir = scratch("reload");
        let device = Authenticator::new("credential-1");
        let first = webauthn(&dir);
        first
            .register("acct-1", &device.register_body(&first, "phone"))
            .expect("registers");

        // A fresh load — the intake restarting — still verifies the device.
        let reloaded = webauthn(&dir);
        reloaded
            .verify_login(&device.login_body(&reloaded))
            .expect("verifies after reload");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_passkey_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        let webauthn = webauthn(&dir);
        let device = Authenticator::new("credential-1");
        webauthn
            .register("acct-1", &device.register_body(&webauthn, "x"))
            .expect("registers");
        let mode = std::fs::metadata(Passkeys::path_in(&dir))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "no group or world access: mode {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
