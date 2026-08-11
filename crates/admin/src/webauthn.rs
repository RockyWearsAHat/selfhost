//! Passkey (WebAuthn) login for the console: biometric identity as a second
//! way through the same session door.
//!
//! The browser holds the private key inside the platform authenticator (Touch
//! ID, Face ID, Windows Hello); this module stores only the credential's
//! public half and verifies signatures with it. Registration happens *inside*
//! an authenticated session, so the console password remains the root
//! credential — a passkey can never grant more than the password that
//! registered it, and deleting `console.passkeys` revokes them all.
//!
//! Passkeys are *named*: each belongs to a person, several people can share
//! one device (each name is its own resident credential, distinguished by the
//! browser's account picker at login), and a verified assertion answers who
//! signed it, so the session it mints knows its holder. The biometric proves
//! a person the device trusts is present; *which* person is proved by the
//! credential's signature, which is what makes the identity cryptographic
//! rather than declared.
//!
//! Only ES256 (ECDSA P-256 over SHA-256) is accepted. Every platform
//! authenticator offers it, and holding to one algorithm keeps verification a
//! single code path through `ring` — the same provider the rest of the
//! workspace links — rather than a menu of them.
//!
//! The verification here is deliberately the discoverable-credential subset of
//! WebAuthn: the login challenge names no credential ids, so an unauthenticated
//! caller learns nothing about what is registered, and the browser's own
//! account picker chooses the key. Attestation is not parsed — the registering
//! caller has already proven itself with the password, so the authenticator's
//! certificate chain would add ceremony without adding trust.

use crate::token::{constant_time_eq, random_bytes, write_private};
use ring::digest;
use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use selfhost_json::Json;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

/// The name of the passkey file inside the data directory.
pub const PASSKEYS_FILENAME: &str = "console.passkeys";

/// Bytes of entropy in a challenge: 256 bits, matching the session id, because
/// forging a challenge is forging a login.
const CHALLENGE_BYTES: usize = 32;

/// How long an issued challenge stays redeemable. A browser round-trips a
/// ceremony in seconds; two minutes covers a slow biometric prompt without
/// leaving a pool of stale challenges to replay against.
const CHALLENGE_LIFETIME: Duration = Duration::from_secs(120);

/// The most outstanding challenges kept. One operator never has more than a
/// couple in flight; a challenge-request loop evicts its own oldest.
const MAX_CHALLENGES: usize = 32;

/// The most passkeys the store will hold. Several people, each with a few
/// devices, never approach this; a registration loop is refused, not stored.
const MAX_PASSKEYS: usize = 32;

/// The longest person's name a passkey may carry. Bounded like every stored
/// string: it renders in the console and names sessions, but it is input.
const MAX_USER_CHARS: usize = 32;

/// The identity a passkey wears when the registering caller names nobody —
/// the same identity a password login mints its session under.
const DEFAULT_USER: &str = "owner";

/// The longest credential id accepted, from the WebAuthn specification.
const MAX_CREDENTIAL_ID_BYTES: usize = 1023;

/// The DER prefix of a SubjectPublicKeyInfo holding an uncompressed P-256
/// point: the browser's `getPublicKey()` always exports exactly this shape for
/// ES256, so the point can be cut out by length and prefix rather than by a
/// DER parser this crate would otherwise have to carry.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// The length of an uncompressed P-256 point: `0x04 || x || y`.
const P256_POINT_BYTES: usize = 65;

/// The COSE algorithm identifier for ES256, the one algorithm accepted here.
const COSE_ES256: i64 = -7;

/// Authenticator-data flag: the user was present at the authenticator.
const FLAG_USER_PRESENT: u8 = 0x01;
/// Authenticator-data flag: the user was *verified* — the biometric or PIN
/// check this whole feature exists for. An assertion without it is refused.
const FLAG_USER_VERIFIED: u8 = 0x04;
/// Authenticator-data flag: attested credential data follows (registration).
const FLAG_ATTESTED_CREDENTIAL: u8 = 0x40;

/// The fixed layout before an authenticator data's variable tail:
/// a 32-byte RP id hash, one flag byte, and a 4-byte signature counter.
const AUTH_DATA_HEADER_BYTES: usize = 37;

/// What a challenge was issued for. A registration challenge redeemed at the
/// login route (or the reverse) is a protocol confusion, never a match.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Purpose {
    /// Issued to an authenticated session about to register a passkey.
    Register,
    /// Issued to a login page about to request an assertion.
    Login,
    /// Issued to somebody redeeming an invitation, who has proved nothing yet
    /// beyond holding a code.
    ///
    /// Its own purpose rather than a second use of [`Purpose::Register`], for
    /// the reason this enum exists at all: the invite door is reachable without
    /// a session and the registration door is owner-only, so a challenge minted
    /// at one must not complete a ceremony at the other. Neither direction is a
    /// privilege gain today — the owner-only route still demands the owner, and
    /// the invite route still demands a code — but "the two doors cannot be
    /// crossed" is a property worth holding structurally rather than re-deriving
    /// from what each door happens to check.
    Invite,
}

/// One outstanding challenge.
struct Challenge {
    /// The base64url rendering the browser echoes back inside clientDataJSON.
    value: String,
    purpose: Purpose,
    issued: Instant,
}

/// The in-memory store of outstanding challenges.
///
/// A cheap-clone handle like [`crate::Sessions`], for the same reason: every
/// clone of the `Api` must issue into and redeem from the same pool. Each
/// challenge is single-use — redeeming removes it — which is what makes a
/// captured assertion worthless a second time.
#[derive(Clone)]
pub struct Challenges {
    entries: Arc<Mutex<Vec<Challenge>>>,
    lifetime: Duration,
}

impl Challenges {
    /// A pool with the production lifetime.
    pub fn new() -> Self {
        Self::with_lifetime(CHALLENGE_LIFETIME)
    }

    /// A pool with an explicit lifetime — the seam that makes expiry testable.
    pub fn with_lifetime(lifetime: Duration) -> Self {
        Self { entries: Arc::new(Mutex::new(Vec::new())), lifetime }
    }

    /// Issues a fresh challenge for `purpose`, returning its base64url form.
    ///
    /// The bytes come from the operating system's entropy; a failure there is
    /// an error, never a weaker challenge.
    pub fn issue(&self, purpose: Purpose) -> io::Result<String> {
        let value = b64url_encode(&random_bytes(CHALLENGE_BYTES)?);
        let now = Instant::now();
        let mut entries = self.lock();
        entries.retain(|entry| now.duration_since(entry.issued) < self.lifetime);
        // Issued in order, so the front is always oldest.
        while entries.len() >= MAX_CHALLENGES {
            entries.remove(0);
        }
        entries.push(Challenge { value: value.clone(), purpose, issued: now });
        Ok(value)
    }

    /// Redeems `presented` for `purpose`: true exactly once per issued value.
    ///
    /// Compared in constant time, like every credential in this crate, and the
    /// walk visits every entry rather than returning early.
    pub fn take(&self, presented: &str, purpose: Purpose) -> bool {
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

    /// The entries, with lock poisoning treated as fatal, as in
    /// [`crate::Sessions`].
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Challenge>> {
        self.entries.lock().expect("the challenge store lock was poisoned")
    }
}

impl Default for Challenges {
    fn default() -> Self {
        Self::new()
    }
}

/// One registered passkey: the public half of a credential and how to name it.
#[derive(Clone)]
pub struct Passkey {
    /// The credential id, base64url exactly as the browser presents it.
    pub id: String,
    /// The uncompressed P-256 point assertions are verified against.
    public_key: Vec<u8>,
    /// The person this passkey belongs to ("Alex", "Mom") — the identity a
    /// verified assertion mints its session under. Several people can share
    /// one device: each name is its own resident credential in the
    /// authenticator, and the browser's account picker chooses between them.
    pub user: String,
    /// The person's own name for the device ("MacBook", "phone").
    pub label: String,
    /// When the passkey was registered, as seconds since the Unix epoch —
    /// wall-clock rather than `Instant` because it survives restarts on disk.
    pub created_unix: u64,
}

/// The durable passkey store: `<data_dir>/console.passkeys`, owner-only, JSON.
///
/// A cheap-clone handle over shared state, like everything the `Api` carries.
/// A missing file is an empty store; an unreadable or malformed one loads
/// empty and says so once, mirroring [`crate::ConsolePassword::load`] — an
/// undecipherable credential file must fail closed, never half-open.
#[derive(Clone)]
pub struct Passkeys {
    path: PathBuf,
    entries: Arc<Mutex<Vec<Passkey>>>,
}

impl Passkeys {
    /// Loads the store from `<data_dir>/console.passkeys`.
    pub fn load(data_dir: &Path) -> Self {
        let path = Self::path_in(data_dir);
        let entries = match std::fs::read_to_string(&path) {
            Ok(text) => match parse_passkeys(&text) {
                Some(entries) => entries,
                None => {
                    eprintln!(
                        "admin: {} is not a valid passkey file; passkey login is \
                         disabled until it is re-registered or removed",
                        path.display()
                    );
                    Vec::new()
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => {
                eprintln!(
                    "admin: could not read {}: {error}; passkey login is disabled",
                    path.display()
                );
                Vec::new()
            }
        };
        Self { path, entries: Arc::new(Mutex::new(entries)) }
    }

    /// Where the passkey file lives for a given data directory.
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(PASSKEYS_FILENAME)
    }

    /// Whether no passkey is registered.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Every registered passkey, for the console's list.
    pub fn list(&self) -> Vec<Passkey> {
        self.lock().clone()
    }

    /// The passkey registered under a credential id, if any.
    fn find(&self, id: &str) -> Option<Passkey> {
        self.lock().iter().find(|entry| entry.id == id).cloned()
    }

    /// Adds a passkey and persists, superseding what it replaces: the same
    /// credential id, or the same person's earlier passkey on the same
    /// device — an authenticator keeps one resident credential per person
    /// and site, so re-registering destroyed that credential authenticator-side
    /// and its stored entry is dead weight.
    ///
    /// Refuses beyond [`MAX_PASSKEYS`]: a registration loop must hit a wall,
    /// not grow a credential file without bound.
    fn add(&self, passkey: Passkey) -> io::Result<()> {
        let mut entries = self.lock();
        entries.retain(|entry| {
            entry.id != passkey.id && !(entry.user == passkey.user && entry.label == passkey.label)
        });
        if entries.len() >= MAX_PASSKEYS {
            return Err(io::Error::other(format!("at most {MAX_PASSKEYS} passkeys may be registered")));
        }
        entries.push(passkey);
        self.persist(&entries)
    }

    /// Removes the passkey named by `id`, persisting; false if unknown.
    fn remove(&self, id: &str) -> io::Result<bool> {
        let mut entries = self.lock();
        let before = entries.len();
        entries.retain(|entry| entry.id != id);
        if entries.len() == before {
            return Ok(false);
        }
        self.persist(&entries)?;
        Ok(true)
    }

    /// Writes the store owner-only via a temporary file and rename, like the
    /// token and the password: a crash mid-write leaves the previous file.
    fn persist(&self, entries: &[Passkey]) -> io::Result<()> {
        let text = passkeys_to_json(entries).to_text();
        let temporary = self.path.with_extension("passkeys.new");
        write_private(&temporary, &text)?;
        std::fs::rename(&temporary, &self.path)
    }

    /// The entries, with lock poisoning treated as fatal, as in
    /// [`crate::Sessions`].
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Passkey>> {
        self.entries.lock().expect("the passkey store lock was poisoned")
    }
}

// Deliberately not a revealing `Debug`: public keys are not secrets, but a
// credential inventory in a log line is still a target list.
impl std::fmt::Debug for Passkeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Passkeys({} registered)", self.lock().len())
    }
}

/// The stored file's JSON shape:
/// `{"passkeys": [{id, publicKey, user, label, createdUnix}]}`.
fn passkeys_to_json(entries: &[Passkey]) -> Json {
    Json::object([(
        "passkeys",
        Json::array(entries.iter().map(|entry| {
            Json::object([
                ("id", Json::string(&entry.id)),
                ("publicKey", Json::string(b64url_encode(&entry.public_key))),
                ("user", Json::string(&entry.user)),
                ("label", Json::string(&entry.label)),
                ("createdUnix", Json::Number(entry.created_unix as f64)),
            ])
        })),
    )])
}

/// Parses the stored file. `None` for anything malformed — including an entry
/// whose key is not a P-256 point, which could never verify anyway. A missing
/// `user` is not malformed: files written before passkeys were named belong to
/// the sole operator they served, [`DEFAULT_USER`].
fn parse_passkeys(text: &str) -> Option<Vec<Passkey>> {
    let value = selfhost_json::parse(text).ok()?;
    let mut entries = Vec::new();
    for item in value.get("passkeys")?.as_array()? {
        let id = item.get("id")?.as_str()?.to_owned();
        let public_key = b64url_decode(item.get("publicKey")?.as_str()?)?;
        if public_key.len() != P256_POINT_BYTES || public_key[0] != 0x04 {
            return None;
        }
        entries.push(Passkey {
            id,
            public_key,
            user: item.get("user").and_then(Json::as_str).unwrap_or(DEFAULT_USER).to_owned(),
            label: item.get("label")?.as_str()?.to_owned(),
            created_unix: item.get("createdUnix")?.as_u64()?,
        });
    }
    Some(entries)
}

/// Passkey login for one relying party: the stores plus the identity checks
/// every ceremony is verified against.
///
/// The relying party id and origin come from configuration — the console
/// site's canonical hostname — never from request headers: the proxy relay
/// deliberately forwards no `Host` or `Origin`, and an identity the client
/// could choose would let it sign for a relying party of its own invention.
#[derive(Clone)]
pub struct Webauthn {
    /// The relying party id: the console site's hostname.
    rp_id: String,
    /// The exact origin the browser must report: `https://<rp_id>`.
    origin: String,
    /// The durable credential store.
    passkeys: Passkeys,
    /// The outstanding-challenge pool.
    challenges: Challenges,
}

impl Webauthn {
    /// Builds passkey login for `rp_id`, loading credentials from `data_dir`.
    pub fn load(rp_id: &str, data_dir: &Path) -> Self {
        Self::with_parts(rp_id, Passkeys::load(data_dir), Challenges::new())
    }

    /// Builds from already-made parts — the seam tests use to inject a
    /// scratch store or a zero-lifetime challenge pool.
    pub fn with_parts(rp_id: &str, passkeys: Passkeys, challenges: Challenges) -> Self {
        Self {
            rp_id: rp_id.to_owned(),
            origin: format!("https://{rp_id}"),
            passkeys,
            challenges,
        }
    }

    /// Whether no passkey is registered — the login route's cue to answer the
    /// uniform 401 rather than hand out a challenge nothing could answer.
    pub fn is_empty(&self) -> bool {
        self.passkeys.is_empty()
    }

    /// Issues a ceremony challenge, as `{"challenge", "rpId"}` for the SPA.
    pub fn challenge(&self, purpose: Purpose) -> io::Result<Json> {
        Ok(Json::object([
            ("challenge", Json::string(self.challenges.issue(purpose)?)),
            ("rpId", Json::string(&self.rp_id)),
        ]))
    }

    /// Issues an invitation's challenge, as `{"challenge", "rpId", "name"}`.
    ///
    /// The extra field is the whole difference: an ordinary registration is
    /// driven by a logged-in owner who already knows whose credential they are
    /// making, while an invitee's browser must be *told* the name to put in the
    /// passkey — and told it by the daemon, from the invitation, rather than
    /// asked for it. Built here rather than assembled by the route so the
    /// ceremony's wire shape stays in the module that defines the ceremony.
    pub fn invite_challenge(&self, name: &str) -> io::Result<Json> {
        Ok(Json::object([
            ("challenge", Json::string(self.challenges.issue(Purpose::Invite)?)),
            ("rpId", Json::string(&self.rp_id)),
            ("name", Json::string(name)),
        ]))
    }

    /// Registers the credential described by a browser's registration body.
    ///
    /// The body carries what `navigator.credentials.create()` returned:
    /// `id` (base64url credential id), `publicKey` (base64url SPKI from
    /// `getPublicKey()`), `algorithm` (COSE, must be ES256), `clientDataJSON`
    /// and `authenticatorData` (base64url), plus an optional `user` (whose
    /// passkey this is; [`DEFAULT_USER`] when unnamed) and `label`. Every
    /// failure is one uninformative error: the caller is already
    /// authenticated, but a registration body is still attacker-shaped input.
    ///
    /// The name comes from the body because only the owner can reach this
    /// route, and the owner may register a credential for anybody. The invite
    /// door cannot afford that and does not use it — see [`Self::register_as`].
    pub fn register(&self, body: &Json) -> Result<Passkey, RefusedCeremony> {
        self.register_as(body, Purpose::Register, None)
    }

    /// Registers a credential under a name this method is *given*, ignoring
    /// whatever the body claims.
    ///
    /// This is the whole security difference between the owner's registration
    /// route and the invite door. [`Self::register`] reads `user` out of the
    /// posted body, which is correct when only the owner can reach it. At the
    /// invite door the caller is a stranger holding a one-time code, and a name
    /// taken from their request would let a code minted for `mom` produce a
    /// passkey called anything they liked — including a name the operator had
    /// already granted real power to. So the caller passes the name from
    /// [`crate::invite::Invites::redeem`] and the body's own `user` field is
    /// discarded, not merely defaulted.
    ///
    /// `purpose` is likewise a parameter so the challenge a ceremony redeems
    /// must be one issued at the same door; see [`Purpose::Invite`].
    pub fn register_as(
        &self,
        body: &Json,
        purpose: Purpose,
        user: Option<&str>,
    ) -> Result<Passkey, RefusedCeremony> {
        let id = credential_id(body)?;
        if body.get("algorithm").and_then(Json::as_i64) != Some(COSE_ES256) {
            return Err(RefusedCeremony);
        }
        let client_data = body.get("clientDataJSON").and_then(Json::as_str).ok_or(RefusedCeremony)?;
        let client_data = b64url_decode(client_data).ok_or(RefusedCeremony)?;
        self.check_client_data(&client_data, "webauthn.create", purpose)?;

        let auth_data = decoded_field(body, "authenticatorData")?;
        self.check_auth_data(&auth_data, FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_ATTESTED_CREDENTIAL)?;

        let spki = decoded_field(body, "publicKey")?;
        let public_key = p256_point_from_spki(&spki).ok_or(RefusedCeremony)?;

        let passkey = Passkey {
            id,
            public_key,
            user: match user {
                Some(given) => given.to_owned(),
                None => named_field(body, "user", DEFAULT_USER, MAX_USER_CHARS),
            },
            // Bounded like every stored string: both names render in the
            // console and live in an owner-only file, but they are still input.
            label: named_field(body, "label", "passkey", 64),
            created_unix: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|since| since.as_secs())
                .unwrap_or(0),
        };
        self.passkeys.add(passkey.clone()).map_err(|_| RefusedCeremony)?;
        Ok(passkey)
    }

    /// Verifies a browser's login assertion; `Ok` carries the passkey that
    /// signed it — whose `user` the caller mints the session under.
    ///
    /// The body carries what `navigator.credentials.get()` returned: `id`,
    /// `clientDataJSON`, `authenticatorData`, and `signature`, all base64url.
    /// Every way of failing — unknown credential, stale challenge, wrong
    /// origin, missing user-verification flag, bad signature — is the same
    /// uninformative refusal, so probing the login door teaches nothing.
    pub fn verify_login(&self, body: &Json) -> Result<Passkey, RefusedCeremony> {
        let id = credential_id(body)?;
        let passkey = self.passkeys.find(&id).ok_or(RefusedCeremony)?;

        let client_data = decoded_field(body, "clientDataJSON")?;
        self.check_client_data(&client_data, "webauthn.get", Purpose::Login)?;

        let auth_data = decoded_field(body, "authenticatorData")?;
        self.check_auth_data(&auth_data, FLAG_USER_PRESENT | FLAG_USER_VERIFIED)?;

        let signature = decoded_field(body, "signature")?;
        // What the authenticator actually signed: the authenticator data with
        // the client data's digest appended.
        let mut message = auth_data;
        message.extend_from_slice(digest::digest(&digest::SHA256, &client_data).as_ref());
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &passkey.public_key)
            .verify(&message, &signature)
            .map_err(|_| RefusedCeremony)?;
        Ok(passkey)
    }

    /// The registered passkeys as
    /// `{"passkeys": [{id, user, label, createdUnix}]}`.
    ///
    /// Public keys stay out on purpose: the console has no use for them, and
    /// what is not sent cannot end up pasted somewhere.
    pub fn list(&self) -> Json {
        Json::object([(
            "passkeys",
            Json::array(self.passkeys.list().into_iter().map(|entry| {
                Json::object([
                    ("id", Json::string(entry.id)),
                    ("user", Json::string(entry.user)),
                    ("label", Json::string(entry.label)),
                    ("createdUnix", Json::Number(entry.created_unix as f64)),
                ])
            })),
        )])
    }

    /// Removes the passkey named by `id`; false if none was registered.
    pub fn remove(&self, id: &str) -> io::Result<bool> {
        self.passkeys.remove(id)
    }

    /// Checks a decoded clientDataJSON: right ceremony type, a challenge this
    /// pool really issued for this purpose, and exactly the configured origin.
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
        let challenge = value.get("challenge").and_then(Json::as_str).ok_or(RefusedCeremony)?;
        if !self.challenges.take(challenge, purpose) {
            return Err(RefusedCeremony);
        }
        Ok(())
    }

    /// Checks a decoded authenticator data: long enough, hashed over *this*
    /// relying party id, and carrying every flag in `required` — user
    /// verification above all, the biometric check itself.
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

/// The one refusal every failed ceremony collapses into.
///
/// Carrying no detail is the point: the route answers the API's uniform 401,
/// and the specific reason lives only here in the verifier where tests can
/// reach it through behaviour.
#[derive(Debug, PartialEq, Eq)]
pub struct RefusedCeremony;

/// Reads and bounds a body's credential id: base64url text that decodes and
/// respects the specification's length cap.
fn credential_id(body: &Json) -> Result<String, RefusedCeremony> {
    let id = body.get("id").and_then(Json::as_str).ok_or(RefusedCeremony)?;
    let decoded = b64url_decode(id).ok_or(RefusedCeremony)?;
    if decoded.is_empty() || decoded.len() > MAX_CREDENTIAL_ID_BYTES {
        return Err(RefusedCeremony);
    }
    Ok(id.to_owned())
}

/// Reads a base64url string field out of a ceremony body, decoded.
fn decoded_field(body: &Json, field: &str) -> Result<Vec<u8>, RefusedCeremony> {
    body.get(field).and_then(Json::as_str).and_then(b64url_decode).ok_or(RefusedCeremony)
}

/// Reads a display-name field out of a registration body: trimmed, bounded to
/// `limit` characters, and `fallback` where absent or blank.
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

/// Cuts the uncompressed point out of a P-256 SubjectPublicKeyInfo.
///
/// `None` for any other key shape — a different curve, a compressed point, or
/// arbitrary DER — which refuses at registration what could never verify at
/// login.
fn p256_point_from_spki(spki: &[u8]) -> Option<Vec<u8>> {
    let point = spki.strip_prefix(P256_SPKI_PREFIX.as_slice())?;
    (point.len() == P256_POINT_BYTES && point[0] == 0x04).then(|| point.to_vec())
}

/// Encodes bytes as unpadded base64url — the alphabet WebAuthn speaks.
pub(crate) fn b64url_encode(data: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let bits = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[(bits >> 18 & 0x3f) as usize] as char);
        out.push(B64[(bits >> 12 & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[(bits >> 6 & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[(bits & 0x3f) as usize] as char);
        }
    }
    out
}

/// Decodes unpadded base64url; padding is tolerated, anything else is `None`.
pub(crate) fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    fn value(byte: u8) -> Option<u32> {
        match byte {
            b'A'..=b'Z' => Some((byte - b'A') as u32),
            b'a'..=b'z' => Some((byte - b'a' + 26) as u32),
            b'0'..=b'9' => Some((byte - b'0' + 52) as u32),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let mut symbols = Vec::new();
    for byte in text.bytes() {
        match byte {
            b'=' => {}
            other => symbols.push(value(other)?),
        }
    }
    let mut out = Vec::with_capacity(symbols.len() / 4 * 3);
    for group in symbols.chunks(4) {
        if group.len() == 1 {
            return None; // a lone symbol cannot encode any byte
        }
        let bits = group.iter().enumerate().fold(0u32, |acc, (i, s)| acc | (s << (18 - 6 * i)));
        out.push((bits >> 16) as u8);
        if group.len() > 2 {
            out.push((bits >> 8) as u8);
        }
        if group.len() > 3 {
            out.push(bits as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};

    /// A scratch directory unique to one test, as in the sibling modules.
    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir()
            .join(format!("selfhost-webauthn-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    /// The relying party every test speaks for.
    const RP: &str = "console.example.com";

    /// A test authenticator: a real P-256 keypair whose public half is
    /// exported in the same SPKI shape a browser's `getPublicKey()` uses.
    struct Authenticator {
        keys: EcdsaKeyPair,
        id: String,
    }

    impl Authenticator {
        fn new(id: &str) -> Self {
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                .expect("a P-256 keypair");
            let keys = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .expect("the keypair parses back");
            Self { keys, id: b64url_encode(id.as_bytes()) }
        }

        fn spki(&self) -> Vec<u8> {
            let mut out = P256_SPKI_PREFIX.to_vec();
            out.extend_from_slice(self.keys.public_key().as_ref());
            out
        }

        /// Authenticator data over `RP` wearing `flags`.
        fn auth_data(flags: u8) -> Vec<u8> {
            let mut out = digest::digest(&digest::SHA256, RP.as_bytes()).as_ref().to_vec();
            out.push(flags);
            out.extend_from_slice(&[0, 0, 0, 1]); // sign counter
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

        /// A complete registration body for a freshly issued challenge,
        /// registering `user`'s passkey on the device called `label`.
        fn register_body(&self, webauthn: &Webauthn, user: &str, label: &str) -> Json {
            self.register_body_for(webauthn, Purpose::Register, user, label)
        }

        /// The same, at a named door — the seam the invite tests bend, so a
        /// ceremony can be built with a challenge from one purpose and offered
        /// at another.
        fn register_body_for(
            &self,
            webauthn: &Webauthn,
            purpose: Purpose,
            user: &str,
            label: &str,
        ) -> Json {
            let challenge = challenge_of(webauthn.challenge(purpose).unwrap());
            let client = Self::client_data("webauthn.create", &challenge, &format!("https://{RP}"));
            let flags = FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_ATTESTED_CREDENTIAL;
            Json::object([
                ("id", Json::string(&self.id)),
                ("algorithm", Json::Number(COSE_ES256 as f64)),
                ("publicKey", Json::string(b64url_encode(&self.spki()))),
                ("clientDataJSON", Json::string(b64url_encode(&client))),
                ("authenticatorData", Json::string(b64url_encode(&Self::auth_data(flags)))),
                ("user", Json::string(user)),
                ("label", Json::string(label)),
            ])
        }

        /// A complete, correctly signed login body for a fresh challenge.
        fn login_body(&self, webauthn: &Webauthn) -> Json {
            self.login_body_with(webauthn, FLAG_USER_PRESENT | FLAG_USER_VERIFIED, None)
        }

        /// The same, with explicit flags and an optional origin override —
        /// the seams the refusal tests bend one at a time.
        fn login_body_with(&self, webauthn: &Webauthn, flags: u8, origin: Option<&str>) -> Json {
            let challenge = challenge_of(webauthn.challenge(Purpose::Login).unwrap());
            let origin = origin.map(str::to_owned).unwrap_or(format!("https://{RP}"));
            let client = Self::client_data("webauthn.get", &challenge, &origin);
            let auth = Self::auth_data(flags);
            let mut message = auth.clone();
            message.extend_from_slice(digest::digest(&digest::SHA256, &client).as_ref());
            let signature = self
                .keys
                .sign(&SystemRandom::new(), &message)
                .expect("signing with the test key");
            Json::object([
                ("id", Json::string(&self.id)),
                ("clientDataJSON", Json::string(b64url_encode(&client))),
                ("authenticatorData", Json::string(b64url_encode(&auth))),
                ("signature", Json::string(b64url_encode(signature.as_ref()))),
            ])
        }
    }

    fn challenge_of(reply: Json) -> String {
        reply.get("challenge").and_then(Json::as_str).expect("a challenge").to_owned()
    }

    fn webauthn(dir: &Path) -> Webauthn {
        Webauthn::with_parts(RP, Passkeys::load(dir), Challenges::new())
    }

    #[test]
    fn base64url_round_trips_and_refuses_the_wrong_alphabet() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"foob", &[0xff, 0xee, 0x00, 0x41]] {
            assert_eq!(b64url_decode(&b64url_encode(data)).as_deref(), Some(data));
        }
        assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8", "url alphabet, unpadded");
        assert!(b64url_decode("a+b/").is_none(), "the standard alphabet is not this one");
        assert!(b64url_decode("a").is_none(), "a lone symbol encodes nothing");
    }

    #[test]
    fn a_challenge_redeems_exactly_once_and_only_for_its_purpose() {
        let challenges = Challenges::new();
        let issued = challenges.issue(Purpose::Login).unwrap();
        assert!(!challenges.take(&issued, Purpose::Register), "purposes do not cross");
        assert!(challenges.take(&issued, Purpose::Login));
        assert!(!challenges.take(&issued, Purpose::Login), "a challenge is single-use");
    }

    #[test]
    fn an_expired_challenge_does_not_redeem() {
        let challenges = Challenges::with_lifetime(Duration::ZERO);
        let issued = challenges.issue(Purpose::Login).unwrap();
        assert!(!challenges.take(&issued, Purpose::Login));
    }

    #[test]
    fn registration_stores_a_key_that_then_verifies_a_login() {
        let dir = scratch("roundtrip");
        let webauthn = webauthn(&dir);
        let device = Authenticator::new("credential-1");

        let stored = webauthn.register(&device.register_body(&webauthn, "Alex", "MacBook")).expect("registers");
        assert_eq!(stored.user, "Alex");
        assert_eq!(stored.label, "MacBook");
        assert!(!webauthn.is_empty());

        let signer = webauthn.verify_login(&device.login_body(&webauthn)).expect("a real assertion verifies");
        assert_eq!(signer.user, "Alex", "the assertion answers who signed it");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_invitation_registers_under_its_own_name_and_never_the_bodys() {
        // The property the whole invite door rests on. The caller there is a
        // stranger holding a code, so a name taken from their request would let
        // a code minted for one person mint a credential for another — including
        // one the operator had already granted real power to.
        let dir = scratch("invite-name");
        let webauthn = webauthn(&dir);
        let device = Authenticator::new("credential-invited");
        let body = device.register_body_for(&webauthn, Purpose::Invite, "alex", "phone");

        let stored = webauthn
            .register_as(&body, Purpose::Invite, Some("mom"))
            .expect("the ceremony is sound");
        assert_eq!(stored.user, "mom", "the invitation's name wins over the body's claim");
        // And it is the stored name, not merely the returned one, that a later
        // login mints its session under.
        assert_eq!(webauthn.verify_login(&device.login_body(&webauthn)).unwrap().user, "mom");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_challenge_from_one_door_cannot_complete_a_ceremony_at_the_other() {
        // `Purpose::Invite` exists so the unauthenticated invite door and the
        // owner-only registration door cannot be crossed. Neither direction is
        // a privilege gain today; this keeps it structural rather than a
        // property re-derived from what each door happens to check.
        let dir = scratch("invite-purpose");
        let webauthn = webauthn(&dir);
        let device = Authenticator::new("credential-crossed");

        let owners = device.register_body_for(&webauthn, Purpose::Register, "mom", "phone");
        assert!(
            webauthn.register_as(&owners, Purpose::Invite, Some("mom")).is_err(),
            "a registration challenge does not open the invite door"
        );

        let invitees = device.register_body_for(&webauthn, Purpose::Invite, "mom", "phone");
        assert!(
            webauthn.register_as(&invitees, Purpose::Register, None).is_err(),
            "and an invitation's challenge does not complete an owner's registration"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_people_on_one_device_stay_distinct() {
        let dir = scratch("two-people");
        let webauthn = webauthn(&dir);
        // Same machine, two resident credentials — one per person.
        let alexs = Authenticator::new("credential-alex");
        let moms = Authenticator::new("credential-mom");
        webauthn.register(&alexs.register_body(&webauthn, "Alex", "MacBook")).expect("registers");
        webauthn.register(&moms.register_body(&webauthn, "Mom", "MacBook")).expect("registers");

        assert_eq!(webauthn.verify_login(&alexs.login_body(&webauthn)).unwrap().user, "Alex");
        assert_eq!(webauthn.verify_login(&moms.login_body(&webauthn)).unwrap().user, "Mom");

        // The same person re-registering the same device supersedes their own
        // passkey — and only theirs.
        let replacement = Authenticator::new("credential-alex-2");
        webauthn.register(&replacement.register_body(&webauthn, "Alex", "MacBook")).expect("registers");
        assert!(webauthn.verify_login(&alexs.login_body(&webauthn)).is_err(), "superseded");
        assert_eq!(webauthn.verify_login(&replacement.login_body(&webauthn)).unwrap().user, "Alex");
        assert_eq!(webauthn.verify_login(&moms.login_body(&webauthn)).unwrap().user, "Mom");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_from_before_names_belongs_to_the_owner() {
        let dir = scratch("unnamed-file");
        // Write through the store, then strip the user fields the way a
        // pre-naming daemon would have written the file.
        let first = webauthn(&dir);
        let device = Authenticator::new("credential-1");
        first.register(&device.register_body(&first, "ignored", "MacBook")).expect("registers");
        let path = Passkeys::path_in(&dir);
        let text = std::fs::read_to_string(&path).unwrap().replace(",\"user\":\"ignored\"", "");
        assert!(!text.contains("\"user\""), "the rewritten file is nameless");
        std::fs::write(&path, text).unwrap();

        let reloaded = webauthn(&dir);
        let signer = reloaded.verify_login(&device.login_body(&reloaded)).expect("still verifies");
        assert_eq!(signer.user, DEFAULT_USER, "an unnamed passkey is the owner's");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn passkeys_survive_a_reload_from_disk() {
        let dir = scratch("reload");
        let first = webauthn(&dir);
        let device = Authenticator::new("credential-1");
        first.register(&device.register_body(&first, "Alex", "phone")).expect("registers");

        // A fresh load — the daemon restarting — still verifies the device.
        let reloaded = webauthn(&dir);
        reloaded.verify_login(&device.login_body(&reloaded)).expect("verifies after reload");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_bent_assertion_is_refused() {
        let dir = scratch("refusals");
        let webauthn = webauthn(&dir);
        let device = Authenticator::new("credential-1");
        webauthn.register(&device.register_body(&webauthn, "Alex", "MacBook")).expect("registers");

        // Presence without verification: the biometric check did not happen.
        let unverified = device.login_body_with(&webauthn, FLAG_USER_PRESENT, None);
        assert!(webauthn.verify_login(&unverified).is_err(), "UV must be set");

        // A phishing page's origin, with everything else genuine.
        let phished = device.login_body_with(
            &webauthn,
            FLAG_USER_PRESENT | FLAG_USER_VERIFIED,
            Some("https://evil.example.com"),
        );
        assert!(webauthn.verify_login(&phished).is_err(), "the origin binds");

        // A signature from a key that was never registered.
        let stranger = Authenticator::new("credential-1"); // same id, different key
        assert!(webauthn.verify_login(&stranger.login_body(&webauthn)).is_err());

        // A replay: the same body a second time redeems no challenge.
        let body = device.login_body(&webauthn);
        webauthn.verify_login(&body).expect("first use verifies");
        assert!(webauthn.verify_login(&body).is_err(), "a challenge is single-use");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn registration_refuses_the_wrong_algorithm_key_shape_and_origin() {
        let dir = scratch("register-refusals");
        let webauthn = webauthn(&dir);
        let device = Authenticator::new("credential-1");

        let mut wrong_alg = device.register_body(&webauthn, "Alex", "x");
        if let Json::Object(entries) = &mut wrong_alg {
            entries.insert("algorithm".into(), Json::Number(-257.0)); // RS256
        }
        assert!(webauthn.register(&wrong_alg).is_err(), "only ES256 is accepted");

        let mut wrong_key = device.register_body(&webauthn, "Alex", "x");
        if let Json::Object(entries) = &mut wrong_key {
            entries.insert("publicKey".into(), Json::string(b64url_encode(&[0x30, 0x59, 0x01])));
        }
        assert!(webauthn.register(&wrong_key).is_err(), "not a P-256 SPKI");

        assert!(webauthn.is_empty(), "nothing refused was stored");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_removed_passkey_stops_verifying() {
        let dir = scratch("remove");
        let webauthn = webauthn(&dir);
        let device = Authenticator::new("credential-1");
        webauthn.register(&device.register_body(&webauthn, "Alex", "MacBook")).expect("registers");

        assert!(webauthn.remove(&device.id).expect("removes"));
        assert!(!webauthn.remove(&device.id).expect("second remove is a no-op"));
        assert!(webauthn.verify_login(&device.login_body(&webauthn)).is_err());
        assert!(webauthn.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_list_names_devices_but_never_their_keys() {
        let dir = scratch("list");
        let webauthn = webauthn(&dir);
        let device = Authenticator::new("credential-1");
        webauthn.register(&device.register_body(&webauthn, "Alex", "MacBook")).expect("registers");
        let text = webauthn.list().to_text();
        assert!(text.contains("MacBook"));
        assert!(!text.contains(&b64url_encode(&device.spki())), "keys stay out of the list");
    }

    #[test]
    fn a_malformed_passkey_file_loads_empty_rather_than_half_open() {
        let dir = scratch("malformed");
        std::fs::write(Passkeys::path_in(&dir), "not json").unwrap();
        assert!(Passkeys::load(&dir).is_empty());
        std::fs::write(Passkeys::path_in(&dir), r#"{"passkeys":[{"id":"AA"}]}"#).unwrap();
        assert!(Passkeys::load(&dir).is_empty(), "a partial entry poisons the load");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_passkey_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("perms");
        let webauthn = webauthn(&dir);
        let device = Authenticator::new("credential-1");
        webauthn.register(&device.register_body(&webauthn, "Alex", "x")).expect("registers");
        let mode = std::fs::metadata(Passkeys::path_in(&dir)).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "no group or world access: mode {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
