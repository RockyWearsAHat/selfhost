//! The desktop VPN app's sign-in door: prove who you are to the console once,
//! and the device you are sitting at is enrolled — no typed name, no admin
//! pasting a grant command with somebody else's key in it.
//!
//! # The shape, and why it is this shape
//!
//! This is an authorization-code exchange with a PKCE verifier, run entirely
//! between parties this deployment already trusts each other's code for: the
//! console's own login (a session cookie, minted by [`crate::webauthn`] or the
//! console password) proves *who*, and this module's one-time code carries
//! that proof across the one gap a cookie cannot cross — from the browser tab
//! that logged in to the desktop process that asked it to. Nothing here is a
//! third-party identity provider; the console **is** the authorization
//! server, which is the whole point of it being "our own OAuth for our own
//! services" rather than a login button belonging to somebody else.
//!
//! `POST /api/vpn/authorize` is reached only by a browser already carrying a
//! session — [`crate::Demand::Authenticated`] gates it exactly like `whoami`
//! — so minting a code first requires a real credential. `POST
//! /api/vpn/enroll` is reached only by presenting the code and the PKCE
//! verifier that matches the challenge sealed into it, which is what stands
//! in for a session on a process that never had a cookie.
//!
//! # Why this never grants anything
//!
//! [`Authorizations::mint`] is refused unless [`selfhost_identity::Policy`]
//! already says the caller may reach the requested location — see
//! [`crate::Api`]'s handler. A code minted here therefore proves nothing new;
//! it carries forward a decision the registry had already made, the same
//! "fully automatic" shape [`crate::invite`]'s redemption gives an invited
//! name's passkey. An account with no `vpn.access:<location>` grant gets a
//! plain refusal naming the missing capability, not a code — there is still
//! exactly one way to hand out a *new* power, and it is the owner writing it
//! down in the people registry, same as it has always been.
//!
//! # Why the code is stored as a digest, and why it is this short-lived
//!
//! Same reasoning as [`crate::invite::Invites`]: the code exists in one place
//! outside this store — the URL the browser is about to redirect through —
//! and this store holds only what proves a presented code matches, never the
//! code itself. It lives for [`AUTHORIZATION_TTL_SECS`], not
//! [`crate::invite::DEFAULT_TTL_HOURS`]: an invitation is something a person
//! reads and acts on later, and this is a redirect the browser is already in
//! the middle of, so a code that outlived the tab it was minted for would be a
//! bearer credential sitting in browser history and a proxy's access log for
//! no reason a legitimate flow ever needs.
//!
//! # Why this is in-memory only
//!
//! [`crate::invite::Invites`] is a durable file because `selfhost people
//! invite` mints one from a second process and the running daemon has to see
//! it without a restart. Nothing outside this process ever mints or redeems
//! one of these — both halves of the exchange are HTTP calls to the one
//! daemon a console session and a VPN sign-in both reach — so there is no
//! second writer to stay consistent with, and a restart losing a code that
//! was moments from being redeemed simply asks the sign-in to run again.

use crate::token::{constant_time_eq, random_bytes};
use ring::digest;
use selfhost_identity::Credential;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// How long a minted authorization code is redeemable.
///
/// Long enough for a browser to finish a redirect to a loopback port on the
/// same machine — which does not touch the network — short enough that a
/// code copied out of a browser's history or a proxy's access log is dead
/// before anybody could type it anywhere.
pub const AUTHORIZATION_TTL_SECS: u64 = 120;

/// The most outstanding authorizations this store will hold at once.
///
/// Each one lives for [`AUTHORIZATION_TTL_SECS`], so this bounds a burst of
/// sign-ins, not a population of users the way [`crate::invite::MAX_INVITES`]
/// does.
const MAX_AUTHORIZATIONS: usize = 64;

/// The entropy behind a code: 192 bits, the same size [`crate::invite`] uses
/// and for the same reason — unguessable while still small enough to sit in a
/// URL.
const CODE_BYTES: usize = 24;

/// One outstanding authorization: who it was minted for, which VPN location
/// it authorizes a roster entry against, and the PKCE challenge the eventual
/// redemption must prove knowledge of the matching verifier for.
struct Authorization {
    /// SHA-256 of the code. The code itself is never stored — see the module
    /// documentation.
    code_digest: Vec<u8>,
    /// The identity the console session named when this was minted —
    /// [`selfhost_identity::Identity::as_str`]'s spelling, so it reads the
    /// owner's or a person's name exactly as the rest of this crate does.
    name: String,
    /// How that session authenticated, carried through so the audit line
    /// [`crate::Api::vpn_enroll`] writes on redemption can name the real
    /// credential rather than inventing one that fits no ceremony that
    /// actually happened.
    credential: Credential,
    /// The relay this code authorizes a roster entry against.
    location: String,
    /// RFC 7636's `S256` challenge: base64url(SHA-256(verifier)), taken
    /// verbatim from the browser and compared against what the desktop app
    /// derives from the verifier it already holds. Not a secret itself —
    /// PKCE's whole point is that the challenge may be seen in transit and
    /// still protect the code, because only the party that generated the
    /// verifier can produce it again.
    code_challenge: String,
    /// When this stops being redeemable, in seconds since the Unix epoch.
    expires_unix: u64,
}

/// Why a presented code and verifier were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemError {
    /// The code is unknown, expired, or already spent. Deliberately the same
    /// answer for all three, like every credential check in this crate: a
    /// stranger probing the door learns nothing about which case they hit.
    NoSuchCode,
    /// The code was real, but the verifier's hash does not match the
    /// challenge it was minted with — the desktop process asking to redeem it
    /// is not the one the browser was redirecting to.
    VerifierMismatch,
}

/// Who and what a redeemed code authorizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorized {
    /// The identity this code was minted for.
    pub name: String,
    /// How that identity's console session authenticated.
    pub credential: Credential,
    /// The VPN location a roster entry may now be provisioned against.
    pub location: String,
}

/// The in-memory authorization-code store behind `/api/vpn/authorize` and
/// `/api/vpn/enroll`. See the module documentation for why this is not a
/// file.
#[derive(Clone)]
pub struct Authorizations {
    entries: Arc<Mutex<Vec<Authorization>>>,
}

impl Authorizations {
    /// An empty store.
    pub fn new() -> Self {
        Self { entries: Arc::new(Mutex::new(Vec::new())) }
    }

    /// Mints a code binding `name` to `location` and `code_challenge`,
    /// evicting anything already expired first so the cap tracks live
    /// entries rather than history.
    ///
    /// The caller — [`crate::Api`]'s `/api/vpn/authorize` handler — is the
    /// one place that must have already checked the policy question this
    /// module never asks: whether `name` may actually reach `location`. See
    /// the module documentation.
    pub fn mint(
        &self,
        name: &str,
        credential: Credential,
        location: &str,
        code_challenge: &str,
    ) -> Result<String, String> {
        let code = crate::webauthn::b64url_encode(&random_bytes(CODE_BYTES).map_err(|error| {
            format!("could not generate a code: {error}")
        })?);
        let now = now_unix();
        let mut entries = self.entries.lock().expect("the vpn authorization lock was poisoned");
        entries.retain(|entry| entry.expires_unix > now);
        if entries.len() >= MAX_AUTHORIZATIONS {
            return Err(format!(
                "at most {MAX_AUTHORIZATIONS} VPN sign-ins may be in flight at once; try again \
                 in a moment"
            ));
        }
        entries.push(Authorization {
            code_digest: sha256(&code),
            name: name.to_owned(),
            credential,
            location: location.to_owned(),
            code_challenge: code_challenge.to_owned(),
            expires_unix: now.saturating_add(AUTHORIZATION_TTL_SECS),
        });
        Ok(code)
    }

    /// Redeems `code`, proving `verifier` hashes to the challenge it was
    /// minted with.
    ///
    /// Single-use: a successful redemption removes the entry, so a code
    /// intercepted after the legitimate desktop process has already used it
    /// is worthless. The comparison is constant-time and the walk visits
    /// every entry, like every credential check in this crate.
    pub fn redeem(&self, code: &str, verifier: &str) -> Result<Authorized, RedeemError> {
        let presented = sha256(code);
        let now = now_unix();
        let mut entries = self.entries.lock().expect("the vpn authorization lock was poisoned");
        let position = entries.iter().enumerate().fold(None, |found, (index, entry)| {
            let hit = entry.expires_unix > now && constant_time_eq(&entry.code_digest, &presented);
            if hit { Some(index) } else { found }
        });
        let Some(index) = position else {
            return Err(RedeemError::NoSuchCode);
        };
        // The verifier is checked before the entry is removed: a mistyped or
        // mismatched verifier must not spend the one code a legitimate retry
        // from the same browser tab would need. Only a *matching* redemption
        // spends it.
        let challenge = crate::webauthn::b64url_encode(digest::digest(&digest::SHA256, verifier.as_bytes()).as_ref());
        if !constant_time_eq(challenge.as_bytes(), entries[index].code_challenge.as_bytes()) {
            return Err(RedeemError::VerifierMismatch);
        }
        let entry = entries.remove(index);
        Ok(Authorized { name: entry.name, credential: entry.credential, location: entry.location })
    }
}

impl Default for Authorizations {
    fn default() -> Self {
        Self::new()
    }
}

// Deliberately not a revealing `Debug`: a code's digest is not the code, but
// naming who is mid-sign-in and to which location is still more than a log
// line needs to say.
impl std::fmt::Debug for Authorizations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.entries.lock().expect("the vpn authorization lock was poisoned").len();
        write!(f, "Authorizations({count} in flight)")
    }
}

/// SHA-256 of a code, as the stored digest.
fn sha256(code: &str) -> Vec<u8> {
    digest::digest(&digest::SHA256, code.as_bytes()).as_ref().to_vec()
}

/// Seconds since the Unix epoch, or zero if the clock is before it.
fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|since| since.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_code_redeems_once_with_the_matching_verifier() {
        let store = Authorizations::new();
        let verifier = "a-verifier-the-desktop-app-generated-locally";
        let challenge = crate::webauthn::b64url_encode(
            digest::digest(&digest::SHA256, verifier.as_bytes()).as_ref(),
        );
        let code = store.mint("mom", Credential::Passkey, "console", &challenge).expect("mints");

        let authorized = store.redeem(&code, verifier).expect("redeems");
        assert_eq!(authorized.name, "mom");
        assert_eq!(authorized.credential, Credential::Passkey);
        assert_eq!(authorized.location, "console");

        assert_eq!(
            store.redeem(&code, verifier),
            Err(RedeemError::NoSuchCode),
            "a code is single-use"
        );
    }

    #[test]
    fn a_verifier_that_does_not_hash_to_the_challenge_is_refused_and_the_code_survives() {
        let store = Authorizations::new();
        let real_verifier = "the-real-verifier";
        let challenge = crate::webauthn::b64url_encode(
            digest::digest(&digest::SHA256, real_verifier.as_bytes()).as_ref(),
        );
        let code = store.mint("mom", Credential::Passkey, "console", &challenge).expect("mints");

        assert_eq!(
            store.redeem(&code, "a-guessed-verifier"),
            Err(RedeemError::VerifierMismatch)
        );
        // The whole point of checking the verifier first: a mismatch must not
        // burn the code a legitimate retry needs.
        assert!(store.redeem(&code, real_verifier).is_ok(), "the code is still live");
    }

    #[test]
    fn an_unknown_or_empty_code_is_refused() {
        let store = Authorizations::new();
        store.mint("mom", Credential::Passkey, "console", "challenge").expect("mints");
        assert_eq!(store.redeem("not-a-code", "verifier"), Err(RedeemError::NoSuchCode));
        assert_eq!(store.redeem("", ""), Err(RedeemError::NoSuchCode));
    }

    #[test]
    fn an_expired_authorization_is_not_redeemable() {
        let store = Authorizations::new();
        let verifier = "verifier";
        let challenge = crate::webauthn::b64url_encode(
            digest::digest(&digest::SHA256, verifier.as_bytes()).as_ref(),
        );
        let code = store.mint("mom", Credential::Passkey, "console", &challenge).expect("mints");
        {
            let mut entries = store.entries.lock().expect("lock");
            entries[0].expires_unix = now_unix().saturating_sub(1);
        }
        assert_eq!(store.redeem(&code, verifier), Err(RedeemError::NoSuchCode));
    }

    #[test]
    fn outstanding_authorizations_are_capped() {
        let store = Authorizations::new();
        for index in 0..MAX_AUTHORIZATIONS {
            store.mint(&format!("p{index}"), Credential::Passkey, "console", "c").expect("under the cap");
        }
        assert!(
            store.mint("one-too-many", Credential::Passkey, "console", "c").is_err(),
            "a burst hits a wall"
        );
    }
}
