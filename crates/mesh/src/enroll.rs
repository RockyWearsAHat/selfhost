//! Proving that a worker is the worker it claims to be, on *this* connection.
//!
//! A worker dials the owner's console site over the tunnel and, immediately after
//! the WebSocket handshake succeeds, opens the link-control channel carrying its
//! node name and a proof. The proof is an HMAC over the handshake:
//!
//! ```text
//! proof = HMAC-SHA256(node_token, context || key || accept || node_name)
//! ```
//!
//! # Why the proof is bound to the handshake, and not just to the token
//!
//! A bearer token presented on its own answers "does the caller know the secret?"
//! and nothing else. Anyone who has ever seen it — a log line, a crash dump, a
//! backup, a second connection that captured it — can present it again on a
//! connection of their own. That is the flaw in the `mesh_ip` arrangement this
//! replaces, where a bare TCP address with no authentication meant anything at
//! that address could impersonate a worker.
//!
//! Binding fixes it. `Sec-WebSocket-Key` is sixteen random bytes the dialler
//! generates per connection; `Sec-WebSocket-Accept` is what the server derived
//! from it. Together they name *this* TCP connection and no other. A proof
//! computed over them is worthless anywhere else: replaying it requires
//! reproducing a handshake that has already happened, on a connection the
//! attacker does not have. So a captured proof is not a credential.
//!
//! # Length-prefixed, and a deliberate strengthening of the design note
//!
//! The design this implements writes the message as a bare concatenation. Bare
//! concatenation of variable-length fields is ambiguous — `("ab", "c")` and
//! `("a", "bc")` produce identical bytes — and an ambiguity in what a signature
//! covers is the shape of a real attack even when the specific instance looks
//! harmless. Here it is *nearly* harmless, because the two handshake fields are
//! fixed-length base64 and the variable field is last. "Nearly harmless" depends
//! on a length check in a different crate continuing to hold, which is not a
//! property worth resting a credential on.
//!
//! So each field is preceded by its `u16` big-endian length. No peer has ever
//! spoken this protocol, so there is no compatibility cost, and both sides
//! compute the message through [`Binding::message`] — one function, so the two
//! ends cannot disagree about it.
//!
//! # Single use, and the residual this module is honest about
//!
//! [`Binding`] proves the connection. It cannot, by itself, prove *freshness*,
//! because every input to it is chosen by the dialler: the handshake key is the
//! client's random bytes and the accept value is derived from them. If an
//! attacker ever obtains the plaintext of a handshake — which over the tunnel
//! means breaking TLS, or reading it out of the owner's own process — nothing in
//! the arithmetic stops them replaying it.
//!
//! [`NonceLedger`] closes that: the accepter remembers the handshake keys it has
//! already honoured and refuses a repeat. It is bounded in both directions, by
//! entry count and by age, because an unbounded memory of every handshake ever
//! seen is itself a way to exhaust the owner's memory. **The residual, stated
//! plainly: a proof replayed after its entry has aged out or been evicted is
//! admitted.** Sizing the ledger is therefore a real decision — the retention
//! window must exceed any plausible capture-to-replay delay. The complete fix is
//! for the *accepter* to contribute a nonce to the binding, which costs a round
//! trip the current flow does not have; it is recorded here rather than left for
//! someone to rediscover.
//!
//! # Constant time
//!
//! Verification goes through `ring::hmac::verify`, which computes the tag and
//! compares it in constant time. It is the same reason every other constant-time
//! comparison in this project is not hand-rolled: a byte-by-byte comparison with
//! an early return leaks the length of the matching prefix, and a proof is
//! exactly the kind of value an attacker gets unlimited attempts at.

use crate::registry::NodeName;
use std::collections::{BTreeSet, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

/// Domain separation for the proof. Never change it without a version bump.
///
/// A key used for two different purposes is a key that can be made to sign one
/// thing and have it read as the other; the context string is what keeps a node
/// token from ever producing a tag that means something else.
pub const PROOF_CONTEXT: &[u8] = b"selfhost-mesh-v1";

/// The length of a node token, in bytes.
///
/// Thirty-two bytes from the same generator that mints `admin.token`. Not
/// negotiable and not a minimum: a token of any other length is a different
/// credential shape and is refused rather than accepted with a warning.
pub const TOKEN_LEN: usize = 32;

/// The length of a proof, in bytes: HMAC-SHA256 output.
pub const PROOF_LEN: usize = 32;

/// The longest handshake field the binding will cover, in bytes.
///
/// `Sec-WebSocket-Key` is 24 base64 characters and `Sec-WebSocket-Accept` is 28;
/// 128 is generous headroom and small enough that a peer cannot make this side
/// hash an unbounded message before it has proved anything at all.
pub const MAX_HANDSHAKE_FIELD: usize = 128;

/// How long a handshake key is remembered by default.
///
/// Long enough to cover any plausible delay between a proof being observed and
/// being replayed on a link that is dialled every few seconds; short enough that
/// the ledger of a busy owner stays small. See the module documentation on the
/// residual this window defines.
pub const DEFAULT_NONCE_TTL: Duration = Duration::from_secs(15 * 60);

/// How many handshake keys are remembered by default.
///
/// The ceiling exists because the ledger is written to by whoever can reach the
/// link route: without it, an attacker who can complete handshakes can make the
/// owner remember an unbounded number of them.
pub const DEFAULT_NONCE_CAPACITY: usize = 4096;

/// A node's enrolment secret.
///
/// Minted once by `selfhost node invite` on the owner and printed once; stored on
/// the worker with the private-file writer. It is the HMAC key, so it never
/// travels on the wire in any form — only tags computed under it do.
#[derive(Clone, PartialEq, Eq)]
pub struct NodeToken([u8; TOKEN_LEN]);

impl NodeToken {
    /// Wraps thirty-two bytes of secret.
    pub fn from_bytes(bytes: [u8; TOKEN_LEN]) -> Self {
        Self(bytes)
    }

    /// Reads a token from the lowercase hex form it is stored and printed in.
    ///
    /// Refuses anything that is not exactly [`TOKEN_LEN`] bytes of well-formed
    /// hex, rather than accepting a short token — a truncated token file is a
    /// weakened credential, and silently accepting one would make the weakening
    /// invisible.
    pub fn from_hex(text: &str) -> Result<Self, EnrollError> {
        let text = text.trim();
        let bytes = decode_hex(text).ok_or(EnrollError::MalformedToken)?;
        let bytes: [u8; TOKEN_LEN] = bytes.try_into().map_err(|_| EnrollError::MalformedToken)?;
        Ok(Self(bytes))
    }

    /// The lowercase hex form, for writing to the token file or printing once.
    ///
    /// Deliberately a named method and not a `Display` implementation: rendering a
    /// secret must be something a reader can see happening at the call site, not
    /// something that falls out of putting a value in a format string.
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }

    /// Mints a fresh token from the operating system's entropy.
    ///
    /// The one function in this module that is not pure. It lives here so that the
    /// length, the encoding and the source of a node token are decided in exactly
    /// one place; a CLI that assembled its own would be free to get any of the
    /// three wrong.
    pub fn generate() -> Result<Self, EnrollError> {
        use ring::rand::SecureRandom;
        let mut bytes = [0u8; TOKEN_LEN];
        ring::rand::SystemRandom::new().fill(&mut bytes).map_err(|_| EnrollError::NoEntropy)?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for NodeToken {
    /// Never prints the secret.
    ///
    /// The precedent is `selfhost_admin::Token`, and the reason is the same: a
    /// derived `Debug` puts the credential into the first log line anyone adds
    /// while debugging, and from there into a file that outlives the debugging.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("NodeToken(<redacted>)")
    }
}

/// An HMAC-SHA256 tag proving knowledge of a node token over one handshake.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Proof([u8; PROOF_LEN]);

impl Proof {
    /// The raw tag bytes.
    pub fn as_bytes(&self) -> &[u8; PROOF_LEN] {
        &self.0
    }

    /// The lowercase hex form, which is how the proof travels inside the
    /// link-control `OPEN`'s ASCII-JSON parameters.
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }

    /// Reads a proof from its hex form.
    ///
    /// Not constant-time, and it does not need to be: this decodes the value the
    /// *peer* presented, which the peer already knows. The comparison that must be
    /// constant-time is [`Binding::verify`], and that one is.
    pub fn from_hex(text: &str) -> Result<Self, EnrollError> {
        let bytes = decode_hex(text.trim()).ok_or(EnrollError::MalformedProof)?;
        let bytes: [u8; PROOF_LEN] = bytes.try_into().map_err(|_| EnrollError::MalformedProof)?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for Proof {
    /// Prints the tag, which is public: it is what the peer just sent us.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "Proof({})", self.to_hex())
    }
}

/// The handshake a proof is bound to.
///
/// Constructed once per connection and validated on construction, so that
/// [`Binding::prove`] and [`Binding::verify`] are infallible and cannot be called
/// with fields that were never checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    key: String,
    accept: String,
    node: NodeName,
}

impl Binding {
    /// Binds a proof to one WebSocket handshake and one node name.
    ///
    /// `key` is the `Sec-WebSocket-Key` the dialler sent and `accept` is the
    /// `Sec-WebSocket-Accept` the server answered with. Both are checked for
    /// length and for being printable ASCII — they are base64, so anything else
    /// means the caller has handed this function something that is not a
    /// handshake field, and hashing it would produce a proof over bytes nobody
    /// intended.
    pub fn new(key: &str, accept: &str, node: NodeName) -> Result<Self, EnrollError> {
        check_handshake_field("sec-websocket-key", key)?;
        check_handshake_field("sec-websocket-accept", accept)?;
        Ok(Self { key: key.to_owned(), accept: accept.to_owned(), node })
    }

    /// The handshake key this binding covers.
    ///
    /// This is the value the accepter hands to [`NonceLedger::admit`]: the ledger
    /// remembers handshakes, and the handshake key is what names one.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The node this binding names.
    pub fn node(&self) -> &NodeName {
        &self.node
    }

    /// The exact bytes the HMAC is computed over.
    ///
    /// Public because it is the specification: if the two ends of a link ever
    /// disagree about a proof, this is the function to print. Length-prefixed for
    /// the reason the module documentation gives.
    pub fn message(&self) -> Vec<u8> {
        let fields: [&[u8]; 3] = [self.key.as_bytes(), self.accept.as_bytes(), self.node.as_str().as_bytes()];
        let total = PROOF_CONTEXT.len() + fields.iter().map(|field| 2 + field.len()).sum::<usize>();
        let mut message = Vec::with_capacity(total);
        message.extend_from_slice(PROOF_CONTEXT);
        for field in fields {
            // Every field is length-checked on construction, so this cannot
            // truncate: MAX_HANDSHAKE_FIELD and MAX_NAME_LEN are both far below
            // u16::MAX.
            let length = u16::try_from(field.len()).unwrap_or(u16::MAX);
            message.extend_from_slice(&length.to_be_bytes());
            message.extend_from_slice(field);
        }
        message
    }

    /// Computes the proof a worker sends.
    pub fn prove(&self, token: &NodeToken) -> Proof {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &token.0);
        let tag = ring::hmac::sign(&key, &self.message());
        let mut proof = [0u8; PROOF_LEN];
        // HMAC-SHA256 is exactly 32 bytes, which is exactly PROOF_LEN; the copy is
        // sized from the destination so a future change to either cannot overrun.
        proof.copy_from_slice(&tag.as_ref()[..PROOF_LEN]);
        Proof(proof)
    }

    /// Whether `presented` is the proof for this handshake under `token`.
    ///
    /// Constant time. Returns a plain `bool` because there is exactly one thing to
    /// do with a failure — close the link with a bare code, log one line, and
    /// increment that node's own failure counter — and a richer error type would
    /// invite a caller to tell the peer *why* it failed.
    pub fn verify(&self, token: &NodeToken, presented: &Proof) -> bool {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &token.0);
        ring::hmac::verify(&key, &self.message(), &presented.0).is_ok()
    }
}

/// Whether a handshake has been honoured before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// This handshake has not been seen; it has now been recorded.
    Fresh,
    /// This handshake was already honoured. Refuse it.
    Replay,
}

/// The handshake keys this accepter has already honoured.
///
/// Bounded by age and by count; see the module documentation for what that costs
/// and why it is bounded anyway. Pure: the caller supplies the clock, so the
/// expiry behaviour is tested by passing times rather than by sleeping.
#[derive(Debug, Clone)]
pub struct NonceLedger {
    capacity: usize,
    ttl: Duration,
    /// Oldest first, so expiry and eviction are both a walk from the front.
    order: VecDeque<(String, Instant)>,
    /// The same keys, for an O(log n) membership test rather than a scan.
    keys: BTreeSet<String>,
    evictions: u64,
}

impl NonceLedger {
    /// A ledger with the default retention window and capacity.
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_NONCE_CAPACITY, DEFAULT_NONCE_TTL)
    }

    /// A ledger with an explicit capacity and retention window.
    ///
    /// A capacity of zero would admit every replay, so it is raised to one: a
    /// misconfiguration must not silently disable the check.
    pub fn with_limits(capacity: usize, ttl: Duration) -> Self {
        Self {
            capacity: capacity.max(1),
            ttl,
            order: VecDeque::new(),
            keys: BTreeSet::new(),
            evictions: 0,
        }
    }

    /// Admits a handshake, or reports it as a replay.
    ///
    /// Expiry is applied first, so a caller that never admits anything still does
    /// not accumulate entries once they are stale; then capacity. The key is
    /// recorded only when it is fresh, so a refused replay does not extend its own
    /// entry's life.
    pub fn admit(&mut self, handshake_key: &str, now: Instant) -> Admission {
        self.expire(now);
        if self.keys.contains(handshake_key) {
            return Admission::Replay;
        }
        while self.order.len() >= self.capacity {
            self.evict_oldest();
        }
        self.order.push_back((handshake_key.to_owned(), now));
        self.keys.insert(handshake_key.to_owned());
        Admission::Fresh
    }

    /// How many handshakes are currently remembered.
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether nothing is remembered.
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// The capacity this ledger was built with.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The retention window this ledger was built with.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// How many entries have been dropped for capacity rather than for age.
    ///
    /// A non-zero count means the ledger is smaller than the link rate needs, and
    /// that the replay window documented on this module is shorter in practice
    /// than [`NonceLedger::ttl`] claims. Worth reporting rather than discovering.
    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    /// Drops every entry older than the retention window.
    ///
    /// Public so an idle accepter can be swept on a timer; `admit` calls it too, so
    /// a caller that never sweeps is still correct, only lazier.
    pub fn expire(&mut self, now: Instant) {
        while let Some((_, recorded)) = self.order.front() {
            // saturating_duration_since, not `-`: `Instant` subtraction panics if
            // the argument is later, and a caller passing a slightly stale `now`
            // must not abort the process.
            if now.saturating_duration_since(*recorded) <= self.ttl {
                break;
            }
            self.forget_oldest();
        }
    }

    fn evict_oldest(&mut self) {
        if self.forget_oldest() {
            self.evictions = self.evictions.saturating_add(1);
        }
    }

    fn forget_oldest(&mut self) -> bool {
        match self.order.pop_front() {
            Some((key, _)) => {
                self.keys.remove(&key);
                true
            }
            None => false,
        }
    }
}

impl Default for NonceLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// Why an enrolment value was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollError {
    /// A token was not exactly [`TOKEN_LEN`] bytes of lowercase hex.
    MalformedToken,
    /// A proof was not exactly [`PROOF_LEN`] bytes of lowercase hex.
    MalformedProof,
    /// A handshake field was empty, over [`MAX_HANDSHAKE_FIELD`], or not
    /// printable ASCII.
    BadHandshakeField {
        /// Which field, by its header name.
        field: &'static str,
    },
    /// The operating system would not provide entropy.
    NoEntropy,
}

impl fmt::Display for EnrollError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedToken => {
                write!(out, "a node token is exactly {TOKEN_LEN} bytes written as {} hex characters", TOKEN_LEN * 2)
            }
            Self::MalformedProof => {
                write!(out, "an enrolment proof is exactly {PROOF_LEN} bytes written as {} hex characters", PROOF_LEN * 2)
            }
            Self::BadHandshakeField { field } => {
                write!(out, "the {field} handshake field is empty, over {MAX_HANDSHAKE_FIELD} bytes, or not printable ASCII")
            }
            Self::NoEntropy => out.write_str("the operating system would not provide random bytes"),
        }
    }
}

impl std::error::Error for EnrollError {}

/// Rejects a handshake field that is empty, oversized, or not printable ASCII.
fn check_handshake_field(name: &'static str, value: &str) -> Result<(), EnrollError> {
    let acceptable = !value.is_empty()
        && value.len() <= MAX_HANDSHAKE_FIELD
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte));
    if acceptable { Ok(()) } else { Err(EnrollError::BadHandshakeField { field: name }) }
}

/// Renders bytes as lowercase hex.
fn encode_hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Two hex digits per byte, written without a formatting machine so the
        // length is obviously exact.
        text.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

const HEX_DIGITS: [u8; 16] = *b"0123456789abcdef";

/// Decodes lowercase hex, refusing anything malformed rather than skipping it.
///
/// Uppercase is refused: these values are always written by this code, so an
/// uppercase digit means the text came from somewhere else and is worth noticing.
fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        out.push((high << 4) | low);
    }
    Some(out)
}

/// One lowercase hex digit's value.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
    const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

    fn node(text: &str) -> NodeName {
        NodeName::parse(text).expect("valid name")
    }

    fn token() -> NodeToken {
        NodeToken::from_bytes([7u8; TOKEN_LEN])
    }

    fn binding() -> Binding {
        Binding::new(KEY, ACCEPT, node("alex-desktop")).expect("valid binding")
    }

    #[test]
    fn a_proof_verifies_against_the_handshake_it_was_made_for() {
        let binding = binding();
        let proof = binding.prove(&token());
        assert!(binding.verify(&token(), &proof));
    }

    #[test]
    fn a_proof_does_not_verify_under_a_different_token() {
        let binding = binding();
        let proof = binding.prove(&token());
        let other = NodeToken::from_bytes([8u8; TOKEN_LEN]);
        assert!(!binding.verify(&other, &proof));
    }

    #[test]
    fn a_proof_does_not_transfer_to_another_connection() {
        // The whole point of channel binding: a captured proof is not a
        // credential, because it names one handshake and no other.
        let captured = binding().prove(&token());

        let other_key = Binding::new("b3RoZXIgY29ubmVjdGlvbg==", ACCEPT, node("alex-desktop")).expect("binding");
        assert!(!other_key.verify(&token(), &captured));

        let other_accept = Binding::new(KEY, "AAAAAAAAAAAAAAAAAAAAAAAAAAA=", node("alex-desktop")).expect("binding");
        assert!(!other_accept.verify(&token(), &captured));
    }

    #[test]
    fn a_proof_does_not_transfer_to_another_node_name() {
        let captured = binding().prove(&token());
        let other_node = Binding::new(KEY, ACCEPT, node("mac-mini")).expect("binding");
        assert!(!other_node.verify(&token(), &captured));
    }

    #[test]
    fn one_flipped_bit_anywhere_in_the_tag_fails() {
        let binding = binding();
        let good = binding.prove(&token());
        for index in 0..PROOF_LEN {
            for bit in 0..8 {
                let mut bytes = *good.as_bytes();
                bytes[index] ^= 1 << bit;
                assert!(!binding.verify(&token(), &Proof(bytes)), "byte {index} bit {bit}");
            }
        }
    }

    #[test]
    fn the_message_is_domain_separated_and_length_prefixed() {
        // This test is the specification of the signed message. If the layout
        // changes, every enrolled node stops verifying, so the change must be
        // deliberate enough to come here first.
        let binding = binding();
        let message = binding.message();
        assert!(message.starts_with(PROOF_CONTEXT));

        let mut expected = Vec::new();
        expected.extend_from_slice(PROOF_CONTEXT);
        for field in [KEY, ACCEPT, "alex-desktop"] {
            expected.extend_from_slice(&u16::try_from(field.len()).expect("short").to_be_bytes());
            expected.extend_from_slice(field.as_bytes());
        }
        assert_eq!(message, expected);
    }

    #[test]
    fn length_prefixing_removes_the_concatenation_ambiguity() {
        // Without the prefixes these two bindings would hash identical bytes, and
        // a proof for one would verify for the other.
        let left = Binding::new("aab", "cc", node("node")).expect("binding");
        let right = Binding::new("aa", "bcc", node("node")).expect("binding");
        assert_ne!(left.message(), right.message());
        let proof = left.prove(&token());
        assert!(!right.verify(&token(), &proof));
    }

    #[test]
    fn handshake_fields_are_bounded_and_must_be_printable_ascii() {
        let long = "a".repeat(MAX_HANDSHAKE_FIELD + 1);
        assert_eq!(
            Binding::new(&long, ACCEPT, node("n")).unwrap_err(),
            EnrollError::BadHandshakeField { field: "sec-websocket-key" }
        );
        assert_eq!(
            Binding::new(KEY, "", node("n")).unwrap_err(),
            EnrollError::BadHandshakeField { field: "sec-websocket-accept" }
        );
        for bad in ["with space", "new\nline", "nul\0byte", "\u{7f}del"] {
            assert!(
                matches!(Binding::new(bad, ACCEPT, node("n")), Err(EnrollError::BadHandshakeField { .. })),
                "{bad:?} should be refused"
            );
        }
        // Exactly at the ceiling is fine.
        assert!(Binding::new(&"a".repeat(MAX_HANDSHAKE_FIELD), ACCEPT, node("n")).is_ok());
    }

    #[test]
    fn a_replayed_proof_is_refused() {
        // The proof itself still verifies — it is the same handshake — which is
        // exactly why the ledger has to exist.
        let mut ledger = NonceLedger::new();
        let now = Instant::now();
        let binding = binding();
        let proof = binding.prove(&token());

        assert_eq!(ledger.admit(binding.key(), now), Admission::Fresh);
        assert!(binding.verify(&token(), &proof), "the arithmetic cannot tell a replay from the original");
        assert_eq!(ledger.admit(binding.key(), now), Admission::Replay);
        assert_eq!(ledger.admit(binding.key(), now + Duration::from_secs(1)), Admission::Replay);
        assert_eq!(ledger.len(), 1, "a refused replay does not add an entry");
    }

    #[test]
    fn different_handshakes_are_each_admitted_once() {
        let mut ledger = NonceLedger::new();
        let now = Instant::now();
        for index in 0..100 {
            let key = format!("handshake-{index}");
            assert_eq!(ledger.admit(&key, now), Admission::Fresh);
            assert_eq!(ledger.admit(&key, now), Admission::Replay);
        }
        assert_eq!(ledger.len(), 100);
    }

    #[test]
    fn entries_age_out_of_the_ledger() {
        let mut ledger = NonceLedger::with_limits(64, Duration::from_secs(60));
        let start = Instant::now();
        assert_eq!(ledger.admit("one", start), Admission::Fresh);
        assert_eq!(ledger.admit("one", start + Duration::from_secs(59)), Admission::Replay);
        // Past the window the entry is gone, and the replay is admitted. This is
        // the documented residual, asserted so nobody has to discover it.
        assert_eq!(ledger.admit("one", start + Duration::from_secs(61)), Admission::Fresh);
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn expiry_can_be_swept_without_admitting_anything() {
        let mut ledger = NonceLedger::with_limits(64, Duration::from_secs(10));
        let start = Instant::now();
        ledger.admit("one", start);
        ledger.admit("two", start);
        assert_eq!(ledger.len(), 2);
        ledger.expire(start + Duration::from_secs(11));
        assert!(ledger.is_empty());
    }

    #[test]
    fn a_stale_now_does_not_abort_the_process() {
        // `Instant` subtraction panics when the argument is later, and under
        // `panic = "abort"` that is the whole daemon. Two callers on different
        // tasks can easily read the clock out of order.
        let mut ledger = NonceLedger::with_limits(8, Duration::from_secs(10));
        let start = Instant::now() + Duration::from_secs(100);
        ledger.admit("one", start);
        ledger.expire(start - Duration::from_secs(50));
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn the_ledger_is_bounded_and_says_when_it_evicted() {
        let mut ledger = NonceLedger::with_limits(4, Duration::from_secs(3600));
        let now = Instant::now();
        for index in 0..10 {
            ledger.admit(&format!("handshake-{index}"), now);
        }
        assert_eq!(ledger.len(), 4, "memory of handshakes is bounded, or it is a way to exhaust the owner");
        assert_eq!(ledger.evictions(), 6);
        // The oldest have been forgotten — the documented residual again.
        assert_eq!(ledger.admit("handshake-0", now), Admission::Fresh);
        assert_eq!(ledger.admit("handshake-9", now), Admission::Replay);
    }

    #[test]
    fn a_zero_capacity_ledger_still_refuses_a_replay() {
        // A misconfiguration must not silently disable the check.
        let mut ledger = NonceLedger::with_limits(0, Duration::from_secs(60));
        assert_eq!(ledger.capacity(), 1);
        let now = Instant::now();
        assert_eq!(ledger.admit("one", now), Admission::Fresh);
        assert_eq!(ledger.admit("one", now), Admission::Replay);
    }

    #[test]
    fn a_token_round_trips_through_hex_and_never_prints_itself() {
        let token = NodeToken::from_bytes([0xabu8; TOKEN_LEN]);
        let hex = token.to_hex();
        assert_eq!(hex.len(), TOKEN_LEN * 2);
        assert_eq!(NodeToken::from_hex(&hex).expect("parse"), token);
        assert_eq!(NodeToken::from_hex(&format!("  {hex}\n")).expect("trims"), token);

        let rendered = format!("{token:?}");
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(!rendered.contains("ab"), "{rendered}");
    }

    #[test]
    fn a_truncated_or_malformed_token_is_refused_rather_than_padded() {
        for text in ["", "ab", &"ab".repeat(TOKEN_LEN - 1), &"ab".repeat(TOKEN_LEN + 1), "zz", "abc"] {
            assert_eq!(NodeToken::from_hex(text).unwrap_err(), EnrollError::MalformedToken, "{text:?}");
        }
        // Uppercase hex is refused: our own writer never produces it.
        assert_eq!(NodeToken::from_hex(&"AB".repeat(TOKEN_LEN)).unwrap_err(), EnrollError::MalformedToken);
    }

    #[test]
    fn a_proof_round_trips_through_hex() {
        let proof = binding().prove(&token());
        assert_eq!(Proof::from_hex(&proof.to_hex()).expect("parse"), proof);
        assert_eq!(Proof::from_hex("").unwrap_err(), EnrollError::MalformedProof);
        assert_eq!(Proof::from_hex("00").unwrap_err(), EnrollError::MalformedProof);
        assert_eq!(Proof::from_hex(&"gg".repeat(PROOF_LEN)).unwrap_err(), EnrollError::MalformedProof);
    }

    #[test]
    fn generated_tokens_are_full_length_and_not_all_the_same() {
        let first = NodeToken::generate().expect("entropy");
        let second = NodeToken::generate().expect("entropy");
        assert_eq!(first.to_hex().len(), TOKEN_LEN * 2);
        assert_ne!(first, second);
    }

    #[test]
    fn arbitrary_hex_input_never_panics() {
        let mut state = 0x0bad_c0de_1234_5678u64;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state % 80) as usize;
            let text: String = (0..len).map(|index| char::from((state >> (index % 8 * 8)) as u8)).collect();
            let _ = NodeToken::from_hex(&text);
            let _ = Proof::from_hex(&text);
            let _ = Binding::new(&text, ACCEPT, node("n"));
        }
    }

    #[test]
    fn errors_render_something_an_operator_can_act_on() {
        assert!(EnrollError::MalformedToken.to_string().contains("64"));
        assert!(EnrollError::MalformedProof.to_string().contains("64"));
        assert!(
            EnrollError::BadHandshakeField { field: "sec-websocket-key" }
                .to_string()
                .contains("sec-websocket-key")
        );
        assert!(EnrollError::NoEntropy.to_string().contains("random"));
    }
}
