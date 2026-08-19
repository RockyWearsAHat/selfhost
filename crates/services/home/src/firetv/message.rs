//! The ADB wire format: a 24-byte header, six commands, and the two integrity
//! fields a device checks before it reads a byte of payload.
//!
//! Every ADB message is a fixed header followed by an optional payload:
//!
//! ```text
//! offset  field         meaning
//!   0      command       one of the six four-letter codes, little-endian
//!   4      arg0          command-specific
//!   8      arg1          command-specific
//!  12      data_length   payload length in bytes
//!  16      data_check    sum of the payload bytes, mod 2^32
//!  20      magic         command XOR 0xffffffff, a cheap frame check
//! ```
//!
//! The checksum and the magic are not security — they are how a device rejects
//! a header that arrived torn or misaligned, and getting either wrong makes the
//! device drop the connection with no diagnostic, which is exactly the failure
//! a test against these bytes prevents. This module is pure: it builds and reads
//! headers and never touches a socket, so the framing can be proved without a
//! television.
//!
//! The connection is opened at protocol version `0x01000000`, which keeps the
//! checksum mandatory (the later `0x01000001` skips it). The connect banner
//! advertises no `shell_v2`, so an opened `shell:` stream carries raw command
//! output rather than the multiplexed shell protocol — the simplest thing that
//! works, and all a keyevent needs.

/// One of the four-letter codes, as the little-endian `u32` it travels as.
const fn code(bytes: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*bytes)
}

/// Connect: opens the transport. `arg0` is the version, `arg1` the maximum
/// payload the sender will accept.
pub const A_CNXN: u32 = code(b"CNXN");
/// Auth: a step of the challenge handshake. `arg0` is the [`AuthKind`].
pub const A_AUTH: u32 = code(b"AUTH");
/// Open: asks the device to open a stream to a destination, e.g. `shell:…`.
pub const A_OPEN: u32 = code(b"OPEN");
/// Okay: acknowledges a stream open or a write.
pub const A_OKAY: u32 = code(b"OKAY");
/// Close: tears a stream down.
pub const A_CLSE: u32 = code(b"CLSE");
/// Write: carries stream payload.
pub const A_WRTE: u32 = code(b"WRTE");

/// The protocol version this host connects as — the one that keeps the payload
/// checksum mandatory, so a device on either side of the checksum-skip change
/// is spoken to the same way.
pub const VERSION: u32 = 0x0100_0000;

/// The largest payload this host will accept in one message, advertised in the
/// connect. 256 KiB is ADB's own default and is never approached by the short
/// shell commands this driver sends.
pub const MAX_PAYLOAD: u32 = 256 * 1024;

/// The banner the connect carries: a host, no advertised features. Omitting
/// `shell_v2` is deliberate — it keeps an opened shell stream raw.
pub const CONNECT_BANNER: &[u8] = b"host::\0";

/// The three kinds of auth message, carried in an [`A_AUTH`] message's `arg0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    /// The device's challenge: a 20-byte token the host must sign.
    Token,
    /// The host's answer: the signature over the token.
    Signature,
    /// The host's public key, sent when no offered signature was recognised —
    /// this is what provokes the television's one-time "allow" dialog.
    PublicKey,
}

impl AuthKind {
    /// The number this kind travels as.
    #[must_use]
    pub fn as_u32(self) -> u32 {
        match self {
            AuthKind::Token => 1,
            AuthKind::Signature => 2,
            AuthKind::PublicKey => 3,
        }
    }

    /// Reads the number back, or `None` for a value ADB does not define.
    #[must_use]
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(AuthKind::Token),
            2 => Some(AuthKind::Signature),
            3 => Some(AuthKind::PublicKey),
            _ => None,
        }
    }
}

/// The fixed size of a message header.
pub const HEADER_LEN: usize = 24;

/// A parsed message: the header fields and the payload that followed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The command code.
    pub command: u32,
    /// The first argument, command-specific.
    pub arg0: u32,
    /// The second argument, command-specific.
    pub arg1: u32,
    /// The payload, already checked against the header's length and checksum.
    pub payload: Vec<u8>,
}

impl Message {
    /// A message with the given fields.
    #[must_use]
    pub fn new(command: u32, arg0: u32, arg1: u32, payload: Vec<u8>) -> Self {
        Message { command, arg0, arg1, payload }
    }

    /// The connect message that opens the transport.
    #[must_use]
    pub fn connect() -> Self {
        Message::new(A_CNXN, VERSION, MAX_PAYLOAD, CONNECT_BANNER.to_vec())
    }

    /// The auth message answering the challenge with a signature.
    #[must_use]
    pub fn auth_signature(signature: Vec<u8>) -> Self {
        Message::new(A_AUTH, AuthKind::Signature.as_u32(), 0, signature)
    }

    /// The auth message offering the host's public key.
    #[must_use]
    pub fn auth_public_key(key: Vec<u8>) -> Self {
        Message::new(A_AUTH, AuthKind::PublicKey.as_u32(), 0, key)
    }

    /// The open message asking for a stream to `destination` (e.g.
    /// `shell:input keyevent 26`), NUL-terminated as ADB requires. `local_id`
    /// is the host's non-zero handle for the stream.
    #[must_use]
    pub fn open(local_id: u32, destination: &str) -> Self {
        let mut payload = destination.as_bytes().to_vec();
        payload.push(0);
        Message::new(A_OPEN, local_id, 0, payload)
    }

    /// The okay acknowledging the peer's stream handle.
    #[must_use]
    pub fn okay(local_id: u32, remote_id: u32) -> Self {
        Message::new(A_OKAY, local_id, remote_id, Vec::new())
    }

    /// The close for a stream.
    #[must_use]
    pub fn close(local_id: u32, remote_id: u32) -> Self {
        Message::new(A_CLSE, local_id, remote_id, Vec::new())
    }

    /// The checksum a device recomputes over the payload before trusting it:
    /// the byte values summed, modulo 2^32.
    #[must_use]
    pub fn checksum(payload: &[u8]) -> u32 {
        payload.iter().fold(0_u32, |sum, &byte| sum.wrapping_add(u32::from(byte)))
    }

    /// The header's magic: the command with every bit flipped.
    #[must_use]
    fn magic(command: u32) -> u32 {
        command ^ 0xffff_ffff
    }

    /// Serialises the message: the 24-byte header, then the payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&self.command.to_le_bytes());
        out.extend_from_slice(&self.arg0.to_le_bytes());
        out.extend_from_slice(&self.arg1.to_le_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&Message::checksum(&self.payload).to_le_bytes());
        out.extend_from_slice(&Message::magic(self.command).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// The payload length a header declares, or `None` if the 24 bytes are not
    /// a valid header (short, or a failed magic check). The caller reads exactly
    /// that many payload bytes next, then hands them to [`Message::from_parts`].
    #[must_use]
    pub fn payload_len(header: &[u8]) -> Option<usize> {
        if header.len() < HEADER_LEN {
            return None;
        }
        let word = |offset: usize| {
            u32::from_le_bytes([
                header[offset],
                header[offset + 1],
                header[offset + 2],
                header[offset + 3],
            ])
        };
        let command = word(0);
        if word(20) != Message::magic(command) {
            return None; // a torn or misframed header
        }
        Some(word(12) as usize)
    }

    /// Assembles a message from a validated header and the payload that
    /// followed, rejecting a payload whose checksum does not match the header —
    /// the check a device does, done here so a caller never acts on a body that
    /// arrived corrupt.
    #[must_use]
    pub fn from_parts(header: &[u8], payload: Vec<u8>) -> Option<Self> {
        if header.len() < HEADER_LEN {
            return None;
        }
        let word = |offset: usize| {
            u32::from_le_bytes([
                header[offset],
                header[offset + 1],
                header[offset + 2],
                header[offset + 3],
            ])
        };
        let command = word(0);
        if word(20) != Message::magic(command) {
            return None;
        }
        if word(12) as usize != payload.len() {
            return None;
        }
        if word(16) != Message::checksum(&payload) {
            return None;
        }
        Some(Message::new(command, word(4), word(8), payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_codes_are_the_four_letters_little_endian() {
        assert_eq!(A_CNXN, 0x4e58_4e43);
        assert_eq!(A_AUTH, 0x4854_5541);
        assert_eq!(A_OPEN, 0x4e45_504f);
        assert_eq!(A_OKAY, 0x5941_4b4f);
        assert_eq!(A_CLSE, 0x4553_4c43);
        assert_eq!(A_WRTE, 0x4554_5257);
    }

    #[test]
    fn auth_kinds_round_trip() {
        for kind in [AuthKind::Token, AuthKind::Signature, AuthKind::PublicKey] {
            assert_eq!(AuthKind::from_u32(kind.as_u32()), Some(kind));
        }
        assert_eq!(AuthKind::from_u32(0), None);
        assert_eq!(AuthKind::from_u32(4), None);
    }

    #[test]
    fn the_checksum_is_the_byte_sum() {
        assert_eq!(Message::checksum(&[]), 0);
        assert_eq!(Message::checksum(&[1, 2, 3]), 6);
        assert_eq!(Message::checksum(&[0xff, 0xff]), 0x1fe);
    }

    #[test]
    fn a_connect_encodes_to_the_expected_header() {
        let bytes = Message::connect().encode();
        assert_eq!(&bytes[0..4], &A_CNXN.to_le_bytes());
        assert_eq!(&bytes[4..8], &VERSION.to_le_bytes());
        assert_eq!(&bytes[8..12], &MAX_PAYLOAD.to_le_bytes());
        assert_eq!(&bytes[12..16], &(CONNECT_BANNER.len() as u32).to_le_bytes());
        assert_eq!(&bytes[16..20], &Message::checksum(CONNECT_BANNER).to_le_bytes());
        assert_eq!(&bytes[20..24], &(A_CNXN ^ 0xffff_ffff).to_le_bytes());
        assert_eq!(&bytes[24..], CONNECT_BANNER);
    }

    #[test]
    fn an_open_carries_a_nul_terminated_destination() {
        let message = Message::open(7, "shell:input keyevent 26");
        assert_eq!(message.command, A_OPEN);
        assert_eq!(message.arg0, 7);
        assert_eq!(message.payload.last(), Some(&0));
        assert!(message.payload.starts_with(b"shell:input keyevent 26"));
    }

    /// The property the socket loop rests on: what `encode` writes, the header
    /// reader accepts and reconstructs exactly.
    #[test]
    fn a_message_round_trips_through_encode_and_parse() {
        let original = Message::auth_signature(vec![0xAB; 256]);
        let bytes = original.encode();
        let len = Message::payload_len(&bytes[..HEADER_LEN]).expect("a valid header");
        assert_eq!(len, 256);
        let payload = bytes[HEADER_LEN..HEADER_LEN + len].to_vec();
        let parsed = Message::from_parts(&bytes[..HEADER_LEN], payload).expect("a valid body");
        assert_eq!(parsed, original);
    }

    #[test]
    fn a_header_with_a_broken_magic_is_rejected() {
        let mut bytes = Message::connect().encode();
        bytes[20] ^= 0x01; // corrupt the magic
        assert_eq!(Message::payload_len(&bytes[..HEADER_LEN]), None);
    }

    #[test]
    fn a_payload_that_fails_its_checksum_is_rejected() {
        let bytes = Message::open(1, "shell:reboot").encode();
        let len = Message::payload_len(&bytes[..HEADER_LEN]).expect("a valid header");
        let mut payload = bytes[HEADER_LEN..HEADER_LEN + len].to_vec();
        payload[0] ^= 0xff; // corrupt a payload byte
        assert_eq!(Message::from_parts(&bytes[..HEADER_LEN], payload), None);
    }

    #[test]
    fn a_short_header_is_not_a_message() {
        assert_eq!(Message::payload_len(&[0; 10]), None);
        assert_eq!(Message::from_parts(&[0; 10], Vec::new()), None);
    }
}
