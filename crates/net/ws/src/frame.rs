//! The frame codec: bytes in, one frame out, and never a panic.
//!
//! This module is shaped deliberately after `selfhost_http::chunked`, and for the
//! same reason. Framing is where protocols get smuggled through, and framing is
//! the only part of a protocol that must cope with the input arriving in pieces
//! chosen by the sender. Both problems are solved by the same discipline: the
//! decoder is a **total function over a byte slice** with no socket anywhere near
//! it, [`ProtocolError::Incomplete`] is how it says *read more and call me
//! again*, and every arithmetic step that touches a length the peer chose is
//! checked. What that buys is the ability to test the dangerous cases
//! exhaustively — a declared length of `u64::MAX`, a reserved bit, a masked
//! server frame, a fragmented ping — with a table of byte strings and no
//! networking at all.
//!
//! # Why totality is not a matter of taste here
//!
//! The release profile sets `panic = "abort"`. There is no unwinding, no task
//! that dies alone, and no `catch_unwind` anywhere in this repository. A slice
//! index that goes one past the end in this file does not corrupt a session — it
//! terminates the process that is also serving 80 and 443, delivering mail,
//! renewing certificates, answering DNS and supervising every service on the box.
//! A remote desktop stream is fed by whoever is on the other end of it, which is
//! why this file indexes nothing without having first proved the byte is there,
//! sizes no buffer from a number it has not bounded, and adds nothing without
//! `checked_add`. The fuzz-shaped test at the bottom is not decoration; it is the
//! property this module exists to hold.
//!
//! # What is refused, and what that refusal buys
//!
//! - **Text frames** (opcode `0x1`) are refused on receipt and never sent. This
//!   is why there is no UTF-8 validator anywhere in this crate or above it: the
//!   only payloads that reach a caller are opaque bytes, and the one place the
//!   protocol insists on text — a close reason — is converted lossily and logged,
//!   never interpreted.
//! - **Any RSV bit** is a protocol error. No extension was negotiated, so no
//!   extension may set a bit; this is exactly how `permessage-deflate` is refused
//!   by omission, and it means a compressed frame is a clean close rather than a
//!   decompression bomb.
//! - **Wrong masking direction.** A client that fails to mask, or a server that
//!   masks, is refused. Masking is not a security measure between us and the peer
//!   — the key travels in the frame — it exists so that a hostile page cannot
//!   steer a *cache or proxy* into interpreting attacker-chosen bytes as a
//!   request. Enforcing the direction is what keeps that property real.
//! - **Non-minimal lengths.** A 200-byte payload declared through the 64-bit form
//!   is legal-looking and forbidden by RFC 6455 §5.2, and accepting it means two
//!   encodings of the same frame — which is the shape of every framing
//!   disagreement between two implementations that ever became a vulnerability.

use crate::limits::Limits;
use std::fmt;

/// The frame kinds this implementation speaks.
///
/// Text is deliberately absent from this enum rather than present and rejected
/// later: making it unrepresentable means no code above can be written that
/// forgets to handle it, and the single refusal lives in [`Opcode::classify`]
/// where it is tested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    /// A continuation of the message the previous non-final data frame began.
    Continuation,
    /// Application data. The only data opcode this stack ever sends or accepts.
    Binary,
    /// The peer is closing, with an optional code and reason.
    Close,
    /// A liveness probe that must be answered with a matching [`Opcode::Pong`].
    Ping,
    /// The answer to a ping, carrying its payload back unchanged.
    Pong,
}

impl Opcode {
    /// Interprets the low four bits of a frame's first byte.
    ///
    /// Returns [`ProtocolError::TextFrame`] for `0x1` specifically, because that
    /// is a legal frame we choose not to speak and the distinction is worth
    /// having in a log; every other unassigned value is a peer that is not
    /// speaking this protocol at all.
    fn classify(bits: u8) -> Result<Self, ProtocolError> {
        match bits {
            0x0 => Ok(Self::Continuation),
            0x1 => Err(ProtocolError::TextFrame),
            0x2 => Ok(Self::Binary),
            0x8 => Ok(Self::Close),
            0x9 => Ok(Self::Ping),
            0xA => Ok(Self::Pong),
            other => Err(ProtocolError::ReservedOpcode(other)),
        }
    }

    /// The four bits this opcode occupies on the wire.
    pub fn bits(self) -> u8 {
        match self {
            Self::Continuation => 0x0,
            Self::Binary => 0x2,
            Self::Close => 0x8,
            Self::Ping => 0x9,
            Self::Pong => 0xA,
        }
    }

    /// Whether this is a control frame.
    ///
    /// Control frames may be injected between the fragments of a data message,
    /// must never themselves be fragmented, and may carry at most 125 bytes —
    /// three rules that exist together so that a peer can always answer a ping
    /// promptly without waiting for a large message to finish.
    pub fn is_control(self) -> bool {
        matches!(self, Self::Close | Self::Ping | Self::Pong)
    }
}

/// Which side of the connection *we* are, which decides who must mask.
///
/// RFC 6455 §5.1 is asymmetric: a client masks every frame it sends and a server
/// masks none. Passing our own role rather than "expect a mask" keeps the
/// reasoning at the call site in the terms the specification uses, so a reader
/// checking the rule does not have to invert it in their head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// We accepted the connection, so incoming frames come from a client and
    /// **must** be masked; the frames we send **must not** be.
    Server,
    /// We opened the connection, so incoming frames come from a server and
    /// **must not** be masked; the frames we send **must** be.
    Client,
}

/// One decoded frame, with its payload already unmasked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Whether this frame completes its message.
    pub fin: bool,
    /// What kind of frame this is.
    pub opcode: Opcode,
    /// The payload, unmasked. Never longer than `Limits::max_frame`.
    pub payload: Vec<u8>,
}

/// A successfully decoded frame and how many bytes of the input it consumed.
///
/// The count is the caller's cue to drain its read buffer, in the same shape
/// `selfhost_http::request::Parsed` uses for a request head: the decoder never
/// owns the buffer, so it reports what it used rather than mutating anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedFrame {
    /// The frame.
    pub frame: Frame,
    /// Bytes of the input the frame occupied, header and payload together.
    pub consumed: usize,
}

/// Why a frame, a message, or a close body could not be accepted.
///
/// One enum for the whole protocol layer rather than one per module, because
/// every variant ends the same way — a close frame with a code and a log line —
/// and [`crate::close::code_for`] is the single place that maps a failure to that
/// code. Splitting them would mean either several mappings or a conversion that
/// exists only to be flattened again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    /// More bytes are needed before a decision can be made. Not a failure: the
    /// caller reads more and calls again, exactly as with a chunked body.
    Incomplete,
    /// A reserved bit was set, which means an extension we never negotiated.
    ReservedBitSet,
    /// A text frame arrived. Legal in the protocol, refused by this stack.
    TextFrame,
    /// An opcode that RFC 6455 does not assign.
    ReservedOpcode(u8),
    /// A client frame arrived unmasked.
    UnmaskedClientFrame,
    /// A server frame arrived masked.
    MaskedServerFrame,
    /// A control frame had `FIN = 0`.
    FragmentedControlFrame,
    /// A control frame's 7-bit length field exceeded 125, which is either an
    /// over-long payload or the extended length form — both forbidden for a
    /// control frame, and both refusable from the second byte alone.
    ControlFrameTooLarge(u64),
    /// A length used a wider form than it needed, which is two encodings of one
    /// frame and forbidden by RFC 6455 §5.2.
    NonMinimalLength,
    /// A 64-bit length had its high bit set, which the specification forbids.
    LengthHighBitSet,
    /// A frame declared more payload than `Limits::max_frame` permits.
    FrameTooLarge(u64),
    /// A message grew past `Limits::max_message` during reassembly.
    MessageTooLarge(usize),
    /// A message was split into more fragments than `Limits::max_fragments`.
    TooManyFragments(usize),
    /// A continuation arrived with no message in progress.
    UnexpectedContinuation,
    /// A new data frame arrived while a fragmented message was still open.
    InterleavedDataFrame,
    /// A control frame was handed to the reassembler, which only takes data.
    ControlFrameNotAMessage,
    /// A close body carried one byte, which can be neither a code nor nothing.
    TruncatedCloseBody,
    /// A close code the specification forbids on the wire.
    ReservedCloseCode(u16),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete => write!(f, "incomplete frame"),
            Self::ReservedBitSet => write!(f, "reserved bit set, but no extension was negotiated"),
            Self::TextFrame => write!(f, "text frames are not accepted; this stack speaks binary only"),
            Self::ReservedOpcode(code) => write!(f, "reserved opcode 0x{code:x}"),
            Self::UnmaskedClientFrame => write!(f, "client frame was not masked"),
            Self::MaskedServerFrame => write!(f, "server frame was masked"),
            Self::FragmentedControlFrame => write!(f, "control frame had FIN = 0"),
            Self::ControlFrameTooLarge(field) => {
                write!(f, "control frame length field was {field}, over the 125 a control payload may be")
            }
            Self::NonMinimalLength => write!(f, "length used a wider form than it needed"),
            Self::LengthHighBitSet => write!(f, "64-bit length had its high bit set"),
            Self::FrameTooLarge(length) => write!(f, "frame declared {length} bytes, over the frame ceiling"),
            Self::MessageTooLarge(length) => write!(f, "message reached {length} bytes, over the message ceiling"),
            Self::TooManyFragments(count) => write!(f, "message split into {count} fragments"),
            Self::UnexpectedContinuation => write!(f, "continuation with no message in progress"),
            Self::InterleavedDataFrame => write!(f, "new data frame while a fragmented message was open"),
            Self::ControlFrameNotAMessage => write!(f, "control frame handed to the reassembler"),
            Self::TruncatedCloseBody => write!(f, "close body of one byte is neither a code nor empty"),
            Self::ReservedCloseCode(code) => write!(f, "close code {code} may not appear on the wire"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// The largest payload a control frame may carry (RFC 6455 §5.5).
const MAX_CONTROL_PAYLOAD: u64 = 125;

/// The largest payload the 7-bit length form can express.
const SEVEN_BIT_MAX: u64 = 125;

/// The largest payload the 16-bit length form can express.
const SIXTEEN_BIT_MAX: u64 = u16::MAX as u64;

/// Decodes one frame from the front of `input`.
///
/// `role` is **our** role, which decides which masking direction is legal;
/// `limits` bounds the payload we are willing to buffer. Returns
/// [`ProtocolError::Incomplete`] when the frame has not fully arrived, which a
/// streaming caller answers by reading more and calling again with a longer
/// slice. Every other error is fatal to the connection: the framing is either
/// hostile or broken, and there is no resynchronisation point in a stream of
/// self-delimiting frames, so the only correct response is to close.
///
/// The order of the checks is load-bearing. Everything that can be decided from
/// the first two bytes — reserved bits, opcode, masking direction, and a control
/// frame that is too large or fragmented — is decided before any length is
/// assembled, and the declared length is compared against `limits.max_frame`
/// **before** the input is measured against it. A peer therefore cannot make us
/// wait for, or size a buffer for, a payload we were always going to refuse.
pub fn parse(input: &[u8], role: Role, limits: &Limits) -> Result<ParsedFrame, ProtocolError> {
    let (&first, &second) = match input {
        [first, second, ..] => (first, second),
        _ => return Err(ProtocolError::Incomplete),
    };

    if first & 0x70 != 0 {
        return Err(ProtocolError::ReservedBitSet);
    }
    let fin = first & 0x80 != 0;
    let opcode = Opcode::classify(first & 0x0f)?;

    let masked = second & 0x80 != 0;
    match (role, masked) {
        (Role::Server, false) => return Err(ProtocolError::UnmaskedClientFrame),
        (Role::Client, true) => return Err(ProtocolError::MaskedServerFrame),
        _ => {}
    }

    let short_length = u64::from(second & 0x7f);
    if opcode.is_control() {
        if !fin {
            return Err(ProtocolError::FragmentedControlFrame);
        }
        if short_length > MAX_CONTROL_PAYLOAD {
            return Err(ProtocolError::ControlFrameTooLarge(short_length));
        }
    }

    let (declared, header_length) = extended_length(input, short_length)?;
    let payload_length = bounded_payload_length(declared, limits)?;

    let mask_length = if masked { 4 } else { 0 };
    let total = header_length
        .checked_add(mask_length)
        .and_then(|prefix| prefix.checked_add(payload_length))
        .ok_or(ProtocolError::FrameTooLarge(declared))?;
    if input.len() < total {
        return Err(ProtocolError::Incomplete);
    }

    let payload_start = header_length + mask_length;
    let mut payload = input[payload_start..total].to_vec();
    if masked {
        let key = [
            input[header_length],
            input[header_length + 1],
            input[header_length + 2],
            input[header_length + 3],
        ];
        unmask(&mut payload, key);
    }

    Ok(ParsedFrame { frame: Frame { fin, opcode, payload }, consumed: total })
}

/// Resolves the payload length and the number of header bytes it occupied.
///
/// The three forms are not interchangeable: RFC 6455 §5.2 requires the shortest
/// one that fits, so a length inside a wider form is refused rather than
/// accepted, and a 64-bit length with its high bit set is refused outright
/// because the specification reserves that bit as zero. Both refusals exist for
/// the same reason — one frame must have exactly one encoding, or two
/// implementations can disagree about where it ends.
fn extended_length(input: &[u8], short_length: u64) -> Result<(u64, usize), ProtocolError> {
    match short_length {
        126 => {
            let bytes = input.get(2..4).ok_or(ProtocolError::Incomplete)?;
            let length = u64::from(u16::from_be_bytes([bytes[0], bytes[1]]));
            if length <= SEVEN_BIT_MAX {
                return Err(ProtocolError::NonMinimalLength);
            }
            Ok((length, 4))
        }
        127 => {
            let bytes = input.get(2..10).ok_or(ProtocolError::Incomplete)?;
            let mut wide = [0u8; 8];
            wide.copy_from_slice(bytes);
            let length = u64::from_be_bytes(wide);
            if length & 0x8000_0000_0000_0000 != 0 {
                return Err(ProtocolError::LengthHighBitSet);
            }
            if length <= SIXTEEN_BIT_MAX {
                return Err(ProtocolError::NonMinimalLength);
            }
            Ok((length, 10))
        }
        short => Ok((short, 2)),
    }
}

/// Turns a declared 64-bit length into a `usize` we are willing to buffer.
///
/// The ceiling is applied to the *declared* value, so the refusal happens on a
/// number rather than on bytes we have already accepted, and the conversion to
/// `usize` happens only after the ceiling has proved the value small — which
/// also makes this correct on a 32-bit target, where a legal 5 GiB frame would
/// otherwise be a silent truncation.
fn bounded_payload_length(declared: u64, limits: &Limits) -> Result<usize, ProtocolError> {
    if declared > limits.max_frame as u64 {
        return Err(ProtocolError::FrameTooLarge(declared));
    }
    usize::try_from(declared).map_err(|_| ProtocolError::FrameTooLarge(declared))
}

/// Applies a masking key in place.
///
/// The key repeats every four bytes from the start of the payload, so the index
/// is taken modulo four rather than tracked; there is no arithmetic here that can
/// overflow and no index that can leave the key.
fn unmask(payload: &mut [u8], key: [u8; 4]) {
    for (offset, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[offset % 4];
    }
}

/// Appends one encoded frame to `out`.
///
/// `mask` is `None` for a server, which is the only way this crate is used in the
/// daemon, and `Some(key)` for a client — the tests use it to speak as a browser
/// does, and it is the same code path a future outbound dialler would take. The
/// length form is always the shortest that fits, so a frame this function writes
/// is one our own parser accepts; that round trip is a property test below rather
/// than an assumption.
pub fn encode(out: &mut Vec<u8>, fin: bool, opcode: Opcode, payload: &[u8], mask: Option<[u8; 4]>) {
    let first = if fin { 0x80 } else { 0 } | opcode.bits();
    out.push(first);

    let mask_bit = if mask.is_some() { 0x80 } else { 0 };
    let length = payload.len() as u64;
    if length <= SEVEN_BIT_MAX {
        out.push(mask_bit | length as u8);
    } else if length <= SIXTEEN_BIT_MAX {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(length as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&length.to_be_bytes());
    }

    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            let start = out.len();
            out.extend_from_slice(payload);
            unmask(&mut out[start..], key);
        }
        None => out.extend_from_slice(payload),
    }
}

/// Reassembles fragmented data frames into whole messages.
///
/// Kept pure and separate from the reader for the reason the whole crate is
/// arranged this way: the interesting failures here are sequences, not bytes — a
/// continuation with nothing open, a second message begun before the first
/// finished, a peer that never sets `FIN` — and a sequence is far easier to write
/// as a test than to provoke over a socket.
///
/// Control frames never enter here. They may legally appear *between* fragments,
/// and interleaving them into the buffer would corrupt the message; the reader
/// answers them directly and passes only data frames to [`Assembler::accept`].
#[derive(Debug)]
pub struct Assembler {
    limits: Limits,
    buffer: Vec<u8>,
    fragments: usize,
    open: bool,
}

impl Assembler {
    /// A reassembler that enforces `limits`.
    pub fn new(limits: Limits) -> Self {
        Self { limits, buffer: Vec::new(), fragments: 0, open: false }
    }

    /// Whether a fragmented message is currently half-delivered.
    ///
    /// The reader uses this to refuse a close that arrives mid-message with the
    /// message silently discarded, and a test uses it to prove the assembler
    /// really did let go of its buffer.
    pub fn in_progress(&self) -> bool {
        self.open
    }

    /// Offers one **data** frame, returning the message when it completes.
    ///
    /// `Ok(None)` means the frame was a fragment and more are expected. The two
    /// ceilings are checked as the message grows rather than at the end, because
    /// a check at the end is a check that happens after the memory has already
    /// been spent.
    ///
    /// **Every refusal leaves the assembler idle.** That guarantee is structural
    /// rather than remembered: the decision is made in the private `offer` below
    /// and this wrapper resets on any `Err` it returns, so a refusal added later
    /// cannot forget to do it. It matters because the alternative is a message
    /// that was refused but left open, whose next continuation frame would be
    /// accepted and glued onto the tail of bytes we had already decided not to
    /// deliver — a caller that chose to keep the connection alive after a
    /// protocol error would then receive one message assembled from two.
    pub fn accept(&mut self, frame: Frame) -> Result<Option<Vec<u8>>, ProtocolError> {
        let outcome = self.offer(frame);
        if outcome.is_err() {
            self.reset();
        }
        outcome
    }

    /// The reassembly decision itself, with no responsibility for cleaning up.
    ///
    /// Separated from [`Assembler::accept`] purely so that "reset on every
    /// refusal" is written once, at the one place every `Err` passes through,
    /// instead of being repeated at each `return` and eventually missed at one of
    /// them — which is exactly how three of the five refusals came to skip it.
    fn offer(&mut self, frame: Frame) -> Result<Option<Vec<u8>>, ProtocolError> {
        if frame.opcode.is_control() {
            return Err(ProtocolError::ControlFrameNotAMessage);
        }
        match (frame.opcode, self.open) {
            (Opcode::Continuation, false) => return Err(ProtocolError::UnexpectedContinuation),
            (Opcode::Binary, true) => return Err(ProtocolError::InterleavedDataFrame),
            _ => {}
        }

        // The one addition in this module that could overflow, and it can only do
        // so when `max_fragments` is `usize::MAX` — a limit no configuration
        // produces, and still not one this file is willing to add without a
        // check, because under `panic = "abort"` an arithmetic overflow here is
        // the whole box rather than one stream.
        let fragments = self
            .fragments
            .checked_add(1)
            .ok_or(ProtocolError::TooManyFragments(usize::MAX))?;
        if fragments > self.limits.max_fragments {
            return Err(ProtocolError::TooManyFragments(fragments));
        }
        let total = self
            .buffer
            .len()
            .checked_add(frame.payload.len())
            .ok_or(ProtocolError::MessageTooLarge(usize::MAX))?;
        if total > self.limits.max_message {
            return Err(ProtocolError::MessageTooLarge(total));
        }

        self.fragments = fragments;
        self.buffer.extend_from_slice(&frame.payload);
        if frame.fin {
            let message = std::mem::take(&mut self.buffer);
            self.reset();
            Ok(Some(message))
        } else {
            self.open = true;
            Ok(None)
        }
    }

    /// Drops any half-delivered message and returns to the idle state.
    ///
    /// Called on completion and, by [`Assembler::accept`], on every refusal — so
    /// a stream that survives an error, which today it never does but a future
    /// caller might choose to, cannot find the tail of a refused message glued to
    /// the front of the next.
    pub fn reset(&mut self) {
        self.buffer = Vec::new();
        self.fragments = 0;
        self.open = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mask key the tests speak as a client with. Any value works; a fixed
    /// one keeps failures reproducible.
    const KEY: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];

    fn client_frame(fin: bool, opcode: Opcode, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        encode(&mut out, fin, opcode, payload, Some(KEY));
        out
    }

    fn parse_from_client(bytes: &[u8]) -> Result<ParsedFrame, ProtocolError> {
        parse(bytes, Role::Server, &Limits::default())
    }

    #[test]
    fn a_masked_binary_frame_round_trips() {
        let raw = client_frame(true, Opcode::Binary, b"hello");
        let parsed = parse_from_client(&raw).expect("parse");
        assert_eq!(parsed.consumed, raw.len());
        assert!(parsed.frame.fin);
        assert_eq!(parsed.frame.opcode, Opcode::Binary);
        assert_eq!(parsed.frame.payload, b"hello");
    }

    #[test]
    fn an_empty_payload_is_a_frame_like_any_other() {
        let raw = client_frame(true, Opcode::Binary, b"");
        let parsed = parse_from_client(&raw).expect("parse");
        assert!(parsed.frame.payload.is_empty());
        assert_eq!(parsed.consumed, 6, "two header bytes and four mask bytes");
    }

    #[test]
    fn a_frame_arriving_one_byte_at_a_time_is_incomplete_until_it_is_not() {
        let raw = client_frame(true, Opcode::Binary, b"the whole message");
        for prefix in 0..raw.len() {
            assert_eq!(
                parse_from_client(&raw[..prefix]),
                Err(ProtocolError::Incomplete),
                "prefix of {prefix} bytes should be incomplete"
            );
        }
        assert!(parse_from_client(&raw).is_ok());
    }

    #[test]
    fn trailing_bytes_after_a_frame_are_left_for_the_next_call() {
        let mut raw = client_frame(true, Opcode::Binary, b"first");
        let boundary = raw.len();
        raw.extend_from_slice(&client_frame(true, Opcode::Binary, b"second"));
        let parsed = parse_from_client(&raw).expect("parse");
        assert_eq!(parsed.consumed, boundary);
        let next = parse_from_client(&raw[parsed.consumed..]).expect("parse");
        assert_eq!(next.frame.payload, b"second");
    }

    // ---- the three length forms --------------------------------------------

    #[test]
    fn all_three_length_forms_decode_to_the_length_they_declare() {
        for length in [0usize, 1, 125, 126, 200, 65_535, 65_536, 200_000] {
            let payload = vec![0x5a; length];
            let raw = client_frame(true, Opcode::Binary, &payload);
            let parsed = parse_from_client(&raw).unwrap_or_else(|error| panic!("length {length}: {error}"));
            assert_eq!(parsed.frame.payload.len(), length);
            assert_eq!(parsed.consumed, raw.len());
        }
    }

    #[test]
    fn the_encoder_picks_the_shortest_length_form() {
        assert_eq!(client_frame(true, Opcode::Binary, &[0; 125])[1] & 0x7f, 125);
        assert_eq!(client_frame(true, Opcode::Binary, &[0; 126])[1] & 0x7f, 126);
        assert_eq!(client_frame(true, Opcode::Binary, &vec![0; 65_536])[1] & 0x7f, 127);
    }

    #[test]
    fn a_sixteen_bit_length_inside_the_seven_bit_range_is_refused() {
        // 0x82 0xFE 0x00 0x05: a five-byte payload declared through the wide form.
        let raw = [0x82, 0xfe, 0x00, 0x05, KEY[0], KEY[1], KEY[2], KEY[3], 0, 0, 0, 0, 0];
        assert_eq!(parse_from_client(&raw), Err(ProtocolError::NonMinimalLength));
    }

    #[test]
    fn a_sixty_four_bit_length_inside_the_sixteen_bit_range_is_refused() {
        let mut raw = vec![0x82, 0xff];
        raw.extend_from_slice(&1024u64.to_be_bytes());
        raw.extend_from_slice(&KEY);
        assert_eq!(parse_from_client(&raw), Err(ProtocolError::NonMinimalLength));
    }

    #[test]
    fn a_sixty_four_bit_length_with_the_high_bit_set_is_a_protocol_error() {
        let mut raw = vec![0x82, 0xff];
        raw.extend_from_slice(&u64::MAX.to_be_bytes());
        raw.extend_from_slice(&KEY);
        assert_eq!(parse_from_client(&raw), Err(ProtocolError::LengthHighBitSet));
    }

    #[test]
    fn a_length_over_the_ceiling_is_refused_before_a_byte_of_it_is_read() {
        let mut raw = vec![0x82, 0xff];
        raw.extend_from_slice(&(64u64 * 1024 * 1024).to_be_bytes());
        raw.extend_from_slice(&KEY);
        // Nothing of the payload has arrived, and the answer is still a refusal
        // rather than "read more" — that is the whole point.
        assert_eq!(parse_from_client(&raw), Err(ProtocolError::FrameTooLarge(64 * 1024 * 1024)));
    }

    #[test]
    fn the_frame_ceiling_is_exact_at_the_boundary() {
        let limits = Limits { max_frame: 1000, ..Limits::default() };
        let at = client_frame(true, Opcode::Binary, &vec![7; 1000]);
        assert!(parse(&at, Role::Server, &limits).is_ok());
        let over = client_frame(true, Opcode::Binary, &vec![7; 1001]);
        assert_eq!(parse(&over, Role::Server, &limits), Err(ProtocolError::FrameTooLarge(1001)));
    }

    // ---- the malformed-frame table -----------------------------------------

    #[test]
    fn the_malformed_frame_table_is_refused_and_never_panics() {
        let masked = [KEY[0], KEY[1], KEY[2], KEY[3]];
        let cases: &[(&str, Vec<u8>, ProtocolError)] = &[
            (
                "RSV1 set",
                [vec![0xc2, 0x80], masked.to_vec()].concat(),
                ProtocolError::ReservedBitSet,
            ),
            (
                "RSV2 set",
                [vec![0xa2, 0x80], masked.to_vec()].concat(),
                ProtocolError::ReservedBitSet,
            ),
            (
                "RSV3 set",
                [vec![0x92, 0x80], masked.to_vec()].concat(),
                ProtocolError::ReservedBitSet,
            ),
            (
                "a text frame",
                [vec![0x81, 0x80], masked.to_vec()].concat(),
                ProtocolError::TextFrame,
            ),
            (
                "a reserved data opcode",
                [vec![0x83, 0x80], masked.to_vec()].concat(),
                ProtocolError::ReservedOpcode(0x3),
            ),
            (
                "a reserved control opcode",
                [vec![0x8b, 0x80], masked.to_vec()].concat(),
                ProtocolError::ReservedOpcode(0xb),
            ),
            ("an unmasked client frame", vec![0x82, 0x00], ProtocolError::UnmaskedClientFrame),
            (
                "a fragmented ping",
                [vec![0x09, 0x80], masked.to_vec()].concat(),
                ProtocolError::FragmentedControlFrame,
            ),
            (
                "a fragmented close",
                [vec![0x08, 0x80], masked.to_vec()].concat(),
                ProtocolError::FragmentedControlFrame,
            ),
            (
                "a 126-byte ping",
                [vec![0x89, 0xfe, 0x00, 0x7e], masked.to_vec()].concat(),
                ProtocolError::ControlFrameTooLarge(126),
            ),
            (
                "a close frame with a 64-bit length",
                [vec![0x88, 0xff], masked.to_vec()].concat(),
                ProtocolError::ControlFrameTooLarge(127),
            ),
            (
                "a 64-bit length with the high bit set",
                [vec![0x82, 0xff], u64::MAX.to_be_bytes().to_vec(), masked.to_vec()].concat(),
                ProtocolError::LengthHighBitSet,
            ),
        ];

        for (name, bytes, expected) in cases {
            assert_eq!(parse_from_client(bytes), Err(expected.clone()), "case: {name}");
        }
    }

    #[test]
    fn a_masked_server_frame_is_refused() {
        let raw = client_frame(true, Opcode::Binary, b"hi");
        assert_eq!(
            parse(&raw, Role::Client, &Limits::default()),
            Err(ProtocolError::MaskedServerFrame)
        );
    }

    #[test]
    fn an_unmasked_server_frame_is_what_a_client_expects() {
        let mut raw = Vec::new();
        encode(&mut raw, true, Opcode::Binary, b"hi", None);
        let parsed = parse(&raw, Role::Client, &Limits::default()).expect("parse");
        assert_eq!(parsed.frame.payload, b"hi");
        // ...and the same bytes are refused when we are the server.
        assert_eq!(parse_from_client(&raw), Err(ProtocolError::UnmaskedClientFrame));
    }

    #[test]
    fn a_control_frame_of_exactly_125_bytes_is_accepted() {
        let raw = client_frame(true, Opcode::Ping, &[3; 125]);
        assert_eq!(parse_from_client(&raw).expect("parse").frame.payload.len(), 125);
    }

    // ---- reassembly ---------------------------------------------------------

    fn data(fin: bool, opcode: Opcode, payload: &[u8]) -> Frame {
        Frame { fin, opcode, payload: payload.to_vec() }
    }

    #[test]
    fn an_unfragmented_binary_frame_is_a_whole_message() {
        let mut assembler = Assembler::new(Limits::default());
        let message = assembler.accept(data(true, Opcode::Binary, b"whole")).expect("accept");
        assert_eq!(message.as_deref(), Some(&b"whole"[..]));
        assert!(!assembler.in_progress());
    }

    #[test]
    fn fragments_are_joined_in_order() {
        let mut assembler = Assembler::new(Limits::default());
        assert_eq!(assembler.accept(data(false, Opcode::Binary, b"one ")).expect("accept"), None);
        assert!(assembler.in_progress());
        assert_eq!(assembler.accept(data(false, Opcode::Continuation, b"two ")).expect("accept"), None);
        let message = assembler.accept(data(true, Opcode::Continuation, b"three")).expect("accept");
        assert_eq!(message.as_deref(), Some(&b"one two three"[..]));
        assert!(!assembler.in_progress());
    }

    #[test]
    fn a_continuation_with_nothing_open_is_refused() {
        let mut assembler = Assembler::new(Limits::default());
        assert_eq!(
            assembler.accept(data(true, Opcode::Continuation, b"orphan")),
            Err(ProtocolError::UnexpectedContinuation)
        );
    }

    #[test]
    fn a_second_message_begun_mid_message_is_refused() {
        let mut assembler = Assembler::new(Limits::default());
        assembler.accept(data(false, Opcode::Binary, b"first")).expect("accept");
        assert_eq!(
            assembler.accept(data(true, Opcode::Binary, b"interleaved")),
            Err(ProtocolError::InterleavedDataFrame)
        );
    }

    #[test]
    fn a_control_frame_is_never_reassembled() {
        let mut assembler = Assembler::new(Limits::default());
        assert_eq!(
            assembler.accept(data(true, Opcode::Ping, b"")),
            Err(ProtocolError::ControlFrameNotAMessage)
        );
    }

    #[test]
    fn too_many_fragments_are_refused_and_the_buffer_is_dropped() {
        let limits = Limits { max_fragments: 3, ..Limits::default() };
        let mut assembler = Assembler::new(limits);
        assembler.accept(data(false, Opcode::Binary, b"a")).expect("accept");
        assembler.accept(data(false, Opcode::Continuation, b"b")).expect("accept");
        assembler.accept(data(false, Opcode::Continuation, b"c")).expect("accept");
        assert_eq!(
            assembler.accept(data(false, Opcode::Continuation, b"d")),
            Err(ProtocolError::TooManyFragments(4))
        );
        assert!(!assembler.in_progress(), "a refused message leaves nothing behind");
    }

    #[test]
    fn every_refusal_leaves_the_assembler_idle() {
        // The contract on `reset` said this and the code did not: three of the
        // five refusals returned before resetting, so a refused message stayed
        // open and the next continuation was glued onto it.
        let interleaved = |assembler: &mut Assembler| {
            assembler.accept(data(false, Opcode::Binary, b"first")).expect("accept");
            assembler.accept(data(true, Opcode::Binary, b"second"))
        };
        let control = |assembler: &mut Assembler| {
            assembler.accept(data(false, Opcode::Binary, b"first")).expect("accept");
            assembler.accept(data(true, Opcode::Ping, b""))
        };
        let orphan = |assembler: &mut Assembler| assembler.accept(data(true, Opcode::Continuation, b"x"));

        for (name, refuse) in [
            ("a second message begun mid-message", &interleaved as &dyn Fn(&mut Assembler) -> _),
            ("a control frame handed to the reassembler", &control),
            ("a continuation with nothing open", &orphan),
        ] {
            let mut assembler = Assembler::new(Limits::default());
            assert!(refuse(&mut assembler).is_err(), "{name} must be refused");
            assert!(!assembler.in_progress(), "{name} left a message open");

            // And the concrete consequence: the next continuation must not be
            // accepted, because there is nothing for it to continue.
            assert_eq!(
                assembler.accept(data(true, Opcode::Continuation, b"tail")),
                Err(ProtocolError::UnexpectedContinuation),
                "{name} let a refused message absorb a continuation"
            );
        }
    }

    #[test]
    fn a_fragment_budget_of_the_whole_address_space_still_cannot_overflow() {
        // `max_fragments: usize::MAX` is not a configuration anyone writes, but
        // it is the one value for which the fragment counter's addition wraps —
        // and a wrap under `panic = "abort"` is not a bug report, it is an
        // outage. Reaching the boundary by feeding fragments is impossible, so
        // the counter is placed there directly.
        let limits = Limits { max_fragments: usize::MAX, max_message: usize::MAX, ..Limits::default() };
        let mut assembler = Assembler::new(limits);
        assembler.accept(data(false, Opcode::Binary, b"open")).expect("accept");
        assembler.fragments = usize::MAX;
        assert_eq!(
            assembler.accept(data(true, Opcode::Continuation, b"")),
            Err(ProtocolError::TooManyFragments(usize::MAX))
        );
        assert!(!assembler.in_progress());
    }

    #[test]
    fn a_message_over_the_byte_ceiling_is_refused_as_it_grows() {
        let limits = Limits { max_message: 8, max_frame: 8, ..Limits::default() };
        let mut assembler = Assembler::new(limits);
        assembler.accept(data(false, Opcode::Binary, b"12345")).expect("accept");
        assert_eq!(
            assembler.accept(data(true, Opcode::Continuation, b"6789")),
            Err(ProtocolError::MessageTooLarge(9))
        );
        assert!(!assembler.in_progress());
    }

    #[test]
    fn the_message_ceiling_is_exact_at_the_boundary() {
        let limits = Limits { max_message: 8, max_frame: 8, ..Limits::default() };
        let mut assembler = Assembler::new(limits);
        assembler.accept(data(false, Opcode::Binary, b"1234")).expect("accept");
        let message = assembler.accept(data(true, Opcode::Continuation, b"5678")).expect("accept");
        assert_eq!(message.as_deref(), Some(&b"12345678"[..]));
    }

    #[test]
    fn an_empty_final_fragment_completes_a_message() {
        let mut assembler = Assembler::new(Limits::default());
        assembler.accept(data(false, Opcode::Binary, b"body")).expect("accept");
        let message = assembler.accept(data(true, Opcode::Continuation, b"")).expect("accept");
        assert_eq!(message.as_deref(), Some(&b"body"[..]));
    }

    // ---- totality -----------------------------------------------------------

    /// A 64-bit xorshift, written here rather than depended on.
    ///
    /// The seed is fixed so a failure is reproducible: the same run produces the
    /// same ten thousand inputs on every machine, which is the difference between
    /// a fuzz test that reports a bug and one that reports a rumour.
    struct Xorshift(u64);

    impl Xorshift {
        fn next(&mut self) -> u64 {
            let mut state = self.0;
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            self.0 = state;
            state
        }

        fn byte(&mut self) -> u8 {
            (self.next() >> 24) as u8
        }
    }

    #[test]
    fn parse_never_panics_on_random_bytes() {
        let mut rng = Xorshift(0x5eed_1234_dead_beef);
        let limits = Limits::default();
        let mut refusals = 0usize;
        let mut successes = 0usize;
        let mut incompletes = 0usize;

        for _ in 0..10_000 {
            let length = (rng.next() % 300) as usize;
            let bytes: Vec<u8> = (0..length).map(|_| rng.byte()).collect();
            for role in [Role::Server, Role::Client] {
                match parse(&bytes, role, &limits) {
                    Ok(parsed) => {
                        assert!(parsed.consumed <= bytes.len(), "consumed past the end of the input");
                        successes += 1;
                    }
                    Err(ProtocolError::Incomplete) => incompletes += 1,
                    Err(_) => refusals += 1,
                }
            }
        }

        // Not an assertion about the parser so much as about the test: if the
        // generator drifted into producing only one outcome, the run would still
        // pass while proving nothing.
        assert!(successes > 0, "no random input ever parsed");
        assert!(refusals > 0, "no random input was ever refused");
        assert!(incompletes > 0, "no random input was ever incomplete");
    }

    #[test]
    fn parse_never_panics_on_mutated_valid_frames() {
        // Random bytes rarely reach the deeper paths; mutating a well-formed
        // frame does, because every prefix stays plausible for longer.
        let mut rng = Xorshift(0x0000_c0ff_ee00_1111);
        let limits = Limits::default();
        let base = client_frame(true, Opcode::Binary, &vec![0x2a; 300]);

        for _ in 0..10_000 {
            let mut bytes = base.clone();
            let flips = 1 + (rng.next() % 4) as usize;
            for _ in 0..flips {
                if bytes.is_empty() {
                    break;
                }
                let index = (rng.next() as usize) % bytes.len();
                bytes[index] ^= rng.byte();
            }
            let cut = (rng.next() as usize) % (bytes.len() + 1);
            bytes.truncate(cut);
            for role in [Role::Server, Role::Client] {
                let _ = parse(&bytes, role, &limits);
            }
        }
    }

    #[test]
    fn every_encoded_frame_parses_back_to_itself() {
        let mut rng = Xorshift(0x1357_9bdf_0246_8ace);
        for _ in 0..500 {
            let length = (rng.next() % 70_000) as usize;
            let payload: Vec<u8> = (0..length).map(|_| rng.byte()).collect();
            let fin = rng.next() & 1 == 0;
            let opcode = if fin { Opcode::Binary } else { Opcode::Continuation };

            let mut masked = Vec::new();
            let key = [rng.byte(), rng.byte(), rng.byte(), rng.byte()];
            encode(&mut masked, fin, opcode, &payload, Some(key));
            let parsed = parse(&masked, Role::Server, &Limits::default()).expect("masked round trip");
            assert_eq!(parsed.frame.payload, payload);
            assert_eq!(parsed.frame.fin, fin);
            assert_eq!(parsed.frame.opcode, opcode);

            let mut plain = Vec::new();
            encode(&mut plain, fin, opcode, &payload, None);
            let parsed = parse(&plain, Role::Client, &Limits::default()).expect("plain round trip");
            assert_eq!(parsed.frame.payload, payload);
        }
    }

    #[test]
    fn masking_is_its_own_inverse() {
        let mut rng = Xorshift(0x00ff_00ff_1234_5678);
        for _ in 0..200 {
            let length = (rng.next() % 40) as usize;
            let original: Vec<u8> = (0..length).map(|_| rng.byte()).collect();
            let key = [rng.byte(), rng.byte(), rng.byte(), rng.byte()];
            let mut buffer = original.clone();
            unmask(&mut buffer, key);
            unmask(&mut buffer, key);
            assert_eq!(buffer, original);
        }
    }
}
