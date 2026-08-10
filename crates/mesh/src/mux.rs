//! The eight-byte frame header, and nothing else.
//!
//! One link carries many channels, because a peer link has to carry a desktop
//! session, a file transfer and a status feed at the same time without any of
//! them being able to starve the others. Every byte on that link is preceded by
//! this header:
//!
//! ```text
//! off  size  field
//!  0     1   version = 1
//!  1     1   kind
//!  2     2   channel      (0 = the link's own control channel)
//!  4     4   length       (payload bytes; at most MAX_PAYLOAD)
//! ```
//!
//! Big-endian, fixed width, no variable-length integers anywhere.
//!
//! # Why the layout is frozen, and why "improving" it would be a regression
//!
//! The fixed width is not a stylistic preference and it is not laziness about
//! compactness. It is an architectural consequence of `panic = "abort"` in the
//! release profile.
//!
//! The owner's daemon is a single process, and it is not a small one: it runs the
//! service supervisor, the authoritative DNS server, the firewall manager, the
//! mail server, the certificate store and the self-updater. When a worker's
//! desktop session is spliced through that daemon to a browser, the daemon
//! **forwards payloads it never interprets** — it reads eight bytes, rewrites a
//! two-byte channel id, and moves `length` bytes onward without looking at any of
//! them. That is only possible because the framing is decidable from a fixed
//! prefix with no state, no lookahead and no arithmetic that can be made to
//! overflow. All interpretation of attacker-influenced desktop bytes happens in
//! the agent — a separate process the daemon spawns, supervises, and can watch
//! die.
//!
//! A variable-length encoding — a varint length, a type-length-value payload
//! header, a self-describing serialisation — would move parsing of hostile bytes
//! into the daemon. Under `panic = "abort"` a single out-of-bounds index in that
//! parser is not a dropped connection: it is the box losing HTTP, HTTPS, DNS and
//! mail simultaneously, at a moment chosen by whoever is on the other end of the
//! link. So: **the header stays eight fixed bytes.** If a future change appears to
//! need more room, it belongs in the payload, which the daemon does not read, or
//! behind a version bump negotiated before any payload flows.
//!
//! # What this module refuses to know
//!
//! Only the header lives here. What an `OPEN` payload means, which channel ids a
//! side may allocate, and how many bytes a sender is allowed to have outstanding
//! are all decisions this module deliberately does not make — they live in
//! [`crate::channel`] and [`crate::credit`]. A parser that also knows the policy
//! is a parser whose policy cannot be tested without feeding it bytes.
//!
//! # Errors, never panics
//!
//! Every entry point here returns a typed error. Nothing indexes without a bounds
//! check, nothing casts a length without checking it first, and
//! [`FrameError::Incomplete`] carries the exact byte count still required so a
//! streaming reader can size its next read rather than guess. That is the same
//! contract `selfhost_http`'s chunked decoder offers, for the same reason.

use crate::channel::ChannelId;
use std::fmt;

/// The protocol version this implementation speaks.
///
/// Present in every header so that a peer running a future protocol is refused
/// with a precise error at the first frame, rather than being misread as a
/// corrupt version of this one.
pub const VERSION: u8 = 1;

/// The width of the header, in bytes. Frozen; see the module documentation.
pub const HEADER_LEN: usize = 8;

/// The largest complete frame, header included.
///
/// One mux frame must fit inside one WebSocket binary frame, and the WebSocket
/// layer's ceiling is 1 MiB. Sizing them identically means a mux frame can never
/// be the thing that forces a WebSocket message to be reassembled from
/// continuations in the daemon.
pub const MAX_FRAME: usize = 1 << 20;

/// The largest payload a single frame may carry.
///
/// [`MAX_FRAME`] less the header. Stated as its own constant because it is the
/// number every producer must respect and the number every parser enforces.
pub const MAX_PAYLOAD: usize = MAX_FRAME - HEADER_LEN;

/// What a frame is for.
///
/// A closed set: an unrecognised byte is [`FrameError::UnknownKind`], never a
/// frame that is forwarded on the assumption that someone downstream will
/// understand it. The payload shape each kind implies is documented here and
/// enforced in the module that owns that meaning, not in the header parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Kind {
    /// Request to open a channel: a one-byte service id and compact ASCII-JSON
    /// parameters. Sent on the channel being opened, never on channel 0's own
    /// behalf. Decoded by [`crate::channel::Open`].
    Open = 0x01,
    /// The peer agreed to the open. No payload.
    Accept = 0x02,
    /// The peer refused the open: a `u16` code and short prose. Decoded by
    /// [`crate::channel::Reject`].
    Reject = 0x03,
    /// Opaque channel data. This is the kind the daemon forwards without
    /// interpretation, and the only kind subject to credit.
    Data = 0x04,
    /// The channel is finished: a `u16` code. Decoded by
    /// [`crate::channel::Close`].
    Close = 0x05,
    /// Liveness probe carrying eight opaque bytes, echoed back verbatim.
    ///
    /// A WebSocket ping proves only the first hop. This proves the whole path,
    /// which is what lets the console show hop RTT and end-to-end RTT as two
    /// separate numbers so a slow session is attributable rather than merely
    /// slow.
    Echo = 0x06,
    /// The reply to an [`Kind::Echo`], carrying its eight bytes unchanged.
    Echoed = 0x07,
    /// A grant of `u32` further payload bytes the peer may send on this channel.
    /// Decoded by [`crate::credit::parse_grant`].
    Credit = 0x08,
}

impl Kind {
    /// Recognises a kind byte, or `None` if it is not one of ours.
    ///
    /// Deliberately not a `TryFrom` with a numeric range check: the mapping is
    /// written out so that adding a kind requires touching this table and the
    /// documentation above it together.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Open),
            0x02 => Some(Self::Accept),
            0x03 => Some(Self::Reject),
            0x04 => Some(Self::Data),
            0x05 => Some(Self::Close),
            0x06 => Some(Self::Echo),
            0x07 => Some(Self::Echoed),
            0x08 => Some(Self::Credit),
            _ => None,
        }
    }

    /// The byte this kind occupies in a header.
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// A short lowercase name, for logs and error prose.
    ///
    /// Separate from `Debug` because log lines are a stable operator-facing
    /// surface and `Debug` output is not.
    pub fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Accept => "accept",
            Self::Reject => "reject",
            Self::Data => "data",
            Self::Close => "close",
            Self::Echo => "echo",
            Self::Echoed => "echoed",
            Self::Credit => "credit",
        }
    }

    /// Whether this kind is only ever meaningful on the link's control channel.
    ///
    /// [`Kind::Echo`] and [`Kind::Echoed`] measure the *link*, so they ride
    /// channel 0; everything else names a channel. Stated here so that both the
    /// sender and the receiver read the rule from the same place.
    pub fn is_link_scoped(self) -> bool {
        matches!(self, Self::Echo | Self::Echoed)
    }
}

impl fmt::Display for Kind {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(self.name())
    }
}

/// Everything an eight-byte header says.
///
/// The version is not a field: [`Header::parse`] refuses anything but
/// [`VERSION`] and [`Header::encode`] always writes it, so a `Header` value
/// cannot exist that would encode to a version this build does not speak. The
/// length is likewise validated on the way in, so [`Header::payload_len`] is
/// infallible and cannot be larger than [`MAX_PAYLOAD`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// What the frame is for.
    pub kind: Kind,
    /// Which channel it belongs to; `0` is the link's own control channel.
    pub channel: ChannelId,
    /// How many payload bytes follow the header. Never exceeds [`MAX_PAYLOAD`].
    pub length: u32,
}

impl Header {
    /// Describes a frame about to be written.
    ///
    /// Fails rather than truncating when the payload is over the ceiling, because
    /// a silently truncated frame is a desynchronised link: the receiver would
    /// read the rest of the payload as the next header.
    pub fn new(kind: Kind, channel: ChannelId, payload_len: usize) -> Result<Self, FrameError> {
        if payload_len > MAX_PAYLOAD {
            return Err(FrameError::PayloadTooLong { length: payload_len });
        }
        // The cast cannot lose data: MAX_PAYLOAD is well under u32::MAX and the
        // comparison above has already rejected everything larger.
        let length = u32::try_from(payload_len).map_err(|_| FrameError::PayloadTooLong { length: payload_len })?;
        Ok(Self { kind, channel, length })
    }

    /// Reads a header from the first [`HEADER_LEN`] bytes of `input`.
    ///
    /// Trailing bytes are ignored — this reads a header, not a frame. Returns
    /// [`FrameError::Incomplete`] when fewer than eight bytes have arrived, which
    /// a streaming reader treats as "read more and call me again" rather than as
    /// a broken peer.
    pub fn parse(input: &[u8]) -> Result<Self, FrameError> {
        // `first_chunk` rather than a slice plus `try_into`: the array conversion
        // could only fail for a slice of the wrong length, which the slice form
        // has already made impossible, and an error arm that cannot be reached is
        // an error arm no test can cover and no reader can trust.
        let Some(head) = input.first_chunk::<HEADER_LEN>() else {
            return Err(FrameError::Incomplete { needed: HEADER_LEN });
        };

        let version = head[0];
        if version != VERSION {
            return Err(FrameError::UnsupportedVersion(version));
        }

        let kind = Kind::from_byte(head[1]).ok_or(FrameError::UnknownKind(head[1]))?;
        let channel = ChannelId::new(u16::from_be_bytes([head[2], head[3]]));
        let length = u32::from_be_bytes([head[4], head[5], head[6], head[7]]);

        if length as u64 > MAX_PAYLOAD as u64 {
            return Err(FrameError::TooLong { declared: length });
        }

        Ok(Self { kind, channel, length })
    }

    /// The eight bytes this header occupies on the wire.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let channel = self.channel.get().to_be_bytes();
        let length = self.length.to_be_bytes();
        [VERSION, self.kind.as_byte(), channel[0], channel[1], length[0], length[1], length[2], length[3]]
    }

    /// How many payload bytes follow, as a `usize`.
    ///
    /// Infallible because `length` was bounded by [`MAX_PAYLOAD`] when the header
    /// was constructed or parsed, and `MAX_PAYLOAD` fits in a `usize` on every
    /// target this project builds for.
    pub fn payload_len(&self) -> usize {
        self.length as usize
    }

    /// The total size of the frame this header introduces, header included.
    ///
    /// Cannot overflow: `payload_len() <= MAX_PAYLOAD` and
    /// `MAX_PAYLOAD + HEADER_LEN == MAX_FRAME`.
    pub fn frame_len(&self) -> usize {
        HEADER_LEN + self.payload_len()
    }
}

/// One complete frame, borrowing its payload from the caller's buffer.
///
/// Borrowed rather than owned so that the forwarding path — the one the module
/// documentation is about — can move bytes without copying them, and so that
/// "used the payload after the buffer was refilled" is a compile error.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// The frame's header.
    pub header: Header,
    /// Exactly `header.length` bytes.
    pub payload: &'a [u8],
}

impl fmt::Debug for Frame<'_> {
    /// Prints the header and the payload's *size*, never its contents.
    ///
    /// A `Frame` can carry a megabyte of somebody's screen; a derived `Debug`
    /// would put that in a log line the first time anyone debugged the router.
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("Frame")
            .field("kind", &self.header.kind.name())
            .field("channel", &self.header.channel.get())
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Reads one frame from the front of `input`, returning it and the bytes after it.
///
/// This is a *total* parser in the sense `selfhost_http`'s chunked decoder is:
/// every input is either a frame, a request for more bytes
/// ([`FrameError::Incomplete`], carrying exactly how many are needed in total),
/// or a typed refusal. It never panics, never indexes without a bounds check, and
/// never allocates.
///
/// Callers loop on this against a growing buffer, draining the returned remainder.
pub fn parse_frame(input: &[u8]) -> Result<(Frame<'_>, &[u8]), FrameError> {
    let header = Header::parse(input)?;
    let total = header.frame_len();
    if input.len() < total {
        return Err(FrameError::Incomplete { needed: total });
    }
    let payload = &input[HEADER_LEN..total];
    Ok((Frame { header, payload }, &input[total..]))
}

/// Appends one encoded frame to `out`.
///
/// Appends rather than allocating so that a writer can pack several frames into
/// one WebSocket message, and so the common path has no per-frame allocation.
/// Nothing is written when the payload is over the ceiling — the buffer is left
/// exactly as it was found, so a rejected frame cannot desynchronise a stream
/// that is still being built.
pub fn write_frame(out: &mut Vec<u8>, kind: Kind, channel: ChannelId, payload: &[u8]) -> Result<(), FrameError> {
    let header = Header::new(kind, channel, payload.len())?;
    append(out, header, payload);
    Ok(())
}

/// Encodes one frame into a fresh buffer.
///
/// The convenience form of [`write_frame`], for the control-plane frames that are
/// sent one at a time and are a few bytes long.
///
/// The header is built — and therefore the ceiling enforced — **before** the
/// buffer is reserved. Reserving first would mean an over-long payload allocated
/// the very memory the ceiling exists to refuse, which turns the check into an
/// error message with no effect: a caller passing a two-gigabyte slice would get
/// its refusal only after the allocation it was supposed to prevent.
pub fn encode_frame(kind: Kind, channel: ChannelId, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    let header = Header::new(kind, channel, payload.len())?;
    let mut out = Vec::with_capacity(header.frame_len());
    append(&mut out, header, payload);
    Ok(out)
}

/// Appends a validated header and the payload it describes.
///
/// Private, and takes the [`Header`] rather than the fields it was built from, so
/// that it is unreachable without having passed [`Header::new`] — the one place
/// the payload ceiling is enforced. `payload.len()` is the length the header
/// declares, because that is what the header was built from.
fn append(out: &mut Vec<u8>, header: Header, payload: &[u8]) {
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(payload);
}

/// Why a frame could not be read or written.
///
/// Every variant is recoverable in the sense that the process survives it; only
/// [`FrameError::Incomplete`] is recoverable in the sense that the *link*
/// survives it. Everything else means the peer is speaking something this build
/// does not, and the correct response is to close the link with a bare code and
/// log one line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Not all of the frame has arrived. `needed` is the total byte count the
    /// buffer must hold before retrying — the header alone at first, then the
    /// whole frame once the length is known — so a reader can ask the socket for
    /// the right amount instead of one byte at a time.
    Incomplete {
        /// Total bytes required in the buffer before this parse can succeed.
        needed: usize,
    },
    /// The version byte was not [`VERSION`].
    ///
    /// Carried rather than discarded so the log line can name the version the
    /// peer speaks, which is the whole diagnostic value of having the field.
    UnsupportedVersion(u8),
    /// The kind byte is not one this build knows.
    UnknownKind(u8),
    /// The declared length exceeds [`MAX_PAYLOAD`].
    ///
    /// Refused from the header alone, before a single payload byte is read and
    /// before anything is allocated on the strength of the number — which is the
    /// point of checking it here.
    TooLong {
        /// The length the peer declared.
        declared: u32,
    },
    /// A payload offered to the encoder exceeds [`MAX_PAYLOAD`]. Ours, not theirs.
    PayloadTooLong {
        /// The length the caller offered.
        length: usize,
    },
}

impl fmt::Display for FrameError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete { needed } => write!(out, "incomplete mux frame: {needed} bytes required"),
            Self::UnsupportedVersion(version) => {
                write!(out, "mux version {version} is not supported (this build speaks {VERSION})")
            }
            Self::UnknownKind(kind) => write!(out, "unknown mux frame kind 0x{kind:02x}"),
            Self::TooLong { declared } => {
                write!(out, "mux frame declares {declared} payload bytes, over the {MAX_PAYLOAD}-byte ceiling")
            }
            Self::PayloadTooLong { length } => {
                write!(out, "cannot encode a {length}-byte payload, over the {MAX_PAYLOAD}-byte ceiling")
            }
        }
    }
}

impl std::error::Error for FrameError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header for a `DATA` frame on channel 7 carrying `payload_len` bytes.
    fn head(payload_len: u32) -> [u8; HEADER_LEN] {
        let length = payload_len.to_be_bytes();
        [VERSION, Kind::Data.as_byte(), 0, 7, length[0], length[1], length[2], length[3]]
    }

    #[test]
    fn the_header_is_exactly_eight_bytes_in_the_documented_order() {
        // This test is the specification. If it is ever "fixed" to match the
        // code, the wire format has changed and every peer is now incompatible.
        let header = Header::new(Kind::Credit, ChannelId::new(0x0102), 4).expect("header");
        assert_eq!(header.encode(), [1, 0x08, 0x01, 0x02, 0, 0, 0, 4]);
    }

    #[test]
    fn round_trips_every_kind() {
        for kind in [
            Kind::Open,
            Kind::Accept,
            Kind::Reject,
            Kind::Data,
            Kind::Close,
            Kind::Echo,
            Kind::Echoed,
            Kind::Credit,
        ] {
            let payload = b"abcd";
            let bytes = encode_frame(kind, ChannelId::new(9), payload).expect("encode");
            let (frame, rest) = parse_frame(&bytes).expect("parse");
            assert_eq!(frame.header.kind, kind);
            assert_eq!(frame.header.channel.get(), 9);
            assert_eq!(frame.payload, payload);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn kind_bytes_are_the_documented_values() {
        assert_eq!(Kind::Open.as_byte(), 0x01);
        assert_eq!(Kind::Credit.as_byte(), 0x08);
        for byte in 0x01u8..=0x08 {
            assert_eq!(Kind::from_byte(byte).expect("known kind").as_byte(), byte);
        }
    }

    #[test]
    fn a_truncated_header_asks_for_the_rest_rather_than_panicking() {
        for taken in 0..HEADER_LEN {
            let bytes = head(0);
            assert_eq!(
                Header::parse(&bytes[..taken]),
                Err(FrameError::Incomplete { needed: HEADER_LEN }),
                "{taken} bytes"
            );
            assert!(matches!(
                parse_frame(&bytes[..taken]),
                Err(FrameError::Incomplete { needed: HEADER_LEN })
            ));
        }
    }

    #[test]
    fn a_truncated_payload_asks_for_the_whole_frame() {
        let mut bytes = head(16).to_vec();
        bytes.extend_from_slice(&[0u8; 10]);
        assert_eq!(parse_frame(&bytes).unwrap_err(), FrameError::Incomplete { needed: HEADER_LEN + 16 });
    }

    #[test]
    fn an_over_cap_length_is_refused_from_the_header_alone() {
        // Nothing has been read past the header and nothing has been allocated:
        // that is the property being asserted, not merely that it errors.
        let declared = u32::try_from(MAX_PAYLOAD).expect("fits") + 1;
        assert_eq!(Header::parse(&head(declared)), Err(FrameError::TooLong { declared }));
        assert_eq!(Header::parse(&head(u32::MAX)), Err(FrameError::TooLong { declared: u32::MAX }));
    }

    #[test]
    fn the_largest_legal_length_is_accepted() {
        let declared = u32::try_from(MAX_PAYLOAD).expect("fits");
        let header = Header::parse(&head(declared)).expect("at the ceiling");
        assert_eq!(header.payload_len(), MAX_PAYLOAD);
        assert_eq!(header.frame_len(), MAX_FRAME);
    }

    #[test]
    fn an_unknown_kind_is_refused_and_names_the_byte() {
        for byte in [0x00u8, 0x09, 0x0a, 0x7f, 0x80, 0xff] {
            let mut bytes = head(0);
            bytes[1] = byte;
            assert_eq!(Header::parse(&bytes), Err(FrameError::UnknownKind(byte)));
        }
    }

    #[test]
    fn a_version_bump_is_refused_and_names_the_version() {
        for version in [0u8, 2, 3, 0xff] {
            let mut bytes = head(0);
            bytes[0] = version;
            assert_eq!(Header::parse(&bytes), Err(FrameError::UnsupportedVersion(version)));
        }
    }

    #[test]
    fn the_version_is_checked_before_the_kind() {
        // Order matters for the operator: a future peer should be told its
        // version is unsupported, not that every one of its kinds is unknown.
        let bytes = [2u8, 0xff, 0, 0, 0, 0, 0, 0];
        assert_eq!(Header::parse(&bytes), Err(FrameError::UnsupportedVersion(2)));
    }

    #[test]
    fn an_over_cap_payload_is_refused_by_the_encoder_without_touching_the_buffer() {
        let mut out = vec![0xaa, 0xbb];
        let payload = vec![0u8; MAX_PAYLOAD + 1];
        let error = write_frame(&mut out, Kind::Data, ChannelId::new(1), &payload).unwrap_err();
        assert_eq!(error, FrameError::PayloadTooLong { length: MAX_PAYLOAD + 1 });
        assert_eq!(out, vec![0xaa, 0xbb], "a refused frame must not desynchronise a partly built buffer");
    }

    #[test]
    fn the_encoder_refuses_an_over_cap_payload_before_it_reserves_anything() {
        // The refusal is asserted here; that it happens *before* the reservation
        // is a property of the code above, where the header — and so the ceiling
        // — is built before `Vec::with_capacity` is reached. A check that runs
        // after the allocation it exists to prevent is not a check.
        let payload = vec![0u8; MAX_PAYLOAD + 1];
        assert_eq!(
            encode_frame(Kind::Data, ChannelId::new(1), &payload),
            Err(FrameError::PayloadTooLong { length: MAX_PAYLOAD + 1 })
        );
    }

    #[test]
    fn several_frames_pack_into_one_buffer_and_parse_back_in_order() {
        let mut buffer = Vec::new();
        write_frame(&mut buffer, Kind::Data, ChannelId::new(1), b"one").expect("write");
        write_frame(&mut buffer, Kind::Data, ChannelId::new(3), b"two!").expect("write");
        write_frame(&mut buffer, Kind::Close, ChannelId::new(1), &[0, 0]).expect("write");

        let (first, rest) = parse_frame(&buffer).expect("first");
        assert_eq!(first.payload, b"one");
        let (second, rest) = parse_frame(rest).expect("second");
        assert_eq!(second.header.channel.get(), 3);
        assert_eq!(second.payload, b"two!");
        let (third, rest) = parse_frame(rest).expect("third");
        assert_eq!(third.header.kind, Kind::Close);
        assert!(rest.is_empty());
    }

    #[test]
    fn a_zero_length_frame_is_legal_and_consumes_exactly_the_header() {
        let bytes = encode_frame(Kind::Accept, ChannelId::new(2), &[]).expect("encode");
        assert_eq!(bytes.len(), HEADER_LEN);
        let (frame, rest) = parse_frame(&bytes).expect("parse");
        assert!(frame.payload.is_empty());
        assert!(rest.is_empty());
    }

    #[test]
    fn echo_and_echoed_are_the_only_link_scoped_kinds() {
        assert!(Kind::Echo.is_link_scoped());
        assert!(Kind::Echoed.is_link_scoped());
        for kind in [Kind::Open, Kind::Accept, Kind::Reject, Kind::Data, Kind::Close, Kind::Credit] {
            assert!(!kind.is_link_scoped(), "{kind}");
        }
    }

    #[test]
    fn debug_on_a_frame_prints_the_size_and_not_the_bytes() {
        let payload = b"the-user-password-they-just-typed";
        let frame = Frame { header: Header::new(Kind::Data, ChannelId::new(1), payload.len()).expect("header"), payload };
        let rendered = format!("{frame:?}");
        assert!(rendered.contains("payload_len"), "{rendered}");
        assert!(!rendered.contains("password"), "{rendered}");
    }

    #[test]
    fn errors_render_something_an_operator_can_act_on() {
        assert!(FrameError::UnsupportedVersion(9).to_string().contains('9'));
        assert!(FrameError::UnknownKind(0x2a).to_string().contains("0x2a"));
        assert!(FrameError::TooLong { declared: 5 }.to_string().contains('5'));
        assert!(FrameError::Incomplete { needed: 8 }.to_string().contains('8'));
        assert!(FrameError::PayloadTooLong { length: 7 }.to_string().contains('7'));
    }

    /// A deterministic 64-bit xorshift, so the fuzz-shaped loop below is
    /// reproducible: a failure found in CI is a failure reproducible on a laptop.
    struct Noise(u64);

    impl Noise {
        fn next(&mut self) -> u64 {
            let mut state = self.0;
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            self.0 = state;
            state
        }

        fn byte(&mut self) -> u8 {
            (self.next() & 0xff) as u8
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_never_lie_about_what_they_parsed() {
        // Under `panic = "abort"` a panic in this parser is the whole box going
        // down, so the property under test is not "handles bad input gracefully"
        // — it is "there is no input at all for which this aborts the process".
        let mut noise = Noise(0x5eed_1eaf_c0ff_ee01);
        let mut parsed = 0u32;

        for _ in 0..40_000 {
            let len = (noise.next() % 40) as usize;
            let mut input: Vec<u8> = (0..len).map(|_| noise.byte()).collect();

            // Half the inputs are steered towards a plausible header so the loop
            // spends its time near the interesting boundaries rather than
            // bouncing off the version check.
            if !input.is_empty() && noise.next() % 2 == 0 {
                input[0] = VERSION;
                if input.len() > 1 {
                    input[1] = (noise.byte() % 10) + 1;
                }
                if input.len() >= HEADER_LEN {
                    let declared = (noise.next() % 48) as u32;
                    input[4..8].copy_from_slice(&declared.to_be_bytes());
                }
            }

            match parse_frame(&input) {
                Ok((frame, rest)) => {
                    parsed += 1;
                    assert_eq!(frame.payload.len(), frame.header.payload_len());
                    assert_eq!(frame.header.frame_len() + rest.len(), input.len());
                    assert!(frame.header.payload_len() <= MAX_PAYLOAD);
                    // Whatever came out must go back in byte for byte.
                    let re_encoded =
                        encode_frame(frame.header.kind, frame.header.channel, frame.payload).expect("re-encode");
                    assert_eq!(re_encoded, input[..frame.header.frame_len()]);
                }
                Err(FrameError::Incomplete { needed }) => assert!(needed >= HEADER_LEN),
                Err(_) => {}
            }
        }

        assert!(parsed > 100, "the corpus must actually reach the success path, got {parsed}");
    }

    #[test]
    fn every_byte_of_every_position_is_survivable_in_a_full_header() {
        // Exhaustive over each header position independently: 8 * 256 headers,
        // each parsed. No panic, and a success implies a legal length.
        for position in 0..HEADER_LEN {
            for byte in 0u8..=255 {
                let mut bytes = head(4);
                bytes[position] = byte;
                if let Ok(header) = Header::parse(&bytes) {
                    assert!(header.payload_len() <= MAX_PAYLOAD);
                    assert_eq!(header.encode()[0], VERSION);
                }
            }
        }
    }
}
