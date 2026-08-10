//! Channel identity, channel lifecycle, and the control frames that drive it.
//!
//! A channel is one conversation inside a link: a desktop session, a file
//! transfer, a status feed. It is opened by one side, agreed or refused by the
//! other, carries [`crate::mux::Kind::Data`] frames for as long as it
//! is useful, and is closed with a code. This module owns all four of those
//! steps, and owns the one decision that makes the whole scheme work without a
//! negotiation round trip.
//!
//! # Odd and even, and why there is no allocation protocol
//!
//! Both ends of a link may open a channel at the same instant. If both drew from
//! the same pool of ids, both could pick `5`, and each would believe the other's
//! `OPEN` was an answer to its own — a collision that no amount of retrying
//! fixes, because the retry collides too.
//!
//! So the pool is split by construction: **the side that dialled allocates odd
//! ids, the side that accepted the dial allocates even ids**, and channel `0` is
//! reserved for the link's own control traffic and belongs to neither. Nothing is
//! negotiated, nothing is locked, and no id can be issued twice. The parity is
//! also a check, not just a convention: a peer that opens a channel with an id
//! from *our* half is either confused about which end of the link it is on or is
//! trying to hijack a channel we are about to open, and either way it is
//! [`ChannelError::WrongParity`] and the link closes.
//!
//! Ids are never reused within a link. Reuse would make a late frame for a closed
//! channel indistinguishable from a frame for a new one that happened to inherit
//! the number, and on a spliced path — where frames from a worker's agent cross a
//! relay hop — "late" is normal. Exhaustion is [`ChannelError::Exhausted`], which
//! ends the link; at 32,767 channels per link that is a link which has been up
//! long enough that re-establishing it costs nothing.
//!
//! # What is pure here
//!
//! Everything. [`ChannelTable`] is a state machine over explicit inputs with no
//! socket, no clock and no allocation beyond its own map, so every refusal — a
//! duplicate open, an open on the control channel, a close of a channel that was
//! never opened, one channel too many — is asserted directly rather than being
//! provoked through a network.

use crate::mux::{Kind, MAX_PAYLOAD};
use std::collections::BTreeMap;
use std::fmt;

/// The default ceiling on concurrently open channels per link.
///
/// A link is expected to carry a handful: a desktop session, its input channel,
/// a file transfer, a status feed. The ceiling exists because each open channel
/// costs a credit window on both sides, so an unbounded channel count is an
/// unbounded memory commitment granted by whoever is on the other end of the
/// link.
pub const DEFAULT_MAX_CHANNELS: usize = 64;

/// The largest `OPEN` parameter block, in bytes.
///
/// Parameters are compact ASCII JSON — a peer name, a service selector, a monitor
/// index. Four kibibytes is generous for that and small enough that the daemon
/// can hold one per pending open without thinking about it.
pub const MAX_OPEN_PARAMS: usize = 4096;

/// The largest `REJECT` prose, in bytes.
///
/// Long enough for a sentence an operator can act on, short enough that a hostile
/// peer cannot use the refusal path to push bulk data at a side that has not
/// agreed to receive any.
pub const MAX_REJECT_REASON: usize = 256;

/// Which end of the link this side is.
///
/// Not a description of privilege — the worker dials and the owner accepts, but
/// the owner is the more privileged of the two. It is purely which half of the
/// channel-id space this side draws from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The side that opened the connection. Allocates odd ids.
    ///
    /// In this system that is always the worker: a worker dials out, and nothing
    /// listens.
    Dialler,
    /// The side that answered the connection. Allocates even ids.
    Accepter,
}

impl Role {
    /// The other end of the link.
    pub fn peer(self) -> Self {
        match self {
            Self::Dialler => Self::Accepter,
            Self::Accepter => Self::Dialler,
        }
    }

    /// Whether `id` belongs to this side's half of the id space.
    ///
    /// The control channel belongs to neither side, so this answers `false` for
    /// it on both — a caller asking "may I open this?" gets the right answer, and
    /// a caller asking "did they open this legally?" gets the right answer too.
    pub fn owns(self, id: ChannelId) -> bool {
        if id.is_control() {
            return false;
        }
        match self {
            Self::Dialler => id.get() % 2 == 1,
            Self::Accepter => id.get() % 2 == 0,
        }
    }

    /// A short lowercase name, for logs and error prose.
    pub fn name(self) -> &'static str {
        match self {
            Self::Dialler => "dialler",
            Self::Accepter => "accepter",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(self.name())
    }
}

/// A channel number, as it appears in bytes 2–3 of every frame header.
///
/// A newtype rather than a bare `u16` because a channel id is rewritten as frames
/// cross a splice — the owner receives a frame on the browser's channel `3` and
/// forwards it on the worker's channel `7` — and a bare integer in that code is
/// an invitation to forward the wrong one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChannelId(u16);

impl ChannelId {
    /// The link's own control channel.
    ///
    /// Carries the enrolment `OPEN`, `ECHO`/`ECHOED`, and nothing that belongs to
    /// a conversation. It is never allocated, never opened and never closed:
    /// closing it means closing the link.
    pub const CONTROL: Self = Self(0);

    /// Wraps a raw channel number.
    ///
    /// Every `u16` is a representable channel id, including `0`; whether a given
    /// id is *legal* in a given position is a question for [`Role::owns`] and
    /// [`ChannelTable`], not for the constructor.
    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// The raw number, for encoding into a header.
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Whether this is the link's control channel.
    pub const fn is_control(self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "#{}", self.0)
    }
}

/// Hands out channel ids from one side's half of the space.
///
/// Monotonic and non-reusing; see the module documentation for why reuse is
/// refused rather than merely discouraged.
#[derive(Debug, Clone)]
pub struct Allocator {
    role: Role,
    /// The next id to issue, held as a `u32` so that "past the end" is
    /// representable and exhaustion is a check rather than a silent wrap to `0`
    /// — which would hand out the control channel.
    next: u32,
}

impl Allocator {
    /// An allocator for `role`, starting at the first id that side may use.
    pub fn new(role: Role) -> Self {
        let next = match role {
            Role::Dialler => 1,
            Role::Accepter => 2,
        };
        Self { role, next }
    }

    /// Which side this allocator draws for.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Issues the next id, or reports the space exhausted.
    ///
    /// Exhaustion is a real terminal state, not a theoretical one to be papered
    /// over with a wrap: at that point the only correct action is to close the
    /// link and dial again, which resets both allocators together.
    pub fn allocate(&mut self) -> Result<ChannelId, ChannelError> {
        let candidate = self.next;
        if candidate > u32::from(u16::MAX) {
            return Err(ChannelError::Exhausted);
        }
        self.next = candidate.saturating_add(2);
        // Cannot truncate: the bound above is exactly u16::MAX.
        Ok(ChannelId::new(candidate as u16))
    }
}

/// Where a channel is in its life.
///
/// Deliberately four states and not two. "Opening" is distinct from "open"
/// because a side may not send data on a channel the peer has not agreed to, and
/// "closing" is distinct from "closed" because a close is a message that crosses
/// the wire and frames may still arrive behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    /// We sent `OPEN` and are waiting for `ACCEPT` or `REJECT`.
    Opening,
    /// Both sides agree the channel exists. Data may flow.
    Open,
    /// We sent `CLOSE`; late frames from the peer are expected and ignored.
    Closing,
}

/// One channel's entry in the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelEntry {
    /// The channel's id.
    pub id: ChannelId,
    /// Which side opened it — which is also which side's id half it came from.
    pub opened_by: Role,
    /// The service id carried by its `OPEN`.
    pub service: u8,
    /// Where it is in its life.
    pub state: ChannelState,
}

/// Every channel on one link, and the rules for moving them between states.
///
/// Pure: it holds no socket and no clock. A caller reads frames, asks this table
/// what they mean, and writes whatever the table's answer implies. That split is
/// what makes "a peer opened a channel from our half of the id space" a unit test
/// rather than a packet capture.
#[derive(Debug, Clone)]
pub struct ChannelTable {
    role: Role,
    allocator: Allocator,
    limit: usize,
    channels: BTreeMap<u16, ChannelEntry>,
}

impl ChannelTable {
    /// A table for a link on which this side is `role`, with the default ceiling.
    pub fn new(role: Role) -> Self {
        Self::with_limit(role, DEFAULT_MAX_CHANNELS)
    }

    /// A table with an explicit ceiling on concurrently open channels.
    ///
    /// The ceiling counts channels in any state, including `Opening`: a peer that
    /// floods opens it never completes would otherwise sit below a limit that
    /// only counted established channels.
    pub fn with_limit(role: Role, limit: usize) -> Self {
        Self { role, allocator: Allocator::new(role), limit, channels: BTreeMap::new() }
    }

    /// Which side of the link this table belongs to.
    pub fn role(&self) -> Role {
        self.role
    }

    /// How many channels exist in any state.
    pub fn len(&self) -> usize {
        self.channels.len()
    }

    /// Whether no channel is open.
    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    /// The entry for `id`, if the table knows it.
    pub fn get(&self, id: ChannelId) -> Option<&ChannelEntry> {
        self.channels.get(&id.get())
    }

    /// Every channel, in id order.
    pub fn entries(&self) -> impl Iterator<Item = &ChannelEntry> {
        self.channels.values()
    }

    /// Allocates an id and records a locally initiated open.
    ///
    /// The caller then writes an `OPEN` frame on the returned id. The channel is
    /// `Opening` until the peer answers; sending data before then is
    /// [`ChannelError::NotOpen`].
    pub fn open(&mut self, service: u8) -> Result<ChannelId, ChannelError> {
        if self.channels.len() >= self.limit {
            return Err(ChannelError::TooMany { limit: self.limit });
        }
        let id = self.allocator.allocate()?;
        let entry =
            ChannelEntry { id, opened_by: self.role, service, state: ChannelState::Opening };
        self.channels.insert(id.get(), entry);
        Ok(id)
    }

    /// Records that the peer opened `id`.
    ///
    /// Refuses, in this order: the control channel (which is not openable), an id
    /// from our own half of the space, an id already in the table, and one
    /// channel too many. The caller answers `ACCEPT` on `Ok` and `REJECT` — or
    /// closes the link, for a parity violation — on `Err`.
    ///
    /// A peer-opened channel is `Open` immediately: there is nothing left to wait
    /// for once we have decided to accept it.
    pub fn accept_remote_open(&mut self, id: ChannelId, service: u8) -> Result<&ChannelEntry, ChannelError> {
        if id.is_control() {
            return Err(ChannelError::ControlReserved);
        }
        let peer = self.role.peer();
        if !peer.owns(id) {
            return Err(ChannelError::WrongParity { id, expected: peer });
        }
        if self.channels.contains_key(&id.get()) {
            return Err(ChannelError::Duplicate(id));
        }
        if self.channels.len() >= self.limit {
            return Err(ChannelError::TooMany { limit: self.limit });
        }
        let entry = ChannelEntry { id, opened_by: peer, service, state: ChannelState::Open };
        Ok(self.channels.entry(id.get()).or_insert(entry))
    }

    /// Records the peer's `ACCEPT` for a channel we opened.
    ///
    /// Refuses an accept for a channel the peer opened — that side does not get
    /// to accept its own open — and for one that is not waiting.
    pub fn accepted(&mut self, id: ChannelId) -> Result<(), ChannelError> {
        let entry = self.channels.get_mut(&id.get()).ok_or(ChannelError::Unknown(id))?;
        if entry.opened_by != self.role {
            return Err(ChannelError::WrongDirection(id));
        }
        if entry.state != ChannelState::Opening {
            return Err(ChannelError::NotOpening(id));
        }
        entry.state = ChannelState::Open;
        Ok(())
    }

    /// Records the peer's `REJECT` for a channel we opened, removing it.
    pub fn rejected(&mut self, id: ChannelId) -> Result<(), ChannelError> {
        let entry = self.channels.get(&id.get()).ok_or(ChannelError::Unknown(id))?;
        if entry.opened_by != self.role {
            return Err(ChannelError::WrongDirection(id));
        }
        if entry.state != ChannelState::Opening {
            return Err(ChannelError::NotOpening(id));
        }
        self.channels.remove(&id.get());
        Ok(())
    }

    /// Marks a channel `Closing` because this side is closing it.
    ///
    /// Idempotent for a channel already closing: a caller that closes on both the
    /// error path and the cleanup path is doing the right thing, and should not be
    /// punished for it. Closing an unknown channel is still an error, because that
    /// means the caller is tracking a channel this table never had.
    pub fn close(&mut self, id: ChannelId) -> Result<(), ChannelError> {
        let entry = self.channels.get_mut(&id.get()).ok_or(ChannelError::Unknown(id))?;
        entry.state = ChannelState::Closing;
        Ok(())
    }

    /// Removes a channel entirely, because the peer closed it or our own close
    /// has been acknowledged by the peer's close.
    ///
    /// Returns the entry as it was, so a caller can report what was lost — which
    /// service, opened by whom — without having looked it up beforehand.
    pub fn closed(&mut self, id: ChannelId) -> Result<ChannelEntry, ChannelError> {
        self.channels.remove(&id.get()).ok_or(ChannelError::Unknown(id))
    }

    /// Whether data may be sent or accepted on `id` right now.
    ///
    /// The one question the data path asks, given its own name so that the data
    /// path cannot get the answer subtly wrong by comparing states itself.
    pub fn may_carry_data(&self, id: ChannelId) -> bool {
        matches!(self.channels.get(&id.get()), Some(entry) if entry.state == ChannelState::Open)
    }

    /// Removes every channel, returning them in id order.
    ///
    /// Called when the link drops. Every returned channel needs its own teardown
    /// — a desktop channel's teardown is releasing every key the far machine
    /// still believes is held down — which is why they are returned rather than
    /// silently dropped.
    pub fn drain(&mut self) -> Vec<ChannelEntry> {
        std::mem::take(&mut self.channels).into_values().collect()
    }
}

/// Why a channel operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    /// This side has issued every id in its half of the space.
    Exhausted,
    /// The link already holds as many channels as it may.
    TooMany {
        /// The ceiling that was reached.
        limit: usize,
    },
    /// The peer opened a channel with an id from our half of the space.
    WrongParity {
        /// The offending id.
        id: ChannelId,
        /// The role whose half that id should have come from.
        expected: Role,
    },
    /// Channel 0 is the link's control channel and cannot be opened or closed.
    ControlReserved,
    /// The peer opened a channel that already exists.
    Duplicate(ChannelId),
    /// No such channel on this link.
    Unknown(ChannelId),
    /// A channel that is not waiting for an answer was accepted or rejected.
    NotOpening(ChannelId),
    /// A channel is open but not in the state the operation requires.
    NotOpen(ChannelId),
    /// An accept or reject arrived for a channel the peer itself opened.
    WrongDirection(ChannelId),
}

impl fmt::Display for ChannelError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted => out.write_str("this side has issued every channel id it may; the link must be re-dialled"),
            Self::TooMany { limit } => write!(out, "the link already holds {limit} channels"),
            Self::WrongParity { id, expected } => {
                write!(out, "channel {id} was opened from the wrong half of the id space; ids there belong to the {expected}")
            }
            Self::ControlReserved => out.write_str("channel 0 is the link's control channel and cannot be opened or closed"),
            Self::Duplicate(id) => write!(out, "channel {id} already exists"),
            Self::Unknown(id) => write!(out, "no channel {id} on this link"),
            Self::NotOpening(id) => write!(out, "channel {id} is not waiting for an answer"),
            Self::NotOpen(id) => write!(out, "channel {id} is not open"),
            Self::WrongDirection(id) => write!(out, "channel {id} was opened by the peer, which cannot also answer it"),
        }
    }
}

impl std::error::Error for ChannelError {}

/// A request to open a channel.
///
/// Borrows its parameters rather than owning them: an `OPEN` is decoded from a
/// frame that the caller already holds, and copying four kibibytes to look at a
/// service id would be a copy per channel for no reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Open<'a> {
    /// Which service the channel is for. A one-byte namespace, closed and small,
    /// so that routing an `OPEN` never requires parsing the parameters.
    pub service: u8,
    /// Compact ASCII JSON, at most [`MAX_OPEN_PARAMS`] bytes. May be empty.
    pub params: &'a [u8],
}

impl<'a> Open<'a> {
    /// Decodes an `OPEN` payload.
    ///
    /// The parameters are checked for size and for being printable ASCII, and
    /// nothing else: this module does not know what any service's parameters
    /// mean, and a parser that guessed would be a parser the daemon runs on
    /// hostile bytes.
    ///
    /// Printable ASCII is a real constraint, not a formality — every JSON encoder
    /// in this workspace escapes non-ASCII as `\uXXXX`, so compact JSON is always
    /// ASCII, and requiring it means a malformed `OPEN` is refused here instead of
    /// travelling further into the system as bytes nobody has looked at.
    pub fn parse(payload: &'a [u8]) -> Result<Self, ControlError> {
        let (&service, params) = payload.split_first().ok_or(ControlError::Truncated { kind: Kind::Open })?;
        if params.len() > MAX_OPEN_PARAMS {
            return Err(ControlError::ParamsTooLong { length: params.len() });
        }
        if let Some(&byte) = params.iter().find(|byte| !(0x20..=0x7e).contains(*byte)) {
            return Err(ControlError::NotPrintableAscii { byte });
        }
        Ok(Self { service, params })
    }

    /// Encodes this open into its payload bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ControlError> {
        if self.params.len() > MAX_OPEN_PARAMS {
            return Err(ControlError::ParamsTooLong { length: self.params.len() });
        }
        if let Some(&byte) = self.params.iter().find(|byte| !(0x20..=0x7e).contains(*byte)) {
            return Err(ControlError::NotPrintableAscii { byte });
        }
        let mut out = Vec::with_capacity(1 + self.params.len());
        out.push(self.service);
        out.extend_from_slice(self.params);
        Ok(out)
    }
}

/// A refusal to open a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reject<'a> {
    /// A machine-readable refusal code. The vocabulary belongs to the service.
    pub code: u16,
    /// Short prose for the operator, at most [`MAX_REJECT_REASON`] bytes.
    pub reason: &'a str,
}

impl<'a> Reject<'a> {
    /// Decodes a `REJECT` payload.
    ///
    /// The prose must be UTF-8 and must contain no control characters. The second
    /// rule matters more than it looks: this string reaches a log line and a
    /// console row, and a peer that can put a newline in it can forge log entries
    /// on the machine it is talking to.
    pub fn parse(payload: &'a [u8]) -> Result<Self, ControlError> {
        let code_bytes: [u8; 2] = payload
            .get(..2)
            .and_then(|slice| slice.try_into().ok())
            .ok_or(ControlError::Truncated { kind: Kind::Reject })?;
        let rest = &payload[2..];
        if rest.len() > MAX_REJECT_REASON {
            return Err(ControlError::ReasonTooLong { length: rest.len() });
        }
        let reason = std::str::from_utf8(rest).map_err(|_| ControlError::ReasonNotUtf8)?;
        if let Some(character) = reason.chars().find(|character| character.is_control()) {
            return Err(ControlError::ReasonHasControlCharacter { character });
        }
        Ok(Self { code: u16::from_be_bytes(code_bytes), reason })
    }

    /// Encodes this refusal into its payload bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ControlError> {
        if self.reason.len() > MAX_REJECT_REASON {
            return Err(ControlError::ReasonTooLong { length: self.reason.len() });
        }
        if let Some(character) = self.reason.chars().find(|character| character.is_control()) {
            return Err(ControlError::ReasonHasControlCharacter { character });
        }
        let mut out = Vec::with_capacity(2 + self.reason.len());
        out.extend_from_slice(&self.code.to_be_bytes());
        out.extend_from_slice(self.reason.as_bytes());
        Ok(out)
    }
}

/// The end of a channel, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Close {
    /// A machine-readable code. `0` means "finished normally".
    pub code: u16,
}

impl Close {
    /// The code meaning the channel finished normally.
    pub const NORMAL: Self = Self { code: 0 };

    /// Decodes a `CLOSE` payload.
    ///
    /// Trailing bytes are refused rather than ignored. A close is two bytes; if
    /// there are more, the peer is speaking something this build does not, and
    /// discovering that at the close of a channel is better than never.
    pub fn parse(payload: &[u8]) -> Result<Self, ControlError> {
        let code_bytes: [u8; 2] =
            payload.try_into().map_err(|_| ControlError::Truncated { kind: Kind::Close })?;
        Ok(Self { code: u16::from_be_bytes(code_bytes) })
    }

    /// Encodes this close into its payload bytes.
    pub fn encode(&self) -> [u8; 2] {
        self.code.to_be_bytes()
    }
}

/// The eight opaque bytes an `ECHO` carries and an `ECHOED` returns unchanged.
///
/// Opaque on purpose: the sender chooses them, the receiver never interprets
/// them, and matching a reply to its probe is entirely the sender's business. In
/// practice they are a monotonic counter, which is why they must not be assumed
/// to be one by the side echoing them back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoToken(pub [u8; 8]);

impl EchoToken {
    /// Decodes an `ECHO` or `ECHOED` payload, which is exactly eight bytes.
    pub fn parse(payload: &[u8]) -> Result<Self, ControlError> {
        payload
            .try_into()
            .map(Self)
            .map_err(|_| ControlError::Truncated { kind: Kind::Echo })
    }

    /// The eight bytes, for encoding.
    pub fn as_bytes(&self) -> [u8; 8] {
        self.0
    }
}

/// Decodes an `ACCEPT` payload, which is empty.
///
/// A function rather than a type because there is nothing to hold. Refusing a
/// non-empty accept is the same forward-compatibility stance the rest of this
/// module takes: new information arrives behind a version bump, not as trailing
/// bytes on an existing frame that older builds would silently ignore.
pub fn parse_accept(payload: &[u8]) -> Result<(), ControlError> {
    if payload.is_empty() {
        Ok(())
    } else {
        Err(ControlError::UnexpectedPayload { kind: Kind::Accept, length: payload.len() })
    }
}

/// Why a control frame's payload could not be read or written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlError {
    /// The payload is shorter than the kind's fixed part requires.
    Truncated {
        /// Which kind was being decoded.
        kind: Kind,
    },
    /// A kind that carries no payload was given one.
    UnexpectedPayload {
        /// Which kind was being decoded.
        kind: Kind,
        /// How many unexpected bytes arrived.
        length: usize,
    },
    /// An `OPEN`'s parameters exceed [`MAX_OPEN_PARAMS`].
    ParamsTooLong {
        /// The length offered.
        length: usize,
    },
    /// An `OPEN`'s parameters contain a byte outside printable ASCII.
    NotPrintableAscii {
        /// The first offending byte.
        byte: u8,
    },
    /// A `REJECT`'s prose exceeds [`MAX_REJECT_REASON`].
    ReasonTooLong {
        /// The length offered.
        length: usize,
    },
    /// A `REJECT`'s prose is not valid UTF-8.
    ReasonNotUtf8,
    /// A `REJECT`'s prose contains a control character, which would let the peer
    /// forge lines in our log.
    ReasonHasControlCharacter {
        /// The first offending character.
        character: char,
    },
}

impl fmt::Display for ControlError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { kind } => write!(out, "{kind} frame payload is too short"),
            Self::UnexpectedPayload { kind, length } => {
                write!(out, "{kind} frame carries {length} unexpected payload bytes")
            }
            Self::ParamsTooLong { length } => {
                write!(out, "open parameters are {length} bytes, over the {MAX_OPEN_PARAMS}-byte ceiling")
            }
            Self::NotPrintableAscii { byte } => {
                write!(out, "open parameters contain byte 0x{byte:02x}, which is not printable ASCII")
            }
            Self::ReasonTooLong { length } => {
                write!(out, "reject reason is {length} bytes, over the {MAX_REJECT_REASON}-byte ceiling")
            }
            Self::ReasonNotUtf8 => out.write_str("reject reason is not valid UTF-8"),
            Self::ReasonHasControlCharacter { character } => {
                write!(out, "reject reason contains the control character U+{:04X}", u32::from(*character))
            }
        }
    }
}

impl std::error::Error for ControlError {}

/// The largest encoded `OPEN` payload: one service byte plus its parameters.
const MAX_OPEN_PAYLOAD: usize = MAX_OPEN_PARAMS.saturating_add(1);

/// The largest encoded `REJECT` payload: a `u16` code plus its prose.
const MAX_REJECT_PAYLOAD: usize = MAX_REJECT_REASON.saturating_add(2);

// Asserted at compile time against the mux ceiling, so that a future increase to
// either parameter ceiling cannot quietly create a control frame this crate is
// willing to build and the framing layer refuses to send.
const _: () = assert!(MAX_OPEN_PAYLOAD <= MAX_PAYLOAD);
const _: () = assert!(MAX_REJECT_PAYLOAD <= MAX_PAYLOAD);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_dialler_gets_odd_ids_and_the_accepter_even_ones() {
        let mut dialler = Allocator::new(Role::Dialler);
        assert_eq!(dialler.allocate().expect("first").get(), 1);
        assert_eq!(dialler.allocate().expect("second").get(), 3);
        assert_eq!(dialler.allocate().expect("third").get(), 5);

        let mut accepter = Allocator::new(Role::Accepter);
        assert_eq!(accepter.allocate().expect("first").get(), 2);
        assert_eq!(accepter.allocate().expect("second").get(), 4);
    }

    #[test]
    fn the_two_halves_never_collide() {
        let mut dialler = Allocator::new(Role::Dialler);
        let mut accepter = Allocator::new(Role::Accepter);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(dialler.allocate().expect("odd").get()));
            assert!(seen.insert(accepter.allocate().expect("even").get()));
        }
        assert!(!seen.contains(&0), "the control channel is never allocated");
    }

    #[test]
    fn allocation_reports_exhaustion_instead_of_wrapping_to_the_control_channel() {
        // The whole point of holding `next` as a u32: wrapping a u16 here would
        // hand out channel 0, and channel 0 is the link's control channel.
        let mut dialler = Allocator::new(Role::Dialler);
        let mut last = 0;
        loop {
            match dialler.allocate() {
                Ok(id) => {
                    assert_ne!(id.get(), 0);
                    last = id.get();
                }
                Err(ChannelError::Exhausted) => break,
                Err(other) => panic!("unexpected {other}"),
            }
        }
        assert_eq!(last, u16::MAX);
        // Still exhausted on every subsequent call, rather than starting over.
        assert_eq!(dialler.allocate(), Err(ChannelError::Exhausted));
        assert_eq!(dialler.allocate(), Err(ChannelError::Exhausted));

        let mut accepter = Allocator::new(Role::Accepter);
        let mut last_even = 0;
        while let Ok(id) = accepter.allocate() {
            last_even = id.get();
        }
        assert_eq!(last_even, u16::MAX - 1);
    }

    #[test]
    fn parity_ownership_excludes_the_control_channel_for_both_sides() {
        assert!(!Role::Dialler.owns(ChannelId::CONTROL));
        assert!(!Role::Accepter.owns(ChannelId::CONTROL));
        assert!(Role::Dialler.owns(ChannelId::new(1)));
        assert!(!Role::Dialler.owns(ChannelId::new(2)));
        assert!(Role::Accepter.owns(ChannelId::new(2)));
        assert!(!Role::Accepter.owns(ChannelId::new(1)));
        assert_eq!(Role::Dialler.peer(), Role::Accepter);
        assert_eq!(Role::Accepter.peer(), Role::Dialler);
    }

    #[test]
    fn a_local_open_is_opening_until_the_peer_agrees() {
        let mut table = ChannelTable::new(Role::Dialler);
        let id = table.open(3).expect("open");
        assert_eq!(table.get(id).expect("entry").state, ChannelState::Opening);
        assert!(!table.may_carry_data(id), "data before ACCEPT is a protocol error");

        table.accepted(id).expect("accept");
        assert_eq!(table.get(id).expect("entry").state, ChannelState::Open);
        assert!(table.may_carry_data(id));
        assert_eq!(table.get(id).expect("entry").service, 3);
        assert_eq!(table.get(id).expect("entry").opened_by, Role::Dialler);
    }

    #[test]
    fn a_rejected_open_leaves_no_trace() {
        let mut table = ChannelTable::new(Role::Dialler);
        let id = table.open(1).expect("open");
        table.rejected(id).expect("reject");
        assert!(table.get(id).is_none());
        assert!(table.is_empty());
        // And the id is not reissued.
        let next = table.open(1).expect("open again");
        assert_ne!(next, id);
    }

    #[test]
    fn a_peer_open_from_our_own_half_is_refused() {
        // The hijack case: we are the dialler, so odd ids are ours. A peer
        // claiming one is either confused or racing our next allocation.
        let mut table = ChannelTable::new(Role::Dialler);
        assert_eq!(
            table.accept_remote_open(ChannelId::new(5), 1).unwrap_err(),
            ChannelError::WrongParity { id: ChannelId::new(5), expected: Role::Accepter }
        );
        assert!(table.is_empty());
    }

    #[test]
    fn a_peer_open_from_the_peers_half_is_open_immediately() {
        let mut table = ChannelTable::new(Role::Dialler);
        let entry = *table.accept_remote_open(ChannelId::new(4), 9).expect("accept");
        assert_eq!(entry.state, ChannelState::Open);
        assert_eq!(entry.opened_by, Role::Accepter);
        assert_eq!(entry.service, 9);
        assert!(table.may_carry_data(ChannelId::new(4)));
    }

    #[test]
    fn the_control_channel_cannot_be_opened() {
        let mut table = ChannelTable::new(Role::Accepter);
        assert_eq!(table.accept_remote_open(ChannelId::CONTROL, 0).unwrap_err(), ChannelError::ControlReserved);
    }

    #[test]
    fn a_duplicate_peer_open_is_refused() {
        let mut table = ChannelTable::new(Role::Dialler);
        table.accept_remote_open(ChannelId::new(2), 1).expect("first");
        assert_eq!(
            table.accept_remote_open(ChannelId::new(2), 1).unwrap_err(),
            ChannelError::Duplicate(ChannelId::new(2))
        );
    }

    #[test]
    fn the_channel_ceiling_counts_channels_that_are_still_opening() {
        // A peer that opens and never finishes must still hit the ceiling, or the
        // ceiling protects nothing.
        let mut table = ChannelTable::with_limit(Role::Dialler, 2);
        table.open(1).expect("first");
        table.open(1).expect("second");
        assert_eq!(table.open(1).unwrap_err(), ChannelError::TooMany { limit: 2 });
        assert_eq!(
            table.accept_remote_open(ChannelId::new(2), 1).unwrap_err(),
            ChannelError::TooMany { limit: 2 }
        );
    }

    #[test]
    fn answering_a_channel_the_peer_opened_is_refused() {
        let mut table = ChannelTable::new(Role::Dialler);
        table.accept_remote_open(ChannelId::new(2), 1).expect("open");
        assert_eq!(table.accepted(ChannelId::new(2)).unwrap_err(), ChannelError::WrongDirection(ChannelId::new(2)));
        assert_eq!(table.rejected(ChannelId::new(2)).unwrap_err(), ChannelError::WrongDirection(ChannelId::new(2)));
    }

    #[test]
    fn answering_twice_is_refused() {
        let mut table = ChannelTable::new(Role::Dialler);
        let id = table.open(1).expect("open");
        table.accepted(id).expect("first");
        assert_eq!(table.accepted(id).unwrap_err(), ChannelError::NotOpening(id));
    }

    #[test]
    fn operations_on_an_unknown_channel_name_it() {
        let mut table = ChannelTable::new(Role::Dialler);
        let ghost = ChannelId::new(41);
        assert_eq!(table.accepted(ghost).unwrap_err(), ChannelError::Unknown(ghost));
        assert_eq!(table.rejected(ghost).unwrap_err(), ChannelError::Unknown(ghost));
        assert_eq!(table.close(ghost).unwrap_err(), ChannelError::Unknown(ghost));
        assert_eq!(table.closed(ghost).unwrap_err(), ChannelError::Unknown(ghost));
        assert!(!table.may_carry_data(ghost));
    }

    #[test]
    fn closing_is_idempotent_but_closing_the_unknown_is_not() {
        let mut table = ChannelTable::new(Role::Dialler);
        let id = table.open(1).expect("open");
        table.accepted(id).expect("accept");
        table.close(id).expect("close");
        table.close(id).expect("closing twice is a caller being careful, not a bug");
        assert!(!table.may_carry_data(id), "data must not flow after we said CLOSE");
        let entry = table.closed(id).expect("closed");
        assert_eq!(entry.id, id);
        assert_eq!(table.closed(id).unwrap_err(), ChannelError::Unknown(id));
    }

    #[test]
    fn draining_returns_every_channel_so_each_can_be_torn_down() {
        // The reason this returns rather than clears: a desktop channel's
        // teardown releases keys the far machine still believes are held.
        let mut table = ChannelTable::new(Role::Dialler);
        let first = table.open(1).expect("open");
        let second = table.open(2).expect("open");
        table.accept_remote_open(ChannelId::new(2), 3).expect("peer open");
        let drained = table.drain();
        assert!(table.is_empty());
        let ids: Vec<u16> = drained.iter().map(|entry| entry.id.get()).collect();
        // Ours (1, 3) and the peer's (2), in id order, all of them.
        assert_eq!(ids, vec![first.get(), 2, second.get()]);
    }

    #[test]
    fn open_round_trips_with_and_without_parameters() {
        for params in [&b""[..], &b"{\"peer\":\"alex-desktop\"}"[..]] {
            let open = Open { service: 7, params };
            let encoded = open.encode().expect("encode");
            let decoded = Open::parse(&encoded).expect("parse");
            assert_eq!(decoded, open);
        }
    }

    #[test]
    fn an_empty_open_payload_is_truncated_rather_than_a_default_service() {
        assert_eq!(Open::parse(&[]).unwrap_err(), ControlError::Truncated { kind: Kind::Open });
    }

    #[test]
    fn open_parameters_are_bounded_and_must_be_printable_ascii() {
        let long = vec![b'x'; MAX_OPEN_PARAMS + 1];
        assert_eq!(
            Open { service: 0, params: &long }.encode().unwrap_err(),
            ControlError::ParamsTooLong { length: MAX_OPEN_PARAMS + 1 }
        );
        let mut payload = vec![0u8];
        payload.extend_from_slice(&long);
        assert_eq!(Open::parse(&payload).unwrap_err(), ControlError::ParamsTooLong { length: MAX_OPEN_PARAMS + 1 });

        for byte in [0x00u8, 0x09, 0x0a, 0x1f, 0x7f, 0x80, 0xff] {
            assert_eq!(
                Open::parse(&[1, byte]).unwrap_err(),
                ControlError::NotPrintableAscii { byte },
                "byte 0x{byte:02x}"
            );
        }
        // At the ceiling exactly is fine.
        let exact = vec![b'x'; MAX_OPEN_PARAMS];
        assert!(Open { service: 0, params: &exact }.encode().is_ok());
    }

    #[test]
    fn reject_round_trips_and_bounds_its_prose() {
        let reject = Reject { code: 403, reason: "this node is not enrolled" };
        let encoded = reject.encode().expect("encode");
        assert_eq!(Reject::parse(&encoded).expect("parse"), reject);

        let long = "x".repeat(MAX_REJECT_REASON + 1);
        assert_eq!(
            Reject { code: 0, reason: &long }.encode().unwrap_err(),
            ControlError::ReasonTooLong { length: MAX_REJECT_REASON + 1 }
        );
        assert_eq!(Reject::parse(&[0]).unwrap_err(), ControlError::Truncated { kind: Kind::Reject });
    }

    #[test]
    fn a_reject_reason_cannot_forge_a_log_line() {
        // This is the whole reason the control-character rule exists: the prose
        // ends up in a log the operator reads and in a row the console renders.
        let hostile = "denied\n2026-08-10 owner: node enrolled successfully";
        assert_eq!(
            Reject { code: 1, reason: hostile }.encode().unwrap_err(),
            ControlError::ReasonHasControlCharacter { character: '\n' }
        );
        let mut payload = vec![0, 1];
        payload.extend_from_slice(hostile.as_bytes());
        assert_eq!(
            Reject::parse(&payload).unwrap_err(),
            ControlError::ReasonHasControlCharacter { character: '\n' }
        );
    }

    #[test]
    fn a_reject_reason_must_be_utf8() {
        let payload = [0u8, 1, 0xff, 0xfe];
        assert_eq!(Reject::parse(&payload).unwrap_err(), ControlError::ReasonNotUtf8);
    }

    #[test]
    fn close_is_exactly_two_bytes() {
        assert_eq!(Close::parse(&[0x04, 0xd2]).expect("parse").code, 1234);
        assert_eq!(Close::NORMAL.encode(), [0, 0]);
        assert_eq!(Close::parse(&[0]).unwrap_err(), ControlError::Truncated { kind: Kind::Close });
        assert_eq!(Close::parse(&[0, 0, 0]).unwrap_err(), ControlError::Truncated { kind: Kind::Close });
    }

    #[test]
    fn an_echo_token_is_exactly_eight_bytes_and_survives_the_round_trip() {
        let token = EchoToken([1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(EchoToken::parse(&token.as_bytes()).expect("parse"), token);
        assert_eq!(EchoToken::parse(&[0; 7]).unwrap_err(), ControlError::Truncated { kind: Kind::Echo });
        assert_eq!(EchoToken::parse(&[0; 9]).unwrap_err(), ControlError::Truncated { kind: Kind::Echo });
    }

    #[test]
    fn an_accept_carries_nothing_and_trailing_bytes_are_refused() {
        parse_accept(&[]).expect("empty accept");
        assert_eq!(
            parse_accept(&[0, 0]).unwrap_err(),
            ControlError::UnexpectedPayload { kind: Kind::Accept, length: 2 }
        );
    }

    #[test]
    fn control_payloads_never_panic_on_arbitrary_bytes() {
        // Same property as the mux fuzz loop, over the payload decoders: no input
        // aborts the process.
        let mut state = 0x1234_5678_9abc_def0u64;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state % 24) as usize;
            let bytes: Vec<u8> = (0..len).map(|index| (state >> (index % 8 * 8)) as u8).collect();
            let _ = Open::parse(&bytes);
            let _ = Reject::parse(&bytes);
            let _ = Close::parse(&bytes);
            let _ = EchoToken::parse(&bytes);
            let _ = parse_accept(&bytes);
        }
    }

    #[test]
    fn errors_render_something_an_operator_can_act_on() {
        assert!(ChannelError::TooMany { limit: 4 }.to_string().contains('4'));
        assert!(ChannelError::Unknown(ChannelId::new(9)).to_string().contains("#9"));
        assert!(
            ChannelError::WrongParity { id: ChannelId::new(3), expected: Role::Accepter }
                .to_string()
                .contains("accepter")
        );
        assert!(ControlError::NotPrintableAscii { byte: 0x0a }.to_string().contains("0x0a"));
        assert!(ControlError::ReasonHasControlCharacter { character: '\n' }.to_string().contains("U+000A"));
    }
}
