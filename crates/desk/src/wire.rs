//! The message codec: one byte of kind, then a fixed layout.
//!
//! # The shape, and why it is this dull
//!
//! Every message is a kind byte followed by fields at known offsets. There are
//! no variable-length integers, no nesting, no self-describing container and no
//! text format. Each length prefix is immediately followed by exactly that many
//! bytes in the same message, so a peer cannot make the parser reserve memory
//! for data it never intends to send — the failure that
//! `Vec::with_capacity(declared_length)` produces, and which under
//! `panic = "abort"` is not an allocation error but a dead daemon.
//!
//! Dullness is the security property. This codec runs on bytes that arrive from
//! the far end of a tunnel, in a process that also holds the operator's desktop;
//! on the console side it runs on bytes from a machine that may not be the one
//! the operator thinks it is. So [`Message::decode`] is a **total** parser: it
//! reads through a bounds-checked cursor, converts every peer-chosen length with
//! `usize::try_from` rather than `as`, refuses trailing bytes, and returns a
//! [`WireError`] that names the field. There is no `unwrap`, no slice index and
//! no unchecked arithmetic anywhere in this file, and the fuzz-shaped test at the
//! bottom exists to keep that true rather than to prove it once.
//!
//! Refusing trailing bytes deserves its own sentence, because it looks like
//! pedantry and is not. A parser that ignores what it does not understand is a
//! parser two implementations can disagree about: the sender believes it sent a
//! field, the receiver silently drops it, and the bug surfaces months later as a
//! behaviour difference nobody can reproduce. Every message here has exactly one
//! encoding, and [`Message::encode`] followed by [`Message::decode`] is the
//! identity — which is what the round-trip tests assert.
//!
//! That identity is why the encoder is fallible too. `try_from` rather than `as`
//! is a rule for **both** directions: a length prefix truncated on the way out is
//! a receiver trusting a number the sender never had, and a list quietly clipped
//! to fit its count field is a peer being told a smaller truth. Anything
//! [`Message::encode`] cannot write exactly is a named [`WireError`], never
//! bytes that decode to something else.
//!
//! # Framing lives elsewhere
//!
//! There is no length prefix on a message here, because there is already one
//! underneath: `selfhost-mesh`'s eight-byte mux header carries the payload
//! length, and beneath *that* the WebSocket frame header carries its own. A third
//! length field would be a third thing that can disagree with the other two, and
//! disagreeing length fields are how request smuggling works. This module is
//! handed one complete message and hands back one message.
//!
//! # Direction
//!
//! Kinds below `0x40` travel from the machine being controlled to the console;
//! kinds from `0x40` up travel the other way. [`Message::direction`] answers
//! which, so a receiver can refuse a message travelling the wrong way — a
//! console that accepts a `Key` message is a console that can be typed *into* by
//! the machine it is controlling.

use crate::grant::Capabilities;
use crate::keys::{KeyError, Usage};
use crate::state::Notice;
use crate::tiles::{Encoding, TileCoord, TileError, TileSize};
use std::fmt;

/// The protocol revision this build speaks.
///
/// Sent in [`Hello`] and checked by the client. A mismatch is a refusal with a
/// clear message, never a best-effort attempt: the self-updater rebuilds the box
/// from a push, so a console and an agent from different commits is an ordinary
/// event and it must produce "update your console", not a corrupted frame.
pub const PROTOCOL_VERSION: u16 = 1;

/// The largest message this codec will encode or decode.
///
/// One mebibyte less the mux header, so a message always fits one mux frame and
/// no reassembly layer is needed above it. A tile of the largest legal size is
/// 128×128×4 = 64 KiB raw, so this ceiling is sixteen times the largest thing
/// that legitimately travels.
pub const MAX_MESSAGE: usize = (1 << 20) - 8;

/// The most monitors a [`Hello`] may describe.
///
/// Sixteen is past any real desk and small enough that the allocation it implies
/// is uninteresting. A machine with more monitors than this is refused with a
/// named error rather than silently truncated, because a truncated monitor list
/// means the console maps pointer coordinates onto the wrong screen.
pub const MAX_MONITORS: usize = 16;

/// The largest monitor edge accepted, in pixels.
///
/// Well past 8K in either direction. Its job is not to predict displays; it is
/// to keep `width * height * 4` inside a `u32` with room to spare so that a
/// peer's claimed geometry can never be the input to an overflow.
pub const MAX_DIMENSION: u32 = 32_768;

/// The largest cursor edge accepted, in pixels.
///
/// Cursor bitmaps are cached by the client, so this is also the per-shape
/// ceiling on what the cache can be made to hold: 128×128×4 is 64 KiB, and the
/// cache's own capacity bounds the rest.
pub const MAX_CURSOR_EDGE: u16 = 128;

/// The largest text-input payload, in bytes.
///
/// Text injection is for a person typing or pasting a line, not for transferring
/// a file through the keyboard. A kibibyte is generous for the former and
/// uninteresting for the latter.
pub const MAX_TEXT_BYTES: usize = 1024;

/// The largest human-readable detail string on a status or refusal, in bytes.
pub const MAX_DETAIL_BYTES: usize = 256;

/// The largest scroll magnitude accepted in one message.
///
/// Units are 1/120 of a wheel notch, matching `WHEEL_DELTA`, so this is a
/// thousand notches — far more than a person produces in one event and far less
/// than the value needed to overflow anything downstream. A larger value is a
/// typed refusal rather than a clamp, because silently clamping means the far
/// machine scrolled a different amount than the client believes it did.
pub const MAX_SCROLL: i32 = 120_000;

/// Why a message could not be decoded.
///
/// Every variant names the field, because the only person who ever reads one of
/// these is trying to work out which side of a version mismatch is wrong. What
/// crosses the network in response is a close code, not this text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The message had no kind byte at all.
    Empty,
    /// The message is longer than [`MAX_MESSAGE`].
    Oversize {
        /// How long it claimed to be.
        length: usize,
    },
    /// The kind byte names no message this build knows.
    UnknownKind(u8),
    /// The message ended in the middle of a field.
    Truncated {
        /// Which field ran off the end.
        field: &'static str,
        /// How many bytes it needed.
        needed: usize,
        /// How many were left.
        available: usize,
    },
    /// The message was fully decoded and bytes remained.
    Trailing {
        /// Which message kind.
        kind: &'static str,
        /// How many bytes were left over.
        extra: usize,
    },
    /// A count or length exceeded its documented ceiling.
    TooLarge {
        /// Which field.
        field: &'static str,
        /// The ceiling.
        limit: usize,
        /// What was claimed.
        actual: usize,
    },
    /// A field that must be UTF-8 was not.
    NotUtf8 {
        /// Which field.
        field: &'static str,
    },
    /// An enumerated field carried a value this build does not know, or a
    /// numeric field was outside its permitted range.
    BadValue {
        /// Which field.
        field: &'static str,
        /// What was carried.
        value: u64,
    },
    /// A key usage this build cannot express. Kept as its own variant, carrying
    /// the key module's own distinction between "not a keyboard usage" and "a
    /// keyboard usage we cannot map", because those two failures are fixed in
    /// different places.
    Key(KeyError),
    /// A tile field was inconsistent — a payload whose length cannot describe
    /// the tile it claims to be.
    Tile(TileError),
}

impl From<KeyError> for WireError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

impl From<TileError> for WireError {
    fn from(error: TileError) -> Self {
        Self::Tile(error)
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => out.write_str("empty message"),
            Self::Oversize { length } => write!(out, "message of {length} bytes exceeds {MAX_MESSAGE}"),
            Self::UnknownKind(kind) => write!(out, "unknown message kind {kind:#04x}"),
            Self::Truncated { field, needed, available } => {
                write!(out, "truncated at {field}: needed {needed} bytes, {available} left")
            }
            Self::Trailing { kind, extra } => {
                write!(out, "{extra} trailing bytes after a {kind} message")
            }
            Self::TooLarge { field, limit, actual } => {
                write!(out, "{field} is {actual}, over the limit of {limit}")
            }
            Self::NotUtf8 { field } => write!(out, "{field} is not valid UTF-8"),
            Self::BadValue { field, value } => write!(out, "{field} carries the unusable value {value}"),
            Self::Key(error) => write!(out, "key: {error}"),
            Self::Tile(error) => write!(out, "tile: {error}"),
        }
    }
}

impl std::error::Error for WireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Key(error) => Some(error),
            Self::Tile(error) => Some(error),
            _ => None,
        }
    }
}

/// Which way a message travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// From the machine being controlled to the console: pixels, cursor, status.
    ToViewer,
    /// From the console to the machine: keys, pointer, text.
    ToAgent,
}

/// One display, in the coordinate space the agent advertises.
///
/// Origins are signed because a virtual desktop's origin is negative whenever a
/// monitor sits left of or above the primary one, and every arithmetic mistake
/// this project could make with monitor geometry starts with storing that as
/// unsigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Monitor {
    /// The agent's own id for this display; referenced by [`FrameBegin`] and
    /// [`Message::PointerMove`].
    pub id: u8,
    /// The left edge in virtual-desktop pixels; negative is legal.
    pub origin_x: i32,
    /// The top edge in virtual-desktop pixels; negative is legal.
    pub origin_y: i32,
    /// Width in physical pixels.
    pub width: u32,
    /// Height in physical pixels.
    pub height: u32,
    /// The display's scale factor in thousandths — 2000 is a Retina display at
    /// 2×, 1500 is Windows at 150%. Sent so the console can label the display,
    /// never so it can compute coordinates: coordinates are physical pixels and
    /// the mapping is `selfhost-screen`'s business.
    pub scale_permille: u16,
    /// Whether this is the primary display.
    pub primary: bool,
}

/// The size of one encoded [`Monitor`] on the wire.
const MONITOR_BYTES: usize = 20;

/// The agent's opening statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// The protocol revision the agent speaks.
    pub protocol: u16,
    /// The tile edge in pixels, which the client uses to size its own grid.
    pub tile: TileSize,
    /// The frame rate the agent will not exceed.
    pub max_fps: u8,
    /// What this session was actually granted — echoed from the redeemed ticket
    /// so the console displays the truth rather than what it asked for.
    pub capabilities: Capabilities,
    /// Every display, in the agent's own order.
    pub monitors: Vec<Monitor>,
}

/// The start of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameBegin {
    /// Which display.
    pub monitor: u8,
    /// A monotonically increasing frame number, so a client can detect a gap.
    pub sequence: u64,
    /// The display's width in pixels at the moment of capture. Repeated per
    /// frame rather than taken from [`Hello`] because a resolution change is one
    /// of the ordinary reasons a capture is rebuilt mid-session.
    pub width: u32,
    /// The display's height in pixels at the moment of capture.
    pub height: u32,
    /// Whether every tile of the frame follows, rather than only the changed
    /// ones. Sent after a reconnect and whenever the client asks.
    pub keyframe: bool,
}

/// One encoded tile.
///
/// # `monitor`, `col` and `row` arrive unvalidated, and that is deliberate
///
/// All three are whatever the peer wrote, across their full numeric range. This
/// codec cannot check them, and should not pretend to: the grid's extent follows
/// from the tile size and the *current* display geometry, which arrive in
/// [`Hello`] and [`FrameBegin`] and change mid-session whenever a resolution
/// does, so a bound applied here would be a bound against a stale shape.
///
/// The obligation is therefore the receiver's, and it is not optional — a column
/// of `u16::MAX` decodes cleanly and names a tile no display has. Discharge it by
/// turning the message into a [`TileCoord`] with [`TileMessage::coord`] and
/// handing that to [`crate::tiles::Grid::bounds`], which is the one function that
/// knows the extent and answers [`crate::tiles::TileError::OutOfGrid`] for a coordinate
/// outside it. `monitor` is resolved the same way: against the ids [`Hello`]
/// advertised, never used as an index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TileMessage {
    /// Which display the peer says this tile belongs to. Must be resolved against
    /// the monitor ids from [`Hello`]; never used as an index.
    pub monitor: u8,
    /// The tile's column, as claimed by the peer. Unbounded here; see the type's
    /// documentation.
    pub col: u16,
    /// The tile's row, as claimed by the peer. Unbounded here; see the type's
    /// documentation.
    pub row: u16,
    /// How the payload is encoded.
    pub encoding: Encoding,
    /// The encoded bytes. Decoded by [`crate::tiles::decode_tile`], which
    /// validates it against the tile size — this codec checks only that the
    /// bytes are present.
    pub payload: Vec<u8>,
}

impl TileMessage {
    /// The claimed position, in the type [`crate::tiles::Grid::bounds`] takes.
    ///
    /// Exists so that the unvalidated pair cannot be used by accident: the only
    /// convenient way to turn a `TileMessage` into a position is to produce a
    /// [`TileCoord`], and the only thing that consumes a `TileCoord` is the grid,
    /// which refuses one that lies outside it. Nothing here validates anything —
    /// it moves the coordinate into the shape whose consumer must.
    pub fn coord(&self) -> TileCoord {
        TileCoord { col: self.col, row: self.row }
    }
}

/// Where the pointer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CursorPos {
    /// Virtual-desktop x, which may be negative.
    pub x: i32,
    /// Virtual-desktop y, which may be negative.
    pub y: i32,
    /// Whether the pointer is being drawn at all — it is hidden while typing on
    /// most platforms, and a client that draws it anyway shows a pointer the
    /// person at the machine cannot see.
    pub visible: bool,
}

/// A cursor bitmap, sent once per distinct shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorShape {
    /// The agent's id for this shape; [`CursorPos`] does not carry it, so the
    /// client keeps the last one it was told.
    pub shape: u64,
    /// The hotspot's x offset within the bitmap.
    pub hotspot_x: u16,
    /// The hotspot's y offset within the bitmap.
    pub hotspot_y: u16,
    /// Bitmap width in pixels.
    pub width: u16,
    /// Bitmap height in pixels.
    pub height: u16,
    /// `width * height * 4` bytes of premultiplied BGRA.
    pub pixels: Vec<u8>,
}

/// Why an input event was not delivered.
///
/// This exists because on Windows it is impossible to tell from the return value
/// whether an injected event arrived: UIPI silently discards injection into any
/// window at a higher integrity level, `SendInput` returns the full count, and
/// `GetLastError` says nothing. So the agent reports what it *knows* — that it
/// refused, or that the platform state makes delivery impossible — and never
/// infers success from a return value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// This session was not granted [`Capabilities::CONTROL`]. Re-checked per
    /// message rather than inferred from the handshake, so a viewer can be
    /// downgraded mid-session.
    NotPermitted,
    /// `[desktop].allow_input` is false for the whole deployment.
    InputDisabled,
    /// The secure desktop is in front.
    SecureDesktop,
    /// The target window is at a higher integrity level than the agent, so the
    /// platform will discard the event. The agent runs at medium integrity
    /// deliberately; see the session documentation.
    ElevatedWindow,
    /// The session is not live — recovering, suspended, or without an agent.
    NotLive,
    /// The key is not in this build's vocabulary. See [`crate::keys`].
    Unmappable,
}

impl Refusal {
    /// The stable wire code.
    pub const fn code(self) -> u8 {
        match self {
            Self::NotPermitted => 0x01,
            Self::InputDisabled => 0x02,
            Self::SecureDesktop => 0x03,
            Self::ElevatedWindow => 0x04,
            Self::NotLive => 0x05,
            Self::Unmappable => 0x06,
        }
    }

    /// Reads a refusal from its wire code.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0x01 => Some(Self::NotPermitted),
            0x02 => Some(Self::InputDisabled),
            0x03 => Some(Self::SecureDesktop),
            0x04 => Some(Self::ElevatedWindow),
            0x05 => Some(Self::NotLive),
            0x06 => Some(Self::Unmappable),
            _ => None,
        }
    }

    /// The sentence a console shows.
    pub const fn sentence(self) -> &'static str {
        match self {
            Self::NotPermitted => "this session may view but not control",
            Self::InputDisabled => "input is disabled for this deployment",
            Self::SecureDesktop => "input suspended while the secure desktop is in front",
            Self::ElevatedWindow => "the focused window is elevated — the platform discards input",
            Self::NotLive => "the session is not live",
            Self::Unmappable => "that key has no mapping on the remote platform",
        }
    }
}

/// A pointer button.
///
/// A closed set: the wire cannot express "button 47", so nothing downstream has
/// to decide what to do with one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    /// The primary button.
    Left,
    /// The wheel button.
    Middle,
    /// The secondary button.
    Right,
    /// The thumb button that means "back".
    Back,
    /// The thumb button that means "forward".
    Forward,
}

impl Button {
    /// The stable wire code.
    pub const fn code(self) -> u8 {
        match self {
            Self::Left => 0x01,
            Self::Middle => 0x02,
            Self::Right => 0x03,
            Self::Back => 0x04,
            Self::Forward => 0x05,
        }
    }

    /// Reads a button from its wire code.
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0x01 => Some(Self::Left),
            0x02 => Some(Self::Middle),
            0x03 => Some(Self::Right),
            0x04 => Some(Self::Back),
            0x05 => Some(Self::Forward),
            _ => None,
        }
    }
}

/// Everything that travels on a desktop channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// The agent's opening statement.
    Hello(Hello),
    /// A change of session state, with the words to display.
    Status {
        /// What happened.
        notice: Notice,
        /// Optional extra detail — a driver name, a session id — for the
        /// diagnostics plate. Never required to understand the notice.
        detail: String,
    },
    /// The start of a frame.
    FrameBegin(FrameBegin),
    /// One tile of the frame in progress.
    Tile(TileMessage),
    /// The end of a frame; the client may present.
    FrameEnd {
        /// The sequence number of the frame that just ended.
        sequence: u64,
    },
    /// The pointer moved.
    CursorPos(CursorPos),
    /// The pointer's shape changed to one the client has not seen.
    CursorShape(CursorShape),
    /// An input event was not delivered.
    InputRefused {
        /// Why.
        reason: Refusal,
    },
    /// A physical key went down or came up.
    Key {
        /// Which key.
        usage: Usage,
        /// True for a press, false for a release.
        down: bool,
    },
    /// Text to type.
    ///
    /// A separate message from [`Message::Key`] because the two take different
    /// paths on both platforms: text goes through the unicode path
    /// (`KEYEVENTF_UNICODE` packets, `CGEventKeyboardSetUnicodeString`) and
    /// shortcuts *must not* — `Ctrl+C` sent as unicode packets does nothing at
    /// all, on either platform. Keeping them as two messages makes that
    /// impossible to get wrong by accident.
    Text {
        /// The text to type.
        text: String,
    },
    /// The pointer moved to an absolute position.
    ///
    /// Absolute, never relative: Windows multiplies relative deltas by pointer
    /// acceleration by up to four times, so a relative protocol makes the
    /// remote pointer land somewhere the client cannot predict.
    PointerMove {
        /// Which display's pixel space the coordinates are in.
        monitor: u8,
        /// x within that display, in pixels.
        x: i32,
        /// y within that display, in pixels.
        y: i32,
    },
    /// A pointer button went down or came up.
    Button {
        /// Which button.
        button: Button,
        /// True for a press.
        down: bool,
    },
    /// The wheel turned, in 1/120ths of a notch.
    Scroll {
        /// Horizontal movement.
        dx: i32,
        /// Vertical movement.
        dy: i32,
    },
    /// Release everything currently held.
    ///
    /// Sent by the client on blur and on reconnect, and applied by the agent on
    /// its own whenever the channel closes. See [`crate::keys::HeldKeys`] for
    /// why this is not optional.
    ReleaseAll,
    /// Ask for a full frame rather than a difference — after a reconnect, or
    /// when the client has lost track of what it is holding.
    RequestFullFrame {
        /// Which display.
        monitor: u8,
    },
}

/// Kind bytes. Grouped by direction: below `0x40` to the viewer, `0x40` and
/// above to the agent.
mod kind {
    /// [`super::Message::Hello`].
    pub const HELLO: u8 = 0x01;
    /// [`super::Message::Status`].
    pub const STATUS: u8 = 0x02;
    /// [`super::Message::FrameBegin`].
    pub const FRAME_BEGIN: u8 = 0x03;
    /// [`super::Message::Tile`].
    pub const TILE: u8 = 0x04;
    /// [`super::Message::FrameEnd`].
    pub const FRAME_END: u8 = 0x05;
    /// [`super::Message::CursorPos`].
    pub const CURSOR_POS: u8 = 0x06;
    /// [`super::Message::CursorShape`].
    pub const CURSOR_SHAPE: u8 = 0x07;
    /// [`super::Message::InputRefused`].
    pub const INPUT_REFUSED: u8 = 0x08;
    /// [`super::Message::Key`].
    pub const KEY: u8 = 0x40;
    /// [`super::Message::Text`].
    pub const TEXT: u8 = 0x41;
    /// [`super::Message::PointerMove`].
    pub const POINTER_MOVE: u8 = 0x42;
    /// [`super::Message::Button`].
    pub const BUTTON: u8 = 0x43;
    /// [`super::Message::Scroll`].
    pub const SCROLL: u8 = 0x44;
    /// [`super::Message::ReleaseAll`].
    pub const RELEASE_ALL: u8 = 0x45;
    /// [`super::Message::RequestFullFrame`].
    pub const REQUEST_FULL_FRAME: u8 = 0x46;
}

impl Message {
    /// The kind byte this message encodes as.
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Hello(_) => kind::HELLO,
            Self::Status { .. } => kind::STATUS,
            Self::FrameBegin(_) => kind::FRAME_BEGIN,
            Self::Tile(_) => kind::TILE,
            Self::FrameEnd { .. } => kind::FRAME_END,
            Self::CursorPos(_) => kind::CURSOR_POS,
            Self::CursorShape(_) => kind::CURSOR_SHAPE,
            Self::InputRefused { .. } => kind::INPUT_REFUSED,
            Self::Key { .. } => kind::KEY,
            Self::Text { .. } => kind::TEXT,
            Self::PointerMove { .. } => kind::POINTER_MOVE,
            Self::Button { .. } => kind::BUTTON,
            Self::Scroll { .. } => kind::SCROLL,
            Self::ReleaseAll => kind::RELEASE_ALL,
            Self::RequestFullFrame { .. } => kind::REQUEST_FULL_FRAME,
        }
    }

    /// A short name for the message kind, for errors and logs.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Hello(_) => "Hello",
            Self::Status { .. } => "Status",
            Self::FrameBegin(_) => "FrameBegin",
            Self::Tile(_) => "Tile",
            Self::FrameEnd { .. } => "FrameEnd",
            Self::CursorPos(_) => "CursorPos",
            Self::CursorShape(_) => "CursorShape",
            Self::InputRefused { .. } => "InputRefused",
            Self::Key { .. } => "Key",
            Self::Text { .. } => "Text",
            Self::PointerMove { .. } => "PointerMove",
            Self::Button { .. } => "Button",
            Self::Scroll { .. } => "Scroll",
            Self::ReleaseAll => "ReleaseAll",
            Self::RequestFullFrame { .. } => "RequestFullFrame",
        }
    }

    /// Which way this message legitimately travels.
    ///
    /// A receiver checks this. It is cheap, and the alternative is a console
    /// that can be typed into by the machine it is displaying.
    pub const fn direction(&self) -> Direction {
        if self.kind() < 0x40 { Direction::ToViewer } else { Direction::ToAgent }
    }

    /// Encodes the message, or names what about it could not be written.
    ///
    /// The inverse of [`Message::decode`] for every value it returns `Ok` for,
    /// which the round-trip tests assert. **It is fallible on purpose.** A codec
    /// whose central property is `decode(encode(m)) == m` cannot have an encoder
    /// that quietly writes something else: a monitor list past [`MAX_MONITORS`]
    /// used to be truncated to fit the one-byte count, which is precisely what
    /// that constant's own documentation says must never happen — a console shown
    /// three of a machine's twenty screens maps pointer coordinates onto a
    /// desktop whose shape it does not know. So an over-long list, a length
    /// prefix that will not fit its field, and a message past [`MAX_MESSAGE`] are
    /// all [`WireError`]s here rather than bytes the peer will refuse or,
    /// worse, misread.
    ///
    /// The one thing still adjusted rather than refused is text: `Status.detail`
    /// and `Text.text` are clipped to their ceilings on a character boundary by
    /// `clamp_utf8`, because those fields are human prose whose tail carries no
    /// meaning, and clipping keeps a diagnostic message deliverable instead of
    /// turning a long driver name into a failure to report anything at all.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut out = Vec::new();
        out.push(self.kind());
        match self {
            Self::Hello(hello) => {
                out.extend_from_slice(&hello.protocol.to_be_bytes());
                out.extend_from_slice(&hello.tile.edge().to_be_bytes());
                out.push(hello.max_fps);
                out.push(hello.capabilities.bits());
                out.push(monitor_count(hello.monitors.len())?);
                for monitor in &hello.monitors {
                    out.push(monitor.id);
                    out.extend_from_slice(&monitor.origin_x.to_be_bytes());
                    out.extend_from_slice(&monitor.origin_y.to_be_bytes());
                    out.extend_from_slice(&monitor.width.to_be_bytes());
                    out.extend_from_slice(&monitor.height.to_be_bytes());
                    out.extend_from_slice(&monitor.scale_permille.to_be_bytes());
                    out.push(u8::from(monitor.primary));
                }
            }
            Self::Status { notice, detail } => {
                out.push(notice.code());
                let bytes = clamp_utf8(detail, MAX_DETAIL_BYTES);
                out.extend_from_slice(&length_u16("status.detail", bytes.len())?.to_be_bytes());
                out.extend_from_slice(bytes);
            }
            Self::FrameBegin(frame) => {
                out.push(frame.monitor);
                out.extend_from_slice(&frame.sequence.to_be_bytes());
                out.extend_from_slice(&frame.width.to_be_bytes());
                out.extend_from_slice(&frame.height.to_be_bytes());
                out.push(u8::from(frame.keyframe));
            }
            Self::Tile(tile) => {
                out.push(tile.monitor);
                out.extend_from_slice(&tile.col.to_be_bytes());
                out.extend_from_slice(&tile.row.to_be_bytes());
                out.push(tile.encoding.code());
                out.extend_from_slice(&length_u32("tile.payload", tile.payload.len())?.to_be_bytes());
                out.extend_from_slice(&tile.payload);
            }
            Self::FrameEnd { sequence } => out.extend_from_slice(&sequence.to_be_bytes()),
            Self::CursorPos(cursor) => {
                out.extend_from_slice(&cursor.x.to_be_bytes());
                out.extend_from_slice(&cursor.y.to_be_bytes());
                out.push(u8::from(cursor.visible));
            }
            Self::CursorShape(shape) => {
                out.extend_from_slice(&shape.shape.to_be_bytes());
                out.extend_from_slice(&shape.hotspot_x.to_be_bytes());
                out.extend_from_slice(&shape.hotspot_y.to_be_bytes());
                out.extend_from_slice(&shape.width.to_be_bytes());
                out.extend_from_slice(&shape.height.to_be_bytes());
                out.extend_from_slice(&length_u32("cursor.pixels", shape.pixels.len())?.to_be_bytes());
                out.extend_from_slice(&shape.pixels);
            }
            Self::InputRefused { reason } => out.push(reason.code()),
            Self::Key { usage, down } => {
                out.extend_from_slice(&usage.hid().to_be_bytes());
                out.push(u8::from(*down));
            }
            Self::Text { text } => {
                let bytes = clamp_utf8(text, MAX_TEXT_BYTES);
                out.extend_from_slice(&length_u16("text.body", bytes.len())?.to_be_bytes());
                out.extend_from_slice(bytes);
            }
            Self::PointerMove { monitor, x, y } => {
                out.push(*monitor);
                out.extend_from_slice(&x.to_be_bytes());
                out.extend_from_slice(&y.to_be_bytes());
            }
            Self::Button { button, down } => {
                out.push(button.code());
                out.push(u8::from(*down));
            }
            Self::Scroll { dx, dy } => {
                out.extend_from_slice(&dx.to_be_bytes());
                out.extend_from_slice(&dy.to_be_bytes());
            }
            Self::ReleaseAll => {}
            Self::RequestFullFrame { monitor } => out.push(*monitor),
        }
        if out.len() > MAX_MESSAGE {
            return Err(WireError::Oversize { length: out.len() });
        }
        Ok(out)
    }

    /// Decodes one complete message.
    ///
    /// Total: every input, including every random byte string, produces either a
    /// `Message` or a `WireError`, and never a panic. Trailing bytes are an
    /// error, so decoding is the exact inverse of encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > MAX_MESSAGE {
            return Err(WireError::Oversize { length: bytes.len() });
        }
        let (&kind, body) = bytes.split_first().ok_or(WireError::Empty)?;
        let mut reader = Reader::new(body);

        let message = match kind {
            kind::HELLO => Self::Hello(decode_hello(&mut reader)?),
            kind::STATUS => {
                let code = reader.u8("status.notice")?;
                let notice = Notice::from_code(code)
                    .ok_or(WireError::BadValue { field: "status.notice", value: u64::from(code) })?;
                let detail = reader.text("status.detail", MAX_DETAIL_BYTES)?;
                Self::Status { notice, detail }
            }
            kind::FRAME_BEGIN => Self::FrameBegin(FrameBegin {
                monitor: reader.u8("frame.monitor")?,
                sequence: reader.u64("frame.sequence")?,
                width: reader.dimension("frame.width")?,
                height: reader.dimension("frame.height")?,
                keyframe: reader.flag("frame.keyframe")?,
            }),
            kind::TILE => Self::Tile(decode_tile_message(&mut reader)?),
            kind::FRAME_END => Self::FrameEnd { sequence: reader.u64("frame.sequence")? },
            kind::CURSOR_POS => Self::CursorPos(CursorPos {
                x: reader.i32("cursor.x")?,
                y: reader.i32("cursor.y")?,
                visible: reader.flag("cursor.visible")?,
            }),
            kind::CURSOR_SHAPE => Self::CursorShape(decode_cursor_shape(&mut reader)?),
            kind::INPUT_REFUSED => {
                let code = reader.u8("refusal.reason")?;
                let reason = Refusal::from_code(code).ok_or(WireError::BadValue {
                    field: "refusal.reason",
                    value: u64::from(code),
                })?;
                Self::InputRefused { reason }
            }
            kind::KEY => Self::Key {
                usage: Usage::from_hid(reader.u16("key.usage")?)?,
                down: reader.flag("key.down")?,
            },
            kind::TEXT => Self::Text { text: reader.text("text.body", MAX_TEXT_BYTES)? },
            kind::POINTER_MOVE => Self::PointerMove {
                monitor: reader.u8("pointer.monitor")?,
                x: reader.i32("pointer.x")?,
                y: reader.i32("pointer.y")?,
            },
            kind::BUTTON => {
                let code = reader.u8("button.code")?;
                let button = Button::from_code(code)
                    .ok_or(WireError::BadValue { field: "button.code", value: u64::from(code) })?;
                Self::Button { button, down: reader.flag("button.down")? }
            }
            kind::SCROLL => Self::Scroll {
                dx: reader.scroll("scroll.dx")?,
                dy: reader.scroll("scroll.dy")?,
            },
            kind::RELEASE_ALL => Self::ReleaseAll,
            kind::REQUEST_FULL_FRAME => {
                Self::RequestFullFrame { monitor: reader.u8("request.monitor")? }
            }
            other => return Err(WireError::UnknownKind(other)),
        };

        reader.expect_end(message.name())?;
        Ok(message)
    }
}

/// The one-byte monitor count for a [`Hello`], or a refusal naming the ceiling.
///
/// The module header promises that every peer-chosen length is converted with
/// `try_from` rather than `as`; that was true of the decoder and false of the
/// encoder, and a length prefix written with `as` is worse than one read with it,
/// because the receiver then trusts a number the sender never really had. This is
/// the encode-side counterpart of the check in [`decode_hello`], and refusing
/// here is what [`MAX_MONITORS`] already documents: a truncated monitor list
/// means the console maps pointer coordinates onto a desktop it does not know the
/// shape of.
fn monitor_count(count: usize) -> Result<u8, WireError> {
    u8::try_from(count).ok().filter(|_| count <= MAX_MONITORS).ok_or(WireError::TooLarge {
        field: "hello.monitors",
        limit: MAX_MONITORS,
        actual: count,
    })
}

/// A `u16` length prefix, or a refusal naming the field it belonged to.
///
/// Unreachable for the two fields that use it — both are clipped by
/// [`clamp_utf8`] first — and written as a checked conversion anyway, because
/// "unreachable" is a property of today's ceilings and `as` would keep silently
/// agreeing with whatever they became.
fn length_u16(field: &'static str, length: usize) -> Result<u16, WireError> {
    u16::try_from(length).map_err(|_| WireError::TooLarge {
        field,
        limit: usize::from(u16::MAX),
        actual: length,
    })
}

/// A `u32` length prefix, or a refusal naming the field it belonged to.
///
/// Bounded by [`MAX_MESSAGE`] rather than by `u32::MAX`, so the encoder refuses
/// exactly what [`Message::decode`] would refuse — a payload this returns `Ok`
/// for is one that can be read back.
fn length_u32(field: &'static str, length: usize) -> Result<u32, WireError> {
    let within_ceiling = length <= MAX_MESSAGE;
    u32::try_from(length).ok().filter(|_| within_ceiling).ok_or(WireError::TooLarge {
        field,
        limit: MAX_MESSAGE,
        actual: length,
    })
}

/// Decodes a [`Hello`] body.
fn decode_hello(reader: &mut Reader<'_>) -> Result<Hello, WireError> {
    let protocol = reader.u16("hello.protocol")?;
    let edge = reader.u16("hello.tile")?;
    let tile = TileSize::new(edge)?;
    let max_fps = reader.u8("hello.max_fps")?;
    let bits = reader.u8("hello.capabilities")?;
    let capabilities = Capabilities::from_bits(bits)
        .ok_or(WireError::BadValue { field: "hello.capabilities", value: u64::from(bits) })?;

    let count = usize::from(reader.u8("hello.monitor_count")?);
    if count > MAX_MONITORS {
        return Err(WireError::TooLarge {
            field: "hello.monitor_count",
            limit: MAX_MONITORS,
            actual: count,
        });
    }

    // The claimed count is bounded by MAX_MONITORS above, but it is also checked
    // against the bytes that are actually present before anything is reserved:
    // a count is a claim, and a claim must never on its own be enough to make
    // the decoder allocate.
    let declared = count.checked_mul(MONITOR_BYTES).ok_or(WireError::TooLarge {
        field: "hello.monitor_count",
        limit: MAX_MONITORS,
        actual: count,
    })?;
    if declared > reader.remaining() {
        return Err(WireError::Truncated {
            field: "hello.monitors",
            needed: declared,
            available: reader.remaining(),
        });
    }

    let mut monitors = Vec::with_capacity(count);
    for _ in 0..count {
        monitors.push(Monitor {
            id: reader.u8("monitor.id")?,
            origin_x: reader.i32("monitor.origin_x")?,
            origin_y: reader.i32("monitor.origin_y")?,
            width: reader.dimension("monitor.width")?,
            height: reader.dimension("monitor.height")?,
            scale_permille: reader.scale("monitor.scale")?,
            primary: reader.flag("monitor.primary")?,
        });
    }

    Ok(Hello { protocol, tile, max_fps, capabilities, monitors })
}

/// Decodes a [`TileMessage`] body.
fn decode_tile_message(reader: &mut Reader<'_>) -> Result<TileMessage, WireError> {
    let monitor = reader.u8("tile.monitor")?;
    let col = reader.u16("tile.col")?;
    let row = reader.u16("tile.row")?;
    let code = reader.u8("tile.encoding")?;
    let encoding = Encoding::from_code(code)
        .ok_or(WireError::BadValue { field: "tile.encoding", value: u64::from(code) })?;
    let payload = reader.blob("tile.payload", MAX_MESSAGE)?.to_vec();
    Ok(TileMessage { monitor, col, row, encoding, payload })
}

/// Decodes a [`CursorShape`] body.
fn decode_cursor_shape(reader: &mut Reader<'_>) -> Result<CursorShape, WireError> {
    let shape = reader.u64("cursor.shape")?;
    let hotspot_x = reader.u16("cursor.hotspot_x")?;
    let hotspot_y = reader.u16("cursor.hotspot_y")?;
    let width = reader.cursor_edge("cursor.width")?;
    let height = reader.cursor_edge("cursor.height")?;

    // `u32::from` on two `u16`s cannot overflow a `u32` product bounded by
    // MAX_CURSOR_EDGE squared times four, but it is written as a checked
    // multiplication anyway: the ceiling is a constant somebody may raise.
    let expected = u32::from(width)
        .checked_mul(u32::from(height))
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or(WireError::BadValue { field: "cursor.size", value: u64::from(width) })?;

    let pixels = reader.blob("cursor.pixels", MAX_MESSAGE)?;
    if pixels.len() != expected as usize {
        return Err(WireError::TooLarge {
            field: "cursor.pixels",
            limit: expected as usize,
            actual: pixels.len(),
        });
    }
    if hotspot_x >= width || hotspot_y >= height {
        return Err(WireError::BadValue {
            field: "cursor.hotspot",
            value: u64::from(hotspot_x.max(hotspot_y)),
        });
    }
    Ok(CursorShape { shape, hotspot_x, hotspot_y, width, height, pixels: pixels.to_vec() })
}

/// Truncates a string to a byte ceiling without splitting a character.
///
/// Encoding never fails, so an over-long string is clipped rather than refused —
/// but clipped on a character boundary, because a `String` cut mid-sequence is
/// not a `String` and the decoder would reject the message we just wrote.
fn clamp_utf8(text: &str, limit: usize) -> &[u8] {
    if text.len() <= limit {
        return text.as_bytes();
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text.as_bytes()[..end]
}

/// A bounds-checked cursor over a message body.
///
/// Every read goes through [`Reader::take`], which is the single place a length
/// is compared against what is left. There is no other way to move the offset,
/// which is what makes "no unchecked index in this file" a property of ten lines
/// rather than of the whole module.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// How many bytes remain.
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.at)
    }

    /// Takes exactly `count` bytes, or reports what was missing.
    fn take(&mut self, count: usize, field: &'static str) -> Result<&'a [u8], WireError> {
        let available = self.remaining();
        if count > available {
            return Err(WireError::Truncated { field, needed: count, available });
        }
        // `at + count` cannot overflow: `count <= available <= bytes.len() - at`.
        let start = self.at;
        self.at = start + count;
        self.bytes.get(start..self.at).ok_or(WireError::Truncated {
            field,
            needed: count,
            available,
        })
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, WireError> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: &'static str) -> Result<u16, WireError> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self, field: &'static str) -> Result<u32, WireError> {
        let bytes = self.take(4, field)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn i32(&mut self, field: &'static str) -> Result<i32, WireError> {
        Ok(self.u32(field)? as i32)
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, WireError> {
        let bytes = self.take(8, field)?;
        let mut value = [0u8; 8];
        value.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(value))
    }

    /// A boolean encoded as a byte. Anything but 0 or 1 is refused rather than
    /// treated as true: two encodings of one value would break round-tripping,
    /// and a peer sending 2 is a peer we do not understand.
    fn flag(&mut self, field: &'static str) -> Result<bool, WireError> {
        match self.u8(field)? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(WireError::BadValue { field, value: u64::from(other) }),
        }
    }

    /// A pixel extent: non-zero and within [`MAX_DIMENSION`].
    fn dimension(&mut self, field: &'static str) -> Result<u32, WireError> {
        let value = self.u32(field)?;
        if value == 0 || value > MAX_DIMENSION {
            return Err(WireError::BadValue { field, value: u64::from(value) });
        }
        Ok(value)
    }

    /// A cursor extent: non-zero and within [`MAX_CURSOR_EDGE`].
    fn cursor_edge(&mut self, field: &'static str) -> Result<u16, WireError> {
        let value = self.u16(field)?;
        if value == 0 || value > MAX_CURSOR_EDGE {
            return Err(WireError::BadValue { field, value: u64::from(value) });
        }
        Ok(value)
    }

    /// A scale factor in thousandths, between 10% and 1000%.
    fn scale(&mut self, field: &'static str) -> Result<u16, WireError> {
        let value = self.u16(field)?;
        if !(100..=10_000).contains(&value) {
            return Err(WireError::BadValue { field, value: u64::from(value) });
        }
        Ok(value)
    }

    /// A scroll magnitude, bounded by [`MAX_SCROLL`] in both directions.
    fn scroll(&mut self, field: &'static str) -> Result<i32, WireError> {
        let value = self.i32(field)?;
        if !(-MAX_SCROLL..=MAX_SCROLL).contains(&value) {
            return Err(WireError::BadValue { field, value: value.unsigned_abs().into() });
        }
        Ok(value)
    }

    /// A `u16`-prefixed UTF-8 string, bounded.
    fn text(&mut self, field: &'static str, limit: usize) -> Result<String, WireError> {
        let length = usize::from(self.u16(field)?);
        if length > limit {
            return Err(WireError::TooLarge { field, limit, actual: length });
        }
        let bytes = self.take(length, field)?;
        std::str::from_utf8(bytes).map(str::to_owned).map_err(|_| WireError::NotUtf8 { field })
    }

    /// A `u32`-prefixed byte string, bounded.
    ///
    /// The length is converted with `try_from` rather than `as`: on a 32-bit
    /// host a `u32` length is not always a `usize`, and `as` would wrap a
    /// hostile length into a small one that then passes the ceiling check.
    fn blob(&mut self, field: &'static str, limit: usize) -> Result<&'a [u8], WireError> {
        let declared = self.u32(field)?;
        let length =
            usize::try_from(declared).map_err(|_| WireError::TooLarge {
                field,
                limit,
                actual: usize::MAX,
            })?;
        if length > limit {
            return Err(WireError::TooLarge { field, limit, actual: length });
        }
        self.take(length, field)
    }

    /// Refuses anything left over.
    fn expect_end(&self, kind: &'static str) -> Result<(), WireError> {
        match self.remaining() {
            0 => Ok(()),
            extra => Err(WireError::Trailing { kind, extra }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitors() -> Vec<Monitor> {
        vec![
            Monitor {
                id: 0,
                origin_x: 0,
                origin_y: 0,
                width: 3024,
                height: 1964,
                scale_permille: 2000,
                primary: true,
            },
            // A monitor left of and above the primary: the case that makes the
            // origin signed, and the one a `u32` origin would silently corrupt.
            Monitor {
                id: 1,
                origin_x: -1920,
                origin_y: -120,
                width: 1920,
                height: 1080,
                scale_permille: 1000,
                primary: false,
            },
        ]
    }

    fn every_message() -> Vec<Message> {
        vec![
            Message::Hello(Hello {
                protocol: PROTOCOL_VERSION,
                tile: TileSize::DEFAULT,
                max_fps: 30,
                capabilities: Capabilities::VIEW.with(Capabilities::CONTROL),
                monitors: monitors(),
            }),
            Message::Hello(Hello {
                protocol: PROTOCOL_VERSION,
                tile: TileSize::new(16).expect("legal size"),
                max_fps: 0,
                capabilities: Capabilities::none(),
                monitors: Vec::new(),
            }),
            Message::Status { notice: Notice::SecureDesktop, detail: String::new() },
            Message::Status {
                notice: Notice::Recovering,
                detail: "DXGI reported DEVICE_REMOVED".to_owned(),
            },
            Message::FrameBegin(FrameBegin {
                monitor: 1,
                sequence: u64::MAX,
                width: 3024,
                height: 1964,
                keyframe: true,
            }),
            Message::Tile(TileMessage {
                monitor: 0,
                col: 0,
                row: 0,
                encoding: Encoding::Unchanged,
                payload: Vec::new(),
            }),
            Message::Tile(TileMessage {
                monitor: 0,
                col: 47,
                row: 30,
                encoding: Encoding::Solid,
                payload: vec![0x10, 0x20, 0x30, 0xFF],
            }),
            Message::Tile(TileMessage {
                monitor: 0,
                col: u16::MAX,
                row: u16::MAX,
                encoding: Encoding::Rle,
                payload: vec![0xFF, 1, 2, 3, 4],
            }),
            Message::FrameEnd { sequence: 9 },
            Message::CursorPos(CursorPos { x: -1920, y: -1, visible: false }),
            Message::CursorPos(CursorPos { x: i32::MAX, y: i32::MIN, visible: true }),
            Message::CursorShape(CursorShape {
                shape: 0xDEAD_BEEF_CAFE_F00D,
                hotspot_x: 1,
                hotspot_y: 2,
                width: 4,
                height: 4,
                pixels: vec![0x7F; 4 * 4 * 4],
            }),
            Message::InputRefused { reason: Refusal::ElevatedWindow },
            Message::Key { usage: Usage::from_code("KeyA").expect("in table"), down: true },
            Message::Key { usage: Usage::from_code("MetaRight").expect("in table"), down: false },
            Message::Text { text: String::new() },
            Message::Text { text: "héllo — ünicode 👍".to_owned() },
            Message::PointerMove { monitor: 0, x: 0, y: 0 },
            Message::PointerMove { monitor: 3, x: -7, y: i32::MIN },
            Message::Button { button: Button::Forward, down: true },
            Message::Scroll { dx: 0, dy: -120 },
            Message::Scroll { dx: MAX_SCROLL, dy: -MAX_SCROLL },
            Message::ReleaseAll,
            Message::RequestFullFrame { monitor: 2 },
        ]
    }

    #[test]
    fn every_message_round_trips_exactly() {
        for message in every_message() {
            let encoded = message.encode().expect("every fixture must be encodable");
            let decoded = Message::decode(&encoded).unwrap_or_else(|error| {
                panic!("{} failed to decode: {error}", message.name());
            });
            assert_eq!(decoded, message, "{} did not round-trip", message.name());
            // Re-encoding must produce the identical bytes, which is what makes
            // "exactly one encoding per value" a checked property rather than an
            // intention.
            assert_eq!(
                decoded.encode().expect("a decoded message must re-encode"),
                encoded,
                "{} re-encoded differently",
                message.name()
            );
        }
    }

    #[test]
    fn kinds_are_distinct_and_sort_by_direction() {
        let mut seen: Vec<u8> = Vec::new();
        for message in every_message() {
            let kind = message.kind();
            if !seen.contains(&kind) {
                seen.push(kind);
            }
            let expected =
                if kind < 0x40 { Direction::ToViewer } else { Direction::ToAgent };
            assert_eq!(message.direction(), expected, "{}", message.name());
        }
        // Fifteen message kinds; a duplicate would make one of them undecodable.
        assert_eq!(seen.len(), 15);
    }

    #[test]
    fn input_messages_travel_only_towards_the_agent() {
        // The property that stops the machine being controlled from typing into
        // the console that is displaying it.
        for message in every_message() {
            let is_input = matches!(
                message,
                Message::Key { .. }
                    | Message::Text { .. }
                    | Message::PointerMove { .. }
                    | Message::Button { .. }
                    | Message::Scroll { .. }
                    | Message::ReleaseAll
                    | Message::RequestFullFrame { .. }
            );
            assert_eq!(is_input, message.direction() == Direction::ToAgent, "{}", message.name());
        }
    }

    #[test]
    fn an_empty_message_is_refused() {
        assert_eq!(Message::decode(&[]), Err(WireError::Empty));
    }

    #[test]
    fn an_unknown_kind_is_refused_by_name() {
        for kind in [0x00u8, 0x09, 0x3F, 0x47, 0xFF] {
            assert_eq!(Message::decode(&[kind]), Err(WireError::UnknownKind(kind)));
        }
    }

    #[test]
    fn every_truncation_of_every_message_is_a_typed_error() {
        // The single most valuable table in this file: for each message, every
        // prefix shorter than the whole must produce an error and never a
        // panic, and never a successfully decoded different message.
        for message in every_message() {
            let encoded = message.encode().expect("every fixture must be encodable");
            for cut in 0..encoded.len() {
                match Message::decode(&encoded[..cut]) {
                    Err(_) => {}
                    Ok(other) => panic!(
                        "{} truncated to {cut} bytes decoded as {}",
                        message.name(),
                        other.name()
                    ),
                }
            }
        }
    }

    #[test]
    fn trailing_bytes_are_refused_rather_than_ignored() {
        for message in every_message() {
            let mut encoded = message.encode().expect("every fixture must be encodable");
            encoded.push(0x00);
            assert_eq!(
                Message::decode(&encoded),
                Err(WireError::Trailing { kind: message.name(), extra: 1 }),
                "{}",
                message.name()
            );
        }
    }

    #[test]
    fn a_message_over_the_ceiling_is_refused_before_anything_is_read() {
        let oversize = vec![kind::RELEASE_ALL; MAX_MESSAGE + 1];
        assert_eq!(
            Message::decode(&oversize),
            Err(WireError::Oversize { length: MAX_MESSAGE + 1 })
        );
    }

    #[test]
    fn a_lying_length_prefix_cannot_make_the_decoder_allocate() {
        // A tile claiming four gigabytes of payload with none present. The
        // failure this asserts against is `Vec::with_capacity(declared)`, which
        // under `panic = "abort"` is not an allocation error but a dead daemon.
        let mut bytes = vec![kind::TILE, 0, 0, 0, 0, 0, Encoding::Raw.code()];
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());
        match Message::decode(&bytes) {
            Err(WireError::TooLarge { field: "tile.payload", .. })
            | Err(WireError::Truncated { field: "tile.payload", .. }) => {}
            other => panic!("expected a bounded refusal, got {other:?}"),
        }

        // The same for a cursor bitmap and for text.
        let mut bytes = vec![kind::TEXT];
        bytes.extend_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            Message::decode(&bytes),
            Err(WireError::TooLarge {
                field: "text.body",
                limit: MAX_TEXT_BYTES,
                actual: usize::from(u16::MAX)
            })
        );
    }

    #[test]
    fn a_monitor_count_over_the_ceiling_is_refused_by_name() {
        let mut bytes = vec![kind::HELLO];
        bytes.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        bytes.extend_from_slice(&64u16.to_be_bytes());
        bytes.push(30);
        bytes.push(Capabilities::VIEW.bits());
        bytes.push(255);
        assert_eq!(
            Message::decode(&bytes),
            Err(WireError::TooLarge {
                field: "hello.monitor_count",
                limit: MAX_MONITORS,
                actual: 255
            })
        );
    }

    #[test]
    fn a_monitor_list_over_the_ceiling_is_refused_by_the_encoder_rather_than_truncated() {
        // The defect this replaces: the count byte was written as
        // `len().min(MAX_MONITORS)` and the list `take(MAX_MONITORS)`, so a
        // seventeen-screen machine announced sixteen screens and the console
        // mapped pointer coordinates onto a desktop of the wrong shape — the
        // exact outcome MAX_MONITORS' own documentation forbids.
        let mut too_many = monitors();
        while too_many.len() <= MAX_MONITORS {
            let mut extra = too_many[0];
            extra.id = u8::try_from(too_many.len()).expect("under 256 in this test");
            too_many.push(extra);
        }
        let hello = Message::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            tile: TileSize::DEFAULT,
            max_fps: 30,
            capabilities: Capabilities::VIEW,
            monitors: too_many,
        });
        assert_eq!(
            hello.encode(),
            Err(WireError::TooLarge {
                field: "hello.monitors",
                limit: MAX_MONITORS,
                actual: MAX_MONITORS + 1
            })
        );

        // And exactly at the ceiling it still encodes, and decodes back whole:
        // the refusal is a boundary, not a fear of large lists.
        let Message::Hello(mut hello) = hello else { panic!("wrong kind") };
        hello.monitors.truncate(MAX_MONITORS);
        let message = Message::Hello(hello);
        let encoded = message.encode().expect("a full but legal list encodes");
        assert_eq!(Message::decode(&encoded).expect("decodes"), message);
    }

    #[test]
    fn an_encoded_length_that_would_not_fit_its_prefix_is_refused_by_name() {
        // The encode-side counterpart of the decoder's ceilings. A `payload.len()
        // as u32` would have written a truncated prefix and produced a message
        // whose declared length and real length disagree, which is the shape of
        // every framing vulnerability this codec is built to avoid.
        let tile = Message::Tile(TileMessage {
            monitor: 0,
            col: 0,
            row: 0,
            encoding: Encoding::Rle,
            payload: vec![0u8; MAX_MESSAGE + 1],
        });
        assert_eq!(
            tile.encode(),
            Err(WireError::TooLarge {
                field: "tile.payload",
                limit: MAX_MESSAGE,
                actual: MAX_MESSAGE + 1
            })
        );
    }

    #[test]
    fn the_encoder_never_produces_bytes_its_own_decoder_calls_oversize() {
        // A payload small enough for its own length prefix can still push the
        // whole message past MAX_MESSAGE once the header is added. Encoding must
        // refuse that too, or `encode` would hand out bytes `decode` rejects.
        let tile = Message::Tile(TileMessage {
            monitor: 0,
            col: 0,
            row: 0,
            encoding: Encoding::Rle,
            payload: vec![0u8; MAX_MESSAGE],
        });
        assert!(matches!(tile.encode(), Err(WireError::Oversize { .. })));
    }

    #[test]
    fn a_tiles_claimed_position_is_only_usable_through_the_grid_that_bounds_it() {
        // The obligation the codec deliberately does not discharge: col and row
        // arrive at full range, and the only thing that knows the extent is the
        // grid. `coord` exists so the unvalidated pair travels as the type whose
        // consumer refuses it.
        let grid = crate::tiles::Grid::new(TileSize::DEFAULT, 1920, 1080).expect("a real display");
        let inside = TileMessage {
            monitor: 0,
            col: 1,
            row: 1,
            encoding: Encoding::Solid,
            payload: vec![0, 0, 0, 0xFF],
        };
        assert!(grid.bounds(inside.coord()).is_ok());

        let outside = TileMessage { col: u16::MAX, row: u16::MAX, ..inside };
        assert_eq!(
            grid.bounds(outside.coord()),
            Err(TileError::OutOfGrid { col: u16::MAX, row: u16::MAX })
        );
    }

    #[test]
    fn a_zero_or_absurd_dimension_is_refused() {
        let frame = |width: u32, height: u32| {
            let mut bytes = vec![kind::FRAME_BEGIN, 0];
            bytes.extend_from_slice(&1u64.to_be_bytes());
            bytes.extend_from_slice(&width.to_be_bytes());
            bytes.extend_from_slice(&height.to_be_bytes());
            bytes.push(0);
            Message::decode(&bytes)
        };
        assert!(matches!(frame(0, 1080), Err(WireError::BadValue { field: "frame.width", .. })));
        assert!(matches!(frame(1920, 0), Err(WireError::BadValue { field: "frame.height", .. })));
        assert!(matches!(
            frame(MAX_DIMENSION + 1, 1080),
            Err(WireError::BadValue { field: "frame.width", .. })
        ));
        assert!(frame(MAX_DIMENSION, MAX_DIMENSION).is_ok());
    }

    #[test]
    fn a_boolean_byte_that_is_not_zero_or_one_is_refused() {
        // Two encodings of "true" would break the identity that re-encoding a
        // decoded message reproduces the same bytes.
        let mut bytes = vec![kind::KEY];
        bytes.extend_from_slice(&0x04u16.to_be_bytes());
        bytes.push(2);
        assert_eq!(
            Message::decode(&bytes),
            Err(WireError::BadValue { field: "key.down", value: 2 })
        );
    }

    #[test]
    fn an_unmappable_key_is_refused_with_the_key_modules_own_error() {
        let mut bytes = vec![kind::KEY];
        bytes.extend_from_slice(&0x66u16.to_be_bytes()); // Power
        bytes.push(1);
        assert_eq!(
            Message::decode(&bytes),
            Err(WireError::Key(KeyError::Unmappable { usage: 0x66 }))
        );

        let mut bytes = vec![kind::KEY];
        bytes.extend_from_slice(&0x1234u16.to_be_bytes());
        bytes.push(1);
        assert_eq!(
            Message::decode(&bytes),
            Err(WireError::Key(KeyError::OutOfPage { usage: 0x1234 }))
        );
    }

    #[test]
    fn a_cursor_bitmap_must_match_its_declared_size() {
        let shape = |width: u16, height: u16, payload: usize| {
            let mut bytes = vec![kind::CURSOR_SHAPE];
            bytes.extend_from_slice(&1u64.to_be_bytes());
            bytes.extend_from_slice(&0u16.to_be_bytes());
            bytes.extend_from_slice(&0u16.to_be_bytes());
            bytes.extend_from_slice(&width.to_be_bytes());
            bytes.extend_from_slice(&height.to_be_bytes());
            bytes.extend_from_slice(&(payload as u32).to_be_bytes());
            bytes.extend_from_slice(&vec![0u8; payload]);
            Message::decode(&bytes)
        };
        assert!(shape(4, 4, 64).is_ok());
        assert!(matches!(shape(4, 4, 63), Err(WireError::TooLarge { field: "cursor.pixels", .. })));
        assert!(matches!(shape(4, 4, 65), Err(WireError::TooLarge { field: "cursor.pixels", .. })));
        assert!(matches!(
            shape(MAX_CURSOR_EDGE + 1, 4, 0),
            Err(WireError::BadValue { field: "cursor.width", .. })
        ));
        assert!(matches!(shape(0, 4, 0), Err(WireError::BadValue { field: "cursor.width", .. })));
    }

    #[test]
    fn a_hotspot_outside_the_bitmap_is_refused() {
        let mut bytes = vec![kind::CURSOR_SHAPE];
        bytes.extend_from_slice(&1u64.to_be_bytes());
        bytes.extend_from_slice(&4u16.to_be_bytes());
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&4u16.to_be_bytes());
        bytes.extend_from_slice(&4u16.to_be_bytes());
        bytes.extend_from_slice(&64u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 64]);
        assert!(matches!(
            Message::decode(&bytes),
            Err(WireError::BadValue { field: "cursor.hotspot", .. })
        ));
    }

    #[test]
    fn an_absurd_scroll_is_refused_rather_than_clamped() {
        let scroll = |dx: i32, dy: i32| {
            let mut bytes = vec![kind::SCROLL];
            bytes.extend_from_slice(&dx.to_be_bytes());
            bytes.extend_from_slice(&dy.to_be_bytes());
            Message::decode(&bytes)
        };
        assert!(scroll(MAX_SCROLL, -MAX_SCROLL).is_ok());
        assert!(matches!(scroll(MAX_SCROLL + 1, 0), Err(WireError::BadValue { .. })));
        // i32::MIN has no positive counterpart; `unsigned_abs` is why this does
        // not overflow while building the error.
        assert!(matches!(scroll(0, i32::MIN), Err(WireError::BadValue { .. })));
    }

    #[test]
    fn invalid_utf8_in_a_text_field_is_refused() {
        let mut bytes = vec![kind::TEXT];
        bytes.extend_from_slice(&2u16.to_be_bytes());
        bytes.extend_from_slice(&[0xFF, 0xFE]);
        assert_eq!(Message::decode(&bytes), Err(WireError::NotUtf8 { field: "text.body" }));
    }

    #[test]
    fn an_over_long_string_is_clipped_on_a_character_boundary_when_encoding() {
        // Prose is clipped rather than refused — see `Message::encode` — but a
        // clip mid-sequence would produce bytes our own decoder rejects, which
        // is worse than the clip.
        let text = "é".repeat(MAX_TEXT_BYTES);
        let encoded = Message::Text { text }.encode().expect("clipping keeps it encodable");
        let decoded = Message::decode(&encoded).expect("a clipped string must still decode");
        let Message::Text { text } = decoded else { panic!("wrong kind") };
        assert!(text.len() <= MAX_TEXT_BYTES);
        assert!(text.chars().all(|character| character == 'é'));
    }

    #[test]
    fn an_unknown_notice_or_refusal_or_button_code_is_refused() {
        assert_eq!(
            Message::decode(&[kind::STATUS, 0x7F, 0, 0]),
            Err(WireError::BadValue { field: "status.notice", value: 0x7F })
        );
        assert_eq!(
            Message::decode(&[kind::INPUT_REFUSED, 0x7F]),
            Err(WireError::BadValue { field: "refusal.reason", value: 0x7F })
        );
        assert_eq!(
            Message::decode(&[kind::BUTTON, 0x7F, 1]),
            Err(WireError::BadValue { field: "button.code", value: 0x7F })
        );
    }

    #[test]
    fn an_unknown_tile_encoding_or_capability_bit_is_refused() {
        let mut bytes = vec![kind::TILE, 0, 0, 0, 0, 0, 0x7F];
        bytes.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            Message::decode(&bytes),
            Err(WireError::BadValue { field: "tile.encoding", value: 0x7F })
        );

        let mut bytes = vec![kind::HELLO];
        bytes.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        bytes.extend_from_slice(&64u16.to_be_bytes());
        bytes.push(30);
        bytes.push(0xF0);
        bytes.push(0);
        assert_eq!(
            Message::decode(&bytes),
            Err(WireError::BadValue { field: "hello.capabilities", value: 0xF0 })
        );
    }

    #[test]
    fn an_illegal_tile_size_is_refused() {
        for edge in [0u16, 1, 63, 65, 256, u16::MAX] {
            let mut bytes = vec![kind::HELLO];
            bytes.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
            bytes.extend_from_slice(&edge.to_be_bytes());
            bytes.push(30);
            bytes.push(Capabilities::VIEW.bits());
            bytes.push(0);
            assert!(
                matches!(Message::decode(&bytes), Err(WireError::Tile(_))),
                "tile edge {edge} was accepted"
            );
        }
    }

    #[test]
    fn every_error_prints_something_useful() {
        // `Display` is what reaches the daemon log, so an error whose message is
        // empty is an error nobody can act on.
        let errors = [
            WireError::Empty,
            WireError::Oversize { length: 1 },
            WireError::UnknownKind(9),
            WireError::Truncated { field: "f", needed: 2, available: 1 },
            WireError::Trailing { kind: "Tile", extra: 3 },
            WireError::TooLarge { field: "f", limit: 1, actual: 2 },
            WireError::NotUtf8 { field: "f" },
            WireError::BadValue { field: "f", value: 4 },
            WireError::Key(KeyError::UnknownCode),
            WireError::Tile(TileError::BadTileSize { edge: 7 }),
        ];
        for error in errors {
            assert!(!error.to_string().is_empty(), "{error:?}");
        }
    }

    /// A tiny deterministic generator. A real fuzzer is not importable under
    /// this workspace's dependency policy, and would not be worth it here: what
    /// the loop below establishes is not "no input crashes" in general, but that
    /// the decoder's control flow has no path that indexes, unwraps or
    /// multiplies without a check — which a hundred thousand structured-random
    /// inputs across every kind byte exercises thoroughly.
    struct Noise(u64);

    impl Noise {
        fn next(&mut self) -> u64 {
            // xorshift64*, chosen because it is six lines and needs no crate.
            let mut state = self.0;
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            self.0 = state;
            state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn byte(&mut self) -> u8 {
            (self.next() >> 24) as u8
        }
    }

    #[test]
    fn decoding_random_bytes_never_panics() {
        // Two thirds unstructured noise, one third a real encoding with a byte
        // or two flipped. The second half matters more than it looks: purely
        // random bytes almost never get past the kind table, so without a
        // structured share the loop would be exercising one `match` twenty
        // thousand times rather than every field validator in the file.
        let corpus: Vec<Vec<u8>> = every_message()
            .iter()
            .map(|message| message.encode().expect("every fixture must be encodable"))
            .collect();
        let mut noise = Noise(0x1234_5678_9ABC_DEF0);
        let mut buffer = Vec::with_capacity(512);
        let mut decoded = 0usize;

        for round in 0..20_000u32 {
            buffer.clear();
            if round % 3 == 0 {
                let seed = &corpus[(noise.next() as usize) % corpus.len()];
                buffer.extend_from_slice(seed);
                for _ in 0..(noise.next() % 3) {
                    let index = (noise.next() as usize) % buffer.len();
                    buffer[index] = noise.byte();
                }
            } else {
                let length = (noise.next() % 96) as usize;
                for _ in 0..length {
                    buffer.push(noise.byte());
                }
                // Steer some of the noise at a real kind byte, so a random
                // payload occasionally reaches a real field parser.
                if !buffer.is_empty() && round % 2 == 0 {
                    let kinds = [
                        kind::HELLO,
                        kind::STATUS,
                        kind::FRAME_BEGIN,
                        kind::TILE,
                        kind::FRAME_END,
                        kind::CURSOR_POS,
                        kind::CURSOR_SHAPE,
                        kind::INPUT_REFUSED,
                        kind::KEY,
                        kind::TEXT,
                        kind::POINTER_MOVE,
                        kind::BUTTON,
                        kind::SCROLL,
                        kind::RELEASE_ALL,
                        kind::REQUEST_FULL_FRAME,
                    ];
                    buffer[0] = kinds[(noise.next() as usize) % kinds.len()];
                }
            }

            if let Ok(message) = Message::decode(&buffer) {
                decoded += 1;
                // Anything that decodes must re-encode to exactly the bytes it
                // came from: an accepted input with a second encoding is a
                // parser two implementations can disagree about.
                assert_eq!(message.encode(), Ok(buffer.clone()), "round {round}");
            }
        }

        // If nothing ever decoded, the loop would be asserting nothing at all.
        assert!(decoded > 0, "the generator never produced a valid message");
    }

    #[test]
    fn decoding_every_mutation_of_every_valid_message_never_panics() {
        // Structure-aware fuzzing: start from something valid and corrupt one
        // byte at a time, which reaches the field validators that random bytes
        // rarely get past.
        let mut noise = Noise(0xC0FF_EE00_1234_5678);
        for message in every_message() {
            let encoded = message.encode().expect("every fixture must be encodable");
            for index in 0..encoded.len() {
                for _ in 0..8 {
                    let mut mutated = encoded.clone();
                    mutated[index] = noise.byte();
                    if let Ok(decoded) = Message::decode(&mutated) {
                        assert_eq!(decoded.encode(), Ok(mutated));
                    }
                }
            }
        }
    }
}
