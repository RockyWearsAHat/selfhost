//! The remote-desktop protocol, and the policy that decides who may drive it.
//!
//! This crate is the vocabulary two very different programs have to agree on: the
//! agent that owns a machine's pixels and its keyboard, and the console — either
//! console — that shows them to a person. It contains the message codec, the key
//! vocabulary, the tile codec, the cursor cache policy, the session state machine
//! and the authorisation tickets, and it contains **no platform integration at
//! all**. That absence is the point of the crate, not an accident of what has been
//! written so far: `unsafe_code = "forbid"` is set in its manifest, so a future
//! edit that reaches for a Win32 or CoreGraphics symbol fails to compile rather
//! than quietly turning the one crate both consoles link into a crate that only
//! builds on the machine being controlled.
//!
//! # Why every module here is pure
//!
//! Everything this crate parses is attacker-influenced. A tile payload, a key
//! usage, a cursor bitmap and a ticket all arrive from the far end of a socket,
//! and the workspace builds with `panic = "abort"` — so a parser that indexes out
//! of bounds does not return an error to a caller, it kills the process, and on
//! the owner box that process also serves 80/443, mail and the certificate store.
//! Every decode path here is therefore a *total* parser: bounds are checked before
//! every read, arithmetic on a length the peer chose is `checked_*`, and the
//! result is a typed error that names the field. The fuzz-shaped tests in
//! [`wire`] and [`tiles`] exist to keep that property true rather than to assert
//! it once.
//!
//! Purity also buys the thing that makes this project testable at all: the whole
//! recovery path — the crash loop, the secure desktop, the user logging out — is
//! driven in [`state`] by feeding it observations, so it is exercised on a laptop
//! with no display attached and no agent running. The same argument
//! `selfhost_supervisor`'s `policy` module makes about restart decisions applies
//! here with more force, because the failure modes involved (a UAC prompt, fast
//! user switching, an RDP session stealing the console) cannot be produced on
//! demand in CI at all.
//!
//! # The modules
//!
//! - [`wire`] — the message codec. One byte of kind, then a fixed layout per
//!   message. No variable-length integers, no self-describing container: a peer
//!   cannot make the parser allocate by lying about a length it never sends.
//! - [`keys`] — USB HID usage page 0x07 as the key vocabulary, and the held-key
//!   set that makes `RELEASE_ALL` possible. A closed table: the protocol cannot
//!   express a key that no platform can map.
//! - [`tiles`] — the 64×64 grid, the previous-frame diff, the four tile
//!   encodings, and the padded-row unpack that a macOS surface needs.
//! - [`cursor`] — the shape cache, which is why the pointer moves at the
//!   viewer's frame rate instead of the capture rate.
//! - [`state`] — the session state machine, which *names* the states a desktop
//!   can be in rather than reporting them all as errors.
//! - [`grant`] — the single-use ticket that authorises an upgrade, and the
//!   freshness rule that stops a twelve-hour cookie from being a keyboard.
//! - [`viewer`] — the impure session driver. Deliberately a stub; see its module
//!   documentation for what it will be and why it is not here yet.
//!
//! # What this crate deliberately does not decide
//!
//! It does not know what a monitor is attached to, what a HID usage means to
//! Win32 or to CoreGraphics, where a session id came from, or what the operator
//! put in their config. Those are `selfhost-screen`, `selfhost-admin` and
//! `selfhost-config`'s business respectively, and each of them passes what it
//! knows in as an argument. Nothing here reads a clock either: every function
//! that cares about time takes `now: Instant`, which is what lets a
//! thirty-second ticket lifetime and a four-hundred-failure backoff both be
//! tested in microseconds.

pub mod cursor;
pub mod grant;
pub mod keys;
pub mod state;
pub mod tiles;
pub mod viewer;
pub mod wire;

pub use cursor::{CursorPolicy, Emission, Pointer, ShapeCache, ShapeDecision, ShapeId};
pub use grant::{
    control_freshness, Authentication, Capabilities, Freshness, Grant, GrantError, Grants, Method,
    Policy, Redemption, SessionId, Ticket, TicketRequest, TICKET_BYTES, TICKET_TTL,
};
pub use keys::{HeldKeys, KeyDef, KeyError, KeyKind, Modifier, Side, Usage, KEYS};
pub use state::{
    Action, Limits, Notice, Observation, Phase, Session, Step, Surrender, Suspension,
};
pub use tiles::{
    Damage, Decoded, Encoding, Grid, MoveRect, Rect, Surface, TileCoord, TileError, TileSize,
    TileUpdate,
};
pub use wire::{
    Button, CursorPos, CursorShape, Direction, FrameBegin, Hello, Message, Monitor, Refusal,
    TileMessage, WireError, PROTOCOL_VERSION,
};
