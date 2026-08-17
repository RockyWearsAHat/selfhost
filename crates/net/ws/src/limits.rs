//! Every ceiling this crate enforces, in one place, with the reasoning attached.
//!
//! A WebSocket is the first thing this repository has ever put on a socket that
//! is *supposed* to stay open for hours and carry megabytes per second. Every
//! other ceiling in the tree assumes a short request — a 64 KiB relay body, a
//! 64 KiB admin body, a 25 MiB forward — and each of those numbers is enforced
//! once, at the moment the body is read, after which the connection is finished
//! with. A stream has no such moment. It is a standing invitation to allocate,
//! and the peer decides how often to accept it.
//!
//! So the limits live here rather than as literals sprinkled through the parser,
//! for three reasons. They are the numbers an operator will one day want to see
//! and change, and a number that is hard to find is a number that gets guessed
//! at. They are the inputs the parser's tests need to vary in order to prove that
//! a refusal happens at the boundary rather than somewhere near it. And gathering
//! them makes the total budget visible: a single stream can hold at most
//! `max_frame + max_message` bytes of our memory at once, and the reader below
//! never allocates beyond that no matter what the peer declares.
//!
//! # Why liveness is a limit and not a feature
//!
//! `HEAD_TIMEOUT` and `IDLE_TIMEOUT` in the proxy both stop at the end of the
//! request head; once a connection is upgraded, the copy loops that carry it are
//! untimed. Nothing above this crate will ever notice a half-open tunnel — not
//! the proxy, which is moving opaque bytes, and not the route, which is waiting
//! on a message that a dead peer will never send. A tunnel whose far end has
//! vanished without a FIN (a laptop that slept, a NAT that forgot, a VPN that
//! dropped) looks exactly like a quiet one. The only way to tell them apart is to
//! ask, and the only layer that can ask is this one. That is why
//! [`Limits::ping_interval`] and [`Limits::pong_deadline`] are not tuning knobs
//! but part of the contract: a stream that stops answering is closed, and the
//! console can then say *link lost, reconnecting* instead of showing an hour-old
//! screenshot as if it were live.

use std::time::Duration;

/// The largest single frame accepted, in bytes: 1 MiB.
///
/// This bounds one allocation. A frame header can declare a payload of nearly
/// 2^63 bytes and the peer never has to send a byte of it; refusing the header
/// on its declared length — before a buffer is sized and before we agree to keep
/// reading — is what keeps that declaration from costing us anything.
pub const MAX_FRAME: usize = 1024 * 1024;

/// The largest reassembled message accepted, in bytes: 4 MiB.
///
/// Fragmentation exists so a sender can begin transmitting before it knows the
/// total size, which means the total size is not knowable from any one header.
/// This is therefore the only bound on a fragmented message, and it is checked
/// after every fragment rather than at the end, so a peer cannot spend our
/// memory first and be refused afterwards.
pub const MAX_MESSAGE: usize = 4 * 1024 * 1024;

/// The largest number of frames one message may be split into.
///
/// [`MAX_MESSAGE`] bounds the bytes but not the count: four megabytes delivered
/// as four million one-byte continuations costs the same memory and several
/// thousand times the work, and it is free for the sender to do. Sixty-four
/// fragments across a four-megabyte ceiling means a peer that fragments finer
/// than 64 KiB on average is refused, which no real client does — a browser
/// sends a small message whole, and our own sender frames on tile boundaries.
pub const MAX_FRAGMENTS: usize = 64;

/// How often the server sends an unsolicited ping: every 15 seconds.
///
/// Chosen to match the proxy's `HEAD_TIMEOUT`, so the two halves of the same
/// connection notice a dead peer on the same timescale, and short enough that a
/// stalled desktop session is visible to a human as a hesitation rather than as
/// a minute of frozen picture.
pub const PING_INTERVAL: Duration = Duration::from_secs(15);

/// How long a peer may go without answering a ping before the stream is closed:
/// 45 seconds.
///
/// Three ping intervals. Two would make a single lost packet on a slow link look
/// like a dead peer; much more than three turns "the link is gone" into a report
/// that arrives long after the operator has noticed for themselves.
pub const PONG_DEADLINE: Duration = Duration::from_secs(45);

/// The longest any stream may live, regardless of health: 12 hours.
///
/// A stream is a standing authorisation, and an authorisation with no end is the
/// thing that turns a browser tab left open on Friday into an unattended door on
/// Monday. The session layer above has its own expiry and re-validates
/// independently; this is the floor beneath it, so that even a bug in that check
/// cannot produce an immortal connection. A caller with a shorter policy narrows
/// it; nothing widens it past the point where a human would have to be told the
/// stream is still open.
pub const MAX_LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);

/// The ceilings and timings one stream runs under.
///
/// Constructed with [`Limits::default`] and then narrowed by the caller; the
/// defaults are the constants in this module and are the values the daemon uses
/// unless configuration says otherwise. Every field is public because this is a
/// bag of numbers with no invariant *between* the numbers — the parser and the
/// assembler each check the one they own, with checked arithmetic, so no
/// combination of values can produce an overflow or an unbounded allocation.
/// A `max_message` smaller than `max_frame` is not a contradiction the type
/// needs to forbid: it simply means single-frame messages are capped by the
/// smaller number, which [`Limits::sane`] will tell a caller who cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest single frame payload accepted, in bytes.
    pub max_frame: usize,
    /// Largest reassembled message accepted, in bytes.
    pub max_message: usize,
    /// Largest number of frames one message may be split into.
    pub max_fragments: usize,
    /// How often to send an unsolicited ping.
    pub ping_interval: Duration,
    /// How long a peer may go without answering before the stream is closed.
    pub pong_deadline: Duration,
    /// The hard maximum lifetime of the stream.
    pub max_lifetime: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_frame: MAX_FRAME,
            max_message: MAX_MESSAGE,
            max_fragments: MAX_FRAGMENTS,
            ping_interval: PING_INTERVAL,
            pong_deadline: PONG_DEADLINE,
            max_lifetime: MAX_LIFETIME,
        }
    }
}

impl Limits {
    /// Whether these limits describe a stream that can actually carry traffic.
    ///
    /// This is a diagnostic, not a gate: nothing in the crate refuses to run on
    /// limits that fail it, because every individual check is already total and
    /// a zero ceiling simply refuses everything rather than misbehaving. It
    /// exists so a caller reading limits out of configuration can say *these
    /// numbers cannot work* at startup, instead of shipping a stream that closes
    /// every peer with a protocol error and looks like a codec bug.
    ///
    /// The pong deadline must exceed the ping interval, or the stream declares
    /// the peer dead before it has had a chance to answer the first ping.
    pub fn sane(&self) -> bool {
        self.max_frame > 0
            && self.max_message >= self.max_frame
            && self.max_fragments > 0
            && !self.ping_interval.is_zero()
            && self.pong_deadline > self.ping_interval
            && !self.max_lifetime.is_zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_are_sane() {
        assert!(Limits::default().sane());
    }

    #[test]
    fn a_pong_deadline_inside_the_ping_interval_is_not_sane() {
        let limits = Limits { pong_deadline: Duration::from_secs(5), ..Limits::default() };
        assert!(!limits.sane(), "the peer would be killed before it could answer");
    }

    #[test]
    fn a_message_ceiling_below_the_frame_ceiling_is_not_sane() {
        let limits = Limits { max_message: 1024, ..Limits::default() };
        assert!(!limits.sane());
    }

    #[test]
    fn zero_ceilings_are_not_sane() {
        assert!(!Limits { max_frame: 0, ..Limits::default() }.sane());
        assert!(!Limits { max_fragments: 0, ..Limits::default() }.sane());
        assert!(!Limits { max_lifetime: Duration::ZERO, ..Limits::default() }.sane());
        assert!(!Limits { ping_interval: Duration::ZERO, ..Limits::default() }.sane());
    }

    #[test]
    fn the_fragment_budget_leaves_room_for_real_traffic() {
        // The point of the count cap is to refuse pathological fragmentation,
        // not to refuse a full-sized message framed at the frame ceiling.
        let limits = Limits::default();
        assert!(limits.max_message / limits.max_frame <= limits.max_fragments);
    }
}
