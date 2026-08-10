//! Flow control: how many bytes a sender may have outstanding, and what it does
//! when the answer is none.
//!
//! # Credit is mandatory, and it is not an optimisation
//!
//! A sender may have at most `credit` payload bytes outstanding on a channel. The
//! receiver grants more as it consumes what has arrived. Without that rule, a
//! screen capture running at 30 frames a second on a fast machine, feeding a link
//! to a slow one, produces exactly one behaviour: an unbounded queue somewhere.
//! In the daemon that queue is the whole box's memory, and under `panic = "abort"`
//! an allocation failure is not an error — it is the process dying, taking the
//! reverse proxy, the DNS server and the mail server with it. Backpressure is
//! therefore the mechanism that keeps a busy desktop session from being a
//! denial-of-service against everything else the daemon does.
//!
//! Credit is also *forwarded across a relay hop*. When the owner splices a
//! browser's channel to a worker's, it does not invent credit of its own: it
//! passes grants through, so the browser's willingness to consume reaches all the
//! way back to the worker's capture loop. Backpressure that stops at the middle
//! box is backpressure that turns the middle box into the queue.
//!
//! # At zero credit, drop and merge — never queue
//!
//! This is the policy that makes a remote desktop usable, and it is why
//! [`LatestOnly`] lives here beside the accounting rather than in the desktop
//! crate. When a reliable stream — a file transfer — runs out of credit, the
//! correct behaviour is to wait: every byte matters and the order matters.
//!
//! When a *desktop* runs out of credit, waiting is the wrong answer, and so is
//! queueing. A frame that could not be sent a second ago describes a screen that
//! no longer exists. Sending it later means the viewer watches the past, and the
//! backlog grows for as long as the link is slower than the screen changes — so
//! the session degrades from "laggy" to "minutes behind" and never recovers. The
//! rule is therefore: **at zero credit the sender drops the frame it could not
//! send and merges its damage into the next one.** The viewer sees fewer frames,
//! each of them current. A remote desktop must show the present, not a backlog.
//!
//! Because that policy silently discards work, it is counted.
//! [`SendWindow::stalls`] and [`LatestOnly::dropped`] exist so the console can
//! show an operator that a session is stalling on credit, instead of leaving them
//! to guess why a desktop feels slow. A dropped frame that nobody can see the
//! count of is indistinguishable from a bug.
//!
//! # Everything here is pure
//!
//! No sockets, no clock, no tasks. A sender asks [`SendWindow::reserve`] whether
//! it may send, a receiver tells [`ReceiveWindow`] what arrived and what it
//! consumed, and the caller does the I/O. That is what lets the hundred-megabyte
//! transfer in this module's tests run as a loop over a struct, asserting the peak
//! outstanding byte count directly, with no network and no timing.

use std::fmt;

/// The window a channel starts with, in bytes.
///
/// Large enough that a well-connected link never stalls on a single frame —
/// 256 KiB covers a quarter of the largest legal mux payload several times over —
/// and small enough that sixty-four such channels commit sixteen mebibytes rather
/// than something unbounded.
pub const INITIAL_WINDOW: u32 = 256 * 1024;

/// The largest window a peer may grant a sender, in bytes.
///
/// A grant that would push the window past this is a protocol error rather than a
/// clamp, because there are only two ways to reach it: a peer that has lost track
/// of its own accounting, or a peer deliberately trying to remove the sender's
/// ceiling so the sender's own buffers become the queue. Neither is something to
/// continue after.
pub const MAX_WINDOW: u32 = 16 * 1024 * 1024;

/// One sender's allowance on one channel.
///
/// Debited by [`SendWindow::reserve`] as bytes are handed to the transport,
/// credited by [`SendWindow::grant`] when a `CREDIT` frame arrives. The difference
/// between what has been sent and what has been granted back is the number of
/// bytes the receiver is holding on our behalf, and it is bounded by the window —
/// which is the property the whole mechanism exists to provide.
#[derive(Debug, Clone)]
pub struct SendWindow {
    available: u32,
    sent: u64,
    granted: u64,
    stalls: u64,
}

impl SendWindow {
    /// A window opened with `initial` bytes of allowance.
    ///
    /// Clamped to [`MAX_WINDOW`]: the initial window is ours to choose, so an
    /// out-of-range value here is a programming mistake in this crate rather than
    /// something a peer did, and the sane response is the ceiling, not an error a
    /// caller would have to handle at every construction site.
    pub fn new(initial: u32) -> Self {
        Self { available: initial.min(MAX_WINDOW), sent: 0, granted: 0, stalls: 0 }
    }

    /// A window opened with [`INITIAL_WINDOW`].
    pub fn initial() -> Self {
        Self::new(INITIAL_WINDOW)
    }

    /// Bytes that may be sent right now.
    pub fn available(&self) -> u32 {
        self.available
    }

    /// Total payload bytes handed to the transport on this channel.
    pub fn sent(&self) -> u64 {
        self.sent
    }

    /// Total bytes the peer has granted since the window opened, excluding the
    /// initial allowance.
    pub fn granted(&self) -> u64 {
        self.granted
    }

    /// Bytes sent that the peer has not yet granted back.
    ///
    /// This is the number the flow-control scheme actually bounds: it can never
    /// exceed the largest window the peer has offered. A test that asserts this
    /// stays under a ceiling across a hundred megabytes is asserting that the
    /// receiver never has to buffer more than a window, which is the entire point.
    pub fn outstanding(&self) -> u64 {
        self.sent.saturating_sub(self.granted)
    }

    /// How many times a send was refused for want of credit.
    ///
    /// Surfaced to the operator. A session that is stalling constantly is a
    /// session whose link cannot carry what its capture loop is producing, and
    /// that is a fact about the network, not a bug to be hunted in the encoder.
    pub fn stalls(&self) -> u64 {
        self.stalls
    }

    /// Everything the console needs to render this channel's flow control.
    pub fn stats(&self) -> CreditStats {
        CreditStats {
            available: self.available,
            outstanding: self.outstanding(),
            sent: self.sent,
            granted: self.granted,
            stalls: self.stalls,
        }
    }

    /// Applies a `CREDIT` grant from the peer.
    ///
    /// A zero grant is refused rather than ignored: it conveys nothing, and a peer
    /// emitting them in a loop is a peer spinning our reader for free. A grant that
    /// would take the window past [`MAX_WINDOW`] is refused for the reason
    /// [`MAX_WINDOW`] documents.
    pub fn grant(&mut self, bytes: u32) -> Result<(), CreditError> {
        if bytes == 0 {
            return Err(CreditError::EmptyGrant);
        }
        let widened = self.available.checked_add(bytes).ok_or(CreditError::WindowOverflow {
            available: self.available,
            grant: bytes,
        })?;
        if widened > MAX_WINDOW {
            return Err(CreditError::WindowOverflow { available: self.available, grant: bytes });
        }
        self.available = widened;
        self.granted = self.granted.saturating_add(u64::from(bytes));
        Ok(())
    }

    /// Asks to send `bytes` of payload, debiting the window if it can be afforded.
    ///
    /// The three answers are genuinely different actions, which is why they are
    /// three variants rather than a `bool`:
    ///
    /// - [`Reservation::Granted`] — send it.
    /// - [`Reservation::Stalled`] — wait for credit (a reliable stream) or drop and
    ///   merge (a desktop). Counted in [`SendWindow::stalls`].
    /// - [`Reservation::Unsatisfiable`] — no future grant can ever be large enough,
    ///   so waiting is a deadlock. The channel must be closed. Without this
    ///   variant, a caller that offered a chunk larger than any legal window would
    ///   wait for a grant that cannot arrive, and the symptom would be a session
    ///   that hangs with no error anywhere.
    ///
    /// A zero-byte reservation is always granted and debits nothing; an empty
    /// `DATA` frame is legal and costs no credit.
    pub fn reserve(&mut self, bytes: u32) -> Reservation {
        if bytes == 0 {
            return Reservation::Granted;
        }
        if bytes > MAX_WINDOW {
            return Reservation::Unsatisfiable { limit: MAX_WINDOW };
        }
        match self.available.checked_sub(bytes) {
            Some(remaining) => {
                self.available = remaining;
                self.sent = self.sent.saturating_add(u64::from(bytes));
                Reservation::Granted
            }
            None => {
                self.stalls = self.stalls.saturating_add(1);
                Reservation::Stalled { short_by: bytes - self.available }
            }
        }
    }
}

/// What [`SendWindow::reserve`] decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reservation {
    /// The window covered it and has been debited.
    Granted,
    /// Not enough credit right now.
    Stalled {
        /// How many more bytes of credit are needed for this exact send.
        short_by: u32,
    },
    /// Larger than any window this protocol allows; no grant can ever cover it.
    Unsatisfiable {
        /// The largest window a peer may ever offer.
        limit: u32,
    },
}

/// One receiver's side of the same accounting.
///
/// The receiver owes the sender an answer: it must eventually grant back every
/// byte it consumes, or the sender stalls forever. It must also notice when the
/// sender exceeds what it was allowed, because a peer that ignores credit is a
/// peer trying to make this side's buffers grow without limit — which is the
/// attack the whole mechanism exists to prevent, so it is refused loudly rather
/// than absorbed.
///
/// Grants are not emitted per frame. A `CREDIT` for every `DATA` would double the
/// frame count on a busy channel to say something the peer can mostly infer. The
/// rule here is the usual one: advertise once at least half the window has been
/// freed, so the sender's allowance is replenished before it runs out and the
/// steady state has no stall in it at all.
#[derive(Debug, Clone)]
pub struct ReceiveWindow {
    capacity: u32,
    /// Arrived and not yet consumed by the application.
    held: u32,
    /// Consumed and not yet advertised back to the sender.
    ungranted: u32,
    received: u64,
    consumed: u64,
}

impl ReceiveWindow {
    /// A receive window of `capacity` bytes, matching the sender's initial window.
    ///
    /// Clamped to [`MAX_WINDOW`], for the reason [`SendWindow::new`] gives.
    pub fn new(capacity: u32) -> Self {
        Self { capacity: capacity.min(MAX_WINDOW), held: 0, ungranted: 0, received: 0, consumed: 0 }
    }

    /// A receive window of [`INITIAL_WINDOW`] bytes.
    pub fn initial() -> Self {
        Self::new(INITIAL_WINDOW)
    }

    /// The window this receiver advertises.
    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    /// Bytes that have arrived and not yet been consumed.
    pub fn held(&self) -> u32 {
        self.held
    }

    /// Total bytes received on this channel.
    pub fn received(&self) -> u64 {
        self.received
    }

    /// Total bytes consumed on this channel.
    pub fn consumed(&self) -> u64 {
        self.consumed
    }

    /// Records that `bytes` of payload arrived.
    ///
    /// Refuses with [`CreditError::PeerOverranWindow`] when the peer sent more than
    /// it had been granted. This is not a soft condition to be recovered from: the
    /// peer is either buggy or hostile, and continuing means accepting an unbounded
    /// amount of data from something that has demonstrated it will not stop.
    pub fn receive(&mut self, bytes: u32) -> Result<(), CreditError> {
        let committed = self.held.saturating_add(self.ungranted);
        let headroom = self.capacity.saturating_sub(committed);
        if bytes > headroom {
            return Err(CreditError::PeerOverranWindow { by: bytes - headroom, capacity: self.capacity });
        }
        self.held += bytes;
        self.received = self.received.saturating_add(u64::from(bytes));
        Ok(())
    }

    /// Records that `bytes` of what arrived have been dealt with.
    ///
    /// Consumed bytes become grantable. Consuming more than has arrived is a bug in
    /// this process, not in the peer, and is reported as one rather than saturating
    /// — a silent saturation here would over-grant, which hands the peer a larger
    /// window than we can hold.
    pub fn consume(&mut self, bytes: u32) -> Result<(), CreditError> {
        if bytes > self.held {
            return Err(CreditError::ConsumedMoreThanArrived { held: self.held, consumed: bytes });
        }
        self.held -= bytes;
        self.ungranted = self.ungranted.saturating_add(bytes);
        self.consumed = self.consumed.saturating_add(u64::from(bytes));
        Ok(())
    }

    /// The grant this receiver should send now, if any, and clears it.
    ///
    /// `None` until at least half the window has been freed; see the type's
    /// documentation for why the threshold exists.
    pub fn take_grant(&mut self) -> Option<u32> {
        if self.ungranted >= self.grant_threshold() {
            self.take_grant_now()
        } else {
            None
        }
    }

    /// The grant this receiver owes, regardless of the threshold, and clears it.
    ///
    /// For the moment a stream goes idle: the threshold optimises the busy case,
    /// but a sender left one byte short of its next send because the receiver was
    /// waiting for a rounder number would hang until something else happened.
    pub fn take_grant_now(&mut self) -> Option<u32> {
        if self.ungranted == 0 {
            return None;
        }
        Some(std::mem::take(&mut self.ungranted))
    }

    /// Bytes consumed but not yet advertised back to the sender.
    pub fn ungranted(&self) -> u32 {
        self.ungranted
    }

    /// At least half the window, and never zero.
    ///
    /// The floor matters for tiny windows used in tests and in constrained
    /// channels: `capacity / 2` of a one-byte window is zero, and a zero threshold
    /// means a `CREDIT` frame per byte.
    fn grant_threshold(&self) -> u32 {
        (self.capacity / 2).max(1)
    }
}

/// A snapshot of one channel's flow control, for the console's diagnostics panel.
///
/// Plain public fields: this is a report, not an invariant-holding type, and the
/// code that renders it should be able to read every number without a method call
/// per field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreditStats {
    /// Bytes the sender may send right now.
    pub available: u32,
    /// Bytes sent that the peer has not yet granted back.
    pub outstanding: u64,
    /// Total payload bytes sent on this channel.
    pub sent: u64,
    /// Total bytes granted by the peer, excluding the initial window.
    pub granted: u64,
    /// How many times a send was refused for want of credit.
    pub stalls: u64,
}

/// Something that can absorb a newer version of itself.
///
/// The seam that lets [`LatestOnly`] hold the drop-and-merge policy without
/// knowing anything about desktops. A desktop frame's `merge` is the union of the
/// two frames' damage rectangles; a status update's `merge` is simply taking the
/// newer value. Composition, not inheritance: the policy is here, the meaning of
/// "merge" is supplied by whoever is being flow-controlled.
///
/// Implementations must be *total* — merging must always succeed and must always
/// leave a value that describes everything both inputs described. A merge that
/// could fail would leave the caller holding two items and no way to send either,
/// which is exactly the queue this type exists to avoid.
pub trait Merge {
    /// Folds `newer` into `self`, so that `self` now describes both.
    fn merge(&mut self, newer: Self);
}

/// A one-slot outbox that drops and merges instead of queueing.
///
/// Hand it whatever the producer just made. If the previous item has not been sent
/// yet, the two are merged and one drop is counted. There is never more than one
/// item held, so the memory cost of a stalled channel is one item — not one item
/// per frame for as long as the stall lasts.
///
/// This is the type that implements "a remote desktop must show the present, not a
/// backlog", and [`LatestOnly::dropped`] is how an operator sees it happening.
#[derive(Debug, Clone)]
pub struct LatestOnly<T> {
    pending: Option<T>,
    dropped: u64,
    offered: u64,
}

impl<T> Default for LatestOnly<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> LatestOnly<T> {
    /// An empty outbox.
    pub fn new() -> Self {
        Self { pending: None, dropped: 0, offered: 0 }
    }

    /// Whether something is waiting to be sent.
    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// How many items were superseded before they could be sent.
    ///
    /// Reported to the operator beside [`SendWindow::stalls`]. The two together
    /// say "the link could not carry what the capture loop produced, and here is
    /// how much was discarded to keep the picture current".
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// How many items were offered in total.
    pub fn offered(&self) -> u64 {
        self.offered
    }

    /// Takes the pending item, if there is one.
    pub fn take(&mut self) -> Option<T> {
        self.pending.take()
    }

    /// A borrow of the pending item, for a caller sizing its next send.
    pub fn peek(&self) -> Option<&T> {
        self.pending.as_ref()
    }
}

impl<T: Merge> LatestOnly<T> {
    /// Offers a newly produced item.
    ///
    /// Merges into whatever is already waiting and counts a drop. Never grows, and
    /// never blocks.
    pub fn offer(&mut self, item: T) {
        self.offered = self.offered.saturating_add(1);
        match self.pending.as_mut() {
            Some(pending) => {
                pending.merge(item);
                self.dropped = self.dropped.saturating_add(1);
            }
            None => self.pending = Some(item),
        }
    }
}

/// Encodes a `CREDIT` payload: the grant, big-endian.
pub fn encode_grant(bytes: u32) -> [u8; 4] {
    bytes.to_be_bytes()
}

/// Decodes a `CREDIT` payload.
///
/// Exactly four bytes; trailing bytes are refused rather than ignored, for the
/// same forward-compatibility reason the rest of this protocol refuses them.
/// A zero grant is refused here rather than at [`SendWindow::grant`] as well, so
/// the frame is rejected before it can be counted as progress.
pub fn parse_grant(payload: &[u8]) -> Result<u32, CreditError> {
    let bytes: [u8; 4] = payload.try_into().map_err(|_| CreditError::MalformedGrant { length: payload.len() })?;
    let grant = u32::from_be_bytes(bytes);
    if grant == 0 {
        return Err(CreditError::EmptyGrant);
    }
    Ok(grant)
}

/// Why a flow-control operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditError {
    /// A `CREDIT` payload was not exactly four bytes.
    MalformedGrant {
        /// The payload length that arrived.
        length: usize,
    },
    /// A grant of zero bytes, which conveys nothing.
    EmptyGrant,
    /// A grant that would take the send window past [`MAX_WINDOW`].
    WindowOverflow {
        /// The window before the grant.
        available: u32,
        /// The grant that was refused.
        grant: u32,
    },
    /// The peer sent more than its credit allowed.
    PeerOverranWindow {
        /// How many bytes beyond the allowance arrived.
        by: u32,
        /// The window the peer had been given.
        capacity: u32,
    },
    /// This process claimed to consume more than has arrived. Ours, not theirs.
    ConsumedMoreThanArrived {
        /// Bytes actually held.
        held: u32,
        /// Bytes the caller claimed to consume.
        consumed: u32,
    },
}

impl fmt::Display for CreditError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedGrant { length } => write!(out, "a credit frame carried {length} bytes, not 4"),
            Self::EmptyGrant => out.write_str("a credit frame granted zero bytes"),
            Self::WindowOverflow { available, grant } => write!(
                out,
                "a grant of {grant} bytes on top of {available} would exceed the {MAX_WINDOW}-byte window ceiling"
            ),
            Self::PeerOverranWindow { by, capacity } => {
                write!(out, "the peer sent {by} bytes beyond its {capacity}-byte credit window")
            }
            Self::ConsumedMoreThanArrived { held, consumed } => {
                write!(out, "consumed {consumed} bytes but only {held} had arrived")
            }
        }
    }
}

impl std::error::Error for CreditError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_send_within_the_window_is_granted_and_debits_it() {
        let mut window = SendWindow::new(1000);
        assert_eq!(window.reserve(400), Reservation::Granted);
        assert_eq!(window.available(), 600);
        assert_eq!(window.sent(), 400);
        assert_eq!(window.outstanding(), 400);
        assert_eq!(window.stalls(), 0);
    }

    #[test]
    fn a_send_beyond_the_window_stalls_and_says_by_how_much() {
        let mut window = SendWindow::new(100);
        assert_eq!(window.reserve(150), Reservation::Stalled { short_by: 50 });
        assert_eq!(window.available(), 100, "a stalled send must not partially debit");
        assert_eq!(window.sent(), 0);
        assert_eq!(window.stalls(), 1);
    }

    #[test]
    fn a_send_larger_than_any_possible_window_is_unsatisfiable_rather_than_a_deadlock() {
        // Without this variant a caller waits for a grant that can never arrive,
        // and the symptom is a session that hangs with no error anywhere.
        let mut window = SendWindow::new(INITIAL_WINDOW);
        assert_eq!(window.reserve(MAX_WINDOW + 1), Reservation::Unsatisfiable { limit: MAX_WINDOW });
        assert_eq!(window.reserve(u32::MAX), Reservation::Unsatisfiable { limit: MAX_WINDOW });
        assert_eq!(window.stalls(), 0, "an impossible send is not a stall");
    }

    #[test]
    fn an_empty_send_costs_nothing() {
        let mut window = SendWindow::new(0);
        assert_eq!(window.reserve(0), Reservation::Granted);
        assert_eq!(window.sent(), 0);
    }

    #[test]
    fn a_grant_reopens_the_window() {
        let mut window = SendWindow::new(100);
        assert_eq!(window.reserve(100), Reservation::Granted);
        assert_eq!(window.reserve(1), Reservation::Stalled { short_by: 1 });
        window.grant(100).expect("grant");
        assert_eq!(window.available(), 100);
        assert_eq!(window.outstanding(), 0, "a grant acknowledges bytes the receiver has dealt with");
        assert_eq!(window.reserve(100), Reservation::Granted);
    }

    #[test]
    fn a_zero_grant_is_refused() {
        let mut window = SendWindow::new(10);
        assert_eq!(window.grant(0).unwrap_err(), CreditError::EmptyGrant);
    }

    #[test]
    fn a_grant_past_the_ceiling_is_refused_rather_than_clamped() {
        let mut window = SendWindow::new(MAX_WINDOW);
        assert_eq!(
            window.grant(1).unwrap_err(),
            CreditError::WindowOverflow { available: MAX_WINDOW, grant: 1 }
        );
        assert_eq!(window.available(), MAX_WINDOW, "a refused grant changes nothing");
        // And it cannot be reached by arithmetic overflow either.
        let mut small = SendWindow::new(1);
        assert!(matches!(small.grant(u32::MAX), Err(CreditError::WindowOverflow { .. })));
    }

    #[test]
    fn the_initial_window_is_clamped_to_the_ceiling() {
        assert_eq!(SendWindow::new(u32::MAX).available(), MAX_WINDOW);
        assert_eq!(ReceiveWindow::new(u32::MAX).capacity(), MAX_WINDOW);
        assert_eq!(SendWindow::initial().available(), INITIAL_WINDOW);
        assert_eq!(ReceiveWindow::initial().capacity(), INITIAL_WINDOW);
    }

    #[test]
    fn stats_report_every_number_the_console_shows() {
        let mut window = SendWindow::new(100);
        window.reserve(60);
        window.reserve(60);
        window.grant(60).expect("grant");
        let stats = window.stats();
        assert_eq!(stats.available, 100);
        assert_eq!(stats.sent, 60);
        assert_eq!(stats.granted, 60);
        assert_eq!(stats.outstanding, 0);
        assert_eq!(stats.stalls, 1);
    }

    #[test]
    fn a_receiver_grants_back_once_half_its_window_is_free() {
        let mut window = ReceiveWindow::new(1000);
        window.receive(400).expect("receive");
        window.consume(400).expect("consume");
        assert_eq!(window.take_grant(), None, "below the half-window threshold");
        window.receive(200).expect("receive");
        window.consume(200).expect("consume");
        assert_eq!(window.take_grant(), Some(600));
        assert_eq!(window.take_grant(), None, "a grant is only taken once");
        assert_eq!(window.received(), 600);
        assert_eq!(window.consumed(), 600);
    }

    #[test]
    fn an_idle_receiver_can_flush_a_small_grant() {
        let mut window = ReceiveWindow::new(1000);
        window.receive(10).expect("receive");
        window.consume(10).expect("consume");
        assert_eq!(window.take_grant(), None);
        assert_eq!(window.take_grant_now(), Some(10));
        assert_eq!(window.take_grant_now(), None);
    }

    #[test]
    fn the_grant_threshold_is_never_zero() {
        // A one-byte window would otherwise emit a CREDIT frame per byte.
        let mut window = ReceiveWindow::new(1);
        assert_eq!(window.take_grant(), None);
        window.receive(1).expect("receive");
        window.consume(1).expect("consume");
        assert_eq!(window.take_grant(), Some(1));
    }

    #[test]
    fn a_peer_that_overruns_its_window_is_refused_rather_than_absorbed() {
        // This is the attack the mechanism exists to stop: a peer that ignores
        // credit and keeps sending until this side's buffers are the problem.
        let mut window = ReceiveWindow::new(100);
        window.receive(100).expect("fills the window");
        assert_eq!(
            window.receive(1).unwrap_err(),
            CreditError::PeerOverranWindow { by: 1, capacity: 100 }
        );
        // Consuming without granting does not reopen the window: the sender does
        // not know about the consumption until a CREDIT frame says so.
        window.consume(100).expect("consume");
        assert_eq!(window.receive(1).unwrap_err(), CreditError::PeerOverranWindow { by: 1, capacity: 100 });
        // The grant is what reopens it.
        assert_eq!(window.take_grant(), Some(100));
        window.receive(100).expect("reopened");
    }

    #[test]
    fn consuming_more_than_arrived_is_reported_as_our_own_bug() {
        let mut window = ReceiveWindow::new(100);
        window.receive(10).expect("receive");
        assert_eq!(
            window.consume(11).unwrap_err(),
            CreditError::ConsumedMoreThanArrived { held: 10, consumed: 11 }
        );
        assert_eq!(window.held(), 10, "a refused consume changes nothing");
    }

    #[test]
    fn a_credit_payload_is_exactly_four_bytes() {
        assert_eq!(parse_grant(&encode_grant(70_000)).expect("parse"), 70_000);
        assert_eq!(parse_grant(&[0, 0, 0]).unwrap_err(), CreditError::MalformedGrant { length: 3 });
        assert_eq!(parse_grant(&[0, 0, 0, 0, 0]).unwrap_err(), CreditError::MalformedGrant { length: 5 });
        assert_eq!(parse_grant(&[0, 0, 0, 0]).unwrap_err(), CreditError::EmptyGrant);
        assert_eq!(parse_grant(&[]).unwrap_err(), CreditError::MalformedGrant { length: 0 });
    }

    /// One hundred megabytes, the size the plan names.
    const HUNDRED_MEGABYTES: u64 = 100 * 1024 * 1024;
    /// A deliberately small window, so the transfer stalls thousands of times.
    const SMALL_WINDOW: u32 = 64 * 1024;
    /// A plausible chunk: one read from a socket.
    const CHUNK: u32 = 16 * 1024;

    #[test]
    fn a_hundred_megabytes_through_a_64_kib_window_completes_with_a_bounded_peak_buffer() {
        // The property under test is not "the transfer finishes" — it is that the
        // receiver never has to hold more than one window at any point during it.
        // That is the whole reason credit is mandatory: the peak is a constant,
        // not a function of how much is being sent or of how much faster the
        // sender is than the link.
        let mut sender = SendWindow::new(SMALL_WINDOW);
        let mut receiver = ReceiveWindow::new(SMALL_WINDOW);

        let mut remaining = HUNDRED_MEGABYTES;
        let mut peak_outstanding = 0u64;
        let mut peak_held = 0u32;
        let mut steps = 0u64;

        while remaining > 0 {
            steps += 1;
            assert!(steps < 100_000, "the transfer must make progress, not spin");

            let chunk = u32::try_from(remaining.min(u64::from(CHUNK))).expect("bounded by CHUNK");
            match sender.reserve(chunk) {
                Reservation::Granted => {
                    remaining -= u64::from(chunk);
                    // The bytes cross the link and land in the receiver.
                    receiver.receive(chunk).expect("the sender never exceeds its credit");
                    peak_outstanding = peak_outstanding.max(sender.outstanding());
                    peak_held = peak_held.max(receiver.held());
                }
                Reservation::Stalled { .. } => {
                    // The receiving application drains what it is holding, and the
                    // grant that frees travels back to the sender.
                    let held = receiver.held();
                    receiver.consume(held).expect("consume what arrived");
                    let grant = receiver.take_grant_now().expect("something was consumed");
                    sender.grant(grant).expect("a grant we ourselves computed always fits");
                }
                Reservation::Unsatisfiable { limit } => panic!("chunk larger than the ceiling {limit}"),
            }
        }

        assert_eq!(sender.sent(), HUNDRED_MEGABYTES);
        assert_eq!(receiver.received(), HUNDRED_MEGABYTES);
        assert!(
            peak_outstanding <= u64::from(SMALL_WINDOW),
            "peak outstanding {peak_outstanding} exceeded the {SMALL_WINDOW}-byte window"
        );
        assert!(
            peak_held <= SMALL_WINDOW,
            "the receiver buffered {peak_held} bytes, more than its own window"
        );
        assert!(sender.stalls() > 1000, "a 64 KiB window over 100 MB must stall repeatedly, got {}", sender.stalls());
    }

    #[test]
    fn the_steady_state_does_not_stall_when_the_receiver_keeps_up() {
        // The counterpart to the test above: when grants arrive at the half-window
        // threshold ahead of the sender running dry, the transfer costs no stalls
        // at all. If this ever starts failing, the threshold in
        // `grant_threshold` has drifted and every session gained a latency spike
        // per window.
        let mut sender = SendWindow::new(SMALL_WINDOW);
        let mut receiver = ReceiveWindow::new(SMALL_WINDOW);
        let mut remaining = 8 * 1024 * 1024u64;

        while remaining > 0 {
            let chunk = u32::try_from(remaining.min(u64::from(CHUNK))).expect("bounded");
            // A receiver that keeps up: it consumes immediately and grants as soon
            // as the threshold allows.
            if let Reservation::Granted = sender.reserve(chunk) {
                remaining -= u64::from(chunk);
                receiver.receive(chunk).expect("within credit");
                receiver.consume(chunk).expect("keeps up");
                if let Some(grant) = receiver.take_grant() {
                    sender.grant(grant).expect("fits");
                }
            } else {
                panic!("a receiver that keeps up must never stall the sender");
            }
        }
        assert_eq!(sender.stalls(), 0);
    }

    /// A stand-in for a captured desktop frame: a sequence number and the damage
    /// it describes, merged by taking the newest sequence and the union of damage.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Damage {
        sequence: u64,
        left: u32,
        right: u32,
    }

    impl Merge for Damage {
        fn merge(&mut self, newer: Self) {
            self.sequence = newer.sequence;
            self.left = self.left.min(newer.left);
            self.right = self.right.max(newer.right);
        }
    }

    #[test]
    fn a_stalled_sender_holds_one_item_however_many_are_produced() {
        // The policy that makes a remote desktop usable: the viewer sees fewer
        // frames, each of them current, and memory does not grow with the stall.
        let mut outbox: LatestOnly<Damage> = LatestOnly::new();
        for sequence in 0..10_000 {
            outbox.offer(Damage { sequence, left: sequence as u32 % 100, right: sequence as u32 % 100 + 10 });
            assert!(outbox.is_pending());
        }
        assert_eq!(outbox.dropped(), 9_999);
        assert_eq!(outbox.offered(), 10_000);

        let merged = outbox.take().expect("one item");
        assert_eq!(merged.sequence, 9_999, "the newest frame's identity wins");
        assert_eq!(merged.left, 0, "damage is unioned, never lost");
        assert_eq!(merged.right, 109);
        assert!(!outbox.is_pending());
        assert_eq!(outbox.take(), None);
    }

    #[test]
    fn an_outbox_that_is_kept_drained_drops_nothing() {
        let mut outbox: LatestOnly<Damage> = LatestOnly::new();
        for sequence in 0..100 {
            outbox.offer(Damage { sequence, left: 0, right: 1 });
            assert_eq!(outbox.take().expect("sent immediately").sequence, sequence);
        }
        assert_eq!(outbox.dropped(), 0);
        assert_eq!(outbox.offered(), 100);
    }

    #[test]
    fn peek_shows_what_is_waiting_without_taking_it() {
        let mut outbox: LatestOnly<Damage> = LatestOnly::new();
        assert_eq!(outbox.peek(), None);
        outbox.offer(Damage { sequence: 1, left: 2, right: 3 });
        assert_eq!(outbox.peek().expect("pending").sequence, 1);
        assert!(outbox.is_pending());
    }

    #[test]
    fn a_desktop_under_a_stalled_window_shows_the_present_and_counts_what_it_dropped() {
        // The two policies together, which is how they are actually used: the
        // capture loop produces faster than the window drains, the outbox merges,
        // and both counters tell the operator what happened.
        let mut window = SendWindow::new(4 * CHUNK);
        let mut outbox: LatestOnly<Damage> = LatestOnly::new();
        let frame_bytes = CHUNK;

        for sequence in 0..64 {
            outbox.offer(Damage { sequence, left: 0, right: 1 });
            if outbox.is_pending() {
                match window.reserve(frame_bytes) {
                    Reservation::Granted => {
                        outbox.take().expect("pending");
                    }
                    // No credit: leave it pending, so the next capture merges into
                    // it rather than queueing behind it.
                    Reservation::Stalled { .. } => {}
                    Reservation::Unsatisfiable { .. } => unreachable!("a frame is smaller than the ceiling"),
                }
            }
        }

        assert_eq!(window.sent(), u64::from(4 * frame_bytes), "exactly one window went out");
        assert!(window.stalls() > 0);
        assert!(outbox.dropped() > 0);
        assert!(outbox.is_pending(), "the newest frame is still waiting, and it is the newest");
        assert_eq!(outbox.peek().expect("pending").sequence, 63);
    }

    #[test]
    fn errors_render_something_an_operator_can_act_on() {
        assert!(CreditError::MalformedGrant { length: 3 }.to_string().contains('3'));
        assert!(CreditError::EmptyGrant.to_string().contains("zero"));
        assert!(CreditError::WindowOverflow { available: 1, grant: 2 }.to_string().contains('2'));
        assert!(CreditError::PeerOverranWindow { by: 5, capacity: 10 }.to_string().contains('5'));
        assert!(CreditError::ConsumedMoreThanArrived { held: 1, consumed: 2 }.to_string().contains('2'));
    }
}
