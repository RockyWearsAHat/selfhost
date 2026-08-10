//! Joining two channels so a browser can drive a machine it has no link to.
//!
//! When the console asks for a desktop on a peer, the owner ends up holding two
//! channels: one to the browser and one on the worker's link. A splice joins
//! them, and the join is deliberately the least interesting code in the crate.
//!
//! ```text
//! browser ──channel 1──► owner ──channel 2──► worker's agent
//!         ◄─────────────       ◄─────────────
//! ```
//!
//! # What crosses, and what a splice refuses to do
//!
//! Three kinds cross: [`Kind::Data`], [`Kind::Credit`] and [`Kind::Close`]. The
//! owner rewrites **only the two-byte channel id** and forwards the payload
//! untouched. Nothing is re-encoded, nothing is inspected, and nothing is
//! buffered beyond a single frame.
//!
//! That is the property the whole of [`crate::mux`] was shaped to allow, and it
//! is worth being blunt about why. The owner's daemon is one process running the
//! service supervisor, the authoritative DNS server, the firewall manager, the
//! mail server, the certificate store and the self-updater, and the workspace
//! sets `panic = "abort"` for release. A parser in *this* code path — one that
//! read a desktop frame, or a file chunk, or anything a peer chose — would be a
//! way for a malicious worker to end all of that at a time of its choosing. So
//! the splice reads eight bytes, checks two things about them, and copies the
//! rest. Everything that interprets attacker-influenced bytes happens in an
//! agent process the daemon spawns, supervises and can watch die.
//!
//! `OPEN`, `ACCEPT` and `REJECT` do not cross: a spliced channel is one that
//! both ends have already agreed to, and an `OPEN` arriving on it is a peer
//! trying to start a conversation somewhere it was not invited.
//! `ECHO`/`ECHOED` do not cross either, because [`crate::mux::Kind`] defines
//! them as measuring *a link* and they ride channel 0. The console's end-to-end
//! round trip is therefore the sum of the two per-link probes rather than one
//! probe along the whole path; making it a single probe would mean redefining
//! those two kinds, which is a change to the wire contract and not a change to
//! this module.
//!
//! # Credit is forwarded, never authored
//!
//! This is the second load-bearing rule, and it is what makes the transfer test
//! below mean something. The splice does **not** keep windows of its own. A
//! middle box that grants credit it cannot honour becomes the queue: the
//! difference between how fast a screen changes and how fast the browser's link
//! can carry it would accumulate in the owner's memory, on the machine that
//! holds every disk and every key. Forwarding `CREDIT` verbatim makes the
//! browser's willingness to consume reach all the way back to the worker's
//! capture loop, so the backpressure is end-to-end and the owner's own
//! commitment for a spliced channel is one frame in flight plus a short bounded
//! inbox.
//!
//! # Both directions run independently
//!
//! Each direction is its own future, joined rather than selected, because a
//! splice where one direction's send can stop the other's reads is a splice that
//! deadlocks the first time a link fills up. They share one stop signal, so
//! whichever direction ends first ends both — a channel is one conversation, and
//! half of one is not useful to anybody.

use crate::channel::{Close, ChannelId};
use crate::link::{ChannelInbox, LinkError, LinkHandle};
use crate::mux::{Header, Kind};
use std::fmt;
use std::sync::Arc;
use tokio::sync::watch;

/// The close code a splice sends when the far end went away without closing.
///
/// A bare number, like every other code on this protocol: the vocabulary belongs
/// to the service, and the surviving end needs to know that its conversation is
/// over, not who did what to whom.
pub const PEER_GONE: u16 = 1;

/// The close code a splice sends when it refused to forward something.
pub const REFUSED: u16 = 2;

/// Whether a frame of this kind may cross a splice.
///
/// The whole policy, in one function, so that the forwarding loop cannot express
/// a different opinion from the documentation. See the module documentation for
/// why each of the others is excluded.
pub fn may_cross(kind: Kind) -> bool {
    matches!(kind, Kind::Data | Kind::Credit | Kind::Close)
}

/// Rewrites a header for the other side of a splice.
///
/// The entire transformation: the channel id, and nothing else. The kind and the
/// length come through unchanged, which is what lets the payload be forwarded
/// without being looked at.
///
/// Pure, and the only place a splice makes a decision — which is why the two
/// refusals are here rather than in the loop.
pub fn rewrite(header: Header, onto: ChannelId) -> Result<Header, SpliceError> {
    if !may_cross(header.kind) {
        return Err(SpliceError::NotForwardable(header.kind));
    }
    if onto.is_control() {
        return Err(SpliceError::ControlTarget);
    }
    Ok(Header { kind: header.kind, channel: onto, length: header.length })
}

/// Why a frame was not forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceError {
    /// A kind that does not cross a splice arrived on a spliced channel.
    NotForwardable(Kind),
    /// A splice was asked to forward onto channel 0, which belongs to the link
    /// itself and carries no conversation.
    ControlTarget,
}

impl fmt::Display for SpliceError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotForwardable(kind) => {
                write!(out, "a {kind} frame does not cross a splice")
            }
            Self::ControlTarget => {
                out.write_str("a splice cannot forward onto channel 0, the link's own control channel")
            }
        }
    }
}

impl std::error::Error for SpliceError {}

/// One end of a splice: where frames arrive, and how to write back to it.
///
/// The channel to forward *onto* is not a field — it is the other side's inbox
/// channel, read from the side itself. One less number to pass, and therefore
/// one less number to pass the wrong way round, which on this code path would
/// mean delivering one viewer's session to another.
pub struct SpliceSide {
    inbox: ChannelInbox,
    out: LinkHandle,
}

impl SpliceSide {
    /// One end of a splice.
    pub fn new(inbox: ChannelInbox, out: LinkHandle) -> Self {
        Self { inbox, out }
    }

    /// The channel this side's conversation uses on its own link.
    pub fn channel(&self) -> ChannelId {
        self.inbox.channel()
    }
}

impl fmt::Debug for SpliceSide {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("SpliceSide").field("channel", &self.inbox.channel().get()).finish()
    }
}

/// How one direction of a splice ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceEnd {
    /// A `CLOSE` was forwarded, and it was the last thing this direction did.
    Closed {
        /// The code the closing end sent.
        code: u16,
    },
    /// The source link ended, so nothing more will arrive on this side.
    PeerGone,
    /// The destination link would not take the frame.
    LinkGone,
    /// Something arrived that does not cross a splice.
    Refused(SpliceError),
    /// The other direction ended first, and a splice ends in both directions
    /// together.
    Companion,
}

impl SpliceEnd {
    /// Whether this direction ended by carrying a close through.
    ///
    /// The one distinction the teardown cares about: an end that already
    /// delivered a `CLOSE` has told the far side, and one that did not has to be
    /// told for it.
    pub fn delivered_close(self) -> bool {
        matches!(self, Self::Closed { .. })
    }
}

impl fmt::Display for SpliceEnd {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed { code } => write!(out, "the channel was closed (code {code})"),
            Self::PeerGone => out.write_str("the machine at that end went away"),
            Self::LinkGone => out.write_str("the link to the other end ended"),
            Self::Refused(error) => write!(out, "{error}"),
            Self::Companion => out.write_str("the other direction ended first"),
        }
    }
}

/// What one direction of a splice carried.
///
/// Plain public fields: a report with no invariant between its numbers, read by
/// the console's diagnostics panel and by the tests that assert this relay never
/// becomes a queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Direction {
    /// How many frames were forwarded.
    pub frames: u64,
    /// How many payload bytes were forwarded.
    pub bytes: u64,
    /// How many of the frames were `CREDIT` grants passed through.
    ///
    /// Reported because *zero* is a bug with a very confusing symptom: the
    /// transfer runs at the initial window and then stops forever, and every
    /// individual component looks correct.
    pub credit_frames: u64,
    /// The largest single payload forwarded.
    ///
    /// This is the owner's per-frame commitment for this direction. It is a
    /// number the operator can compare against the mux ceiling to see that the
    /// relay is copying rather than accumulating.
    pub peak_payload: usize,
    /// How this direction ended.
    pub end: SpliceEnd,
}

/// What a whole splice carried, and how it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpliceOutcome {
    /// Left to right — in the console's case, browser to machine.
    pub forward: Direction,
    /// Right to left — the machine's answer, and the browser's credit.
    pub reverse: Direction,
}

impl SpliceOutcome {
    /// Every payload byte the owner relayed, in both directions.
    pub fn bytes(&self) -> u64 {
        self.forward.bytes.saturating_add(self.reverse.bytes)
    }

    /// The largest single payload the owner held, in either direction.
    ///
    /// The splice forwards one frame at a time, so this is the peak amount of
    /// relayed data in the owner's hands at any instant — the number that says
    /// the relay is not a queue.
    pub fn peak_payload(&self) -> usize {
        self.forward.peak_payload.max(self.reverse.peak_payload)
    }
}

/// Runs a splice until it ends, and reports what it carried.
///
/// Frames from `left` are rewritten onto `right`'s channel and written to
/// `right`'s link, and the other way round, until either direction ends. Then —
/// and this matters more than it looks — whichever end has *not* been told that
/// the conversation is over is sent a `CLOSE`, so a browser whose worker vanished
/// mid-session sees its channel end rather than waiting for a frame that will
/// never come.
pub async fn run(left: SpliceSide, right: SpliceSide) -> SpliceOutcome {
    let SpliceSide { inbox: mut left_inbox, out: left_out } = left;
    let SpliceSide { inbox: mut right_inbox, out: right_out } = right;
    let left_channel = left_inbox.channel();
    let right_channel = right_inbox.channel();

    let (stop, watcher) = watch::channel(false);
    let stop = Arc::new(stop);

    let (forward, reverse) = tokio::join!(
        pump(&mut left_inbox, &right_out, right_channel, &stop, watcher.clone()),
        pump(&mut right_inbox, &left_out, left_channel, &stop, watcher),
    );

    // One code for the whole splice, not one per direction. A refusal is a fact
    // about the conversation, and telling the end that broke the rule that its
    // *peer* went away would be a false explanation on the one path where the
    // truth is worth reading.
    let code = if matches!(forward.end, SpliceEnd::Refused(_))
        || matches!(reverse.end, SpliceEnd::Refused(_))
    {
        REFUSED
    } else {
        PEER_GONE
    };

    // The direction *towards* a side is the one that would have delivered its
    // close, so that is the one whose ending decides whether it needs telling.
    if !forward.end.delivered_close() {
        announce_end(&right_out, right_channel, code).await;
    }
    if !reverse.end.delivered_close() {
        announce_end(&left_out, left_channel, code).await;
    }

    SpliceOutcome { forward, reverse }
}

/// Moves frames one way until something stops it.
///
/// Every exit sets the shared stop signal, so the companion direction ends too.
/// The `select!` is what keeps one direction's blocked write from stopping the
/// other direction's reads — and [`ChannelInbox::recv`] is cancel-safe, so the
/// arm that loses the race has lost nothing.
async fn pump(
    inbox: &mut ChannelInbox,
    out: &LinkHandle,
    onto: ChannelId,
    stop: &Arc<watch::Sender<bool>>,
    mut watcher: watch::Receiver<bool>,
) -> Direction {
    let mut direction =
        Direction { frames: 0, bytes: 0, credit_frames: 0, peak_payload: 0, end: SpliceEnd::PeerGone };

    loop {
        let frame = tokio::select! {
            frame = inbox.recv() => frame,
            changed = watcher.changed() => {
                // An error means the sender is gone, which can only happen once
                // both directions have finished; either way this one is over.
                let _ = changed;
                direction.end = SpliceEnd::Companion;
                break;
            }
        };
        let Some(frame) = frame else {
            direction.end = SpliceEnd::PeerGone;
            break;
        };

        let header = match rewrite(frame.header, onto) {
            Ok(header) => header,
            Err(error) => {
                direction.end = SpliceEnd::Refused(error);
                break;
            }
        };
        if out.send_frame(header.kind, header.channel, &frame.payload).await.is_err() {
            direction.end = SpliceEnd::LinkGone;
            break;
        }

        direction.frames = direction.frames.saturating_add(1);
        direction.bytes = direction.bytes.saturating_add(frame.payload.len() as u64);
        direction.peak_payload = direction.peak_payload.max(frame.payload.len());
        if header.kind == Kind::Credit {
            direction.credit_frames = direction.credit_frames.saturating_add(1);
        }
        if header.kind == Kind::Close {
            direction.end = SpliceEnd::Closed { code: close_code(&frame.payload) };
            break;
        }
    }

    stop.send_replace(true);
    direction
}

/// Tells one end that its conversation is over, best effort.
///
/// Best effort because the usual reason for being here is that something already
/// went away, and failing to tell a link that has itself ended is not a further
/// failure — the code that was waiting on it is being woken by the link ending
/// anyway.
async fn announce_end(out: &LinkHandle, channel: ChannelId, code: u16) {
    let closed: Result<(), LinkError> =
        out.send_frame(Kind::Close, channel, &Close { code }.encode()).await;
    // Reported by the caller's outcome rather than here; a splice that cannot
    // deliver a close has already recorded why in its `SpliceEnd`.
    let _ = closed;
}

/// The code inside a `CLOSE` payload, or zero if it is not one.
///
/// Reading two bytes of our own protocol's fixed control frame is not the sort
/// of interpretation the module documentation refuses: it is the same fixed-width
/// decode the header itself gets, it cannot fail, and the value is only ever
/// reported. The payload is still forwarded byte for byte regardless.
fn close_code(payload: &[u8]) -> u16 {
    Close::parse(payload).map_or(0, |close| close.code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::Role;
    use crate::credit::{
        INITIAL_WINDOW, ReceiveWindow, Reservation, SendWindow, encode_grant, parse_grant,
    };
    use crate::link::{CHANNEL_INBOX, Link, LinkHandle, OwnedFrame};
    use crate::registry::DropReason;
    use selfhost_ws::{Duplex, Limits};
    use std::time::Duration;
    use tokio::task::JoinHandle;

    /// One link, as its two ends see it.
    struct Wire {
        near: LinkHandle,
        far: LinkHandle,
        near_driver: JoinHandle<DropReason>,
        far_driver: JoinHandle<DropReason>,
    }

    /// A link between a dialler (`far`) and an accepter (`near`, the owner).
    fn wire(capacity: usize) -> Wire {
        let (dialler_io, accepter_io) = tokio::io::duplex(capacity);
        let (far_link, far, _far_control) =
            Link::new(Duplex::client(dialler_io, Limits::default()), Role::Dialler);
        let (near_link, near, _near_control) =
            Link::new(Duplex::server(accepter_io, Limits::default()), Role::Accepter);
        Wire {
            near,
            far,
            near_driver: tokio::spawn(near_link.run()),
            far_driver: tokio::spawn(far_link.run()),
        }
    }

    fn header(kind: Kind, channel: u16, length: u32) -> Header {
        Header { kind, channel: ChannelId::new(channel), length }
    }

    #[test]
    fn the_rewrite_changes_the_channel_and_nothing_else() {
        // This test is the specification of a splice. If it ever needs changing
        // to match the code, the owner has started interpreting somebody's
        // desktop bytes.
        let original = header(Kind::Data, 1, 4096);
        let rewritten = rewrite(original, ChannelId::new(2)).expect("forwardable");
        assert_eq!(rewritten.channel, ChannelId::new(2));
        assert_eq!(rewritten.kind, original.kind);
        assert_eq!(rewritten.length, original.length);
    }

    #[test]
    fn exactly_three_kinds_cross_a_splice() {
        for kind in [Kind::Data, Kind::Credit, Kind::Close] {
            assert!(may_cross(kind), "{kind}");
            assert!(rewrite(header(kind, 1, 0), ChannelId::new(2)).is_ok());
        }
        for kind in [Kind::Open, Kind::Accept, Kind::Reject, Kind::Echo, Kind::Echoed] {
            assert!(!may_cross(kind), "{kind}");
            assert_eq!(
                rewrite(header(kind, 1, 0), ChannelId::new(2)).unwrap_err(),
                SpliceError::NotForwardable(kind)
            );
        }
    }

    #[test]
    fn a_splice_never_forwards_onto_the_control_channel() {
        // Channel 0 carries the link's own enrolment and liveness traffic;
        // forwarding a conversation onto it would let one peer speak as the
        // link itself.
        assert_eq!(
            rewrite(header(Kind::Data, 1, 8), ChannelId::CONTROL).unwrap_err(),
            SpliceError::ControlTarget
        );
    }

    #[test]
    fn a_close_payload_is_read_for_reporting_and_never_required() {
        assert_eq!(close_code(&Close { code: 1234 }.encode()), 1234);
        assert_eq!(close_code(&[]), 0, "a malformed close still ends the channel");
        assert_eq!(close_code(&[1, 2, 3]), 0);
    }

    #[tokio::test]
    async fn a_frame_crosses_a_splice_with_its_payload_untouched() {
        let browser = wire(64 * 1024);
        let worker = wire(64 * 1024);
        let browser_channel = ChannelId::new(1);
        let worker_channel = ChannelId::new(2);

        let splice = tokio::spawn(run(
            SpliceSide::new(
                browser.near.attach(browser_channel).expect("attach"),
                browser.near.clone(),
            ),
            SpliceSide::new(worker.near.attach(worker_channel).expect("attach"), worker.near.clone()),
        ));

        let mut at_worker = worker.far.attach(worker_channel).expect("attach");
        let mut at_browser = browser.far.attach(browser_channel).expect("attach");

        browser.far.send_frame(Kind::Data, browser_channel, b"keystroke").await.expect("send");
        let arrived = at_worker.recv().await.expect("frame");
        assert_eq!(arrived.channel(), worker_channel, "only the channel id is rewritten");
        assert_eq!(arrived.payload, b"keystroke");

        worker.far.send_frame(Kind::Data, worker_channel, b"pixels").await.expect("send");
        let back = at_browser.recv().await.expect("frame");
        assert_eq!(back.channel(), browser_channel);
        assert_eq!(back.payload, b"pixels");

        // A close from either end finishes the splice in both directions.
        worker.far.send_frame(Kind::Close, worker_channel, &Close::NORMAL.encode()).await.expect("send");
        let outcome = tokio::time::timeout(Duration::from_secs(5), splice)
            .await
            .expect("the splice must finish")
            .expect("task");
        assert_eq!(outcome.reverse.end, SpliceEnd::Closed { code: 0 });
        assert_eq!(outcome.forward.end, SpliceEnd::Companion);
        assert_eq!(outcome.bytes(), (b"keystroke".len() + b"pixels".len() + 2) as u64);

        browser.near_driver.abort();
        browser.far_driver.abort();
        worker.near_driver.abort();
        worker.far_driver.abort();
    }

    #[tokio::test]
    async fn a_kind_that_does_not_cross_ends_the_splice_and_tells_both_ends() {
        let browser = wire(64 * 1024);
        let worker = wire(64 * 1024);
        let browser_channel = ChannelId::new(1);
        let worker_channel = ChannelId::new(2);
        let mut at_browser = browser.far.attach(browser_channel).expect("attach");
        let mut at_worker = worker.far.attach(worker_channel).expect("attach");

        let splice = tokio::spawn(run(
            SpliceSide::new(browser.near.attach(browser_channel).expect("attach"), browser.near.clone()),
            SpliceSide::new(worker.near.attach(worker_channel).expect("attach"), worker.near.clone()),
        ));

        // A worker trying to start a conversation on a channel it was not
        // invited to open.
        worker.far.send_frame(Kind::Open, worker_channel, b"\x01{}").await.expect("send");

        let outcome = tokio::time::timeout(Duration::from_secs(5), splice)
            .await
            .expect("the splice must finish")
            .expect("task");
        assert_eq!(outcome.reverse.end, SpliceEnd::Refused(SpliceError::NotForwardable(Kind::Open)));

        // Both ends are told, so neither waits for a frame that will not come.
        for inbox in [&mut at_browser, &mut at_worker] {
            let closed = tokio::time::timeout(Duration::from_secs(5), inbox.recv())
                .await
                .expect("a close must arrive")
                .expect("frame");
            assert_eq!(closed.kind(), Kind::Close);
            assert_eq!(close_code(&closed.payload), REFUSED);
        }

        browser.near_driver.abort();
        browser.far_driver.abort();
        worker.near_driver.abort();
        worker.far_driver.abort();
    }

    #[tokio::test]
    async fn a_peer_that_vanishes_mid_splice_leaves_the_other_end_told_rather_than_waiting() {
        // The failure this test exists for: a browser whose machine lost power
        // must see its channel end, not sit on a spinner forever.
        let browser = wire(64 * 1024);
        let worker = wire(64 * 1024);
        let browser_channel = ChannelId::new(1);
        let worker_channel = ChannelId::new(2);
        let mut at_browser = browser.far.attach(browser_channel).expect("attach");

        let splice = tokio::spawn(run(
            SpliceSide::new(browser.near.attach(browser_channel).expect("attach"), browser.near.clone()),
            SpliceSide::new(worker.near.attach(worker_channel).expect("attach"), worker.near.clone()),
        ));

        worker.far.send_frame(Kind::Data, worker_channel, b"half a screen").await.expect("send");
        assert_eq!(at_browser.recv().await.expect("frame").payload, b"half a screen");

        // The worker's machine goes away: its link ends without a close. The
        // owner's own end of that link is left running, so what wakes the
        // browser is the real mechanism — the socket dying — and not the test
        // tearing down both sides by hand.
        worker.far_driver.abort();
        drop(worker.far);

        let closed = tokio::time::timeout(Duration::from_secs(5), at_browser.recv())
            .await
            .expect("the browser must be told")
            .expect("frame");
        assert_eq!(closed.kind(), Kind::Close);
        assert_eq!(close_code(&closed.payload), PEER_GONE);

        let outcome = tokio::time::timeout(Duration::from_secs(5), splice)
            .await
            .expect("the splice must finish")
            .expect("task");
        assert!(
            matches!(outcome.reverse.end, SpliceEnd::PeerGone | SpliceEnd::LinkGone),
            "{:?}",
            outcome.reverse.end
        );

        browser.near_driver.abort();
        browser.far_driver.abort();
        worker.near_driver.abort();
    }

    /// One hundred megabytes, the size the plan names.
    const HUNDRED_MEGABYTES: u64 = 100 * 1024 * 1024;
    /// A deliberately small window, so the transfer is flow-controlled
    /// throughout rather than fitting inside one grant.
    const WINDOW: u32 = 64 * 1024;
    /// One capture's worth of bytes.
    const CHUNK: u32 = 32 * 1024;

    #[tokio::test]
    async fn a_hundred_megabytes_crosses_a_splice_through_a_64_kib_window_without_the_owner_queueing()
    {
        // The property under test is not that the transfer finishes. It is that
        // credit granted by the *browser* reaches the *worker* through a relay
        // that keeps no windows of its own, so that at no point does the owner —
        // the machine holding every disk and every key — hold more than one
        // frame of somebody else's data.
        let browser = wire(256 * 1024);
        let worker = wire(256 * 1024);
        let browser_channel = ChannelId::new(1);
        let worker_channel = ChannelId::new(2);

        let splice = tokio::spawn(run(
            SpliceSide::new(browser.near.attach(browser_channel).expect("attach"), browser.near.clone()),
            SpliceSide::new(worker.near.attach(worker_channel).expect("attach"), worker.near.clone()),
        ));

        let sending = tokio::spawn(send_metered(
            worker.far.clone(),
            worker.far.attach(worker_channel).expect("attach"),
            worker_channel,
        ));
        let receiving = tokio::spawn(receive_metered(
            browser.far.clone(),
            browser.far.attach(browser_channel).expect("attach"),
            browser_channel,
        ));

        let sent = tokio::time::timeout(Duration::from_secs(120), sending)
            .await
            .expect("the transfer must finish")
            .expect("sender task");
        let received = tokio::time::timeout(Duration::from_secs(120), receiving)
            .await
            .expect("the transfer must finish")
            .expect("receiver task");
        let outcome = tokio::time::timeout(Duration::from_secs(30), splice)
            .await
            .expect("the splice must finish")
            .expect("splice task");

        assert_eq!(sent.bytes, HUNDRED_MEGABYTES, "every byte was offered");
        assert_eq!(received.bytes, HUNDRED_MEGABYTES, "every byte arrived");
        assert!(sent.stalls > 0, "a 64 KiB window over 100 MB must be flow-controlled throughout");

        // End to end: the browser's grants reached the worker's send window.
        assert!(received.grants > 100, "the browser granted repeatedly, got {}", received.grants);
        // A hundred megabytes cannot cross a 64 KiB window at all unless grants
        // kept arriving from the far end of the relay, so the count itself is
        // the end-to-end evidence.
        assert!(
            outcome.forward.credit_frames > 1000,
            "credit must cross continuously, got {}",
            outcome.forward.credit_frames
        );
        // The shortfall is bounded by what was in flight when the close crossed:
        // a splice ends in both directions together, so grants issued after the
        // conversation ended have nowhere to go. Anything larger would mean
        // credit was being dropped during the transfer rather than at its end.
        let in_flight = u64::from(WINDOW / CHUNK) + CHANNEL_INBOX as u64;
        assert!(
            received.grants.saturating_sub(outcome.forward.credit_frames) <= in_flight,
            "granted {}, forwarded {}",
            received.grants,
            outcome.forward.credit_frames
        );

        // The bounded peak: the sender never had more than a window outstanding,
        // the receiver never held more than a window, and the owner never held
        // more than one frame.
        assert!(
            sent.peak_outstanding <= u64::from(WINDOW),
            "the sender had {} bytes outstanding, past its {WINDOW}-byte window",
            sent.peak_outstanding
        );
        assert!(
            received.peak_held <= WINDOW,
            "the receiver buffered {} bytes, more than its own window",
            received.peak_held
        );
        assert!(
            outcome.peak_payload() <= CHUNK as usize,
            "the owner held {} bytes of one frame",
            outcome.peak_payload()
        );
        assert_eq!(outcome.reverse.bytes, HUNDRED_MEGABYTES + 2, "the data and its close");
        assert_eq!(outcome.reverse.end, SpliceEnd::Closed { code: 0 });

        browser.near_driver.abort();
        browser.far_driver.abort();
        worker.near_driver.abort();
        worker.far_driver.abort();
    }

    /// What the metered sender did.
    struct Sent {
        bytes: u64,
        stalls: u64,
        peak_outstanding: u64,
    }

    /// Sends [`HUNDRED_MEGABYTES`] under a [`WINDOW`]-byte send window, waiting
    /// for credit rather than queueing, and closes the channel at the end.
    ///
    /// Credit is drained eagerly after every send. That is not an optimisation:
    /// a link's reader stops while a channel's inbox is full, and a task that is
    /// blocked writing on the same link it has stopped reading is a task waiting
    /// for itself. Draining keeps the inbox near empty, which is also how a real
    /// agent must be written.
    async fn send_metered(out: LinkHandle, mut credit: ChannelInbox, channel: ChannelId) -> Sent {
        let payload = vec![0xa5u8; CHUNK as usize];
        let mut window = SendWindow::new(WINDOW);
        let mut remaining = HUNDRED_MEGABYTES;
        let mut peak_outstanding = 0u64;

        while remaining > 0 {
            drain_grants(&mut credit, &mut window);
            let chunk = u32::try_from(remaining.min(u64::from(CHUNK))).expect("bounded by CHUNK");
            match window.reserve(chunk) {
                Reservation::Granted => {
                    out.send_frame(Kind::Data, channel, &payload[..chunk as usize])
                        .await
                        .expect("the link stays up for the whole transfer");
                    remaining -= u64::from(chunk);
                    peak_outstanding = peak_outstanding.max(window.outstanding());
                }
                Reservation::Stalled { .. } => {
                    let frame = credit.recv().await.expect("credit must arrive or the transfer hangs");
                    apply_grant(&frame, &mut window);
                }
                Reservation::Unsatisfiable { limit } => {
                    unreachable!("a {CHUNK}-byte chunk is under the {limit}-byte ceiling")
                }
            }
        }

        out.send_frame(Kind::Close, channel, &Close::NORMAL.encode()).await.expect("close");
        Sent { bytes: window.sent(), stalls: window.stalls(), peak_outstanding }
    }

    /// Applies every grant already waiting, without blocking.
    fn drain_grants(credit: &mut ChannelInbox, window: &mut SendWindow) {
        while let Some(frame) = credit.try_recv() {
            apply_grant(&frame, window);
        }
    }

    /// Applies one `CREDIT` frame to a send window.
    fn apply_grant(frame: &OwnedFrame, window: &mut SendWindow) {
        assert_eq!(frame.kind(), Kind::Credit, "only credit comes back on this channel");
        let grant = parse_grant(&frame.payload).expect("a well-formed grant");
        window.grant(grant).expect("a grant this side's own window asked for");
    }

    /// What the metered receiver did.
    struct Received {
        bytes: u64,
        grants: u64,
        peak_held: u32,
    }

    /// Consumes everything that arrives under a [`WINDOW`]-byte receive window,
    /// granting credit back as it goes, until the channel closes.
    async fn receive_metered(
        out: LinkHandle,
        mut inbox: ChannelInbox,
        channel: ChannelId,
    ) -> Received {
        let mut window = ReceiveWindow::new(WINDOW);
        let mut grants = 0u64;
        let mut peak_held = 0u32;

        while let Some(frame) = inbox.recv().await {
            match frame.kind() {
                Kind::Data => {
                    let arrived = u32::try_from(frame.payload.len()).expect("under the mux ceiling");
                    window.receive(arrived).expect("the sender never exceeds its credit");
                    peak_held = peak_held.max(window.held());
                    // The application consumes immediately; the grant is what
                    // has to travel back through the owner.
                    window.consume(arrived).expect("consume what arrived");
                    if let Some(grant) = window.take_grant() {
                        out.send_frame(Kind::Credit, channel, &encode_grant(grant))
                            .await
                            .expect("the link stays up for the whole transfer");
                        grants += 1;
                    }
                }
                Kind::Close => break,
                other => unreachable!("nothing else crosses a splice, got {other}"),
            }
        }

        Received { bytes: window.received(), grants, peak_held }
    }

    // A quiet drift in these numbers would turn the transfer test above into a
    // test of nothing: a window as large as the transfer is not flow control,
    // and a chunk larger than the window stalls on the first frame with no way
    // out. Checked at compile time, because they are constants.
    const _: () = assert!(WINDOW as u64 * 16 < HUNDRED_MEGABYTES);
    const _: () = assert!(CHUNK < WINDOW);
    const _: () = assert!(WINDOW < INITIAL_WINDOW);

    #[test]
    fn ends_render_something_an_operator_can_act_on() {
        assert!(SpliceEnd::Closed { code: 7 }.to_string().contains('7'));
        assert!(SpliceEnd::PeerGone.to_string().contains("went away"));
        assert!(SpliceEnd::LinkGone.to_string().contains("link"));
        assert!(SpliceEnd::Companion.to_string().contains("other direction"));
        assert!(
            SpliceEnd::Refused(SpliceError::NotForwardable(Kind::Open)).to_string().contains("open")
        );
        assert!(SpliceError::ControlTarget.to_string().contains("channel 0"));
        assert!(SpliceEnd::Closed { code: 0 }.delivered_close());
        assert!(!SpliceEnd::PeerGone.delivered_close());
    }
}
