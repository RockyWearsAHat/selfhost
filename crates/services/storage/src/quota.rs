//! Whether one more upload is allowed to start, and whether it may continue.
//!
//! Ceiling arithmetic, and the one live count it is enforced against. Four
//! different limits can refuse an upload and they refuse it for four different
//! reasons, which is why this is a small module with a typed answer rather than
//! an `if` in the write path:
//!
//! 1. **The share's quota** — what the operator said this share may hold.
//! 2. **Free space on the volume** — what the disk actually has, minus a floor.
//!    A quota is a promise about one share; free space is a fact about the whole
//!    machine, and the machine hosts the reverse proxy, the mail spool and the
//!    box's own source tree. A full boot volume does not degrade the NAS, it
//!    stops the box.
//! 3. **Concurrent uploads** — a count, because each in-flight upload holds a
//!    file descriptor, a scratch buffer and a socket.
//! 4. **In-flight bytes** — the sum of what the running uploads have *promised*
//!    to write. This is the limit nobody thinks of, and it is the one that
//!    matters: ten simultaneous uploads that are each comfortably under quota
//!    are collectively over it, and every one of them passes an admission check
//!    that only looks at bytes already on disk.
//!
//! Three of those four are spent against a number the client supplied — its
//! declared length — once, before the first byte. So the declaration is itself
//! the fifth limit, and the only one enforced per chunk: an upload allowed to
//! write past what it declared has spent room the other three still believe is
//! free. [`still_admitted`] is where that is refused, and it is why it takes the
//! promise as well as the running total.
//!
//! # Why this is arithmetic worth isolating
//!
//! Every number here is attacker-influenced. `Content-Length` is whatever the
//! client wrote; `used` grows as bytes land; the volume's free space is reported
//! by the operating system. Adding two of them together can overflow a `u64`,
//! and in release builds this workspace sets `panic = "abort"`, so an
//! overflowing add is not a wrapped number and not a panic to catch — it is the
//! daemon that serves ports 80 and 443 disappearing.
//!
//! So nothing here adds without [`u64::checked_add`] and nothing subtracts
//! without [`u64::saturating_sub`], and the table below drives every one of
//! those paths with `u64::MAX` on purpose.
//!
//! # The one stateful thing here, and why it is here
//!
//! [`admit`] and [`still_admitted`] are pure functions of numbers somebody has
//! to be keeping. [`Ledger`] is who keeps them: the count of uploads running,
//! the bytes they have promised, and the measured size of each share. It is the
//! only impure item in this module, and it lives *next to* the arithmetic
//! rather than in the write path for a specific reason — the increment and the
//! decrement have to be the same pair. A ceiling maintained in one file and
//! spent in another is a ceiling that leaks: every early return, every `?`, and
//! every cancelled task on the write path is a place a decrement can be
//! forgotten, and eight forgotten decrements is a NAS that refuses every upload
//! until the daemon restarts. So the count is only reachable through
//! [`Reservation`], which decrements in its `Drop` — the one place no control
//! flow can skip.
//!
//! # Why the share's size is cached rather than measured per request
//!
//! `used_bytes` is a whole-subtree walk ([`crate::fs::Dir::measure`]), one open
//! per file. Doing it on every `PUT` would make a share of forty thousand files
//! unusable, and doing it never would let the quota drift away from the disk the
//! first time somebody writes over SMB. So it is measured, cached, adjusted as
//! this process moves bytes, and **expired** after [`USAGE_TTL`] so that a
//! change made behind our back is corrected within minutes rather than never.

use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Bytes of free space that must remain on the volume after an upload finishes.
///
/// One gigabyte. The number is not about the NAS: it is what the rest of the box
/// needs to keep working — log files, the ACME account and certificates, the
/// self-updater's `git fetch` and `cargo build` of its own source tree, and the
/// mail spool. A machine that fills its boot volume does not serve a smaller
/// NAS; it stops answering on 443 and the operator loses the console they would
/// have used to fix it.
pub const FREE_SPACE_FLOOR: u64 = 1024 * 1024 * 1024;

/// The default ceiling on uploads running at once.
pub const DEFAULT_MAX_CONCURRENT: u32 = 8;

/// The default ceiling on bytes promised by uploads running at once.
///
/// Sixteen gigabytes: large enough that a person moving a folder of video into
/// the share never meets it, small enough that it cannot itself fill a volume
/// that satisfied [`FREE_SPACE_FLOOR`] when the first upload was admitted.
pub const DEFAULT_MAX_IN_FLIGHT_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// The ceilings, as one value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The share's quota in bytes, or `None` for "as much as the volume holds".
    pub quota_bytes: Option<u64>,
    /// Most uploads that may run at once, across all shares.
    pub max_concurrent: u32,
    /// Most bytes that may be promised by running uploads, across all shares.
    pub max_in_flight_bytes: u64,
    /// Free space that must remain after an upload completes.
    pub free_space_floor: u64,
}

impl Limits {
    /// The ceilings for a share with the given quota, everything else default.
    pub fn for_quota(quota_bytes: Option<u64>) -> Self {
        Self {
            quota_bytes,
            max_concurrent: DEFAULT_MAX_CONCURRENT,
            max_in_flight_bytes: DEFAULT_MAX_IN_FLIGHT_BYTES,
            free_space_floor: FREE_SPACE_FLOOR,
        }
    }
}

/// What is true right now, as the write path observed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    /// Bytes the share already holds.
    pub used_bytes: u64,
    /// Bytes free on the volume the share's root lives on.
    pub free_bytes: u64,
    /// Uploads currently running, across all shares.
    pub uploads_running: u32,
    /// Bytes the running uploads have promised to write but not yet written.
    pub in_flight_bytes: u64,
}

/// Whether an upload may start, and if not, why not.
///
/// Each refusal maps to a different HTTP status and a different sentence in the
/// console, which is the reason for a typed answer rather than a boolean:
/// `OverQuota` is `507` and the operator's own setting, `NoSpace` is `507` and a
/// fact about the disk, and the two busy variants are `503` with a `Retry-After`
/// because they will pass on their own. Collapsing them would tell an operator
/// to delete files when the real answer was "wait four seconds".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// The upload may start.
    Allowed,
    /// The share's quota would be exceeded.
    OverQuota {
        /// What the share may hold.
        limit: u64,
        /// What it holds now.
        used: u64,
        /// What this upload would add.
        wanted: u64,
    },
    /// The volume would drop below its free-space floor.
    NoSpace {
        /// Free bytes on the volume.
        free: u64,
        /// Free bytes that must remain afterwards.
        floor: u64,
        /// What this upload would add.
        wanted: u64,
    },
    /// Too many uploads are already running.
    TooManyUploads {
        /// How many may run at once.
        limit: u32,
    },
    /// Too many bytes are already promised by running uploads.
    TooMuchInFlight {
        /// How many bytes may be promised at once.
        limit: u64,
    },
    /// The declared length is larger than any arithmetic here can carry, which
    /// means it is larger than any volume can hold.
    ///
    /// Reached only when a client declares a `Content-Length` near `u64::MAX`.
    /// It is refused explicitly rather than left to an overflow, because "left
    /// to an overflow" in a release build of this workspace is an abort.
    Absurd,
    /// The upload is sending more than it declared it would.
    ///
    /// This is the refusal that makes every other ceiling here mean something.
    /// The quota, the in-flight budget and the free-space floor are all admitted
    /// against the *declared* length, and none of them is re-measured per chunk
    /// — so a receiver that accepted bytes past the declaration would spend
    /// room three ceilings believed was still free. On a share with no quota at
    /// all it would be bounded by nothing whatsoever, on a box whose disk also
    /// holds the mail spool and the TLS key store.
    ///
    /// It is a fact about the client rather than about the box, so it is `400`
    /// rather than `507`: nothing here is full, the body is longer than the
    /// framing said it would be.
    PastDeclaration {
        /// What the client said it would send.
        declared: u64,
        /// What it has sent, counting the chunk being refused.
        written: u64,
    },
}

impl Admission {
    /// Whether the upload may proceed.
    pub fn allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// The HTTP status this refusal is answered with.
    ///
    /// A number rather than a `Response` so that this module keeps no opinion
    /// about bodies: WebDAV wants an XML `<D:error>` here and the JSON file API
    /// wants an object, and both want the same status and the same sentence.
    ///
    /// `507 Insufficient Storage` for a quota or a full volume — RFC 4331 §5
    /// defines it for exactly this, and Finder and the Windows client both
    /// present it as "the disk is full" rather than as a mysterious failure.
    /// `503 Service Unavailable` for the two ceilings that clear on their own,
    /// because telling a client to retry a full disk is telling it to hammer a
    /// request that cannot succeed. [`Admission::Absurd`] is `400`: nothing is
    /// wrong with the server, the declared length is wrong.
    pub fn status_code(self) -> u16 {
        match self {
            Self::Allowed => 200,
            Self::OverQuota { .. } | Self::NoSpace { .. } => 507,
            Self::TooManyUploads { .. } | Self::TooMuchInFlight { .. } => 503,
            Self::Absurd | Self::PastDeclaration { .. } => 400,
        }
    }

    /// Whether waiting and retrying would plausibly succeed.
    ///
    /// True exactly for the two concurrency limits. A quota or a full disk needs
    /// somebody to delete something or change a setting, and telling a client to
    /// retry that is telling it to hammer a request that cannot succeed.
    pub fn retryable(self) -> bool {
        matches!(self, Self::TooManyUploads { .. } | Self::TooMuchInFlight { .. })
    }
}

impl fmt::Display for Admission {
    /// Prose the console renders as-is.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowed => f.write_str("allowed"),
            Self::OverQuota { limit, used, wanted } => write!(
                f,
                "this share is limited to {limit} bytes and already holds {used}; \
                 the upload needs another {wanted}"
            ),
            Self::NoSpace { free, floor, wanted } => write!(
                f,
                "the volume has {free} bytes free and must keep {floor} in reserve; \
                 the upload needs {wanted}"
            ),
            Self::TooManyUploads { limit } => {
                write!(f, "{limit} uploads are already running; try again shortly")
            }
            Self::TooMuchInFlight { limit } => write!(
                f,
                "uploads in progress already account for the {limit}-byte transfer budget; \
                 try again shortly"
            ),
            Self::Absurd => {
                f.write_str("the declared length is larger than any volume can hold")
            }
            Self::PastDeclaration { declared, written } => write!(
                f,
                "this upload said it would send {declared} bytes and has now sent {written}"
            ),
        }
    }
}

/// Decides whether an upload of `wanted` bytes may start.
///
/// The order of the checks is the order of their cost to the operator: the two
/// that will clear on their own are tested first, so a caller that is merely
/// early is not told its data is too large. The quota is tested before free
/// space so that a share which is over its own limit says so, rather than
/// blaming a disk that has plenty of room.
///
/// This is the check *before* the first byte. The write path must also call
/// [`still_admitted`] as bytes land, because a `Content-Length` is a claim: a
/// chunked or lying client can send more than it declared, and an upload that
/// was admitted at 1 KiB must not be allowed to write 100 GiB.
pub fn admit(limits: Limits, usage: Usage, wanted: u64) -> Admission {
    if usage.uploads_running >= limits.max_concurrent {
        return Admission::TooManyUploads { limit: limits.max_concurrent };
    }

    let Some(promised) = usage.in_flight_bytes.checked_add(wanted) else {
        return Admission::Absurd;
    };
    if promised > limits.max_in_flight_bytes {
        return Admission::TooMuchInFlight { limit: limits.max_in_flight_bytes };
    }

    if let Some(limit) = limits.quota_bytes {
        let Some(after) = usage.used_bytes.checked_add(wanted) else {
            return Admission::Absurd;
        };
        if after > limit {
            return Admission::OverQuota { limit, used: usage.used_bytes, wanted };
        }
    }

    // Free space is compared against what the *other* running uploads have also
    // promised, not just this one. Ten uploads each admitted against the same
    // observed free space is exactly how a volume fills up while every
    // individual check passed.
    let Some(committed) = promised.checked_add(limits.free_space_floor) else {
        return Admission::Absurd;
    };
    if committed > usage.free_bytes {
        return Admission::NoSpace {
            free: usage.free_bytes,
            floor: limits.free_space_floor,
            wanted,
        };
    }

    Admission::Allowed
}

/// Re-checks an upload that is already running, after `written` bytes have
/// landed.
///
/// A `Content-Length` is a claim by the client, and the framing layer will stop
/// a fixed-length body at its declared length — but this is the belt that does
/// not depend on that, and it is what makes every ceiling in this module true
/// rather than approximately true. It is called against a running byte counter,
/// so it takes what has been written as well as what was promised.
///
/// **The declaration is the binding limit, and it is checked first.** [`admit`]
/// spends `promised` bytes of the in-flight budget, measures the free-space
/// floor against `promised`, and compares `promised` against the quota — once,
/// before the first byte. None of those three is re-measured per chunk, and
/// re-measuring them would not help: the room was already promised to this
/// upload. So a receiver that let a client write past its declaration would let
/// it spend room three ceilings still believe is free, and on a share with no
/// quota it would be bounded by nothing at all. That is
/// [`Admission::PastDeclaration`], and it is why this function needs both
/// numbers.
///
/// The quota is then re-checked as well, which is redundant on today's paths
/// (nothing can be admitted whose declaration already exceeds the quota) and
/// deliberately kept: it costs one comparison and it is the check that stays
/// correct if a future caller ever reserves room in some other way.
pub fn still_admitted(limits: Limits, used_before: u64, promised: u64, written: u64) -> Admission {
    if written > promised {
        return Admission::PastDeclaration { declared: promised, written };
    }
    let Some(limit) = limits.quota_bytes else {
        return Admission::Allowed;
    };
    let Some(total) = used_before.checked_add(written) else {
        return Admission::Absurd;
    };
    if total > limit {
        return Admission::OverQuota { limit, used: used_before, wanted: written };
    }
    Admission::Allowed
}

/// Bytes still available in a share, for RFC 4331 `quota-available-bytes`.
///
/// Finder and the Windows Mini-Redirector both read this, and both refuse every
/// copy when it reads zero — so an unquotaed share must not report zero. Without
/// a quota the answer is what the volume has, minus the reserve, which is the
/// truthful answer to "how much can I put here".
///
/// Saturating throughout: a share that is already over its quota (because the
/// operator lowered it, or because files arrived over SMB behind our back)
/// reports zero available rather than underflowing.
pub fn available(limits: Limits, usage: Usage) -> u64 {
    let on_volume = usage.free_bytes.saturating_sub(limits.free_space_floor);
    match limits.quota_bytes {
        None => on_volume,
        Some(limit) => limit.saturating_sub(usage.used_bytes).min(on_volume),
    }
}

/// Bytes a share currently holds, for RFC 4331 `quota-used-bytes`.
///
/// Trivial today, and it exists so that the WebDAV property has one place to
/// come from rather than reaching into a `Usage` field directly — the day used
/// bytes are counted differently (excluding in-progress temp files, say), it
/// changes here and everywhere at once.
pub fn used(usage: Usage) -> u64 {
    usage.used_bytes
}

/// How long a measured share size is trusted before it is measured again.
///
/// Five minutes. The number is a trade between two ways of being wrong: too
/// short and every upload pays for a subtree walk, too long and a share written
/// over SMB — which this crate does not see — keeps a quota that no longer
/// matches the disk. Within one process the number is kept exact by
/// [`Ledger::adjust`], so the expiry only ever corrects for changes made
/// *outside* this daemon.
pub const USAGE_TTL: Duration = Duration::from_secs(300);

/// The live counts every admission decision is made against.
///
/// One per daemon, shared. Everything it holds is a number somebody has to keep
/// and nobody else does: how many uploads are running, how many bytes they have
/// promised, and how large each share was when it was last measured.
///
/// # The counts are only reachable through a [`Reservation`]
///
/// There is no `release` on this type, deliberately. An upload takes a
/// [`Reservation`] from [`Ledger::admit`] and the counts come back when that
/// value is dropped — on the happy path, on a `?`, on a panic, and on a task
/// cancelled at an `await`. A pair of public increment/decrement methods would
/// be correct in the four places that remember them and wrong in the fifth, and
/// the fifth is a NAS that refuses every upload until the daemon is restarted.
///
/// # Poisoning
///
/// The lock guards plain integers and is never held across a call that can
/// panic, so a poisoned lock means some *other* thread died holding it with the
/// numbers intact. Recovering the guard is therefore right, and the alternative
/// — propagating the poison — would turn one unrelated panic into a NAS that
/// refuses every write for the life of the process.
#[derive(Debug, Default)]
pub struct Ledger {
    state: Mutex<Counts>,
}

/// What [`Ledger`] is guarding.
#[derive(Debug, Default)]
struct Counts {
    /// Uploads currently running, across all shares.
    uploads_running: u32,
    /// Bytes promised by running uploads and not yet written.
    in_flight_bytes: u64,
    /// The measured size of each share that has been measured.
    ///
    /// A `Vec` rather than a map because shares are declared in configuration
    /// and a deployment has a handful of them: a linear scan of five entries is
    /// faster than hashing a string, and it keeps this type free of a `Hash`
    /// requirement on an id that is a validated string.
    shares: Vec<ShareUsage>,
}

/// One share's measured size, and when it was measured.
#[derive(Debug)]
struct ShareUsage {
    /// The share's id.
    id: String,
    /// Bytes it held, adjusted by everything this process has done since.
    used_bytes: u64,
    /// When the measurement was taken.
    measured_at: Instant,
    /// Bytes promised by uploads running **into this share** and not yet
    /// written.
    ///
    /// Separate from [`Counts::in_flight_bytes`], which is the whole box's
    /// transfer budget, because the quota is a promise about *one* share: two
    /// 600 MB uploads into a share with a 1 GB quota are each under it and
    /// jointly over it, and a check that looked only at bytes already on disk
    /// would admit both. This is the number that makes the quota true under
    /// concurrency, and it is why an entry exists for a share the moment an
    /// upload into it is admitted rather than only once it has been measured.
    in_flight_bytes: u64,
}

impl Ledger {
    /// An empty ledger: nothing running, nothing measured.
    pub fn new() -> Self {
        Self::default()
    }

    /// The measured size of a share, if it has been measured recently enough.
    ///
    /// `None` means *measure it*, and it is what a caller gets both before the
    /// first measurement and once [`USAGE_TTL`] has passed. Returning an
    /// `Option` rather than a stale number is the point: a quota enforced
    /// against an hour-old measurement of a share that SMB has been filling is
    /// a quota that is not enforced.
    pub fn used(&self, share: &str) -> Option<u64> {
        let counts = self.lock();
        let entry = counts.shares.iter().find(|entry| entry.id == share)?;
        (entry.measured_at.elapsed() < USAGE_TTL).then_some(entry.used_bytes)
    }

    /// Records a fresh measurement of a share.
    pub fn observe(&self, share: &str, used_bytes: u64) {
        let mut counts = self.lock();
        let now = Instant::now();
        match counts.shares.iter_mut().find(|entry| entry.id == share) {
            Some(entry) => {
                entry.used_bytes = used_bytes;
                entry.measured_at = now;
            }
            None => counts.shares.push(ShareUsage {
                id: share.to_string(),
                used_bytes,
                measured_at: now,
                in_flight_bytes: 0,
            }),
        }
    }

    /// Moves a share's cached size by what this process just did to it.
    ///
    /// Called after a file lands and after one is removed, so that a hundred
    /// uploads inside one [`USAGE_TTL`] window are each admitted against the
    /// size the share actually has rather than against the size it had when the
    /// first of them started. Saturating in both directions: a share whose
    /// cached size has drifted below zero is a share reporting nothing used,
    /// which the next measurement corrects.
    ///
    /// A share that has not been measured is left alone. Adjusting an unknown
    /// starting point would invent a measurement, and an invented one never
    /// expires into a real one.
    pub fn adjust(&self, share: &str, added: u64, removed: u64) {
        let mut counts = self.lock();
        if let Some(entry) = counts.shares.iter_mut().find(|entry| entry.id == share) {
            entry.used_bytes = entry.used_bytes.saturating_add(added).saturating_sub(removed);
        }
    }

    /// Forgets what a share measured, so the next admission measures it again.
    ///
    /// The honest answer to an operation whose effect on the size this code
    /// cannot compute — a recursive delete that failed halfway, a `MOVE`
    /// between two shares — where guessing would leave the cache confidently
    /// wrong until the TTL expired.
    ///
    /// **Only the measurement is forgotten.** A share's entry also carries
    /// [`ShareUsage::in_flight_bytes`], which is not a measurement at all: it is
    /// what uploads running *right now* have already promised, and it is the
    /// number that makes the quota true under concurrency. Dropping the whole
    /// entry gave that promise back — so a `DELETE` issued while an upload was
    /// running let the next upload be admitted against room the first had
    /// already spent, and two 600-byte uploads fitted in a 1000-byte share. An
    /// entry holding nothing but a measurement is still removed, so the table
    /// does not keep a row per share that was once written to.
    pub fn forget(&self, share: &str) {
        let stale = Instant::now().checked_sub(USAGE_TTL).unwrap_or_else(Instant::now);
        let mut counts = self.lock();
        counts.shares.retain(|entry| entry.id != share || entry.in_flight_bytes > 0);
        if let Some(entry) = counts.shares.iter_mut().find(|entry| entry.id == share) {
            // Timed out rather than deleted: `Ledger::used` answers `None`, the
            // caller measures again, and `observe` overwrites both fields while
            // leaving the promise where it is.
            entry.used_bytes = 0;
            entry.measured_at = stale;
        }
    }

    /// Asks whether an upload of `wanted` bytes into `share` may start, and
    /// takes the room for it if so.
    ///
    /// The decision and the increment happen under one lock, which is the whole
    /// reason this is a method rather than a call to [`admit`] followed by a
    /// bump: two uploads that each read the counts, each decided they fit, and
    /// each then incremented would both be admitted against the same free
    /// space. That is precisely the "ten simultaneous under-quota uploads" this
    /// module's documentation names as the limit nobody thinks of.
    ///
    /// `used_bytes` is the caller's freshly measured or cached size for the
    /// share — [`Ledger::used`] is where it comes from — and `free_bytes` is
    /// [`crate::fs::Dir::free_space`]. Both are passed in rather than read here
    /// because both need the filesystem, and this type deliberately touches
    /// none.
    pub fn admit(
        self: &Arc<Self>,
        share: &str,
        limits: Limits,
        used_bytes: u64,
        free_bytes: u64,
        wanted: u64,
    ) -> Result<Reservation, Admission> {
        let mut counts = self.lock();
        // What this share already owes, on disk and in flight. Saturating: a
        // number that has run away is a number that refuses uploads, which is
        // the safe direction for a ceiling.
        let owed = used_bytes.saturating_add(counts.share_in_flight(share));
        let usage = Usage {
            used_bytes: owed,
            free_bytes,
            uploads_running: counts.uploads_running,
            in_flight_bytes: counts.in_flight_bytes,
        };
        match admit(limits, usage, wanted) {
            Admission::Allowed => {
                counts.uploads_running = counts.uploads_running.saturating_add(1);
                counts.in_flight_bytes = counts.in_flight_bytes.saturating_add(wanted);
                counts.reserve_for_share(share, wanted);
                drop(counts);
                Ok(Reservation {
                    ledger: Arc::clone(self),
                    share: share.to_string(),
                    limits,
                    used_before: owed,
                    promised: wanted,
                    written: 0,
                    released: false,
                })
            }
            refused => Err(refused),
        }
    }

    /// The guarded counts, with a poisoned lock recovered rather than
    /// propagated — see this type's documentation for why.
    fn lock(&self) -> std::sync::MutexGuard<'_, Counts> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Gives back what a finished upload was holding.
    ///
    /// Private, and called only from [`Reservation`]'s `Drop`, because that is
    /// the one place no control flow can skip.
    fn release(&self, promised: u64, written: u64, share: &str) {
        let mut counts = self.lock();
        counts.uploads_running = counts.uploads_running.saturating_sub(1);
        counts.in_flight_bytes = counts.in_flight_bytes.saturating_sub(promised);
        if let Some(entry) = counts.shares.iter_mut().find(|entry| entry.id == share) {
            entry.in_flight_bytes = entry.in_flight_bytes.saturating_sub(promised);
            entry.used_bytes = entry.used_bytes.saturating_add(written);
        }
    }
}

impl Counts {
    /// Bytes promised by uploads already running into one share.
    fn share_in_flight(&self, share: &str) -> u64 {
        self.shares
            .iter()
            .find(|entry| entry.id == share)
            .map_or(0, |entry| entry.in_flight_bytes)
    }

    /// Records that an upload into one share has been admitted.
    ///
    /// Creates the entry when the share has not been measured, with a
    /// measurement time far enough in the past that [`Ledger::used`] still
    /// reports it as needing measuring — the promise is real and must be
    /// counted, but a `used_bytes` of zero that nobody measured must never read
    /// as a fresh answer.
    fn reserve_for_share(&mut self, share: &str, wanted: u64) {
        match self.shares.iter_mut().find(|entry| entry.id == share) {
            Some(entry) => entry.in_flight_bytes = entry.in_flight_bytes.saturating_add(wanted),
            None => {
                let stale = Instant::now().checked_sub(USAGE_TTL).unwrap_or_else(Instant::now);
                self.shares.push(ShareUsage {
                    id: share.to_string(),
                    used_bytes: 0,
                    measured_at: stale,
                    in_flight_bytes: wanted,
                });
            }
        }
    }
}

/// Room held for one running upload, given back when this value is dropped.
///
/// Two things are being held: a slot in the concurrency ceiling, and `promised`
/// bytes of the in-flight budget. Both come back in `Drop`, whatever ended the
/// upload — which is why there is no `release` to forget to call.
///
/// # Bytes are credited to the share only when somebody says they landed
///
/// [`Reservation::finish`] adds what was written to the share's cached size, so
/// an upload of ten megabytes moves the quota by ten megabytes even if it
/// declared a hundred. `Drop` adds **nothing**, and that asymmetry is the whole
/// point: an upload that ended any other way — a swept idle session, a write
/// that failed, a task cancelled at an `await` — has had its partial file
/// removed by [`crate::fs::Upload`]'s own `Drop`, so the bytes it wrote are not
/// on the disk and must not be in the share's size.
///
/// It used to be the other way round: `Drop` credited whatever had been written
/// unless a caller had remembered to call a `rollback` first. That is the
/// pattern this module's own documentation warns against two paragraphs above —
/// a rule kept correct in the four places somebody remembered it and wrong in
/// the fifth — and the fifth was a share that reported itself full of files it
/// did not have, refusing every upload until the measurement expired.
#[derive(Debug)]
pub struct Reservation {
    /// The ledger the room came from.
    ledger: Arc<Ledger>,
    /// Which share's size the written bytes belong to.
    share: String,
    /// The ceilings this upload was admitted against.
    limits: Limits,
    /// What the share held when the upload started.
    used_before: u64,
    /// What the upload declared it would write.
    promised: u64,
    /// What it has written so far.
    written: u64,
    /// Whether the room has already been given back, so `Drop` does not give it
    /// back twice.
    released: bool,
}

impl Reservation {
    /// Records bytes that have landed, and re-checks the quota.
    ///
    /// This is the belt that does not depend on the client having told the
    /// truth about `Content-Length`. It is called as the copy loop runs, not
    /// once at the end: an upload that declared a kilobyte and is sending a
    /// hundred gigabytes must be stopped while it is sending them, not
    /// discovered afterwards.
    ///
    /// A refusal does **not** release the reservation — the caller still has to
    /// unwind the partial file, and dropping this value is what gives the room
    /// back.
    ///
    /// A **refused** chunk does not move the counter, and that is not a detail:
    /// [`Reservation::written`] is what the caller reports as the resume offset
    /// and what the share's cached size grows by on [`Reservation::finish`].
    /// Counting bytes the caller was just told not to write would put a
    /// resumable upload's offset past the end of its own file and add phantom
    /// bytes to the share.
    pub fn record(&mut self, bytes: u64) -> Admission {
        let landed = self.written.saturating_add(bytes);
        let admission = still_admitted(self.limits, self.used_before, self.promised, landed);
        if admission.allowed() {
            self.written = landed;
        }
        admission
    }

    /// How much has landed so far, for a progress report.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// How much was promised, so a progress report has a denominator.
    pub fn promised(&self) -> u64 {
        self.promised
    }

    /// Hands the room back and declares that what was written is on the disk.
    ///
    /// Called by a caller that has just published the file — and by nobody
    /// else. This is the *only* way the share's cached size grows, so a caller
    /// that forgets it under-counts a ceiling, which the next measurement
    /// corrects, rather than over-counting one, which nothing corrects until the
    /// measurement expires.
    pub fn finish(mut self) {
        let landed = self.written;
        self.release(landed);
    }

    /// Gives the concurrency slot and the promised bytes back, crediting
    /// `landed` bytes to the share, exactly once.
    fn release(&mut self, landed: u64) {
        if self.released {
            return;
        }
        self.released = true;
        self.ledger.release(self.promised, landed, &self.share);
    }
}

impl Drop for Reservation {
    /// Gives the room back and credits **nothing**.
    ///
    /// A reservation reaching `Drop` without [`Reservation::finish`] is an
    /// upload nobody published: the swept idle session, the write that failed,
    /// the task cancelled at an `await`. [`crate::fs::Upload`]'s own `Drop` has
    /// removed the partial file those wrote, so crediting their bytes would
    /// charge the share for data that is not there.
    fn drop(&mut self) {
        self.release(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn limits() -> Limits {
        Limits {
            quota_bytes: Some(100 * GIB),
            max_concurrent: 4,
            max_in_flight_bytes: 1000 * GIB,
            free_space_floor: FREE_SPACE_FLOOR,
        }
    }

    fn usage() -> Usage {
        Usage { used_bytes: 10 * GIB, free_bytes: 500 * GIB, uploads_running: 0, in_flight_bytes: 0 }
    }

    #[test]
    fn an_ordinary_upload_is_admitted() {
        assert_eq!(admit(limits(), usage(), GIB), Admission::Allowed);
        assert!(admit(limits(), usage(), GIB).allowed());
    }

    #[test]
    fn the_quota_is_a_ceiling_on_the_total_not_on_the_upload() {
        // Exactly filling the quota is allowed; one byte more is not.
        let exact = 90 * GIB;
        assert_eq!(admit(limits(), usage(), exact), Admission::Allowed);
        assert_eq!(
            admit(limits(), usage(), exact + 1),
            Admission::OverQuota { limit: 100 * GIB, used: 10 * GIB, wanted: exact + 1 }
        );
    }

    #[test]
    fn a_share_without_a_quota_is_bounded_only_by_the_volume() {
        let unlimited = Limits { quota_bytes: None, ..limits() };
        let plenty = Usage { free_bytes: 500 * GIB, ..usage() };
        assert_eq!(admit(unlimited, plenty, 9 * GIB), Admission::Allowed);

        let nearly_full = Usage { free_bytes: 2 * GIB, ..usage() };
        assert!(matches!(
            admit(unlimited, nearly_full, 9 * GIB),
            Admission::NoSpace { floor: FREE_SPACE_FLOOR, .. }
        ));
    }

    #[test]
    fn the_free_space_floor_is_kept_even_when_the_quota_would_allow_it() {
        // The quota is a promise about this share; the floor is a fact about the
        // machine, and the machine hosts the console the operator would use to
        // fix a full disk.
        let tight = Usage { free_bytes: FREE_SPACE_FLOOR + GIB, ..usage() };
        assert_eq!(admit(limits(), tight, GIB), Admission::Allowed);
        assert_eq!(
            admit(limits(), tight, GIB + 1),
            Admission::NoSpace {
                free: FREE_SPACE_FLOOR + GIB,
                floor: FREE_SPACE_FLOOR,
                wanted: GIB + 1
            }
        );
    }

    #[test]
    fn ten_uploads_each_under_quota_are_collectively_over_it() {
        // The limit nobody thinks of. Each of these passes a check that only
        // looks at bytes already on disk.
        let budget = Limits { max_in_flight_bytes: 10 * GIB, ..limits() };
        let busy = Usage { in_flight_bytes: 9 * GIB, uploads_running: 3, ..usage() };
        assert_eq!(admit(budget, busy, GIB), Admission::Allowed);
        assert_eq!(admit(budget, busy, GIB + 1), Admission::TooMuchInFlight { limit: 10 * GIB });
    }

    #[test]
    fn in_flight_bytes_count_against_free_space_as_well() {
        // Two uploads admitted against the same observed free space is how a
        // volume fills while every individual check passed.
        let volume = Usage {
            free_bytes: FREE_SPACE_FLOOR + 4 * GIB,
            in_flight_bytes: 3 * GIB,
            uploads_running: 1,
            used_bytes: 0,
        };
        assert_eq!(admit(limits(), volume, GIB), Admission::Allowed);
        assert!(matches!(admit(limits(), volume, GIB + 1), Admission::NoSpace { .. }));
    }

    #[test]
    fn the_concurrency_ceiling_is_checked_first_because_it_clears_by_itself() {
        let saturated = Usage { uploads_running: 4, ..usage() };
        assert_eq!(admit(limits(), saturated, 1), Admission::TooManyUploads { limit: 4 });
        // Even an upload that would also breach the quota is told the fixable
        // thing first.
        assert_eq!(admit(limits(), saturated, u64::MAX), Admission::TooManyUploads { limit: 4 });
        assert!(admit(limits(), saturated, 1).retryable());
    }

    #[test]
    fn only_the_concurrency_refusals_are_worth_retrying() {
        assert!(!Admission::Allowed.retryable());
        assert!(!Admission::OverQuota { limit: 1, used: 1, wanted: 1 }.retryable());
        assert!(!Admission::NoSpace { free: 1, floor: 1, wanted: 1 }.retryable());
        assert!(!Admission::Absurd.retryable());
        assert!(Admission::TooManyUploads { limit: 1 }.retryable());
        assert!(Admission::TooMuchInFlight { limit: 1 }.retryable());
    }

    #[test]
    fn nothing_overflows_however_large_the_declared_length() {
        // Every one of these adds would wrap or abort without `checked_add`.
        let huge = Limits {
            quota_bytes: Some(u64::MAX),
            max_concurrent: 4,
            max_in_flight_bytes: u64::MAX,
            free_space_floor: FREE_SPACE_FLOOR,
        };
        let loaded = Usage {
            used_bytes: u64::MAX - 1,
            free_bytes: u64::MAX,
            uploads_running: 0,
            in_flight_bytes: u64::MAX - 1,
        };
        assert_eq!(admit(huge, loaded, u64::MAX), Admission::Absurd);
        assert_eq!(admit(huge, loaded, 2), Admission::Absurd);
        assert_eq!(admit(huge, Usage { in_flight_bytes: 0, ..loaded }, u64::MAX), Admission::Absurd);

        // The free-space add is the third one, and it has its own ceiling.
        let no_quota = Limits { quota_bytes: None, max_in_flight_bytes: u64::MAX, ..huge };
        let clean = Usage { used_bytes: 0, in_flight_bytes: 0, ..loaded };
        assert_eq!(admit(no_quota, clean, u64::MAX), Admission::Absurd);
    }

    #[test]
    fn a_running_upload_is_re_checked_as_bytes_land() {
        // A `Content-Length` is a claim. This is the belt that does not depend
        // on the client having told the truth.
        let bounded = Limits { quota_bytes: Some(1000), ..limits() };
        assert_eq!(still_admitted(bounded, 0, 1000, 1000), Admission::Allowed);
        assert_eq!(still_admitted(bounded, 900, 100, 100), Admission::Allowed);
        assert_eq!(
            still_admitted(bounded, 900, 2000, 1000),
            Admission::OverQuota { limit: 1000, used: 900, wanted: 1000 }
        );
        assert_eq!(still_admitted(bounded, u64::MAX, 1, 1), Admission::Absurd);
    }

    /// The declaration binds whatever the quota says — including on a share
    /// that has none, which is where the only other ceilings were the in-flight
    /// budget and the free-space floor, and both were spent at admission.
    #[test]
    fn an_upload_may_never_write_past_the_length_it_was_admitted_against() {
        let bounded = Limits { quota_bytes: Some(1000), ..limits() };
        assert_eq!(
            still_admitted(bounded, 0, 10, 11),
            Admission::PastDeclaration { declared: 10, written: 11 }
        );

        let unlimited = Limits { quota_bytes: None, ..bounded };
        assert_eq!(still_admitted(unlimited, 0, 1, 1), Admission::Allowed);
        assert_eq!(
            still_admitted(unlimited, 0, 1, 2),
            Admission::PastDeclaration { declared: 1, written: 2 }
        );
        assert_eq!(
            still_admitted(unlimited, u64::MAX, 0, u64::MAX),
            Admission::PastDeclaration { declared: 0, written: u64::MAX }
        );

        // It is the client that is wrong, not the box: `400`, and no
        // `Retry-After`, because sending the same body again would be refused
        // in exactly the same place.
        let past = Admission::PastDeclaration { declared: 1, written: 2 };
        assert_eq!(past.status_code(), 400);
        assert!(!past.retryable());
        assert!(past.to_string().contains("has now sent 2"));
    }

    #[test]
    fn available_space_never_reads_zero_on_a_share_that_has_room() {
        // Finder and the Windows Mini-Redirector both refuse every copy when
        // this reads zero, so an unquotaed share reporting zero would look like
        // a broken mount.
        let unlimited = Limits { quota_bytes: None, ..limits() };
        assert_eq!(available(unlimited, usage()), 500 * GIB - FREE_SPACE_FLOOR);

        // With a quota, the smaller of the two answers is the true one.
        assert_eq!(available(limits(), usage()), 90 * GIB);
        let small_volume = Usage { free_bytes: FREE_SPACE_FLOOR + GIB, ..usage() };
        assert_eq!(available(limits(), small_volume), GIB);
    }

    #[test]
    fn a_share_over_its_quota_reports_zero_rather_than_underflowing() {
        // Reachable in practice: the operator lowered the quota, or files
        // arrived over SMB behind our back.
        let over = Usage { used_bytes: 200 * GIB, ..usage() };
        assert_eq!(available(limits(), over), 0);
        assert_eq!(used(over), 200 * GIB);

        // And a volume already below the floor has nothing to offer.
        let cramped = Usage { free_bytes: 0, used_bytes: 0, ..usage() };
        assert_eq!(available(Limits { quota_bytes: None, ..limits() }, cramped), 0);
    }

    #[test]
    fn every_refusal_explains_itself_in_prose() {
        for admission in [
            Admission::Allowed,
            Admission::OverQuota { limit: 1, used: 1, wanted: 1 },
            Admission::NoSpace { free: 1, floor: 1, wanted: 1 },
            Admission::TooManyUploads { limit: 1 },
            Admission::TooMuchInFlight { limit: 1 },
            Admission::Absurd,
        ] {
            assert!(!admission.to_string().is_empty());
        }
    }

    /// The counts come back however the upload ended, which is the property
    /// that keeps a NAS from refusing every write after eight failed ones.
    #[test]
    fn room_taken_by_an_upload_comes_back_when_it_is_dropped() {
        let ledger = Arc::new(Ledger::new());
        let tight = Limits { max_concurrent: 2, ..limits() };
        ledger.observe("vault", 0);

        let first = ledger.admit("vault", tight, 0, 500 * GIB, GIB).expect("admitted");
        let second = ledger.admit("vault", tight, 0, 500 * GIB, GIB).expect("admitted");
        assert!(matches!(
            ledger.admit("vault", tight, 0, 500 * GIB, GIB),
            Err(Admission::TooManyUploads { limit: 2 })
        ));

        // An early return, a `?`, a cancelled task: all of them are this.
        drop(first);
        let third = ledger.admit("vault", tight, 0, 500 * GIB, GIB).expect("room came back");
        drop((second, third));

        // And with everything finished the ceiling is whole again.
        for _ in 0..2 {
            let taken = ledger.admit("vault", tight, 0, 500 * GIB, GIB).expect("admitted");
            drop(taken);
        }
    }

    /// Two uploads admitted against the same observed free space is how a
    /// volume fills while every individual check passed — so the decision and
    /// the increment happen together.
    #[test]
    fn a_second_upload_is_measured_against_what_the_first_one_promised() {
        let ledger = Arc::new(Ledger::new());
        let budget = Limits { max_in_flight_bytes: 10 * GIB, ..limits() };

        let first = ledger.admit("vault", budget, 0, 500 * GIB, 9 * GIB).expect("admitted");
        assert!(matches!(
            ledger.admit("vault", budget, 0, 500 * GIB, 2 * GIB),
            Err(Admission::TooMuchInFlight { limit: budget_limit }) if budget_limit == 10 * GIB
        ));
        assert!(ledger.admit("vault", budget, 0, 500 * GIB, GIB).is_ok());
        drop(first);
    }

    #[test]
    fn what_lands_moves_the_share_and_what_is_abandoned_does_not() {
        let ledger = Arc::new(Ledger::new());
        ledger.observe("vault", 1000);
        assert_eq!(ledger.used("vault"), Some(1000));

        let mut landing = ledger.admit("vault", limits(), 1000, 500 * GIB, 500).expect("admitted");
        assert_eq!(landing.record(300), Admission::Allowed);
        assert_eq!(landing.record(200), Admission::Allowed);
        assert_eq!(landing.written(), 500);
        assert_eq!(landing.promised(), 500);
        landing.finish();
        assert_eq!(ledger.used("vault"), Some(1500));

        // Dropped rather than finished, which is every way an upload can end
        // except publication — and none of them leaves bytes on the disk, so
        // none of them may move the share's size. There is deliberately nothing
        // to call here: that is the fix.
        let mut abandoned = ledger.admit("vault", limits(), 1500, 500 * GIB, 500).expect("admitted");
        assert_eq!(abandoned.record(400), Admission::Allowed);
        drop(abandoned);
        assert_eq!(ledger.used("vault"), Some(1500), "bytes that were not kept are not counted");

        // A delete moves it the other way, and never below zero.
        ledger.adjust("vault", 0, 2000);
        assert_eq!(ledger.used("vault"), Some(0));

        // An unmeasured share is left unmeasured rather than invented.
        ledger.adjust("photos", 900, 0);
        assert_eq!(ledger.used("photos"), None);
        ledger.forget("vault");
        assert_eq!(ledger.used("vault"), None);
    }

    /// A client that declares a kilobyte and sends a hundred gigabytes is
    /// stopped while it is sending them.
    /// The quota is a promise about one share, so two uploads into it are
    /// measured against each other — not each against the same figure from the
    /// disk.
    #[test]
    fn two_uploads_into_one_share_cannot_jointly_exceed_its_quota() {
        let ledger = Arc::new(Ledger::new());
        let bounded = Limits { quota_bytes: Some(1000), ..limits() };
        ledger.observe("vault", 0);

        let first = ledger.admit("vault", bounded, 0, 500 * GIB, 600).expect("admitted");
        // The second is admitted against 600 already promised, not against the
        // zero bytes currently on disk.
        assert!(matches!(
            ledger.admit("vault", bounded, 0, 500 * GIB, 600),
            Err(Admission::OverQuota { limit: 1000, used: 600, wanted: 600 })
        ));
        assert!(ledger.admit("vault", bounded, 0, 500 * GIB, 400).is_ok());

        // A different share is unaffected: the promise belongs to one share.
        ledger.observe("photos", 0);
        assert!(ledger.admit("photos", bounded, 0, 500 * GIB, 900).is_ok());

        // And the promise comes back when the upload ends, so a share does not
        // stay full of uploads that finished.
        drop(first);
        assert!(ledger.admit("vault", bounded, 0, 500 * GIB, 600).is_ok());
    }

    /// Admitting an upload into a share nobody has measured must not invent a
    /// measurement: the promise is counted, and the size is still asked for.
    #[test]
    fn admitting_into_an_unmeasured_share_does_not_fabricate_its_size() {
        let ledger = Arc::new(Ledger::new());
        let bounded = Limits { quota_bytes: Some(1000), ..limits() };
        let held = ledger.admit("fresh", bounded, 0, 500 * GIB, 900).expect("admitted");
        assert_eq!(ledger.used("fresh"), None, "nothing has measured this share yet");
        assert!(matches!(
            ledger.admit("fresh", bounded, 0, 500 * GIB, 200),
            Err(Admission::OverQuota { .. })
        ));
        drop(held);
    }

    #[test]
    fn a_lying_content_length_is_caught_as_the_bytes_land() {
        let ledger = Arc::new(Ledger::new());
        let bounded = Limits { quota_bytes: Some(1000), ..limits() };
        ledger.observe("vault", 900);

        let mut running = ledger.admit("vault", bounded, 900, 500 * GIB, 100).expect("admitted");
        assert_eq!(running.record(100), Admission::Allowed);
        // One byte past the hundred it declared, which is also one byte past the
        // room every ceiling was measured against.
        assert!(matches!(
            running.record(1),
            Admission::PastDeclaration { declared: 100, written: 101 }
        ));
        assert_eq!(running.written(), 100, "a refused chunk is not a chunk that landed");
        // The refusal does not release the room: the caller still has a partial
        // file to unwind, and dropping the reservation is what gives it back —
        // crediting nothing, because nothing was published.
        drop(running);
        assert_eq!(ledger.used("vault"), Some(900));
    }

    #[test]
    fn a_measurement_is_trusted_only_while_it_is_fresh() {
        let ledger = Ledger::new();
        ledger.observe("vault", 42);
        assert_eq!(ledger.used("vault"), Some(42));
        assert_eq!(ledger.used("absent"), None);

        // The expiry is what corrects for bytes written behind our back — over
        // SMB, or by the operator at the console.
        {
            let mut counts = ledger.lock();
            let entry = counts.shares.first_mut().expect("the measured share");
            entry.measured_at = Instant::now()
                .checked_sub(USAGE_TTL + Duration::from_secs(1))
                .expect("a clock with five minutes on it");
        }
        assert_eq!(ledger.used("vault"), None, "a stale measurement asks to be taken again");
    }

    #[test]
    fn every_refusal_carries_the_status_that_matches_its_cause() {
        assert_eq!(Admission::Allowed.status_code(), 200);
        assert_eq!(Admission::OverQuota { limit: 1, used: 1, wanted: 1 }.status_code(), 507);
        assert_eq!(Admission::NoSpace { free: 1, floor: 1, wanted: 1 }.status_code(), 507);
        assert_eq!(Admission::TooManyUploads { limit: 1 }.status_code(), 503);
        assert_eq!(Admission::TooMuchInFlight { limit: 1 }.status_code(), 503);
        assert_eq!(Admission::Absurd.status_code(), 400);
    }

    #[test]
    fn the_default_limits_are_the_documented_ones() {
        let defaults = Limits::for_quota(Some(42));
        assert_eq!(defaults.quota_bytes, Some(42));
        assert_eq!(defaults.max_concurrent, DEFAULT_MAX_CONCURRENT);
        assert_eq!(defaults.max_in_flight_bytes, DEFAULT_MAX_IN_FLIGHT_BYTES);
        assert_eq!(defaults.free_space_floor, FREE_SPACE_FLOOR);
    }
}
