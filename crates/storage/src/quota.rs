//! Whether one more upload is allowed to start, and whether it may continue.
//!
//! Pure ceiling arithmetic. Four different limits can refuse an upload and they
//! refuse it for four different reasons, which is why this is a small module
//! with a typed answer rather than an `if` in the write path:
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

use std::fmt;

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
}

impl Admission {
    /// Whether the upload may proceed.
    pub fn allowed(self) -> bool {
        matches!(self, Self::Allowed)
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
/// not depend on that, and it is what makes the quota true rather than
/// approximately true. It is called against a running byte counter, so it takes
/// what has been written rather than what was promised.
pub fn still_admitted(limits: Limits, used_before: u64, written: u64) -> Admission {
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
        assert_eq!(still_admitted(bounded, 0, 1000), Admission::Allowed);
        assert_eq!(
            still_admitted(bounded, 0, 1001),
            Admission::OverQuota { limit: 1000, used: 0, wanted: 1001 }
        );
        assert_eq!(still_admitted(bounded, 900, 100), Admission::Allowed);
        assert_eq!(
            still_admitted(bounded, 900, 101),
            Admission::OverQuota { limit: 1000, used: 900, wanted: 101 }
        );
        assert_eq!(still_admitted(bounded, u64::MAX, 1), Admission::Absurd);

        // No quota means nothing to re-check; the free-space floor is enforced
        // by the caller's own periodic check, not by arithmetic on a promise.
        let unlimited = Limits { quota_bytes: None, ..bounded };
        assert_eq!(still_admitted(unlimited, u64::MAX, u64::MAX), Admission::Allowed);
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

    #[test]
    fn the_default_limits_are_the_documented_ones() {
        let defaults = Limits::for_quota(Some(42));
        assert_eq!(defaults.quota_bytes, Some(42));
        assert_eq!(defaults.max_concurrent, DEFAULT_MAX_CONCURRENT);
        assert_eq!(defaults.max_in_flight_bytes, DEFAULT_MAX_IN_FLIGHT_BYTES);
        assert_eq!(defaults.free_space_floor, FREE_SPACE_FLOOR);
    }
}
