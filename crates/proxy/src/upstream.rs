//! The health-checked upstream pool.
//!
//! This is the part of the project that has to be *right* rather than merely
//! present. "Load balanced" is easy to claim and easy to fake: DNS round-robin
//! hands out addresses with no idea whether anything is listening, and a proxy
//! with only passive checks discovers a dead node by serving somebody an error.
//!
//! What is implemented here instead:
//!
//! - **Active probes** on their own timer, so a dead instance leaves rotation
//!   before a visitor arrives rather than because one did.
//! - **Hysteresis in both directions.** An instance must fail `unhealthy_after`
//!   consecutive probes to leave, and succeed `healthy_after` consecutive probes
//!   to return. A single threshold makes a flapping instance oscillate in and
//!   out on alternating probes, which is worse than leaving it out.
//! - **Automatic recovery**, because an operator should not have to notice.
//! - **Least-connections selection**, which suits this workload: a client
//!   pulling a multi-megabyte video segment holds its slot far longer than one
//!   fetching JSON, so counting live connections tracks real load where counting
//!   requests does not.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

/// One application instance the proxy can forward to.
#[derive(Debug)]
pub struct Upstream {
    /// Socket address, already resolved from node role and mesh membership.
    address: String,
    /// Whether this instance is currently in rotation.
    healthy: AtomicBool,
    /// Requests currently being served by this instance.
    in_flight: AtomicUsize,
    /// Consecutive successful probes since the last failure.
    consecutive_ok: AtomicU32,
    /// Consecutive failed probes since the last success.
    consecutive_fail: AtomicU32,
    /// Probes that have failed since the process started.
    total_failures: AtomicU32,
}

impl Upstream {
    /// Creates an upstream, optimistically in rotation.
    ///
    /// Starting healthy means a restart does not black-hole traffic for one
    /// probe interval. A genuinely dead instance is removed by the first probes.
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            healthy: AtomicBool::new(true),
            in_flight: AtomicUsize::new(0),
            consecutive_ok: AtomicU32::new(0),
            consecutive_fail: AtomicU32::new(0),
            total_failures: AtomicU32::new(0),
        }
    }

    /// The socket address to connect to.
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Whether this instance is in rotation.
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
    }

    /// Requests currently in flight to this instance.
    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::Acquire)
    }

    /// Probes that have failed over the process lifetime.
    pub fn total_failures(&self) -> u32 {
        self.total_failures.load(Ordering::Relaxed)
    }

    /// Records a successful probe, returning true if this brought it back into
    /// rotation.
    pub fn record_success(&self, healthy_after: u32) -> bool {
        self.consecutive_fail.store(0, Ordering::Release);
        let streak = self.consecutive_ok.fetch_add(1, Ordering::AcqRel) + 1;

        if !self.is_healthy() && streak >= healthy_after {
            self.healthy.store(true, Ordering::Release);
            return true;
        }
        false
    }

    /// Records a failed probe, returning true if this removed it from rotation.
    pub fn record_failure(&self, unhealthy_after: u32) -> bool {
        self.consecutive_ok.store(0, Ordering::Release);
        self.total_failures.fetch_add(1, Ordering::Relaxed);
        let streak = self.consecutive_fail.fetch_add(1, Ordering::AcqRel) + 1;

        if self.is_healthy() && streak >= unhealthy_after {
            self.healthy.store(false, Ordering::Release);
            return true;
        }
        false
    }
}

/// A guard that decrements an upstream's in-flight count when dropped.
///
/// Tying the count to a guard rather than to explicit calls means it stays
/// correct when a handler returns early, propagates an error, or is cancelled —
/// all of which would otherwise leak a permanently elevated count and make the
/// instance look busier than it is forever.
#[derive(Debug)]
pub struct Lease {
    upstream: Arc<Upstream>,
}

impl Lease {
    /// The address this lease was taken against.
    pub fn address(&self) -> &str {
        self.upstream.address()
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.upstream.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The set of instances serving one site.
#[derive(Debug)]
pub struct Pool {
    upstreams: Vec<Arc<Upstream>>,
    /// Cursor used to break ties fairly rather than always picking the first.
    cursor: AtomicUsize,
}

impl Pool {
    /// Builds a pool from resolved addresses.
    pub fn new(addresses: impl IntoIterator<Item = String>) -> Self {
        Self {
            upstreams: addresses.into_iter().map(|a| Arc::new(Upstream::new(a))).collect(),
            cursor: AtomicUsize::new(0),
        }
    }

    /// Every instance, healthy or not.
    pub fn upstreams(&self) -> &[Arc<Upstream>] {
        &self.upstreams
    }

    /// Whether the pool has no instances at all.
    pub fn is_empty(&self) -> bool {
        self.upstreams.is_empty()
    }

    /// How many instances are currently in rotation.
    pub fn healthy_count(&self) -> usize {
        self.upstreams.iter().filter(|u| u.is_healthy()).count()
    }

    /// Picks the healthy instance with the fewest requests in flight, and leases
    /// it.
    ///
    /// Returns `None` when every instance is out of rotation — the caller must
    /// answer `502` rather than forwarding to a known-dead node, which is the
    /// entire point of tracking health.
    ///
    /// Ties are broken by a rotating cursor so that an idle pool spreads load
    /// instead of sending everything to whichever instance is listed first.
    pub fn acquire(&self) -> Option<Lease> {
        let count = self.upstreams.len();
        if count == 0 {
            return None;
        }

        let start = self.cursor.fetch_add(1, Ordering::Relaxed);
        let mut best: Option<(&Arc<Upstream>, usize)> = None;

        for offset in 0..count {
            let upstream = &self.upstreams[(start.wrapping_add(offset)) % count];
            if !upstream.is_healthy() {
                continue;
            }
            let load = upstream.in_flight();
            match best {
                Some((_, best_load)) if load >= best_load => {}
                _ => best = Some((upstream, load)),
            }
        }

        let (chosen, _) = best?;
        chosen.in_flight.fetch_add(1, Ordering::AcqRel);
        Some(Lease { upstream: Arc::clone(chosen) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool_of(addresses: &[&str]) -> Pool {
        Pool::new(addresses.iter().map(|s| (*s).to_owned()))
    }

    #[test]
    fn an_empty_pool_yields_nothing() {
        assert!(pool_of(&[]).acquire().is_none());
    }

    #[test]
    fn instances_start_in_rotation() {
        let pool = pool_of(&["127.0.0.1:1"]);
        assert_eq!(pool.healthy_count(), 1);
        assert!(pool.acquire().is_some());
    }

    #[test]
    fn a_dead_pool_yields_nothing_rather_than_a_dead_node() {
        // The whole reason to track health: never hand traffic to a node we
        // already know is not answering.
        let pool = pool_of(&["127.0.0.1:1"]);
        pool.upstreams()[0].record_failure(1);
        assert_eq!(pool.healthy_count(), 0);
        assert!(pool.acquire().is_none());
    }

    #[test]
    fn removal_requires_consecutive_failures() {
        let pool = pool_of(&["127.0.0.1:1"]);
        let upstream = &pool.upstreams()[0];

        assert!(!upstream.record_failure(3));
        assert!(upstream.is_healthy());
        assert!(!upstream.record_failure(3));
        assert!(upstream.is_healthy());
        assert!(upstream.record_failure(3));
        assert!(!upstream.is_healthy());
    }

    #[test]
    fn one_success_resets_the_failure_streak() {
        let pool = pool_of(&["127.0.0.1:1"]);
        let upstream = &pool.upstreams()[0];

        upstream.record_failure(3);
        upstream.record_failure(3);
        upstream.record_success(1);
        // The streak restarts, so two more failures must not be enough.
        upstream.record_failure(3);
        upstream.record_failure(3);
        assert!(upstream.is_healthy());
    }

    #[test]
    fn recovery_requires_consecutive_successes() {
        let pool = pool_of(&["127.0.0.1:1"]);
        let upstream = &pool.upstreams()[0];

        upstream.record_failure(1);
        assert!(!upstream.is_healthy());

        assert!(!upstream.record_success(2));
        assert!(!upstream.is_healthy());
        assert!(upstream.record_success(2));
        assert!(upstream.is_healthy());
    }

    #[test]
    fn a_flapping_instance_does_not_oscillate_on_alternating_probes() {
        // With a single threshold this instance would rejoin on every other
        // probe and take a share of traffic it cannot serve.
        let pool = pool_of(&["127.0.0.1:1"]);
        let upstream = &pool.upstreams()[0];
        upstream.record_failure(1);

        for _ in 0..5 {
            upstream.record_success(3);
            upstream.record_failure(2);
            assert!(!upstream.is_healthy(), "flapping instance rejoined rotation");
        }
    }

    #[test]
    fn traffic_moves_to_the_survivor_and_returns_on_recovery() {
        let pool = pool_of(&["127.0.0.1:1", "127.0.0.1:2"]);
        let (first, second) = (&pool.upstreams()[0], &pool.upstreams()[1]);

        first.record_failure(1);
        assert_eq!(pool.healthy_count(), 1);
        for _ in 0..10 {
            let lease = pool.acquire().expect("survivor should serve");
            assert_eq!(lease.address(), second.address());
        }

        first.record_success(1);
        assert_eq!(pool.healthy_count(), 2);
    }

    #[test]
    fn least_connections_prefers_the_idle_instance() {
        let pool = pool_of(&["127.0.0.1:1", "127.0.0.1:2"]);

        // Hold two leases; whichever instances they landed on are now busy.
        let mut held: Vec<Lease> = (0..2).filter_map(|_| pool.acquire()).collect();
        assert_eq!(held.len(), 2);
        assert_eq!(pool.upstreams()[0].in_flight(), 1);
        assert_eq!(pool.upstreams()[1].in_flight(), 1);

        // Release exactly one. `held` keeps the other alive — draining the vec
        // instead would drop both and leave nothing busy to compare against.
        let released = held.remove(0);
        let released_address = released.address().to_owned();
        drop(released);

        let idle: Vec<_> = pool.upstreams().iter().filter(|u| u.in_flight() == 0).collect();
        assert_eq!(idle.len(), 1, "expected exactly one idle instance");
        assert_eq!(idle[0].address(), released_address);

        // The idle instance must be chosen over the one still serving.
        let lease = pool.acquire().unwrap();
        assert_eq!(lease.address(), released_address);

        drop(held);
    }

    #[test]
    fn a_lease_releases_its_slot_when_dropped() {
        let pool = pool_of(&["127.0.0.1:1"]);
        {
            let _lease = pool.acquire().unwrap();
            assert_eq!(pool.upstreams()[0].in_flight(), 1);
        }
        // Dropping must release even on an early return or a cancelled handler,
        // or the instance looks permanently busy.
        assert_eq!(pool.upstreams()[0].in_flight(), 0);
    }

    #[test]
    fn ties_rotate_instead_of_always_picking_the_first() {
        let pool = pool_of(&["127.0.0.1:1", "127.0.0.1:2"]);
        let mut seen = std::collections::BTreeSet::new();

        for _ in 0..4 {
            let lease = pool.acquire().unwrap();
            seen.insert(lease.address().to_owned());
            drop(lease);
        }

        assert_eq!(seen.len(), 2, "an idle pool sent everything to one instance");
    }

    #[test]
    fn failures_are_counted_for_diagnostics() {
        let pool = pool_of(&["127.0.0.1:1"]);
        let upstream = &pool.upstreams()[0];
        upstream.record_failure(10);
        upstream.record_failure(10);
        assert_eq!(upstream.total_failures(), 2);
    }
}
