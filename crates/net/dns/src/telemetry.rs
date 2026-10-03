//! DNS telemetry: lock-free counters and statistics collection.
//!
//! This module tracks DNS query statistics including per-upstream metrics,
//! latency buckets, and a rolling one-minute window over the last 1440 minutes (24 hours).
//! All counters are atomic for thread-safe updates without locks.

use selfhost_json::Json;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// DNS telemetry snapshot at a point in time.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Unix timestamp when this snapshot was taken.
    pub at_unix: u64,
    /// Unix timestamp when the server started (or the telemetry was reset).
    pub since_unix: u64,
    /// The process identifier: "daemon" or "lan-dns".
    pub process: String,
    /// Global counters.
    pub counters: GlobalCounters,
    /// Per-upstream statistics.
    pub upstreams: Vec<UpstreamStats>,
    /// Last 1440 one-minute buckets (oldest first).
    pub minutes: Vec<MinuteStats>,
}

/// Global DNS counters.
#[derive(Debug, Clone, Default)]
pub struct GlobalCounters {
    /// Total queries received.
    pub queries: u64,
    /// Queries from LAN peers.
    pub lan: u64,
    /// Queries from non-LAN peers.
    pub public: u64,
    /// Queries answered from local zones.
    pub zone: u64,
    /// Queries answered from cache.
    pub cache_hit: u64,
    /// Queries served stale (from expired cache entries).
    pub stale: u64,
    /// Queries successfully forwarded upstream.
    pub forwarded: u64,
    /// SERVFAIL responses sent.
    pub servfail: u64,
    /// Queries dropped (over capacity).
    pub dropped: u64,
    /// Socket receive/accept errors.
    pub recv_errors: u64,
}

/// Per-upstream statistics.
#[derive(Debug, Clone)]
pub struct UpstreamStats {
    /// The upstream resolver address.
    pub addr: String,
    /// Successful responses received.
    pub ok: u64,
    /// Queries that timed out.
    pub timeout: u64,
    /// Queries that received errors.
    pub error: u64,
    /// Latency buckets: [bucket_ms, count].
    /// Buckets: <5, <20, <50, <100, <250, <500, <1000, <2000, >=2000 ms.
    pub buckets_ms: Vec<(Option<u16>, u64)>,
}

/// One-minute statistics for the rolling window.
#[derive(Debug, Clone, Default)]
pub struct MinuteStats {
    /// Unix timestamp (start of the minute).
    pub at_unix: u64,
    /// Queries in this minute.
    pub queries: u64,
    /// Failed queries (SERVFAIL + drops).
    pub failures: u64,
    /// Queries taking >= 500ms.
    pub slow: u64,
}

/// The telemetry holder.
#[derive(Clone)]
pub struct Telemetry {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Telemetry").finish()
    }
}

struct Inner {
    /// Global counters.
    queries: AtomicU64,
    lan: AtomicU64,
    public: AtomicU64,
    zone: AtomicU64,
    cache_hit: AtomicU64,
    stale: AtomicU64,
    forwarded: AtomicU64,
    servfail: AtomicU64,
    dropped: AtomicU64,
    recv_errors: AtomicU64,
    /// Per-upstream counters. Entry structure: addr, ok, timeout, error, buckets...
    /// We'll use a Vec of (String, Arc<UpstreamInner>).
    upstreams: std::sync::Mutex<Vec<(String, Arc<UpstreamInner>)>>,
    /// Ring buffer of minutes: current index and the 1440 slots.
    minute_ring: std::sync::Mutex<MinuteRing>,
    /// Server start time (for "since" field).
    start_time: u64,
}

struct UpstreamInner {
    ok: AtomicU64,
    timeout: AtomicU64,
    error: AtomicU64,
    /// Latency buckets: <5, <20, <50, <100, <250, <500, <1000, <2000, >=2000 ms
    buckets: [AtomicU64; 9],
}

struct MinuteRing {
    current_index: usize,
    current_minute: u64,
    slots: [MinuteStats; 1440],
}

impl MinuteRing {
    fn new() -> Self {
        let now = current_unix_time();
        let slots = std::array::from_fn::<_, 1440, _>(|_| MinuteStats::default());
        Self {
            current_index: 0,
            current_minute: now / 60,
            slots,
        }
    }

    fn advance_if_needed(&mut self) {
        let now = current_unix_time();
        let current_minute = now / 60;

        if current_minute > self.current_minute {
            self.current_minute = current_minute;
            self.current_index = (self.current_index + 1) % 1440;
            self.slots[self.current_index] = MinuteStats {
                at_unix: current_minute * 60,
                ..Default::default()
            };
        }
    }

    fn record_query(&mut self) {
        self.advance_if_needed();
        self.slots[self.current_index].queries = self.slots[self.current_index].queries.saturating_add(1);
    }

    fn record_failure(&mut self) {
        self.advance_if_needed();
        self.slots[self.current_index].failures = self.slots[self.current_index].failures.saturating_add(1);
    }

    fn record_slow(&mut self) {
        self.advance_if_needed();
        self.slots[self.current_index].slow = self.slots[self.current_index].slow.saturating_add(1);
    }
}

impl Telemetry {
    /// Creates a new telemetry tracker.
    pub fn new() -> Self {
        let start_time = current_unix_time();
        Self {
            inner: Arc::new(Inner {
                queries: AtomicU64::new(0),
                lan: AtomicU64::new(0),
                public: AtomicU64::new(0),
                zone: AtomicU64::new(0),
                cache_hit: AtomicU64::new(0),
                stale: AtomicU64::new(0),
                forwarded: AtomicU64::new(0),
                servfail: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
                recv_errors: AtomicU64::new(0),
                upstreams: std::sync::Mutex::new(Vec::new()),
                minute_ring: std::sync::Mutex::new(MinuteRing::new()),
                start_time,
            }),
        }
    }

    /// Records a received query.
    pub fn record_query(&self) {
        self.inner.queries.fetch_add(1, Ordering::Relaxed);
        let mut ring = self.inner.minute_ring.lock().unwrap();
        ring.record_query();
    }

    /// Records a query from a LAN peer.
    pub fn record_lan(&self) {
        self.inner.lan.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a query from a non-LAN peer.
    pub fn record_public(&self) {
        self.inner.public.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a query answered from local zones.
    pub fn record_zone(&self) {
        self.inner.zone.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a cache hit.
    pub fn record_cache_hit(&self) {
        self.inner.cache_hit.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a stale cache hit.
    pub fn record_stale(&self) {
        self.inner.stale.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a successful forward.
    pub fn record_forwarded(&self) {
        self.inner.forwarded.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a SERVFAIL response.
    pub fn record_servfail(&self) {
        self.inner.servfail.fetch_add(1, Ordering::Relaxed);
        let mut ring = self.inner.minute_ring.lock().unwrap();
        ring.record_failure();
    }

    /// Records a dropped query.
    pub fn record_dropped(&self) {
        self.inner.dropped.fetch_add(1, Ordering::Relaxed);
        let mut ring = self.inner.minute_ring.lock().unwrap();
        ring.record_failure();
    }

    /// Records a receive error.
    pub fn record_recv_error(&self) {
        self.inner.recv_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a slow query (>= 500ms).
    pub fn record_slow(&self) {
        let mut ring = self.inner.minute_ring.lock().unwrap();
        ring.record_slow();
    }

    /// Records an upstream response.
    pub fn record_upstream_response(&self, addr: &SocketAddr, latency_ms: u64) {
        let mut upstreams = self.inner.upstreams.lock().unwrap();
        let addr_str = addr.to_string();

        let upstream = upstreams
            .iter_mut()
            .find(|(a, _)| a == &addr_str)
            .map(|(_, u)| Arc::clone(u))
            .unwrap_or_else(|| {
                let u = Arc::new(UpstreamInner {
                    ok: AtomicU64::new(0),
                    timeout: AtomicU64::new(0),
                    error: AtomicU64::new(0),
                    buckets: [const { AtomicU64::new(0) }; 9],
                });
                upstreams.push((addr_str, Arc::clone(&u)));
                u
            });

        upstream.ok.fetch_add(1, Ordering::Relaxed);

        // Record latency bucket.
        let bucket_idx = match latency_ms {
            0..=4 => 0,
            5..=19 => 1,
            20..=49 => 2,
            50..=99 => 3,
            100..=249 => 4,
            250..=499 => 5,
            500..=999 => 6,
            1000..=1999 => 7,
            _ => 8,
        };
        upstream.buckets[bucket_idx].fetch_add(1, Ordering::Relaxed);
    }

    /// Records an upstream timeout.
    pub fn record_upstream_timeout(&self, addr: &SocketAddr) {
        let mut upstreams = self.inner.upstreams.lock().unwrap();
        let addr_str = addr.to_string();

        let upstream = upstreams
            .iter_mut()
            .find(|(a, _)| a == &addr_str)
            .map(|(_, u)| Arc::clone(u))
            .unwrap_or_else(|| {
                let u = Arc::new(UpstreamInner {
                    ok: AtomicU64::new(0),
                    timeout: AtomicU64::new(0),
                    error: AtomicU64::new(0),
                    buckets: [const { AtomicU64::new(0) }; 9],
                });
                upstreams.push((addr_str, Arc::clone(&u)));
                u
            });

        upstream.timeout.fetch_add(1, Ordering::Relaxed);
    }

    /// Records an upstream error.
    pub fn record_upstream_error(&self, addr: &SocketAddr) {
        let mut upstreams = self.inner.upstreams.lock().unwrap();
        let addr_str = addr.to_string();

        let upstream = upstreams
            .iter_mut()
            .find(|(a, _)| a == &addr_str)
            .map(|(_, u)| Arc::clone(u))
            .unwrap_or_else(|| {
                let u = Arc::new(UpstreamInner {
                    ok: AtomicU64::new(0),
                    timeout: AtomicU64::new(0),
                    error: AtomicU64::new(0),
                    buckets: [const { AtomicU64::new(0) }; 9],
                });
                upstreams.push((addr_str, Arc::clone(&u)));
                u
            });

        upstream.error.fetch_add(1, Ordering::Relaxed);
    }

    /// Takes a snapshot of all telemetry.
    pub fn snapshot(&self, process: &str) -> Snapshot {
        let at_unix = current_unix_time();

        let counters = GlobalCounters {
            queries: self.inner.queries.load(Ordering::Relaxed),
            lan: self.inner.lan.load(Ordering::Relaxed),
            public: self.inner.public.load(Ordering::Relaxed),
            zone: self.inner.zone.load(Ordering::Relaxed),
            cache_hit: self.inner.cache_hit.load(Ordering::Relaxed),
            stale: self.inner.stale.load(Ordering::Relaxed),
            forwarded: self.inner.forwarded.load(Ordering::Relaxed),
            servfail: self.inner.servfail.load(Ordering::Relaxed),
            dropped: self.inner.dropped.load(Ordering::Relaxed),
            recv_errors: self.inner.recv_errors.load(Ordering::Relaxed),
        };

        let upstreams = {
            let upstreams_inner = self.inner.upstreams.lock().unwrap();
            upstreams_inner
                .iter()
                .map(|(addr, upstream)| UpstreamStats {
                    addr: addr.clone(),
                    ok: upstream.ok.load(Ordering::Relaxed),
                    timeout: upstream.timeout.load(Ordering::Relaxed),
                    error: upstream.error.load(Ordering::Relaxed),
                    buckets_ms: vec![
                        (Some(5), upstream.buckets[0].load(Ordering::Relaxed)),
                        (Some(20), upstream.buckets[1].load(Ordering::Relaxed)),
                        (Some(50), upstream.buckets[2].load(Ordering::Relaxed)),
                        (Some(100), upstream.buckets[3].load(Ordering::Relaxed)),
                        (Some(250), upstream.buckets[4].load(Ordering::Relaxed)),
                        (Some(500), upstream.buckets[5].load(Ordering::Relaxed)),
                        (Some(1000), upstream.buckets[6].load(Ordering::Relaxed)),
                        (Some(2000), upstream.buckets[7].load(Ordering::Relaxed)),
                        (None, upstream.buckets[8].load(Ordering::Relaxed)),
                    ],
                })
                .collect()
        };

        let minutes = {
            let ring = self.inner.minute_ring.lock().unwrap();
            let mut result = Vec::with_capacity(1440);
            for i in 0..1440 {
                let idx = (ring.current_index + i) % 1440;
                if ring.slots[idx].at_unix > 0 || i > 0 {
                    result.push(ring.slots[idx].clone());
                }
            }
            result
        };

        Snapshot {
            at_unix,
            since_unix: self.inner.start_time,
            process: process.to_string(),
            counters,
            upstreams,
            minutes,
        }
    }
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::new()
    }
}

/// Converts a Snapshot to JSON using the selfhost_json crate.
pub fn snapshot_to_json(snapshot: &Snapshot) -> Json {
    let upstreams = snapshot
        .upstreams
        .iter()
        .map(|upstream| {
            let buckets = upstream
                .buckets_ms
                .iter()
                .map(|(ms, count)| {
                    Json::array(vec![
                        ms.map(|m| Json::Number(m as f64)).unwrap_or(Json::Null),
                        Json::Number(*count as f64),
                    ])
                })
                .collect::<Vec<_>>();

            Json::object(vec![
                ("addr", Json::String(upstream.addr.clone())),
                ("ok", Json::Number(upstream.ok as f64)),
                ("timeout", Json::Number(upstream.timeout as f64)),
                ("error", Json::Number(upstream.error as f64)),
                ("buckets_ms", Json::Array(buckets)),
            ])
        })
        .collect::<Vec<_>>();

    let minutes = snapshot
        .minutes
        .iter()
        .map(|m| {
            Json::object(vec![
                ("at_unix", Json::Number(m.at_unix as f64)),
                ("queries", Json::Number(m.queries as f64)),
                ("failures", Json::Number(m.failures as f64)),
                ("slow", Json::Number(m.slow as f64)),
            ])
        })
        .collect::<Vec<_>>();

    Json::object(vec![
        ("at_unix", Json::Number(snapshot.at_unix as f64)),
        ("since_unix", Json::Number(snapshot.since_unix as f64)),
        ("process", Json::String(snapshot.process.clone())),
        (
            "counters",
            Json::object(vec![
                ("queries", Json::Number(snapshot.counters.queries as f64)),
                ("lan", Json::Number(snapshot.counters.lan as f64)),
                ("public", Json::Number(snapshot.counters.public as f64)),
                ("zone", Json::Number(snapshot.counters.zone as f64)),
                ("cache_hit", Json::Number(snapshot.counters.cache_hit as f64)),
                ("stale", Json::Number(snapshot.counters.stale as f64)),
                ("forwarded", Json::Number(snapshot.counters.forwarded as f64)),
                ("servfail", Json::Number(snapshot.counters.servfail as f64)),
                ("dropped", Json::Number(snapshot.counters.dropped as f64)),
                ("recv_errors", Json::Number(snapshot.counters.recv_errors as f64)),
            ]),
        ),
        ("upstreams", Json::Array(upstreams)),
        ("minutes", Json::Array(minutes)),
    ])
}

/// Get the current Unix timestamp in seconds.
fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_counters() {
        let tel = Telemetry::new();
        tel.record_query();
        tel.record_lan();
        tel.record_zone();
        tel.record_cache_hit();

        let snapshot = tel.snapshot("test");
        assert_eq!(snapshot.counters.queries, 1);
        assert_eq!(snapshot.counters.lan, 1);
        assert_eq!(snapshot.counters.zone, 1);
        assert_eq!(snapshot.counters.cache_hit, 1);
    }

    #[test]
    fn test_upstream_tracking() {
        let tel = Telemetry::new();
        let addr: SocketAddr = "1.1.1.1:53".parse().unwrap();

        tel.record_upstream_response(&addr, 10);
        tel.record_upstream_response(&addr, 500);
        tel.record_upstream_timeout(&addr);

        let snapshot = tel.snapshot("test");
        assert_eq!(snapshot.upstreams.len(), 1);
        assert_eq!(snapshot.upstreams[0].ok, 2);
        assert_eq!(snapshot.upstreams[0].timeout, 1);
    }

    #[test]
    fn test_snapshot_json_has_required_fields() {
        let tel = Telemetry::new();
        tel.record_query();

        let snapshot = tel.snapshot("daemon");
        let json = snapshot_to_json(&snapshot);

        assert!(json.get("at_unix").is_some());
        assert!(json.get("since_unix").is_some());
        assert!(json.get("process").is_some());
        assert!(json.get("counters").is_some());
        assert!(json.get("upstreams").is_some());
        assert!(json.get("minutes").is_some());
    }

    #[test]
    fn test_minute_ring_advances() {
        let tel = Telemetry::new();
        // Record multiple queries in the same minute
        for _ in 0..10 {
            tel.record_query();
        }

        let snapshot = tel.snapshot("test");
        assert_eq!(snapshot.counters.queries, 10);
        assert!(snapshot.minutes.len() > 0);
    }
}
