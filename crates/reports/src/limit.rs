//! Rate limiting, because the intake is open and the caller is anonymous.
//!
//! Two buckets stand between a stranger and this box's disk and mailbox: one **per source**,
//! so a single agent looping cannot outrun everybody else, and one **global**, so a thousand
//! sources each staying inside the per-source rate still cannot. Both are token buckets — a
//! steady rate with a burst on top — because a reporter that files three reports in one
//! second while writing them up is ordinary, and a reporter that files three a second for an
//! hour is not.
//!
//! # The clock is a parameter
//!
//! Every entry point takes `now`. That is what lets the whole module be tested against an
//! exact timeline instead of a sleeping test, and it is why a limiter is a plain value with
//! no timer inside it.
//!
//! # The table of sources is bounded too
//!
//! A limiter that grows one entry per source *is* the memory-exhaustion vector it was added
//! to prevent, so the table is capped at [`MAX_TRACKED`]. When it is full, sources whose
//! bucket has refilled — which is to say, ones no longer using their allowance — are dropped
//! first, and if none has, the least recently seen goes. Dropping the *idle* rather than the
//! *active* is deliberate: the entry that matters is the one being spent.

use std::collections::HashMap;
use std::time::Instant;

/// How many distinct sources are tracked at once.
pub const MAX_TRACKED: usize = 4_096;

/// A steady rate with a burst allowance.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rate {
    /// How many requests may arrive at once before the steady rate applies.
    pub burst: u32,
    /// How many are replenished per minute.
    pub per_minute: f64,
}

impl Rate {
    /// A rate of `burst` at once, refilling `per_minute`.
    #[must_use]
    pub fn new(burst: u32, per_minute: f64) -> Self {
        Self { burst, per_minute }
    }
}

/// What a limiter decided about one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The request may proceed.
    Admit,
    /// The request is refused; the number is what to put in `Retry-After`, in seconds.
    Refuse(u64),
}

impl Decision {
    /// Whether this decision admits the request.
    #[must_use]
    pub fn admitted(self) -> bool {
        matches!(self, Self::Admit)
    }
}

/// One token bucket.
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    /// A full bucket as of `now`.
    fn full(rate: Rate, now: Instant) -> Self {
        Self { tokens: f64::from(rate.burst), last: now }
    }

    /// Refills for the time since the last look, then spends one token if there is one.
    fn take(&mut self, rate: Rate, now: Instant) -> Decision {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * rate.per_minute / 60.0).min(f64::from(rate.burst));
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            return Decision::Admit;
        }
        // Seconds until one whole token exists again, rounded up and never zero: a
        // `Retry-After: 0` invites the client straight back into the same refusal.
        let missing = 1.0 - self.tokens;
        let wait = (missing * 60.0 / rate.per_minute).ceil().max(1.0);
        Decision::Refuse(wait as u64)
    }

    /// Whether this bucket has refilled completely — the mark of a source no longer active.
    fn idle(&self, rate: Rate) -> bool {
        self.tokens >= f64::from(rate.burst)
    }
}

/// A single bucket, for something there is only one of — the mailer, say.
#[derive(Debug, Clone)]
pub struct Meter {
    rate: Rate,
    bucket: Option<Bucket>,
}

impl Meter {
    /// A meter that admits at `rate`, starting full.
    #[must_use]
    pub fn new(rate: Rate) -> Self {
        Self { rate, bucket: None }
    }

    /// Spends one allowance, or says how long to wait.
    pub fn take(&mut self, now: Instant) -> Decision {
        let bucket = self.bucket.get_or_insert_with(|| Bucket::full(self.rate, now));
        bucket.take(self.rate, now)
    }
}

/// The per-source and global limiter the intake runs every request through.
#[derive(Debug, Clone)]
pub struct Limiter {
    per_source: Rate,
    global_rate: Rate,
    sources: HashMap<String, Bucket>,
    global: Option<Bucket>,
}

impl Limiter {
    /// A limiter allowing `per_source` from each source and `global` in total.
    #[must_use]
    pub fn new(per_source: Rate, global: Rate) -> Self {
        Self {
            per_source,
            global_rate: global,
            sources: HashMap::new(),
            global: None,
        }
    }

    /// Whether a request from `source` is admitted at `now`.
    ///
    /// The per-source bucket is consulted first so that a flood from one place is refused
    /// without spending the global allowance everybody else shares.
    pub fn admit(&mut self, source: &str, now: Instant) -> Decision {
        if let Some(bucket) = self.sources.get_mut(source) {
            let decision = bucket.take(self.per_source, now);
            if !decision.admitted() {
                return decision;
            }
        } else {
            self.make_room(now);
            let mut bucket = Bucket::full(self.per_source, now);
            let decision = bucket.take(self.per_source, now);
            self.sources.insert(source.to_string(), bucket);
            if !decision.admitted() {
                return decision;
            }
        }

        let global = self.global.get_or_insert_with(|| Bucket::full(self.global_rate, now));
        global.take(self.global_rate, now)
    }

    /// How many sources are currently tracked. Exposed for the health answer.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.sources.len()
    }

    /// Makes room for one more source when the table is at [`MAX_TRACKED`].
    fn make_room(&mut self, now: Instant) {
        if self.sources.len() < MAX_TRACKED {
            return;
        }
        let rate = self.per_source;
        let before = self.sources.len();
        self.sources.retain(|_, bucket| {
            let mut refilled = *bucket;
            let elapsed = now.saturating_duration_since(refilled.last).as_secs_f64();
            refilled.tokens =
                (refilled.tokens + elapsed * rate.per_minute / 60.0).min(f64::from(rate.burst));
            !refilled.idle(rate)
        });
        if self.sources.len() < before {
            return;
        }
        // Everyone is mid-burst: the least recently seen loses its place.
        if let Some(oldest) = self
            .sources
            .iter()
            .min_by_key(|(_, bucket)| bucket.last)
            .map(|(source, _)| source.clone())
        {
            self.sources.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn limiter() -> Limiter {
        Limiter::new(Rate::new(3, 3.0), Rate::new(10, 60.0))
    }

    #[test]
    fn a_burst_is_admitted_and_the_next_one_is_not() {
        let mut limiter = limiter();
        let now = Instant::now();
        for _ in 0..3 {
            assert!(limiter.admit("one", now).admitted());
        }
        match limiter.admit("one", now) {
            Decision::Refuse(seconds) => assert!(seconds >= 1, "retry-after was {seconds}"),
            Decision::Admit => panic!("a fourth request inside the burst must be refused"),
        }
    }

    #[test]
    fn waiting_earns_another_request() {
        let mut limiter = limiter();
        let start = Instant::now();
        for _ in 0..3 {
            assert!(limiter.admit("one", start).admitted());
        }
        assert!(!limiter.admit("one", start).admitted());
        // Three a minute: twenty seconds buys exactly one.
        assert!(limiter.admit("one", start + Duration::from_secs(20)).admitted());
    }

    #[test]
    fn one_flooding_source_does_not_refuse_another() {
        let mut limiter = limiter();
        let now = Instant::now();
        for _ in 0..5 {
            let _ = limiter.admit("flooder", now);
        }
        assert!(limiter.admit("someone-else", now).admitted());
    }

    #[test]
    fn the_global_bucket_stops_a_crowd_that_each_stay_polite() {
        let mut limiter = Limiter::new(Rate::new(3, 3.0), Rate::new(4, 4.0));
        let now = Instant::now();
        for nth in 0..4 {
            assert!(limiter.admit(&format!("source-{nth}"), now).admitted());
        }
        assert!(
            !limiter.admit("source-99", now).admitted(),
            "the global allowance is spent, so the crowd is refused"
        );
    }

    #[test]
    fn the_source_table_never_grows_past_its_cap() {
        let mut limiter = limiter();
        let now = Instant::now();
        for nth in 0..(MAX_TRACKED + 200) {
            let _ = limiter.admit(&format!("source-{nth}"), now);
        }
        assert!(limiter.tracked() <= MAX_TRACKED, "tracked {}", limiter.tracked());
    }

    #[test]
    fn an_idle_source_is_evicted_before_an_active_one() {
        let mut limiter = Limiter::new(Rate::new(2, 60.0), Rate::new(1_000_000, 1_000_000.0));
        let start = Instant::now();
        // Fill the table with sources that spend nothing after their first request.
        for nth in 0..MAX_TRACKED {
            let _ = limiter.admit(&format!("idle-{nth}"), start);
        }
        // An active source, still mid-burst at the moment the table is full.
        let later = start + Duration::from_secs(120);
        assert!(limiter.admit("active", later).admitted());
        assert!(limiter.admit("active", later).admitted());
        let _ = limiter.admit("newcomer", later);
        assert!(
            !limiter.admit("active", later).admitted(),
            "the active source kept its bucket rather than being evicted and refilled"
        );
    }

    #[test]
    fn a_meter_is_one_bucket_with_the_same_arithmetic() {
        let mut meter = Meter::new(Rate::new(1, 1.0));
        let now = Instant::now();
        assert!(meter.take(now).admitted());
        assert!(!meter.take(now).admitted());
        assert!(meter.take(now + Duration::from_secs(61)).admitted());
    }
}
