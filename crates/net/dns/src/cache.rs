//! TTL-respecting forward cache with serve-stale support (RFC 8767).
//!
//! Caches upstream DNS answers for queries that originate from LAN peers
//! asking about names outside every served zone — the split-horizon forward path.
//! Zone answers are never cached; negative answers (NXDOMAIN / NOERROR with no
//! answers) are cached with their own TTL rules.
//!
//! # Cache key
//!
//! `(lowercase qname, qtype, qclass)`, but DNS stub queries are always qclass IN (1).
//!
//! # Storage
//!
//! For each cached entry:
//! - The raw upstream response bytes
//! - The time it was stored (`Instant`)
//! - The minimum TTL across all answer and authority records
//!
//! # TTL and expiry
//!
//! - **Positive answers** (NOERROR with answers): cached for the minimum TTL
//!   across all answer records.
//! - **Negative answers** (NXDOMAIN or NOERROR with no answers): cached for
//!   `min(SOA minimum if present, 300s)`.
//! - **Uncacheable**: SERVFAIL, REFUSED, truncated (TC), or malformed responses.
//!
//! # Serve-stale (RFC 8767)
//!
//! Expired entries are kept for up to 24 hours. When every upstream fails,
//! a stale entry is served instead with all TTLs rewritten to 30 seconds,
//! and "stale" is counted for diagnostics.
//!
//! # Bounded capacity
//!
//! Maximum 4096 entries. When full and inserting:
//! 1. Evict all expired-beyond-stale entries (older than 24h).
//! 2. If still full, evict the soonest-expiring entry.
//!
//! Entry capacity stays constant: memory does not grow unbounded.
//!
//! # On-wire TTL rewriting
//!
//! Uses the same DNS wire parsing as [`wire`] to find and decrement each record's TTL.

use crate::wire::{self, RecordType, Response, ResponseCode};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Maximum number of cache entries. Memory stays bounded.
const MAX_CACHE_ENTRIES: usize = 4096;

/// How long to serve a stale entry after it expires.
const STALE_WINDOW: Duration = Duration::from_secs(24 * 3600);

/// TTL to use when serving a stale entry.
const STALE_TTL: u32 = 30;

/// Default TTL for negative answers when no SOA is present.
const DEFAULT_NEGATIVE_TTL: u32 = 300;

/// One cached DNS response.
#[derive(Clone)]
struct CacheEntry {
    /// Raw response bytes from the upstream (with the original message ID).
    response: Vec<u8>,
    /// When this entry was cached.
    stored_at: Instant,
    /// Minimum TTL across all answer/authority records.
    min_ttl: u32,
}

/// Cache key: (lowercase qname, qtype code).
///
/// qclass is always IN (1) for DNS stub queries, so we don't store it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    qname: String,
    qtype: u16,
}

impl CacheKey {
    fn new(qname: &str, qtype: RecordType) -> Self {
        Self {
            qname: qname.to_ascii_lowercase(),
            qtype: qtype.code(),
        }
    }
}

/// A TTL-respecting cache for upstream DNS answers.
///
/// Thread-safe via a `Mutex`, as it's called from async query handlers.
pub struct DnsCache {
    entries: std::sync::Mutex<HashMap<CacheKey, CacheEntry>>,
}

impl DnsCache {
    /// Creates an empty cache.
    pub fn new() -> Self {
        Self {
            entries: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Looks up a cached answer.
    ///
    /// Returns `Some(answer_bytes)` if a fresh entry exists, with the message ID
    /// rewritten to `new_id` and all TTLs decremented by the elapsed time.
    /// Returns `None` if no entry exists or it has expired.
    pub fn lookup(&self, qname: &str, qtype: RecordType, new_id: u16) -> Option<Vec<u8>> {
        let key = CacheKey::new(qname, qtype);
        let entries = self.entries.lock().unwrap();

        let entry = entries.get(&key)?;
        let elapsed = entry.stored_at.elapsed();

        // Expired?
        if elapsed > Duration::from_secs(entry.min_ttl as u64) {
            return None;
        }

        Some(rewrite_answer(&entry.response, new_id, elapsed, None))
    }

    /// Looks up a stale cached answer (expired but within the stale window).
    ///
    /// Used when all upstreams fail. Returns a response with TTLs set to 30.
    pub fn lookup_stale(&self, qname: &str, qtype: RecordType, new_id: u16) -> Option<Vec<u8>> {
        let key = CacheKey::new(qname, qtype);
        let entries = self.entries.lock().unwrap();

        let entry = entries.get(&key)?;
        let elapsed = entry.stored_at.elapsed();

        // Must be expired but within stale window.
        let ttl_secs = entry.min_ttl as u64;
        if elapsed <= Duration::from_secs(ttl_secs) {
            // Still fresh, not stale.
            return None;
        }
        if elapsed > STALE_WINDOW {
            // Too old even for stale serving.
            return None;
        }

        // Serve stale with TTL=30.
        Some(rewrite_answer(
            &entry.response,
            new_id,
            Duration::ZERO,
            Some(STALE_TTL),
        ))
    }

    /// Caches a successful upstream response.
    ///
    /// Never caches SERVFAIL, REFUSED, or truncated answers. Updates the cache
    /// to stay within MAX_CACHE_ENTRIES by evicting stale entries and then the
    /// soonest-expiring live entry if necessary.
    pub fn insert(&self, qname: &str, qtype: RecordType, response: &[u8]) {
        // Decode to check if it's cacheable.
        let decoded = match wire::decode_response(response) {
            Ok(resp) => resp,
            Err(_) => return, // Malformed, don't cache.
        };

        // Never cache failure codes.
        if matches!(
            decoded.code,
            ResponseCode::ServerFailure | ResponseCode::Refused | ResponseCode::FormatError
        ) {
            return;
        }

        // Never cache truncated.
        if is_truncated(response) {
            return;
        }

        let is_negative = decoded.answers.is_empty();
        let min_ttl = calculate_min_ttl(&decoded, is_negative);

        let entry = CacheEntry {
            response: response.to_vec(),
            stored_at: Instant::now(),
            min_ttl,
        };

        let key = CacheKey::new(qname, qtype);

        let mut entries = self.entries.lock().unwrap();

        // Ensure room for the new entry.
        if entries.len() >= MAX_CACHE_ENTRIES && !entries.contains_key(&key) {
            evict_one(&mut entries);
        }

        entries.insert(key, entry);
    }

    /// Returns the number of entries currently cached.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Checks if a response has the TC (truncated) bit set.
fn is_truncated(response: &[u8]) -> bool {
    if response.len() < 3 {
        return false;
    }
    // Byte 2, bit 1 is the TC flag.
    (response[2] & 0x02) != 0
}

/// Calculates the minimum TTL for caching.
///
/// For positive answers: the minimum TTL across all answer records.
/// For negative answers: min(SOA minimum if present in authority, 300s).
fn calculate_min_ttl(response: &Response, is_negative: bool) -> u32 {
    if is_negative {
        // Negative answer: use SOA minimum or default.
        let soa_min = response
            .authority
            .iter()
            .find_map(|record| match &record.data {
                // RFC 2308 §5: the lesser of the SOA's own TTL and its minimum.
                crate::wire::RecordData::Soa { minimum, .. } => Some(record.ttl.min(*minimum)),
                _ => None,
            });

        return soa_min
            .unwrap_or(DEFAULT_NEGATIVE_TTL)
            .min(DEFAULT_NEGATIVE_TTL);
    }

    // Positive answer: minimum across all answer records.
    response
        .answers
        .iter()
        .map(|record| record.ttl)
        .min()
        .unwrap_or(0)
}

/// EDNS0's OPT pseudo-record type. Its TTL field carries the extended RCODE,
/// version and DO flag, not a lifetime, so TTL rewriting must leave it alone.
const OPT_TYPE: u16 = 41;

/// The UDP size every client accepts without EDNS0 (RFC 1035).
const CLASSIC_UDP_SIZE: usize = 512;

/// Copies `response` with its message ID set to `new_id` and every record's
/// TTL either reduced by `elapsed` or, for serve-stale, pinned to `pinned`.
fn rewrite_answer(response: &[u8], new_id: u16, elapsed: Duration, pinned: Option<u32>) -> Vec<u8> {
    let mut answer = response.to_vec();
    let elapsed = u32::try_from(elapsed.as_secs()).unwrap_or(u32::MAX);
    for at in record_offsets(&answer) {
        if field(&answer, at) == OPT_TYPE {
            continue;
        }
        let ttl = &mut answer[at + 4..at + 8];
        let old = u32::from_be_bytes([ttl[0], ttl[1], ttl[2], ttl[3]]);
        let new = pinned.unwrap_or_else(|| old.saturating_sub(elapsed));
        ttl.copy_from_slice(&new.to_be_bytes());
    }
    if let Some(id) = answer.get_mut(..2) {
        id.copy_from_slice(&new_id.to_be_bytes());
    }
    answer
}

/// The largest UDP answer the sender of `query` accepts: its EDNS0 OPT
/// record's advertised size, never below 512, or 512 when it sent none.
/// A cached answer fetched for one client must not overflow another's buffer.
pub(crate) fn udp_payload_limit(query: &[u8]) -> usize {
    record_offsets(query)
        .into_iter()
        .find(|&at| field(query, at) == OPT_TYPE)
        .map(|at| usize::from(field(query, at + 2)).max(CLASSIC_UDP_SIZE))
        .unwrap_or(CLASSIC_UDP_SIZE)
}

/// Offsets of each resource record's fixed fields (TYPE, CLASS, TTL,
/// RDLENGTH) across the answer, authority and additional sections, in order.
/// A malformed tail ends the list early, leaving those records untouched.
fn record_offsets(message: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    if message.len() < 12 {
        return offsets;
    }
    let count = |at: usize| usize::from(field(message, at));
    let records = count(6) + count(8) + count(10);
    let mut pos = 12;
    for _ in 0..count(4) {
        let Some(next) = skip_name(message, pos) else {
            return offsets;
        };
        pos = next + 4; // QTYPE and QCLASS.
    }
    for _ in 0..records {
        let Some(at) = skip_name(message, pos) else {
            break;
        };
        if message.len() < at + 10 {
            break;
        }
        offsets.push(at);
        pos = at + 10 + usize::from(field(message, at + 8));
    }
    offsets
}

/// The big-endian u16 at `at`; callers have bounds-checked it.
fn field(message: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([message[at], message[at + 1]])
}

/// Skips over a domain name in DNS wire format, returning the position after it.
///
/// A compression pointer ends the name in place, so it is never followed.
/// Returns `None` if the name is malformed or runs past the message.
fn skip_name(response: &[u8], mut pos: usize) -> Option<usize> {
    let mut labels = 0;
    // A name is at most 255 bytes, so at most 127 labels.
    const MAX_LABELS: usize = 127;

    loop {
        if pos >= response.len() {
            return None;
        }

        let len = response[pos];

        // Check for compression pointer (top 2 bits set).
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= response.len() {
                return None;
            }
            // This is a pointer; in a cached message, we just skip over it (2 bytes).
            // The pointer itself doesn't advance further; the name ends here.
            return Some(pos + 2);
        }

        if len == 0 {
            // End of name.
            return Some(pos + 1);
        }

        pos += 1 + len as usize;
        labels += 1;
        if labels > MAX_LABELS || pos > response.len() {
            return None;
        }
    }
}

/// Evicts one entry to make room for a new one.
///
/// Prefers to evict:
/// 1. Expired-beyond-stale entries (older than 24h).
/// 2. If none, the soonest-expiring (freshest-starting) entry.
fn evict_one(entries: &mut HashMap<CacheKey, CacheEntry>) {
    // First, evict any entry that's been stale for too long.
    if let Some(key) = entries.iter().find_map(|(k, v)| {
        if v.stored_at.elapsed() > STALE_WINDOW {
            Some(k.clone())
        } else {
            None
        }
    }) {
        entries.remove(&key);
        return;
    }

    // If no stale-expired entries, evict the soonest-expiring live entry.
    if let Some(key) = entries
        .iter()
        .min_by_key(|(_, v)| {
            let ttl_secs = v.min_ttl as u64;
            let expiry = v.stored_at + Duration::from_secs(ttl_secs);
            expiry.saturating_duration_since(Instant::now())
        })
        .map(|(k, _)| k.clone())
    {
        entries.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Query, Record, RecordData, ResponseFlags, encode_response};
    use std::net::Ipv4Addr;

    fn query(name: &str) -> Query {
        Query {
            id: 1234,
            name: name.to_string(),
            record_type: RecordType::A,
            recursion_desired: true,
        }
    }

    fn flags() -> ResponseFlags {
        ResponseFlags {
            authoritative: false,
            truncated: false,
        }
    }

    /// An upstream answer: one A record for `name` with `ttl`.
    fn a_answer(name: &str, ttl: u32) -> Vec<u8> {
        let answer = Record {
            name: name.to_string(),
            ttl,
            data: RecordData::A(Ipv4Addr::new(93, 184, 216, 34)),
        };
        encode_response(
            &query(name),
            ResponseCode::NoError,
            flags(),
            &[answer],
            &[],
            &[],
        )
    }

    fn rcode_answer(name: &str, code: ResponseCode, authority: &[Record]) -> Vec<u8> {
        encode_response(&query(name), code, flags(), &[], authority, &[])
    }

    fn soa(ttl: u32, minimum: u32) -> Record {
        Record {
            name: "example".to_string(),
            ttl,
            data: RecordData::Soa {
                primary: "ns.example".to_string(),
                responsible: "admin.example".to_string(),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 86400,
                minimum,
            },
        }
    }

    /// Appends an EDNS0 OPT record advertising `size` with the DO bit set.
    fn with_opt(mut message: Vec<u8>, size: u16) -> Vec<u8> {
        let additional = field(&message, 10) + 1;
        message[10..12].copy_from_slice(&additional.to_be_bytes());
        message.push(0); // root owner name
        message.extend_from_slice(&OPT_TYPE.to_be_bytes());
        message.extend_from_slice(&size.to_be_bytes());
        message.extend_from_slice(&0x0000_8000u32.to_be_bytes()); // DO flag
        message.extend_from_slice(&0u16.to_be_bytes());
        message
    }

    fn ttls(message: &[u8]) -> Vec<u32> {
        record_offsets(message)
            .into_iter()
            .map(|at| u32::from_be_bytes(message[at + 4..at + 8].try_into().unwrap()))
            .collect()
    }

    #[test]
    fn fresh_hit_carries_the_new_id_and_the_remaining_ttl() {
        let cache = DnsCache::new();
        cache.insert("example.com", RecordType::A, &a_answer("example.com", 300));

        let hit = cache.lookup("example.com", RecordType::A, 5678).unwrap();
        assert_eq!(
            field(&hit, 0),
            5678,
            "the cached answer must carry the asker's ID"
        );
        let decoded = wire::decode_response(&hit).unwrap();
        assert_eq!(decoded.answers.len(), 1);
        assert!((299..=300).contains(&decoded.answers[0].ttl));
        assert_eq!(
            decoded.answers[0].data,
            RecordData::A(Ipv4Addr::new(93, 184, 216, 34))
        );
    }

    #[test]
    fn an_expired_entry_is_only_served_stale_with_a_short_ttl() {
        let cache = DnsCache::new();
        cache.insert("short.ttl", RecordType::A, &a_answer("short.ttl", 0));
        std::thread::sleep(Duration::from_millis(5));

        assert!(cache.lookup("short.ttl", RecordType::A, 9).is_none());
        let stale = cache.lookup_stale("short.ttl", RecordType::A, 9).unwrap();
        assert_eq!(field(&stale, 0), 9);
        assert_eq!(ttls(&stale), vec![STALE_TTL]);
    }

    #[test]
    fn a_fresh_entry_is_never_served_as_stale() {
        let cache = DnsCache::new();
        cache.insert("fresh.test", RecordType::A, &a_answer("fresh.test", 300));
        assert!(cache.lookup_stale("fresh.test", RecordType::A, 9).is_none());
    }

    #[test]
    fn rewriting_ttls_leaves_the_edns_opt_record_alone() {
        let cached = with_opt(a_answer("opt.test", 300), 1232);
        let stale = rewrite_answer(&cached, 7, Duration::ZERO, Some(STALE_TTL));
        assert_eq!(ttls(&stale), vec![STALE_TTL, 0x0000_8000]);
        let aged = rewrite_answer(&cached, 7, Duration::from_secs(100), None);
        assert_eq!(ttls(&aged), vec![200, 0x0000_8000]);
    }

    #[test]
    fn negative_answers_use_the_lesser_soa_ttl_capped_at_300() {
        let cache = DnsCache::new();
        let nx = rcode_answer("gone.example", ResponseCode::NameError, &[soa(60, 900)]);
        cache.insert("gone.example", RecordType::A, &nx);
        let entries = cache.entries.lock().unwrap();
        assert_eq!(
            entries[&CacheKey::new("gone.example", RecordType::A)].min_ttl,
            60
        );
        drop(entries);
        assert!(cache.lookup("gone.example", RecordType::A, 9).is_some());

        let bare = rcode_answer("bare.example", ResponseCode::NameError, &[]);
        cache.insert("bare.example", RecordType::A, &bare);
        let entries = cache.entries.lock().unwrap();
        assert_eq!(
            entries[&CacheKey::new("bare.example", RecordType::A)].min_ttl,
            DEFAULT_NEGATIVE_TTL
        );
    }

    #[test]
    fn failures_and_truncated_answers_are_never_cached() {
        let cache = DnsCache::new();
        for code in [ResponseCode::ServerFailure, ResponseCode::Refused] {
            cache.insert(
                "fail.example",
                RecordType::A,
                &rcode_answer("fail.example", code, &[]),
            );
        }
        let mut truncated = a_answer("fail.example", 300);
        truncated[2] |= 0x02;
        cache.insert("fail.example", RecordType::A, &truncated);
        cache.insert("fail.example", RecordType::A, b"garbage");
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn capacity_is_bounded_and_eviction_takes_the_soonest_to_expire() {
        let cache = DnsCache::new();
        cache.insert(
            "short.example",
            RecordType::A,
            &a_answer("short.example", 1),
        );
        for i in 0..MAX_CACHE_ENTRIES {
            let name = format!("host{i}.example");
            cache.insert(&name, RecordType::A, &a_answer(&name, 3600));
        }
        assert_eq!(cache.len(), MAX_CACHE_ENTRIES);
        assert!(cache.lookup("short.example", RecordType::A, 9).is_none());
        assert!(cache.lookup("host0.example", RecordType::A, 9).is_some());
    }

    #[test]
    fn names_match_case_insensitively() {
        let cache = DnsCache::new();
        cache.insert("Example.COM", RecordType::A, &a_answer("Example.COM", 300));
        assert!(cache.lookup("example.com", RecordType::A, 5678).is_some());
        assert!(cache.lookup("EXAMPLE.COM", RecordType::A, 5678).is_some());
        assert!(
            cache
                .lookup("example.com", RecordType::Aaaa, 5678)
                .is_none()
        );
    }

    #[test]
    fn udp_payload_limit_reads_the_askers_edns_size() {
        let plain = wire::encode_query(1, "example.com", RecordType::A).unwrap();
        assert_eq!(udp_payload_limit(&plain), 512);
        assert_eq!(udp_payload_limit(&with_opt(plain.clone(), 1232)), 1232);
        assert_eq!(udp_payload_limit(&with_opt(plain, 100)), 512);
        assert_eq!(udp_payload_limit(b"short"), 512);
    }
}
