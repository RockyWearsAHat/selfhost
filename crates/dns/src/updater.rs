//! Dynamic-IP updater: keeps the authoritative apex A pointed at this machine's
//! real WAN address, on a home connection where that address changes without
//! warning.
//!
//! # Why the router, not a public echo
//!
//! The address the internet must reach is the one the box holding the port
//! forward believes it has. Asking a public "what's my IP" service answers a
//! *different* question behind carrier-grade NAT, and would write an address no
//! forward points at. The sovereign source is the router's own
//! `GetExternalIPAddress` over UPnP-IGD — see [`selfhost_igd::Gateway`].
//!
//! # The one subtle thing: a missing answer is not a new address
//!
//! A router that reboots, or a multicast probe that is lost, yields *no* IP —
//! never `0.0.0.0`. Writing an unreadable or private answer into the zone would
//! break every name the moment the router hiccups, so such an answer is logged
//! once and ignored ([`Movement::Unusable`]), and the last good address stands
//! until a real, different, public one is read. Serial numbers only ever move
//! forward ([`next_serial`]), because a secondary that sees a serial go
//! backwards ignores the update.
//!
//! # Shape
//!
//! The daemon polls [`track_wan_ip`] as one branch of its `select!`; it never
//! returns, discovers the gateway once, fires its first check immediately (to
//! deploy the current IP on startup), and thereafter re-checks on the timer.
//! The change-detection and serial-bump rules it applies are the pure functions
//! [`assess`] and [`next_serial`], which are what the tests exercise.

use crate::authority::Authority;
use selfhost_igd::Gateway;
use std::net::Ipv4Addr;
use std::time::Duration;

/// How often the WAN IP is re-checked. A residential address changes rarely, so
/// a slow poll is enough; matching the daemon's other background loops.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(300);

/// What a freshly-read WAN address means for the zone, relative to the last one
/// deployed. The updater acts only on [`Movement::Changed`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Movement {
    /// The address is not a usable public IPv4 — private (RFC 1918), carrier-grade
    /// NAT (RFC 6598), loopback, link-local, or other reserved space. It is logged
    /// and ignored, never written into a zone.
    Unusable(Ipv4Addr),
    /// The address equals the one already deployed; nothing to do.
    Unchanged,
    /// A new, usable address different from the last: deploy it to every zone.
    Changed(Ipv4Addr),
}

/// Decides what a freshly-read WAN address means relative to the last one
/// deployed. Pure: no clock, no socket — the whole change-detection rule in one
/// place so it can be tested without a router.
///
/// An unusable address is `Unusable` regardless of `last`, because it must never
/// be adopted as the new "current" — the last *good* address has to keep
/// standing through a router hiccup.
pub fn assess(last: Option<Ipv4Addr>, candidate: Ipv4Addr) -> Movement {
    if !is_deployable(candidate) {
        Movement::Unusable(candidate)
    } else if last == Some(candidate) {
        Movement::Unchanged
    } else {
        Movement::Changed(candidate)
    }
}

/// The next SOA serial after a change, given the current serial and today's date
/// as `YYYYMMDD` (e.g. `20260807`) — the date-aware serial rule this crate
/// recommends for the apex-A bump.
///
/// Two properties a secondary depends on, held together:
///
/// - **Date-fresh.** On a new day the serial jumps to `YYYYMMDD00`, the
///   convention `default_zone` seeds and operators read at a glance.
/// - **Strictly increasing, always.** Multiple changes in one day increment past
///   the base, and a clock that jumps *backwards* still yields `current + 1` — a
///   serial that goes backwards makes a secondary silently ignore the update, so
///   monotonicity wins over matching the date exactly. `saturating_add` also
///   means it never wraps to a *lower* value at the `u32` ceiling, unlike a plain
///   `wrapping_add(1)`.
///
/// [`Authority::set_apex_a`] presently increments the serial directly; see the
/// integration notes for adopting this rule so the `YYYYMMDD` convention survives
/// past the first hundred changes of a day.
pub fn next_serial(current: u32, today_yyyymmdd: u32) -> u32 {
    let date_base = today_yyyymmdd.saturating_mul(100);
    current.saturating_add(1).max(date_base)
}

/// Whether an address is one the updater may publish as the apex A.
///
/// Rejects the ranges a router reports when it is *not* holding a routable
/// address: RFC 1918 private space, RFC 6598 carrier-grade NAT, and the obvious
/// non-global reservations. Anything left is treated as a real WAN address.
fn is_deployable(address: Ipv4Addr) -> bool {
    !(address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_unspecified()
        || address.is_broadcast()
        || address.is_multicast()
        || is_carrier_grade(address))
}

/// Whether an address is in the carrier-grade NAT range, `100.64.0.0/10`
/// (RFC 6598). The standard library has no stable predicate for it.
fn is_carrier_grade(address: Ipv4Addr) -> bool {
    let [first, second, ..] = address.octets();
    first == 100 && (64..=127).contains(&second)
}

/// The one operation the updater needs from the authoritative server: replace a
/// zone's apex A and bump its SOA serial, returning the new serial (or `None`
/// when no zone with that origin is served).
///
/// A trait rather than a direct call so the updater's orchestration is testable
/// with a fake in-memory writer, and so this module carries no coupling to how
/// zones are stored. [`Authority`] implements it by delegating to its inherent
/// `set_apex_a`; the semantics — one apex A, a monotonically bumped serial — are
/// identical.
#[allow(async_fn_in_trait)] // Both impl and caller live in this workspace and await
                            // on the daemon's single runtime; no `Send` bound is needed.
pub trait ApexWriter {
    /// Rewrites the apex A of `origin` to `address` and bumps that zone's SOA
    /// serial. Returns the new serial, or `None` if no such zone is served.
    async fn write_apex_a(&self, origin: &str, address: Ipv4Addr) -> Option<u32>;
}

impl ApexWriter for Authority {
    async fn write_apex_a(&self, origin: &str, address: Ipv4Addr) -> Option<u32> {
        self.set_apex_a(origin, address).await
    }
}

/// Writes `address` as the apex A of every origin in `zones`, returning each
/// zone that changed and its new SOA serial. Origins with no matching zone are
/// skipped. This is the single point where a detected change becomes served data.
async fn apply_change<W: ApexWriter>(
    writer: &W,
    zones: &[String],
    address: Ipv4Addr,
) -> Vec<(String, u32)> {
    let mut applied = Vec::new();
    for origin in zones {
        if let Some(serial) = writer.write_apex_a(origin, address).await {
            applied.push((origin.clone(), serial));
        }
    }
    applied
}

/// Tracks this machine's WAN IP via the router and rewrites the apex A + SOA
/// serial of every zone in `zones` when it moves.
///
/// Never returns: it is a branch of the daemon's `select!`, and the `select!`
/// ending aborts it. Each tick asks the router `GetExternalIPAddress`
/// (sovereign — the box that holds the forward is the box that knows the
/// address); the first tick fires immediately so the current IP is deployed on
/// startup. The gateway is discovered once and re-discovered only after a call
/// fails, since a router that reboots invalidates its control URL.
///
/// A router that cannot be reached, or that reports an unusable address, is
/// logged **once** (repeats of the same reason are suppressed, like the git
/// poller) and retried next tick — a missing answer is never treated as
/// "the IP became `0.0.0.0`".
pub async fn track_wan_ip(authority: impl ApexWriter, zones: Vec<String>, interval: Duration) {
    // A failure repeated every interval would fill the log with one fact, so the
    // last complaint is remembered and only a *change* of reason is worth a line.
    let mut last_complaint: Option<String> = None;
    let mut last_deployed: Option<Ipv4Addr> = None;
    let mut gateway: Option<Gateway> = None;

    // `interval`'s first tick is immediate; that is deliberate — deploy the
    // current address on startup rather than after one poll.
    let mut ticker = tokio::time::interval(interval);

    loop {
        ticker.tick().await;

        // Discover once; re-discover only after a call has failed.
        if gateway.is_none() {
            match Gateway::discover().await {
                Ok(found) => gateway = Some(found),
                Err(reason) => {
                    complain(&mut last_complaint, format!("no router to ask for the WAN IP ({reason})"));
                    continue;
                }
            }
        }
        let Some(router) = gateway.as_ref() else { continue };

        let candidate = match router.external_address().await {
            Ok(address) => address,
            Err(reason) => {
                complain(&mut last_complaint, format!("the router did not report a WAN IP ({reason})"));
                // The control URL may be stale after a reboot; force re-discovery.
                gateway = None;
                continue;
            }
        };

        match assess(last_deployed, candidate) {
            Movement::Unusable(address) => {
                complain(
                    &mut last_complaint,
                    format!("the router reported {address}, which is not a public address; ignoring"),
                );
            }
            Movement::Unchanged => recovered(&mut last_complaint),
            Movement::Changed(address) => {
                recovered(&mut last_complaint);
                let applied = apply_change(&authority, &zones, address).await;
                if applied.is_empty() {
                    eprintln!("dynamic-ip: WAN IP is {address}, but no configured zone matched");
                }
                for (origin, serial) in &applied {
                    eprintln!("dynamic-ip: {origin} apex A → {address} (SOA serial {serial})");
                }
                last_deployed = Some(address);
            }
        }
    }
}

/// Logs `reason` only if it differs from the last complaint, so a persistent
/// fault is one line rather than one per tick.
///
/// `pub(crate)`: [`crate::namecheap`]'s tracking loop follows the same
/// once-per-change-of-reason logging rule, one instance per configured entry
/// rather than one for the whole daemon.
pub(crate) fn complain(last: &mut Option<String>, reason: String) {
    if last.as_deref() != Some(reason.as_str()) {
        eprintln!("dynamic-ip: {reason}");
        *last = Some(reason);
    }
}

/// Notes that the router is answering with a usable address again, but only if
/// it had been complaining — the mirror of [`complain`].
pub(crate) fn recovered(last: &mut Option<String>) {
    if last.take().is_some() {
        eprintln!("dynamic-ip: the router is answering with a usable address again");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[test]
    fn a_first_public_address_is_a_change_to_deploy() {
        let ip = Ipv4Addr::new(203, 0, 113, 5);
        assert_eq!(assess(None, ip), Movement::Changed(ip));
    }

    #[test]
    fn the_same_address_seen_again_is_unchanged() {
        let ip = Ipv4Addr::new(203, 0, 113, 5);
        assert_eq!(assess(Some(ip), ip), Movement::Unchanged);
    }

    #[test]
    fn a_different_public_address_is_a_change() {
        let old = Ipv4Addr::new(203, 0, 113, 5);
        let new = Ipv4Addr::new(198, 51, 100, 9);
        assert_eq!(assess(Some(old), new), Movement::Changed(new));
    }

    #[test]
    fn private_cgnat_and_junk_addresses_are_never_deployed() {
        for octets in [
            [10, 0, 0, 1],       // RFC 1918
            [172, 16, 4, 4],     // RFC 1918
            [192, 168, 1, 1],    // RFC 1918
            [100, 64, 0, 1],     // RFC 6598 CGNAT
            [100, 127, 255, 1],  // RFC 6598 CGNAT, top of range
            [127, 0, 0, 1],      // loopback
            [169, 254, 1, 1],    // link-local
            [0, 0, 0, 0],        // unspecified
        ] {
            let ip = Ipv4Addr::from(octets);
            // Unusable whether or not a good address was previously deployed.
            assert_eq!(assess(None, ip), Movement::Unusable(ip), "{ip} should be unusable");
            let good = Ipv4Addr::new(203, 0, 113, 1);
            assert_eq!(assess(Some(good), ip), Movement::Unusable(ip), "{ip} must not replace a good IP");
        }
    }

    #[test]
    fn a_public_address_just_outside_cgnat_is_deployable() {
        // 100.63/8 and 100.128/9 are ordinary public space; only 100.64/10 is CGNAT.
        let below = Ipv4Addr::new(100, 63, 0, 1);
        let above = Ipv4Addr::new(100, 128, 0, 1);
        assert_eq!(assess(None, below), Movement::Changed(below));
        assert_eq!(assess(None, above), Movement::Changed(above));
    }

    #[test]
    fn serial_jumps_to_the_date_base_on_a_new_day() {
        // Yesterday's serial, today's date → today's base, ending in 00.
        assert_eq!(next_serial(2_026_080_609, 20_260_807), 2_026_080_700);
    }

    #[test]
    fn serial_increments_within_the_same_day() {
        assert_eq!(next_serial(2_026_080_700, 20_260_807), 2_026_080_701);
        assert_eq!(next_serial(2_026_080_701, 20_260_807), 2_026_080_702);
    }

    #[test]
    fn serial_stays_monotonic_when_the_clock_runs_backwards() {
        // A serial from the future must not go backwards just because the date did.
        let from_future = 2_026_080_705;
        assert_eq!(next_serial(from_future, 20_200_101), from_future + 1);
    }

    #[test]
    fn serial_is_strictly_increasing_over_a_run_of_changes() {
        let mut serial = 2_026_080_700;
        for _ in 0..500 {
            let next = next_serial(serial, 20_260_807);
            assert!(next > serial, "serial must strictly increase: {serial} -> {next}");
            serial = next;
        }
    }

    /// An in-memory `ApexWriter` that applies the real serial rule, standing in
    /// for the authoritative server so the apply path is testable without one.
    struct FakeAuthority {
        serials: Mutex<HashMap<String, u32>>,
        today: u32,
    }

    impl ApexWriter for FakeAuthority {
        async fn write_apex_a(&self, origin: &str, _address: Ipv4Addr) -> Option<u32> {
            let mut serials = self.serials.lock().expect("test mutex");
            let current = *serials.get(origin)?;
            let next = next_serial(current, self.today);
            serials.insert(origin.to_owned(), next);
            Some(next)
        }
    }

    #[tokio::test]
    async fn applying_a_change_bumps_every_known_zone_and_skips_unknown_ones() {
        let authority = FakeAuthority {
            serials: Mutex::new(HashMap::from([
                ("example.com".to_owned(), 2_026_080_700),
                ("example.net".to_owned(), 2_026_080_700),
            ])),
            today: 20_260_807,
        };
        let zones = vec![
            "example.com".to_owned(),
            "example.net".to_owned(),
            "not-served.example".to_owned(),
        ];

        let applied = apply_change(&authority, &zones, Ipv4Addr::new(203, 0, 113, 9)).await;

        // The unknown origin is skipped; the two served zones each bumped once.
        assert_eq!(
            applied,
            vec![
                ("example.com".to_owned(), 2_026_080_701),
                ("example.net".to_owned(), 2_026_080_701),
            ],
        );
    }
}
