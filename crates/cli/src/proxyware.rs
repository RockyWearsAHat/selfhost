//! Domains that mean a device has been enrolled in a residential proxy network.
//!
//! A device that relays somebody else's traffic has to be told what to relay,
//! and it has to find its controller by name before it can be told anything.
//! That name resolution is the one moment the whole scheme is visible from
//! inside the network — no packet capture, no router log, no waiting for the
//! device to choose to send something.
//!
//! # Why this is the signal worth watching
//!
//! The FBI's March 2026 advisory on residential proxies (I-031226-PSA)
//! describes how devices get enrolled: an SDK inside a free app, a free VPN
//! whose terms bury the arrangement, a sideloaded streaming app, or a
//! "passive income" client the owner installed on purpose without understanding
//! it. In every case the device ends up talking to one of a small number of
//! commercial services, and Infoblox's June 2026 telemetry found queries to
//! those services' domains in over 65% of the networks it sees.
//!
//! So the question "which device is doing this" has a direct answer: whichever
//! one asks for these names.
//!
//! # Why the list is short
//!
//! Every entry names a company and comes from a published source, so a match is
//! something the reader can go and verify rather than a verdict to trust. A
//! long list assembled from guesswork would produce confident accusations
//! against ordinary hardware, which is the failure this tool keeps having to
//! design against.
//!
//! A match is strong evidence. **No match is not a clean bill of health** — the
//! service could be one not listed here, or the device could be resolving names
//! over encrypted DNS where this cannot see them. See
//! [`resolves_dns_elsewhere`].

/// A residential proxy or bandwidth-sharing service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyService {
    /// The company or product behind the domain.
    pub name: &'static str,
    /// What it is, in terms of what it does to the device running it.
    pub what_it_does: &'static str,
}

/// Domains that belong to residential proxy services, and what each one means.
///
/// Sources: the published domain list at
/// <https://gist.github.com/Firefishy/5e60867d2425a380cc0e28eebbbf3887>, and
/// Infoblox Threat Intel, "Residential Proxies in the Wild" (June 2026), which
/// names the services seen most often in real networks.
const INDICATORS: [(&str, ProxyService); 15] = [
    ("bright-sdk.com", ProxyService {
        name: "Bright Data (Bright SDK)",
        what_it_does: "an SDK app developers embed to monetise their users' connections — the \
                       most widely seen residential proxy service in network telemetry",
    }),
    ("brightdata.com", ProxyService {
        name: "Bright Data",
        what_it_does: "a commercial residential proxy network; the supply side is other people's \
                       devices",
    }),
    ("infatica-sdk.io", ProxyService {
        name: "Infatica (SDK)",
        what_it_does: "an SDK bundled into apps to route strangers' traffic through the device",
    }),
    ("infatica.io", ProxyService {
        name: "Infatica",
        what_it_does: "a residential proxy network",
    }),
    ("ipidea.io", ProxyService {
        name: "IPIDEA",
        what_it_does: "a residential proxy network; one of its apps was removed by Google in \
                       January 2026",
    }),
    ("oxylabs.io", ProxyService {
        name: "Oxylabs",
        what_it_does: "a commercial proxy provider whose residential pool is made of consumer \
                       devices",
    }),
    ("packetstream.io", ProxyService {
        name: "PacketStream",
        what_it_does: "a bandwidth-sharing agent that sells the connection it is installed on",
    }),
    ("packetsdk.com", ProxyService {
        name: "PacketSDK",
        what_it_does: "an app-monetisation SDK that shares the device's bandwidth",
    }),
    ("packetshare.io", ProxyService {
        name: "Packetshare",
        what_it_does: "a bandwidth-sharing client",
    }),
    ("abcproxy.com", ProxyService {
        name: "ABCProxy",
        what_it_does: "a residential proxy provider",
    }),
    ("pawns.app", ProxyService {
        name: "Pawns.app (IPRoyal)",
        what_it_does: "a paid bandwidth-sharing app feeding IPRoyal's proxy supply",
    }),
    ("iproyal.com", ProxyService {
        name: "IPRoyal",
        what_it_does: "the residential proxy network behind Pawns.app",
    }),
    ("honeygain.com", ProxyService {
        name: "Honeygain",
        what_it_does: "pays the device's owner to let strangers route traffic through it",
    }),
    ("earn.fm", ProxyService {
        name: "EarnFM",
        what_it_does: "a bandwidth-sharing app that resells the connection",
    }),
    ("peer2profit.com", ProxyService {
        name: "Peer2Profit",
        what_it_does: "a bandwidth-sharing service",
    }),
];

/// Resolvers that answer over an encrypted transport this cannot observe.
///
/// A device querying one of these is about to stop using the network's resolver
/// entirely, which matters: it is not evidence of anything wrong, but it does
/// mean silence from that device proves nothing.
const ENCRYPTED_RESOLVERS: [&str; 6] = [
    "dns.google",
    "cloudflare-dns.com",
    "dns.quad9.net",
    "doh.opendns.com",
    "dns.adguard.com",
    "dns.nextdns.io",
];

/// The proxy service a domain belongs to, if it belongs to a known one.
///
/// Matches the registered domain and anything under it, since these services
/// spread their infrastructure across subdomains.
pub fn identify(qname: &str) -> Option<ProxyService> {
    let name = qname.trim_end_matches('.').to_ascii_lowercase();
    INDICATORS
        .iter()
        .find(|(domain, _)| name == *domain || name.ends_with(&format!(".{domain}")))
        .map(|(_, service)| *service)
}

/// Whether a domain is an encrypted-DNS resolver.
///
/// Reported separately from a proxy finding, because it explains an *absence*
/// of findings rather than being one.
pub fn resolves_dns_elsewhere(qname: &str) -> bool {
    let name = qname.trim_end_matches('.').to_ascii_lowercase();
    ENCRYPTED_RESOLVERS
        .iter()
        .any(|resolver| name == *resolver || name.ends_with(&format!(".{resolver}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_known_service_is_named_with_what_it_does() {
        let found = identify("pawns.app").expect("a listed indicator");
        assert_eq!(found.name, "Pawns.app (IPRoyal)");
        assert!(found.what_it_does.contains("bandwidth"));
    }

    #[test]
    fn subdomains_match_because_these_services_spread_across_them() {
        assert!(identify("ipinfo.ipidea.io").is_some(), "the subdomain seen in real telemetry");
        assert!(identify("api.honeygain.com").is_some());
        assert!(identify("a.b.c.packetstream.io").is_some());
    }

    #[test]
    fn a_trailing_dot_and_odd_case_still_match() {
        // Names arrive off the wire in whatever case the client used, and a
        // fully-qualified name keeps its root dot. Missing the culprit over
        // punctuation would be an embarrassing way to fail.
        assert!(identify("Pawns.App.").is_some());
        assert!(identify("HONEYGAIN.COM").is_some());
    }

    #[test]
    fn ordinary_domains_are_not_accused() {
        for ordinary in [
            "amazon.com",
            "device-metrics-us.amazon.com",
            "sonos.com",
            "google.com",
            "netflix.com",
        ] {
            assert_eq!(identify(ordinary), None, "{ordinary} must not match");
        }
    }

    #[test]
    fn a_lookalike_suffix_does_not_match() {
        // `notpawns.app` shares a suffix with `pawns.app` textually but is a
        // different domain. Matching it would accuse the wrong device.
        assert_eq!(identify("notpawns.app"), None);
        assert_eq!(identify("myhoneygain.com.example.org"), None);
    }

    #[test]
    fn encrypted_resolvers_are_flagged_separately_from_proxies() {
        assert!(resolves_dns_elsewhere("dns.google"));
        assert!(resolves_dns_elsewhere("mozilla.cloudflare-dns.com"));
        // And are not themselves a proxy finding.
        assert_eq!(identify("dns.google"), None);
        assert!(!resolves_dns_elsewhere("amazon.com"));
    }

    #[test]
    fn every_indicator_explains_itself() {
        // A domain match that only prints a company name leaves the reader to
        // go and research what that company does.
        for (domain, service) in INDICATORS {
            assert!(!domain.is_empty());
            assert!(
                service.what_it_does.len() > 25,
                "{} does not explain what it does to the device",
                service.name
            );
        }
    }
}
