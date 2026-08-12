//! Proving what the internet can actually reach, from a network that cannot
//! ask the internet.
//!
//! Every reachability check this project had before was taken from *inside*:
//! the proxy is listening, the router reports a forward, the zone is served.
//! None of them answers the only question that matters — can a stranger get
//! here — and this house has no vantage point outside itself. It is single-NAT
//! with no hairpin, so the box's own public address is unreachable from the LAN,
//! and there is no machine elsewhere to ask.
//!
//! # The trick: make a third party originate the connection
//!
//! An external vantage point does not have to be a machine we own. It has to be
//! something outside the network that will connect *to us* on request, and then
//! tell us — or show us — that it did. Two already exist, cost nothing, and are
//! fully automatic.
//!
//! ## Port 53 — the public resolvers
//!
//! Ask Google, Cloudflare and Quad9 to resolve `<nonce>.<a zone we serve>`,
//! where the nonce has never existed. What comes back settles it:
//!
//! - **`NXDOMAIN`** — proof. That answer is authoritative-negative, and the only
//!   machine on earth that can produce it for a name inside our zone is our
//!   nameserver. No cache can hold a name invented a second ago, so the resolver
//!   reached us: the delegation is right and the edge forwards 53 here.
//! - **`SERVFAIL` or a timeout** — the resolver tried and could not get an
//!   answer. The name is delegated to us and we did not respond.
//! - **`NOERROR` with an answer** — something is answering for our zone that is
//!   not us, which is worth knowing on its own.
//!
//! The nonce is what makes this airtight, and it is why the check installs no
//! record and needs nothing from the running daemon. A *positive* lookup would
//! prove nothing: any resolver could serve it from cache without ever having
//! touched this machine.
//!
//! ## Ports 80 and 443 — the certificate is a receipt
//!
//! A Let's Encrypt certificate cannot exist unless the CA reached this machine
//! on 80 or 443 to validate the challenge. So a real certificate on disk *is* a
//! signed, dated record that the public path worked — and the `rcgen`
//! self-signed fallback is a record that it never has. This reads that evidence
//! rather than gathering new evidence, which is why it costs nothing and cannot
//! burn an issuance rate limit.
//!
//! # What this deliberately does not claim
//!
//! There is no witness here for 25, 465, 587 or 993. Nothing external will
//! open an IMAP session on request the way a resolver will answer a query, so
//! those ports are reported as *unwitnessed* rather than inferred from the fact
//! that a listener is bound. Saying "reachable" on that basis is the exact
//! mistake this module exists to stop making.

use selfhost_config::Config;
use selfhost_dns::{RecordType, ResponseCode, Resolver};
use selfhost_proxy::CertificateStore;
use std::net::SocketAddr;
use std::time::Duration;

/// Public recursive resolvers used as external witnesses.
///
/// Three run by different organisations on different networks, because the
/// finding is "the internet can reach us" and one provider agreeing with itself
/// is not that. Disagreement between them is itself a result worth printing —
/// it usually means a delegation that has propagated unevenly.
const WITNESSES: &[(&str, &str)] =
    &[("Google", "8.8.8.8:53"), ("Cloudflare", "1.1.1.1:53"), ("Quad9", "9.9.9.9:53")];

/// How long one witness is given to answer.
///
/// Generous compared to a normal lookup: the whole point is a query that must
/// travel to our own nameserver and back rather than being served from the
/// resolver's cache, and a timeout is one of the answers being measured.
const WITNESS_TIMEOUT: Duration = Duration::from_secs(8);

/// What one public resolver reported about a name only we can answer for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Witnessed {
    /// The resolver reached our nameserver. The strongest result available.
    Reached,
    /// The resolver tried and got nothing back: delegated here, not answering.
    Unreachable {
        /// What it said, for the report.
        detail: String,
    },
    /// Something answered, but it was not the answer only we could give.
    Impostor {
        /// What came back instead.
        detail: String,
    },
    /// The question could not be put at all — this machine's own network.
    Inconclusive {
        /// Why.
        reason: String,
    },
}

impl Witnessed {
    /// Whether this witness proves the public path works.
    pub fn is_proof(&self) -> bool {
        matches!(self, Self::Reached)
    }

    /// A one-line summary for the report.
    pub fn summary(&self) -> String {
        match self {
            Self::Reached => "reached our nameserver".to_owned(),
            Self::Unreachable { detail } => format!("could not reach us ({detail})"),
            Self::Impostor { detail } => format!("something else answered ({detail})"),
            Self::Inconclusive { reason } => format!("no verdict ({reason})"),
        }
    }
}

/// Asks one public resolver for a name that has never existed, inside `zone`.
///
/// See the module docs for why the answer is proof. `nonce` must be unique per
/// run: a repeat would be answerable from the resolver's negative cache, which
/// would report success without anything having travelled to this machine.
pub async fn witness_dns(resolver_address: &str, zone: &str, nonce: &str) -> Witnessed {
    let Ok(address) = resolver_address.parse::<SocketAddr>() else {
        return Witnessed::Inconclusive { reason: format!("{resolver_address} is not an address") };
    };
    let resolver = Resolver::at(address).with_timeout(WITNESS_TIMEOUT);
    let name = format!("{nonce}.{zone}");

    match resolver.query(&name, RecordType::A).await {
        // The one proof. Authoritative-negative for a name invented moments
        // ago: no cache could hold it, so our nameserver answered.
        Ok(response) if response.code == ResponseCode::NameError => Witnessed::Reached,
        // Delegated here and nothing came back. This is what a missing port
        // forward looks like from outside, and it is the finding this whole
        // module was written to be able to state.
        Ok(response) if response.code == ResponseCode::ServerFailure => {
            Witnessed::Unreachable { detail: "SERVFAIL".to_owned() }
        }
        Ok(response) if response.code == ResponseCode::NoError => Witnessed::Impostor {
            detail: format!("NOERROR with {} answer(s) for a name that does not exist", response.answers.len()),
        },
        Ok(response) => Witnessed::Impostor { detail: format!("{:?}", response.code) },
        Err(error) => Witnessed::Unreachable { detail: error.to_string() },
    }
}

/// Where the internet believes `zone`'s nameservers are, and whether any of
/// them is this deployment.
///
/// This is load-bearing, not decoration. `NXDOMAIN` proves that *an*
/// authoritative server was reached — not that it was ours. Without tying the
/// delegation to this machine, the probe reports "proven reachable" for every
/// domain on earth, because `google.com` also answers `NXDOMAIN` for a name
/// that does not exist. Caught by running the check against a domain this
/// deployment does not serve and watching it claim success.
///
/// The tie is by address, not by name: an `NS` label can be anything, and only
/// the address it resolves to says whether the server behind it is this box.
pub async fn delegation_of(zone: &str, ours: Option<std::net::Ipv4Addr>) -> Delegation {
    let Ok(address) = WITNESSES[0].1.parse::<SocketAddr>() else {
        return Delegation { nameservers: Vec::new(), points_here: None };
    };
    let resolver = Resolver::at(address).with_timeout(WITNESS_TIMEOUT);

    let nameservers = match resolver.lookup_ns(zone).await {
        Ok(found) => found,
        Err(_) => return Delegation { nameservers: Vec::new(), points_here: None },
    };

    // Without our own public address there is nothing to compare against, and
    // `None` is the honest answer — never `true`, which is the failure this
    // function exists to prevent.
    let Some(ours) = ours else {
        return Delegation { nameservers, points_here: None };
    };

    let mut points_here = Some(false);
    for nameserver in &nameservers {
        match resolver.lookup_a(nameserver).await {
            Ok(addresses) if addresses.contains(&ours) => {
                points_here = Some(true);
                break;
            }
            Ok(_) => {}
            // One unresolvable NS is not proof of anything either way; keep
            // looking rather than concluding from a lookup that failed.
            Err(_) => {}
        }
    }
    Delegation { nameservers, points_here }
}

/// What the internet says about a zone's nameservers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    /// The `NS` names the internet returns for the zone.
    pub nameservers: Vec<String>,
    /// Whether any of them resolves to this deployment's public address.
    ///
    /// `None` when it could not be established — no public address discovered,
    /// or the lookups failed. `None` is never treated as `true`: a probe whose
    /// target cannot be confirmed to be us proves nothing about us.
    pub points_here: Option<bool>,
}

/// A nonce that has never been queried before, without a randomness source.
///
/// The dependency policy admits no RNG crate, and none is needed: uniqueness is
/// what matters here, not unpredictability. An attacker who guessed the next
/// nonce could at most make the name exist, which this check already reports as
/// an impostor rather than as success.
///
/// Three parts, and the counter is not decoration. The clock alone is not
/// enough: `SystemTime` is only as fine as the platform's clock, and two calls
/// close together return the *same* value — caught by the test below, which
/// failed with two identical nonces before this counter existed. A repeated
/// nonce is the one way this probe can lie, because the second query would be
/// answered from the resolver's negative cache and reported as success with
/// nothing having reached this machine.
pub fn nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    /// Distinguishes two nonces minted inside one clock tick.
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_nanos())
        .unwrap_or(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("selfhost-probe-{:x}-{now:x}-{count:x}", std::process::id())
}

/// What the certificate on disk proves about ports 80 and 443.
///
/// A real certificate is a receipt: the CA reached this machine to validate the
/// challenge, so the public path worked when it was issued. The self-signed
/// fallback proves the opposite — that it never has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateEvidence {
    /// A CA-issued certificate: the public path worked at issuance.
    Issued {
        /// The host it names.
        host: String,
        /// How long ago it was issued — how old the proof is.
        age: Duration,
    },
    /// A stored pair with no issue marker: the locally generated fallback, so
    /// no CA has ever reached this machine for this name.
    SelfSigned {
        /// The host it names.
        host: String,
    },
    /// No certificate for this host at all.
    Absent {
        /// The host that has none.
        host: String,
    },
}

impl CertificateEvidence {
    /// Whether this is evidence the public path worked.
    pub fn is_proof(&self) -> bool {
        matches!(self, Self::Issued { .. })
    }

    /// A one-line summary for the report.
    ///
    /// An issued certificate's summary leads with *when*, because that is the
    /// weakness of this kind of evidence: it proves the path worked at
    /// issuance, not that it works now. The DNS witness is the live check; this
    /// one is a receipt, and a receipt is dated.
    pub fn summary(&self) -> String {
        match self {
            Self::Issued { age, .. } => format!(
                "issued by a CA {} day(s) ago — the CA reached this machine on 80/443 to \
                 validate it then",
                age.as_secs() / 86_400
            ),
            Self::SelfSigned { .. } => {
                "the self-signed fallback — no CA has ever validated this name here".to_owned()
            }
            Self::Absent { .. } => "no certificate yet".to_owned(),
        }
    }
}

/// Reads what the certificate store can prove about each site hostname.
///
/// Read-only and offline: this gathers no new evidence and cannot burn an
/// issuance rate limit. It reports what issuance already established.
///
/// The issued-or-not question is answered by
/// [`acme_task::certificate_age`](crate::acme_task::certificate_age), which is
/// the same marker the renewal loop reads. Deciding it here a second way — by
/// parsing the certificate, say — would be a second answer that could disagree
/// with the one the daemon actually acts on.
pub fn certificate_evidence(config: &Config, store: &CertificateStore) -> Vec<CertificateEvidence> {
    config
        .sites
        .iter()
        .map(|site| {
            let host = site.canonical().to_owned();
            match crate::acme_task::certificate_age(store, &host) {
                Some(age) => CertificateEvidence::Issued { host, age },
                None if store.has_pair(&host) => {
                    CertificateEvidence::SelfSigned { host }
                }
                None => CertificateEvidence::Absent { host },
            }
        })
        .collect()
}

/// Runs every available witness and prints what each one actually establishes.
///
/// Returns an error only when the deployment cannot be asked about at all — no
/// served zones and no sites. A witness that reports "unreachable" is a
/// successful run with a bad finding, not a failed run, so it prints and
/// returns `Ok`: this is a diagnostic, and a diagnostic that exits non-zero on
/// a discovered fault is one nobody can put in a script.
pub async fn report(config: &Config, project_dir: &std::path::Path) -> Result<(), String> {
    let zones: Vec<String> = config
        .dns
        .as_ref()
        .map(|dns| dns.zones.iter().map(|zone| zone.domain.clone()).collect())
        .unwrap_or_default();

    if zones.is_empty() && config.sites.is_empty() {
        return Err(
            "this deployment serves no zones and no sites, so there is nothing to ask the \
             internet about"
                .to_owned(),
        );
    }

    println!("Asking the internet what it can reach here.");
    println!(
        "\nNothing on this network can answer that — there is no NAT hairpin and no machine\n\
         outside the house — so each check below makes a third party originate the\n\
         connection and reports only what that actually proves."
    );

    // --- port 53: a live, external, on-demand witness -----------------------
    if zones.is_empty() {
        println!("\nport 53 — no [dns] zones configured, so there is nothing to witness");
    }
    // Established once: every zone's delegation is judged against it, and
    // without it no zone can be proven to be *ours* rather than merely alive.
    let ours = crate::doctor::discover_public_ip().await;
    match ours {
        Some(address) => println!("\nthis network's public address: {address}"),
        None => println!(
            "\n! this network's public address could not be discovered, so a zone cannot be\n\
             \x20 confirmed to be served by *this* box rather than by somebody else's."
        ),
    }

    for zone in &zones {
        println!("\nport 53 · {zone}");

        let delegation = delegation_of(zone, ours).await;
        if delegation.nameservers.is_empty() {
            println!(
                "  ✗ the internet has no NS records for this zone, so no query will ever be\n\
                 \x20   sent here. Point the domain's nameservers at this box."
            );
            continue;
        }
        println!("  delegated to  {}", delegation.nameservers.join(", "));

        match delegation.points_here {
            Some(true) => {}
            Some(false) => {
                // Without this the probe below would report success: any
                // delegated zone answers NXDOMAIN for a name that does not
                // exist, whoever serves it.
                println!(
                    "  ✗ none of those nameservers resolves to this network's address, so this\n\
                     \x20   zone is served by somebody else. Nothing here can be proven about\n\
                     \x20   this box until the delegation points at it."
                );
                continue;
            }
            None => {
                println!(
                    "  ? cannot confirm those nameservers are this box, so the result below\n\
                     \x20   says only that *something* authoritative answered — not that it was us."
                );
            }
        }

        // One nonce per zone. Reusing it across zones would still be unique per
        // name, but a fresh one per query keeps a retry from ever landing on a
        // resolver's negative cache.
        let nonce = nonce();
        let mut proven = 0usize;
        for (who, address) in WITNESSES {
            let verdict = witness_dns(address, zone, &nonce).await;
            let mark = if verdict.is_proof() { "✓" } else { "✗" };
            println!("  {mark} {who:<11} {}", verdict.summary());
            if verdict.is_proof() {
                proven += 1;
            }
        }

        // The strength of the conclusion is capped by the delegation check: a
        // confirmed delegation turns "something answered" into "this box
        // answered", and nothing else can.
        let confirmed = delegation.points_here == Some(true);
        match proven {
            0 => println!(
                "  → no resolver could reach this box. The edge is not forwarding UDP+TCP 53\n\
                 \x20   here, or the box is not answering."
            ),
            n if n == WITNESSES.len() && confirmed => println!(
                "  → PROVEN reachable from the public internet, right now: every resolver got\n\
                 \x20   an authoritative answer, from a nameserver at this network's address,\n\
                 \x20   for a name that did not exist a second ago."
            ),
            n if n == WITNESSES.len() => println!(
                "  → every resolver got an authoritative answer, but this run could not confirm\n\
                 \x20   the answering nameserver is this box, so it is not proof about this box."
            ),
            n => println!(
                "  → reached by {n} of {}. A split like this is usually a delegation that has\n\
                 \x20   not finished propagating.",
                WITNESSES.len()
            ),
        }
    }

    // --- ports 80/443: dated evidence, not a live check ---------------------
    println!("\nports 80 and 443");
    let data_dir = project_dir.join(&config.server.data_dir);
    match CertificateStore::open(&data_dir) {
        Ok(store) => {
            let evidence = certificate_evidence(config, &store);
            if evidence.is_empty() {
                println!("  no sites configured");
            }
            for item in &evidence {
                let (host, mark) = match item {
                    CertificateEvidence::Issued { host, .. } => (host, "✓"),
                    CertificateEvidence::SelfSigned { host } | CertificateEvidence::Absent { host } => {
                        (host, "✗")
                    }
                };
                println!("  {mark} {host:<28} {}", item.summary());
            }
            if evidence.iter().any(CertificateEvidence::is_proof) {
                println!(
                    "  → this is a receipt, not a live check: it proves the CA reached this box\n\
                     \x20   when the certificate was issued. `selfhost doctor` reports the edge."
                );
            }
        }
        Err(error) => println!("  ? cannot read the certificate store ({error})"),
    }

    // --- the ports nothing will witness -------------------------------------
    if config.mail.is_some() {
        println!("\nmail ports (25, 465, 587, 993) — NOT WITNESSED");
        println!(
            "  Nothing on the public internet will open an IMAP or SMTP session on request\n\
             \x20 the way a resolver will answer a query, so this tool cannot prove these are\n\
             \x20 reachable and does not guess. What would prove it: a real message arriving\n\
             \x20 from outside, or a mail client connecting over a genuinely external network."
        );
    }

    println!(
        "\nTo reach the public address from inside this network, run `selfhost hairpin`."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonce_is_different_every_time_it_is_asked_for() {
        // A repeated nonce would be answerable from a resolver's negative
        // cache, which would report success with nothing having reached us —
        // the one way this check could lie.
        // Minted back to back on purpose: this is the case that actually
        // failed, because the platform clock is not fine enough to separate
        // two calls in the same tick.
        let minted: std::collections::BTreeSet<String> = (0..1_000).map(|_| nonce()).collect();
        assert_eq!(minted.len(), 1_000, "a reused nonce makes the whole probe meaningless");
    }

    #[test]
    fn a_nonce_is_a_legal_single_dns_label() {
        let nonce = nonce();
        assert!(nonce.len() <= 63, "a DNS label caps at 63 octets: {nonce}");
        assert!(
            nonce.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "must be a legal label: {nonce}"
        );
        assert!(!nonce.starts_with('-') && !nonce.ends_with('-'), "{nonce}");
    }

    #[test]
    fn only_reaching_our_nameserver_counts_as_proof() {
        assert!(Witnessed::Reached.is_proof());
        // The failure that matters: a resolver that tried and got nothing is
        // exactly what a missing port forward looks like, and must never be
        // read as success.
        assert!(!Witnessed::Unreachable { detail: "SERVFAIL".into() }.is_proof());
        assert!(!Witnessed::Impostor { detail: "NOERROR".into() }.is_proof());
        assert!(!Witnessed::Inconclusive { reason: "no network".into() }.is_proof());
    }

    #[test]
    fn only_a_ca_issued_certificate_is_evidence_the_public_path_worked() {
        assert!(
            CertificateEvidence::Issued {
                host: "example.com".into(),
                age: Duration::from_secs(0)
            }
            .is_proof()
        );
        // The fallback exists precisely because no CA could reach us, so
        // treating it as evidence would invert the finding.
        assert!(!CertificateEvidence::SelfSigned { host: "example.com".into() }.is_proof());
        assert!(!CertificateEvidence::Absent { host: "example.com".into() }.is_proof());
    }

    #[test]
    fn an_issued_certificates_summary_says_how_old_the_proof_is() {
        // The weakness of receipt-style evidence: it proves the path worked
        // then, not now. The age has to be in the sentence or a reader will
        // take a two-month-old proof as a current one.
        let evidence = CertificateEvidence::Issued {
            host: "example.com".into(),
            age: Duration::from_secs(3 * 86_400),
        };
        assert!(evidence.summary().contains("3 day(s) ago"), "{}", evidence.summary());
    }

    #[test]
    fn a_delegation_that_cannot_be_tied_to_this_box_is_never_reported_as_ours() {
        // The bug this pins, found by running the probe against a domain this
        // deployment does not serve and watching it report success: NXDOMAIN
        // proves *an* authoritative server was reached, and every delegated
        // zone on the internet produces one. Only the address behind the NS
        // records ties that answer to this machine, so "unknown" must never
        // collapse into "yes".
        let unknown = Delegation { nameservers: vec!["ns1.google.com".into()], points_here: None };
        assert_ne!(unknown.points_here, Some(true));

        let elsewhere =
            Delegation { nameservers: vec!["ns1.google.com".into()], points_here: Some(false) };
        assert_ne!(elsewhere.points_here, Some(true));
    }

    #[tokio::test]
    async fn a_zone_delegated_elsewhere_is_not_claimed_as_this_deployment() {
        // An end-to-end guard on the same bug, against a real delegation that
        // certainly is not us. Skipped rather than failed without a network:
        // this is a diagnostic's test, not a reason to fail an offline build.
        let ours = std::net::Ipv4Addr::new(203, 0, 113, 1); // TEST-NET-3: never routed
        let delegation = delegation_of("google.com", Some(ours)).await;
        if delegation.nameservers.is_empty() {
            return; // no network in this environment
        }
        assert_eq!(
            delegation.points_here,
            Some(false),
            "google.com must never be reported as served by this deployment"
        );
    }

    #[test]
    fn three_independent_organisations_are_asked_not_one() {
        // One provider agreeing with itself is not "the internet can reach us".
        assert!(WITNESSES.len() >= 3, "a single witness is not a quorum");
        let addresses: std::collections::BTreeSet<&str> =
            WITNESSES.iter().map(|(_, address)| *address).collect();
        assert_eq!(addresses.len(), WITNESSES.len(), "the witnesses must be distinct");
    }
}
