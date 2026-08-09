//! The pure reconcile engine: what the config wants, versus what the
//! registrar serves, becomes a [`Plan`].
//!
//! Everything here is I/O-free on purpose: [`desired_records`] reads only the
//! parsed [`Config`], and [`plan`] compares two in-memory record sets, so the
//! entire engine — including the first law — is provable by unit test. The
//! network enters only through a [`crate::DnsProvider`], which is handed this
//! module's outputs.

use std::net::Ipv4Addr;

use selfhost_config::{Config, RecordConfig};

use crate::{Record, RecordType};

/// Every record `domain` must publish for this deployment, derived from the
/// config — the "desired" input to [`plan`].
///
/// Emits, in order:
///
/// - when any site claims `domain` or a name under it: an apex `A` and a
///   wildcard `*` `A` to `server_ip`, plus one `A` per distinct site
///   subdomain (`www.example.com` → `www`) — the explicit records survive
///   registrars that ignore wildcards;
/// - when `[mail]` covers `domain`: the records [`selfhost_config::Mail::dns_records`]
///   generates (MX, SPF, DMARC, DKIM when `dkim_txt` is supplied, CAA) —
///   reused, not re-derived, so this crate and the served zone can never
///   disagree — plus an `A` for each name the promise must resolve
///   (the MX target and the `mail`/`imap`/`smtp` client-autoconfig hosts that
///   fall under `domain`), and the RFC 6186 client-discovery SRVs:
///   `_imaps._tcp` → `0 1 993 imap.<domain>` and `_submission._tcp` →
///   `0 1 587 smtp.<domain>`.
///
/// `dkim_txt` is the value of `mail::dkim::Dkim::public_txt()`; the caller
/// reads the key because this function performs no I/O. Pass `None` when
/// signing is unconfigured or the key does not exist yet — the DKIM record is
/// then omitted, exactly as `Mail::dns_records` omits it.
pub fn desired_records(
    config: &Config,
    domain: &str,
    server_ip: Ipv4Addr,
    dkim_txt: Option<&str>,
) -> Vec<Record> {
    let mut records = Vec::new();
    let address = server_ip.to_string();

    // Sites: apex + wildcard once, then each distinct subdomain explicitly.
    let mut any_site = false;
    let mut site_hosts: Vec<&str> = Vec::new();
    for site in &config.sites {
        for name in &site.domains {
            let name = name.trim_end_matches('.');
            if name.eq_ignore_ascii_case(domain) {
                any_site = true;
            } else if let Some(host) = subdomain_host(name, domain) {
                any_site = true;
                if !site_hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
                    site_hosts.push(host);
                }
            }
        }
    }
    if any_site {
        records.push(a_record("@", &address));
        records.push(a_record("*", &address));
    }
    for host in site_hosts {
        records.push(a_record(host, &address));
    }

    let covered_by_mail = config
        .mail
        .as_ref()
        .filter(|mail| mail.domains.iter().any(|d| d.eq_ignore_ascii_case(domain)));
    if let Some(mail) = covered_by_mail {
        for generated in mail.dns_records(domain, dkim_txt) {
            records.push(from_config_record(&generated));
        }

        // The promise the MX and autoconfig hostnames make is only kept if
        // they resolve; publish an A for each one that lives under this domain.
        let mut promised: Vec<String> = mail
            .client_hosts()
            .into_iter()
            .filter_map(|name| subdomain_host(&name, domain).map(str::to_owned))
            .collect();
        if let Some(host) = subdomain_host(&mail.hostname, domain) {
            if !promised.iter().any(|h| h.eq_ignore_ascii_case(host)) {
                promised.push(host.to_owned());
            }
        }
        for host in promised {
            if !records
                .iter()
                .any(|r| r.rtype.kind() == "A" && r.host.eq_ignore_ascii_case(&host))
            {
                records.push(a_record(&host, &address));
            }
        }

        // RFC 6186: let mail clients discover the IMAP and submission servers
        // by SRV instead of hard-coded guesses.
        records.push(Record {
            host: "_imaps._tcp".into(),
            rtype: RecordType::Srv { priority: 0, weight: 1, port: 993 },
            value: format!("imap.{domain}"),
            ttl: None,
        });
        records.push(Record {
            host: "_submission._tcp".into(),
            rtype: RecordType::Srv { priority: 0, weight: 1, port: 587 },
            value: format!("smtp.{domain}"),
            ttl: None,
        });
    }

    records
}

/// What must change at the registrar, and — just as important — what must not.
///
/// Built only by [`plan`]. `create + update + keep` cover the desired set;
/// `remove` and `untouched` partition the observed records the desired set
/// did not exactly match, by the one question that matters: is the record's
/// `(host, type)` claimed by the config?
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// Desired records the registrar does not serve yet.
    pub create: Vec<Record>,
    /// `(observed, desired)` pairs at a claimed `(host, type)` whose data
    /// differs — the observed record becomes the desired one.
    pub update: Vec<(Record, Record)>,
    /// Observed records that already match a desired record, kept verbatim
    /// (their live TTL included).
    pub keep: Vec<Record>,
    /// Observed records at a **claimed** `(host, type)` that the desired set
    /// no longer accounts for — e.g. the second of two old MX records when
    /// one is desired. The only records reconciliation ever removes.
    pub remove: Vec<Record>,
    /// Observed records whose `(host, type)` the desired set does not claim.
    /// The first law: these survive verbatim, always.
    pub untouched: Vec<Record>,
}

impl Plan {
    /// The complete record set the domain should end up serving: everything
    /// unclaimed, verbatim, plus the desired set in its final form.
    ///
    /// This — never a bare desired set — is what
    /// [`crate::DnsProvider::apply`] receives, and it is how a
    /// replace-everything registrar upholds the first law.
    pub fn final_set(&self) -> Vec<Record> {
        let mut set = self.untouched.clone();
        set.extend(self.keep.iter().cloned());
        set.extend(self.update.iter().map(|(_, desired)| desired.clone()));
        set.extend(self.create.iter().cloned());
        set
    }

    /// True when the registrar already serves exactly what the config wants.
    pub fn is_settled(&self) -> bool {
        self.create.is_empty() && self.update.is_empty() && self.remove.is_empty()
    }

    /// The plan as the diff the operator reads before (or instead of) an
    /// apply: one summary line, then one line per record, `+` create,
    /// `~` update, `-` remove, `=` keep, `.` untouched.
    pub fn render(&self) -> String {
        let mut out = format!(
            "{} to create, {} to update, {} to remove, {} in place, {} not ours (untouched)\n",
            self.create.len(),
            self.update.len(),
            self.remove.len(),
            self.keep.len(),
            self.untouched.len()
        );
        for record in &self.create {
            out.push_str(&format!("+ {record}\n"));
        }
        for (observed, desired) in &self.update {
            out.push_str(&format!("~ {observed} => {desired}\n"));
        }
        for record in &self.remove {
            out.push_str(&format!("- {record}\n"));
        }
        for record in &self.keep {
            out.push_str(&format!("= {record}\n"));
        }
        for record in &self.untouched {
            out.push_str(&format!(". {record}\n"));
        }
        out
    }
}

/// Diffs what the registrar serves against what the config wants.
///
/// Matching is by `(host, type)`, both ASCII-case-insensitive; that pair being
/// present in `desired` is what "claimed" means. Within a claimed pair:
/// records equal under [`records_match`] are kept; remaining observed and
/// desired records are paired into updates; surplus desired become creates;
/// surplus observed become removes. Observed records at unclaimed pairs are
/// untouched — the first law, mechanically enforced by partitioning them out
/// before any comparison happens.
pub fn plan(observed: &[Record], desired: &[Record]) -> Plan {
    // Partition by the law first: only claimed records enter the diff at all.
    let mut pool: Vec<Record> = Vec::new();
    let mut untouched: Vec<Record> = Vec::new();
    for record in observed {
        if desired.iter().any(|d| same_claim(d, record)) {
            pool.push(record.clone());
        } else {
            untouched.push(record.clone());
        }
    }

    // Pass one: desired records the registrar already serves, kept verbatim.
    let mut keep = Vec::new();
    let mut unmatched: Vec<&Record> = Vec::new();
    for want in desired {
        match pool.iter().position(|have| records_match(want, have)) {
            Some(i) => keep.push(pool.remove(i)),
            None => unmatched.push(want),
        }
    }

    // Pass two: pair what remains within each claim; leftovers are creates
    // (nothing observed to reuse) or removes (nothing desired to become).
    let mut update = Vec::new();
    let mut create = Vec::new();
    for want in unmatched {
        match pool.iter().position(|have| same_claim(want, have)) {
            Some(i) => update.push((pool.remove(i), want.clone())),
            None => create.push(want.clone()),
        }
    }

    Plan { create, update, keep, remove: pool, untouched }
}

/// Whether two records occupy the same `(host, type)` claim,
/// ASCII-case-insensitively. Type-specific fields are ignored here — see
/// [`RecordType::kind`] for why.
fn same_claim(a: &Record, b: &Record) -> bool {
    a.host.eq_ignore_ascii_case(&b.host) && a.rtype.kind() == b.rtype.kind()
}

/// Whether an observed record already satisfies a desired one.
///
/// The claim must match, the type-specific fields must be equal, and the value
/// must be equal — case-insensitively and ignoring a trailing dot, except for
/// `TXT` and `CAA`, whose text is significant, since DNS names compare
/// case-blind but SPF/DKIM/verification strings do not. The dot matters:
/// registrars list name-valued targets fully qualified (`mail.example.com.`),
/// and treating that as a difference would rewrite an already-correct record
/// on every sync, forever. A desired TTL of `None` accepts any observed TTL;
/// TTLs differ only when both sides state one and they disagree.
pub fn records_match(desired: &Record, observed: &Record) -> bool {
    if !same_claim(desired, observed) || desired.rtype != observed.rtype_normalised() {
        return false;
    }
    let value_equal = match desired.rtype {
        RecordType::Txt | RecordType::Caa => desired.value == observed.value,
        _ => desired
            .value
            .trim_end_matches('.')
            .eq_ignore_ascii_case(observed.value.trim_end_matches('.')),
    };
    let ttl_equal = match (desired.ttl, observed.ttl) {
        (Some(want), Some(have)) => want == have,
        _ => true,
    };
    value_equal && ttl_equal
}

impl Record {
    /// This record's type with its name folded to the engine's variants, so an
    /// observed `Other("txt")` compares equal to the desired [`RecordType::Txt`].
    /// Providers should still parse into the schema'd variants; this is the
    /// safety net that keeps case or spelling drift from faking a diff.
    fn rtype_normalised(&self) -> RecordType {
        match &self.rtype {
            RecordType::Other(name) => match name.to_ascii_uppercase().as_str() {
                "A" => RecordType::A,
                "AAAA" => RecordType::Aaaa,
                "CNAME" => RecordType::Cname,
                "TXT" => RecordType::Txt,
                "CAA" => RecordType::Caa,
                upper => RecordType::Other(upper.into()),
            },
            schema => schema.clone(),
        }
    }
}

/// An `A` record at `host` with no TTL opinion.
fn a_record(host: &str, address: &str) -> Record {
    Record { host: host.into(), rtype: RecordType::A, value: address.into(), ttl: None }
}

/// `name` relative to `domain` when `name` is strictly under it
/// (`"www.example.com"` → `"www"`), else `None`. Case-insensitive, ignoring a
/// trailing dot on `name`. The stricter cousin of [`crate::relative_host`]:
/// it borrows, and the apex or a foreign name is `None` rather than a
/// spelling. Like it, a non-ASCII name whose split point lands mid-character
/// simply fails to match — never panics.
fn subdomain_host<'n>(name: &'n str, domain: &str) -> Option<&'n str> {
    let name = name.trim_end_matches('.');
    let host_len = name.len().checked_sub(domain.len() + 1).filter(|&len| len > 0)?;
    if !name.is_char_boundary(host_len) {
        return None;
    }
    let (host, suffix) = name.split_at(host_len);
    (suffix.starts_with('.') && suffix[1..].eq_ignore_ascii_case(domain)).then_some(host)
}

/// A [`RecordConfig`] from `Mail::dns_records`, in this crate's shape.
///
/// Private on purpose: it only ever sees that generator's output, whose types
/// `Mail::check` has already validated (an MX always carries a preference).
fn from_config_record(record: &RecordConfig) -> Record {
    let rtype = match record.record_type.to_ascii_uppercase().as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::Aaaa,
        "CNAME" => RecordType::Cname,
        "TXT" => RecordType::Txt,
        "CAA" => RecordType::Caa,
        // The generator sets preference on every MX; 0 would only appear if a
        // future generator change broke that, and 0 still delivers.
        "MX" => RecordType::Mx { preference: record.preference.unwrap_or(0) },
        other => RecordType::Other(other.into()),
    };
    Record {
        host: record.name.clone(),
        rtype,
        value: record.value.clone(),
        ttl: Some(record.ttl),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deployment with two sites (one holding a foreign domain) and mail
    /// with DKIM configured, parsed through the real config validator.
    fn deployment() -> Config {
        Config::parse(
            r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "main"
domains = ["example.com", "www.example.com"]
static_root = "./public"

[[sites]]
name = "side"
domains = ["app.example.com", "elsewhere.net"]
static_root = "./public"

[mail]
hostname = "mail.example.com"
domains = ["example.com"]

[mail.dkim]
selector = "s1"
private_key = "dkim/k.pem"
"#,
        )
        .expect("the test deployment must validate")
    }

    const IP: Ipv4Addr = Ipv4Addr::new(172, 83, 6, 109);

    fn find<'r>(records: &'r [Record], host: &str, kind: &str) -> Option<&'r Record> {
        records.iter().find(|r| r.host == host && r.rtype.kind() == kind)
    }

    #[test]
    fn derives_site_a_records_apex_wildcard_and_each_subdomain() {
        let records = desired_records(&deployment(), "example.com", IP, None);
        for host in ["@", "*", "www", "app"] {
            let record = find(&records, host, "A").unwrap_or_else(|| panic!("A at {host}"));
            assert_eq!(record.value, "172.83.6.109");
        }
        assert!(
            records.iter().all(|r| !r.host.contains("elsewhere")),
            "a foreign domain's site must not leak into this domain's records: {records:?}"
        );
    }

    #[test]
    fn derives_the_mail_records_from_the_one_config_generator() {
        let records =
            desired_records(&deployment(), "example.com", IP, Some("v=DKIM1; k=rsa; p=AAAA"));

        let mx = find(&records, "@", "MX").expect("an MX at the apex");
        assert_eq!(mx.value, "mail.example.com");
        assert_eq!(mx.rtype, RecordType::Mx { preference: 10 });

        assert_eq!(find(&records, "@", "TXT").expect("SPF").value, "v=spf1 mx -all");
        assert!(find(&records, "_dmarc", "TXT").expect("DMARC").value.contains("p=reject"));
        assert_eq!(
            find(&records, "s1._domainkey", "TXT").expect("DKIM").value,
            "v=DKIM1; k=rsa; p=AAAA"
        );
        assert_eq!(find(&records, "@", "CAA").expect("CAA").value, "0 issue letsencrypt.org");
    }

    #[test]
    fn derives_a_records_for_the_names_mail_promises() {
        // The MX target and the client-autoconfig hosts must resolve, or the
        // published promise black-holes mail and breaks account setup.
        let records = desired_records(&deployment(), "example.com", IP, None);
        for host in ["mail", "imap", "smtp"] {
            assert!(find(&records, host, "A").is_some(), "A at {host}");
        }
    }

    #[test]
    fn derives_the_rfc6186_client_discovery_srvs() {
        let records = desired_records(&deployment(), "example.com", IP, None);

        let imaps = find(&records, "_imaps._tcp", "SRV").expect("an IMAPS SRV");
        assert_eq!(imaps.rtype, RecordType::Srv { priority: 0, weight: 1, port: 993 });
        assert_eq!(imaps.value, "imap.example.com");

        let submission = find(&records, "_submission._tcp", "SRV").expect("a submission SRV");
        assert_eq!(submission.rtype, RecordType::Srv { priority: 0, weight: 1, port: 587 });
        assert_eq!(submission.value, "smtp.example.com");
    }

    #[test]
    fn omits_dkim_without_a_key_and_mail_records_off_the_mail_domain() {
        let no_key = desired_records(&deployment(), "example.com", IP, None);
        assert!(
            no_key.iter().all(|r| !r.host.ends_with("._domainkey")),
            "no DKIM record without a key to stand behind it"
        );

        // elsewhere.net has a site but is not a mail domain: A records only.
        let foreign = desired_records(&deployment(), "elsewhere.net", IP, None);
        assert!(find(&foreign, "@", "A").is_some(), "the site still gets its apex A");
        assert!(find(&foreign, "*", "A").is_some());
        assert!(
            foreign.iter().all(|r| matches!(r.rtype, RecordType::A)),
            "no mail promise for a domain mail does not cover: {foreign:?}"
        );
    }

    fn a(host: &str, value: &str) -> Record {
        Record { host: host.into(), rtype: RecordType::A, value: value.into(), ttl: None }
    }

    fn txt(host: &str, value: &str) -> Record {
        Record { host: host.into(), rtype: RecordType::Txt, value: value.into(), ttl: None }
    }

    #[test]
    fn the_first_law_unclaimed_records_survive_verbatim() {
        // The operator's own records — a verification TXT, a CNAME to a
        // service elsewhere — share the zone but not a claim.
        let foreign_txt = txt("zb1234", "verification=abc");
        let foreign_cname = Record {
            host: "status".into(),
            rtype: RecordType::Cname,
            value: "stats.example.org".into(),
            ttl: Some(300),
        };
        let observed = vec![foreign_txt.clone(), foreign_cname.clone(), a("@", "9.9.9.9")];
        let desired = vec![a("@", "1.2.3.4")];

        let plan = plan(&observed, &desired);
        assert_eq!(plan.untouched, vec![foreign_txt.clone(), foreign_cname.clone()]);
        assert_eq!(plan.update, vec![(a("@", "9.9.9.9"), a("@", "1.2.3.4"))]);
        assert!(plan.create.is_empty() && plan.keep.is_empty() && plan.remove.is_empty());

        let final_set = plan.final_set();
        assert!(final_set.contains(&foreign_txt), "the final set carries foreign records");
        assert!(final_set.contains(&foreign_cname));
        assert!(final_set.contains(&a("@", "1.2.3.4")));
        assert_eq!(final_set.len(), 3);
    }

    #[test]
    fn planning_the_desired_set_against_itself_is_all_keep() {
        let desired = desired_records(&deployment(), "example.com", IP, Some("v=DKIM1; p=A"));
        let plan = plan(&desired, &desired);
        assert!(plan.is_settled(), "an already-correct zone plans no changes");
        assert_eq!(plan.keep.len(), desired.len());
        assert!(plan.untouched.is_empty());
    }

    #[test]
    fn host_and_type_matching_is_case_insensitive() {
        // Registrars echo names and types in whatever case they please; that
        // must never read as a difference.
        let observed = vec![Record {
            host: "WWW".into(),
            rtype: RecordType::Other("a".into()),
            value: "1.2.3.4".into(),
            ttl: Some(3600),
        }];
        let desired = vec![a("www", "1.2.3.4")];

        let plan = plan(&observed, &desired);
        assert_eq!(plan.keep, observed, "kept verbatim, live TTL and all");
        assert!(plan.is_settled(), "case drift is not a diff: {}", plan.render());
    }

    #[test]
    fn txt_values_compare_case_sensitively_but_targets_do_not() {
        let observed_txt = vec![txt("@", "v=spf1 MX -all")];
        let desired_txt = vec![txt("@", "v=spf1 mx -all")];
        assert_eq!(plan(&observed_txt, &desired_txt).update.len(), 1, "TXT text is significant");

        let mx = |target: &str| Record {
            host: "@".into(),
            rtype: RecordType::Mx { preference: 10 },
            value: target.into(),
            ttl: None,
        };
        let settled = plan(&[mx("MAIL.Example.COM")], &[mx("mail.example.com")]);
        assert!(settled.is_settled(), "DNS names compare case-blind");
    }

    #[test]
    fn a_fully_qualified_observed_target_is_not_a_diff() {
        // Registrars (Namecheap among them) list name-valued targets with the
        // trailing dot; planning an update over that spelling difference would
        // rewrite the whole zone on every sync, forever.
        let mx = |target: &str| Record {
            host: "@".into(),
            rtype: RecordType::Mx { preference: 10 },
            value: target.into(),
            ttl: None,
        };
        let settled = plan(&[mx("mail.example.com.")], &[mx("mail.example.com")]);
        assert!(settled.is_settled(), "a trailing dot is not a change: {}", settled.render());

        let cname = |target: &str| Record {
            host: "www".into(),
            rtype: RecordType::Cname,
            value: target.into(),
            ttl: None,
        };
        assert!(plan(&[cname("example.com.")], &[cname("example.com")]).is_settled());
    }

    #[test]
    fn a_non_ascii_site_name_never_panics_the_subdomain_split() {
        // A split point inside a multi-byte character must read as "not under
        // this domain", not as a panic — config validation is the real guard,
        // but this function must hold its own.
        assert_eq!(subdomain_host("www.example.com", "example.com"), Some("www"));
        assert_eq!(subdomain_host("héllo.example.com", "example.com"), Some("héllo"));
        // Splitting "héllo…" two bytes in lands inside 'é' — the old
        // byte-index split panicked here.
        assert_eq!(subdomain_host("héllo.example.com", "llo.example.com"), None);
        assert_eq!(subdomain_host("short", "much-longer-domain.example"), None);
        assert_eq!(subdomain_host("example.com", "example.com"), None, "the apex is not under");
    }

    #[test]
    fn a_changed_mx_preference_is_an_update_not_a_create() {
        let mx = |preference| Record {
            host: "@".into(),
            rtype: RecordType::Mx { preference },
            value: "mail.example.com".into(),
            ttl: None,
        };
        let plan = plan(&[mx(20)], &[mx(10)]);
        assert_eq!(plan.update, vec![(mx(20), mx(10))]);
        assert!(plan.create.is_empty(), "same claim, so the record evolves in place");
    }

    #[test]
    fn surplus_observed_records_at_a_claimed_type_are_removed() {
        // Two stale MX records, one desired: one updates, one is removed —
        // and only because the config claims (@, MX).
        let mx = |target: &str| Record {
            host: "@".into(),
            rtype: RecordType::Mx { preference: 10 },
            value: target.into(),
            ttl: None,
        };
        let observed = vec![mx("old-a.example.net"), mx("old-b.example.net")];
        let desired = vec![mx("mail.example.com")];

        let plan = plan(&observed, &desired);
        assert_eq!(plan.update.len(), 1);
        assert_eq!(plan.remove, vec![mx("old-b.example.net")]);
        let final_set = plan.final_set();
        assert_eq!(final_set, vec![mx("mail.example.com")], "the stale MX is gone: {final_set:?}");
    }

    #[test]
    fn a_desired_ttl_of_none_accepts_any_observed_ttl() {
        let observed = vec![Record { ttl: Some(60), ..a("@", "1.2.3.4") }];
        assert!(plan(&observed, &[a("@", "1.2.3.4")]).is_settled(), "no TTL opinion, no diff");

        let strict = vec![Record { ttl: Some(3600), ..a("@", "1.2.3.4") }];
        assert_eq!(plan(&observed, &strict).update.len(), 1, "a stated TTL is enforced");
    }

    #[test]
    fn render_names_every_bucket() {
        let observed = vec![a("@", "9.9.9.9"), txt("foreign", "keep-me")];
        let desired = vec![a("@", "1.2.3.4"), a("www", "1.2.3.4")];
        let text = plan(&observed, &desired).render();
        assert!(text.contains("+ A www -> 1.2.3.4"), "{text}");
        assert!(text.contains("~ A @ -> 9.9.9.9 => A @ -> 1.2.3.4"), "{text}");
        assert!(text.contains(". TXT foreign -> keep-me"), "{text}");
        assert!(text.starts_with("1 to create, 1 to update, 0 to remove"), "{text}");
    }
}
