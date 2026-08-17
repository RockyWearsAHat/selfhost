//! The runtime model of an authoritative zone.
//!
//! A [`Zone`] is what the server actually serves: an apex, its SOA, its
//! nameservers, and every other record, stored as [`wire::Record`] so that
//! answering a query is a filter over one vec and there is exactly one wire
//! spelling of a record to keep correct. The config crate holds the *declarative*
//! shape ([`config::Dns`]); this is the thing it expands into, which is why the
//! dependency runs this way — `dns` depends on `config`, never the reverse.
//!
//! The subtlety worth stating: **the common case writes almost nothing.** A
//! deployment names a domain and this machine's public IP, and
//! [`default_zone`] fills in the rest — apex and `www` `A`, two nameservers with
//! glue, and an SOA whose serial is today's date. Everything else is an override
//! of that baseline, not a thing the operator must assemble by hand.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use selfhost_config::{RecordConfig, SoaConfig, ZoneConfig};

use crate::wire::{Record, RecordData, RecordType};

/// Refresh timer for a derived zone: how long a secondary waits between checks.
/// Two hours, an RFC 1912 §2.2 middle-of-the-road value.
pub const DEFAULT_REFRESH: u32 = 7200;
/// Retry timer: how long a secondary waits after a failed refresh. One hour.
pub const DEFAULT_RETRY: u32 = 3600;
/// Expire timer: how long a secondary serves the zone with no successful
/// refresh before giving up. Two weeks, so a long primary outage does not take
/// the domain down the moment a refresh is missed.
pub const DEFAULT_EXPIRE: u32 = 1_209_600;
/// Minimum / negative-cache TTL. One hour, short enough that a corrected record
/// or a fixed typo propagates the same day.
pub const DEFAULT_MINIMUM: u32 = 3600;

/// Longest `CNAME` chain [`Zone::answer`] follows before giving up. A larger
/// chain is a misconfiguration; the bound is what stops a cyclic alias in a
/// hand-edited config from recursing until the server's stack overflows.
const MAX_CNAME_CHAIN: u8 = 8;

/// The start-of-authority parameters, owned so the updater can bump `serial`.
///
/// Mirrors [`wire::RecordData::Soa`] field-for-field; [`Zone::soa_record`] turns
/// it into a [`wire::Record`] at serve time so there is exactly one wire spelling
/// and the authority section of every NXDOMAIN reads from the same source as an
/// SOA answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Soa {
    /// Primary nameserver for the zone.
    pub primary: String,
    /// Responsible party in DNS form (`hostmaster.example.com`).
    pub responsible: String,
    /// Zone version, increased on every change so a secondary re-transfers.
    pub serial: u32,
    /// Seconds a secondary waits between refresh checks.
    pub refresh: u32,
    /// Seconds a secondary waits before retrying a failed refresh.
    pub retry: u32,
    /// Seconds a secondary keeps serving with no successful refresh.
    pub expire: u32,
    /// Negative-cache TTL and the SOA record's own TTL.
    pub minimum: u32,
}

/// One authoritative zone: an apex name and the records under it.
///
/// Records are stored fully-qualified and lowercased so serving is an exact
/// owner-name match, and the SOA and nameservers are held apart from `records`
/// because the server synthesises them into the authority section of an
/// NXDOMAIN and the updater bumps the serial in place.
#[derive(Debug, Clone)]
pub struct Zone {
    /// The zone apex, lowercased, no trailing dot (e.g. "example.com").
    pub origin: String,
    /// The SOA, held apart so the updater can bump its serial without a scan.
    pub soa: Soa,
    /// Authoritative nameserver hostnames — the apex `NS` RRset.
    pub nameservers: Vec<String>,
    /// Every other record, owner names fully-qualified and lowercased.
    pub records: Vec<Record>,
}

impl Zone {
    /// Whether `qname` falls at or under this zone's origin (case-insensitive).
    pub fn contains(&self, qname: &str) -> bool {
        let q = normalize(qname);
        q == self.origin || q.ends_with(&format!(".{}", self.origin))
    }

    /// Every record answering an exact owner name and type.
    ///
    /// A `CNAME` is followed for an address query (`A`/`AAAA`) per RFC 1034
    /// §4.3.2: the `CNAME` is returned alongside whatever records its target
    /// carries *within this zone*, so a client asking for the address of an alias
    /// gets both the alias and the answer in one message. The apex `SOA` and `NS`
    /// are not returned here — they live outside `records` and the server emits
    /// them itself.
    pub fn answer(&self, qname: &str, qtype: RecordType) -> Vec<Record> {
        self.answer_within(qname, qtype, MAX_CNAME_CHAIN)
    }

    /// [`Zone::answer`] with a remaining-hops budget so a `CNAME` loop in a
    /// hand-edited config cannot recurse without bound and abort the server on a
    /// single client query. When the budget is spent the chase simply stops and
    /// the `CNAME` records gathered so far are returned unresolved.
    fn answer_within(&self, qname: &str, qtype: RecordType, hops: u8) -> Vec<Record> {
        let q = normalize(qname);
        let direct: Vec<Record> = self
            .records
            .iter()
            .filter(|record| record.name == q && data_type(&record.data) == qtype)
            .cloned()
            .collect();
        if !direct.is_empty() {
            return direct;
        }

        // No record of the asked type. For an address query, an alias at this
        // name is followed to its target's records so the client resolves the
        // whole chain from one answer.
        if matches!(qtype, RecordType::A | RecordType::Aaaa) && hops > 0 {
            if let Some(alias) = self
                .records
                .iter()
                .find(|record| record.name == q && data_type(&record.data) == RecordType::Cname)
            {
                let mut chain = vec![alias.clone()];
                if let RecordData::Name(target) = &alias.data {
                    chain.extend(self.answer_within(target, qtype, hops - 1));
                }
                return chain;
            }
        }
        Vec::new()
    }

    /// Whether any record exists at `qname`, distinguishing NODATA from NXDOMAIN.
    ///
    /// The apex always exists; otherwise the name exists if any record owns it.
    /// The caller uses this to choose between NOERROR-with-no-answer (the name is
    /// here, the type is not) and NXDOMAIN (the name is not here at all).
    pub fn name_exists(&self, qname: &str) -> bool {
        let q = normalize(qname);
        q == self.origin
            || self.nameservers.iter().any(|ns| normalize(ns) == q)
            || self.records.iter().any(|record| record.name == q)
    }

    /// The apex SOA as a wire record (owner = origin, ttl = `soa.minimum`).
    pub fn soa_record(&self) -> Record {
        Record {
            name: self.origin.clone(),
            ttl: self.soa.minimum,
            data: RecordData::Soa {
                primary: self.soa.primary.clone(),
                responsible: self.soa.responsible.clone(),
                serial: self.soa.serial,
                refresh: self.soa.refresh,
                retry: self.soa.retry,
                expire: self.soa.expire,
                minimum: self.soa.minimum,
            },
        }
    }

    /// The apex `NS` RRset as wire records, owner = origin, ttl = `soa.minimum`.
    pub fn ns_records(&self) -> Vec<Record> {
        self.nameservers
            .iter()
            .map(|ns| Record {
                name: self.origin.clone(),
                ttl: self.soa.minimum,
                data: RecordData::Name(normalize(ns)),
            })
            .collect()
    }

    /// Builds a runtime zone from its config, filling a bare zone from the IP.
    ///
    /// A zone with no records expands to [`default_zone`] (apex and `www` `A`,
    /// nameserver glue, a dated SOA); a zone that lists records takes those
    /// verbatim and derives only the SOA and nameservers. `secondaries` are
    /// appended to the nameserver set so they are advertised as `NS`. A `None`
    /// public IP leaves the address records out — the updater fills the apex `A`
    /// on its first tick — rather than inventing a placeholder address.
    pub fn from_config(zone: &ZoneConfig, secondaries: &[String], public_ip: Option<Ipv4Addr>) -> Zone {
        let origin = normalize(&zone.domain);
        let mut built = scaffold(&origin, public_ip);

        if let Some(overrides) = &zone.soa {
            apply_soa_overrides(&mut built.soa, overrides);
        }

        if !zone.nameservers.is_empty() {
            built.nameservers = zone.nameservers.iter().map(|ns| normalize(ns)).collect();
        }
        for secondary in secondaries {
            let secondary = normalize(secondary);
            if !built.nameservers.contains(&secondary) {
                built.nameservers.push(secondary);
            }
        }

        // A listed record set replaces the derived apex/www/glue entirely, so an
        // explicit zone is exactly what it declares and nothing more.
        if !zone.records.is_empty() {
            built.records = zone
                .records
                .iter()
                .filter_map(|record| record_from_config(&origin, record))
                .collect();
        }

        built
    }

    /// Appends config records to this zone, qualifying owner names against the
    /// apex, so records generated elsewhere (the mail domain's `MX`/SPF/DMARC/
    /// DKIM/CAA — see `config::Mail::dns_records`) can be published on top of a
    /// zone's derived apex/www/glue without the caller needing this crate's wire
    /// spelling. A record whose value cannot be parsed is skipped, matching the
    /// defensive drop in [`Zone::from_config`].
    pub fn push_config_records(&mut self, records: &[RecordConfig]) {
        for record in records {
            if let Some(built) = record_from_config(&self.origin, record) {
                self.records.push(built);
            }
        }
    }

    /// Adds an `A` for `name` at `ip`, unless the name already answers one.
    ///
    /// The building block for auto-populating a derived zone with the hostnames
    /// the rest of the config claims — each site domain and mail host under the
    /// apex gets an address without the operator writing a record for it. A name
    /// that already carries an `A` (the scaffold's apex/`www`/glue, or an earlier
    /// claim) is left alone rather than accumulating duplicates.
    pub fn ensure_address(&mut self, name: &str, ip: Ipv4Addr) {
        let owner = qualify(&self.origin, &normalize(name));
        let has_a = self
            .records
            .iter()
            .any(|record| record.name == owner && matches!(record.data, RecordData::A(_)));
        if !has_a {
            self.records.push(address(&owner, ip));
        }
    }
}

/// Derives a serviceable zone from just a domain and this machine's public IP.
///
/// This is what a bare `[[dns.zone]] domain = "..."` expands to: apex `A` and
/// `www` `A` at `public_ip`, an SOA whose primary is `ns1.<domain>` and whose
/// responsible party is `hostmaster.<domain>`, and two nameservers
/// `ns1`/`ns2.<domain>` with glue `A` records so the delegation resolves from a
/// single box. Timers follow RFC 1912 §2.2 defaults and the serial is today's
/// `YYYYMMDD00`. A real off-site secondary is added through `[dns].secondaries`,
/// not here.
///
/// Mail and certificate records are deliberately *not* derived — see the
/// commented template inside for the `MX`, SPF/DMARC `TXT`, and Let's Encrypt
/// `CAA` records a deployment adds once its mail and TLS are in place.
pub fn default_zone(domain: &str, public_ip: Ipv4Addr) -> Zone {
    scaffold(&normalize(domain), Some(public_ip))
}

/// Builds the baseline SOA + nameservers, and the address records when an IP is
/// known. Shared by [`default_zone`] and [`Zone::from_config`].
fn scaffold(origin: &str, public_ip: Option<Ipv4Addr>) -> Zone {
    let ns1 = format!("ns1.{origin}");
    let ns2 = format!("ns2.{origin}");

    let soa = Soa {
        primary: ns1.clone(),
        responsible: format!("hostmaster.{origin}"),
        serial: today_serial(),
        refresh: DEFAULT_REFRESH,
        retry: DEFAULT_RETRY,
        expire: DEFAULT_EXPIRE,
        minimum: DEFAULT_MINIMUM,
    };

    let mut records = Vec::new();
    if let Some(ip) = public_ip {
        // The apex and www point at this box; ns1/ns2 carry glue so a resolver
        // that is told "ns1.<domain> is authoritative" can find its address
        // without a second delegation to chase.
        records.push(address(origin, ip));
        records.push(address(&format!("www.{origin}"), ip));
        records.push(address(&ns1, ip));
        records.push(address(&ns2, ip));

        // Records a deployment adds once mail and TLS are in place. They are left
        // as a template rather than derived, because inventing a mail exchanger
        // or an SPF policy for a domain that has no mail yet publishes a promise
        // the box cannot keep:
        //
        //   [[dns.zone.record]]                 # mail is delivered to this host
        //   name = "@"; type = "MX"; preference = 10; value = "mail.<domain>"
        //
        //   [[dns.zone.record]]                 # only this host may send as us
        //   name = "@"; type = "TXT"; value = "v=spf1 mx -all"
        //
        //   [[dns.zone.record]]                 # reject unaligned mail, report abuse
        //   name = "_dmarc"; type = "TXT"
        //   value = "v=DMARC1; p=reject; rua=mailto:postmaster@<domain>"
        //
        //   [[dns.zone.record]]                 # only Let's Encrypt may issue certs
        //   name = "@"; type = "CAA"; value = "0 issue letsencrypt.org"
    }

    Zone { origin: origin.to_owned(), soa, nameservers: vec![ns1, ns2], records }
}

/// Applies a config's SOA overrides onto a derived SOA, field by field.
fn apply_soa_overrides(soa: &mut Soa, overrides: &SoaConfig) {
    if let Some(primary) = &overrides.primary {
        soa.primary = normalize(primary);
    }
    if let Some(responsible) = &overrides.responsible {
        soa.responsible = normalize(responsible);
    }
    if let Some(serial) = overrides.serial {
        soa.serial = serial;
    }
    if let Some(refresh) = overrides.refresh {
        soa.refresh = refresh;
    }
    if let Some(retry) = overrides.retry {
        soa.retry = retry;
    }
    if let Some(expire) = overrides.expire {
        soa.expire = expire;
    }
    if let Some(minimum) = overrides.minimum {
        soa.minimum = minimum;
    }
}

/// Turns one config record into a wire record, or drops it if its value cannot
/// be parsed — validation has already reported such a record, so a survivor here
/// is defended against rather than trusted.
fn record_from_config(origin: &str, record: &RecordConfig) -> Option<Record> {
    let name = qualify(origin, &record.name);
    let data = match record.record_type.to_ascii_uppercase().as_str() {
        "A" => RecordData::A(record.value.parse::<Ipv4Addr>().ok()?),
        "AAAA" => RecordData::Aaaa(record.value.parse::<Ipv6Addr>().ok()?),
        "MX" => RecordData::Mx {
            preference: record.preference?,
            exchange: normalize(&record.value),
        },
        "TXT" => RecordData::Txt(record.value.clone()),
        "CNAME" | "NS" => RecordData::Name(normalize(&record.value)),
        "SRV" => srv_data(&record.value)?,
        "CAA" => RecordData::Unknown {
            record_type: RecordType::Caa,
            data: caa_rdata(&record.value)?,
        },
        _ => return None,
    };
    Some(Record { name, ttl: record.ttl, data })
}

/// Parses an `SRV` value in presentation form (`<priority> <weight> <port>
/// <target>`, RFC 2782's zone-file order) into its payload. `None` when any
/// numeric field does not parse or the target is missing.
fn srv_data(value: &str) -> Option<RecordData> {
    let mut fields = value.split_whitespace();
    let priority = fields.next()?.parse().ok()?;
    let weight = fields.next()?.parse().ok()?;
    let port = fields.next()?.parse().ok()?;
    let target = normalize(fields.next()?);
    if target.is_empty() || fields.next().is_some() {
        return None;
    }
    Some(RecordData::Srv { priority, weight, port, target })
}

/// Encodes a `CAA` value in presentation form (`<flags> <tag> <value>`) into its
/// wire rdata: a one-byte flags field, a length-prefixed tag, then the value.
fn caa_rdata(value: &str) -> Option<Vec<u8>> {
    let mut fields = value.split_whitespace();
    let flags: u8 = fields.next()?.parse().ok()?;
    let tag = fields.next()?;
    if tag.is_empty() || tag.len() > u8::MAX as usize {
        return None;
    }
    let rest: Vec<&str> = fields.collect();
    if rest.is_empty() {
        return None;
    }
    let quality = rest.join(" ");
    let quality = quality.trim_matches('"');

    let mut rdata = Vec::with_capacity(2 + tag.len() + quality.len());
    rdata.push(flags);
    rdata.push(tag.len() as u8);
    rdata.extend_from_slice(tag.as_bytes());
    rdata.extend_from_slice(quality.as_bytes());
    Some(rdata)
}

/// A `wire::Record` holding an `A` at `name`, ttl [`DEFAULT_MINIMUM`].
fn address(name: &str, ip: Ipv4Addr) -> Record {
    Record { name: name.to_owned(), ttl: DEFAULT_MINIMUM, data: RecordData::A(ip) }
}

/// Lowercases a name and strips a trailing dot, the one spelling used everywhere.
fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Resolves a config owner name against the zone apex.
///
/// `"@"` is the apex; a name already at or under the origin is kept as written;
/// anything else is treated as relative and the origin appended, so `"www"`
/// becomes `www.<origin>`.
fn qualify(origin: &str, name: &str) -> String {
    if name == "@" {
        return origin.to_owned();
    }
    let lowered = normalize(name);
    if lowered == origin || lowered.ends_with(&format!(".{origin}")) {
        lowered
    } else {
        format!("{lowered}.{origin}")
    }
}

/// Today's SOA serial in `YYYYMMDD00` form, seeded from the system clock.
///
/// The `00` suffix is the day's revision counter; the updater increments from
/// here on each apex change so a secondary always sees the number move forward.
fn today_serial() -> u32 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0) as i64;
    let (year, month, day) = civil_from_days(seconds.div_euclid(86_400));
    (year as u32) * 1_000_000 + month * 10_000 + day * 100
}

/// Converts days since 1970-01-01 into a civil `(year, month, day)`.
///
/// Howard Hinnant's `civil_from_days`, used rather than a date crate so the DNS
/// crate pulls in no dependency to stamp a serial. Valid across the whole range
/// this project will ever see. `pub(crate)` because [`crate::time`] reuses it
/// for the log timestamp rather than keeping a second copy in the same crate.
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// The record type a payload corresponds to. Mirrors the wire module's private
/// mapping; kept here so this module does not reach into wire internals.
fn data_type(data: &RecordData) -> RecordType {
    match data {
        RecordData::A(_) => RecordType::A,
        RecordData::Aaaa(_) => RecordType::Aaaa,
        RecordData::Name(_) => RecordType::Cname,
        RecordData::Mx { .. } => RecordType::Mx,
        RecordData::Txt(_) => RecordType::Txt,
        RecordData::Soa { .. } => RecordType::Soa,
        RecordData::Srv { .. } => RecordType::Srv,
        RecordData::Unknown { record_type, .. } => *record_type,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);

    fn zone_config(domain: &str, records: Vec<RecordConfig>) -> ZoneConfig {
        ZoneConfig {
            domain: domain.to_owned(),
            soa: None,
            nameservers: Vec::new(),
            records,
        }
    }

    fn record(name: &str, record_type: &str, value: &str) -> RecordConfig {
        RecordConfig {
            name: name.to_owned(),
            record_type: record_type.to_owned(),
            ttl: 3600,
            value: value.to_owned(),
            preference: None,
        }
    }

    #[test]
    fn a_default_zone_carries_apex_www_and_nameserver_glue() {
        let zone = default_zone("Example.COM", IP);
        assert_eq!(zone.origin, "example.com", "the origin is lowercased");

        // Apex, www, and both nameservers resolve to this box out of the box.
        for name in ["example.com", "www.example.com", "ns1.example.com", "ns2.example.com"] {
            let answers = zone.answer(name, RecordType::A);
            assert_eq!(answers.len(), 1, "{name} should have one A record");
            assert_eq!(answers[0].data, RecordData::A(IP));
        }
        assert_eq!(zone.nameservers, vec!["ns1.example.com", "ns2.example.com"]);
    }

    #[test]
    fn a_default_soa_names_ns1_and_hostmaster_with_a_dated_serial() {
        let zone = default_zone("example.com", IP);
        assert_eq!(zone.soa.primary, "ns1.example.com");
        assert_eq!(zone.soa.responsible, "hostmaster.example.com");
        assert_eq!(zone.soa.refresh, DEFAULT_REFRESH);
        assert_eq!(zone.soa.expire, DEFAULT_EXPIRE);
        // A YYYYMMDD00 serial is ten digits and this century.
        assert!(zone.soa.serial >= 2_000_000_000, "serial {} looks undated", zone.soa.serial);
        assert_eq!(zone.soa.serial % 100, 0, "the revision counter starts at 00");
    }

    #[test]
    fn the_soa_record_owns_the_apex_with_the_minimum_ttl() {
        let zone = default_zone("example.com", IP);
        let soa = zone.soa_record();
        assert_eq!(soa.name, "example.com");
        assert_eq!(soa.ttl, zone.soa.minimum);
        assert!(matches!(soa.data, RecordData::Soa { serial, .. } if serial == zone.soa.serial));
    }

    #[test]
    fn contains_matches_the_apex_and_names_under_it_but_not_a_sibling() {
        let zone = default_zone("example.com", IP);
        assert!(zone.contains("example.com"));
        assert!(zone.contains("www.EXAMPLE.com"));
        assert!(zone.contains("deep.sub.example.com"));
        assert!(!zone.contains("example.net"));
        assert!(!zone.contains("notexample.com"));
    }

    #[test]
    fn name_exists_separates_nodata_from_nxdomain() {
        let zone = default_zone("example.com", IP);
        // www exists (it has an A) but has no MX: NODATA, not NXDOMAIN.
        assert!(zone.name_exists("www.example.com"));
        assert!(zone.answer("www.example.com", RecordType::Mx).is_empty());
        // nothing named "absent" exists at all: NXDOMAIN.
        assert!(!zone.name_exists("absent.example.com"));
    }

    #[test]
    fn an_address_query_follows_a_cname_to_its_target() {
        let zone = Zone::from_config(
            &zone_config(
                "example.com",
                vec![
                    record("@", "A", "203.0.113.10"),
                    record("blog", "CNAME", "www.example.com"),
                    record("www", "A", "203.0.113.20"),
                ],
            ),
            &[],
            Some(IP),
        );

        let answers = zone.answer("blog.example.com", RecordType::A);
        // The CNAME and the resolved address arrive together.
        assert!(matches!(answers[0].data, RecordData::Name(ref t) if t == "www.example.com"));
        assert!(answers.iter().any(|r| r.data == RecordData::A(Ipv4Addr::new(203, 0, 113, 20))));
    }

    #[test]
    fn a_bare_config_zone_expands_to_the_default() {
        let zone = Zone::from_config(&zone_config("example.com", vec![]), &[], Some(IP));
        assert_eq!(zone.answer("example.com", RecordType::A)[0].data, RecordData::A(IP));
        assert_eq!(zone.answer("www.example.com", RecordType::A).len(), 1);
    }

    #[test]
    fn listed_records_replace_the_derived_defaults_entirely() {
        let zone = Zone::from_config(
            &zone_config("example.com", vec![record("@", "A", "198.51.100.1")]),
            &[],
            Some(IP),
        );
        // The derived www default is gone; only the listed apex A remains.
        assert_eq!(
            zone.answer("example.com", RecordType::A)[0].data,
            RecordData::A(Ipv4Addr::new(198, 51, 100, 1))
        );
        assert!(zone.answer("www.example.com", RecordType::A).is_empty());
    }

    #[test]
    fn secondaries_are_appended_to_the_nameserver_set_without_duplication() {
        let zone = Zone::from_config(
            &zone_config("example.com", vec![]),
            &["ns2.he.net".to_owned(), "ns1.example.com".to_owned()],
            Some(IP),
        );
        assert!(zone.nameservers.contains(&"ns2.he.net".to_owned()));
        // ns1.example.com is already derived and must not be added twice.
        assert_eq!(zone.nameservers.iter().filter(|ns| *ns == "ns1.example.com").count(), 1);
    }

    #[test]
    fn mx_txt_and_caa_records_build_from_config() {
        let mut mx = record("@", "MX", "mail.example.com");
        mx.preference = Some(10);
        let zone = Zone::from_config(
            &zone_config(
                "example.com",
                vec![
                    mx,
                    record("@", "TXT", "v=spf1 mx -all"),
                    record("@", "CAA", "0 issue letsencrypt.org"),
                ],
            ),
            &[],
            Some(IP),
        );

        assert_eq!(
            zone.answer("example.com", RecordType::Mx)[0].data,
            RecordData::Mx { preference: 10, exchange: "mail.example.com".to_owned() }
        );
        assert_eq!(
            zone.answer("example.com", RecordType::Txt)[0].data,
            RecordData::Txt("v=spf1 mx -all".to_owned())
        );
        // 0 (flags) 05 (tag len) "issue" "letsencrypt.org"
        let caa = &zone.answer("example.com", RecordType::Caa)[0].data;
        assert_eq!(
            *caa,
            RecordData::Unknown {
                record_type: RecordType::Caa,
                data: b"\x00\x05issueletsencrypt.org".to_vec(),
            }
        );
    }

    #[test]
    fn a_config_soa_override_replaces_only_the_named_fields() {
        let mut config = zone_config("example.com", vec![]);
        config.soa = Some(SoaConfig { serial: Some(2030010105), ..SoaConfig::default() });
        let zone = Zone::from_config(&config, &[], Some(IP));
        assert_eq!(zone.soa.serial, 2030010105, "the override wins");
        // Un-overridden fields keep the derived defaults.
        assert_eq!(zone.soa.primary, "ns1.example.com");
        assert_eq!(zone.soa.refresh, DEFAULT_REFRESH);
    }

    #[test]
    fn a_zone_with_no_public_ip_yet_has_an_soa_but_no_address_records() {
        // Before the updater's first tick the apex A is simply absent, rather
        // than a placeholder like 0.0.0.0 that would point the domain at nothing.
        let zone = Zone::from_config(&zone_config("example.com", vec![]), &[], None);
        assert!(zone.answer("example.com", RecordType::A).is_empty());
        assert_eq!(zone.soa.primary, "ns1.example.com");
        assert_eq!(zone.nameservers.len(), 2);
    }

    #[test]
    fn civil_from_days_matches_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
        // A leap day, to exercise the month/day arithmetic across February.
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
    }
}
