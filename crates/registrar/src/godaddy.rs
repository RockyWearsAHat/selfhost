//! GoDaddy DNS provider, over the v1 Domains API.
//!
//! GoDaddy's API (`api.godaddy.com/v1/domains/{domain}/records`, authenticated
//! by an `Authorization: sso-key {key}:{secret}` header) is *group-replace*
//! CRUD: `PUT …/records/{type}/{name}` swaps out every record sharing that
//! type and owner name in one call, and `GET …/records` lists the zone. Names
//! are relative with `"@"` for the apex — the crate's own spelling — except
//! SRV, where GoDaddy splits the owner into `service` + `protocol` fields and
//! keeps only the base name in `name` (so `_imaps._tcp.example.com` is
//! `service:"_imaps", protocol:"_tcp", name:"@"`). This module translates both
//! directions at the edge, as [`crate::Record`] demands.
//!
//! # Apply strategy, and how the first law holds
//!
//! [`DnsProvider::apply`] receives the full final set
//! ([`crate::plan::Plan::final_set`]). It fetches a fresh listing, buckets
//! both sides into GoDaddy's `(type, name)` groups, and `PUT`s only the
//! groups whose contents differ — a settled zone costs one `GET` and no
//! writes. Because unclaimed records ride inside the final set, an untouched
//! group compares equal and is never written; and when a foreign record
//! *shares* a group with managed ones — GoDaddy's SRV grouping ignores the
//! service, so a stranger's `_minecraft._tcp` shares `SRV/@` with our
//! `_imaps._tcp` — the replacement body carries the foreigner too, so the
//! group-wide `PUT` cannot erase it. No `DELETE` is ever issued: every
//! claimed group survives in the final set (the plan removes surplus records
//! only *within* claimed groups), so absence of a group from the set always
//! means "leave it alone".
//!
//! Worth knowing about the API: the rate limit is 60 requests per minute per
//! credential (one reconcile is one `GET` plus a handful of group `PUT`s, far
//! below it); GoDaddy has restricted this API since May 2024 to accounts
//! holding 10+ domains (50+ for some endpoints), which surfaces as an
//! authentication refusal; and value rules the API enforces — TTL minimums
//! and the like — surface verbatim as [`ProviderError::Api`]. The listing is
//! fetched as a single unpaginated page, which is safe only because
//! `fetch_zone` refuses a listing that reaches the reported server-side row
//! cap — see `SUSPECTED_PAGE_CAP`.

use std::collections::BTreeMap;

use selfhost_json::Json;

use crate::{ApiRequest, ApiResponse, DnsProvider, ProviderError, Record, RecordType, Transport};

/// Production endpoint. GoDaddy's test environment (`api.ote-godaddy.com`)
/// serves fabricated zones, so there is no configuration knob for it: this
/// provider only ever talks to the API that owns real domains.
const API_BASE: &str = "https://api.godaddy.com";

/// The row count at which a single-page listing can no longer be trusted.
///
/// GoDaddy's v1 records endpoint documents optional `offset`/`limit`
/// pagination but not its server-side default, and third-party clients report
/// listings capped near 500 rows; the official figure could not be confirmed
/// from the docs. A listing truncated by such a cap is indistinguishable from
/// a smaller zone, and a group `PUT` built from it (worst case `SRV/@`, which
/// replaces every service at the apex at once) would erase the records the
/// listing never showed. So a listing that reaches this length is refused
/// outright — fail closed until the pagination contract is pinned down — a
/// bound no self-host deployment's zone approaches.
const SUSPECTED_PAGE_CAP: usize = 500;

/// The GoDaddy registrar, driven through an injected [`Transport`] so every
/// exchange below is testable against canned responses.
///
/// Credentials are the key/secret pair GoDaddy issues at
/// `developer.godaddy.com`; they ride on each request as the legacy `sso-key`
/// authorization scheme, which the v1 API accepts account-wide.
pub struct GoDaddy<T> {
    transport: T,
    api_key: String,
    api_secret: String,
}

impl<T> GoDaddy<T> {
    /// A provider for the account `api_key`/`api_secret` belongs to.
    pub fn new(transport: T, api_key: impl Into<String>, api_secret: impl Into<String>) -> Self {
        Self { transport, api_key: api_key.into(), api_secret: api_secret.into() }
    }
}

impl<T: Transport + Sync> GoDaddy<T> {
    /// One authenticated exchange: build, send, and demand success — any
    /// non-2xx answer becomes [`ProviderError::Api`] carrying the API's own
    /// error body verbatim.
    async fn exchange(
        &self,
        method: &str,
        url: String,
        body: Option<Json>,
    ) -> Result<ApiResponse, ProviderError> {
        let mut headers = vec![
            ("Authorization".into(), format!("sso-key {}:{}", self.api_key, self.api_secret)),
            ("Accept".into(), "application/json".into()),
        ];
        if body.is_some() {
            headers.push(("Content-Type".into(), "application/json".into()));
        }
        let request = ApiRequest {
            method: method.into(),
            url,
            headers,
            body: body.map(|json| json.to_text().into_bytes()).unwrap_or_default(),
        };
        let response = self.transport.send(request).await?;
        if (200..300).contains(&response.status) {
            Ok(response)
        } else {
            let detail = match response.text() {
                text if text.is_empty() => "(empty response body)".into(),
                text => text,
            };
            Err(ProviderError::Api { status: response.status, detail })
        }
    }

    /// The zone as GoDaddy currently serves it, in the crate's shape — or a
    /// refusal when the listing reaches [`SUSPECTED_PAGE_CAP`] rows, because
    /// a listing that long may be a truncated page, and reconciling against a
    /// partial zone would erase the records the page never showed.
    async fn fetch_zone(&self, domain: &str) -> Result<Vec<Record>, ProviderError> {
        let url = format!("{API_BASE}/v1/domains/{}/records", encode_segment(domain));
        let response = self.exchange("GET", url, None).await?;
        let json = selfhost_json::parse(&response.text())
            .map_err(|err| ProviderError::Protocol(format!("the record listing is not JSON: {err}")))?;
        let items = json
            .as_array()
            .ok_or_else(|| ProviderError::Protocol("the record listing is not a JSON array".into()))?;
        if items.len() >= SUSPECTED_PAGE_CAP {
            return Err(ProviderError::Protocol(format!(
                "GoDaddy listed {} records — at the ~{SUSPECTED_PAGE_CAP}-row page cap its v1 \
                 API is reported to serve — so the listing may be truncated; refusing to \
                 reconcile a zone that may not be fully visible",
                items.len()
            )));
        }
        items.iter().map(parse_record).collect()
    }
}

impl<T: Transport + Sync> DnsProvider for GoDaddy<T> {
    async fn list(&self, domain: &str) -> Result<Vec<Record>, ProviderError> {
        self.fetch_zone(domain).await
    }

    async fn apply(&self, domain: &str, records: &[Record]) -> Result<(), ProviderError> {
        let observed = self.fetch_zone(domain).await?;
        let observed_groups = group_by_godaddy_key(&observed);
        for (key, want) in group_by_godaddy_key(records) {
            let already_served =
                observed_groups.get(&key).is_some_and(|have| same_records(&want, have));
            if already_served {
                continue;
            }
            let payload: Vec<Json> =
                want.iter().map(|record| record_payload(record)).collect::<Result<_, _>>()?;
            let (kind, name) = key;
            let url = format!(
                "{API_BASE}/v1/domains/{}/records/{kind}/{}",
                encode_segment(domain),
                encode_segment(&name),
            );
            self.exchange("PUT", url, Some(Json::array(payload))).await?;
        }
        Ok(())
    }
}

/// GoDaddy's replacement unit: uppercase type and lowercase owner `name` —
/// for SRV, the *base* name with the service and protocol labels stripped,
/// because that is the granularity `PUT …/records/{type}/{name}` swaps.
///
/// An SRV whose host does not split (a shape GoDaddy itself never produces)
/// falls back to its full host, an island key no well-formed desired record
/// collides with, so such a record is compared against itself and never
/// rewritten.
fn godaddy_key(record: &Record) -> (String, String) {
    let name = match (&record.rtype, srv_split(&record.host)) {
        (RecordType::Srv { .. }, Some((_, _, base))) => base,
        _ => record.host.as_str(),
    };
    (record.rtype.kind(), name.to_ascii_lowercase())
}

/// The records bucketed into their [`godaddy_key`] groups, deterministically
/// ordered so an apply always issues its `PUT`s in the same sequence.
fn group_by_godaddy_key(records: &[Record]) -> BTreeMap<(String, String), Vec<&Record>> {
    let mut groups: BTreeMap<(String, String), Vec<&Record>> = BTreeMap::new();
    for record in records {
        groups.entry(godaddy_key(record)).or_default().push(record);
    }
    groups
}

/// Whether two groups hold the same records regardless of order.
///
/// Exact equality is enough: a group needing no write consists purely of
/// records the final set carried over verbatim from the very listing being
/// compared against, so any difference at all is a genuine change.
fn same_records(want: &[&Record], have: &[&Record]) -> bool {
    if want.len() != have.len() {
        return false;
    }
    let mut unmatched: Vec<&Record> = have.to_vec();
    want.iter().all(|record| {
        match unmatched.iter().position(|candidate| candidate == record) {
            Some(i) => {
                unmatched.remove(i);
                true
            }
            None => false,
        }
    })
}

/// An SRV host split GoDaddy's way: `_imaps._tcp` → `("_imaps", "_tcp",
/// "@")`, `_x._udp.sub` → `("_x", "_udp", "sub")`. `None` when the host does
/// not carry the RFC 2782 underscore labels.
fn srv_split(host: &str) -> Option<(&str, &str, &str)> {
    let (service, rest) = host.split_once('.')?;
    let (protocol, base) = match rest.split_once('.') {
        Some((protocol, base)) => (protocol, base),
        None => (rest, "@"),
    };
    (service.starts_with('_') && protocol.starts_with('_') && !base.is_empty())
        .then_some((service, protocol, base))
}

/// One listed record into the crate's shape.
///
/// SRV hosts are reassembled from the `service`/`protocol`/`name` triple;
/// when the API omits the split fields the `name` is trusted as the full
/// owner, which keeps the record grouped by itself and therefore safe. A
/// record missing a number its type requires (MX priority, SRV port) is a
/// protocol error, never silently defaulted — a guessed preference could fake
/// a diff and rewrite a record the operator never changed.
fn parse_record(item: &Json) -> Result<Record, ProviderError> {
    let kind = required_str(item, "type")?.to_ascii_uppercase();
    let name = required_str(item, "name")?;
    let value = required_str(item, "data")?.to_owned();
    let mut host = name.to_owned();
    let rtype = match kind.as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::Aaaa,
        "CNAME" => RecordType::Cname,
        "TXT" => RecordType::Txt,
        "CAA" => RecordType::Caa,
        "MX" => RecordType::Mx { preference: required_number(item, "priority", &kind)? },
        "SRV" => {
            let service = item.get("service").and_then(Json::as_str);
            let protocol = item.get("protocol").and_then(Json::as_str);
            if let (Some(service), Some(protocol)) = (service, protocol) {
                host = match name {
                    "@" => format!("{service}.{protocol}"),
                    base => format!("{service}.{protocol}.{base}"),
                };
            }
            RecordType::Srv {
                priority: required_number(item, "priority", &kind)?,
                weight: required_number(item, "weight", &kind)?,
                port: required_number(item, "port", &kind)?,
            }
        }
        other => RecordType::Other(other.into()),
    };
    Ok(Record { host, rtype, value, ttl: optional_number(item, "ttl")? })
}

/// A record as the JSON object GoDaddy's `PUT` body wants. Fails only for an
/// SRV whose host cannot be split into the `service`/`protocol`/`name` shape
/// the API requires — refusing loudly beats sending a body the API would
/// misfile.
fn record_payload(record: &Record) -> Result<Json, ProviderError> {
    let mut entries = vec![("data", Json::string(record.value.clone()))];
    match &record.rtype {
        RecordType::Srv { priority, weight, port } => {
            let (service, protocol, base) = srv_split(&record.host).ok_or_else(|| {
                ProviderError::Protocol(format!(
                    "cannot express SRV host {:?} to GoDaddy: expected _service._protocol[.name]",
                    record.host
                ))
            })?;
            entries.push(("name", Json::string(base)));
            entries.push(("service", Json::string(service)));
            entries.push(("protocol", Json::string(protocol)));
            entries.push(("priority", Json::Number(f64::from(*priority))));
            entries.push(("weight", Json::Number(f64::from(*weight))));
            entries.push(("port", Json::Number(f64::from(*port))));
        }
        RecordType::Mx { preference } => {
            entries.push(("name", Json::string(record.host.clone())));
            entries.push(("priority", Json::Number(f64::from(*preference))));
        }
        _ => entries.push(("name", Json::string(record.host.clone()))),
    }
    entries.push(("type", Json::string(record.rtype.kind())));
    if let Some(ttl) = record.ttl {
        entries.push(("ttl", Json::Number(f64::from(ttl))));
    }
    Ok(Json::object(entries))
}

/// The string `field` of a listed record, or the protocol error naming what
/// is missing.
fn required_str<'j>(item: &'j Json, field: &str) -> Result<&'j str, ProviderError> {
    item.get(field).and_then(Json::as_str).ok_or_else(|| {
        ProviderError::Protocol(format!("a listed record is missing its {field:?} string"))
    })
}

/// The numeric `field` a `kind` record must carry, range-checked into the
/// target integer type.
fn required_number<N: TryFrom<u64>>(
    item: &Json,
    field: &str,
    kind: &str,
) -> Result<N, ProviderError> {
    item.get(field)
        .and_then(Json::as_u64)
        .and_then(|n| N::try_from(n).ok())
        .ok_or_else(|| {
            ProviderError::Protocol(format!(
                "a listed {kind} record is missing a usable {field:?} number"
            ))
        })
}

/// The optional numeric `field`: absent is fine, present-but-unusable is a
/// protocol error rather than a silently dropped value.
fn optional_number<N: TryFrom<u64>>(item: &Json, field: &str) -> Result<Option<N>, ProviderError> {
    match item.get(field) {
        None => Ok(None),
        Some(json) => json
            .as_u64()
            .and_then(|n| N::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| {
                ProviderError::Protocol(format!("a listed record's {field:?} is not a usable number"))
            }),
    }
}

/// `raw` as one URL path segment, percent-encoding everything RFC 3986 does
/// not allow there. `@`, `*`, `_`, and `.` — the characters DNS owner names
/// actually use — stay literal, so the URLs read like the documentation's.
fn encode_segment(raw: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'@' | b'*' => {
                out.push(byte as char);
            }
            other => {
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::plan;
    use crate::testing::{block_on, ok, response, Canned};

    fn provider(transport: &Canned) -> GoDaddy<&Canned> {
        GoDaddy::new(transport, "test-key", "test-secret")
    }

    fn a(host: &str, value: &str, ttl: Option<u32>) -> Record {
        Record { host: host.into(), rtype: RecordType::A, value: value.into(), ttl }
    }

    fn srv(host: &str, target: &str, port: u16) -> Record {
        Record {
            host: host.into(),
            rtype: RecordType::Srv { priority: 0, weight: 1, port },
            value: target.into(),
            ttl: Some(3600),
        }
    }

    #[test]
    fn list_asks_for_the_zone_with_sso_key_auth() {
        // A wrong URL or a malformed sso-key header fails against the real
        // API only — this pins both to the documented wire shape.
        let transport = Canned::scripted([ok("[]")]);
        let records = block_on(provider(&transport).list("example.com")).expect("an empty zone lists");
        assert!(records.is_empty());

        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].url, "https://api.godaddy.com/v1/domains/example.com/records");
        assert!(requests[0].body.is_empty());
        let auth = ("Authorization".to_string(), "sso-key test-key:test-secret".to_string());
        assert!(requests[0].headers.contains(&auth), "headers: {:?}", requests[0].headers);
    }

    #[test]
    fn list_parses_the_documented_record_shapes() {
        // Each type's fields land in the right slot; a swapped priority or a
        // dropped TTL here would corrupt every plan built on the listing.
        let transport = Canned::scripted([ok(r#"[
            {"type":"A","name":"@","data":"172.83.6.109","ttl":600},
            {"type":"MX","name":"@","data":"mail.example.com","priority":10,"ttl":3600},
            {"type":"TXT","name":"_dmarc","data":"v=DMARC1; p=reject"},
            {"type":"CAA","name":"@","data":"0 issue letsencrypt.org","ttl":3600},
            {"type":"NS","name":"@","data":"ns1.example.net","ttl":3600}
        ]"#)]);
        let records = block_on(provider(&transport).list("example.com")).expect("the listing parses");
        assert_eq!(records[0], a("@", "172.83.6.109", Some(600)));
        assert_eq!(records[1].rtype, RecordType::Mx { preference: 10 });
        assert_eq!(records[1].value, "mail.example.com");
        assert_eq!(records[2].rtype, RecordType::Txt);
        assert_eq!(records[2].value, "v=DMARC1; p=reject");
        assert_eq!(records[3].rtype, RecordType::Caa);
        assert_eq!(records[4].rtype, RecordType::Other("NS".into()), "unknown types survive");
    }

    #[test]
    fn list_reassembles_srv_hosts_from_service_and_protocol() {
        // GoDaddy splits an SRV owner into three fields; gluing them back
        // wrong would break claim matching for every SRV the config wants.
        let transport = Canned::scripted([ok(r#"[
            {"type":"SRV","name":"@","data":"imap.example.com","service":"_imaps",
             "protocol":"_tcp","port":993,"priority":0,"weight":1,"ttl":3600},
            {"type":"SRV","name":"sub","data":"mc.example.com","service":"_minecraft",
             "protocol":"_tcp","port":25565,"priority":0,"weight":5,"ttl":600}
        ]"#)]);
        let records = block_on(provider(&transport).list("example.com")).expect("SRVs parse");
        assert_eq!(records[0].host, "_imaps._tcp");
        assert_eq!(records[0].rtype, RecordType::Srv { priority: 0, weight: 1, port: 993 });
        assert_eq!(records[0].value, "imap.example.com");
        assert_eq!(records[1].host, "_minecraft._tcp.sub");
        assert_eq!(records[1].rtype, RecordType::Srv { priority: 0, weight: 5, port: 25565 });
    }

    #[test]
    fn list_refuses_a_record_missing_a_required_number() {
        // Defaulting a missing MX priority to 0 would fake a diff and rewrite
        // a record the operator never touched; the honest answer is an error.
        let transport =
            Canned::scripted([ok(r#"[{"type":"MX","name":"@","data":"mail.example.com"}]"#)]);
        let error = block_on(provider(&transport).list("example.com")).unwrap_err();
        assert!(
            matches!(&error, ProviderError::Protocol(detail) if detail.contains("priority")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_listing_at_the_suspected_page_cap_is_refused_as_possibly_truncated() {
        // A server-side page cap would make a big zone list as exactly the
        // cap; a group PUT built from that prefix would erase the unlisted
        // tail. Fail closed at the boundary.
        let rows: Vec<String> = (0..SUSPECTED_PAGE_CAP)
            .map(|i| format!(r#"{{"type":"A","name":"h{i}","data":"1.2.3.4","ttl":600}}"#))
            .collect();
        let body = format!("[{}]", rows.join(","));
        let transport = Canned::scripted([ok(&body)]);
        let error = block_on(provider(&transport).list("example.com")).unwrap_err();
        assert!(
            matches!(&error, ProviderError::Protocol(detail) if detail.contains("truncated")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn list_surfaces_the_apis_own_words_on_refusal() {
        let body = r#"{"code":"UNABLE_TO_AUTHENTICATE","message":"Unauthorized : credentials must be specified"}"#;
        let transport =
            Canned::scripted([response(401, body)]);
        let error = block_on(provider(&transport).list("example.com")).unwrap_err();
        match error {
            ProviderError::Api { status, detail } => {
                assert_eq!(status, 401);
                assert_eq!(detail, body, "the API's words arrive verbatim, untruncated");
            }
            other => panic!("expected an Api error, got: {other}"),
        }
    }

    #[test]
    fn list_reports_an_unparseable_success_as_protocol() {
        let transport = Canned::scripted([ok("<html>maintenance</html>")]);
        let error = block_on(provider(&transport).list("example.com")).unwrap_err();
        assert!(matches!(error, ProviderError::Protocol(_)), "unexpected error: {error}");
    }

    #[test]
    fn apply_puts_only_the_groups_that_differ() {
        // Observed: a stale apex A and a foreign TXT. Final set: the apex A
        // corrected, a new www A, the TXT untouched. Exactly two group PUTs
        // must go out — and none for the TXT, which needs nothing.
        let transport = Canned::scripted([
            ok(r#"[
                {"type":"A","name":"@","data":"9.9.9.9","ttl":600},
                {"type":"TXT","name":"zb1234","data":"verification=abc","ttl":3600}
            ]"#),
            ok("{}"),
            ok("{}"),
        ]);
        let observed = block_on(provider(&transport).list("example.com")).expect("the zone lists");
        let desired = vec![a("@", "172.83.6.109", None), a("www", "172.83.6.109", None)];
        let final_set = plan(&observed, &desired).final_set();

        // The apply issues its own fresh GET, so script the listing again.
        transport.rescript([
            ok(r#"[
                {"type":"A","name":"@","data":"9.9.9.9","ttl":600},
                {"type":"TXT","name":"zb1234","data":"verification=abc","ttl":3600}
            ]"#),
            ok("{}"),
            ok("{}"),
        ]);
        block_on(provider(&transport).apply("example.com", &final_set)).expect("the apply lands");

        let requests: Vec<ApiRequest> = transport.requests().into_iter().skip(2).collect();
        assert_eq!(requests.len(), 2, "one PUT per differing group, none for the foreign TXT");
        assert_eq!(requests[0].method, "PUT");
        assert_eq!(requests[0].url, "https://api.godaddy.com/v1/domains/example.com/records/A/@");
        assert_eq!(
            String::from_utf8(requests[0].body.clone()).unwrap(),
            r#"[{"data":"172.83.6.109","name":"@","type":"A"}]"#
        );
        assert_eq!(requests[1].url, "https://api.godaddy.com/v1/domains/example.com/records/A/www");
        assert_eq!(
            String::from_utf8(requests[1].body.clone()).unwrap(),
            r#"[{"data":"172.83.6.109","name":"www","type":"A"}]"#
        );
    }

    #[test]
    fn apply_carries_foreign_srvs_through_a_shared_group_replace() {
        // GoDaddy's SRV replacement unit is the *base* name: PUT records/SRV/@
        // swaps every service at the apex at once. The first law survives only
        // because the replacement body carries the foreign _minecraft._tcp
        // alongside the managed _imaps._tcp — this is the test that proves it.
        let listing = r#"[
            {"type":"SRV","name":"@","data":"imap.example.com","service":"_imaps",
             "protocol":"_tcp","port":143,"priority":0,"weight":1,"ttl":3600},
            {"type":"SRV","name":"@","data":"mc.example.com","service":"_minecraft",
             "protocol":"_tcp","port":25565,"priority":0,"weight":5,"ttl":600}
        ]"#;
        let transport = Canned::scripted([ok(listing)]);
        let observed = block_on(provider(&transport).list("example.com")).expect("the zone lists");
        let desired = vec![srv("_imaps._tcp", "imap.example.com", 993)];
        let final_set = plan(&observed, &desired).final_set();

        transport.rescript([ok(listing), ok("{}")]);
        block_on(provider(&transport).apply("example.com", &final_set)).expect("the apply lands");

        let requests: Vec<ApiRequest> = transport.requests().into_iter().skip(2).collect();
        assert_eq!(requests.len(), 1, "both services share one SRV/@ group");
        assert_eq!(requests[0].url, "https://api.godaddy.com/v1/domains/example.com/records/SRV/@");
        let body = String::from_utf8(requests[0].body.clone()).unwrap();
        assert!(
            body.contains(r#""service":"_minecraft""#) && body.contains(r#""port":25565"#),
            "the foreign SRV must ride along or the replace erases it: {body}"
        );
        assert!(body.contains(r#""service":"_imaps""#) && body.contains(r#""port":993"#), "{body}");
    }

    #[test]
    fn apply_a_settled_zone_writes_nothing() {
        let listing = r#"[{"type":"A","name":"@","data":"172.83.6.109","ttl":600}]"#;
        let transport = Canned::scripted([ok(listing)]);
        let observed = block_on(provider(&transport).list("example.com")).expect("the zone lists");
        let final_set = plan(&observed, &[a("@", "172.83.6.109", None)]).final_set();

        transport.rescript([ok(listing)]);
        block_on(provider(&transport).apply("example.com", &final_set)).expect("nothing to do");
        assert_eq!(transport.requests().len(), 2, "the second GET is the apply's only traffic");
    }

    #[test]
    fn apply_surfaces_a_put_refusal_verbatim() {
        let body = r#"{"code":"INVALID_BODY","message":"Request body doesn't fulfill schema","fields":[{"code":"MIN","path":"records.ttl"}]}"#;
        let transport = Canned::scripted([
            ok("[]"),
            response(422, body),
        ]);
        let error = block_on(provider(&transport).apply("example.com", &[a("@", "172.83.6.109", Some(60))]))
            .unwrap_err();
        match error {
            ProviderError::Api { status, detail } => {
                assert_eq!(status, 422);
                assert_eq!(detail, body);
            }
            other => panic!("expected an Api error, got: {other}"),
        }
    }

    #[test]
    fn apply_refuses_an_srv_host_it_cannot_express() {
        // A malformed SRV host cannot be split into GoDaddy's service and
        // protocol fields; sending it anyway would misfile the record.
        let transport = Canned::scripted([ok("[]")]);
        let error =
            block_on(provider(&transport).apply("example.com", &[srv("oops", "x.example.com", 1)]));
        assert!(
            matches!(&error, Err(ProviderError::Protocol(detail)) if detail.contains("oops")),
            "unexpected result: {error:?}"
        );
        assert_eq!(transport.requests().len(), 1, "nothing is PUT after the refusal");
    }

    #[test]
    fn path_segments_keep_dns_characters_and_escape_the_rest() {
        // "@" and "*" are legal path characters GoDaddy's docs use literally;
        // anything else unusual must be escaped or the URL changes meaning.
        assert_eq!(encode_segment("@"), "@");
        assert_eq!(encode_segment("*"), "*");
        assert_eq!(encode_segment("_imaps._tcp"), "_imaps._tcp");
        assert_eq!(encode_segment("a b/c"), "a%20b%2Fc");
    }

    #[test]
    fn mx_and_srv_payloads_carry_their_numbers() {
        let mx = Record {
            host: "@".into(),
            rtype: RecordType::Mx { preference: 10 },
            value: "mail.example.com".into(),
            ttl: Some(3600),
        };
        assert_eq!(
            record_payload(&mx).expect("an MX serialises").to_text(),
            r#"{"data":"mail.example.com","name":"@","priority":10,"ttl":3600,"type":"MX"}"#
        );
        assert_eq!(
            record_payload(&srv("_imaps._tcp", "imap.example.com", 993))
                .expect("an SRV serialises")
                .to_text(),
            concat!(
                r#"{"data":"imap.example.com","name":"@","port":993,"priority":0,"#,
                r#""protocol":"_tcp","service":"_imaps","ttl":3600,"type":"SRV","weight":1}"#
            )
        );
    }
}
