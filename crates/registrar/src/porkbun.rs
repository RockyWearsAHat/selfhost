//! Porkbun DNS provider: the v3 JSON API, driven one record at a time.
//!
//! Porkbun (`https://api.porkbun.com/api/json/v3/dns/...`) is a per-record
//! CRUD API, JSON both ways: `retrieve/{domain}` lists the zone with each
//! row's numeric `id`, and `create/{domain}`, `edit/{domain}/{id}`,
//! `delete/{domain}/{id}` change exactly one record each. Every call here is
//! a POST whose body carries the `apikey`/`secretapikey` pair — the body is
//! the credential channel, so no secret ever rides in a URL. Every response
//! wears the same envelope: `status` is `"SUCCESS"` or `"ERROR"`, and errors
//! explain themselves in `message` (plus a machine-readable `code`), which is
//! passed to the operator verbatim.
//!
//! Two conventions are translated at this edge and nowhere else:
//!
//! - **Names.** Listings return fully-qualified names (`"www.example.com"`);
//!   writes take the bare subdomain (`"www"`, `"*"`, `""` for the apex). Both
//!   become the crate's relative spelling (`"www"`, `"*"`, `"@"`).
//! - **Priorities.** MX preference and SRV priority travel in the `prio`
//!   field, so an SRV's `content` is only `weight port target` — the
//!   priority is *not* repeated inside it.
//!
//! [`DnsProvider::apply`] receives the full final set, fetches its own fresh
//! listing, diffs with [`plan::plan`], and issues only the closing edits,
//! deletes, and creates. Records the set does not claim never appear in any
//! write, which is how this per-record provider upholds the crate's first law.

use selfhost_json::Json;

use crate::{
    plan, relative_host, ApiRequest, ApiResponse, DnsProvider, ProviderError, Record, RecordType,
    Transport,
};

/// Every DNS endpoint lives under this path; the per-call suffix names the
/// operation and the domain (and, for `edit`/`delete`, the record id).
const BASE: &str = "https://api.porkbun.com/api/json/v3/dns";

/// The Porkbun registrar, speaking its v3 DNS API over an injected
/// [`Transport`].
///
/// Both keys come from the account's API access page; Porkbun requires the
/// pair on every call. The struct holds no other state — each operation
/// fetches what it needs, so a `Porkbun` can be built once and used for any
/// number of domains.
pub struct Porkbun<T: Transport> {
    transport: T,
    api_key: String,
    secret_api_key: String,
}

impl<T: Transport> Porkbun<T> {
    /// A provider for the account `api_key`/`secret_api_key` belong to.
    pub fn new(
        transport: T,
        api_key: impl Into<String>,
        secret_api_key: impl Into<String>,
    ) -> Self {
        Self { transport, api_key: api_key.into(), secret_api_key: secret_api_key.into() }
    }

    /// The body every call starts from: the credential pair, nothing else.
    /// `retrieve` and `delete` send exactly this; writes extend it.
    fn auth_body(&self) -> Json {
        Json::object([
            ("apikey", Json::string(self.api_key.clone())),
            ("secretapikey", Json::string(self.secret_api_key.clone())),
        ])
    }

    /// The `create`/`edit` body for `record`: credentials plus the record in
    /// Porkbun's spelling. `ttl` and `prio` are included only when the record
    /// states them — an omitted `ttl` lets the account default apply, exactly
    /// what `Record::ttl = None` ("no opinion") means.
    fn write_body(&self, record: &Record) -> Json {
        let (content, priority) = wire_data(record);
        let mut entries = vec![
            ("apikey", Json::string(self.api_key.clone())),
            ("secretapikey", Json::string(self.secret_api_key.clone())),
            ("name", Json::string(porkbun_name(&record.host))),
            ("type", Json::string(record.rtype.kind())),
            ("content", Json::string(content)),
        ];
        if let Some(ttl) = record.ttl {
            entries.push(("ttl", Json::Number(f64::from(ttl))));
        }
        if let Some(priority) = priority {
            entries.push(("prio", Json::Number(f64::from(priority))));
        }
        Json::object(entries)
    }

    /// One POST to `url`, envelope checked: the parsed body on `SUCCESS`,
    /// the API's own words as a [`ProviderError`] otherwise.
    async fn post(&self, url: String, body: Json) -> Result<Json, ProviderError> {
        let request = ApiRequest {
            method: "POST".into(),
            url,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: body.to_text().into_bytes(),
        };
        interpret(self.transport.send(request).await?)
    }

    /// The zone as Porkbun serves it, each record still wearing its row id —
    /// the private listing `apply` needs, from which the public [`list`]
    /// drops the ids.
    ///
    /// [`list`]: DnsProvider::list
    async fn rows(&self, domain: &str) -> Result<Vec<Row>, ProviderError> {
        let listing = self.post(format!("{BASE}/retrieve/{domain}"), self.auth_body()).await?;
        let rows = listing.get("records").and_then(Json::as_array).ok_or_else(|| {
            ProviderError::Protocol(format!(
                "the retrieve response has no records array: {}",
                listing.to_text()
            ))
        })?;
        rows.iter().map(|row| row_from_json(row, domain)).collect()
    }
}

impl<T: Transport + Sync> DnsProvider for Porkbun<T> {
    async fn list(&self, domain: &str) -> Result<Vec<Record>, ProviderError> {
        Ok(self.rows(domain).await?.into_iter().map(|row| row.record).collect())
    }

    async fn apply(&self, domain: &str, records: &[Record]) -> Result<(), ProviderError> {
        // Diff against a listing fetched *now*, not one the caller saw
        // earlier, so the ids edited and deleted are the zone's current ones.
        let mut rows = self.rows(domain).await?;
        let observed: Vec<Record> = rows.iter().map(|row| row.record.clone()).collect();
        let plan = plan::plan(&observed, records);

        // Edits first (they reuse existing rows), then deletes (clearing
        // stale duplicates before anything new lands), then creates. The
        // plan's untouched records appear in none of these — the first law.
        for (old, new) in &plan.update {
            let id = claim_row_id(&mut rows, old)?;
            self.post(format!("{BASE}/edit/{domain}/{id}"), self.write_body(new)).await?;
        }
        for old in &plan.remove {
            let id = claim_row_id(&mut rows, old)?;
            self.post(format!("{BASE}/delete/{domain}/{id}"), self.auth_body()).await?;
        }
        for new in &plan.create {
            self.post(format!("{BASE}/create/{domain}"), self.write_body(new)).await?;
        }
        Ok(())
    }
}

/// One listed record and the id Porkbun files it under.
struct Row {
    id: String,
    record: Record,
}

/// The id of the row holding exactly `wanted`, consumed from `rows` so two
/// identical records resolve to two distinct ids.
///
/// The plan's observed records are verbatim clones of this listing, so a miss
/// is a bug in this module, reported rather than swallowed.
fn claim_row_id(rows: &mut Vec<Row>, wanted: &Record) -> Result<String, ProviderError> {
    match rows.iter().position(|row| row.record == *wanted) {
        Some(i) => Ok(rows.swap_remove(i).id),
        None => Err(ProviderError::Protocol(format!(
            "planned change refers to a record missing from the listing it was planned from: {wanted}"
        ))),
    }
}

/// Accepts or refuses one exchange by Porkbun's envelope.
///
/// `status: "SUCCESS"` yields the parsed body. Any other `status` — whatever
/// the HTTP code, since Porkbun has answered both `200` and `4xx` envelopes —
/// is the API refusing, reported in its own `code`/`message` words. A body
/// that is not the documented envelope is a protocol surprise on a 2xx and an
/// API refusal (quoted whole) on an error status.
fn interpret(response: ApiResponse) -> Result<Json, ProviderError> {
    let http_ok = (200..300).contains(&response.status);
    let text = response.text();
    let envelope = match selfhost_json::parse(&text) {
        Ok(envelope) => envelope,
        Err(error) if http_ok => {
            return Err(ProviderError::Protocol(format!(
                "HTTP {} but the body is not JSON ({error}): {text}",
                response.status
            )));
        }
        Err(_) => return Err(ProviderError::Api { status: response.status, detail: text }),
    };
    match envelope.get("status").and_then(Json::as_str) {
        Some("SUCCESS") => Ok(envelope),
        Some(_) => {
            let code = envelope.get("code").and_then(Json::as_str);
            let message = envelope.get("message").and_then(Json::as_str);
            let detail = match (code, message) {
                (Some(code), Some(message)) => format!("{code}: {message}"),
                (None, Some(message)) => message.to_owned(),
                (Some(code), None) => code.to_owned(),
                (None, None) => text,
            };
            Err(ProviderError::Api { status: response.status, detail })
        }
        None if http_ok => Err(ProviderError::Protocol(format!(
            "the response carries no status field: {text}"
        ))),
        None => Err(ProviderError::Api { status: response.status, detail: text }),
    }
}

/// A listed row in the crate's shape, or why it cannot be read.
///
/// `id`, `name`, `type`, and `content` are required — a row missing them is
/// a protocol error, because a record that cannot be addressed cannot be
/// safely reconciled — and so is the `prio` of an MX or SRV row: priority is
/// identity-bearing, and silently defaulting it to 0 would fake a diff and
/// rewrite a record the operator never changed (the same rule the GoDaddy
/// and Cloudflare providers enforce). Only `ttl` is read leniently (Porkbun
/// lists numbers as strings): an unreadable `ttl` becomes "no opinion",
/// which at worst costs a redundant update, never a lost record.
fn row_from_json(row: &Json, domain: &str) -> Result<Row, ProviderError> {
    let id = match row.get("id") {
        Some(id) => id
            .as_str()
            .map(str::to_owned)
            .or_else(|| id.as_u64().map(|n| n.to_string())),
        None => None,
    }
    .ok_or_else(|| {
        ProviderError::Protocol(format!("a DNS record row has no id: {}", row.to_text()))
    })?;
    let name = required_text(row, "name")?;
    let kind = required_text(row, "type")?.to_ascii_uppercase();
    let content = required_text(row, "content")?;
    let ttl = number_field(row, "ttl").and_then(|n| u32::try_from(n).ok());

    let (rtype, value) = match kind.as_str() {
        "A" => (RecordType::A, content),
        "AAAA" => (RecordType::Aaaa, content),
        "CNAME" => (RecordType::Cname, content),
        "TXT" => (RecordType::Txt, content),
        "CAA" => (RecordType::Caa, content),
        "MX" => (RecordType::Mx { preference: required_priority(row, &kind)? }, content),
        "SRV" => {
            let priority = required_priority(row, &kind)?;
            match srv_content(&content) {
                Some((weight, port, target)) => {
                    (RecordType::Srv { priority, weight, port }, target)
                }
                // An SRV whose content is not `weight port target` cannot be
                // represented faithfully; carrying it as an opaque row keeps it
                // matched by kind rather than silently dropped or mangled.
                None => (RecordType::Other("SRV".into()), content),
            }
        }
        other => (RecordType::Other(other.into()), content),
    };
    Ok(Row {
        id,
        record: Record { host: relative_host(&name, domain), rtype, value, ttl },
    })
}

/// A required string field of a listed row, or the protocol error naming it.
fn required_text(row: &Json, field: &str) -> Result<String, ProviderError> {
    row.get(field).and_then(Json::as_str).map(str::to_owned).ok_or_else(|| {
        ProviderError::Protocol(format!(
            "a DNS record row is missing the {field:?} field: {}",
            row.to_text()
        ))
    })
}

/// A numeric row field however Porkbun spelt it — a JSON number, or the
/// numeric string its listings actually use. Anything else reads as absent.
fn number_field(row: &Json, field: &str) -> Option<u64> {
    let value = row.get(field)?;
    value.as_u64().or_else(|| value.as_str().and_then(|s| s.trim().parse().ok()))
}

/// The `prio` an MX or SRV row must carry, or the protocol error naming the
/// row — never a silent 0, which would fake a diff and rewrite a record that
/// was never wrong.
fn required_priority(row: &Json, kind: &str) -> Result<u16, ProviderError> {
    number_field(row, "prio").and_then(|n| u16::try_from(n).ok()).ok_or_else(|| {
        ProviderError::Protocol(format!(
            "a listed {kind} record has no usable \"prio\": {}",
            row.to_text()
        ))
    })
}

/// `weight port target` — an SRV's content once the priority moved to `prio`.
/// `None` when the content is not exactly that shape.
fn srv_content(content: &str) -> Option<(u16, u16, String)> {
    let mut parts = content.split_whitespace();
    let weight = parts.next()?.parse().ok()?;
    let port = parts.next()?.parse().ok()?;
    let target = parts.next()?.to_owned();
    match parts.next() {
        Some(_) => None,
        None => Some((weight, port, target)),
    }
}

/// The crate's relative host as the `name` a write takes: Porkbun wants the
/// bare subdomain, with the apex spelt as an empty string.
fn porkbun_name(host: &str) -> String {
    if host == "@" {
        String::new()
    } else {
        host.to_owned()
    }
}

/// A record's `content` and `prio` in Porkbun's split: MX preference and SRV
/// priority ride the `prio` field, an SRV's content is `weight port target`,
/// and every other type sends its value verbatim with no priority at all.
fn wire_data(record: &Record) -> (String, Option<u16>) {
    match record.rtype {
        RecordType::Mx { preference } => (record.value.clone(), Some(preference)),
        RecordType::Srv { priority, weight, port } => {
            (format!("{weight} {port} {}", record.value), Some(priority))
        }
        _ => (record.value.clone(), None),
    }
}

#[cfg(test)]
mod tests {
    use crate::testing::{block_on, response, Canned};

    use super::*;

    fn success() -> ApiResponse {
        response(200, r#"{"status":"SUCCESS"}"#)
    }

    fn provider(responses: impl IntoIterator<Item = ApiResponse>) -> Porkbun<Canned> {
        Porkbun::new(Canned::scripted(responses), "pk1_key", "sk1_secret")
    }

    fn body_json(request: &ApiRequest) -> Json {
        selfhost_json::parse(&String::from_utf8_lossy(&request.body))
            .expect("every request body this provider builds must be valid JSON")
    }

    /// A full Porkbun listing: apex A, subdomain, wildcard, MX with a string
    /// prio, TXT, and a numeric-string TTL throughout — the shapes the real
    /// API returns.
    const LISTING: &str = r#"{"status":"SUCCESS","cloudflare":"disabled","records":[
        {"id":"1","name":"example.com","type":"A","content":"1.2.3.4","ttl":"600","prio":null,"notes":null},
        {"id":"2","name":"www.example.com","type":"A","content":"1.2.3.4","ttl":"600","prio":null,"notes":null},
        {"id":"3","name":"*.example.com","type":"A","content":"1.2.3.4","ttl":"600","prio":null,"notes":null},
        {"id":"4","name":"example.com","type":"MX","content":"mail.example.com","ttl":"600","prio":"10","notes":null},
        {"id":"5","name":"example.com","type":"TXT","content":"v=spf1 mx -all","ttl":"600","prio":null,"notes":null}
    ]}"#;

    #[test]
    fn list_posts_the_documented_retrieve_request_with_body_credentials() {
        // A wrong URL or credentials in the wrong place fails against the
        // real API in a way no other test would catch.
        let porkbun = provider([response(200, LISTING)]);
        block_on(porkbun.list("example.com")).expect("a scripted listing must parse");

        let requests = porkbun.transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");
        assert_eq!(requests[0].url, "https://api.porkbun.com/api/json/v3/dns/retrieve/example.com");
        assert_eq!(requests[0].headers, vec![("Content-Type".into(), "application/json".into())]);
        assert_eq!(
            body_json(&requests[0]),
            Json::object([
                ("apikey", Json::string("pk1_key")),
                ("secretapikey", Json::string("sk1_secret")),
            ]),
            "retrieve carries exactly the credential pair, nothing else"
        );
    }

    #[test]
    fn list_translates_porkbun_rows_into_relative_records() {
        // Fully-qualified names, string TTLs, and string prios are Porkbun's
        // spellings; leaking any of them upward would fake diffs forever.
        let porkbun = provider([response(200, LISTING)]);
        let records = block_on(porkbun.list("example.com")).expect("the listing must parse");

        assert_eq!(records.len(), 5);
        assert_eq!(
            records[0],
            Record { host: "@".into(), rtype: RecordType::A, value: "1.2.3.4".into(), ttl: Some(600) }
        );
        assert_eq!(records[1].host, "www");
        assert_eq!(records[2].host, "*");
        assert_eq!(records[3].rtype, RecordType::Mx { preference: 10 });
        assert_eq!(records[3].value, "mail.example.com");
        assert_eq!(records[4].rtype, RecordType::Txt);
        assert_eq!(records[4].value, "v=spf1 mx -all");
    }

    #[test]
    fn list_reads_an_srv_from_prio_plus_weight_port_target_content() {
        // Porkbun keeps SRV priority in prio and only weight/port/target in
        // content; reading all four out of content would shift every field.
        let listing = r#"{"status":"SUCCESS","records":[
            {"id":"7","name":"_imaps._tcp.example.com","type":"SRV","content":"1 993 imap.example.com","ttl":"600","prio":"0"}
        ]}"#;
        let porkbun = provider([response(200, listing)]);
        let records = block_on(porkbun.list("example.com")).expect("the SRV row must parse");

        assert_eq!(
            records,
            vec![Record {
                host: "_imaps._tcp".into(),
                rtype: RecordType::Srv { priority: 0, weight: 1, port: 993 },
                value: "imap.example.com".into(),
                ttl: Some(600),
            }]
        );
    }

    #[test]
    fn an_unreadable_srv_content_survives_as_an_opaque_row() {
        // A malformed SRV must not be mangled into fake numbers or dropped —
        // either would eventually delete or corrupt a record we never owned.
        let listing = r#"{"status":"SUCCESS","records":[
            {"id":"8","name":"_x._tcp.example.com","type":"SRV","content":"not numbers here at all","ttl":"600","prio":"0"}
        ]}"#;
        let porkbun = provider([response(200, listing)]);
        let records = block_on(porkbun.list("example.com")).expect("the row still lists");

        assert_eq!(records[0].rtype, RecordType::Other("SRV".into()));
        assert_eq!(records[0].value, "not numbers here at all");
    }

    #[test]
    fn an_mx_row_without_a_usable_prio_is_a_protocol_error() {
        // Defaulting a missing preference to 0 would fake a diff against the
        // desired preference-10 MX and rewrite a record that was never wrong,
        // on every sync — the honest answer is an error naming the row.
        let listing = r#"{"status":"SUCCESS","records":[
            {"id":"9","name":"example.com","type":"MX","content":"mail.example.com","ttl":"600","prio":null}
        ]}"#;
        let porkbun = provider([response(200, listing)]);
        let error = block_on(porkbun.list("example.com")).expect_err("no prio, no guess");

        assert!(
            matches!(&error, ProviderError::Protocol(detail) if detail.contains("prio")),
            "got: {error}"
        );
    }

    #[test]
    fn an_error_envelope_becomes_an_api_error_in_porkbuns_own_words() {
        // Truncating or paraphrasing the API's message leaves the operator
        // debugging blind.
        let porkbun = provider([response(
            400,
            r#"{"status":"ERROR","code":"INVALID_API_KEY","message":"Invalid API key."}"#,
        )]);
        let error = block_on(porkbun.list("example.com")).expect_err("an ERROR envelope must refuse");

        match error {
            ProviderError::Api { status, detail } => {
                assert_eq!(status, 400);
                assert_eq!(detail, "INVALID_API_KEY: Invalid API key.");
            }
            other => panic!("expected an Api error, got {other:?}"),
        }
    }

    #[test]
    fn a_successful_status_with_an_undocumented_body_is_a_protocol_error() {
        // 2xx plus garbage means our model of the API is wrong — that must
        // surface as Protocol, not be misread as the API refusing.
        let not_json = provider([response(200, "<html>surprise</html>")]);
        assert!(matches!(
            block_on(not_json.list("example.com")),
            Err(ProviderError::Protocol(_))
        ));

        let no_records = provider([response(200, r#"{"status":"SUCCESS"}"#)]);
        assert!(matches!(
            block_on(no_records.list("example.com")),
            Err(ProviderError::Protocol(_))
        ));
    }

    /// The listing `apply` diffs against: a stale apex A, a foreign TXT this
    /// deployment never claimed, and two MX records where one should remain.
    const APPLY_LISTING: &str = r#"{"status":"SUCCESS","records":[
        {"id":"101","name":"example.com","type":"A","content":"9.9.9.9","ttl":"600","prio":null},
        {"id":"102","name":"zb123.example.com","type":"TXT","content":"verification=abc","ttl":"600","prio":null},
        {"id":"103","name":"example.com","type":"MX","content":"old-a.example.net","ttl":"600","prio":"10"},
        {"id":"104","name":"example.com","type":"MX","content":"old-b.example.net","ttl":"600","prio":"20"}
    ]}"#;

    /// The full final set for that zone: the foreign TXT carried through
    /// (as `Plan::final_set` would), a corrected apex A, one MX, one new SRV.
    fn final_set() -> Vec<Record> {
        vec![
            Record {
                host: "zb123".into(),
                rtype: RecordType::Txt,
                value: "verification=abc".into(),
                ttl: None,
            },
            Record { host: "@".into(), rtype: RecordType::A, value: "1.2.3.4".into(), ttl: None },
            Record {
                host: "@".into(),
                rtype: RecordType::Mx { preference: 10 },
                value: "mail.example.com".into(),
                ttl: None,
            },
            Record {
                host: "_imaps._tcp".into(),
                rtype: RecordType::Srv { priority: 0, weight: 1, port: 993 },
                value: "imap.example.com".into(),
                ttl: None,
            },
        ]
    }

    #[test]
    fn apply_issues_only_the_closing_edits_deletes_and_creates() {
        let porkbun = provider([
            response(200, APPLY_LISTING),
            success(), // edit 101: apex A value
            success(), // edit 103: MX target
            success(), // delete 104: the surplus MX
            response(200, r#"{"status":"SUCCESS","id":"9001"}"#), // create the SRV
        ]);
        block_on(porkbun.apply("example.com", &final_set())).expect("a scripted apply succeeds");

        let requests = porkbun.transport.requests();
        let urls: Vec<&str> = requests.iter().map(|r| r.url.as_str()).collect();
        assert_eq!(
            urls,
            vec![
                "https://api.porkbun.com/api/json/v3/dns/retrieve/example.com",
                "https://api.porkbun.com/api/json/v3/dns/edit/example.com/101",
                "https://api.porkbun.com/api/json/v3/dns/edit/example.com/103",
                "https://api.porkbun.com/api/json/v3/dns/delete/example.com/104",
                "https://api.porkbun.com/api/json/v3/dns/create/example.com",
            ]
        );

        // The apex edit: name is the empty string (Porkbun's apex spelling),
        // and a TTL-less record sends no ttl so the account default applies.
        let apex = body_json(&requests[1]);
        assert_eq!(apex.get("name"), Some(&Json::string("")));
        assert_eq!(apex.get("type"), Some(&Json::string("A")));
        assert_eq!(apex.get("content"), Some(&Json::string("1.2.3.4")));
        assert_eq!(apex.get("ttl"), None);

        // The MX edit carries its preference in prio, not in content.
        let mx = body_json(&requests[2]);
        assert_eq!(mx.get("content"), Some(&Json::string("mail.example.com")));
        assert_eq!(mx.get("prio"), Some(&Json::Number(10.0)));

        // The delete is addressed by id alone; its body is just credentials.
        assert_eq!(body_json(&requests[3]).get("name"), None);
    }

    #[test]
    fn apply_writes_an_srv_as_prio_plus_weight_port_target() {
        // Repeating the priority inside content would publish a five-field
        // SRV; dropping weight or port would publish a broken one.
        let porkbun = provider([
            response(200, APPLY_LISTING),
            success(),
            success(),
            success(),
            success(),
        ]);
        block_on(porkbun.apply("example.com", &final_set())).expect("a scripted apply succeeds");

        let requests = porkbun.transport.requests();
        let srv = body_json(requests.last().expect("the create request"));
        assert_eq!(srv.get("name"), Some(&Json::string("_imaps._tcp")));
        assert_eq!(srv.get("type"), Some(&Json::string("SRV")));
        assert_eq!(srv.get("content"), Some(&Json::string("1 993 imap.example.com")));
        assert_eq!(srv.get("prio"), Some(&Json::Number(0.0)));
    }

    #[test]
    fn the_first_law_apply_never_writes_to_an_unclaimed_record() {
        // Row 102 is the operator's own verification TXT. No edit, delete,
        // or replacement may ever reference it.
        let porkbun = provider([
            response(200, APPLY_LISTING),
            success(),
            success(),
            success(),
            success(),
        ]);
        block_on(porkbun.apply("example.com", &final_set())).expect("a scripted apply succeeds");

        for request in porkbun.transport.requests() {
            assert!(
                !request.url.ends_with("/102"),
                "an unclaimed record was written to: {}",
                request.url
            );
        }
    }

    #[test]
    fn apply_of_a_settled_zone_sends_no_writes() {
        // A no-op reconcile must cost one read, not a rewrite of the zone.
        let porkbun = provider([response(200, LISTING)]);
        let settled = block_on(porkbun.list("example.com")).expect("the listing must parse");

        let again = provider([response(200, LISTING)]);
        block_on(again.apply("example.com", &settled)).expect("a settled apply succeeds");
        assert_eq!(again.transport.requests().len(), 1, "retrieve only, no writes");
    }

    #[test]
    fn apply_stops_at_the_first_failed_write_and_reports_it_verbatim() {
        // Ploughing on after a refused write would leave the zone half-moved
        // with the error buried; the operator gets the API's words instead.
        let porkbun = provider([
            response(200, APPLY_LISTING),
            response(400, r#"{"status":"ERROR","message":"Edit error: TTL below minimum."}"#),
        ]);
        let error = block_on(porkbun.apply("example.com", &final_set()))
            .expect_err("a refused edit must fail the apply");

        match error {
            ProviderError::Api { status, detail } => {
                assert_eq!(status, 400);
                assert_eq!(detail, "Edit error: TTL below minimum.");
            }
            other => panic!("expected an Api error, got {other:?}"),
        }
        assert_eq!(porkbun.transport.requests().len(), 2, "nothing sent after the failure");
    }
}
