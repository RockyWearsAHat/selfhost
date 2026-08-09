//! Cloudflare DNS provider: the v4 REST API, spoken through an injected
//! transport.
//!
//! Cloudflare's API (`api.cloudflare.com/client/v4`, `Authorization: Bearer`
//! token) is per-record CRUD over JSON: a zone is found by name
//! (`GET /zones?name=`), its records listed page by page
//! (`GET /zones/{id}/dns_records`), and each change is its own
//! `POST`/`PUT`/`DELETE`. So [`DnsProvider::apply`] does not push the given
//! set anywhere wholesale — it lists the zone fresh, feeds that listing and
//! the given **full final set** back through the crate's own engine
//! ([`plan::plan`]), and issues only the creates, updates, and deletes that
//! close the gap. The first law holds structurally: a record the final set
//! does not claim lands in the plan's `untouched` bucket, and no request is
//! ever built from that bucket.
//!
//! Cloudflare's own conventions are translated at this edge and nowhere else:
//! names are absolute (`"@"` ⇄ the domain itself), `ttl: 1` means "automatic"
//! (⇄ this crate's `ttl: None`), MX preference rides top-level `priority`,
//! SRV numbers and CAA fields ride a `data` object with the service labels in
//! `name`, and TXT content comes back RFC 1035-quoted. Every exchange goes
//! through the injected [`Transport`], so the whole protocol — pagination,
//! error envelopes, both directions of the translation — is tested below
//! against canned responses, never a socket.

use selfhost_json::Json;

use crate::{plan, relative_host};
use crate::{ApiRequest, DnsProvider, ProviderError, Record, RecordType, Transport};

/// Where Cloudflare's v4 API lives; every URL this module builds starts here.
const API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// Records requested per listing page — Cloudflare's documented default, kept
/// explicit so pagination is exercised deliberately rather than by surprise.
const PER_PAGE: u32 = 100;

/// The TTL value Cloudflare spells "automatic", mapped to this crate's
/// `ttl: None` in both directions so "no opinion" survives a round trip.
const TTL_AUTOMATIC: u32 = 1;

/// The Cloudflare provider: an API token plus the transport that carries it.
///
/// The token needs `Zone → Zone: Read` and `Zone → DNS: Edit` on the zones it
/// reconciles; it is sent as `Authorization: Bearer` on every request and
/// never appears in a URL.
pub struct Cloudflare<T: Transport> {
    transport: T,
    token: String,
}

impl<T: Transport> Cloudflare<T> {
    /// A provider that authenticates every exchange with `token` over
    /// `transport`.
    pub fn new(transport: T, token: impl Into<String>) -> Self {
        Self { transport, token: token.into() }
    }

    /// One authenticated exchange, decoded to Cloudflare's response envelope.
    ///
    /// Success means an HTTP 2xx **and** the envelope's `success: true`;
    /// anything else becomes [`ProviderError::Api`] carrying the envelope's
    /// own error messages (or the raw body when there is no envelope), so the
    /// operator reads Cloudflare's words, not a paraphrase. The whole parsed
    /// document is returned — callers read `result` and `result_info` from it.
    async fn call(
        &self,
        method: &str,
        url: String,
        body: Option<Json>,
    ) -> Result<Json, ProviderError> {
        let mut headers = vec![("Authorization".to_owned(), format!("Bearer {}", self.token))];
        let body = match body {
            Some(json) => {
                headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
                json.to_text().into_bytes()
            }
            None => Vec::new(),
        };
        let request = ApiRequest { method: method.to_owned(), url, headers, body };
        let response = self.transport.send(request).await?;
        let text = response.text();
        let ok = (200..300).contains(&response.status);
        let doc = match selfhost_json::parse(&text) {
            Ok(doc) => doc,
            // A failure status with a non-JSON body is still the API refusing;
            // hand the operator the body verbatim rather than a parse error.
            Err(_) if !ok => {
                return Err(ProviderError::Api { status: response.status, detail: text });
            }
            Err(error) => {
                return Err(ProviderError::Protocol(format!(
                    "Cloudflare answered HTTP {} with a body that is not JSON ({error}): {text}",
                    response.status
                )));
            }
        };
        let success = doc.get("success").and_then(Json::as_bool).unwrap_or(false);
        if ok && success {
            Ok(doc)
        } else {
            Err(ProviderError::Api {
                status: response.status,
                detail: envelope_errors(&doc).unwrap_or(text),
            })
        }
    }

    /// The id of the zone serving `domain`, via `GET /zones?name=` — the
    /// domain percent-encoded through the crate's one shared encoder, so a
    /// malformed name (`&`, `#`) cannot silently rewrite the query's meaning.
    async fn zone_id(&self, domain: &str) -> Result<String, ProviderError> {
        let url = format!("{API_BASE}/zones?name={}", crate::percent_encode(domain));
        let doc = self.call("GET", url, None).await?;
        doc.get("result")
            .and_then(Json::as_array)
            .and_then(<[Json]>::first)
            .and_then(|zone| zone.get("id"))
            .and_then(Json::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                // An empty result is a successful answer, so this is not an Api
                // error — but it still ends reconciliation with the one fact
                // the operator needs: this token cannot see this zone.
                ProviderError::Protocol(format!(
                    "Cloudflare lists no zone named {domain}; \
                     the API token may not be scoped to it"
                ))
            })
    }

    /// Every record in the zone with its Cloudflare id, following
    /// `result_info.total_pages` until the listing is complete — a zone one
    /// record past a page boundary must not silently lose its tail.
    async fn records_with_ids(
        &self,
        zone_id: &str,
        domain: &str,
    ) -> Result<Vec<(String, Record)>, ProviderError> {
        let mut listed = Vec::new();
        let mut page: u64 = 1;
        loop {
            let url =
                format!("{API_BASE}/zones/{zone_id}/dns_records?page={page}&per_page={PER_PAGE}");
            let doc = self.call("GET", url, None).await?;
            let entries = doc.get("result").and_then(Json::as_array).ok_or_else(|| {
                ProviderError::Protocol("the record listing has no result array".to_owned())
            })?;
            for entry in entries {
                listed.push(record_from_entry(entry, domain)?);
            }
            // A paginated endpoint that stops declaring its page count cannot
            // be trusted: defaulting to "one page" would silently truncate a
            // larger zone, and apply would then re-create its lost records as
            // duplicates beside the unseen originals.
            let total_pages = doc
                .get("result_info")
                .and_then(|info| info.get("total_pages"))
                .and_then(Json::as_u64)
                .ok_or_else(|| {
                    ProviderError::Protocol(
                        "the record listing has no result_info.total_pages; refusing to treat \
                         a possibly truncated listing as the whole zone"
                            .to_owned(),
                    )
                })?;
            if page >= total_pages {
                return Ok(listed);
            }
            page += 1;
        }
    }
}

impl<T: Transport + Sync> DnsProvider for Cloudflare<T> {
    async fn list(&self, domain: &str) -> Result<Vec<Record>, ProviderError> {
        let zone = self.zone_id(domain).await?;
        let listed = self.records_with_ids(&zone, domain).await?;
        Ok(listed.into_iter().map(|(_, record)| record).collect())
    }

    async fn apply(&self, domain: &str, records: &[Record]) -> Result<(), ProviderError> {
        let zone = self.zone_id(domain).await?;
        let mut listed = self.records_with_ids(&zone, domain).await?;
        // Diff with the crate's own engine rather than a private one: `records`
        // is the full final set, so records it does not claim come out in
        // `untouched` — and no request below is built from that bucket, which
        // is the first law, mechanically.
        let observed: Vec<Record> = listed.iter().map(|(_, record)| record.clone()).collect();
        let plan = plan::plan(&observed, records);
        for (stale, fresh) in &plan.update {
            let id = take_id(&mut listed, stale)?;
            let url = format!("{API_BASE}/zones/{zone}/dns_records/{id}");
            self.call("PUT", url, Some(entry_body(fresh, domain)?)).await?;
        }
        for stale in &plan.remove {
            let id = take_id(&mut listed, stale)?;
            let url = format!("{API_BASE}/zones/{zone}/dns_records/{id}");
            self.call("DELETE", url, None).await?;
        }
        for fresh in &plan.create {
            let url = format!("{API_BASE}/zones/{zone}/dns_records");
            self.call("POST", url, Some(entry_body(fresh, domain)?)).await?;
        }
        Ok(())
    }
}

/// The envelope's `errors` as one line of Cloudflare's own words
/// (`code: message; …`), or `None` when the document carries no errors —
/// the caller then falls back to the raw body, never to silence.
fn envelope_errors(doc: &Json) -> Option<String> {
    let errors = doc.get("errors").and_then(Json::as_array)?;
    if errors.is_empty() {
        return None;
    }
    let lines: Vec<String> = errors
        .iter()
        .map(|error| {
            let message = error.get("message").and_then(Json::as_str).unwrap_or_default();
            match error.get("code").and_then(Json::as_i64) {
                Some(code) => format!("{code}: {message}"),
                None => message.to_owned(),
            }
        })
        .collect();
    Some(lines.join("; "))
}

/// The Cloudflare id that goes with `record`, taken out of the listing pool.
///
/// The plan's stale records are clones of the listing, so equality finds the
/// original row; taking it out keeps two identical stale records from mapping
/// to the same id. A miss means the engine handed back a record the listing
/// never contained — a bug worth failing loudly on, not deleting blind.
fn take_id(listed: &mut Vec<(String, Record)>, record: &Record) -> Result<String, ProviderError> {
    let at = listed
        .iter()
        .position(|(_, have)| have == record)
        .ok_or_else(|| ProviderError::Protocol(format!("no listed record matches {record}")))?;
    Ok(listed.remove(at).0)
}

/// One listed record decoded into `(id, Record)`, translating every
/// Cloudflare convention back to the crate's neutral shape — see the module
/// doc for the inventory. A field the schema requires but the entry lacks is
/// a [`ProviderError::Protocol`]: guessing at a half-parsed record would make
/// the diff lie.
fn record_from_entry(entry: &Json, domain: &str) -> Result<(String, Record), ProviderError> {
    let text = |key: &str| {
        entry.get(key).and_then(Json::as_str).map(str::to_owned).ok_or_else(|| {
            ProviderError::Protocol(format!(
                "a listed record is missing {key:?}: {}",
                entry.to_text()
            ))
        })
    };
    let id = text("id")?;
    let kind = text("type")?.to_ascii_uppercase();
    let host = relative_host(&text("name")?, domain);
    let ttl = match entry.get("ttl").and_then(Json::as_u64) {
        None => None,
        Some(seconds) if seconds == u64::from(TTL_AUTOMATIC) => None,
        Some(seconds) => Some(u32::try_from(seconds).map_err(|_| {
            ProviderError::Protocol(format!("a listed record's ttl {seconds} exceeds u32"))
        })?),
    };
    let (rtype, value) = match kind.as_str() {
        "A" => (RecordType::A, text("content")?),
        "AAAA" => (RecordType::Aaaa, text("content")?),
        "CNAME" => (RecordType::Cname, text("content")?),
        "TXT" => (RecordType::Txt, unquote_txt(text("content")?)),
        "MX" => (RecordType::Mx { preference: number(entry, "priority")? }, text("content")?),
        "SRV" => {
            let data = entry.get("data").ok_or_else(|| {
                ProviderError::Protocol(format!("an SRV record has no data: {}", entry.to_text()))
            })?;
            let target = data.get("target").and_then(Json::as_str).ok_or_else(|| {
                ProviderError::Protocol(format!("an SRV record has no target: {}", entry.to_text()))
            })?;
            let rtype = RecordType::Srv {
                priority: number(data, "priority")?,
                weight: number(data, "weight")?,
                port: number(data, "port")?,
            };
            (rtype, target.to_owned())
        }
        "CAA" => {
            // tag/value/flags are required like every other schema'd field:
            // a half-parsed CAA ("0  ") would fake a diff and rewrite a
            // record based on an observation this code never actually made.
            let data = entry.get("data").ok_or_else(|| {
                ProviderError::Protocol(format!("a CAA record has no data: {}", entry.to_text()))
            })?;
            let text_field = |key: &str| {
                data.get(key).and_then(Json::as_str).ok_or_else(|| {
                    ProviderError::Protocol(format!(
                        "a CAA record's data is missing {key:?}: {}",
                        entry.to_text()
                    ))
                })
            };
            let tag = text_field("tag")?;
            let value = text_field("value")?;
            let flags = number(data, "flags")?;
            (RecordType::Caa, format!("{flags} {tag} {value}"))
        }
        other => (RecordType::Other(other.to_owned()), text("content")?),
    };
    Ok((id, Record { host, rtype, value, ttl }))
}

/// The create/update request body for `record`, in the shape Cloudflare's
/// endpoints require: `content` for simple types, top-level `priority` for
/// MX, a `data` object for SRV and CAA. `A`/`AAAA`/`CNAME` are pinned
/// `proxied: false` — reconciliation manages DNS, and the deployment's mail,
/// SSH, and ACME need the origin address answered, not Cloudflare's edge.
fn entry_body(record: &Record, domain: &str) -> Result<Json, ProviderError> {
    let mut fields: Vec<(&str, Json)> = vec![
        ("type", Json::string(record.rtype.kind())),
        ("name", Json::string(absolute_name(&record.host, domain))),
        ("ttl", Json::Number(f64::from(record.ttl.unwrap_or(TTL_AUTOMATIC)))),
    ];
    let content = || Json::String(record.value.clone());
    match &record.rtype {
        RecordType::A | RecordType::Aaaa | RecordType::Cname => {
            fields.push(("content", content()));
            fields.push(("proxied", Json::Bool(false)));
        }
        RecordType::Txt | RecordType::Other(_) => fields.push(("content", content())),
        RecordType::Mx { preference } => {
            fields.push(("content", content()));
            fields.push(("priority", Json::Number(f64::from(*preference))));
        }
        RecordType::Srv { priority, weight, port } => {
            // The service labels live in `name`; `data` carries only the
            // numbers and the target.
            fields.push((
                "data",
                Json::object([
                    ("priority", Json::Number(f64::from(*priority))),
                    ("weight", Json::Number(f64::from(*weight))),
                    ("port", Json::Number(f64::from(*port))),
                    ("target", content()),
                ]),
            ));
        }
        RecordType::Caa => {
            // The crate spells CAA as one "flags tag value" string; Cloudflare
            // wants the three fields apart. A value that does not split is a
            // malformed input worth refusing before it reaches the API.
            let mut parts = record.value.splitn(3, ' ');
            let (Some(flags), Some(tag), Some(value)) =
                (parts.next(), parts.next(), parts.next())
            else {
                return Err(ProviderError::Protocol(format!(
                    "CAA value {:?} is not \"flags tag value\"",
                    record.value
                )));
            };
            let flags: u8 = flags.parse().map_err(|_| {
                ProviderError::Protocol(format!("CAA flags {flags:?} is not a number"))
            })?;
            fields.push((
                "data",
                Json::object([
                    ("flags", Json::Number(f64::from(flags))),
                    ("tag", Json::string(tag)),
                    ("value", Json::string(value.trim_matches('"'))),
                ]),
            ));
        }
    }
    Ok(Json::object(fields))
}

/// A required `u16` off a JSON object, or the [`ProviderError::Protocol`]
/// that names what was missing — MX preference and SRV numbers must never be
/// silently defaulted, or the diff would invent a change.
fn number(entry: &Json, key: &str) -> Result<u16, ProviderError> {
    entry
        .get(key)
        .and_then(Json::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .ok_or_else(|| {
            ProviderError::Protocol(format!(
                "a listed record is missing numeric {key:?}: {}",
                entry.to_text()
            ))
        })
}

/// The crate's relative host as the absolute name Cloudflare expects:
/// `"@"` is the domain, anything else — `"*"` and service labels included —
/// is a prefix of it.
fn absolute_name(host: &str, domain: &str) -> String {
    if host == "@" {
        domain.to_owned()
    } else {
        format!("{host}.{domain}")
    }
}

/// TXT content with Cloudflare's RFC 1035 quoting removed.
///
/// The API returns TXT content as one or more quoted character-strings —
/// `"\"v=spf1 mx -all\""` for short values, `"\"chunk1\" \"chunk2\""` once
/// the text exceeds a 255-octet chunk (every RSA-2048 DKIM key does) — but
/// accepts unquoted text on write. Chunks are unquoted, unescaped, and
/// concatenated, so a long DKIM record compares equal to its desired value
/// instead of faking an update on every sync. Content that does not parse as
/// quoted chunks passes through verbatim rather than being half-unquoted.
fn unquote_txt(content: String) -> String {
    match txt_chunks(&content) {
        Some(joined) => joined,
        None => content,
    }
}

/// `text` parsed as whitespace-separated RFC 1035 quoted character-strings,
/// concatenated with `\"`/`\\` escapes resolved — or `None` when the text is
/// not exactly that shape.
fn txt_chunks(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text.trim();
    if !rest.starts_with('"') {
        return None;
    }
    while !rest.is_empty() {
        rest = rest.strip_prefix('"')?;
        let mut close = None;
        let mut escaped = false;
        for (at, ch) in rest.char_indices() {
            match (escaped, ch) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => {
                    close = Some(at);
                    break;
                }
                _ => {}
            }
        }
        let close = close?;
        let mut pending_escape = false;
        for ch in rest[..close].chars() {
            if pending_escape || ch != '\\' {
                out.push(ch);
                pending_escape = false;
            } else {
                pending_escape = true;
            }
        }
        rest = rest[close + 1..].trim_start();
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use crate::testing::{block_on, response, Canned};

    use super::*;

    /// The canned script as `(status, body)` pairs — the shape every scenario
    /// below reads most naturally in.
    fn canned<const N: usize>(replies: [(u16, &str); N]) -> Canned {
        Canned::scripted(replies.map(|(status, body)| response(status, body)))
    }

    /// A successful `GET /zones?name=` answer naming zone id `zone9`.
    const ZONE_REPLY: &str =
        r#"{"success":true,"errors":[],"result":[{"id":"zone9","name":"example.com"}]}"#;

    /// A successful mutation answer; the provider only checks the envelope.
    const MUTATED_REPLY: &str = r#"{"success":true,"errors":[],"result":{"id":"row"}}"#;

    fn provider(canned: Canned) -> Cloudflare<Canned> {
        Cloudflare::new(canned, "cf-token")
    }

    fn a(host: &str, value: &str) -> Record {
        Record { host: host.into(), rtype: RecordType::A, value: value.into(), ttl: None }
    }

    #[test]
    fn list_translates_every_cloudflare_convention_back_to_the_crate_shape() {
        // One page holding one record of each schema'd flavor. Any convention
        // left untranslated here would fake a diff on every reconcile.
        let listing = r#"{"success":true,"errors":[],"result":[
            {"id":"a1","type":"A","name":"example.com","content":"1.2.3.4","ttl":1,"proxied":false},
            {"id":"a2","type":"A","name":"*.example.com","content":"1.2.3.4","ttl":300},
            {"id":"t1","type":"TXT","name":"example.com","content":"\"v=spf1 mx -all\"","ttl":3600},
            {"id":"m1","type":"MX","name":"example.com","content":"mail.example.com","priority":10,"ttl":1},
            {"id":"s1","type":"SRV","name":"_imaps._tcp.example.com","content":"1 993 imap.example.com",
             "data":{"priority":0,"weight":1,"port":993,"target":"imap.example.com"},"ttl":1},
            {"id":"c1","type":"CAA","name":"example.com","content":"0 issue \"letsencrypt.org\"",
             "data":{"flags":0,"tag":"issue","value":"letsencrypt.org"},"ttl":1}
        ],"result_info":{"page":1,"total_pages":1}}"#;
        let canned = canned([(200, ZONE_REPLY), (200, listing)]);
        let provider = provider(canned);

        let records = block_on(provider.list("example.com")).expect("the listing parses");

        assert_eq!(
            records,
            vec![
                a("@", "1.2.3.4"),
                Record { ttl: Some(300), ..a("*", "1.2.3.4") },
                Record {
                    host: "@".into(),
                    rtype: RecordType::Txt,
                    value: "v=spf1 mx -all".into(),
                    ttl: Some(3600),
                },
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
                Record {
                    host: "@".into(),
                    rtype: RecordType::Caa,
                    value: "0 issue letsencrypt.org".into(),
                    ttl: None,
                },
            ]
        );

        let requests = provider.transport.requests();
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[0].url, format!("{API_BASE}/zones?name=example.com"));
        assert!(
            requests[0]
                .headers
                .contains(&("Authorization".to_owned(), "Bearer cf-token".to_owned())),
            "every request must carry the bearer token: {:?}",
            requests[0].headers
        );
        assert_eq!(
            requests[1].url,
            format!("{API_BASE}/zones/zone9/dns_records?page=1&per_page=100")
        );
    }

    #[test]
    fn list_follows_pagination_to_the_last_page() {
        // A zone one record past a page boundary must not lose its tail — a
        // truncated listing would read as records to delete.
        let page = |id: &str, name: &str, total: u32| {
            format!(
                r#"{{"success":true,"errors":[],"result":[
                    {{"id":"{id}","type":"A","name":"{name}","content":"1.2.3.4","ttl":1}}
                ],"result_info":{{"total_pages":{total}}}}}"#
            )
        };
        let first = page("a1", "example.com", 2);
        let second = page("a2", "www.example.com", 2);
        let canned =
            canned([(200, ZONE_REPLY), (200, first.as_str()), (200, second.as_str())]);
        let provider = provider(canned);

        let records = block_on(provider.list("example.com")).expect("both pages parse");

        assert_eq!(records, vec![a("@", "1.2.3.4"), a("www", "1.2.3.4")]);
        let requests = provider.transport.requests();
        assert_eq!(requests.len(), 3, "zone lookup plus one request per page");
        assert!(requests[1].url.ends_with("page=1&per_page=100"), "{}", requests[1].url);
        assert!(requests[2].url.ends_with("page=2&per_page=100"), "{}", requests[2].url);
    }

    /// A zone holding a matching A at `www`, a stale apex A, a good and a
    /// stale MX, and a foreign verification TXT this deployment never claimed.
    const DIFF_LISTING: &str = r#"{"success":true,"errors":[],"result":[
        {"id":"keep1","type":"A","name":"www.example.com","content":"1.2.3.4","ttl":1},
        {"id":"old1","type":"A","name":"example.com","content":"9.9.9.9","ttl":1},
        {"id":"mx1","type":"MX","name":"example.com","content":"mail.example.com","priority":10,"ttl":1},
        {"id":"mx2","type":"MX","name":"example.com","content":"old.example.net","priority":20,"ttl":1},
        {"id":"foreign","type":"TXT","name":"zb123.example.com","content":"\"verification=abc\"","ttl":1}
    ],"result_info":{"total_pages":1}}"#;

    /// The full final set for [`DIFF_LISTING`]'s zone: the foreign TXT
    /// (carried by `Plan::final_set`), the records already right, the apex A
    /// corrected, and a DMARC TXT not yet published.
    fn final_set() -> Vec<Record> {
        vec![
            Record {
                host: "zb123".into(),
                rtype: RecordType::Txt,
                value: "verification=abc".into(),
                ttl: None,
            },
            a("www", "1.2.3.4"),
            a("@", "1.2.3.4"),
            Record {
                host: "@".into(),
                rtype: RecordType::Mx { preference: 10 },
                value: "mail.example.com".into(),
                ttl: None,
            },
            Record {
                host: "_dmarc".into(),
                rtype: RecordType::Txt,
                value: "v=DMARC1; p=reject".into(),
                ttl: None,
            },
        ]
    }

    #[test]
    fn apply_issues_only_the_creates_updates_and_deletes_that_close_the_gap() {
        let canned = canned([
            (200, ZONE_REPLY),
            (200, DIFF_LISTING),
            (200, MUTATED_REPLY), // PUT: apex A corrected
            (200, MUTATED_REPLY), // DELETE: stale second MX
            (200, MUTATED_REPLY), // POST: DMARC TXT created
        ]);
        let provider = provider(canned);

        block_on(provider.apply("example.com", &final_set())).expect("the apply succeeds");

        let requests = provider.transport.requests();
        let mutations: Vec<(&str, &str)> = requests[2..]
            .iter()
            .map(|request| (request.method.as_str(), request.url.as_str()))
            .collect();
        assert_eq!(
            mutations,
            vec![
                ("PUT", "https://api.cloudflare.com/client/v4/zones/zone9/dns_records/old1"),
                ("DELETE", "https://api.cloudflare.com/client/v4/zones/zone9/dns_records/mx2"),
                ("POST", "https://api.cloudflare.com/client/v4/zones/zone9/dns_records"),
            ]
        );

        let put_body = selfhost_json::parse(&String::from_utf8(requests[2].body.clone()).unwrap())
            .expect("the PUT body is JSON");
        assert_eq!(
            put_body,
            Json::object([
                ("type", Json::string("A")),
                ("name", Json::string("example.com")),
                ("ttl", Json::Number(1.0)),
                ("content", Json::string("1.2.3.4")),
                ("proxied", Json::Bool(false)),
            ])
        );

        let post_body = selfhost_json::parse(&String::from_utf8(requests[4].body.clone()).unwrap())
            .expect("the POST body is JSON");
        assert_eq!(post_body.get("name").and_then(Json::as_str), Some("_dmarc.example.com"));
        assert_eq!(
            post_body.get("content").and_then(Json::as_str),
            Some("v=DMARC1; p=reject"),
            "TXT content is sent unquoted; the API quotes it itself"
        );
    }

    #[test]
    fn apply_never_touches_a_record_outside_the_final_set() {
        // The first law at the wire: had the foreign TXT been dropped from the
        // final set (a caller bug) or mis-diffed here, a DELETE for id
        // "foreign" would appear. It must not, ever.
        let canned = canned([
            (200, ZONE_REPLY),
            (200, DIFF_LISTING),
            (200, MUTATED_REPLY),
            (200, MUTATED_REPLY),
            (200, MUTATED_REPLY),
        ]);
        let provider = provider(canned);

        block_on(provider.apply("example.com", &final_set())).expect("the apply succeeds");

        for request in provider.transport.requests() {
            assert!(
                !request.url.ends_with("/foreign") && !request.url.ends_with("/keep1"),
                "a record already right or never claimed must not be touched: {} {}",
                request.method,
                request.url
            );
        }
    }

    #[test]
    fn apply_on_a_settled_zone_sends_no_mutations() {
        let listing = r#"{"success":true,"errors":[],"result":[
            {"id":"a1","type":"A","name":"example.com","content":"1.2.3.4","ttl":1}
        ],"result_info":{"total_pages":1}}"#;
        let canned = canned([(200, ZONE_REPLY), (200, listing)]);
        let provider = provider(canned);

        block_on(provider.apply("example.com", &[a("@", "1.2.3.4")])).expect("nothing to do");

        assert_eq!(
            provider.transport.requests().len(),
            2,
            "a settled zone costs exactly the zone lookup and the listing"
        );
    }

    #[test]
    fn creating_an_srv_sends_the_data_object_cloudflare_requires() {
        let empty = r#"{"success":true,"errors":[],"result":[],"result_info":{"total_pages":1}}"#;
        let canned = canned([(200, ZONE_REPLY), (200, empty), (200, MUTATED_REPLY)]);
        let provider = provider(canned);
        let srv = Record {
            host: "_imaps._tcp".into(),
            rtype: RecordType::Srv { priority: 0, weight: 1, port: 993 },
            value: "imap.example.com".into(),
            ttl: None,
        };

        block_on(provider.apply("example.com", &[srv])).expect("the create succeeds");

        let requests = provider.transport.requests();
        let body = selfhost_json::parse(&String::from_utf8(requests[2].body.clone()).unwrap())
            .expect("the SRV body is JSON");
        assert_eq!(
            body,
            Json::object([
                ("type", Json::string("SRV")),
                ("name", Json::string("_imaps._tcp.example.com")),
                ("ttl", Json::Number(1.0)),
                (
                    "data",
                    Json::object([
                        ("priority", Json::Number(0.0)),
                        ("weight", Json::Number(1.0)),
                        ("port", Json::Number(993.0)),
                        ("target", Json::string("imap.example.com")),
                    ])
                ),
            ]),
            "the service labels ride the name; data carries the numbers and target"
        );
    }

    #[test]
    fn a_chunked_txt_listing_unquotes_and_concatenates() {
        // TXT content past 255 octets — every RSA-2048 DKIM key — comes back
        // as multiple quoted chunks; treating the quoting as a difference
        // would plan a rewrite of an already-correct record on every sync.
        let listing = r#"{"success":true,"errors":[],"result":[
            {"id":"t9","type":"TXT","name":"s1._domainkey.example.com",
             "content":"\"v=DKIM1; k=rsa; p=AAAA\" \"BBBB\"","ttl":1}
        ],"result_info":{"total_pages":1}}"#;
        let provider = provider(canned([(200, ZONE_REPLY), (200, listing)]));

        let records = block_on(provider.list("example.com")).expect("the listing parses");

        assert_eq!(records[0].value, "v=DKIM1; k=rsa; p=AAAABBBB");
        assert_eq!(records[0].host, "s1._domainkey");
    }

    #[test]
    fn txt_chunks_handles_escapes_and_refuses_what_is_not_chunked() {
        assert_eq!(txt_chunks(r#""one" "two""#).as_deref(), Some("onetwo"));
        assert_eq!(txt_chunks(r#""say \"hi\" \\ back""#).as_deref(), Some(r#"say "hi" \ back"#));
        assert_eq!(txt_chunks("bare text"), None, "unquoted content is not chunked");
        assert_eq!(txt_chunks(r#""unterminated"#), None);
        assert_eq!(txt_chunks(r#""a" trailing"#), None, "junk between chunks is malformed");
    }

    #[test]
    fn a_listing_without_result_info_is_refused_not_truncated() {
        // Trusting a single page when the page count is missing would later
        // re-create the unseen records as duplicates beside their originals.
        let listing = r#"{"success":true,"errors":[],"result":[
            {"id":"a1","type":"A","name":"example.com","content":"1.2.3.4","ttl":1}
        ]}"#;
        let provider = provider(canned([(200, ZONE_REPLY), (200, listing)]));

        let error = block_on(provider.list("example.com")).expect_err("no page count, no trust");

        assert!(
            matches!(&error, ProviderError::Protocol(detail) if detail.contains("total_pages")),
            "got: {error}"
        );
    }

    #[test]
    fn a_caa_missing_its_data_fields_is_a_protocol_error() {
        // A half-parsed CAA ("0  ") would fake a diff and PUT a rewrite based
        // on an observation never actually made.
        let listing = r#"{"success":true,"errors":[],"result":[
            {"id":"c1","type":"CAA","name":"example.com","content":"0 issue x",
             "data":{"flags":0,"tag":"issue"},"ttl":1}
        ],"result_info":{"total_pages":1}}"#;
        let provider = provider(canned([(200, ZONE_REPLY), (200, listing)]));

        let error = block_on(provider.list("example.com")).expect_err("value is required");

        assert!(
            matches!(&error, ProviderError::Protocol(detail) if detail.contains("value")),
            "got: {error}"
        );
    }

    #[test]
    fn an_error_envelope_surfaces_cloudflares_own_words() {
        let refusal = r#"{"success":false,"errors":[
            {"code":1003,"message":"Invalid or missing zone id."},
            {"code":9109,"message":"Invalid access token"}
        ],"messages":[],"result":null}"#;
        let canned = canned([(400, refusal)]);
        let provider = provider(canned);

        let error = block_on(provider.list("example.com")).expect_err("the API refused");

        match error {
            ProviderError::Api { status, detail } => {
                assert_eq!(status, 400);
                assert_eq!(detail, "1003: Invalid or missing zone id.; 9109: Invalid access token");
            }
            other => panic!("expected an Api error, got {other}"),
        }
    }

    #[test]
    fn a_zone_the_token_cannot_see_is_reported_by_name() {
        // Cloudflare answers an empty success for an unknown or unscoped zone;
        // the operator must learn which domain went unfound, not get an index
        // panic or a silent no-op.
        let empty = r#"{"success":true,"errors":[],"result":[]}"#;
        let canned = canned([(200, empty)]);
        let provider = provider(canned);

        let error = block_on(provider.list("example.com")).expect_err("no zone to list");

        match error {
            ProviderError::Protocol(detail) => {
                assert!(detail.contains("example.com"), "{detail}");
            }
            other => panic!("expected a Protocol error, got {other}"),
        }
    }

    #[test]
    fn a_success_status_with_a_non_json_body_is_a_protocol_error() {
        // A proxy page or HTML error served with a 200 must not be mistaken
        // for an empty zone.
        let canned = canned([(200, "<html>maintenance</html>")]);
        let provider = provider(canned);

        let error = block_on(provider.list("example.com")).expect_err("not a JSON envelope");

        assert!(
            matches!(error, ProviderError::Protocol(_)),
            "expected a Protocol error, got {error}"
        );
    }
}
