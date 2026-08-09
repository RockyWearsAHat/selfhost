//! Namecheap DNS provider — the registrar's XML API, spoken over an injected
//! [`Transport`].
//!
//! Namecheap's API is one HTTPS endpoint (`https://api.namecheap.com/xml.response`)
//! that multiplexes commands by a `Command` parameter. Every call authenticates
//! with four query/form parameters — `ApiUser`, `ApiKey`, `UserName`,
//! `ClientIp` (the caller's whitelisted public address) — and names the domain
//! as an `SLD`/`TLD` pair (`example.co.uk` → `SLD=example`, `TLD=co.uk`).
//! Responses are XML inside an `<ApiResponse Status="OK|ERROR">` envelope;
//! failures arrive as `<Error Number="…">its own words</Error>` elements,
//! which this module surfaces verbatim.
//!
//! Two commands cover [`DnsProvider`]:
//!
//! - `namecheap.domains.dns.getHosts` (GET) lists the zone as `<host …/>`
//!   elements carrying `Name`, `Type`, `Address`, `MXPref`, `TTL`. Quirks the
//!   parser absorbs: the element's case varies (`<host>` in live responses,
//!   `<Host>` in the documentation), and `MXPref` appears on *every* row, so
//!   it is only meaningful when `Type="MX"`.
//! - `namecheap.domains.dns.setHosts` (POST, form-encoded — Namecheap
//!   recommends POST beyond ten records) **replaces the domain's entire record
//!   set**: any record not in the call is deleted. `apply` therefore pushes
//!   the full final set in one call, and — because one bad push can erase an
//!   operator's zone — it refuses to write at all unless a fresh `getHosts`
//!   read just succeeded. That fresh read is not only a health check: any
//!   record it holds at a `(host, type)` the pushed set does not claim (one
//!   the operator created between the caller's plan and this push) is merged
//!   into the push instead of being silently erased. Fields are numbered per
//!   record (`HostName1`, `RecordType1`, `Address1`, `MXPref1`, `TTL1`, …).
//!   `EmailType` is zone state `setHosts` replaces exactly like host records:
//!   the value the fresh read observed (`FWD`, `MXE`, `OX`, `GMAIL`, …) is
//!   echoed back so a push cannot silently switch off the operator's mail
//!   forwarding, and it is overridden to `MX` only when the pushed set itself
//!   carries MX records — the one case where the config claims mail routing.
//!
//! # The SRV gap
//!
//! Namecheap's API **cannot write SRV records**: `setHosts` documents its
//! `RecordType` vocabulary as `A, AAAA, ALIAS, CAA, CNAME, MX, MXE, NS, TXT,
//! URL, URL301, FRAME` — no SRV — and Namecheap's own Terraform provider
//! states the restriction outright. Combined with replace-everything
//! semantics this is dangerous: a push that omits an SRV the operator created
//! by hand would erase it, and no push can recreate one. So `apply` refuses
//! whenever SRV records appear in the set to write *or* in the zone it just
//! read, naming them; [`Namecheap::unwritable`] lets a caller discover the
//! affected records up front and drop them from the desired set. The refusal
//! on *observed* SRV rows is deliberate and total: a zone holding a hand-made
//! SRV can never be safely rewritten by this API, so callers must warn the
//! operator **not** to add SRV records in Namecheap's panel for a domain this
//! tool manages — doing so blocks every future apply. An SRV row `getHosts`
//! does return is carried as [`RecordType::Other`]`("SRV")` with its
//! `Address` verbatim — the API documents no SRV field layout, and guessing
//! one apart could corrupt a record this crate exists to protect.
//!
//! Note `selfhost_config::NamecheapDdns` is this registrar's *Dynamic DNS*
//! feature — a separate per-domain password updating one existing record; the
//! credentials here are the account-level API key and are not interchangeable
//! with it.

use crate::plan;
use crate::{ApiRequest, ApiResponse, DnsProvider, ProviderError, Record, RecordType, Transport};

/// The one endpoint Namecheap's whole XML API lives behind.
const ENDPOINT: &str = "https://api.namecheap.com/xml.response";

/// The account-level credentials every Namecheap API call must carry.
///
/// All four come from the account's API settings page; `client_ip` is the
/// public address the account has whitelisted — Namecheap rejects calls from
/// anywhere else, so it is part of the credential, not something the
/// transport can discover.
#[derive(Debug, Clone)]
pub struct Credentials {
    /// The API username (`ApiUser`) — normally the account name.
    pub api_user: String,
    /// The API key (`ApiKey`) from the account's API settings.
    pub api_key: String,
    /// The acting account (`UserName`) — same as `api_user` unless acting on
    /// behalf of a sub-account.
    pub user_name: String,
    /// The whitelisted public IPv4 address (`ClientIp`) these calls originate
    /// from, as dotted text.
    pub client_ip: String,
}

/// The Namecheap registrar, generic over the [`Transport`] that carries its
/// HTTPS exchanges so every protocol path is testable against canned XML.
pub struct Namecheap<T: Transport> {
    transport: T,
    credentials: Credentials,
}

impl<T: Transport> Namecheap<T> {
    /// A provider speaking through `transport` as `credentials`.
    pub fn new(transport: T, credentials: Credentials) -> Self {
        Self { transport, credentials }
    }

    /// The records in `records` that Namecheap's API cannot express — today,
    /// exactly the SRV records (see the module docs for why).
    ///
    /// [`DnsProvider::apply`] refuses outright when any are present; a caller
    /// that would rather push everything else can subtract these first. Warn
    /// the operator that the subtracted records simply go unpublished — they
    /// must **not** be added by hand in Namecheap's panel, because `apply`
    /// also refuses whenever the zone it reads holds SRV rows it could never
    /// restate, so a hand-made SRV blocks every future push.
    pub fn unwritable(records: &[Record]) -> Vec<&Record> {
        records.iter().filter(|record| record.rtype.kind() == "SRV").collect()
    }

    /// The auth and command parameters every call starts from, in a fixed
    /// order so requests are byte-for-byte reproducible in tests.
    fn base_params(&self, command: &str, sld: &str, tld: &str) -> Vec<(String, String)> {
        vec![
            ("ApiUser".into(), self.credentials.api_user.clone()),
            ("ApiKey".into(), self.credentials.api_key.clone()),
            ("UserName".into(), self.credentials.user_name.clone()),
            ("ClientIp".into(), self.credentials.client_ip.clone()),
            ("Command".into(), command.into()),
            ("SLD".into(), sld.into()),
            ("TLD".into(), tld.into()),
        ]
    }

    /// One `getHosts` read: the zone's records plus its `EmailType` — the
    /// mail-routing mode (`MX`, `FWD`, `MXE`, …) that `setHosts` replaces
    /// right alongside the records, so a push must know it to preserve it.
    async fn fetch_hosts(&self, domain: &str) -> Result<GetHosts, ProviderError> {
        let (sld, tld) = split_domain(domain)?;
        let params = self.base_params("namecheap.domains.dns.getHosts", sld, tld);
        let request = ApiRequest {
            method: "GET".into(),
            url: format!("{ENDPOINT}?{}", form_encode(&params)),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let body = interpreted(self.transport.send(request).await?)?;
        parse_hosts(&body)
    }
}

impl<T: Transport + Sync> DnsProvider for Namecheap<T> {
    async fn list(&self, domain: &str) -> Result<Vec<Record>, ProviderError> {
        Ok(self.fetch_hosts(domain).await?.records)
    }

    async fn apply(&self, domain: &str, records: &[Record]) -> Result<(), ProviderError> {
        if records.is_empty() {
            return Err(ProviderError::Protocol(
                "refusing to push an empty record set: setHosts replaces the domain's entire \
                 zone, so this would erase every record it holds"
                    .into(),
            ));
        }

        // The read is the safety interlock: it proves auth, the SLD/TLD
        // split, and that the API is answering sanely before anything is
        // overwritten; it reveals SRV records a push would destroy; and its
        // contents guard against the write below erasing what the registrar
        // gained since the caller planned.
        let zone = self.fetch_hosts(domain).await?;

        let blocked: Vec<String> = Self::unwritable(records)
            .into_iter()
            .chain(Self::unwritable(&zone.records))
            .map(|record| record.to_string())
            .collect();
        if !blocked.is_empty() {
            // No ProviderError variant models a capability gap; Protocol is
            // the "the API's contract cannot carry this" bucket.
            return Err(ProviderError::Protocol(format!(
                "Namecheap's setHosts API cannot write SRV records, and it replaces the whole \
                 zone per call — pushing would erase or fail to create: {}. Remove hand-made \
                 SRV records from the zone (this API can never restate them) before syncing",
                blocked.join("; ")
            )));
        }

        // The caller's final set was built from an earlier listing; anything
        // the fresh read holds at a claim the set does not state — a record
        // the operator created in the meantime — rides along in the push
        // instead of being erased by the whole-zone replace.
        let concurrent = plan::plan(&zone.records, records).untouched;
        let push: Vec<&Record> = records.iter().chain(&concurrent).collect();

        let (sld, tld) = split_domain(domain)?;
        let mut params = self.base_params("namecheap.domains.dns.setHosts", sld, tld);
        for (index, record) in push.iter().enumerate() {
            push_record_params(&mut params, index, record);
        }
        // EmailType is zone state the push replaces: claim MX routing only
        // when the set itself carries MX records; otherwise echo the mode the
        // fresh read observed, so a site-only sync cannot silently destroy
        // the operator's Namecheap mail forwarding (FWD/MXE/OX/GMAIL).
        let email_type = if push.iter().any(|record| record.rtype.kind() == "MX") {
            Some("MX".to_owned())
        } else {
            zone.email_type
        };
        if let Some(mode) = email_type {
            params.push(("EmailType".into(), mode));
        }

        let request = ApiRequest {
            method: "POST".into(),
            url: ENDPOINT.into(),
            headers: vec![("Content-Type".into(), "application/x-www-form-urlencoded".into())],
            body: form_encode(&params).into_bytes(),
        };
        let body = interpreted(self.transport.send(request).await?)?;
        confirm_set_hosts(&body)
    }
}

/// What one `getHosts` read established: the records, and the zone's
/// `EmailType` when the result element carried one.
struct GetHosts {
    records: Vec<Record>,
    email_type: Option<String>,
}

/// `domain` as Namecheap's `(SLD, TLD)` pair: the first label, then the rest
/// (`example.co.uk` → `("example", "co.uk")`, matching how Namecheap treats
/// multi-label public suffixes).
fn split_domain(domain: &str) -> Result<(&str, &str), ProviderError> {
    match domain.split_once('.') {
        Some((sld, tld)) if !sld.is_empty() && !tld.is_empty() => Ok((sld, tld)),
        // Protocol, not Transport: the network is fine — this input cannot be
        // expressed in the API's addressing scheme (Cloudflare reports its
        // cannot-address case the same way).
        _ => Err(ProviderError::Protocol(format!(
            "cannot address {domain:?} at Namecheap: its API names domains as an SLD.TLD pair, \
             and this name does not split into one"
        ))),
    }
}

/// Appends the numbered `setHosts` fields for one record. Parameters are
/// 1-based (`HostName1`…); `MXPref` only accompanies MX records, and an
/// absent TTL is left to Namecheap's default (1800) by omitting the field.
fn push_record_params(params: &mut Vec<(String, String)>, index: usize, record: &Record) {
    let n = index + 1;
    params.push((format!("HostName{n}"), record.host.clone()));
    params.push((format!("RecordType{n}"), record.rtype.kind()));
    let address = match record.rtype {
        RecordType::Caa => caa_to_api(&record.value),
        _ => record.value.clone(),
    };
    params.push((format!("Address{n}"), address));
    if let RecordType::Mx { preference } = record.rtype {
        params.push((format!("MXPref{n}"), preference.to_string()));
    }
    if let Some(ttl) = record.ttl {
        params.push((format!("TTL{n}"), ttl.to_string()));
    }
}

/// A CAA value in Namecheap's spelling: the data field quoted, as its API
/// examples show (`0 issue "letsencrypt.org"`). Anything that does not split
/// into `flag tag data` passes through verbatim rather than being guessed at.
fn caa_to_api(value: &str) -> String {
    match caa_parts(value) {
        Some((flag, tag, data)) if !data.starts_with('"') => format!("{flag} {tag} \"{data}\""),
        _ => value.to_string(),
    }
}

/// A CAA `Address` from Namecheap in the engine's spelling: quotes stripped
/// from the data field, so an observed record compares equal to the desired
/// one instead of faking a permanent diff. Inverse of [`caa_to_api`], so
/// untouched CAA records round-trip losslessly.
fn caa_from_api(address: &str) -> String {
    match caa_parts(address) {
        Some((flag, tag, data))
            if data.len() >= 2 && data.starts_with('"') && data.ends_with('"') =>
        {
            format!("{flag} {tag} {}", &data[1..data.len() - 1])
        }
        _ => address.to_string(),
    }
}

/// A CAA value's `(flag, tag, data)` fields, when it has exactly that shape.
fn caa_parts(text: &str) -> Option<(&str, &str, &str)> {
    let mut fields = text.splitn(3, ' ');
    match (fields.next(), fields.next(), fields.next()) {
        (Some(flag), Some(tag), Some(data)) if !data.is_empty() => Some((flag, tag, data)),
        _ => None,
    }
}

/// The response body once the exchange itself is judged: a non-200 status or
/// a `Status="ERROR"` envelope becomes [`ProviderError::Api`] carrying the
/// API's own words, and a body without the documented envelope — or without
/// its **closing** tag — is a [`ProviderError::Protocol`]. The closing-tag
/// demand is the truncation defence: `Status="OK"` sits at the top of the
/// document, so a body cut off mid-transfer between `<host/>` rows would
/// otherwise parse as a shorter zone and the next push would erase the tail.
/// Only a complete `Status="OK"` body comes back.
fn interpreted(response: ApiResponse) -> Result<String, ProviderError> {
    if response.status != 200 {
        return Err(ProviderError::Api { status: response.status, detail: response.text() });
    }
    let body = response.text();
    let envelope = first_tag(&body, "ApiResponse")?.ok_or_else(|| {
        ProviderError::Protocol(format!("no <ApiResponse> envelope in the response: {body}"))
    })?;
    if !body.to_ascii_lowercase().contains("</apiresponse") {
        return Err(ProviderError::Protocol(format!(
            "the response never closes its <ApiResponse> envelope — a truncated body must not \
             be trusted as a complete zone: {body}"
        )));
    }
    let status = attr(envelope, "Status")?.ok_or_else(|| {
        ProviderError::Protocol(format!("the <ApiResponse> envelope has no Status: {body}"))
    })?;
    if status.eq_ignore_ascii_case("ok") {
        return Ok(body);
    }
    let errors = error_lines(&body)?;
    let detail = if errors.is_empty() { body } else { errors.join("; ") };
    Err(ProviderError::Api { status: response.status, detail })
}

/// A `getHosts` body as [`GetHosts`], or an error if the body is not the
/// documented shape. A row missing a required attribute fails the whole
/// listing — silently dropping it would later erase the record, since
/// `setHosts` deletes whatever the push omits. The result element's
/// `EmailType` rides along so `apply` can echo the zone's mail-routing mode.
fn parse_hosts(body: &str) -> Result<GetHosts, ProviderError> {
    let result = first_tag(body, "DomainDNSGetHostsResult")?.ok_or_else(|| {
        ProviderError::Protocol(format!(
            "getHosts answered OK without a DomainDNSGetHostsResult: {body}"
        ))
    })?;
    let email_type = attr(result, "EmailType")?;
    let records = tags(body, "host")?.into_iter().map(record_from_host).collect::<Result<_, _>>()?;
    Ok(GetHosts { records, email_type })
}

/// One `<host …/>` element as a [`Record`], translating Namecheap's
/// conventions at the edge: `MXPref` read only for MX rows (it is emitted on
/// every row), CAA quotes stripped, and SRV rows carried verbatim as
/// [`RecordType::Other`] because the API documents no SRV field layout.
fn record_from_host(tag: &str) -> Result<Record, ProviderError> {
    let required = |name: &str| {
        attr(tag, name)?.ok_or_else(|| {
            ProviderError::Protocol(format!("a host record without {name} in: <{tag}>"))
        })
    };
    let host = required("Name")?;
    let kind = required("Type")?.to_ascii_uppercase();
    let address = required("Address")?;
    let ttl = match attr(tag, "TTL")? {
        Some(text) => Some(text.parse().map_err(|_| {
            ProviderError::Protocol(format!("unreadable TTL {text:?} on a host record: <{tag}>"))
        })?),
        None => None,
    };
    let (rtype, value) = match kind.as_str() {
        "A" => (RecordType::A, address),
        "AAAA" => (RecordType::Aaaa, address),
        "CNAME" => (RecordType::Cname, address),
        "TXT" => (RecordType::Txt, address),
        "CAA" => (RecordType::Caa, caa_from_api(&address)),
        "MX" => {
            let text = required("MXPref")?;
            let preference = text.parse().map_err(|_| {
                ProviderError::Protocol(format!("unreadable MXPref {text:?} on an MX record"))
            })?;
            (RecordType::Mx { preference }, address)
        }
        other => (RecordType::Other(other.to_string()), address),
    };
    Ok(Record { host, rtype, value, ttl })
}

/// Confirms a `setHosts` body reported success: Namecheap can answer
/// `Status="OK"` while `DomainDNSSetHostsResult` says `IsSuccess="false"`,
/// and treating that as done would leave the operator believing records were
/// written that were not.
fn confirm_set_hosts(body: &str) -> Result<(), ProviderError> {
    let result = first_tag(body, "DomainDNSSetHostsResult")?.ok_or_else(|| {
        ProviderError::Protocol(format!(
            "setHosts answered OK without a DomainDNSSetHostsResult: {body}"
        ))
    })?;
    match attr(result, "IsSuccess")? {
        Some(flag) if flag.eq_ignore_ascii_case("true") => Ok(()),
        _ => Err(ProviderError::Protocol(format!(
            "setHosts did not confirm success (IsSuccess missing or false): {body}"
        ))),
    }
}

// --- Minimal XML extraction -------------------------------------------------
//
// Namecheap's responses are flat, attribute-carrying XML; these helpers pull
// exactly what the protocol needs and error on anything malformed — a parse
// that guessed would sooner or later feed `setHosts` a wrong zone.

/// Every opening `<name …` tag's attribute text (exclusive of the closing
/// `>`), matched ASCII-case-insensitively — live responses spell `<host>`
/// where the documentation spells `<Host>`. An unterminated tag is an error.
fn tags<'x>(xml: &'x str, name: &str) -> Result<Vec<&'x str>, ProviderError> {
    let lower = xml.to_ascii_lowercase();
    let needle = format!("<{}", name.to_ascii_lowercase());
    let mut spans = Vec::new();
    let mut from = 0;
    while let Some(found) = lower[from..].find(&needle) {
        let start = from + found;
        let after = start + needle.len();
        // A name boundary, so `<host` never matches inside `<hostmaster`.
        let at_boundary = matches!(
            lower.as_bytes().get(after),
            Some(byte) if byte.is_ascii_whitespace() || *byte == b'>' || *byte == b'/'
        );
        if !at_boundary {
            from = after;
            continue;
        }
        let end = after
            + xml[after..].find('>').ok_or_else(|| {
                ProviderError::Protocol(format!("unterminated <{name}> tag in: {xml}"))
            })?;
        spans.push(&xml[start + 1..end]);
        from = end + 1;
    }
    Ok(spans)
}

/// The first `<name …` tag's attribute text — `Ok(None)` when the document
/// simply has none. Malformed XML propagates as the error it is: absence and
/// brokenness are different answers, and reporting corruption as "the element
/// is missing" would send the operator debugging the wrong thing.
fn first_tag<'x>(xml: &'x str, name: &str) -> Result<Option<&'x str>, ProviderError> {
    let mut spans = tags(xml, name)?;
    Ok(if spans.is_empty() { None } else { Some(spans.swap_remove(0)) })
}

/// The decoded value of attribute `name` within one tag's text, matched
/// ASCII-case-insensitively at a word boundary (so `Pref` never matches
/// inside `MXPref`). `Ok(None)` when the attribute is absent; an unterminated
/// value or broken entity is an error.
fn attr(tag: &str, name: &str) -> Result<Option<String>, ProviderError> {
    let lower = tag.to_ascii_lowercase();
    let needle = format!("{}=\"", name.to_ascii_lowercase());
    let mut from = 0;
    while let Some(found) = lower[from..].find(&needle) {
        let start = from + found;
        let preceded_by_space =
            start > 0 && lower.as_bytes()[start - 1].is_ascii_whitespace();
        if !preceded_by_space {
            from = start + needle.len();
            continue;
        }
        let value_start = start + needle.len();
        let value_end = value_start
            + tag[value_start..].find('"').ok_or_else(|| {
                ProviderError::Protocol(format!("unterminated {name} attribute in: <{tag}>"))
            })?;
        return xml_decode(&tag[value_start..value_end]).map(Some);
    }
    Ok(None)
}

/// Every `<Error …>text</Error>` element as `"error <Number>: <text>"`, the
/// API's own words for what it refused.
fn error_lines(xml: &str) -> Result<Vec<String>, ProviderError> {
    let lower = xml.to_ascii_lowercase();
    let mut lines = Vec::new();
    let mut from = 0;
    while let Some(found) = lower[from..].find("<error") {
        let start = from + found;
        let after = start + "<error".len();
        let at_boundary = matches!(
            lower.as_bytes().get(after),
            Some(byte) if byte.is_ascii_whitespace() || *byte == b'>'
        );
        if !at_boundary {
            from = after;
            continue;
        }
        let open_end = after
            + xml[after..].find('>').ok_or_else(|| {
                ProviderError::Protocol(format!("unterminated <Error> tag in: {xml}"))
            })?;
        let close = open_end
            + lower[open_end..].find("</error").ok_or_else(|| {
                ProviderError::Protocol(format!("unclosed <Error> element in: {xml}"))
            })?;
        let number = attr(&xml[start + 1..open_end], "Number")?;
        let text = xml_decode(xml[open_end + 1..close].trim())?;
        lines.push(match number {
            Some(number) => format!("error {number}: {text}"),
            None => text,
        });
        from = close + 1;
    }
    Ok(lines)
}

/// `text` with XML character entities decoded. An entity this decoder does
/// not know is an error, not a passthrough — a half-decoded TXT value would
/// be pushed back to the registrar corrupted.
fn xml_decode(text: &str) -> Result<String, ProviderError> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let end = amp
            + rest[amp..].find(';').ok_or_else(|| {
                ProviderError::Protocol(format!("unterminated XML entity in {text:?}"))
            })?;
        let entity = &rest[amp + 1..end];
        match entity {
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" => out.push('\''),
            numeric if numeric.starts_with('#') => {
                let digits = numeric.trim_start_matches('#');
                let code = match digits.strip_prefix(['x', 'X']) {
                    Some(hex) => u32::from_str_radix(hex, 16),
                    None => digits.parse(),
                };
                let decoded = code.ok().and_then(char::from_u32).ok_or_else(|| {
                    ProviderError::Protocol(format!("unreadable XML entity &{entity}; in {text:?}"))
                })?;
                out.push(decoded);
            }
            other => {
                return Err(ProviderError::Protocol(format!(
                    "unknown XML entity &{other}; in {text:?}"
                )));
            }
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// `pairs` as an `application/x-www-form-urlencoded` string (also valid as a
/// URL query), every byte outside the unreserved set percent-encoded by the
/// crate's one shared encoder ([`crate::percent_encode`]).
fn form_encode(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| {
            format!("{}={}", crate::percent_encode(key), crate::percent_encode(value))
        })
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{block_on as run, ok, Canned};

    fn provider(replies: Vec<ApiResponse>) -> Namecheap<Canned> {
        Namecheap::new(
            Canned::scripted(replies),
            Credentials {
                api_user: "ncuser".into(),
                api_key: "secret".into(),
                user_name: "ncuser".into(),
                client_ip: "172.83.6.109".into(),
            },
        )
    }

    fn requests(provider: &Namecheap<Canned>) -> Vec<ApiRequest> {
        provider.transport.requests()
    }

    /// A docs-faithful envelope around `inner`, `Status="OK"`.
    fn envelope(inner: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<ApiResponse xmlns="http://api.namecheap.com/xml.response" Status="OK">
  <Errors />
  <RequestedCommand>namecheap.domains.dns.getHosts</RequestedCommand>
  <CommandResponse Type="namecheap.domains.dns.getHosts">{inner}</CommandResponse>
  <Server>PHX01</Server>
</ApiResponse>"#
        )
    }

    fn get_hosts_body(rows: &str) -> String {
        envelope(&format!(
            r#"<DomainDNSGetHostsResult Domain="example.com" IsUsingOurDNS="true">{rows}</DomainDNSGetHostsResult>"#
        ))
    }

    fn set_hosts_ok() -> String {
        envelope(r#"<DomainDNSSetHostsResult Domain="example.com" IsSuccess="true" />"#)
    }

    const ERROR_BODY: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ApiResponse xmlns="http://api.namecheap.com/xml.response" Status="ERROR">
  <Errors><Error Number="2019166">Domain not found</Error></Errors>
  <RequestedCommand>namecheap.domains.dns.getHosts</RequestedCommand>
</ApiResponse>"#;

    fn a(host: &str, value: &str) -> Record {
        Record { host: host.into(), rtype: RecordType::A, value: value.into(), ttl: None }
    }

    #[test]
    fn list_asks_gethosts_with_the_documented_auth_and_domain_split() {
        let provider = provider(vec![ok(&get_hosts_body(""))]);
        run(provider.list("example.co.uk")).expect("an empty zone lists cleanly");

        let sent = requests(&provider);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].method, "GET");
        assert!(sent[0].body.is_empty());
        // The multi-label suffix stays whole in TLD — Namecheap's convention.
        assert_eq!(
            sent[0].url,
            format!(
                "{ENDPOINT}?ApiUser=ncuser&ApiKey=secret&UserName=ncuser&\
                 ClientIp=172.83.6.109&Command=namecheap.domains.dns.getHosts&\
                 SLD=example&TLD=co.uk"
            )
        );
    }

    #[test]
    fn list_parses_the_documented_host_rows_translating_at_the_edge() {
        // Mixed <host>/<Host> case (a live-API quirk), MXPref on every row
        // (only meaningful for MX), entities in TXT, quoted CAA data.
        let body = get_hosts_body(
            r#"
      <host HostId="12" Name="@" Type="A" Address="1.2.3.4" MXPref="10" TTL="1800" />
      <Host HostId="13" Name="@" Type="MX" Address="mail.example.com." MXPref="10" TTL="1800" />
      <Host HostId="14" Name="@" Type="TXT" Address="v=spf1 mx -all &amp; &quot;quoted&quot;" TTL="300" />
      <Host HostId="15" Name="@" Type="CAA" Address="0 issue &quot;letsencrypt.org&quot;" MXPref="10" TTL="1800" />"#,
        );
        let provider = provider(vec![ok(&body)]);
        let records = run(provider.list("example.com")).expect("the documented body parses");

        assert_eq!(records.len(), 4);
        assert_eq!(records[0], Record { ttl: Some(1800), ..a("@", "1.2.3.4") });
        assert_eq!(records[1].rtype, RecordType::Mx { preference: 10 });
        assert_eq!(records[1].value, "mail.example.com.");
        assert_eq!(records[2].value, r#"v=spf1 mx -all & "quoted""#);
        assert_eq!(records[3].rtype, RecordType::Caa);
        assert_eq!(records[3].value, "0 issue letsencrypt.org", "CAA quotes strip at the edge");
    }

    #[test]
    fn an_observed_srv_row_survives_verbatim_not_guessed_apart() {
        // The API documents no SRV field layout; inventing one could corrupt
        // a record the first law promises to protect.
        let body = get_hosts_body(
            r#"<host HostId="19" Name="_sip._tcp" Type="SRV" Address="0 5 5060 sip.example.com." MXPref="10" TTL="1800" />"#,
        );
        let records = run(provider(vec![ok(&body)]).list("example.com")).expect("SRV rows list");
        assert_eq!(records[0].rtype, RecordType::Other("SRV".into()));
        assert_eq!(records[0].value, "0 5 5060 sip.example.com.");
    }

    #[test]
    fn an_error_envelope_surfaces_the_apis_own_words() {
        let error = run(provider(vec![ok(ERROR_BODY)]).list("example.com"))
            .expect_err("Status=ERROR must not read as an empty zone");
        match error {
            ProviderError::Api { status, detail } => {
                assert_eq!(status, 200);
                assert!(detail.contains("2019166") && detail.contains("Domain not found"), "{detail}");
            }
            other => panic!("expected an Api error, got: {other}"),
        }
    }

    #[test]
    fn an_http_error_status_is_an_api_refusal_with_the_body_verbatim() {
        let reply = ApiResponse { status: 500, body: b"upstream melted".to_vec() };
        let error = run(provider(vec![reply]).list("example.com")).expect_err("500 is a refusal");
        match error {
            ProviderError::Api { status, detail } => {
                assert_eq!(status, 500);
                assert_eq!(detail, "upstream melted");
            }
            other => panic!("expected an Api error, got: {other}"),
        }
    }

    #[test]
    fn malformed_xml_errors_instead_of_dropping_records() {
        // Each corruption must fail the listing: a silently dropped row would
        // later be erased by the replace-everything push.
        let missing_address =
            get_hosts_body(r#"<host HostId="1" Name="www" Type="A" TTL="60" />"#);
        let unterminated = r#"<ApiResponse Status="OK"><DomainDNSGetHostsResult><host Name="www"#;
        let bad_entity =
            get_hosts_body(r#"<host Name="@" Type="TXT" Address="v=spf1 &bogus; -all" TTL="60" />"#);
        let no_result = set_hosts_ok(); // an OK envelope, but not a getHosts one
        for body in [missing_address, unterminated.to_string(), bad_entity, no_result] {
            let error = run(provider(vec![ok(&body)]).list("example.com"))
                .expect_err("malformed XML must error");
            assert!(matches!(error, ProviderError::Protocol(_)), "got: {error}");
        }
    }

    #[test]
    fn apply_reads_first_then_replaces_with_numbered_fields() {
        let provider = provider(vec![ok(&get_hosts_body("")), ok(&set_hosts_ok())]);
        let records = vec![
            a("@", "172.83.6.109"),
            Record {
                host: "@".into(),
                rtype: RecordType::Mx { preference: 10 },
                value: "mail.example.com".into(),
                ttl: Some(1800),
            },
            Record {
                host: "@".into(),
                rtype: RecordType::Txt,
                value: "v=spf1 mx -all".into(),
                ttl: None,
            },
            Record {
                host: "@".into(),
                rtype: RecordType::Caa,
                value: "0 issue letsencrypt.org".into(),
                ttl: None,
            },
        ];
        run(provider.apply("example.com", &records)).expect("a clean push succeeds");

        let sent = requests(&provider);
        assert_eq!(sent.len(), 2, "one read, then one write");
        let push = &sent[1];
        assert_eq!(push.method, "POST");
        assert_eq!(push.url, ENDPOINT, "setHosts posts its fields in the body");
        assert!(push
            .headers
            .contains(&("Content-Type".into(), "application/x-www-form-urlencoded".into())));

        let body = String::from_utf8(push.body.clone()).expect("a form body is ASCII");
        assert!(body.contains("Command=namecheap.domains.dns.setHosts"), "{body}");
        assert!(body.contains("SLD=example") && body.contains("TLD=com"), "{body}");
        assert!(body.contains("HostName1=%40&RecordType1=A&Address1=172.83.6.109"), "{body}");
        assert!(!body.contains("TTL1="), "no TTL opinion means the field is omitted: {body}");
        assert!(body.contains("RecordType2=MX&Address2=mail.example.com&MXPref2=10&TTL2=1800"), "{body}");
        assert!(body.contains("Address3=v%3Dspf1%20mx%20-all"), "{body}");
        assert!(body.contains("Address4=0%20issue%20%22letsencrypt.org%22"), "CAA data is quoted for the API: {body}");
        assert!(body.contains("EmailType=MX"), "custom MX routing must be pinned: {body}");
    }

    #[test]
    fn apply_without_mx_records_sends_no_emailtype() {
        let provider = provider(vec![ok(&get_hosts_body("")), ok(&set_hosts_ok())]);
        run(provider.apply("example.com", &[a("www", "1.2.3.4")])).expect("push succeeds");
        let body = String::from_utf8(requests(&provider)[1].body.clone()).unwrap();
        assert!(!body.contains("EmailType"), "no MX, no mail-mode opinion: {body}");
    }

    /// A getHosts result element carrying an `EmailType`, as the live API
    /// returns for a zone using one of Namecheap's mail products.
    fn get_hosts_body_with_email_type(rows: &str, email_type: &str) -> String {
        envelope(&format!(
            r#"<DomainDNSGetHostsResult Domain="example.com" EmailType="{email_type}" IsUsingOurDNS="true">{rows}</DomainDNSGetHostsResult>"#
        ))
    }

    #[test]
    fn apply_echoes_the_observed_emailtype_so_mail_forwarding_survives() {
        // A site-only push to a zone using free email forwarding: omitting
        // EmailType would reset the mail mode and silently kill forwarding.
        let observed = get_hosts_body_with_email_type("", "FWD");
        let provider = provider(vec![ok(&observed), ok(&set_hosts_ok())]);
        run(provider.apply("example.com", &[a("www", "1.2.3.4")])).expect("push succeeds");
        let body = String::from_utf8(requests(&provider)[1].body.clone()).unwrap();
        assert!(body.contains("EmailType=FWD"), "the observed mail mode is echoed: {body}");
    }

    #[test]
    fn apply_overrides_emailtype_to_mx_only_when_the_set_claims_mx() {
        // The config publishing its own MX is the one case where switching
        // the zone to custom MX routing is what the operator asked for.
        let observed = get_hosts_body_with_email_type("", "FWD");
        let provider = provider(vec![ok(&observed), ok(&set_hosts_ok())]);
        let mx = Record {
            host: "@".into(),
            rtype: RecordType::Mx { preference: 10 },
            value: "mail.example.com".into(),
            ttl: None,
        };
        run(provider.apply("example.com", &[mx])).expect("push succeeds");
        let body = String::from_utf8(requests(&provider)[1].body.clone()).unwrap();
        assert!(body.contains("EmailType=MX"), "MX in the set claims mail routing: {body}");
        assert!(!body.contains("EmailType=FWD"), "{body}");
    }

    #[test]
    fn apply_carries_records_the_registrar_gained_since_the_caller_planned() {
        // The operator adds a verification TXT between the caller's list and
        // this push; the interlock read sees it, so the whole-zone replace
        // must restate it rather than erase it.
        let drifted = get_hosts_body(
            r#"<host HostId="21" Name="zb999" Type="TXT" Address="verification=zzz" TTL="300" />"#,
        );
        let provider = provider(vec![ok(&drifted), ok(&set_hosts_ok())]);
        run(provider.apply("example.com", &[a("@", "1.2.3.4")])).expect("push succeeds");
        let body = String::from_utf8(requests(&provider)[1].body.clone()).unwrap();
        assert!(body.contains("HostName1=%40"), "the pushed set leads: {body}");
        assert!(
            body.contains("HostName2=zb999") && body.contains("Address2=verification%3Dzzz"),
            "the concurrently created record rides along: {body}"
        );
    }

    #[test]
    fn a_body_that_never_closes_its_envelope_is_refused_as_truncated() {
        // Status="OK" sits at the top of the document, so a connection cut
        // between <host/> rows would otherwise read as a shorter zone — and
        // the next push would erase the records after the cut.
        let complete = get_hosts_body(
            r#"<host HostId="1" Name="@" Type="A" Address="1.2.3.4" TTL="1800" />"#,
        );
        let truncated = &complete[..complete.rfind("</ApiResponse>").expect("fixture closes")];
        let error = run(provider(vec![ok(truncated)]).list("example.com"))
            .expect_err("a truncated body must not parse as a zone");
        assert!(
            matches!(&error, ProviderError::Protocol(detail) if detail.contains("truncated")),
            "got: {error}"
        );
    }

    #[test]
    fn apply_refuses_to_write_when_the_read_fails() {
        // The disaster this guards: overwriting a zone nobody could list.
        let provider = provider(vec![ok(ERROR_BODY)]);
        let error = run(provider.apply("example.com", &[a("@", "1.2.3.4")]))
            .expect_err("a failed read must block the write");
        assert!(matches!(error, ProviderError::Api { .. }), "got: {error}");
        assert_eq!(requests(&provider).len(), 1, "no setHosts call may follow a failed read");
    }

    #[test]
    fn apply_refuses_srv_records_the_api_cannot_carry() {
        // Desired SRVs cannot be created…
        let provider_a = provider(vec![ok(&get_hosts_body(""))]);
        let srv = Record {
            host: "_imaps._tcp".into(),
            rtype: RecordType::Srv { priority: 0, weight: 1, port: 993 },
            value: "imap.example.com".into(),
            ttl: None,
        };
        let error = run(provider_a.apply("example.com", &[a("@", "1.2.3.4"), srv]))
            .expect_err("an SRV in the set must refuse the push");
        assert!(error.to_string().contains("_imaps._tcp"), "names the record: {error}");
        assert_eq!(requests(&provider_a).len(), 1, "the refusal happens before any write");

        // …and live SRVs would be erased by a push that cannot restate them.
        let observed_srv = get_hosts_body(
            r#"<host Name="_sip._tcp" Type="SRV" Address="0 5 5060 sip.example.com." TTL="1800" />"#,
        );
        let provider_b = provider(vec![ok(&observed_srv)]);
        let error = run(provider_b.apply("example.com", &[a("@", "1.2.3.4")]))
            .expect_err("a live SRV must refuse the push that would erase it");
        assert!(error.to_string().contains("_sip._tcp"), "names the record: {error}");
        assert_eq!(requests(&provider_b).len(), 1);
    }

    #[test]
    fn apply_refuses_an_empty_set_that_would_erase_the_zone() {
        let provider = provider(vec![]);
        let error = run(provider.apply("example.com", &[]))
            .expect_err("an empty push is a zone wipe");
        assert!(matches!(error, ProviderError::Protocol(_)), "got: {error}");
        assert!(requests(&provider).is_empty(), "refused before any exchange");
    }

    #[test]
    fn sethosts_claiming_issuccess_false_is_an_error() {
        // Status="OK" with IsSuccess="false" is a real Namecheap answer;
        // reporting it as done would strand the operator on stale records.
        let not_written =
            envelope(r#"<DomainDNSSetHostsResult Domain="example.com" IsSuccess="false" />"#);
        let provider = provider(vec![ok(&get_hosts_body("")), ok(&not_written)]);
        let error = run(provider.apply("example.com", &[a("@", "1.2.3.4")]))
            .expect_err("IsSuccess=false is not success");
        assert!(matches!(error, ProviderError::Protocol(_)), "got: {error}");
    }

    #[test]
    fn a_domain_without_a_dot_cannot_be_addressed() {
        // An input problem, not a network one: Protocol, so the operator is
        // steered at the config rather than at connectivity.
        let provider = provider(vec![]);
        let error = run(provider.list("localhost")).expect_err("no SLD.TLD split exists");
        assert!(matches!(error, ProviderError::Protocol(_)), "got: {error}");
        assert!(requests(&provider).is_empty());
    }

    #[test]
    fn unwritable_names_exactly_the_srv_records() {
        let srv = Record {
            host: "_imaps._tcp".into(),
            rtype: RecordType::Srv { priority: 0, weight: 1, port: 993 },
            value: "imap.example.com".into(),
            ttl: None,
        };
        let observed_style =
            Record { rtype: RecordType::Other("srv".into()), ..a("_sub._tcp", "0 1 587 x") };
        let records = vec![a("@", "1.2.3.4"), srv.clone(), observed_style.clone()];
        let blocked = Namecheap::<Canned>::unwritable(&records);
        assert_eq!(blocked, vec![&srv, &observed_style], "both spellings of SRV are caught");
    }
}
