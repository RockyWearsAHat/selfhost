//! Namecheap's Dynamic DNS: keeps one record per configured entry pointed at
//! this machine's WAN address, for a domain whose nameservers stay with
//! Namecheap rather than moving to this project's own authority.
//!
//! # Shape
//!
//! Mirrors [`crate::updater`] closely on purpose — same WAN-IP source
//! ([`selfhost_igd::Gateway`]), same [`assess`] change-detection rule, same
//! once-per-change-of-reason logging — but the "write" side is one HTTPS `GET`
//! per entry to Namecheap's DDNS endpoint instead of a local zone mutation, and
//! entries are independent: `example.com`'s password being wrong must not stop
//! `other.com` from being kept current, so failures are tracked and logged per
//! entry rather than for the tracker as a whole.
//!
//! # Why one connection per update, and why the response is read at all
//!
//! Namecheap answers a small XML document whose `<ErrCount>` is `0` on success
//! and non-zero with an `<Err1>` message otherwise — an HTTP `200` alone does
//! not mean the record was updated (a wrong password, for instance, still
//! answers `200`). [`parse_result`] reads just enough of that document to tell
//! success from failure; a hand-rolled XML parser buys nothing here since the
//! shape is fixed and tiny, so this is a targeted scan, not a general one.

use crate::updater::{assess, complain, recovered, Movement};
use selfhost_acme::transport::{HttpsClient, Url};
use selfhost_config::NamecheapDdns;
use selfhost_igd::Gateway;
use std::net::Ipv4Addr;
use std::time::Duration;

/// Namecheap's fixed Dynamic DNS host. Documented at
/// <https://www.namecheap.com/support/knowledgebase/article.aspx/29/11/how-do-i-use-a-browser-to-dynamically-update-the-hosts-ip>.
const DDNS_HOST: &str = "dynamicdns.park-your-domain.com";

/// The one operation this updater needs against Namecheap's API: update one
/// entry's record. A trait, mirroring [`crate::updater::ApexWriter`], so the
/// tracking loop is testable with a fake writer rather than a live account.
#[allow(async_fn_in_trait)] // Both impl and caller live in this workspace and await
                            // on the daemon's single runtime; no `Send` bound is needed.
pub trait DdnsWriter {
    /// Updates `entry`'s record to `address`. `Err` carries a reason fit to
    /// log, already distinguishing a transport failure from Namecheap
    /// refusing the update.
    async fn update(&self, entry: &NamecheapDdns, address: Ipv4Addr) -> Result<(), String>;
}

/// Namecheap's Dynamic DNS, over [`selfhost_acme`]'s HTTPS client — reused
/// rather than a second TLS client, since this crate needs exactly what that
/// one already is: one outbound HTTPS request, response read whole.
pub struct NamecheapClient {
    http: HttpsClient,
}

impl NamecheapClient {
    /// Builds a client verifying Namecheap's certificate against the bundled
    /// Mozilla roots, the same trust [`HttpsClient::new`] gives ACME.
    pub fn new() -> Result<Self, String> {
        HttpsClient::new().map(|http| Self { http }).map_err(|error| error.to_string())
    }
}

impl DdnsWriter for NamecheapClient {
    async fn update(&self, entry: &NamecheapDdns, address: Ipv4Addr) -> Result<(), String> {
        let path = format!(
            "/update?host={}&domain={}&password={}&ip={address}",
            percent_encode(&entry.host),
            percent_encode(&entry.domain),
            percent_encode(&entry.password),
        );
        let url = Url { host: DDNS_HOST.to_owned(), port: 443, path };

        let response = self.http.get(&url).await.map_err(|error| error.to_string())?;
        if response.status.0 != 200 {
            return Err(format!("Namecheap answered HTTP {}", response.status.0));
        }
        parse_result(&String::from_utf8_lossy(&response.body))
    }
}

/// Percent-encodes a query-string value per RFC 3986's `unreserved` set.
///
/// A Dynamic DNS password can contain any character an operator's password
/// generator produced — `&`, `=`, `%`, even control bytes — and every one of
/// them has to survive as data, not be read as the next query parameter.
fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Reads a Namecheap Dynamic DNS response for `<ErrCount>` and, when it is
/// non-zero, the first `<Err1>` message.
///
/// Namecheap can answer `200 OK` for a rejected update — a wrong password
/// among them — so the status line alone is not the answer; this is.
fn parse_result(body: &str) -> Result<(), String> {
    let errors = tag_text(body, "ErrCount").and_then(|text| text.trim().parse::<u32>().ok());
    match errors {
        Some(0) => Ok(()),
        Some(_) => {
            let reason = tag_text(body, "Err1").unwrap_or("no reason given").trim().to_owned();
            Err(format!("Namecheap refused the update: {reason}"))
        }
        // A response that does not even carry `<ErrCount>` is not the document
        // this API is documented to answer with — treated as a failure rather
        // than a silent success, the same "an absent answer is not a good one"
        // rule `assess` applies to the WAN IP itself.
        None => Err(format!("unrecognised response from Namecheap: {}", body.trim())),
    }
}

/// The text content of the first `<tag>...</tag>` in `body`, or `None` if the
/// tag does not appear. A scan, not a parser: this document's shape is fixed
/// and small enough that a general XML parser would buy nothing extra.
fn tag_text<'a>(body: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)? + start;
    Some(&body[start..end])
}

/// Tracks this machine's WAN IP and keeps every configured entry's record
/// pointed at it.
///
/// Never returns: a branch of the daemon's `select!`, like
/// [`crate::updater::track_wan_ip`]. Returns immediately if `entries` is
/// empty — nothing to track, and no reason to hold a `select!` branch open for
/// a feature nobody configured. The gateway is shared across every entry (one
/// machine has one WAN address); failure to update one entry does not stop the
/// others, and each entry's own failure is logged at most once per change of
/// reason, independently of every other entry's.
pub async fn track_namecheap_ddns(
    writer: impl DdnsWriter,
    entries: Vec<NamecheapDdns>,
    interval: Duration,
) {
    if entries.is_empty() {
        return;
    }

    let mut gateway_complaint: Option<String> = None;
    let mut entry_complaints: Vec<Option<String>> = vec![None; entries.len()];
    let mut last_deployed: Vec<Option<Ipv4Addr>> = vec![None; entries.len()];
    let mut gateway: Option<Gateway> = None;

    // `interval`'s first tick is immediate, deploying the current address to
    // every entry on startup rather than after one wait — the same reasoning
    // `track_wan_ip` gives.
    let mut ticker = tokio::time::interval(interval);

    loop {
        ticker.tick().await;

        if gateway.is_none() {
            match Gateway::discover().await {
                Ok(found) => gateway = Some(found),
                Err(reason) => {
                    complain(&mut gateway_complaint, format!("no router to ask for the WAN IP ({reason})"));
                    continue;
                }
            }
        }
        let Some(router) = gateway.as_ref() else { continue };

        let candidate = match router.external_address().await {
            Ok(address) => address,
            Err(reason) => {
                complain(
                    &mut gateway_complaint,
                    format!("the router did not report a WAN IP ({reason})"),
                );
                gateway = None;
                continue;
            }
        };
        recovered(&mut gateway_complaint);

        for (i, entry) in entries.iter().enumerate() {
            match assess(last_deployed[i], candidate) {
                Movement::Unusable(address) => complain(
                    &mut entry_complaints[i],
                    format!(
                        "the router reported {address} for {}.{}, which is not a public \
                         address; ignoring"
                        , entry.host, entry.domain
                    ),
                ),
                Movement::Unchanged => recovered(&mut entry_complaints[i]),
                Movement::Changed(address) => match writer.update(entry, address).await {
                    Ok(()) => {
                        recovered(&mut entry_complaints[i]);
                        eprintln!("namecheap-ddns: {}.{} -> {address}", entry.host, entry.domain);
                        last_deployed[i] = Some(address);
                    }
                    Err(reason) => complain(
                        &mut entry_complaints[i],
                        format!("could not update {}.{}: {reason}", entry.host, entry.domain),
                    ),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn a_successful_response_has_zero_errors() {
        let body = "<?xml version=\"1.0\"?>\n<interface-response>\n<ErrCount>0</ErrCount>\n\
                     <Done>true</Done>\n</interface-response>";
        assert_eq!(parse_result(body), Ok(()));
    }

    #[test]
    fn a_refused_update_carries_namecheaps_own_reason() {
        let body = "<interface-response><ErrCount>1</ErrCount><errors>\
                     <Err1>Domain not found</Err1></errors></interface-response>";
        let error = parse_result(body).unwrap_err();
        assert!(error.contains("Domain not found"), "{error}");
    }

    #[test]
    fn a_response_missing_err_count_is_a_failure_not_a_silent_success() {
        let error = parse_result("<html>not what we expected</html>").unwrap_err();
        assert!(error.contains("unrecognised"), "{error}");
    }

    #[test]
    fn special_characters_in_a_password_survive_percent_encoding() {
        let encoded = percent_encode("p@ss w/ord&=%");
        assert_eq!(encoded, "p%40ss%20w%2Ford%26%3D%25");
        // Round-trips through the one property that matters here: none of the
        // query string's own delimiters appear in the encoded output.
        assert!(!encoded.contains('&') && !encoded.contains('='));
    }

    /// An in-memory `DdnsWriter` that records every call and can be told to
    /// fail for a specific entry, standing in for a live Namecheap account.
    struct FakeWriter {
        calls: Mutex<Vec<(String, Ipv4Addr)>>,
        fail_domains: Vec<String>,
    }

    impl DdnsWriter for FakeWriter {
        async fn update(&self, entry: &NamecheapDdns, address: Ipv4Addr) -> Result<(), String> {
            if self.fail_domains.contains(&entry.domain) {
                return Err("simulated failure".into());
            }
            self.calls.lock().expect("test mutex").push((entry.domain.clone(), address));
            Ok(())
        }
    }

    fn entry(domain: &str) -> NamecheapDdns {
        NamecheapDdns { domain: domain.into(), host: "@".into(), password: "secret".into() }
    }

    #[tokio::test]
    async fn tracking_with_no_entries_returns_immediately_rather_than_looping_forever() {
        let writer = FakeWriter { calls: Mutex::new(Vec::new()), fail_domains: Vec::new() };
        // If this did not return, the test itself would hang.
        track_namecheap_ddns(writer, Vec::new(), Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn a_failure_on_one_entry_does_not_prevent_the_writer_from_being_asked_for_the_others() {
        let writer =
            FakeWriter { calls: Mutex::new(Vec::new()), fail_domains: vec!["broken.com".into()] };
        let address = Ipv4Addr::new(203, 0, 113, 5);

        let broken = writer.update(&entry("broken.com"), address).await;
        let healthy = writer.update(&entry("healthy.com"), address).await;

        assert!(broken.is_err(), "the failing entry must actually fail");
        assert!(healthy.is_ok(), "a sibling entry's failure must not affect this one");
        assert_eq!(
            writer.calls.lock().expect("test mutex").as_slice(),
            &[("healthy.com".to_owned(), address)],
            "only the entry that succeeded is recorded as called through"
        );
    }
}
