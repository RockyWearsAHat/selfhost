//! Microsoft Autodiscover — the one server-side discovery path macOS and iOS
//! Mail actually act on for a domain Apple's client does not already know.
//!
//! Mail POSTs a small XML request naming the address being configured to
//! `https://autodiscover.<domain>/autodiscover/autodiscover.xml` (and the
//! bare mail domain, which the proxy also routes here — see
//! `crates/proxy/src/server.rs`'s `dispatch`). It parses the XML response but
//! only acts on an `EXCH`/`EXPR` protocol block naming an EWS endpoint
//! (`crate::ews`) — everything else in the Outlook response schema (IMAP,
//! POP3, SMTP blocks) it silently discards. iOS Mail instead asks for, and
//! acts on, the ActiveSync-flavoured `MobileSync` response schema
//! (`crate::eas`). Two request shapes, two response shapes, same endpoint:
//! [`respond`] tells them apart by which schema the request itself asked for
//! and answers with the matching one.
//!
//! Deliberately unauthenticated, the same posture as [`crate::pacc`]: the
//! response only names hostnames DNS and the certificate already publish,
//! plus the email address the caller supplied back to them. The credential
//! check happens per-request at EWS/ActiveSync, not here.
//!
//! No XML crate exists anywhere in this workspace (see `crates/storage/src/dav`
//! for the house style) and this module does not add one — both the request
//! field it needs and the response it writes are narrow enough that a small
//! hand-rolled scanner and string builder are the whole implementation.

use crate::xml::{element_text, escape};
use selfhost_config::autodiscover::{ACTIVESYNC_PATH, EWS_PATH};

/// Builds the Autodiscover XML response for a request against `host` (the
/// `autodiscover.<domain>` name the client connected to — used verbatim as
/// the EWS/ActiveSync server name, since the certificate on this connection
/// already names it) carrying `body`, the client's raw POST.
///
/// Never fails: an unparseable or emailless request still gets a well-formed
/// response, with an empty address rather than a guess — Mail's own retry
/// behaviour on a malformed response is worse than an address-less one that
/// at least names working EWS/ActiveSync URLs.
pub fn respond(host: &str, body: &[u8]) -> Vec<u8> {
    let email = requested_email(body).unwrap_or_default();
    let response = if wants_mobilesync(body) {
        mobilesync_response(host, &email)
    } else {
        outlook_response(host, &email)
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
         <Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\">\
         {response}\
         </Autodiscover>"
    )
    .into_bytes()
}

/// The Outlook/EWS response schema — the block macOS Mail acts on, naming an
/// `EXCH` protocol whose `ASUrl`/`EwsUrl` point at [`crate::ews`].
fn outlook_response(host: &str, email: &str) -> String {
    let email = escape(email);
    format!(
        "<Response xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a\">\
         <User><DisplayName>{email}</DisplayName></User>\
         <Account>\
         <AccountType>email</AccountType>\
         <Action>settings</Action>\
         <Protocol>\
         <Type>EXCH</Type>\
         <Server>{host}</Server>\
         <ASUrl>https://{host}{EWS_PATH}</ASUrl>\
         <EwsUrl>https://{host}{EWS_PATH}</EwsUrl>\
         <LoginName>{email}</LoginName>\
         </Protocol>\
         </Account>\
         </Response>"
    )
}

/// The ActiveSync/MobileSync response schema — the block iOS Mail acts on,
/// naming the `Url` [`crate::eas`] is served at.
fn mobilesync_response(host: &str, email: &str) -> String {
    let email = escape(email);
    format!(
        "<Response xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006\">\
         <Culture>en:en</Culture>\
         <User><EMailAddress>{email}</EMailAddress><DisplayName>{email}</DisplayName></User>\
         <Action><Settings><Server>\
         <Type>MobileSync</Type>\
         <Url>https://{host}{ACTIVESYNC_PATH}</Url>\
         <Name>{host}</Name>\
         </Server></Settings></Action>\
         </Response>"
    )
}

/// The `<EMailAddress>` element's text content, if the request names one.
fn requested_email(body: &[u8]) -> Option<String> {
    element_text(std::str::from_utf8(body).ok()?, "EMailAddress")
}

/// Whether the request asked for the ActiveSync (`MobileSync`) response
/// schema rather than the Outlook/EWS one — iOS Mail's
/// `<AcceptableResponseSchema>` names
/// `.../mobilesync/requestschema/2006a`; any other value, or none at all,
/// gets the Outlook/EWS response macOS Mail expects.
fn wants_mobilesync(body: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(body) else { return false };
    element_text(text, "AcceptableResponseSchema")
        .is_some_and(|schema| schema.to_ascii_lowercase().contains("mobilesync"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn outlook_request(email: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
             <Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006\">\
             <Request><EMailAddress>{email}</EMailAddress>\
             <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>\
             </Request></Autodiscover>"
        )
        .into_bytes()
    }

    fn mobilesync_request(email: &str) -> Vec<u8> {
        format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
             <Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/mobilesync/requestschema/2006a\">\
             <Request><EMailAddress>{email}</EMailAddress>\
             <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/mobilesync/requestschema/2006a</AcceptableResponseSchema>\
             </Request></Autodiscover>"
        )
        .into_bytes()
    }

    #[test]
    fn an_outlook_request_gets_an_exch_protocol_block_naming_ews() {
        let xml = String::from_utf8(respond("autodiscover.example.com", &outlook_request("dave@example.com"))).unwrap();
        assert!(xml.contains("<Type>EXCH</Type>"));
        assert!(xml.contains("<ASUrl>https://autodiscover.example.com/EWS/Exchange.asmx</ASUrl>"));
        assert!(xml.contains("<LoginName>dave@example.com</LoginName>"));
        assert!(!xml.contains("MobileSync"));
    }

    #[test]
    fn a_mobilesync_request_gets_a_mobilesync_block_naming_activesync() {
        let xml =
            String::from_utf8(respond("autodiscover.example.com", &mobilesync_request("dave@example.com"))).unwrap();
        assert!(xml.contains("<Type>MobileSync</Type>"));
        assert!(xml.contains("<Url>https://autodiscover.example.com/Microsoft-Server-ActiveSync</Url>"));
        assert!(xml.contains("<EMailAddress>dave@example.com</EMailAddress>"));
        assert!(!xml.contains("EXCH"));
    }

    #[test]
    fn a_request_with_no_email_still_yields_well_formed_xml_with_an_empty_login_name() {
        let xml = String::from_utf8(respond("autodiscover.example.com", b"not xml at all")).unwrap();
        assert!(xml.starts_with("<?xml"));
        assert!(xml.contains("<LoginName></LoginName>"));
    }

    #[test]
    fn the_email_address_is_escaped_in_the_response() {
        let xml = String::from_utf8(respond("autodiscover.example.com", &outlook_request("a&b@example.com"))).unwrap();
        assert!(xml.contains("a&amp;b@example.com"));
        assert!(!xml.contains("a&b@example.com"));
    }
}
