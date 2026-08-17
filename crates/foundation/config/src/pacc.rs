//! PACC — the automatic account-configuration document a mail domain publishes.
//!
//! `draft-ietf-mailmaint-pacc` (*Automatic Configuration of Email, Calendar, and
//! Contact Server Settings*) is the successor to the SRV discovery of RFC 6186:
//! instead of asking DNS for a service record, a client derives the domain from
//! the address the user typed and fetches one JSON document over HTTPS —
//!
//! ```text
//! https://ua-auto-config.<domain>/.well-known/user-agent-configuration.json
//! ```
//!
//! — whose integrity it checks against a digest published in a
//! `_ua-auto-config.<domain>` `TXT` record. The document names the IMAP and
//! submission hosts and the authentication the server accepts, which is exactly
//! what account setup asks the user to type when discovery fails.
//!
//! This module is the *derivation*, and it is deliberately the only one: the
//! digest in DNS is a digest **of these bytes**, so the served document and the
//! record that vouches for it must come from one generator or the two silently
//! disagree and every client rejects the configuration. [`document`] produces
//! the bytes, [`txt_value`] wraps a digest of them in the record's tag syntax,
//! and the SHA-256 itself is computed by the caller (`selfhost-mail::pacc`) —
//! this crate is the schema and performs no crypto, the same way it takes the
//! DKIM public key as a parameter rather than reading a key.
//!
//! Honest posture: no macOS or iOS build is known to implement PACC yet — the
//! draft's client side was still being written by its authors in July 2026, and
//! a sweep of this project's own Macs found none of its strings. Publishing the
//! document costs one static route and one `TXT` record, is inert to every
//! client that has never heard of it, and is the only specified path that ends
//! with a working account from an address and a password alone. See
//! `discovery-lab.dx` for the measurements behind that sentence.

use selfhost_json::Json;

/// The label prefixed to the mail domain to reach the configuration document.
pub const HOST_PREFIX: &str = "ua-auto-config";

/// The path the configuration document is served at, on [`host`].
pub const WELL_KNOWN_PATH: &str = "/.well-known/user-agent-configuration.json";

/// The `TXT` record name, relative to the mail domain, carrying the digest.
pub const TXT_NAME: &str = "_ua-auto-config";

/// The version tag every digest record must open with.
pub const VERSION_TAG: &str = "UAAC1";

/// The hostname a client fetches `domain`'s configuration document from.
///
/// One name per mail domain — it joins [`crate::mail::Mail::client_hosts`], so
/// it gets an `A` record and a certificate for free rather than by a second rule.
pub fn host(domain: &str) -> String {
    format!("{HOST_PREFIX}.{domain}")
}

/// The configuration document `domain` publishes, as the exact bytes served.
///
/// Names only what this deployment actually runs and can prove: IMAP on
/// `imap.<domain>` and submission on `smtp.<domain>` — the same two names
/// [`crate::mail::Mail::client_hosts`] publishes and certifies, which is why a
/// client that reads this document reaches a host with an `A` record and a
/// certificate — and password authentication, which is the only method the
/// submission and IMAP servers implement. Nothing is advertised that a client
/// would then fail to reach: the draft has the client probe the advertised
/// servers directly on 993 and 465, which are the two implicit-TLS binds
/// `[mail]` defaults to.
///
/// The returned string is what must be hashed for [`txt_value`] and what the
/// proxy must serve byte for byte; the JSON object is key-ordered, so the same
/// config always produces the same bytes and therefore the same digest.
pub fn document(domain: &str) -> String {
    Json::object([
        (
            "protocols",
            Json::object([
                ("imap", Json::object([("host", Json::string(format!("imap.{domain}")))])),
                ("submit", Json::object([("host", Json::string(format!("smtp.{domain}")))])),
            ]),
        ),
        ("authentication", Json::object([("password", Json::Bool(true))])),
    ])
    .to_text()
}

/// The `TXT` record body vouching for a document with this digest.
///
/// `digest` is base64 of the SHA-256 of exactly the bytes [`document`] returned,
/// as `selfhost-mail::pacc::digest` computes it.
pub fn txt_value(digest: &str) -> String {
    format!("v={VERSION_TAG}; a=sha256; d={digest}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mail::{Mail, MailBind};

    fn mail_config() -> Mail {
        Mail {
            hostname: "mail.example.com".into(),
            domains: vec!["example.com".into()],
            mailboxes: vec![],
            dkim: None,
            relay: None,
            bind: MailBind::default(),
            max_message_bytes: 25 * 1024 * 1024,
            require_tls_for_auth: true,
        }
    }

    #[test]
    fn the_document_names_the_hosts_the_deployment_publishes() {
        let text = document("example.com");
        assert_eq!(
            text,
            r#"{"authentication":{"password":true},"protocols":{"imap":{"host":"imap.example.com"},"submit":{"host":"smtp.example.com"}}}"#
        );
    }

    #[test]
    fn every_host_the_document_advertises_is_one_the_config_publishes() {
        // The document is only honest if the names in it are names this
        // deployment gives an address and a certificate to.
        let hosts = mail_config().client_hosts();
        let text = document("example.com");
        let advertised =
            ["imap.example.com".to_owned(), "smtp.example.com".to_owned(), host("example.com")];
        for advertised in advertised {
            assert!(
                hosts.contains(&advertised),
                "{advertised} must be a published client host"
            );
        }
        assert!(text.contains("imap.example.com") && text.contains("smtp.example.com"));
    }

    #[test]
    fn the_record_carries_the_version_algorithm_and_digest_tags() {
        assert_eq!(
            txt_value("K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols="),
            "v=UAAC1; a=sha256; d=K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols="
        );
    }

    #[test]
    fn the_configuration_host_is_one_label_under_the_mail_domain() {
        assert_eq!(host("example.com"), "ua-auto-config.example.com");
    }
}
