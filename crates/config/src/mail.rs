//! The mail section of a deployment.
//!
//! A deployment that sends and receives mail for its domains declares it here,
//! in `selfhost.config.toml`, exactly as it declares its sites and its zone: one
//! hand-written document every service reads. This module is only the *schema*,
//! its validation, and the one derivation that must not live anywhere else — the
//! set of DNS records a mail domain has to publish. The running servers (SMTP,
//! submission, IMAP) are built from these types in `selfhost-mail`, which depends
//! on this crate; this crate never depends on `mail`, so the address rules a
//! mailbox is checked against are re-stated here rather than imported, the same
//! way [`crate::dns`] re-states the DNS name limits instead of depending on the
//! `dns` crate that depends on it.
//!
//! The honest posture, stated once: publishing an `MX` and an SPF record is a
//! *promise* that this machine handles the domain's mail. [`Mail::dns_records`]
//! generates that promise from the config so the served zone and the operator's
//! printed instructions can never disagree — but whether the promise can be kept
//! (a clean sending reputation, forward-confirmed reverse DNS) is measured at
//! send time by `selfhost-mail`, never assumed here.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::dns::RecordConfig;
use crate::validate::Problem;

/// Longest a full address may be, in bytes (RFC 5321 §4.5.3.1.3). Mirrors
/// `mail::address::MAX_ADDRESS`, kept local so `config` stays free of a dependency
/// on the `mail` crate (which depends on *this* one).
const MAX_ADDRESS: usize = 254;
/// Longest the part before the `@` may be. Mirrors `mail::address::MAX_LOCAL`.
const MAX_LOCAL: usize = 64;
/// Longest a domain may be. Mirrors `mail::address::MAX_DOMAIN`.
const MAX_DOMAIN: usize = 255;
/// Longest a single DNS label may be.
const MAX_LABEL: usize = 63;

/// Mail, when this machine sends and receives for its domains.
///
/// Absent from the config means no mail: the daemon binds no SMTP, submission, or
/// IMAP listener and the doctor's mail section reports it as not configured. Mail
/// is opt-in because a box that answers on `:25` for a domain whose `MX` points
/// elsewhere black-holes that domain's mail, a failure that is invisible until
/// someone's message never arrives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mail {
    /// This server's own FQDN, used in the EHLO/HELO and the SMTP banner, and the
    /// name every domain's `MX` points at. e.g. "mail.example.com".
    pub hostname: String,

    /// Domains this server accepts inbound mail for and may authenticate senders
    /// of. Every mailbox address must be local to one of these.
    pub domains: Vec<String>,

    /// The mailboxes that exist. Mail to a local address that is not one of these
    /// (nor one of their aliases) is refused at `RCPT` time, not stored — a
    /// black-holed message is worse than a bounce.
    #[serde(default)]
    pub mailboxes: Vec<Mailbox>,

    /// DKIM signing selector and key location. Absent → outbound mail is unsigned
    /// and no `_domainkey` record is published; the doctor warns, because unsigned
    /// mail is junked far more often.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dkim: Option<DkimConfig>,

    /// Outbound relay (smarthost). Present → submission goes through the relay
    /// when direct delivery is measured to be unusable from this network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<Relay>,

    /// The listener binds. Every field defaults to the standard mail port on
    /// `0.0.0.0`, so a bare `[mail]` binds all four correctly.
    #[serde(default)]
    pub bind: MailBind,

    /// Largest message accepted, in bytes. Announced in the ESMTP `SIZE`
    /// extension and enforced by the receiver. Defaults to 25 MiB.
    #[serde(default = "default_max_message")]
    pub max_message_bytes: u64,

    /// Refuse `AUTH` before `STARTTLS`, so a password never crosses the wire in
    /// the clear. Defaults to `true`; turn it off only for a local test.
    #[serde(default = "default_true")]
    pub require_tls_for_auth: bool,
}

impl Mail {
    /// Collects every structural problem with the mail configuration.
    ///
    /// `at` is the dotted path problems are reported under (`mail`). Every rule is
    /// checked and every violation collected, in the crate's all-at-once style, so
    /// one `selfhost check` names everything that needs fixing rather than the
    /// first thing.
    pub fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        if let Some(message) = fqdn_problem(&self.hostname) {
            problems.push(Problem { field: format!("{at}.hostname"), message });
        }

        if self.domains.is_empty() {
            problems.push(Problem {
                field: format!("{at}.domains"),
                message: "declare at least one domain, or this server accepts mail for nothing"
                    .into(),
            });
        }
        for (i, domain) in self.domains.iter().enumerate() {
            if let Some(message) = fqdn_problem(domain) {
                problems.push(Problem { field: format!("{at}.domains[{i}]"), message });
            }
        }

        for (i, mailbox) in self.mailboxes.iter().enumerate() {
            // A repeated address is ambiguous — which password authenticates
            // it, which one delivery lands in — so it is caught here rather
            // than left for the two mailboxes to silently race at runtime.
            let repeated = self.mailboxes[..i]
                .iter()
                .any(|earlier| earlier.address.eq_ignore_ascii_case(&mailbox.address));
            if repeated {
                problems.push(Problem {
                    field: format!("{at}.mailboxes[{i}].address"),
                    message: format!(
                        "\"{}\" is already claimed by an earlier mailbox",
                        mailbox.address
                    ),
                });
            }
            mailbox.check(&format!("{at}.mailboxes[{i}]"), &self.domains, problems);
        }

        for (label, bind) in [
            ("smtp", &self.bind.smtp),
            ("submission", &self.bind.submission),
            ("imap", &self.bind.imap),
            ("imaps", &self.bind.imaps),
        ] {
            if bind.parse::<SocketAddr>().is_err() {
                problems.push(Problem {
                    field: format!("{at}.bind.{label}"),
                    message: "must be a bindable address like 0.0.0.0:25".into(),
                });
            }
        }

        if let Some(dkim) = &self.dkim {
            dkim.check(&format!("{at}.dkim"), problems);
        }

        if let Some(relay) = &self.relay {
            relay.check(&format!("{at}.relay"), problems);
        }

        if self.max_message_bytes == 0 {
            problems.push(Problem {
                field: format!("{at}.max_message_bytes"),
                message: "must be at least 1; a zero limit would refuse every message".into(),
            });
        }
    }

    /// The four listener binds, parsed, for the firewall and the daemon.
    ///
    /// Returns each successfully-parsed bind paired with its role. A bind that
    /// does not parse is omitted — [`Mail::check`] has already reported it — so a
    /// caller opening firewall ports never has to re-handle a malformed address.
    pub fn socket_binds(&self) -> Vec<(&'static str, SocketAddr)> {
        [
            ("smtp", &self.bind.smtp),
            ("submission", &self.bind.submission),
            ("imap", &self.bind.imap),
            ("imaps", &self.bind.imaps),
        ]
        .into_iter()
        .filter_map(|(role, bind)| bind.parse::<SocketAddr>().ok().map(|address| (role, address)))
        .collect()
    }

    /// The DNS records this mail domain must publish, as [`RecordConfig`] so they
    /// flow through `dns::Zone::from_config` unchanged and print identically for
    /// an operator whose authoritative DNS lives elsewhere.
    ///
    /// One generator, two consumers (the served zone and the printed instructions)
    /// — so the two can never disagree about what to publish. Emits, for `domain`:
    ///
    /// - `MX` `@` → [`Mail::hostname`], preference 10 — mail is delivered here;
    /// - `TXT` `@` `"v=spf1 mx -all"` — only this host's `MX` may send as us;
    /// - `TXT` `_dmarc` `"v=DMARC1; p=reject; rua=mailto:postmaster@<domain>"` —
    ///   reject unaligned mail and report abuse to `postmaster`;
    /// - `TXT` `<selector>._domainkey` with `dkim_txt`, **only** when DKIM signing
    ///   is configured *and* the public key is supplied (a `_domainkey` record
    ///   with no live key behind it tells receivers to distrust our unsigned mail);
    /// - `CAA` `@` `"0 issue letsencrypt.org"` — only Let's Encrypt may issue the
    ///   certificate the mail host serves for STARTTLS.
    ///
    /// `dkim_txt` is the value from `mail::dkim::Dkim::public_txt()`; pass `None`
    /// when signing is not configured or the key has not been generated yet.
    pub fn dns_records(&self, domain: &str, dkim_txt: Option<&str>) -> Vec<RecordConfig> {
        let mut records = vec![
            RecordConfig {
                name: "@".into(),
                record_type: "MX".into(),
                ttl: default_ttl(),
                value: self.hostname.clone(),
                preference: Some(10),
            },
            txt("@", "v=spf1 mx -all"),
            txt("_dmarc", &format!("v=DMARC1; p=reject; rua=mailto:postmaster@{domain}")),
        ];

        // The DKIM record is published only when there is a key to stand behind
        // it. A selector without a live key is a promise of signed mail this box
        // is not keeping, and receivers penalise exactly that mismatch.
        if let (Some(dkim), Some(public)) = (&self.dkim, dkim_txt) {
            records.push(txt(&format!("{}._domainkey", dkim.selector), public));
        }

        records.push(RecordConfig {
            name: "@".into(),
            record_type: "CAA".into(),
            ttl: default_ttl(),
            value: "0 issue letsencrypt.org".into(),
            preference: None,
        });

        records
    }
}

/// One mailbox that exists on this server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mailbox {
    /// The full `local@domain` address. Its domain must be one of [`Mail::domains`].
    pub address: String,

    /// The password verifier — an Argon2 or scrypt hash, never a plaintext
    /// password. The daemon checks a submitted password against this; the config
    /// holds no reversible secret.
    pub password_hash: String,

    /// Extra addresses that deliver to this mailbox. Each must also be local to
    /// one of [`Mail::domains`].
    #[serde(default)]
    pub aliases: Vec<String>,
}

impl Mailbox {
    /// Collects every structural problem with this mailbox against its domains.
    fn check(&self, at: &str, domains: &[String], problems: &mut Vec<Problem>) {
        if let Some(message) = mailbox_problem(&self.address, domains) {
            problems.push(Problem { field: format!("{at}.address"), message });
        }
        if self.password_hash.trim().is_empty() {
            problems.push(Problem {
                field: format!("{at}.password_hash"),
                message: "must not be empty; store a password hash, never a plaintext password"
                    .into(),
            });
        }
        for (i, alias) in self.aliases.iter().enumerate() {
            if let Some(message) = mailbox_problem(alias, domains) {
                problems.push(Problem { field: format!("{at}.aliases[{i}]"), message });
            }
        }
    }
}

/// DKIM signing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimConfig {
    /// The selector, e.g. `"s1"`, published at `<selector>._domainkey.<domain>`.
    pub selector: String,
    /// PEM private key path under `data_dir`; generated on first run if missing.
    pub private_key: PathBuf,
}

impl DkimConfig {
    /// Collects every structural problem with the DKIM configuration.
    fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        // The selector is a DNS label; it becomes `<selector>._domainkey.<domain>`.
        if self.selector.is_empty() || self.selector.len() > MAX_LABEL {
            problems.push(Problem {
                field: format!("{at}.selector"),
                message: format!("must be 1..={MAX_LABEL} characters; it becomes a DNS label"),
            });
        } else if !self.selector.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            problems.push(Problem {
                field: format!("{at}.selector"),
                message: "may only contain letters, digits, and dash".into(),
            });
        }
        if self.private_key.as_os_str().is_empty() {
            problems.push(Problem {
                field: format!("{at}.private_key"),
                message: "must name a PEM key path under data_dir".into(),
            });
        }
    }
}

/// A smarthost for outbound mail when direct delivery is measured to be unusable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relay {
    /// The relay host, e.g. `"smtp.provider.com"`.
    pub host: String,
    /// The submission port, usually `587`.
    pub port: u16,
    /// The SASL username the relay authenticates.
    pub username: String,
    /// The SASL password. A relay credential is a shared secret the provider
    /// issues; unlike a mailbox it has no hashed form, so it is stored as given.
    pub password: String,
}

impl Relay {
    /// Collects every structural problem with the relay configuration.
    fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        if let Some(message) = fqdn_problem(&self.host) {
            problems.push(Problem { field: format!("{at}.host"), message });
        }
        if self.port == 0 {
            problems.push(Problem {
                field: format!("{at}.port"),
                message: "must be a real port, usually 587".into(),
            });
        }
        if self.username.is_empty() {
            problems.push(Problem {
                field: format!("{at}.username"),
                message: "a relay authenticates; give the username the provider issued".into(),
            });
        }
    }
}

/// Where the four mail servers bind. Each defaults to its standard port on
/// `0.0.0.0`, so a deployment writes a bind only to override one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailBind {
    /// Inbound SMTP from other mail servers. Standard `0.0.0.0:25`.
    #[serde(default = "default_smtp_bind")]
    pub smtp: String,
    /// Authenticated submission from this deployment's own users. `0.0.0.0:587`.
    #[serde(default = "default_submission_bind")]
    pub submission: String,
    /// IMAP with STARTTLS. `0.0.0.0:143`.
    #[serde(default = "default_imap_bind")]
    pub imap: String,
    /// Implicit-TLS IMAP. `0.0.0.0:993`.
    #[serde(default = "default_imaps_bind")]
    pub imaps: String,
}

impl Default for MailBind {
    fn default() -> Self {
        Self {
            smtp: default_smtp_bind(),
            submission: default_submission_bind(),
            imap: default_imap_bind(),
            imaps: default_imaps_bind(),
        }
    }
}

/// A `TXT` [`RecordConfig`] at `name` with `value`, at the default TTL.
fn txt(name: &str, value: &str) -> RecordConfig {
    RecordConfig {
        name: name.to_owned(),
        record_type: "TXT".into(),
        ttl: default_ttl(),
        value: value.to_owned(),
        preference: None,
    }
}

/// Why an address cannot serve as a mailbox on these domains, or `None` if it is
/// fine. Re-states the `mail::address` rules the receiver enforces at `RCPT` time,
/// so a config that would store mail nowhere fails at load rather than at delivery.
fn mailbox_problem(address: &str, domains: &[String]) -> Option<String> {
    let text = address.trim();
    if text.len() > MAX_ADDRESS {
        return Some(format!("is over {MAX_ADDRESS} characters"));
    }
    let Some((local, domain)) = text.rsplit_once('@') else {
        return Some("must be a full address of the form local@domain".into());
    };
    if local.is_empty() || local.len() > MAX_LOCAL {
        return Some(format!("the local part must be 1..={MAX_LOCAL} characters"));
    }
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Some("the local part has a leading, trailing, or doubled dot".into());
    }
    if local.contains('"') {
        return Some("quoted local parts are not supported".into());
    }
    if domain.is_empty() || domain.len() > MAX_DOMAIN {
        return Some(format!("the domain must be 1..={MAX_DOMAIN} characters"));
    }
    if fqdn_problem(domain).is_some() {
        return Some(format!("\"{domain}\" is not a valid domain"));
    }
    if !domains.iter().any(|d| d.eq_ignore_ascii_case(domain)) {
        return Some(format!(
            "\"{domain}\" is not one of this server's domains; a mailbox must be local to \
             mail.domains, or its mail would be relayed rather than stored"
        ));
    }
    None
}

/// Why a name cannot be used as a mail FQDN, or `None` if it is fine.
///
/// A mail hostname and a mail domain are both fully-qualified names that must
/// carry a dot — a bare label cannot receive internet mail — so the same check
/// serves the hostname, each domain, and the relay host.
fn fqdn_problem(name: &str) -> Option<String> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return Some("must not be empty".into());
    }
    if trimmed.len() > MAX_DOMAIN {
        return Some(format!("is {} bytes; a name may be at most {MAX_DOMAIN}", trimmed.len()));
    }
    if !trimmed.contains('.') {
        return Some(format!("\"{name}\" needs a dot; a bare label cannot receive internet mail"));
    }
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Some(format!("\"{name}\" has an empty label"));
        }
        if label.len() > MAX_LABEL {
            return Some(format!("label \"{label}\" is over {MAX_LABEL} bytes"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Some(format!("label \"{label}\" may not start or end with a dash"));
        }
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Some(format!("label \"{label}\" may only contain letters, digits, and dash"));
        }
    }
    None
}

fn default_smtp_bind() -> String {
    "0.0.0.0:25".to_owned()
}

fn default_submission_bind() -> String {
    "0.0.0.0:587".to_owned()
}

fn default_imap_bind() -> String {
    "0.0.0.0:143".to_owned()
}

fn default_imaps_bind() -> String {
    "0.0.0.0:993".to_owned()
}

/// 25 MiB — the de-facto ceiling most receivers accept, so a message this server
/// takes is one the wider network will too.
fn default_max_message() -> u64 {
    25 * 1024 * 1024
}

fn default_ttl() -> u32 {
    3600
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Config;

    /// Parses a config and returns its validation problems, or an empty vec.
    fn problems_of(text: &str) -> Vec<Problem> {
        match Config::parse(text) {
            Ok(_) => Vec::new(),
            Err(crate::ConfigError::Invalid(problems)) => problems,
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    /// A valid deployment with the given `[mail]` body appended.
    fn config_with_mail(mail_body: &str) -> String {
        format!(
            r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "a"
domains = ["example.com"]
static_root = "./public"

{mail_body}
"#
        )
    }

    #[test]
    fn a_bare_mail_section_binds_the_standard_ports() {
        let text = config_with_mail(
            r#"
[mail]
hostname = "mail.example.com"
domains = ["example.com"]
"#,
        );
        let config = Config::parse(&text).expect("valid");
        let mail = config.mail.expect("mail present");
        assert_eq!(mail.bind.smtp, "0.0.0.0:25");
        assert_eq!(mail.bind.submission, "0.0.0.0:587");
        assert_eq!(mail.bind.imap, "0.0.0.0:143");
        assert_eq!(mail.bind.imaps, "0.0.0.0:993");
        assert_eq!(mail.max_message_bytes, 25 * 1024 * 1024);
        assert!(mail.require_tls_for_auth, "TLS-before-AUTH defaults on");
    }

    #[test]
    fn a_config_without_a_mail_section_serves_no_mail() {
        let config = Config::parse(&config_with_mail("")).expect("valid");
        assert!(config.mail.is_none(), "mail is opt-in");
    }

    #[test]
    fn a_full_mail_section_with_mailboxes_and_dkim_parses() {
        let text = config_with_mail(
            r#"
[mail]
hostname = "mail.example.com"
domains = ["example.com"]

[mail.dkim]
selector = "s1"
private_key = "dkim/example.com.pem"

  [[mail.mailboxes]]
  address = "dave@example.com"
  password_hash = "$argon2id$v=19$m=65536,t=3,p=4$abc$def"
  aliases = ["postmaster@example.com"]
"#,
        );
        let config = Config::parse(&text).expect("valid");
        let mail = config.mail.expect("mail present");
        assert_eq!(mail.mailboxes.len(), 1);
        assert_eq!(mail.dkim.as_ref().unwrap().selector, "s1");
    }

    #[test]
    fn rejects_a_mailbox_whose_domain_is_not_one_of_ours() {
        // The single biggest divergence risk: storing mail for a domain we do not
        // own. A mailbox must be local to mail.domains or its mail would be
        // relayed, not stored.
        let problems = problems_of(&config_with_mail(
            r#"
[mail]
hostname = "mail.example.com"
domains = ["example.com"]

  [[mail.mailboxes]]
  address = "dave@elsewhere.net"
  password_hash = "x"
"#,
        ));
        assert!(
            problems.iter().any(|p| p.field == "mail.mailboxes[0].address"),
            "{problems:?}"
        );
    }

    #[test]
    fn rejects_two_mailboxes_claiming_the_same_address() {
        // Which password authenticates it? Which one delivery lands in? An
        // address must belong to exactly one mailbox.
        let problems = problems_of(&config_with_mail(
            r#"
[mail]
hostname = "mail.example.com"
domains = ["example.com"]

  [[mail.mailboxes]]
  address = "dave@example.com"
  password_hash = "x"

  [[mail.mailboxes]]
  address = "DAVE@example.com"
  password_hash = "y"
"#,
        ));
        assert!(
            problems.iter().any(|p| p.field == "mail.mailboxes[1].address"),
            "{problems:?}"
        );
    }

    #[test]
    fn rejects_a_plaintext_looking_empty_hash_and_a_bad_bind() {
        let problems = problems_of(&config_with_mail(
            r#"
[mail]
hostname = "mail.example.com"
domains = ["example.com"]

[mail.bind]
smtp = "25"

  [[mail.mailboxes]]
  address = "dave@example.com"
  password_hash = "   "
"#,
        ));
        assert!(problems.iter().any(|p| p.field == "mail.bind.smtp"), "{problems:?}");
        assert!(
            problems.iter().any(|p| p.field == "mail.mailboxes[0].password_hash"),
            "{problems:?}"
        );
    }

    #[test]
    fn rejects_a_hostname_that_is_a_bare_label() {
        let problems = problems_of(&config_with_mail(
            r#"
[mail]
hostname = "mail"
domains = ["example.com"]
"#,
        ));
        assert!(problems.iter().any(|p| p.field == "mail.hostname"), "{problems:?}");
    }

    #[test]
    fn rejects_a_dkim_selector_that_is_not_a_dns_label() {
        let problems = problems_of(&config_with_mail(
            r#"
[mail]
hostname = "mail.example.com"
domains = ["example.com"]

[mail.dkim]
selector = "not a label"
private_key = "dkim/k.pem"
"#,
        ));
        assert!(problems.iter().any(|p| p.field == "mail.dkim.selector"), "{problems:?}");
    }

    #[test]
    fn reports_every_problem_at_once_not_just_the_first() {
        let problems = problems_of(&config_with_mail(
            r#"
[mail]
hostname = "mail"
domains = ["example.com"]

[mail.bind]
imap = "nope"

  [[mail.mailboxes]]
  address = "not-an-address"
  password_hash = ""
"#,
        ));
        assert!(problems.len() >= 4, "expected several problems, got {problems:?}");
    }

    #[test]
    fn generates_the_exact_records_a_mail_domain_must_publish() {
        let mail = Mail {
            hostname: "mail.example.com".into(),
            domains: vec!["example.com".into()],
            mailboxes: vec![],
            dkim: Some(DkimConfig { selector: "s1".into(), private_key: "k.pem".into() }),
            relay: None,
            bind: MailBind::default(),
            max_message_bytes: default_max_message(),
            require_tls_for_auth: true,
        };
        let records = mail.dns_records("example.com", Some("v=DKIM1; k=rsa; p=AAAA"));

        let mx = records.iter().find(|r| r.record_type == "MX").expect("an MX");
        assert_eq!(mx.name, "@");
        assert_eq!(mx.value, "mail.example.com");
        assert_eq!(mx.preference, Some(10));

        assert!(
            records.iter().any(|r| r.name == "@" && r.value == "v=spf1 mx -all"),
            "SPF at the apex"
        );
        assert!(
            records
                .iter()
                .any(|r| r.name == "_dmarc" && r.value.contains("p=reject")
                    && r.value.contains("postmaster@example.com")),
            "a rejecting DMARC naming postmaster"
        );
        assert!(
            records
                .iter()
                .any(|r| r.name == "s1._domainkey" && r.value == "v=DKIM1; k=rsa; p=AAAA"),
            "the DKIM public key at the selector"
        );
        assert!(
            records
                .iter()
                .any(|r| r.record_type == "CAA" && r.value == "0 issue letsencrypt.org"),
            "a Let's Encrypt CAA"
        );
    }

    #[test]
    fn omits_the_dkim_record_when_no_key_is_supplied() {
        // A _domainkey record with no live key behind it tells receivers to
        // distrust our unsigned mail. It is published only when both the selector
        // is configured and the public key is available.
        let mail = Mail {
            hostname: "mail.example.com".into(),
            domains: vec!["example.com".into()],
            mailboxes: vec![],
            dkim: Some(DkimConfig { selector: "s1".into(), private_key: "k.pem".into() }),
            relay: None,
            bind: MailBind::default(),
            max_message_bytes: default_max_message(),
            require_tls_for_auth: true,
        };
        let records = mail.dns_records("example.com", None);
        assert!(
            !records.iter().any(|r| r.name.ends_with("._domainkey")),
            "no DKIM record without a key: {records:?}"
        );
    }

    #[test]
    fn the_generated_records_are_valid_config_records() {
        // The generator's output must pass the record validation it will later
        // flow through, or the served zone and the printed instructions could
        // carry a record dns::Zone::from_config silently drops.
        let mail = Mail {
            hostname: "mail.example.com".into(),
            domains: vec!["example.com".into()],
            mailboxes: vec![],
            dkim: Some(DkimConfig { selector: "s1".into(), private_key: "k.pem".into() }),
            relay: None,
            bind: MailBind::default(),
            max_message_bytes: default_max_message(),
            require_tls_for_auth: true,
        };
        let text = toml_zone_with(mail.dns_records("example.com", Some("v=DKIM1; p=AAAA")));
        assert!(Config::parse(&text).is_ok(), "generated records should validate:\n{text}");
    }

    /// Renders records into a `[dns]` zone so the config validator checks them.
    fn toml_zone_with(records: Vec<RecordConfig>) -> String {
        let mut body = String::from(
            r#"
[dns]

[[dns.zone]]
domain = "example.com"
"#,
        );
        for record in records {
            body.push_str("\n  [[dns.zone.record]]\n");
            body.push_str(&format!("  name = \"{}\"\n", record.name));
            body.push_str(&format!("  type = \"{}\"\n", record.record_type));
            body.push_str(&format!("  value = \"{}\"\n", record.value.replace('"', "\\\"")));
            if let Some(preference) = record.preference {
                body.push_str(&format!("  preference = {preference}\n"));
            }
        }
        format!(
            r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "a"
domains = ["example.com"]
static_root = "./public"
{body}
"#
        )
    }
}
