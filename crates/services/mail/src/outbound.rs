//! The outbound send path: sign, route, and deliver a spooled message.
//!
//! This is where the pieces meet. A message leaves [`crate::client::OutboundQueue`],
//! is DKIM-signed for its sender domain, routed to each recipient domain's mail
//! exchangers via [`crate::client::mx_delivery_order`] over the DNS resolver, and
//! handed to [`crate::client::deliver_to_host`]. When a relay (smarthost) is
//! configured it is used instead of direct MX delivery — one authenticated
//! connection carries every recipient — which is the path a server on blocklisted
//! or PTR-mismatched IP space must take to be accepted at all.
//!
//! Signing lives here, at send time, rather than at submission: the `t=` stamp is
//! then the moment of sending, and a message re-tried after a restart is signed
//! exactly once, when it actually goes out.

use crate::client::{deliver_to_host, mx_delivery_order, Delivery, QueuedMessage, SmtpClient};
use crate::dkim::Dkim;
use crate::message::Message;
use crate::smtp::Envelope;
use selfhost_config::Relay;
use selfhost_dns::Resolver;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_rustls::TlsConnector;

/// The DKIM key and selector to sign outbound mail with.
pub struct SigningIdentity<'a> {
    /// The loaded signing key.
    pub dkim: &'a Dkim,
    /// The selector published at `<selector>._domainkey.<domain>`.
    pub selector: &'a str,
}

/// Everything the send path needs that is not the message itself.
///
/// Borrowed so one set of collaborators (resolver, key, TLS connector) serves
/// every message the queue runner processes, assembled once by the daemon.
pub struct SendContext<'a> {
    /// The DNS resolver used for MX lookup.
    pub resolver: &'a Resolver,
    /// The HELO name this server announces when sending.
    pub helo: &'a str,
    /// The DKIM identity, or `None` to send unsigned (doctor warns).
    pub signing: Option<SigningIdentity<'a>>,
    /// A TLS connector for opportunistic STARTTLS on outbound connections.
    pub tls: Option<&'a TlsConnector>,
    /// A relay to send through instead of direct MX delivery, when present.
    pub relay: Option<&'a Relay>,
}

/// The outcome of attempting to deliver one message to every destination.
#[derive(Debug)]
pub struct SendReport {
    /// Per destination (a recipient domain, or `"relay"`), the delivery result.
    pub results: Vec<(String, Result<Delivery, String>)>,
}

impl SendReport {
    /// Whether every destination accepted the message.
    pub fn all_delivered(&self) -> bool {
        !self.results.is_empty() && self.results.iter().all(|(_, r)| r.is_ok())
    }
}

/// Signs, routes, and delivers one queued message.
///
/// Returns a per-destination report; the caller (the queue runner) decides from
/// it whether to remove the message from the spool or leave it for a retry. A
/// destination that permanently refuses and one that is merely deferred both
/// surface here as an `Err` with the reason, so retry policy stays the caller's.
pub async fn deliver(context: &SendContext<'_>, queued: &QueuedMessage) -> SendReport {
    let message = sign(context, queued);
    let envelope = Envelope {
        sender: queued.sender.clone(),
        recipients: queued.recipients.clone(),
        helo: queued.helo.clone(),
    };

    if let Some(relay) = context.relay {
        return deliver_via_relay(context, relay, &envelope, &message).await;
    }
    deliver_direct(context, &envelope, &message).await
}

/// DKIM-signs the message for the sender's domain, if a signing identity is set.
///
/// A null sender (a bounce) has no domain to sign for and is sent as-is; a bounce
/// is never signed or relayed, honouring the null-path rules in [`crate::address`].
fn sign(context: &SendContext<'_>, queued: &QueuedMessage) -> Message {
    let (Some(identity), Some(sender)) = (&context.signing, queued.sender.address()) else {
        return queued.message.clone();
    };
    match identity.dkim.sign(&queued.message, sender.domain(), identity.selector, now_secs()) {
        Ok(value) => queued.message.with_prepended_header("DKIM-Signature", &value),
        // A signing failure must not silently send unsigned mail as if signed;
        // send unsigned and let the far end's DKIM result (and doctor) show it.
        Err(_) => queued.message.clone(),
    }
}

/// Delivers directly to each recipient domain's mail exchangers.
async fn deliver_direct(context: &SendContext<'_>, envelope: &Envelope, message: &Message) -> SendReport {
    let mut results = Vec::new();
    for domain in distinct_domains(envelope) {
        let result = deliver_to_domain(context, envelope, message, &domain).await;
        results.push((domain, result));
    }
    SendReport { results }
}

/// Tries a domain's MX hosts in order until one accepts the message.
async fn deliver_to_domain(
    context: &SendContext<'_>,
    envelope: &Envelope,
    message: &Message,
    domain: &str,
) -> Result<Delivery, String> {
    let mx = context.resolver.lookup_mx(domain).await.unwrap_or_default();
    let hosts = mx_delivery_order(&mx, domain);

    let mut last_error = String::from("no hosts to try");
    for host in hosts {
        let mut client = SmtpClient::for_domain(envelope, domain, context.helo);
        if context.tls.is_some() {
            client = client.with_starttls();
        }
        match deliver_to_host(&host, 25, &mut client, message.as_bytes(), context.tls).await {
            Ok(delivery) => return Ok(delivery),
            Err(error) => last_error = format!("{host}: {error}"),
        }
    }
    Err(last_error)
}

/// Delivers every recipient through the configured relay in one connection.
async fn deliver_via_relay(
    context: &SendContext<'_>,
    relay: &Relay,
    envelope: &Envelope,
    message: &Message,
) -> SendReport {
    let recipients = envelope.recipients.iter().map(|a| a.to_string()).collect();
    let mut client = SmtpClient::new(context.helo, envelope.sender.to_string(), recipients)
        .with_relay_auth(relay.username.clone(), relay.password.clone());

    let result = deliver_to_host(&relay.host, relay.port, &mut client, message.as_bytes(), context.tls)
        .await
        .map_err(|error| format!("relay {}: {error}", relay.host));
    SendReport { results: vec![("relay".to_owned(), result)] }
}

/// The distinct recipient domains of an envelope, each a separate destination.
fn distinct_domains(envelope: &Envelope) -> Vec<String> {
    let mut domains: Vec<String> = Vec::new();
    for recipient in &envelope.recipients {
        let domain = recipient.domain().to_owned();
        if !domains.contains(&domain) {
            domains.push(domain);
        }
    }
    domains
}

/// The current Unix time in seconds, for the DKIM `t=` tag.
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, Path};

    fn envelope(recipients: &[&str]) -> Envelope {
        Envelope {
            sender: Path::parse("<dave@example.com>").unwrap(),
            recipients: recipients.iter().map(|r| Address::parse(r).unwrap()).collect(),
            helo: "mail.example.com".into(),
        }
    }

    #[test]
    fn distinct_domains_groups_recipients_by_destination() {
        let env = envelope(&["a@x.com", "b@x.com", "c@y.com"]);
        assert_eq!(distinct_domains(&env), vec!["x.com", "y.com"]);
    }

    #[test]
    fn a_send_report_is_delivered_only_when_every_destination_succeeded() {
        let ok = Delivery { accepted: vec!["a@x.com".into()], rejected: vec![], last_code: 250 };
        let delivered = SendReport { results: vec![("x.com".into(), Ok(ok.clone()))] };
        assert!(delivered.all_delivered());

        let mixed = SendReport {
            results: vec![("x.com".into(), Ok(ok)), ("y.com".into(), Err("deferred".into()))],
        };
        assert!(!mixed.all_delivered());
        assert!(!SendReport { results: vec![] }.all_delivered());
    }
}
