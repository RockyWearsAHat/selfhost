//! What an authenticated EWS/ActiveSync request needs beyond its own bytes.

use crate::address::{Address, Path};
use crate::client::OutboundQueue;
use crate::dkim::b64_decode;
use crate::message::Message;
use crate::smtp::Envelope;
use crate::store::Maildir;
use crate::submission::Authenticator;
use std::path::Path as FsPath;

/// The shared store and this deployment's outbound identity.
///
/// Built by the proxy from the same `Maildir`/`Authenticator` handles
/// `mail_task`'s own SMTP/IMAP listeners share (see
/// `selfhost_proxy::Server::attach_mail`) plus the `[mail]` config it was
/// constructed from, and borrowed fresh for every request rather than cached
/// per-connection — a `Context` is cheap to build (four borrows) and never
/// outlives the request that built it.
pub struct Context<'a> {
    /// The one shared Maildir — see the module-level "one shared instance"
    /// invariant `selfhost_mail::store` documents.
    pub maildir: &'a Maildir,
    /// Where `OutboundQueue::open` finds the spool — the same directory
    /// `mail_task`'s outbound sweep already drains, so a message spooled here
    /// is delivered by the sweep that is already running, not a second one.
    pub data_dir: &'a FsPath,
    /// This deployment's SMTP identity, used as the `HELO` name on a message
    /// composed via EWS/ActiveSync rather than submitted over SMTP itself.
    pub hostname: &'a str,
    /// Domains this deployment delivers locally — the same list
    /// `crate::submission` partitions a submitted message's recipients
    /// against.
    pub local_domains: &'a [String],
}

/// Sends a composed message on behalf of `mailbox`: local recipients are
/// delivered straight into their own mailbox, remote recipients are spooled
/// to the outbound queue `mail_task`'s own sweep already drains — the exact
/// split `crate::submission::read_and_enqueue` applies to a client's own
/// `MAIL`/`RCPT TO`, reused here so the open-relay rule stays enforced in
/// exactly the one place its own module doc promises: nothing here decides
/// *whether* to relay, only *where* recipients already resolved to.
///
/// `recipients` is every To/Cc/Bcc address the composed message named. An
/// empty list is not an error — the caller decides whether that is
/// meaningful (EWS `CreateItem` may only be saving a draft).
pub async fn send(
    ctx: &Context<'_>,
    mailbox: &Address,
    recipients: Vec<Address>,
    message: &Message,
) -> std::io::Result<()> {
    let (local, remote): (Vec<Address>, Vec<Address>) =
        recipients.into_iter().partition(|recipient| recipient.is_local_to(ctx.local_domains));

    let mut mailboxes: Vec<Address> = Vec::new();
    for recipient in &local {
        if let Some(target) = ctx.maildir.resolve(recipient).cloned() {
            if !mailboxes.contains(&target) {
                mailboxes.push(target);
            }
        }
    }
    for target in &mailboxes {
        ctx.maildir.deliver(target, message).await.map_err(std::io::Error::other)?;
    }

    if !remote.is_empty() {
        let queue = OutboundQueue::open(ctx.data_dir)?;
        let envelope =
            Envelope { sender: Path::Mailbox(mailbox.clone()), recipients: remote, helo: ctx.hostname.to_owned() };
        queue.enqueue(&envelope, message)?;
    }
    Ok(())
}

/// The To/Cc/Bcc addresses a composed message names, parsed from its own
/// headers rather than any structured recipient elements a request also
/// carried (EWS `<t:ToRecipients>`, an ActiveSync `SendMail` has none at
/// all) — the raw MIME a client sends is the authoritative record of what
/// it is sending, so reading recipients from the same place reading the
/// body does keeps the two from ever disagreeing. Shared by
/// `crate::ews::create_item` and `crate::eas::send_mail_response`, the two
/// operations that turn a composed message into an actual send.
pub fn recipients_from_message(message: &Message) -> Vec<Address> {
    let mut recipients = Vec::new();
    for name in ["to", "cc", "bcc"] {
        for header in message.headers(name) {
            for candidate in header.split(',') {
                if let Some(address) = address_in_header_value(candidate) {
                    if !recipients.contains(&address) {
                        recipients.push(address);
                    }
                }
            }
        }
    }
    recipients
}

/// Extracts the address from one `To`/`Cc`/`Bcc` header entry, which may be a
/// bare address or `"Display Name" <address>`. A best-effort reading — real
/// RFC 5322 address lists allow a comma inside a quoted display name, which
/// this simple comma-split does not honour — acceptable here because a
/// misread entry is simply skipped (an address that fails to parse), never
/// silently misdelivered to the wrong mailbox.
fn address_in_header_value(value: &str) -> Option<Address> {
    let value = value.trim();
    let candidate = match (value.find('<'), value.find('>')) {
        (Some(start), Some(end)) if start < end => &value[start + 1..end],
        _ => value,
    };
    Address::parse(candidate.trim()).ok()
}

/// Verifies an HTTP `Authorization: Basic base64(user:pass)` header against
/// `authenticator` — the exact PBKDF2 check IMAP/submission already trust,
/// reused here rather than duplicated so EWS/ActiveSync create no second
/// trust boundary: a stolen mailbox password reads no more through either
/// than it already could over IMAP.
///
/// `None` for a missing header, a non-`Basic` scheme, malformed base64, a
/// colon-less decoded value, or a wrong password — deliberately one outcome
/// for all of them, the same "wrong name or wrong password looks identical"
/// posture [`Authenticator::verify`] itself documents, so a caller that
/// turns this into `401` cannot leak which reason applied.
pub fn authenticate_basic(header: Option<&str>, authenticator: &dyn Authenticator) -> Option<Address> {
    let encoded = header?.strip_prefix("Basic ")?;
    let decoded = b64_decode(encoded.trim()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (username, password) = text.split_once(':')?;
    authenticator.verify(username, password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::submission::ConfigAuthenticator;
    use selfhost_config::Mailbox;

    fn authenticator() -> ConfigAuthenticator {
        ConfigAuthenticator::new(&[Mailbox {
            address: "dave@example.com".to_owned(),
            password_hash: crate::submission::hash_password("s3cret").unwrap(),
            aliases: vec![],
        }])
    }

    fn basic_header(user: &str, pass: &str) -> String {
        format!("Basic {}", crate::dkim::b64_encode(format!("{user}:{pass}").as_bytes()))
    }

    #[test]
    fn a_correct_basic_header_authenticates_to_its_address() {
        let auth = authenticator();
        let header = basic_header("dave@example.com", "s3cret");
        let mailbox = authenticate_basic(Some(&header), &auth);
        assert_eq!(mailbox, Some(Address::parse("dave@example.com").unwrap()));
    }

    #[test]
    fn a_wrong_password_is_refused() {
        let auth = authenticator();
        let header = basic_header("dave@example.com", "wrong");
        assert_eq!(authenticate_basic(Some(&header), &auth), None);
    }

    #[test]
    fn a_missing_header_is_refused() {
        assert_eq!(authenticate_basic(None, &authenticator()), None);
    }

    #[test]
    fn a_non_basic_scheme_is_refused() {
        assert_eq!(authenticate_basic(Some("Bearer sometoken"), &authenticator()), None);
    }
}
