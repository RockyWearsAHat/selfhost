//! Confirming that an account's email address is reachable, and telling it so.
//!
//! # The token is mirrored from the invite door
//!
//! [`Verifications`] is `crates/admin/src/invite.rs::Invites` with the name changed: a
//! high-entropy token, stored only as its SHA-256 digest, single-use, expiring on its own, and
//! superseded rather than duplicated when minted again for the same account. The reasoning is
//! identical — a backup of this box's data directory must not be a set of live "confirm this
//! email" links any more than it should be a set of live invitations — so it is copied rather
//! than generalised into a shared abstraction two call sites do not yet justify.
//!
//! # Sending is enqueuing, not delivering
//!
//! This crate does not speak SMTP to the outside world and does not want to: DKIM signing, MX
//! resolution, and relay policy already live in `selfhost_mail::outbound`, driven by the daemon
//! process that already has a DNS resolver and a signing key loaded. What this module does is
//! write one file into `<data_dir>/mail/queue` — the same spool `selfhost_mail::client::
//! OutboundQueue` and the daemon's own outbound sweep already agree on — so a verification email
//! is delivered by the same path any other outbound message on this box takes, including its
//! retry policy. `crate::notify`, by contrast, submits straight to loopback SMTP because it is
//! addressing a mailbox *this box hosts*; a verification email is addressed to a stranger's
//! inbox, which is exactly the outbound case that module's own documentation says is out of
//! scope for it.

use ring::digest;
use ring::rand::{SecureRandom, SystemRandom};
use selfhost_json::Json;
use selfhost_mail::{Address, Envelope, Message, OutboundQueue, Path as MailPath};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// The name of the verification-token file inside `<data_dir>/reports/`.
pub const VERIFY_FILENAME: &str = "verify.json";

/// How long a verification link stays live. Three days: long enough that a link waiting in an
/// inbox over a weekend still works, short enough that a stale link is not a permanent door.
pub const TOKEN_TTL_SECS: u64 = 3 * 24 * 60 * 60;

/// The most outstanding verification tokens held at once.
pub const MAX_PENDING: usize = 20_000;

/// Bytes of entropy in a token: 192 bits, the same size `crates/admin/src/invite.rs` uses.
const TOKEN_BYTES: usize = 24;

/// One outstanding verification.
struct Pending {
    account_id: String,
    digest: Vec<u8>,
    expires_unix: u64,
}

/// The durable verification-token store.
#[derive(Clone)]
pub struct Verifications {
    path: PathBuf,
    entries: Arc<Mutex<Vec<Pending>>>,
}

impl Verifications {
    /// Loads the store. A missing or malformed file loads empty, failing closed: no stale token
    /// resurrects a live one it never had.
    pub fn load(data_dir: &Path) -> Self {
        let path = Self::path_in(data_dir);
        let entries = match std::fs::read_to_string(&path) {
            Ok(text) => parse(&text).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        Self {
            path,
            entries: Arc::new(Mutex::new(entries)),
        }
    }

    /// Where the verification file lives for a given data directory.
    #[must_use]
    pub fn path_in(data_dir: &Path) -> PathBuf {
        data_dir.join(VERIFY_FILENAME)
    }

    /// Mints a token for `account_id`, superseding any outstanding one for the same account.
    ///
    /// # Errors
    /// An [`io::Error`] naming what the random source or the write refused.
    pub fn mint(&self, account_id: &str) -> io::Result<String> {
        let mut bytes = [0u8; TOKEN_BYTES];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| io::Error::other("the system random source was unavailable"))?;
        let token = crate::oauth::b64url_encode(&bytes);
        let now = now_unix();
        let mut entries = self.lock();
        entries.retain(|entry| entry.account_id != account_id && entry.expires_unix > now);
        if entries.len() >= MAX_PENDING {
            return Err(io::Error::other(format!(
                "at most {MAX_PENDING} verification links may be outstanding at once"
            )));
        }
        entries.push(Pending {
            account_id: account_id.to_string(),
            digest: sha256(&token),
            expires_unix: now.saturating_add(TOKEN_TTL_SECS),
        });
        self.persist(&entries)?;
        Ok(token)
    }

    /// Redeems `token`, returning the account it verifies; `None` for anything unknown, expired,
    /// or already used. Single-use and constant-time, like every credential lookup in this
    /// crate; the walk visits every entry rather than short-circuiting.
    pub fn redeem(&self, token: &str) -> Option<String> {
        let presented = sha256(token);
        let now = now_unix();
        let mut entries = self.lock();
        let mut found = None;
        entries.retain(|entry| {
            let hit = entry.expires_unix > now && constant_time_eq(&entry.digest, &presented);
            if hit {
                found = Some(entry.account_id.clone());
            }
            !hit
        });
        if found.is_some() {
            let _ = self.persist(&entries);
        }
        found
    }

    fn persist(&self, entries: &[Pending]) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = to_json(entries).to_text();
        let temporary = self.path.with_extension("json.tmp");
        std::fs::write(&temporary, &text)?;
        restrict(&temporary);
        std::fs::rename(&temporary, &self.path)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Pending>> {
        self.entries
            .lock()
            .expect("the verification store lock was poisoned")
    }
}

impl std::fmt::Debug for Verifications {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "Verifications({} outstanding)", self.lock().len())
    }
}

/// Builds and spools a "confirm your email" message addressed to `to`.
///
/// `verify_url` is built entirely from server-controlled values — the configured base URL and a
/// random token — so nothing here needs the header-injection cleaning `crate::report::one_line`
/// gives a reporter's own text; there is no reporter's text in this message.
///
/// # Errors
/// A sentence naming what could not be spooled: `from`/`to` not parsing as addresses, or the
/// queue's own write failing.
pub fn send_verification(
    queue: &OutboundQueue,
    from: &str,
    to: &str,
    helo: &str,
    site_name: &str,
    verify_url: &str,
) -> Result<String, String> {
    let sender =
        Address::parse(from).map_err(|error| format!("`{from}` is not an address: {error}"))?;
    let recipient =
        Address::parse(to).map_err(|error| format!("`{to}` is not an address: {error}"))?;
    let envelope = Envelope {
        sender: MailPath::Mailbox(sender.clone()),
        recipients: vec![recipient.clone()],
        helo: helo.to_string(),
    };
    let raw = message(
        &sender,
        &recipient,
        site_name,
        verify_url,
        SystemTime::now(),
    );
    let message = Message::parse(raw).map_err(|error| format!("{error:?}"))?;
    queue
        .enqueue(&envelope, &message)
        .map_err(|error| format!("could not spool the verification email: {error}"))
}

/// The RFC 5322 bytes for a verification message.
fn message(
    from: &Address,
    to: &Address,
    site_name: &str,
    verify_url: &str,
    now: SystemTime,
) -> Vec<u8> {
    let stamp = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let domain = from.domain();
    let mut head = String::new();
    head.push_str(&format!("Date: {}\r\n", crate::clock::rfc5322(now)));
    head.push_str(&format!("From: {site_name} <{from}>\r\n"));
    head.push_str(&format!("To: <{to}>\r\n"));
    head.push_str(&format!("Subject: Confirm your email for {site_name}\r\n"));
    head.push_str(&format!("Message-ID: <verify-{stamp}@{domain}>\r\n"));
    head.push_str("MIME-Version: 1.0\r\n");
    head.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    head.push_str("Content-Transfer-Encoding: 8bit\r\n");
    head.push_str("Auto-Submitted: auto-generated\r\n");
    head.push_str("\r\n");

    let mut body = String::new();
    body.push_str(&format!(
        "Confirm this address for your {site_name} account:\r\n\r\n"
    ));
    body.push_str(verify_url);
    body.push_str("\r\n\r\nThis link works once and stops working in three days.\r\n");
    body.push_str(
        "If you did not request this, nothing happens until it is clicked — ignore it.\r\n",
    );

    let mut out = head.into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

fn sha256(text: &str) -> Vec<u8> {
    digest::digest(&digest::SHA256, text.as_bytes())
        .as_ref()
        .to_vec()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |differences, (a, b)| differences | (a ^ b))
        == 0
}

fn restrict(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

fn to_json(entries: &[Pending]) -> Json {
    Json::object([(
        "pending",
        Json::array(entries.iter().map(|entry| {
            Json::object([
                ("accountId", Json::string(&entry.account_id)),
                (
                    "digest",
                    Json::string(crate::oauth::b64url_encode(&entry.digest)),
                ),
                ("expiresUnix", Json::Number(entry.expires_unix as f64)),
            ])
        })),
    )])
}

fn parse(text: &str) -> Option<Vec<Pending>> {
    let value = selfhost_json::parse(text).ok()?;
    let items = value.get("pending")?.as_array()?;
    let mut entries = Vec::new();
    for item in items {
        entries.push(Pending {
            account_id: item.get("accountId")?.as_str()?.to_owned(),
            digest: crate::oauth::b64url_decode(item.get("digest")?.as_str()?)?,
            expires_unix: item.get("expiresUnix")?.as_u64()?,
        });
    }
    Some(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "selfhost-reports-verify-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn a_minted_token_redeems_once_and_names_its_account() {
        let dir = scratch("redeem");
        let verifications = Verifications::load(&dir);
        let token = verifications.mint("acct-1").expect("mints");
        assert_eq!(verifications.redeem(&token), Some("acct-1".to_string()));
        assert_eq!(verifications.redeem(&token), None, "single-use");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_token_is_not_in_the_file_that_records_it() {
        let dir = scratch("digest-only");
        let token = Verifications::load(&dir).mint("acct-1").expect("mints");
        let stored = std::fs::read_to_string(Verifications::path_in(&dir)).expect("file");
        assert!(!stored.contains(&token));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn re_minting_for_the_same_account_supersedes_the_first_token() {
        let dir = scratch("supersede");
        let verifications = Verifications::load(&dir);
        let first = verifications.mint("acct-1").expect("mints");
        let second = verifications.mint("acct-1").expect("mints again");
        assert_eq!(
            verifications.redeem(&first),
            None,
            "the first token is dead"
        );
        assert_eq!(verifications.redeem(&second), Some("acct-1".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_unknown_token_redeems_nothing() {
        let dir = scratch("unknown");
        let verifications = Verifications::load(&dir);
        assert_eq!(verifications.redeem("not-a-real-token"), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tokens_survive_a_reload_from_disk() {
        let dir = scratch("reload");
        let token = Verifications::load(&dir).mint("acct-1").expect("mints");
        assert_eq!(
            Verifications::load(&dir).redeem(&token),
            Some("acct-1".to_string())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_message_carries_the_link_and_no_header_break() {
        let from = Address::parse("reports@example.com").unwrap();
        let to = Address::parse("alex@example.com").unwrap();
        let raw = message(
            &from,
            &to,
            "dx reports",
            "https://box.example/report/verify?token=abc123",
            UNIX_EPOCH,
        );
        let text = String::from_utf8(raw).unwrap();
        assert!(text.contains("Subject: Confirm your email for dx reports\r\n"));
        assert!(text.contains("https://box.example/report/verify?token=abc123"));
        assert!(text.contains("\r\n\r\n"), "the head ends with a blank line");
    }

    #[test]
    fn sending_spools_into_the_outbound_queue() {
        let dir = scratch("send");
        let queue = OutboundQueue::open(&dir).expect("queue");
        let id = send_verification(
            &queue,
            "reports@example.com",
            "alex@example.com",
            "example.com",
            "dx reports",
            "https://box.example/report/verify?token=abc123",
        )
        .expect("spooled");
        assert!(!id.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_bad_address_is_refused_before_anything_is_spooled() {
        let dir = scratch("bad-address");
        let queue = OutboundQueue::open(&dir).expect("queue");
        let error = send_verification(
            &queue,
            "reports@example.com",
            "not an address",
            "example.com",
            "dx reports",
            "https://box.example/report/verify?token=abc123",
        )
        .expect_err("refused");
        assert!(error.contains("is not an address"), "{error}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
