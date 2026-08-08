//! The shared Maildir store — the one place every accepted message lands.
//!
//! Maildir is chosen for one property: delivery is a rename, not a lock. The
//! receiver writes a message into `tmp/`, fsyncs it, then renames it into
//! `new/`; a rename within a directory is atomic on the platforms this runs on,
//! so an IMAP reader scanning `new/` never sees a half-written file and the two
//! never need a cross-process lock. That is the same guarantee
//! [`CertificateStore::install`](selfhost_proxy::tls) relies on for certificates.
//!
//! # Ownership note
//!
//! This file holds the **delivery / write** side of the contract's `Maildir`
//! (`open`, `exists`, `deliver`, and the UID allocation that IMAP correctness
//! depends on — seam S-1: the receiver's `deliver` is the sole UID allocator).
//! The read/flag surface (`list`, `fetch`, `flags`, `set_flags`) is implemented
//! here in a straightforward form so the type is complete and testable; the
//! IMAP author owns and may deepen it against this same on-disk format.

use crate::address::Address;
use crate::message::Message;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// An IMAP UID: monotonic per mailbox, never reused. The receiver assigns it at
/// delivery; every other reader treats it as opaque and stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uid(pub u32);

/// The opaque Maildir base filename identifying one stored message.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoredId(pub String);

/// A mailbox folder. `Inbox` is the Maildir root; the rest are Maildir++
/// subfolders (`.Sent`, `.Drafts`, …), so one mailbox holds them all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Folder {
    /// Newly delivered and read inbox mail.
    Inbox,
    /// Copies of sent mail.
    Sent,
    /// Unsent drafts.
    Drafts,
    /// Deleted mail awaiting expunge.
    Trash,
    /// Suspected spam.
    Junk,
}

/// IMAP message flags, encoded in the Maildir filename's `:2,` suffix.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
    /// The message has been read.
    pub seen: bool,
    /// The message has been replied to.
    pub answered: bool,
    /// The message is flagged for follow-up.
    pub flagged: bool,
    /// The message is marked for deletion.
    pub deleted: bool,
    /// The message is a draft.
    pub draft: bool,
}

/// What went wrong touching the store.
#[derive(Debug)]
pub enum StoreError {
    /// An underlying filesystem error.
    Io(io::Error),
    /// The address is not a mailbox this store serves.
    NoSuchMailbox(Address),
    /// No stored message carries the given UID.
    NotFound(Uid),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "mail store I/O error: {e}"),
            Self::NoSuchMailbox(a) => write!(f, "no such mailbox: {a}"),
            Self::NotFound(u) => write!(f, "no message with uid {}", u.0),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// The Maildir tree. Cloning is cheap — an `Arc` around the shared state — so a
/// per-connection driver holds its own handle.
#[derive(Clone)]
pub struct Maildir(Arc<Inner>);

struct Inner {
    root: PathBuf,
    mailboxes: Vec<Address>,
    /// Next UID to hand out, per mailbox, mirrored to `.uidnext` on disk so the
    /// sequence stays monotonic across restarts.
    uid_next: Mutex<HashMap<String, u32>>,
}

impl Maildir {
    /// Opens (creating as needed) the mail tree under `data_dir` for exactly the
    /// given mailbox addresses, including their aliases if the caller expanded
    /// them into the list. Each mailbox gets `tmp/`, `new/`, `cur/` and a stable
    /// `.uidvalidity` stamped on first creation.
    pub fn open(data_dir: &Path, mailboxes: &[Address]) -> Result<Self, StoreError> {
        let root = data_dir.join("mail");
        for mailbox in mailboxes {
            let dir = mailbox_dir(&root, mailbox);
            for sub in ["tmp", "new", "cur"] {
                std::fs::create_dir_all(dir.join(sub))?;
            }
            let validity = dir.join(".uidvalidity");
            if !validity.exists() {
                std::fs::write(&validity, now_secs().to_string())?;
            }
        }
        Ok(Self(Arc::new(Inner {
            root,
            mailboxes: mailboxes.to_vec(),
            uid_next: Mutex::new(HashMap::new()),
        })))
    }

    /// Whether `address` (matched case-insensitively against the configured set)
    /// is a real mailbox here. The receiver calls this at `RCPT` so mail for an
    /// unknown local user is refused, not black-holed.
    pub fn exists(&self, address: &Address) -> bool {
        self.0.mailboxes.iter().any(|known| known.matches(address))
    }

    /// Delivers one message to one mailbox and returns its assigned UID.
    ///
    /// Atomic: bytes are written to `tmp/`, fsynced, then renamed into `new/`.
    /// The UID is allocated first and persisted before the rename, so a crash
    /// cannot reuse it. Delivering to an address that is not a mailbox here is
    /// an error, never a silent drop.
    pub async fn deliver(&self, mailbox: &Address, msg: &Message) -> Result<Uid, StoreError> {
        if !self.exists(mailbox) {
            return Err(StoreError::NoSuchMailbox(mailbox.clone()));
        }
        let dir = mailbox_dir(&self.0.root, mailbox);
        let uid = self.allocate_uid(mailbox, &dir).await?;

        let base = format!(
            "{}.P{}U{}.selfhost,S={}",
            now_secs(),
            std::process::id(),
            uid.0,
            msg.size()
        );
        let tmp = dir.join("tmp").join(&base);
        let file = tokio::fs::File::create(&tmp).await?;
        {
            use tokio::io::AsyncWriteExt;
            let mut file = file;
            file.write_all(msg.as_bytes()).await?;
            // fsync before the rename: a message present in new/ must be a
            // message whose bytes are actually on disk.
            file.sync_all().await?;
        }
        tokio::fs::rename(&tmp, dir.join("new").join(&base)).await?;
        Ok(uid)
    }

    /// The UIDs present in a folder, ascending — the IMAP read side.
    pub async fn list(&self, mailbox: &Address, folder: Folder) -> Result<Vec<Uid>, StoreError> {
        let dir = self.folder_dir(mailbox, folder)?;
        let mut uids = Vec::new();
        for sub in ["new", "cur"] {
            let mut entries = match tokio::fs::read_dir(dir.join(sub)).await {
                Ok(entries) => entries,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            while let Some(entry) = entries.next_entry().await? {
                if let Some(uid) = uid_from_name(&entry.file_name().to_string_lossy()) {
                    uids.push(Uid(uid));
                }
            }
        }
        uids.sort();
        Ok(uids)
    }

    /// Reads back one stored message by UID, from the given folder.
    pub async fn fetch(&self, mailbox: &Address, folder: Folder, uid: Uid) -> Result<Message, StoreError> {
        let path = self.locate(mailbox, folder, uid).await?.ok_or(StoreError::NotFound(uid))?;
        let bytes = tokio::fs::read(&path).await?;
        Message::parse(bytes).map_err(|_| StoreError::NotFound(uid))
    }

    /// The flags currently set on a message, in the given folder.
    pub async fn flags(&self, mailbox: &Address, folder: Folder, uid: Uid) -> Result<Flags, StoreError> {
        let path = self.locate(mailbox, folder, uid).await?.ok_or(StoreError::NotFound(uid))?;
        Ok(flags_from_name(&path.file_name().unwrap_or_default().to_string_lossy()))
    }

    /// Replaces the flags on a message by renaming it within the folder's
    /// `cur/`, the Maildir convention. Last writer wins on the same UID
    /// (seam S-2); acceptable because a mailbox has a single reader in
    /// practice.
    pub async fn set_flags(
        &self,
        mailbox: &Address,
        folder: Folder,
        uid: Uid,
        flags: Flags,
    ) -> Result<(), StoreError> {
        let dir = self.folder_dir(mailbox, folder)?;
        let path = self.locate(mailbox, folder, uid).await?.ok_or(StoreError::NotFound(uid))?;
        let base = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.split(':').next().unwrap_or(n).to_owned())
            .unwrap_or_default();
        let target = dir.join("cur").join(format!("{base}:2,{}", flags_suffix(flags)));
        tokio::fs::rename(&path, &target).await?;
        Ok(())
    }

    /// The mailbox's UID validity value — stable for the life of the mailbox, as
    /// IMAP requires so a client can trust its cached UIDs.
    pub async fn uid_validity(&self, mailbox: &Address) -> u32 {
        let dir = mailbox_dir(&self.0.root, mailbox);
        tokio::fs::read_to_string(dir.join(".uidvalidity"))
            .await
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    /// The UID the next delivered message will receive — `SELECT`/`STATUS`'s
    /// `UIDNEXT`. Reads the same persisted counter [`Maildir::deliver`]
    /// allocates from, without advancing it.
    pub async fn uid_next(&self, mailbox: &Address) -> u32 {
        let key = mailbox_key(mailbox);
        let map = self.0.uid_next.lock().await;
        match map.get(&key) {
            Some(next) => *next,
            None => read_uid_next(&mailbox_dir(&self.0.root, mailbox)).await,
        }
    }

    /// When a message was delivered, read from its filesystem modification
    /// time.
    ///
    /// Maildir's atomic rename-into-place (see the module doc) makes this
    /// exactly the delivery moment, and it needs no extra bookkeeping the way
    /// a value encoded in the filename would — the filesystem already keeps it.
    pub async fn internal_date(
        &self,
        mailbox: &Address,
        folder: Folder,
        uid: Uid,
    ) -> Result<SystemTime, StoreError> {
        let path = self.locate(mailbox, folder, uid).await?.ok_or(StoreError::NotFound(uid))?;
        Ok(tokio::fs::metadata(&path).await?.modified()?)
    }

    /// Allocates the next UID for a mailbox and persists the counter.
    async fn allocate_uid(&self, mailbox: &Address, dir: &Path) -> Result<Uid, StoreError> {
        let key = mailbox_key(mailbox);
        let mut map = self.0.uid_next.lock().await;
        let next = match map.get(&key) {
            Some(n) => *n,
            None => read_uid_next(dir).await,
        };
        tokio::fs::write(dir.join(".uidnext"), (next + 1).to_string()).await?;
        map.insert(key, next + 1);
        Ok(Uid(next))
    }

    /// The on-disk directory for a folder, erroring if the mailbox is unknown.
    fn folder_dir(&self, mailbox: &Address, folder: Folder) -> Result<PathBuf, StoreError> {
        if !self.exists(mailbox) {
            return Err(StoreError::NoSuchMailbox(mailbox.clone()));
        }
        let base = mailbox_dir(&self.0.root, mailbox);
        Ok(match folder {
            Folder::Inbox => base,
            Folder::Sent => base.join(".Sent"),
            Folder::Drafts => base.join(".Drafts"),
            Folder::Trash => base.join(".Trash"),
            Folder::Junk => base.join(".Junk"),
        })
    }

    /// Finds the full path of a message by UID within a folder.
    async fn locate(&self, mailbox: &Address, folder: Folder, uid: Uid) -> Result<Option<PathBuf>, StoreError> {
        let dir = self.folder_dir(mailbox, folder)?;
        for sub in ["new", "cur"] {
            let sub_dir = dir.join(sub);
            let mut entries = match tokio::fs::read_dir(&sub_dir).await {
                Ok(entries) => entries,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            while let Some(entry) = entries.next_entry().await? {
                if uid_from_name(&entry.file_name().to_string_lossy()) == Some(uid.0) {
                    return Ok(Some(sub_dir.join(entry.file_name())));
                }
            }
        }
        Ok(None)
    }
}

/// The directory holding one mailbox: `<root>/<domain>/<local>`.
fn mailbox_dir(root: &Path, mailbox: &Address) -> PathBuf {
    root.join(sanitise(mailbox.domain())).join(sanitise(mailbox.local()))
}

/// A stable case-insensitive key for the in-memory UID map.
fn mailbox_key(mailbox: &Address) -> String {
    format!("{}@{}", mailbox.local().to_ascii_lowercase(), mailbox.domain())
}

/// Reads the persisted next-UID for a mailbox, defaulting to 1.
async fn read_uid_next(dir: &Path) -> u32 {
    tokio::fs::read_to_string(dir.join(".uidnext"))
        .await
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(1)
}

/// Extracts the `U<n>` UID token a delivery encodes into the filename.
fn uid_from_name(name: &str) -> Option<u32> {
    // Name shape: "<secs>.P<pid>U<uid>.selfhost,S=<size>[:2,<flags>]".
    let base = name.split(':').next().unwrap_or(name);
    let after_u = base.split('U').nth(1)?;
    let digits: String = after_u.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

/// Reads the flag set from a Maildir `:2,<flags>` suffix.
fn flags_from_name(name: &str) -> Flags {
    let Some((_, info)) = name.split_once(":2,") else {
        return Flags::default();
    };
    Flags {
        seen: info.contains('S'),
        answered: info.contains('R'),
        flagged: info.contains('F'),
        deleted: info.contains('T'),
        draft: info.contains('D'),
    }
}

/// Renders flags into the Maildir suffix, in the canonical alphabetical order.
fn flags_suffix(flags: Flags) -> String {
    let mut s = String::new();
    if flags.draft {
        s.push('D');
    }
    if flags.flagged {
        s.push('F');
    }
    if flags.answered {
        s.push('R');
    }
    if flags.seen {
        s.push('S');
    }
    if flags.deleted {
        s.push('T');
    }
    s
}

/// Seconds since the Unix epoch, saturating rather than panicking on a clock
/// set before 1970.
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Reduces a path component to bytes safe as a directory name.
fn sanitise(component: &str) -> String {
    component
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' { c } else { '_' })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory no other test can collide on.
    ///
    /// The clock alone is not enough: `SystemTime`'s effective resolution on
    /// some platforms is coarser than a nanosecond, and this whole suite's
    /// tests start together off one thread pool — a real, observed flake, not
    /// a hypothetical one. A per-process counter closes the gap the clock
    /// leaves open.
    fn temp_root() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let ordinal = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join(format!("selfhost-store-{}-{}-{ordinal}", std::process::id(), now_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn now_nanos() -> u128 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
    }

    fn addr(s: &str) -> Address {
        Address::parse(s).unwrap()
    }

    fn msg(body: &str) -> Message {
        Message::parse(format!("Subject: t\r\n\r\n{body}").into_bytes()).unwrap()
    }

    #[tokio::test]
    async fn delivery_lands_the_message_in_new() {
        let root = temp_root();
        let dave = addr("dave@example.com");
        let store = Maildir::open(&root, std::slice::from_ref(&dave)).unwrap();

        let uid = store.deliver(&dave, &msg("hello")).await.unwrap();
        assert_eq!(uid, Uid(1));

        // The bytes are readable back and the body survived intact.
        let fetched = store.fetch(&dave, Folder::Inbox, uid).await.unwrap();
        assert_eq!(fetched.body(), b"hello");

        // And it is in new/, the atomic-rename destination.
        let new_dir = root.join("mail").join("example.com").join("dave").join("new");
        let count = std::fs::read_dir(&new_dir).unwrap().count();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn uids_are_monotonic_and_unique_per_mailbox() {
        let root = temp_root();
        let dave = addr("dave@example.com");
        let store = Maildir::open(&root, std::slice::from_ref(&dave)).unwrap();

        let first = store.deliver(&dave, &msg("a")).await.unwrap();
        let second = store.deliver(&dave, &msg("b")).await.unwrap();
        assert_eq!(first, Uid(1));
        assert_eq!(second, Uid(2));

        let mut uids = store.list(&dave, Folder::Inbox).await.unwrap();
        uids.sort();
        assert_eq!(uids, vec![Uid(1), Uid(2)]);
    }

    #[tokio::test]
    async fn existence_is_case_insensitive_and_delivery_to_a_stranger_is_refused() {
        let root = temp_root();
        let dave = addr("dave@example.com");
        let store = Maildir::open(&root, std::slice::from_ref(&dave)).unwrap();

        assert!(store.exists(&addr("DAVE@EXAMPLE.COM")));
        assert!(!store.exists(&addr("nobody@example.com")));

        let err = store.deliver(&addr("nobody@example.com"), &msg("x")).await.unwrap_err();
        assert!(matches!(err, StoreError::NoSuchMailbox(_)));
    }

    #[tokio::test]
    async fn uid_validity_is_stable_across_reopen() {
        let root = temp_root();
        let dave = addr("dave@example.com");
        let a = Maildir::open(&root, std::slice::from_ref(&dave)).unwrap();
        let first = a.uid_validity(&dave).await;
        let b = Maildir::open(&root, std::slice::from_ref(&dave)).unwrap();
        assert_eq!(first, b.uid_validity(&dave).await);
    }

    #[tokio::test]
    async fn uid_next_reports_without_advancing_it() {
        let root = temp_root();
        let dave = addr("dave@example.com");
        let store = Maildir::open(&root, std::slice::from_ref(&dave)).unwrap();

        assert_eq!(store.uid_next(&dave).await, 1, "nothing delivered yet");
        let uid = store.deliver(&dave, &msg("a")).await.unwrap();
        assert_eq!(uid, Uid(1));
        assert_eq!(store.uid_next(&dave).await, 2, "advanced by exactly the one delivery");
        // Reading it again must not itself advance the counter.
        assert_eq!(store.uid_next(&dave).await, 2);
    }

    #[tokio::test]
    async fn internal_date_is_the_delivery_moment() {
        let root = temp_root();
        let dave = addr("dave@example.com");
        let store = Maildir::open(&root, std::slice::from_ref(&dave)).unwrap();

        let before = SystemTime::now();
        let uid = store.deliver(&dave, &msg("a")).await.unwrap();
        let after = SystemTime::now();

        let delivered = store.internal_date(&dave, Folder::Inbox, uid).await.unwrap();
        assert!(delivered >= before && delivered <= after, "{delivered:?} not within [{before:?}, {after:?}]");
    }

    #[tokio::test]
    async fn flags_round_trip_through_the_filename() {
        let root = temp_root();
        let dave = addr("dave@example.com");
        let store = Maildir::open(&root, std::slice::from_ref(&dave)).unwrap();
        let uid = store.deliver(&dave, &msg("x")).await.unwrap();

        assert_eq!(store.flags(&dave, Folder::Inbox, uid).await.unwrap(), Flags::default());
        let seen = Flags { seen: true, ..Flags::default() };
        store.set_flags(&dave, Folder::Inbox, uid, seen).await.unwrap();
        assert_eq!(store.flags(&dave, Folder::Inbox, uid).await.unwrap(), seen);
    }

    #[tokio::test]
    async fn fetch_flags_and_set_flags_all_target_the_folder_they_are_given() {
        // Regression: `fetch`/`flags`/`set_flags` used to hardcode `Folder::Inbox`
        // regardless of what was asked for, so a `Sent`/`Drafts`/etc. message
        // could never be read or re-flagged — only ever `list`ed. There is no
        // public API to deliver anywhere but the inbox (this crate supports no
        // `APPEND`), so a message is placed in `Sent` by hand, the same on-disk
        // shape `deliver` itself writes.
        let root = temp_root();
        let dave = addr("dave@example.com");
        let store = Maildir::open(&root, std::slice::from_ref(&dave)).unwrap();

        let sent = root.join("mail").join("example.com").join("dave").join(".Sent");
        std::fs::create_dir_all(sent.join("new")).unwrap();
        std::fs::create_dir_all(sent.join("cur")).unwrap();
        std::fs::write(sent.join("new").join("1.P1U7.selfhost,S=5"), b"Subject: t\r\n\r\nhello").unwrap();

        let fetched = store.fetch(&dave, Folder::Sent, Uid(7)).await.unwrap();
        assert_eq!(fetched.body(), b"hello");
        assert_eq!(store.flags(&dave, Folder::Sent, Uid(7)).await.unwrap(), Flags::default());

        let seen = Flags { seen: true, ..Flags::default() };
        store.set_flags(&dave, Folder::Sent, Uid(7), seen).await.unwrap();
        assert_eq!(store.flags(&dave, Folder::Sent, Uid(7)).await.unwrap(), seen);

        // And the inbox — empty here — must not be where any of this landed.
        assert!(store.fetch(&dave, Folder::Inbox, Uid(7)).await.is_err());
    }
}
