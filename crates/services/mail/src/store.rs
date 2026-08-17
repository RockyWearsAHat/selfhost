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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// Every folder this store offers, in the fixed order [`crate::ews`] and
/// [`crate::eas`] both report them — this deployment's folder set never
/// grows or reorders, so both protocols' folder listings are stable across
/// requests without either needing to remember an ordering of its own.
pub const FOLDERS: [Folder; 5] = [Folder::Inbox, Folder::Drafts, Folder::Sent, Folder::Trash, Folder::Junk];

/// The literal name [`crate::ews`] uses as an EWS `DistinguishedFolderId`
/// and [`crate::eas`] mints as an ActiveSync `ServerId` — the same slug in
/// both protocols is deliberate: it means "does this folder exist" is one
/// function shared by both rather than two id schemes that could disagree.
pub fn folder_slug(folder: Folder) -> &'static str {
    match folder {
        Folder::Inbox => "inbox",
        Folder::Drafts => "drafts",
        Folder::Sent => "sentitems",
        Folder::Trash => "deleteditems",
        Folder::Junk => "junkemail",
    }
}

/// The reverse of [`folder_slug`]. `None` for anything this store did not
/// itself mint — a stale id, a client typo, or a guess.
pub fn folder_from_slug(slug: &str) -> Option<Folder> {
    FOLDERS.into_iter().find(|folder| folder_slug(*folder) == slug)
}

/// The name a mail client should show a human for this folder — used by
/// both [`crate::ews`]'s `DisplayName` and [`crate::eas`]'s.
pub fn folder_display_name(folder: Folder) -> &'static str {
    match folder {
        Folder::Inbox => "Inbox",
        Folder::Drafts => "Drafts",
        Folder::Sent => "Sent Items",
        Folder::Trash => "Deleted Items",
        Folder::Junk => "Junk Email",
    }
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
    /// An alias names a delivery target that is not one of the store's
    /// mailboxes — a configuration the store refuses to open, because mail
    /// accepted for that alias could never be delivered anywhere.
    AliasWithoutMailbox {
        /// The alias address as configured.
        alias: Address,
        /// The target it names, which no mailbox matches.
        target: Address,
    },
    /// No stored message carries the given UID.
    NotFound(Uid),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "mail store I/O error: {e}"),
            Self::NoSuchMailbox(a) => write!(f, "no such mailbox: {a}"),
            Self::AliasWithoutMailbox { alias, target } => {
                write!(f, "alias {alias} delivers to {target}, which is not a mailbox here")
            }
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
    /// Alias → mailbox routes. Every target is one of `mailboxes` — `open`
    /// refuses anything else — so resolution can never dangle.
    aliases: Vec<(Address, Address)>,
    /// Next UID to hand out, per mailbox **and folder** — each folder is its
    /// own UID namespace, same as IMAP requires — mirrored to that folder's
    /// own `.uidnext` on disk so the sequence stays monotonic across restarts.
    uid_next: Mutex<HashMap<(String, Folder), u32>>,
}

impl Maildir {
    /// Opens (creating as needed) the mail tree under `data_dir` for exactly the
    /// given mailbox addresses. Each mailbox gets `tmp/`, `new/`, `cur/` and a
    /// stable `.uidvalidity` stamped on first creation.
    ///
    /// `aliases` are extra `(alias, target)` addresses that accept and deliver
    /// into an existing mailbox — no directory of their own, so the same message
    /// addressed to `postmaster@` and read over IMAP as the target mailbox is
    /// one file, not two. An alias whose target is not in `mailboxes` is an
    /// error: accepting mail that can never land anywhere is a black hole. An
    /// alias that spells an existing mailbox address is inert, not an error —
    /// [`Maildir::resolve`] checks mailboxes first, so the mailbox always wins.
    pub fn open(
        data_dir: &Path,
        mailboxes: &[Address],
        aliases: &[(Address, Address)],
    ) -> Result<Self, StoreError> {
        for (alias, target) in aliases {
            if !mailboxes.iter().any(|known| known.matches(target)) {
                return Err(StoreError::AliasWithoutMailbox {
                    alias: alias.clone(),
                    target: target.clone(),
                });
            }
        }
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
            aliases: aliases.to_vec(),
            uid_next: Mutex::new(HashMap::new()),
        })))
    }

    /// The mailbox `address` delivers to: the matching mailbox itself, or the
    /// target of a matching alias. `None` means no mail for this address —
    /// matching is case-insensitive, like every address comparison here.
    pub fn resolve(&self, address: &Address) -> Option<&Address> {
        self.0
            .mailboxes
            .iter()
            .find(|known| known.matches(address))
            .or_else(|| {
                self.0
                    .aliases
                    .iter()
                    .find(|(alias, _)| alias.matches(address))
                    .map(|(_, target)| target)
            })
    }

    /// Whether `address` is a mailbox or an alias of one. The receiver calls
    /// this at `RCPT` so mail for an unknown local user is refused, not
    /// black-holed.
    pub fn exists(&self, address: &Address) -> bool {
        self.resolve(address).is_some()
    }

    /// Delivers one message to one mailbox (or alias — the message lands in the
    /// alias's target) and returns its assigned UID.
    ///
    /// Atomic: bytes are written to `tmp/`, fsynced, then renamed into `new/`.
    /// The UID is allocated first and persisted before the rename, so a crash
    /// cannot reuse it. Delivering to an address that is not a mailbox here is
    /// an error, never a silent drop.
    pub async fn deliver(&self, mailbox: &Address, msg: &Message) -> Result<Uid, StoreError> {
        let target =
            self.resolve(mailbox).ok_or_else(|| StoreError::NoSuchMailbox(mailbox.clone()))?.clone();
        self.write_message(&target, Folder::Inbox, msg).await
    }

    /// Writes one message into an arbitrary folder of an existing mailbox and
    /// returns its assigned UID — the folder-aware generalisation of
    /// [`Maildir::deliver`], which only ever targets [`Folder::Inbox`].
    ///
    /// Used to save a sent copy or a draft (EWS `CreateItem`, ActiveSync
    /// `SendMail`/`Sync` composing an item) — deliberately separate from
    /// `deliver`, which is the one place inbound SMTP mail lands and must
    /// stay the sole path a stranger's message can take.
    pub async fn save(&self, mailbox: &Address, folder: Folder, msg: &Message) -> Result<Uid, StoreError> {
        let target =
            self.resolve(mailbox).ok_or_else(|| StoreError::NoSuchMailbox(mailbox.clone()))?.clone();
        self.write_message(&target, folder, msg).await
    }

    /// Moves a message from one folder to another, allocating it a **new**
    /// UID in the destination — IMAP `MOVE` semantics (RFC 6851 §4.3): a
    /// moved message is a new message in its new mailbox, not a renamed one.
    /// Used for EWS `UpdateItem`/`DeleteItem` and ActiveSync moving/deleting
    /// an item (Deleted Items is a folder here, not a distinct mechanism).
    pub async fn move_message(
        &self,
        mailbox: &Address,
        from: Folder,
        uid: Uid,
        to: Folder,
    ) -> Result<Uid, StoreError> {
        let msg = self.fetch(mailbox, from, uid).await?;
        let new_uid = self.save(mailbox, to, &msg).await?;
        if let Some(path) = self.locate(mailbox, from, uid).await? {
            tokio::fs::remove_file(&path).await?;
        }
        Ok(new_uid)
    }

    /// Permanently removes a message — real deletion, not a move to
    /// [`Folder::Trash`]. Used for EWS `DeleteItem`'s `HardDelete`, and for
    /// deleting a message that is already in Trash: moving Trash→Trash would
    /// only assign it a new UID forever, so "delete something already
    /// deleted" means remove it for good, the same as emptying Trash in an
    /// ordinary mail client.
    pub async fn purge(&self, mailbox: &Address, folder: Folder, uid: Uid) -> Result<(), StoreError> {
        let path = self.locate(mailbox, folder, uid).await?.ok_or(StoreError::NotFound(uid))?;
        tokio::fs::remove_file(&path).await?;
        Ok(())
    }

    /// The tmp→fsync→rename write shared by [`Maildir::deliver`] and
    /// [`Maildir::save`] — `mailbox` must already be resolved to a real
    /// mailbox address (not an alias), and the folder's directories are
    /// created on demand since only the mailbox root is guaranteed to exist
    /// from [`Maildir::open`].
    async fn write_message(&self, mailbox: &Address, folder: Folder, msg: &Message) -> Result<Uid, StoreError> {
        let dir = self.folder_dir(mailbox, folder)?;
        for sub in ["tmp", "new", "cur"] {
            tokio::fs::create_dir_all(dir.join(sub)).await?;
        }
        let uid = self.allocate_uid(mailbox, folder, &dir).await?;

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

    /// A folder's UID validity value — stable for the life of the folder, as
    /// IMAP requires so a client can trust its cached UIDs. Each folder is its
    /// own IMAP mailbox and so has its own validity stamp; `Folder::Inbox`'s
    /// directory is the mailbox root, so this reads exactly the path the
    /// single-folder version of this method always meant.
    pub async fn uid_validity(&self, mailbox: &Address, folder: Folder) -> u32 {
        let Ok(dir) = self.folder_dir(mailbox, folder) else { return 0 };
        tokio::fs::read_to_string(dir.join(".uidvalidity"))
            .await
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    /// The UID the next message written to `folder` will receive —
    /// `SELECT`/`STATUS`'s `UIDNEXT`. Reads the same persisted counter
    /// [`Maildir::deliver`]/[`Maildir::save`] allocate from, without
    /// advancing it.
    pub async fn uid_next(&self, mailbox: &Address, folder: Folder) -> u32 {
        let Ok(dir) = self.folder_dir(mailbox, folder) else { return 1 };
        let key = (mailbox_key(mailbox), folder);
        let map = self.0.uid_next.lock().await;
        match map.get(&key) {
            Some(next) => *next,
            None => read_uid_next(&dir).await,
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

    /// Allocates the next UID for a mailbox's folder and persists the counter.
    async fn allocate_uid(&self, mailbox: &Address, folder: Folder, dir: &Path) -> Result<Uid, StoreError> {
        let key = (mailbox_key(mailbox), folder);
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
        let store = Maildir::open(&root, std::slice::from_ref(&dave), &[]).unwrap();

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
        let store = Maildir::open(&root, std::slice::from_ref(&dave), &[]).unwrap();

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
        let store = Maildir::open(&root, std::slice::from_ref(&dave), &[]).unwrap();

        assert!(store.exists(&addr("DAVE@EXAMPLE.COM")));
        assert!(!store.exists(&addr("nobody@example.com")));

        let err = store.deliver(&addr("nobody@example.com"), &msg("x")).await.unwrap_err();
        assert!(matches!(err, StoreError::NoSuchMailbox(_)));
    }

    #[tokio::test]
    async fn an_alias_accepts_and_delivers_into_its_target_mailbox() {
        let root = temp_root();
        let dave = addr("dave@example.com");
        let aliases = [(addr("postmaster@example.com"), dave.clone())];
        let store = Maildir::open(&root, std::slice::from_ref(&dave), &aliases).unwrap();

        // The alias exists (case-insensitively) but is not a mailbox of its own.
        assert!(store.exists(&addr("POSTMASTER@Example.com")));
        assert!(!root.join("mail").join("example.com").join("postmaster").exists());

        let uid = store.deliver(&addr("postmaster@example.com"), &msg("for the operator")).await.unwrap();
        let fetched = store.fetch(&dave, Folder::Inbox, uid).await.unwrap();
        assert_eq!(fetched.body(), b"for the operator");
    }

    #[test]
    fn an_alias_whose_target_is_no_mailbox_refuses_to_open() {
        // Accepting mail for an alias that routes nowhere would be a black
        // hole, so the store refuses the configuration outright.
        let root = temp_root();
        let dave = addr("dave@example.com");
        let aliases = [(addr("postmaster@example.com"), addr("ghost@example.com"))];
        let Err(err) = Maildir::open(&root, std::slice::from_ref(&dave), &aliases) else {
            panic!("a dangling alias must not open");
        };
        assert!(matches!(err, StoreError::AliasWithoutMailbox { .. }));
    }

    #[tokio::test]
    async fn uid_validity_is_stable_across_reopen() {
        let root = temp_root();
        let dave = addr("dave@example.com");
        let a = Maildir::open(&root, std::slice::from_ref(&dave), &[]).unwrap();
        let first = a.uid_validity(&dave, Folder::Inbox).await;
        let b = Maildir::open(&root, std::slice::from_ref(&dave), &[]).unwrap();
        assert_eq!(first, b.uid_validity(&dave, Folder::Inbox).await);
    }

    #[tokio::test]
    async fn uid_next_reports_without_advancing_it() {
        let root = temp_root();
        let dave = addr("dave@example.com");
        let store = Maildir::open(&root, std::slice::from_ref(&dave), &[]).unwrap();

        assert_eq!(store.uid_next(&dave, Folder::Inbox).await, 1, "nothing delivered yet");
        let uid = store.deliver(&dave, &msg("a")).await.unwrap();
        assert_eq!(uid, Uid(1));
        assert_eq!(
            store.uid_next(&dave, Folder::Inbox).await,
            2,
            "advanced by exactly the one delivery"
        );
        // Reading it again must not itself advance the counter.
        assert_eq!(store.uid_next(&dave, Folder::Inbox).await, 2);
    }

    #[tokio::test]
    async fn each_folder_is_its_own_uid_namespace() {
        // A folder's UIDNEXT must not be perturbed by writes to a different
        // folder — each is a distinct IMAP mailbox with its own sequence.
        let root = temp_root();
        let dave = addr("dave@example.com");
        let store = Maildir::open(&root, std::slice::from_ref(&dave), &[]).unwrap();

        let inbox_uid = store.deliver(&dave, &msg("hello")).await.unwrap();
        assert_eq!(inbox_uid, Uid(1));

        let sent_uid = store.save(&dave, Folder::Sent, &msg("sent copy")).await.unwrap();
        assert_eq!(sent_uid, Uid(1), "Sent's own namespace starts at 1, independent of Inbox");

        let second_inbox = store.deliver(&dave, &msg("world")).await.unwrap();
        assert_eq!(second_inbox, Uid(2), "Inbox's counter is unaffected by the Sent write");

        assert_eq!(store.uid_next(&dave, Folder::Inbox).await, 3);
        assert_eq!(store.uid_next(&dave, Folder::Sent).await, 2);
    }

    #[tokio::test]
    async fn save_writes_into_the_named_folder_and_is_readable_back() {
        let root = temp_root();
        let dave = addr("dave@example.com");
        let store = Maildir::open(&root, std::slice::from_ref(&dave), &[]).unwrap();

        let uid = store.save(&dave, Folder::Drafts, &msg("a draft")).await.unwrap();
        let fetched = store.fetch(&dave, Folder::Drafts, uid).await.unwrap();
        assert_eq!(fetched.body(), b"a draft");
        assert!(store.fetch(&dave, Folder::Inbox, uid).await.is_err(), "must land only in Drafts");
    }

    #[tokio::test]
    async fn save_refuses_a_stranger_mailbox() {
        let root = temp_root();
        let dave = addr("dave@example.com");
        let store = Maildir::open(&root, std::slice::from_ref(&dave), &[]).unwrap();

        let err = store.save(&addr("nobody@example.com"), Folder::Sent, &msg("x")).await.unwrap_err();
        assert!(matches!(err, StoreError::NoSuchMailbox(_)));
    }

    #[tokio::test]
    async fn move_message_assigns_a_new_uid_in_the_destination_and_removes_the_original() {
        let root = temp_root();
        let dave = addr("dave@example.com");
        let store = Maildir::open(&root, std::slice::from_ref(&dave), &[]).unwrap();

        let inbox_uid = store.deliver(&dave, &msg("move me")).await.unwrap();
        let trash_uid = store.move_message(&dave, Folder::Inbox, inbox_uid, Folder::Trash).await.unwrap();

        assert_eq!(trash_uid, Uid(1), "Trash's own namespace, independent of the Inbox UID it came from");
        assert!(store.fetch(&dave, Folder::Inbox, inbox_uid).await.is_err(), "gone from the source folder");
        let fetched = store.fetch(&dave, Folder::Trash, trash_uid).await.unwrap();
        assert_eq!(fetched.body(), b"move me");
    }

    #[tokio::test]
    async fn move_message_reports_not_found_for_a_uid_absent_from_the_source_folder() {
        let root = temp_root();
        let dave = addr("dave@example.com");
        let store = Maildir::open(&root, std::slice::from_ref(&dave), &[]).unwrap();

        let err = store.move_message(&dave, Folder::Inbox, Uid(99), Folder::Trash).await.unwrap_err();
        assert!(matches!(err, StoreError::NotFound(Uid(99))));
    }

    #[tokio::test]
    async fn internal_date_is_the_delivery_moment() {
        let root = temp_root();
        let dave = addr("dave@example.com");
        let store = Maildir::open(&root, std::slice::from_ref(&dave), &[]).unwrap();

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
        let store = Maildir::open(&root, std::slice::from_ref(&dave), &[]).unwrap();
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
        let store = Maildir::open(&root, std::slice::from_ref(&dave), &[]).unwrap();

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
