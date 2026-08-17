//! Exchange ActiveSync (EAS) — the protocol iOS Mail drives a mailbox over,
//! once Autodiscover ([`crate::autodiscover`]) points it here with a
//! `MobileSync` response.
//!
//! The same deliberately narrow subset [`crate::ews`] offers macOS Mail:
//! `Provision` (accepted with no device-policy restrictions), `FolderSync`
//! (the fixed five-folder set), `Sync` (incremental, per folder), fetching a
//! message's raw MIME (`ItemOperations`/`AirSyncBase:Data`), and `SendMail`.
//! Folder identity is the exact string [`crate::store::folder_slug`] already
//! defines for EWS — this deployment mints its own `ServerId` values (there
//! is no upstream Exchange minting them), so reusing the slug means "is this
//! folder real" is one function shared by both protocols rather than two id
//! schemes that could disagree. `Sync`'s incremental token is the folder's
//! own `UIDNEXT`, the same trick [`crate::ews`]'s `SyncFolderItems` uses.
//!
//! # WBXML tag numbers — honest about what is and is not verified
//!
//! [MS-ASWBXML] defines ~25 numbered "code pages", each the binary encoding
//! of one XML namespace's tag names. [`crate::wbxml`] implements the wire
//! format itself, which is unambiguous from the spec text alone; the code
//! numbers below are this module's own reading of the published tag tables
//! for the handful of elements these five operations touch, not bytes
//! captured from a real device. They are named constants precisely so a
//! wrong one is a one-line fix rather than a rewrite — the plan that shipped
//! this feature says outright that Apple's client-side EAS subset needs a
//! real iPhone/iPad to confirm against, the same way EWS needs a real Mac;
//! this file is the other half of that same caveat.

use crate::address::Address;
use crate::context::{self, Context};
use crate::message::Message;
use crate::store::{folder_display_name, folder_from_slug, folder_slug, Folder, Uid, FOLDERS};
use crate::wbxml::{Reader, Token, Writer};

// ---------------------------------------------------------------------------
// Code pages and tag codes (see the module-level caveat)
// ---------------------------------------------------------------------------

const PAGE_AIRSYNC: u8 = 0;
const PAGE_FOLDERHIERARCHY: u8 = 7;
const PAGE_PROVISION: u8 = 14;
const PAGE_AIRSYNCBASE: u8 = 17;
const PAGE_ITEMOPERATIONS: u8 = 20;
const PAGE_COMPOSEMAIL: u8 = 21;

mod airsync {
    pub const SYNC: u8 = 0x05;
    pub const ADD: u8 = 0x07;
    pub const SYNC_KEY: u8 = 0x0A;
    pub const SERVER_ID: u8 = 0x0C;
    pub const STATUS: u8 = 0x0D;
    pub const COLLECTION: u8 = 0x0E;
    pub const CLASS: u8 = 0x0F;
    pub const COLLECTION_ID: u8 = 0x11;
    pub const COMMANDS: u8 = 0x15;
    pub const APPLICATION_DATA: u8 = 0x1C;
    pub const COLLECTIONS: u8 = 0x1B;
}

mod folder_hierarchy {
    pub const DISPLAY_NAME: u8 = 0x07;
    pub const SERVER_ID: u8 = 0x08;
    pub const PARENT_ID: u8 = 0x09;
    pub const TYPE: u8 = 0x0A;
    pub const STATUS: u8 = 0x0B;
    pub const CHANGES: u8 = 0x0D;
    pub const ADD: u8 = 0x0E;
    pub const SYNC_KEY: u8 = 0x11;
    pub const FOLDER_SYNC: u8 = 0x15;
    pub const COUNT: u8 = 0x16;
}

mod provision {
    pub const PROVISION: u8 = 0x05;
    pub const POLICIES: u8 = 0x06;
    pub const POLICY: u8 = 0x07;
    pub const POLICY_TYPE: u8 = 0x08;
    pub const POLICY_KEY: u8 = 0x09;
    pub const STATUS: u8 = 0x0B;
}

mod airsyncbase {
    pub const BODY: u8 = 0x0A;
    pub const DATA: u8 = 0x0B;
    pub const TYPE: u8 = 0x06;
}

mod item_operations {
    pub const ITEM_OPERATIONS: u8 = 0x05;
    pub const FETCH: u8 = 0x06;
    pub const STATUS: u8 = 0x0D;
    pub const RESPONSE: u8 = 0x0E;
    pub const PROPERTIES: u8 = 0x0B;
}

mod compose_mail {
    pub const SEND_MAIL: u8 = 0x05;
    pub const SAVE_IN_SENT_ITEMS: u8 = 0x08;
    pub const MIME: u8 = 0x10;
    pub const STATUS: u8 = 0x12;
}

/// The distinguished folder `Type` value [MS-ASCMD]'s `FolderSync` response
/// gives each default folder. There is no standard type for a `Junk` folder
/// in the classic table this module was written against, so it is reported
/// as `12` (a generic user mail folder) rather than an invented number —
/// worth rechecking against a real device's own `FolderSync` reply, which
/// would show whichever type it actually expects.
fn folder_type(folder: Folder) -> u8 {
    match folder {
        Folder::Inbox => 2,
        Folder::Drafts => 3,
        Folder::Trash => 4,
        Folder::Sent => 5,
        Folder::Junk => 12,
    }
}

/// Status `1` — `Success`, the one status code every response below uses on
/// its happy path. [MS-ASCMD] defines many more; this deployment's failure
/// modes are narrow enough (not found, bad auth already handled earlier)
/// that a single failure code is unneeded — see each operation's own error
/// path for what it does instead of enumerating them.
const STATUS_SUCCESS: &str = "1";

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// Handles one authenticated ActiveSync request (already WBXML, already
/// scoped to `mailbox` by [`crate::context::authenticate_basic`]) and
/// returns the WBXML response.
///
/// ActiveSync names its operation in the query string
/// (`?Cmd=FolderSync&...`) in real deployments, but the body's own root tag
/// already says the same thing unambiguously — reading it there means this
/// function needs no query-string parameter threaded in just to agree with
/// what the body already states.
pub async fn handle(ctx: &Context<'_>, mailbox: &Address, body: &[u8]) -> Vec<u8> {
    let Some(mut reader) = Reader::new(body) else {
        return status_only_document(PAGE_AIRSYNC, airsync::SYNC, airsync::STATUS, "3"); // 3 = protocol error
    };
    // The root tag's code page: an explicit `SwitchPage` if the document
    // wrote one, or page 0 (`AirSync`) if it didn't — [`Writer::switch_page`]
    // never emits a token for a page a document is already on, and every
    // document starts on page 0, so a `Sync` request (page 0) legitimately
    // opens straight on its root tag with no switch at all.
    let mut page = 0u8;
    let Some(root) = (loop {
        match reader.next() {
            Some(Token::SwitchPage(p)) => page = p,
            Some(Token::Tag { code, .. }) => break Some(code),
            _ => break None,
        }
    }) else {
        return status_only_document(PAGE_AIRSYNC, airsync::SYNC, airsync::STATUS, "3");
    };

    match (page, root) {
        (PAGE_PROVISION, provision::PROVISION) => provision_response(body),
        (PAGE_FOLDERHIERARCHY, folder_hierarchy::FOLDER_SYNC) => folder_sync_response(body),
        (PAGE_AIRSYNC, airsync::SYNC) => sync_response(ctx, mailbox, body).await,
        (PAGE_ITEMOPERATIONS, item_operations::ITEM_OPERATIONS) => item_operations_response(ctx, mailbox, body).await,
        (PAGE_COMPOSEMAIL, compose_mail::SEND_MAIL) => send_mail_response(ctx, mailbox, body).await,
        _ => status_only_document(PAGE_AIRSYNC, airsync::SYNC, airsync::STATUS, "3"),
    }
}

/// A minimal `<Root><Status>{status}</Status></Root>`-shaped error document
/// — used only when the request could not even be identified; every
/// operation below reports its own, correctly-paged status on its own
/// unhappy paths instead.
fn status_only_document(page: u8, root: u8, status_tag: u8, status: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.switch_page(page);
    w.start_tag(root);
    w.text_tag(status_tag, status);
    w.end_tag();
    w.finish()
}

/// The text of the first `Tag`-then-`Text` pair matching `(page, code)`
/// anywhere in `body` — this module's equivalent of [`crate::xml::element_text`]
/// for WBXML: narrow, linear, and exactly as much parsing these five
/// operations need rather than a general document-tree reader.
fn find_text(body: &[u8], page: u8, code: u8) -> Option<String> {
    let mut reader = Reader::new(body)?;
    let mut current_page = 0u8;
    loop {
        match reader.next()? {
            Token::SwitchPage(p) => current_page = p,
            Token::Tag { code: c, has_content: true } if current_page == page && c == code => {
                return match reader.next()? {
                    Token::Text(text) => Some(text),
                    _ => None,
                };
            }
            Token::End => {}
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Provision
// ---------------------------------------------------------------------------

/// Accepts whatever policy type was requested with no restrictions —
/// [`crate::ews`]'s module doc explains the same choice for EWS's own
/// absence of any mailbox-policy concept; ActiveSync just makes the
/// handshake explicit where EWS has none.
fn provision_response(body: &[u8]) -> Vec<u8> {
    let policy_type =
        find_text(body, PAGE_PROVISION, provision::POLICY_TYPE).unwrap_or_else(|| "MS-EAS-Provisioning-WBXML".to_owned());

    let mut w = Writer::new();
    w.switch_page(PAGE_PROVISION);
    w.start_tag(provision::PROVISION);
    w.text_tag(provision::STATUS, STATUS_SUCCESS);
    w.start_tag(provision::POLICIES);
    w.start_tag(provision::POLICY);
    w.text_tag(provision::POLICY_TYPE, &policy_type);
    w.text_tag(provision::STATUS, STATUS_SUCCESS);
    w.text_tag(provision::POLICY_KEY, "1");
    w.end_tag(); // Policy
    w.end_tag(); // Policies
    w.end_tag(); // Provision
    w.finish()
}

// ---------------------------------------------------------------------------
// FolderSync
// ---------------------------------------------------------------------------

/// Same fixed token [`crate::ews`]'s `SyncFolderHierarchy` uses — the folder
/// set never changes, so a client already holding `"1"` gets an empty
/// `Changes`-equivalent (no `Add` entries) rather than the whole set again.
const FOLDER_SYNC_TOKEN: &str = "1";

fn folder_sync_response(body: &[u8]) -> Vec<u8> {
    let first_sync = find_text(body, PAGE_FOLDERHIERARCHY, folder_hierarchy::SYNC_KEY).as_deref() != Some(FOLDER_SYNC_TOKEN);

    let mut w = Writer::new();
    w.switch_page(PAGE_FOLDERHIERARCHY);
    w.start_tag(folder_hierarchy::FOLDER_SYNC);
    w.text_tag(folder_hierarchy::STATUS, STATUS_SUCCESS);
    w.text_tag(folder_hierarchy::SYNC_KEY, FOLDER_SYNC_TOKEN);
    if first_sync {
        w.text_tag(folder_hierarchy::COUNT, &FOLDERS.len().to_string());
        w.start_tag(folder_hierarchy::CHANGES);
        for folder in FOLDERS {
            w.start_tag(folder_hierarchy::ADD);
            w.text_tag(folder_hierarchy::SERVER_ID, folder_slug(folder));
            w.text_tag(folder_hierarchy::PARENT_ID, "0");
            w.text_tag(folder_hierarchy::DISPLAY_NAME, folder_display_name(folder));
            w.text_tag(folder_hierarchy::TYPE, &folder_type(folder).to_string());
            w.end_tag(); // Add
        }
        w.end_tag(); // Changes
    } else {
        w.text_tag(folder_hierarchy::COUNT, "0");
    }
    w.end_tag(); // FolderSync
    w.finish()
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

/// Incremental per-folder sync, same `UIDNEXT`-as-token design
/// [`crate::ews::find_or_sync_items`]'s doc explains in full — new mail is
/// reported correctly; a deletion or flag change since the last `Sync` is
/// not, for the same honestly-stated reason (no tombstone log).
async fn sync_response(ctx: &Context<'_>, mailbox: &Address, body: &[u8]) -> Vec<u8> {
    let Some(server_id) = find_text(body, PAGE_AIRSYNC, airsync::COLLECTION_ID) else {
        return status_only_document(PAGE_AIRSYNC, airsync::SYNC, airsync::STATUS, "8"); // 8 = object not found
    };
    let Some(folder) = folder_from_slug(&server_id) else {
        return status_only_document(PAGE_AIRSYNC, airsync::SYNC, airsync::STATUS, "8");
    };

    let requested_key = find_text(body, PAGE_AIRSYNC, airsync::SYNC_KEY);
    let since: Option<u32> = requested_key.as_deref().filter(|k| *k != "0").and_then(|k| k.parse().ok());

    let Ok(mut uids) = ctx.maildir.list(mailbox, folder).await else {
        return status_only_document(PAGE_AIRSYNC, airsync::SYNC, airsync::STATUS, "8");
    };
    uids.sort();
    if let Some(since) = since {
        uids.retain(|uid| uid.0 >= since);
    }
    let next_token = ctx.maildir.uid_next(mailbox, folder).await;

    let mut w = Writer::new();
    w.switch_page(PAGE_AIRSYNC);
    w.start_tag(airsync::SYNC);
    w.start_tag(airsync::COLLECTIONS);
    w.start_tag(airsync::COLLECTION);
    w.text_tag(airsync::CLASS, "Email");
    w.text_tag(airsync::SYNC_KEY, &next_token.to_string());
    w.text_tag(airsync::COLLECTION_ID, &server_id);
    w.text_tag(airsync::STATUS, STATUS_SUCCESS);
    if !uids.is_empty() {
        w.start_tag(airsync::COMMANDS);
        for uid in &uids {
            w.start_tag(airsync::ADD);
            w.text_tag(airsync::SERVER_ID, &item_server_id(folder, *uid));
            w.start_tag(airsync::APPLICATION_DATA);
            let subject =
                ctx.maildir.fetch(mailbox, folder, *uid).await.ok().and_then(|m| m.header("subject")).unwrap_or_default();
            w.switch_page(PAGE_AIRSYNCBASE);
            w.start_tag(airsyncbase::BODY);
            w.text_tag(airsyncbase::TYPE, "1"); // 1 = plain text (subject stands in; full body via ItemOperations Fetch)
            w.text_tag(airsyncbase::DATA, &subject);
            w.end_tag(); // Body
            w.switch_page(PAGE_AIRSYNC);
            w.end_tag(); // ApplicationData
            w.end_tag(); // Add
        }
        w.end_tag(); // Commands
    }
    w.end_tag(); // Collection
    w.end_tag(); // Collections
    w.end_tag(); // Sync
    w.finish()
}

/// A `ServerId` naming one message: `"<folder-slug>:<uid>"`, plain text
/// rather than base64 — ActiveSync `ServerId`s are ordinary strings on the
/// wire (unlike EWS `ItemId`, which convention shapes as opaque base64), and
/// this one only ever needs to round-trip through this server itself.
fn item_server_id(folder: Folder, uid: Uid) -> String {
    format!("{}:{}", folder_slug(folder), uid.0)
}

fn item_id_from_server_id(id: &str) -> Option<(Folder, Uid)> {
    let (slug, uid) = id.split_once(':')?;
    Some((folder_from_slug(slug)?, Uid(uid.parse().ok()?)))
}

// ---------------------------------------------------------------------------
// ItemOperations (Fetch — the whole-message equivalent of EWS's GetItem)
// ---------------------------------------------------------------------------

async fn item_operations_response(ctx: &Context<'_>, mailbox: &Address, body: &[u8]) -> Vec<u8> {
    let Some(server_id) = find_text(body, PAGE_AIRSYNC, airsync::SERVER_ID) else {
        return status_only_document(PAGE_ITEMOPERATIONS, item_operations::ITEM_OPERATIONS, item_operations::STATUS, "2");
    };
    let found = item_id_from_server_id(&server_id);

    let mut w = Writer::new();
    w.switch_page(PAGE_ITEMOPERATIONS);
    w.start_tag(item_operations::ITEM_OPERATIONS);
    match found {
        Some((folder, uid)) => match ctx.maildir.fetch(mailbox, folder, uid).await {
            Ok(message) => {
                w.text_tag(item_operations::STATUS, STATUS_SUCCESS);
                w.start_tag(item_operations::RESPONSE);
                w.start_tag(item_operations::FETCH);
                w.text_tag(item_operations::STATUS, STATUS_SUCCESS);
                w.start_tag(item_operations::PROPERTIES);
                w.switch_page(PAGE_AIRSYNCBASE);
                w.start_tag(airsyncbase::BODY);
                w.text_tag(airsyncbase::TYPE, "4"); // 4 = MIME — the raw-bytes shortcut, same as EWS's MimeContent
                w.start_tag(airsyncbase::DATA);
                w.opaque(message.as_bytes()); // WBXML's native binary token — no base64 needed, unlike EWS's XML text
                w.end_tag(); // Data
                w.end_tag(); // Body
                w.switch_page(PAGE_ITEMOPERATIONS);
                w.end_tag(); // Properties
                w.end_tag(); // Fetch
                w.end_tag(); // Response
            }
            Err(_) => {
                w.text_tag(item_operations::STATUS, "2"); // 2 = protocol/data error
            }
        },
        None => {
            w.text_tag(item_operations::STATUS, "2");
        }
    }
    w.end_tag(); // ItemOperations
    w.finish()
}

// ---------------------------------------------------------------------------
// SendMail
// ---------------------------------------------------------------------------

async fn send_mail_response(ctx: &Context<'_>, mailbox: &Address, body: &[u8]) -> Vec<u8> {
    let status = match compose_mime(body) {
        Some(raw) => match Message::parse(raw) {
            Ok(message) => {
                let recipients = context::recipients_from_message(&message);
                let save = find_text(body, PAGE_COMPOSEMAIL, compose_mail::SAVE_IN_SENT_ITEMS).is_some()
                    || has_empty_tag(body, PAGE_COMPOSEMAIL, compose_mail::SAVE_IN_SENT_ITEMS);
                let sent = context::send(ctx, mailbox, recipients, &message).await.is_ok();
                if sent && save {
                    let _ = ctx.maildir.save(mailbox, Folder::Sent, &message).await;
                }
                if sent { STATUS_SUCCESS } else { "6" } // 6 = server error
            }
            Err(_) => "6",
        },
        None => "6",
    };

    let mut w = Writer::new();
    w.switch_page(PAGE_COMPOSEMAIL);
    w.start_tag(compose_mail::SEND_MAIL);
    w.text_tag(compose_mail::STATUS, status);
    w.end_tag();
    w.finish()
}

/// The raw MIME bytes a `SendMail` request carries in its `Mime` element —
/// opaque binary on the wire, the ActiveSync equivalent of EWS's base64
/// `MimeContent`.
fn compose_mime(body: &[u8]) -> Option<Vec<u8>> {
    let mut reader = Reader::new(body)?;
    let mut current_page = 0u8;
    loop {
        match reader.next()? {
            Token::SwitchPage(p) => current_page = p,
            Token::Tag { code, has_content: true } if current_page == PAGE_COMPOSEMAIL && code == compose_mail::MIME => {
                return match reader.next()? {
                    Token::Opaque(bytes) => Some(bytes),
                    _ => None,
                };
            }
            _ => {}
        }
    }
}

/// Whether an empty (no-content) tag at `(page, code)` appears anywhere —
/// `SaveInSentItems` is a presence flag, sent as a childless tag rather than
/// with text content, so [`find_text`] cannot see it.
fn has_empty_tag(body: &[u8], page: u8, code: u8) -> bool {
    let Some(reader) = Reader::new(body) else { return false };
    let mut current_page = 0u8;
    for token in reader {
        match token {
            Token::SwitchPage(p) => current_page = p,
            Token::Tag { code: c, has_content: false } if current_page == page && c == code => return true,
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Maildir;
    use std::path::PathBuf;

    fn temp_root() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let ordinal = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("selfhost-eas-{}-{}-{ordinal}", std::process::id(), nanos));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn addr(s: &str) -> Address {
        Address::parse(s).unwrap()
    }

    fn msg(headers: &str, body: &str) -> Message {
        Message::parse(format!("{headers}\r\n\r\n{body}").into_bytes()).unwrap()
    }

    struct Fixture {
        data_dir: PathBuf,
        maildir: Maildir,
        mailbox: Address,
        domains: Vec<String>,
    }

    impl Fixture {
        fn new() -> Self {
            let data_dir = temp_root();
            let mailbox = addr("dave@example.com");
            let maildir = Maildir::open(&data_dir, std::slice::from_ref(&mailbox), &[]).unwrap();
            Self { data_dir, maildir, mailbox, domains: vec!["example.com".to_owned()] }
        }

        fn ctx(&self) -> Context<'_> {
            Context {
                maildir: &self.maildir,
                data_dir: &self.data_dir,
                hostname: "mail.example.com",
                local_domains: &self.domains,
            }
        }
    }

    fn provision_request() -> Vec<u8> {
        let mut w = Writer::new();
        w.switch_page(PAGE_PROVISION);
        w.start_tag(provision::PROVISION);
        w.start_tag(provision::POLICIES);
        w.start_tag(provision::POLICY);
        w.text_tag(provision::POLICY_TYPE, "MS-EAS-Provisioning-WBXML");
        w.end_tag();
        w.end_tag();
        w.end_tag();
        w.finish()
    }

    fn folder_sync_request(sync_key: &str) -> Vec<u8> {
        let mut w = Writer::new();
        w.switch_page(PAGE_FOLDERHIERARCHY);
        w.start_tag(folder_hierarchy::FOLDER_SYNC);
        w.text_tag(folder_hierarchy::SYNC_KEY, sync_key);
        w.end_tag();
        w.finish()
    }

    fn sync_request(server_id: &str, sync_key: &str) -> Vec<u8> {
        let mut w = Writer::new();
        w.switch_page(PAGE_AIRSYNC);
        w.start_tag(airsync::SYNC);
        w.start_tag(airsync::COLLECTIONS);
        w.start_tag(airsync::COLLECTION);
        w.text_tag(airsync::SYNC_KEY, sync_key);
        w.text_tag(airsync::COLLECTION_ID, server_id);
        w.end_tag();
        w.end_tag();
        w.end_tag();
        w.finish()
    }

    fn fetch_request(server_id: &str) -> Vec<u8> {
        let mut w = Writer::new();
        w.switch_page(PAGE_ITEMOPERATIONS);
        w.start_tag(item_operations::ITEM_OPERATIONS);
        w.start_tag(item_operations::FETCH);
        w.switch_page(PAGE_AIRSYNC);
        w.text_tag(airsync::SERVER_ID, server_id);
        w.switch_page(PAGE_ITEMOPERATIONS);
        w.end_tag();
        w.end_tag();
        w.finish()
    }

    fn send_mail_request(mime: &[u8], save_in_sent: bool) -> Vec<u8> {
        let mut w = Writer::new();
        w.switch_page(PAGE_COMPOSEMAIL);
        w.start_tag(compose_mail::SEND_MAIL);
        if save_in_sent {
            w.empty_tag(compose_mail::SAVE_IN_SENT_ITEMS);
        }
        w.start_tag(compose_mail::MIME);
        w.opaque(mime);
        w.end_tag();
        w.end_tag();
        w.finish()
    }

    #[tokio::test]
    async fn provision_accepts_and_echoes_the_requested_policy_type() {
        let fx = Fixture::new();
        let response = handle(&fx.ctx(), &fx.mailbox, &provision_request()).await;
        assert_eq!(find_text(&response, PAGE_PROVISION, provision::STATUS).as_deref(), Some(STATUS_SUCCESS));
        assert_eq!(
            find_text(&response, PAGE_PROVISION, provision::POLICY_TYPE).as_deref(),
            Some("MS-EAS-Provisioning-WBXML")
        );
        assert_eq!(find_text(&response, PAGE_PROVISION, provision::POLICY_KEY).as_deref(), Some("1"));
    }

    #[tokio::test]
    async fn folder_sync_adds_every_folder_on_first_sync_and_nothing_on_the_second() {
        let fx = Fixture::new();
        let first = handle(&fx.ctx(), &fx.mailbox, &folder_sync_request("0")).await;
        assert_eq!(find_text(&first, PAGE_FOLDERHIERARCHY, folder_hierarchy::STATUS).as_deref(), Some(STATUS_SUCCESS));
        assert_eq!(find_text(&first, PAGE_FOLDERHIERARCHY, folder_hierarchy::COUNT).as_deref(), Some("5"));
        assert_eq!(find_text(&first, PAGE_FOLDERHIERARCHY, folder_hierarchy::SERVER_ID).as_deref(), Some("inbox"));

        let second = handle(&fx.ctx(), &fx.mailbox, &folder_sync_request("1")).await;
        assert_eq!(find_text(&second, PAGE_FOLDERHIERARCHY, folder_hierarchy::COUNT).as_deref(), Some("0"));
        assert_eq!(find_text(&second, PAGE_FOLDERHIERARCHY, folder_hierarchy::SERVER_ID), None);
    }

    #[tokio::test]
    async fn sync_reports_a_delivered_message_and_advances_the_sync_key() {
        let fx = Fixture::new();
        fx.maildir.deliver(&fx.mailbox, &msg("Subject: hello", "body")).await.unwrap();

        let response = handle(&fx.ctx(), &fx.mailbox, &sync_request("inbox", "0")).await;
        assert_eq!(find_text(&response, PAGE_AIRSYNC, airsync::STATUS).as_deref(), Some(STATUS_SUCCESS));
        assert_eq!(find_text(&response, PAGE_AIRSYNC, airsync::SERVER_ID).as_deref(), Some("inbox:1"));
        let key = find_text(&response, PAGE_AIRSYNC, airsync::SYNC_KEY).unwrap();
        assert_ne!(key, "0");
    }

    #[tokio::test]
    async fn sync_against_an_unknown_folder_reports_object_not_found() {
        let fx = Fixture::new();
        let response = handle(&fx.ctx(), &fx.mailbox, &sync_request("not-a-real-folder", "0")).await;
        assert_eq!(find_text(&response, PAGE_AIRSYNC, airsync::STATUS).as_deref(), Some("8"));
    }

    #[tokio::test]
    async fn item_operations_fetch_serves_the_raw_message_as_opaque_mime() {
        let fx = Fixture::new();
        fx.maildir.deliver(&fx.mailbox, &msg("Subject: raw", "the body")).await.unwrap();

        let response = handle(&fx.ctx(), &fx.mailbox, &fetch_request("inbox:1")).await;
        assert_eq!(find_text(&response, PAGE_ITEMOPERATIONS, item_operations::STATUS).as_deref(), Some(STATUS_SUCCESS));

        let reader = Reader::new(&response).unwrap();
        let mut mime = None;
        for token in reader {
            if let Token::Opaque(bytes) = token {
                mime = Some(bytes);
            }
        }
        let mime = String::from_utf8(mime.unwrap()).unwrap();
        assert!(mime.contains("the body"));
        assert!(mime.contains("Subject: raw"));
    }

    #[tokio::test]
    async fn item_operations_fetch_of_an_unknown_id_reports_an_error_status() {
        let fx = Fixture::new();
        let response = handle(&fx.ctx(), &fx.mailbox, &fetch_request("inbox:999")).await;
        assert_eq!(find_text(&response, PAGE_ITEMOPERATIONS, item_operations::STATUS).as_deref(), Some("2"));
    }

    #[tokio::test]
    async fn send_mail_queues_outbound_and_saves_to_sent_when_asked() {
        let fx = Fixture::new();
        let mime = msg("Subject: outgoing\r\nTo: stranger@elsewhere.example", "hi").as_bytes().to_vec();
        let response = handle(&fx.ctx(), &fx.mailbox, &send_mail_request(&mime, true)).await;
        assert_eq!(find_text(&response, PAGE_COMPOSEMAIL, compose_mail::STATUS).as_deref(), Some(STATUS_SUCCESS));

        let sent = fx.maildir.list(&fx.mailbox, Folder::Sent).await.unwrap();
        assert_eq!(sent.len(), 1);

        let queue = crate::client::OutboundQueue::open(&fx.data_dir).unwrap();
        assert_eq!(queue.list().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn send_mail_without_save_in_sent_items_does_not_save_a_copy() {
        let fx = Fixture::new();
        let mime = msg("Subject: outgoing\r\nTo: stranger@elsewhere.example", "hi").as_bytes().to_vec();
        handle(&fx.ctx(), &fx.mailbox, &send_mail_request(&mime, false)).await;
        assert_eq!(fx.maildir.list(&fx.mailbox, Folder::Sent).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn an_unrecognised_root_tag_reports_a_protocol_error_status() {
        let mut w = Writer::new();
        w.switch_page(PAGE_AIRSYNC);
        w.empty_tag(0x3f); // not a code this module recognises as any operation's root
        let request = w.finish();

        let fx = Fixture::new();
        let response = handle(&fx.ctx(), &fx.mailbox, &request).await;
        assert_eq!(find_text(&response, PAGE_AIRSYNC, airsync::STATUS).as_deref(), Some("3"));
    }
}
