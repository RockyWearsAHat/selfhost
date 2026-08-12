//! Exchange Web Services — the protocol macOS Mail actually drives a mailbox
//! over once Autodiscover ([`crate::autodiscover`]) points it here.
//!
//! A deliberately narrow subset: enough operations for Mail to list, read,
//! send, flag, and delete mail, each mapped straight onto the existing
//! [`crate::store::Maildir`] rather than a second, EWS-shaped mail store.
//! `GetItem`/`CreateItem` serve/accept the message as raw MIME via
//! `<t:MimeContent>` — a real, spec-legal shortcut (EWS defines
//! `MimeContent` precisely so a server need not map every field to its own
//! structured item properties) — rather than reconstructing headers,
//! recipients, and body parts from this store's own `Message` type field by
//! field.
//!
//! Folder ids are the fixed literal `DistinguishedFolderId` names real
//! Exchange uses (`"inbox"`, `"drafts"`, `"sentitems"`, `"deleteditems"`,
//! `"junkemail"`) — this deployment's folder set is exactly that fixed list,
//! so there is nothing to allocate an id for. Item ids are opaque
//! base64 tokens encoding `(folder, uid)`; a client is only ever expected to
//! echo an item id back, never interpret it, so there is no server-side
//! session or lookup table to keep in sync — the token *is* the state,
//! exactly as this store's own filenames already encode everything IMAP
//! needs.
//!
//! No XML crate exists anywhere in this workspace; [`crate::xml`] is the
//! shared scanner every operation here uses to read its request and every
//! response is built as a plain string, the same house style
//! `crates/storage/src/dav` uses for WebDAV.

use crate::address::Address;
use crate::context::{self, Context};
use crate::dkim::{b64_decode, b64_encode};
use crate::message::Message;
use crate::store::{folder_display_name, folder_from_slug, folder_slug, Folder, Uid, FOLDERS};
use crate::xml::{attr_value, attr_values, element_text, escape};

/// Handles one authenticated EWS SOAP request and returns the full response
/// envelope's bytes — never fails outright: a request this server cannot
/// make sense of gets a SOAP `Fault`, not a transport error, because a
/// malformed *body* on an already-authenticated, already-TLS'd connection is
/// a client bug to report in-band, not a reason to drop the connection.
pub async fn handle(ctx: &Context<'_>, mailbox: &Address, body: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(body) else {
        return soap_envelope(&fault("ErrorInvalidRequest", "request body was not valid UTF-8"));
    };

    // Checked in roughly most-frequent-first order; the names are disjoint
    // (`crate::xml::has_element`'s own tests cover why a longer name never
    // false-positives a shorter one), so order only affects which operation
    // wins if a client somehow sent more than one — never true in practice.
    let inner = if has(text, "FindItem") {
        find_or_sync_items(ctx, mailbox, text, false).await
    } else if has(text, "SyncFolderItems") {
        find_or_sync_items(ctx, mailbox, text, true).await
    } else if has(text, "GetItem") {
        get_item(ctx, mailbox, text).await
    } else if has(text, "CreateItem") {
        create_item(ctx, mailbox, text).await
    } else if has(text, "DeleteItem") {
        delete_item(ctx, mailbox, text).await
    } else if has(text, "UpdateItem") {
        update_item(ctx, mailbox, text).await
    } else if has(text, "SyncFolderHierarchy") {
        sync_folder_hierarchy(text)
    } else if has(text, "FindFolder") {
        find_folder()
    } else if has(text, "GetFolder") {
        get_folder(text)
    } else if has(text, "ResolveNames") {
        resolve_names(mailbox)
    } else {
        fault("ErrorInvalidRequest", "unrecognised or unsupported operation")
    };

    soap_envelope(&inner)
}

/// Whether `body` names `name`'s operation element — thin wrapper so this
/// file reads as a dispatch table rather than a wall of `xml::` calls.
fn has(body: &str, name: &str) -> bool {
    crate::xml::has_element(body, name)
}

// ---------------------------------------------------------------------------
// Item id encoding — folder naming itself is shared, see `crate::store`
// ---------------------------------------------------------------------------

/// Encodes an item id as opaque base64 over `"<folder-slug>:<uid>"` — see the
/// module doc for why this needs no server-side table.
fn encode_item_id(folder: Folder, uid: Uid) -> String {
    b64_encode(format!("{}:{}", folder_slug(folder), uid.0).as_bytes())
}

/// Decodes an item id a client echoed back. `None` for anything this server
/// did not itself mint — a stale id from a different mailbox, a client typo,
/// or an attempt to guess one — which every caller treats as "not found"
/// rather than a parse error, so probing for other mailboxes' items looks
/// identical to asking for one that never existed.
fn decode_item_id(id: &str) -> Option<(Folder, Uid)> {
    let bytes = b64_decode(id).ok()?;
    let text = String::from_utf8(bytes).ok()?;
    let (slug, uid) = text.split_once(':')?;
    Some((folder_from_slug(slug)?, Uid(uid.parse().ok()?)))
}

// ---------------------------------------------------------------------------
// SOAP envelope and fault
// ---------------------------------------------------------------------------

const NAMESPACES: &str = "xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" \
     xmlns:t=\"http://schemas.microsoft.com/exchange/services/2006/types\" \
     xmlns:m=\"http://schemas.microsoft.com/exchange/services/2006/messages\"";

fn soap_envelope(body: &str) -> Vec<u8> {
    format!("<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope {NAMESPACES}><soap:Body>{body}</soap:Body></soap:Envelope>")
        .into_bytes()
}

fn fault(code: &str, reason: &str) -> String {
    format!(
        "<soap:Fault><faultcode>soap:Client</faultcode><faultstring>{}</faultstring>\
         <detail><t:ResponseCode>{code}</t:ResponseCode></detail></soap:Fault>",
        escape(reason)
    )
}

/// Wraps one response message in the `ResponseMessages`/`Success` envelope
/// every EWS operation response shares, so each operation only builds its
/// own inner content.
fn response_message(operation: &str, class: &str, code: &str, inner: &str) -> String {
    format!(
        "<m:{operation}Response>\
         <m:ResponseMessages>\
         <m:{operation}ResponseMessage ResponseClass=\"{class}\">\
         <m:ResponseCode>{code}</m:ResponseCode>\
         {inner}\
         </m:{operation}ResponseMessage>\
         </m:ResponseMessages>\
         </m:{operation}Response>"
    )
}

// ---------------------------------------------------------------------------
// ResolveNames
// ---------------------------------------------------------------------------

/// Always resolves to the one authenticated mailbox — this server has
/// exactly one identity per connection, so there is nothing else a name
/// could mean.
fn resolve_names(mailbox: &Address) -> String {
    let address = escape(&mailbox.to_string());
    let name = escape(mailbox.local());
    let resolution = format!(
        "<t:Resolution><t:Mailbox><t:Name>{name}</t:Name><t:EmailAddress>{address}</t:EmailAddress>\
         <t:RoutingType>SMTP</t:RoutingType><t:MailboxType>Mailbox</t:MailboxType></t:Mailbox></t:Resolution>"
    );
    response_message(
        "ResolveNames",
        "Success",
        "NoError",
        &format!(
            "<m:ResolutionSet TotalItemsInView=\"1\" IncludesLastItemInRange=\"true\">{resolution}</m:ResolutionSet>"
        ),
    )
}

// ---------------------------------------------------------------------------
// Folder hierarchy: GetFolder, FindFolder, SyncFolderHierarchy
// ---------------------------------------------------------------------------

fn folder_xml(folder: Folder) -> String {
    format!(
        "<t:Folder><t:FolderId Id=\"{}\"/><t:DisplayName>{}</t:DisplayName></t:Folder>",
        folder_slug(folder),
        folder_display_name(folder)
    )
}

fn get_folder(body: &str) -> String {
    let requested = attr_values(body, "Id");
    let messages: String = requested
        .iter()
        .map(|id| match folder_from_slug(id) {
            Some(folder) => response_message("GetFolder", "Success", "NoError", &folder_xml(folder)),
            None => response_message("GetFolder", "Error", "ErrorFolderNotFound", ""),
        })
        .collect();
    // `GetFolder` returns one response message per requested id, so the
    // per-message wrapper `response_message` already builds is repeated
    // rather than nested — strip the outer `m:GetFolderResponse` duplicate
    // wrapping by re-joining only the `ResponseMessages` contents.
    format!(
        "<m:GetFolderResponse><m:ResponseMessages>{}</m:ResponseMessages></m:GetFolderResponse>",
        strip_response_wrapper(&messages, "GetFolder")
    )
}

/// Everything this store offers is a top-level folder, so `FindFolder`
/// answers the same fixed set regardless of which parent was asked for.
fn find_folder() -> String {
    let folders: String = FOLDERS.into_iter().map(folder_xml).collect();
    response_message(
        "FindFolder",
        "Success",
        "NoError",
        &format!(
            "<m:RootFolder TotalItemsInView=\"{}\" IncludesLastItemInRange=\"true\"><t:Folders>{folders}</t:Folders></m:RootFolder>",
            FOLDERS.len()
        ),
    )
}

/// A fixed sync token: the folder set on this deployment never changes, so
/// there is nothing to report on a second sync with the same token — the
/// caller either has no state yet (anything other than `"1"`, including
/// absent) and gets every folder as a `Create`, or already has `"1"` and gets
/// an empty change set.
const FOLDER_SYNC_TOKEN: &str = "1";

/// The `<m:SyncState>`/`<t:SyncState>` a client sent back, if any — shared by
/// `SyncFolderHierarchy` (an opaque fixed token, see [`FOLDER_SYNC_TOKEN`])
/// and `SyncFolderItems` (a per-folder `UIDNEXT`, see [`find_or_sync_items`]).
fn sync_state(body: &str) -> Option<String> {
    element_text(body, "SyncState")
}

fn sync_folder_hierarchy(body: &str) -> String {
    let first_sync = sync_state(body).as_deref() != Some(FOLDER_SYNC_TOKEN);
    let changes = if first_sync {
        let creates: String = FOLDERS.into_iter().map(|f| format!("<t:Create>{}</t:Create>", folder_xml(f))).collect();
        format!("<m:Changes>{creates}</m:Changes>")
    } else {
        "<m:Changes/>".to_owned()
    };
    response_message(
        "SyncFolderHierarchy",
        "Success",
        "NoError",
        &format!("<m:SyncState>{FOLDER_SYNC_TOKEN}</m:SyncState><m:IncludesLastFolderInRange>true</m:IncludesLastFolderInRange>{changes}"),
    )
}

/// Strips one layer of `<m:{op}Response><m:ResponseMessages>...</m:ResponseMessages></m:{op}Response>`
/// wrapping so several per-item response messages can be re-joined under one
/// shared `ResponseMessages` element, as `GetFolder`/`GetItem` need for a
/// multi-id request.
fn strip_response_wrapper(joined_messages: &str, operation: &str) -> String {
    let open = format!("<m:{operation}Response><m:ResponseMessages>");
    let close = format!("</m:ResponseMessages></m:{operation}Response>");
    joined_messages.replace(&open, "").replace(&close, "")
}

// ---------------------------------------------------------------------------
// Items: FindItem / SyncFolderItems, GetItem, CreateItem, UpdateItem, DeleteItem
// ---------------------------------------------------------------------------

/// `FindItem` (a full listing) and `SyncFolderItems` (an incremental one)
/// share almost everything: both name one folder and return item summaries
/// for it. The difference is what a repeat call means — `FindItem` always
/// lists everything again; `SyncFolderItems` is asked to report only what
/// changed since a `SyncState` it was given last time.
///
/// The sync token used here is the folder's own `UIDNEXT` at the moment of
/// the response (`Maildir::uid_next`) — UIDs are monotonic per folder, so a
/// client that comes back with an old `UIDNEXT` is a client asking "what's
/// new since this many messages existed", which is exactly `uid >= token`.
/// Honest limitation, stated rather than hidden: this reports new messages
/// correctly but not deletions or flag changes made since the last sync —
/// there is no tombstone log — so `IncludesLastItemInRange` is always `true`
/// and a client that needs to notice a deletion falls back to a later full
/// `FindItem`.
async fn find_or_sync_items(ctx: &Context<'_>, mailbox: &Address, body: &str, incremental: bool) -> String {
    let operation = if incremental { "SyncFolderItems" } else { "FindItem" };
    let Some(folder) = attr_value(body, "Id").as_deref().and_then(folder_from_slug) else {
        return response_message(operation, "Error", "ErrorFolderNotFound", "");
    };

    let since: Option<u32> = if incremental { sync_state(body).and_then(|s| s.parse().ok()) } else { None };

    let Ok(mut uids) = ctx.maildir.list(mailbox, folder).await else {
        return response_message(operation, "Error", "ErrorItemNotFound", "");
    };
    uids.sort();
    if let Some(since) = since {
        uids.retain(|uid| uid.0 >= since);
    }

    let mut items = String::new();
    for uid in &uids {
        let summary = item_summary_xml(ctx, mailbox, folder, *uid).await;
        if incremental {
            items.push_str(&format!("<t:Create>{summary}</t:Create>"));
        } else {
            items.push_str(&summary);
        }
    }

    if incremental {
        let next_token = ctx.maildir.uid_next(mailbox, folder).await;
        response_message(
            operation,
            "Success",
            "NoError",
            &format!(
                "<m:SyncState>{next_token}</m:SyncState><m:IncludesLastItemInRange>true</m:IncludesLastItemInRange><m:Changes>{items}</m:Changes>"
            ),
        )
    } else {
        response_message(
            operation,
            "Success",
            "NoError",
            &format!(
                "<m:RootFolder TotalItemsInView=\"{}\" IncludesLastItemInRange=\"true\"><t:Items>{items}</t:Items></m:RootFolder>",
                uids.len()
            ),
        )
    }
}

/// One item's summary — used by both `FindItem`'s flat `<t:Items>` list and
/// `SyncFolderItems`' `<t:Create>`-wrapped one; the caller supplies the
/// wrapping since only it knows which operation is asking.
async fn item_summary_xml(ctx: &Context<'_>, mailbox: &Address, folder: Folder, uid: Uid) -> String {
    let id = encode_item_id(folder, uid);
    let subject = ctx
        .maildir
        .fetch(mailbox, folder, uid)
        .await
        .ok()
        .and_then(|message| message.header("subject"))
        .unwrap_or_default();
    format!(
        "<t:Message><t:ItemId Id=\"{id}\" ChangeKey=\"1\"/><t:Subject>{}</t:Subject></t:Message>",
        escape(&subject)
    )
}

async fn get_item(ctx: &Context<'_>, mailbox: &Address, body: &str) -> String {
    let ids = attr_values(body, "Id");
    if ids.is_empty() {
        return response_message("GetItem", "Error", "ErrorInvalidRequest", "");
    }

    let mut messages = String::new();
    for id in &ids {
        let found = match decode_item_id(id) {
            Some((folder, uid)) => ctx.maildir.fetch(mailbox, folder, uid).await.ok(),
            None => None,
        };
        let inner = found.map(|message| {
            let mime = b64_encode(message.as_bytes());
            let subject = escape(&message.header("subject").unwrap_or_default());
            format!(
                "<t:Message><t:ItemId Id=\"{id}\" ChangeKey=\"1\"/><t:Subject>{subject}</t:Subject>\
                 <t:MimeContent CharacterSet=\"UTF-8\">{mime}</t:MimeContent></t:Message>"
            )
        });
        let ok = inner.is_some();
        messages.push_str(&response_message(
            "GetItem",
            if ok { "Success" } else { "Error" },
            if ok { "NoError" } else { "ErrorItemNotFound" },
            &inner.unwrap_or_default(),
        ));
    }
    format!(
        "<m:GetItemResponse><m:ResponseMessages>{}</m:ResponseMessages></m:GetItemResponse>",
        strip_response_wrapper(&messages, "GetItem")
    )
}

/// `CreateItem` — a client composing a message: always saves it into the
/// requested folder (`SavedItemFolderId`, default `Drafts`), and, when
/// `MessageDisposition` asks for it, also hands it to
/// [`context::send`] for local delivery / outbound spooling — the same split
/// a client's own SMTP submission goes through.
async fn create_item(ctx: &Context<'_>, mailbox: &Address, body: &str) -> String {
    let Some(mime_b64) = element_text(body, "MimeContent") else {
        return response_message("CreateItem", "Error", "ErrorInvalidRequest", "");
    };
    let Ok(raw) = b64_decode(&mime_b64) else {
        return response_message("CreateItem", "Error", "ErrorInvalidRequest", "");
    };
    let Ok(message) = Message::parse(raw) else {
        return response_message("CreateItem", "Error", "ErrorInvalidRequest", "");
    };

    let disposition = attr_value(body, "MessageDisposition").unwrap_or_else(|| "SaveOnly".to_owned());
    let target = attr_value(body, "Id").as_deref().and_then(folder_from_slug).unwrap_or(Folder::Drafts);

    if disposition.contains("Send") {
        let recipients = context::recipients_from_message(&message);
        if context::send(ctx, mailbox, recipients, &message).await.is_err() {
            return response_message("CreateItem", "Error", "ErrorMessageSizeExceeded", "");
        }
    }
    if disposition != "SendOnly" {
        let save_target = if disposition == "SendAndSaveCopy" && target == Folder::Drafts {
            Folder::Sent
        } else {
            target
        };
        let Ok(uid) = ctx.maildir.save(mailbox, save_target, &message).await else {
            return response_message("CreateItem", "Error", "ErrorInsufficientResources", "");
        };
        let id = encode_item_id(save_target, uid);
        return response_message(
            "CreateItem",
            "Success",
            "NoError",
            &format!("<m:Items><t:Message><t:ItemId Id=\"{id}\" ChangeKey=\"1\"/></t:Message></m:Items>"),
        );
    }
    response_message("CreateItem", "Success", "NoError", "<m:Items/>")
}

async fn delete_item(ctx: &Context<'_>, mailbox: &Address, body: &str) -> String {
    let ids = attr_values(body, "Id");
    if ids.is_empty() {
        return response_message("DeleteItem", "Error", "ErrorInvalidRequest", "");
    }
    let hard = attr_value(body, "DeleteType").as_deref() == Some("HardDelete");

    for id in &ids {
        let Some((folder, uid)) = decode_item_id(id) else { continue };
        if hard || folder == Folder::Trash {
            let _ = ctx.maildir.purge(mailbox, folder, uid).await;
        } else {
            let _ = ctx.maildir.move_message(mailbox, folder, uid, Folder::Trash).await;
        }
    }
    response_message("DeleteItem", "Success", "NoError", "")
}

/// `UpdateItem` — this server honours exactly one field change, `IsRead`
/// (`message:IsRead`), which is the one Mail sends on every read/unread
/// toggle. Any other requested field is silently accepted and ignored rather
/// than faulted: EWS defines dozens of settable fields, and refusing the
/// whole request over one this server does not model would block the read
/// flag change riding alongside it.
async fn update_item(ctx: &Context<'_>, mailbox: &Address, body: &str) -> String {
    let ids = attr_values(body, "Id");
    if ids.is_empty() {
        return response_message("UpdateItem", "Error", "ErrorInvalidRequest", "");
    }
    let is_read = element_text(body, "IsRead").map(|value| value == "true");

    for id in &ids {
        let Some((folder, uid)) = decode_item_id(id) else { continue };
        if let Some(seen) = is_read {
            if let Ok(mut flags) = ctx.maildir.flags(mailbox, folder, uid).await {
                flags.seen = seen;
                let _ = ctx.maildir.set_flags(mailbox, folder, uid, flags).await;
            }
        }
    }
    response_message("UpdateItem", "Success", "NoError", "<m:Items/>")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::OutboundQueue;
    use crate::store::Maildir;
    use std::path::PathBuf;

    /// A directory no other test can collide on — same discipline
    /// `crate::store`'s own tests use.
    fn temp_root() -> PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let ordinal = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("selfhost-ews-{}-{}-{ordinal}", std::process::id(), nanos));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn addr(s: &str) -> Address {
        Address::parse(s).unwrap()
    }

    fn msg(headers: &str, body: &str) -> Message {
        Message::parse(format!("{headers}\r\n\r\n{body}").into_bytes()).unwrap()
    }

    /// One mailbox, one Maildir, one `Context` — every test builds its own so
    /// none can see another's mail.
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

    fn xml(bytes: Vec<u8>) -> String {
        String::from_utf8(bytes).unwrap()
    }

    #[tokio::test]
    async fn an_unrecognised_operation_gets_a_soap_fault() {
        let fx = Fixture::new();
        let response = xml(handle(&fx.ctx(), &fx.mailbox, b"<m:SomeUnknownOperation/>").await);
        assert!(response.contains("<soap:Fault>"));
        assert!(response.contains("ErrorInvalidRequest"));
    }

    #[tokio::test]
    async fn resolve_names_always_resolves_to_the_authenticated_mailbox() {
        let fx = Fixture::new();
        let response = xml(handle(&fx.ctx(), &fx.mailbox, b"<m:ResolveNames><m:UnresolvedEntry>anything</m:UnresolvedEntry></m:ResolveNames>").await);
        assert!(response.contains("<t:EmailAddress>dave@example.com</t:EmailAddress>"));
        assert!(response.contains("ResponseClass=\"Success\""));
    }

    #[tokio::test]
    async fn get_folder_reports_every_requested_distinguished_folder() {
        let fx = Fixture::new();
        let request = r#"<m:GetFolder><m:FolderIds><t:DistinguishedFolderId Id="inbox"/><t:DistinguishedFolderId Id="drafts"/></m:FolderIds></m:GetFolder>"#;
        let response = xml(handle(&fx.ctx(), &fx.mailbox, request.as_bytes()).await);
        assert!(response.contains("<t:DisplayName>Inbox</t:DisplayName>"));
        assert!(response.contains("<t:DisplayName>Drafts</t:DisplayName>"));
    }

    #[tokio::test]
    async fn find_folder_lists_the_whole_fixed_set() {
        let fx = Fixture::new();
        let response = xml(handle(&fx.ctx(), &fx.mailbox, b"<m:FindFolder Traversal=\"Shallow\"/>").await);
        for name in ["Inbox", "Drafts", "Sent Items", "Deleted Items", "Junk Email"] {
            assert!(response.contains(name), "missing {name} in {response}");
        }
    }

    #[tokio::test]
    async fn sync_folder_hierarchy_reports_creates_on_first_sync_and_nothing_on_the_second() {
        let fx = Fixture::new();
        let first = xml(handle(&fx.ctx(), &fx.mailbox, b"<m:SyncFolderHierarchy/>").await);
        assert!(first.contains("<t:Create>"));
        assert!(first.contains("<m:SyncState>1</m:SyncState>"));

        let second_request = b"<m:SyncFolderHierarchy><m:SyncState>1</m:SyncState></m:SyncFolderHierarchy>";
        let second = xml(handle(&fx.ctx(), &fx.mailbox, second_request).await);
        assert!(!second.contains("<t:Create>"));
        assert!(second.contains("<m:Changes/>"));
    }

    #[tokio::test]
    async fn find_item_lists_a_delivered_message_by_subject() {
        let fx = Fixture::new();
        fx.maildir.deliver(&fx.mailbox, &msg("Subject: hello there", "body")).await.unwrap();

        let request = r#"<m:FindItem Traversal="Shallow"><m:ParentFolderIds><t:DistinguishedFolderId Id="inbox"/></m:ParentFolderIds></m:FindItem>"#;
        let response = xml(handle(&fx.ctx(), &fx.mailbox, request.as_bytes()).await);
        assert!(response.contains("<t:Subject>hello there</t:Subject>"));
        assert!(response.contains("TotalItemsInView=\"1\""));
    }

    #[tokio::test]
    async fn sync_folder_items_reports_only_what_arrived_since_the_given_sync_state() {
        let fx = Fixture::new();
        fx.maildir.deliver(&fx.mailbox, &msg("Subject: first", "a")).await.unwrap();

        let request = r#"<m:SyncFolderItems><m:SyncFolderId><t:DistinguishedFolderId Id="inbox"/></m:SyncFolderId></m:SyncFolderItems>"#;
        let first = xml(handle(&fx.ctx(), &fx.mailbox, request.as_bytes()).await);
        assert!(first.contains("<t:Subject>first</t:Subject>"));
        let token = first.split("<m:SyncState>").nth(1).unwrap().split("</m:SyncState>").next().unwrap().to_owned();

        fx.maildir.deliver(&fx.mailbox, &msg("Subject: second", "b")).await.unwrap();
        let second_request = format!(
            r#"<m:SyncFolderItems><m:SyncFolderId><t:DistinguishedFolderId Id="inbox"/></m:SyncFolderId><m:SyncState>{token}</m:SyncState></m:SyncFolderItems>"#
        );
        let second = xml(handle(&fx.ctx(), &fx.mailbox, second_request.as_bytes()).await);
        assert!(second.contains("<t:Subject>second</t:Subject>"));
        assert!(!second.contains("<t:Subject>first</t:Subject>"), "must not re-report an already-synced item");
    }

    #[tokio::test]
    async fn get_item_serves_the_raw_message_as_mime_content() {
        let fx = Fixture::new();
        let uid = fx.maildir.deliver(&fx.mailbox, &msg("Subject: raw", "the body")).await.unwrap();
        let id = encode_item_id(Folder::Inbox, uid);

        let request = format!(r#"<m:GetItem><m:ItemIds><t:ItemId Id="{id}"/></m:ItemIds></m:GetItem>"#);
        let response = xml(handle(&fx.ctx(), &fx.mailbox, request.as_bytes()).await);
        let mime_b64 = response.split("CharacterSet=\"UTF-8\">").nth(1).unwrap().split("</t:MimeContent>").next().unwrap();
        let decoded = String::from_utf8(b64_decode(mime_b64).unwrap()).unwrap();
        assert!(decoded.contains("the body"));
        assert!(decoded.contains("Subject: raw"));
    }

    #[tokio::test]
    async fn get_item_reports_error_for_an_id_this_server_never_minted() {
        let fx = Fixture::new();
        let request = r#"<m:GetItem><m:ItemIds><t:ItemId Id="not-a-real-token"/></m:ItemIds></m:GetItem>"#;
        let response = xml(handle(&fx.ctx(), &fx.mailbox, request.as_bytes()).await);
        assert!(response.contains("ResponseClass=\"Error\""));
        assert!(response.contains("ErrorItemNotFound"));
    }

    #[tokio::test]
    async fn create_item_save_only_lands_in_drafts_by_default() {
        let fx = Fixture::new();
        let mime = b64_encode(msg("Subject: a draft", "draft body").as_bytes());
        let request = format!(
            r#"<m:CreateItem MessageDisposition="SaveOnly"><m:Items><t:Message><t:MimeContent CharacterSet="UTF-8">{mime}</t:MimeContent></t:Message></m:Items></m:CreateItem>"#
        );
        let response = xml(handle(&fx.ctx(), &fx.mailbox, request.as_bytes()).await);
        assert!(response.contains("ResponseClass=\"Success\""));

        let drafts = fx.maildir.list(&fx.mailbox, Folder::Drafts).await.unwrap();
        assert_eq!(drafts.len(), 1);
    }

    #[tokio::test]
    async fn create_item_send_and_save_copy_queues_outbound_and_saves_to_sent() {
        let fx = Fixture::new();
        let mime = b64_encode(msg("Subject: outgoing\r\nTo: stranger@elsewhere.example", "hi").as_bytes());
        let request = format!(
            r#"<m:CreateItem MessageDisposition="SendAndSaveCopy"><m:Items><t:Message><t:MimeContent CharacterSet="UTF-8">{mime}</t:MimeContent></t:Message></m:Items></m:CreateItem>"#
        );
        let response = xml(handle(&fx.ctx(), &fx.mailbox, request.as_bytes()).await);
        assert!(response.contains("ResponseClass=\"Success\""));

        let sent = fx.maildir.list(&fx.mailbox, Folder::Sent).await.unwrap();
        assert_eq!(sent.len(), 1, "a copy must land in Sent");

        let queue = OutboundQueue::open(&fx.data_dir).unwrap();
        assert_eq!(queue.list().unwrap().len(), 1, "the remote recipient must be spooled outbound");
    }

    #[tokio::test]
    async fn create_item_send_and_save_copy_to_a_local_recipient_delivers_directly_not_via_the_queue() {
        let fx = Fixture::new();
        let carol = addr("carol@example.com");
        Maildir::open(&fx.data_dir, &[fx.mailbox.clone(), carol.clone()], &[]).unwrap();
        let mime = b64_encode(msg("Subject: local\r\nTo: carol@example.com", "hi carol").as_bytes());
        let request = format!(
            r#"<m:CreateItem MessageDisposition="SendAndSaveCopy"><m:Items><t:Message><t:MimeContent CharacterSet="UTF-8">{mime}</t:MimeContent></t:Message></m:Items></m:CreateItem>"#
        );
        // Rebuild the fixture's maildir handle so it also knows about carol.
        let maildir = Maildir::open(&fx.data_dir, &[fx.mailbox.clone(), carol.clone()], &[]).unwrap();
        let ctx = Context { maildir: &maildir, data_dir: &fx.data_dir, hostname: "mail.example.com", local_domains: &fx.domains };
        handle(&ctx, &fx.mailbox, request.as_bytes()).await;

        let carol_inbox = maildir.list(&carol, Folder::Inbox).await.unwrap();
        assert_eq!(carol_inbox.len(), 1);
        let queue = OutboundQueue::open(&fx.data_dir).unwrap();
        assert_eq!(queue.list().unwrap().len(), 0, "a local recipient must never be spooled outbound");
    }

    #[tokio::test]
    async fn delete_item_moves_to_trash_by_default() {
        let fx = Fixture::new();
        let uid = fx.maildir.deliver(&fx.mailbox, &msg("Subject: doomed", "x")).await.unwrap();
        let id = encode_item_id(Folder::Inbox, uid);
        let request = format!(r#"<m:DeleteItem><m:ItemIds><t:ItemId Id="{id}"/></m:ItemIds></m:DeleteItem>"#);
        handle(&fx.ctx(), &fx.mailbox, request.as_bytes()).await;

        assert!(fx.maildir.fetch(&fx.mailbox, Folder::Inbox, uid).await.is_err());
        let trash = fx.maildir.list(&fx.mailbox, Folder::Trash).await.unwrap();
        assert_eq!(trash.len(), 1);
    }

    #[tokio::test]
    async fn delete_item_hard_delete_removes_it_for_good() {
        let fx = Fixture::new();
        let uid = fx.maildir.deliver(&fx.mailbox, &msg("Subject: gone", "x")).await.unwrap();
        let id = encode_item_id(Folder::Inbox, uid);
        let request = format!(r#"<m:DeleteItem DeleteType="HardDelete"><m:ItemIds><t:ItemId Id="{id}"/></m:ItemIds></m:DeleteItem>"#);
        handle(&fx.ctx(), &fx.mailbox, request.as_bytes()).await;

        assert!(fx.maildir.fetch(&fx.mailbox, Folder::Inbox, uid).await.is_err());
        assert_eq!(fx.maildir.list(&fx.mailbox, Folder::Trash).await.unwrap().len(), 0, "hard delete must not pass through Trash");
    }

    #[tokio::test]
    async fn update_item_toggles_the_read_flag() {
        let fx = Fixture::new();
        let uid = fx.maildir.deliver(&fx.mailbox, &msg("Subject: read me", "x")).await.unwrap();
        assert!(!fx.maildir.flags(&fx.mailbox, Folder::Inbox, uid).await.unwrap().seen);

        let id = encode_item_id(Folder::Inbox, uid);
        let request = format!(
            r#"<m:UpdateItem><m:ItemChanges><t:ItemChange><t:ItemId Id="{id}"/><t:Updates><t:SetItemField><t:Message><t:IsRead>true</t:IsRead></t:Message></t:SetItemField></t:Updates></t:ItemChange></m:ItemChanges></m:UpdateItem>"#
        );
        handle(&fx.ctx(), &fx.mailbox, request.as_bytes()).await;

        assert!(fx.maildir.flags(&fx.mailbox, Folder::Inbox, uid).await.unwrap().seen);
    }

    #[test]
    fn item_ids_round_trip_through_encode_and_decode() {
        let id = encode_item_id(Folder::Sent, Uid(42));
        assert_eq!(decode_item_id(&id), Some((Folder::Sent, Uid(42))));
    }

    #[test]
    fn decode_item_id_rejects_a_token_this_server_never_minted() {
        assert_eq!(decode_item_id("not-base64!!"), None);
        assert_eq!(decode_item_id(&b64_encode(b"nonsense-with-no-colon")), None);
    }
}
