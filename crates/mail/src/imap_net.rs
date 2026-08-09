//! The IMAP network driver — ports 143 (`STARTTLS`) and 993 (implicit TLS).
//!
//! This is the socket-facing half of [`crate::imap`], the same split
//! [`crate::receive`] and [`crate::submission`] use for SMTP: the state
//! machine there decides what a command means and what store operation it
//! implies; this file performs exactly that operation against
//! [`crate::store::Maildir`] and feeds the result back through the matching
//! `*_result`/`*_complete` method to get the response lines. `imap.rs`'s own
//! module doc names this file `net.rs`; it lives here under a name that does
//! not collide with anything else at the crate root.
//!
//! What this file adds on top of the pure session, because a state machine
//! with no filesystem cannot know it:
//!
//! - **Mailbox name to folder.** `SELECT`/`STATUS`/`FETCH`/`STORE` name a
//!   mailbox by the string the client sent; this maps it to a
//!   [`crate::store::Folder`] and answers `NO` for anything outside the fixed
//!   set `crate::imap` advertises, since [`crate::imap::ISession`] has no
//!   store to check existence against itself.
//! - **`\Seen` on a non-peek `FETCH`.** Set before the message is read, so
//!   the flags returned alongside it are already current.
//! - **STARTTLS.** The plaintext socket is upgraded in place using the same
//!   certificate material the proxy serves, with the same injection defence
//!   `submission.rs` uses: a command already pipelined ahead of the upgrade
//!   is refused and the connection dropped, rather than trusted as if it had
//!   arrived encrypted.
//!
//! What is not here: `\Recent`. This store's on-disk format (see
//! `crate::store`) does not distinguish "delivered since this mailbox was
//! last opened" from an ordinary unread message — Maildir's own `new/` vs
//! `cur/` split would carry that, but nothing here reads which one a UID
//! came from — so `SelectData::recent` is always reported as `0` rather than
//! a number this driver cannot actually measure.

use crate::address::Address;
use crate::imap::{
    FetchPlan, Flag, IAction, IConfig, IResponse, ISession, MessageData, SelectData, Status,
    StorePlan, StoreOp,
};
use crate::store::{Flags as StoreFlags, Folder, Maildir, StoreError, Uid};
use crate::submission::Authenticator;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Everything an IMAP connection needs, assembled once by the daemon.
#[derive(Clone)]
pub struct ImapServer {
    /// How the session answers — hostname, capabilities.
    pub config: IConfig,
    /// The shared Maildir every mailbox is read from.
    pub store: Maildir,
    /// Verifies `LOGIN` credentials — the same authenticator submission uses,
    /// so a mailbox's password is one fact, checked one way.
    pub authenticator: Arc<dyn Authenticator>,
    /// TLS material for `STARTTLS` or implicit TLS. `None` disables both —
    /// `LOGIN` then stays refused for the life of the connection, since
    /// [`IConfig::require_tls_for_auth`] has nothing to upgrade to.
    pub tls: Option<Arc<rustls::ServerConfig>>,
    /// True for the `:993` listener: TLS is already active before the
    /// greeting, and `STARTTLS` is never offered. False for `:143`.
    pub implicit_tls: bool,
}

/// Accepts IMAP connections forever, one task per connection.
///
/// A failed connection is dropped, not logged by return, the same discipline
/// [`crate::receive::serve_smtp`] uses — one malformed or hostile peer must
/// not stop the listener.
pub async fn serve_imap(listener: TcpListener, server: ImapServer) -> io::Result<()> {
    let server = Arc::new(server);
    loop {
        let (stream, peer) = listener.accept().await?;
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let _ = handle_connection(stream, peer, server).await;
        });
    }
}

/// One `[imap]`-tagged line into the daemon's log stream.
///
/// Only connection events, command verbs, and server-authored response lines
/// are ever logged. Command *arguments* never are — `LOGIN` carries the
/// password as an argument and a SASL continuation line is nothing but
/// credentials — which is why client lines pass through [`command_summary`]
/// first. This exists because a mail client's failure report ("unable to
/// verify") says nothing about which step died; the log does.
fn log_imap(peer: SocketAddr, message: impl AsRef<str>) {
    eprintln!("[imap] {peer} {}", message.as_ref());
}

/// The loggable form of one client line: its tag and uppercased verb, with the
/// argument tail dropped (see [`log_imap`] for why the tail must never leak).
fn command_summary(line: &str) -> String {
    let mut tokens = line.split_whitespace();
    let tag = tokens.next().unwrap_or("");
    let verb = tokens.next().unwrap_or("").to_ascii_uppercase();
    format!("{tag} {verb}").trim().to_owned()
}

/// Writes responses to the client, logging the last one — the tagged status
/// line, which is the part that tells an operator how the command ended.
async fn send<S>(peer: SocketAddr, stream: &mut S, responses: &[IResponse]) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    if let Some(last) = responses.last() {
        let text: String = last.text().trim_end().chars().take(96).collect();
        log_imap(peer, format!("<< {text}"));
    }
    write_responses(stream, responses).await
}

/// Drives one connection: the implicit-TLS handshake (`:993`) or the
/// cleartext greeting and optional `STARTTLS` upgrade (`:143`), then commands
/// until the client logs out or the connection closes.
async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    server: Arc<ImapServer>,
) -> io::Result<()> {
    let mut session = ISession::new(server.config.clone());

    if server.implicit_tls {
        let Some(tls) = server.tls.clone() else { return Ok(()) };
        log_imap(peer, "connected (implicit TLS)");
        let mut tls_stream = TlsAcceptor::from(tls).accept(stream).await?;
        session.tls_established();
        tls_stream.write_all(session.greeting().to_wire()).await?;
        let _ = converse(&mut tls_stream, peer, &mut session, &server).await?;
        log_imap(peer, "closed");
        return Ok(());
    }

    let mut stream = stream;
    log_imap(peer, "connected (cleartext, STARTTLS offered)");
    stream.write_all(session.greeting().to_wire()).await?;
    match converse(&mut stream, peer, &mut session, &server).await? {
        Flow::Done => {
            log_imap(peer, "closed");
            Ok(())
        }
        Flow::StartTls => {
            let Some(tls) = server.tls.clone() else { return Ok(()) };
            let mut tls_stream = TlsAcceptor::from(tls).accept(stream).await?;
            session.tls_established();
            log_imap(peer, "TLS established via STARTTLS");
            let _ = converse(&mut tls_stream, peer, &mut session, &server).await?;
            log_imap(peer, "closed");
            Ok(())
        }
    }
}

/// How a conversation ended.
enum Flow {
    /// The client logged out or the connection closed.
    Done,
    /// The client asked to upgrade; the caller performs the handshake.
    StartTls,
}

/// Reads commands and drives the session until it closes or asks for TLS.
///
/// Generic over the transport so the identical loop runs on plaintext and TLS
/// and can be driven by an in-memory duplex in tests, matching
/// `submission.rs`'s `converse`.
async fn converse<S>(
    stream: &mut S,
    peer: SocketAddr,
    session: &mut ISession,
    server: &ImapServer,
) -> io::Result<Flow>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    loop {
        line.clear();
        let read = read_command_line(&mut reader, &mut line).await?;
        if read == 0 {
            return Ok(Flow::Done);
        }

        if session.awaiting_secret() {
            log_imap(peer, ">> <sasl credentials line>");
        } else {
            log_imap(peer, format!(">> {}", command_summary(&line)));
        }

        match session.command(&line) {
            IAction::Respond(responses) => send(peer, reader.get_mut(), &responses).await?,
            IAction::StartTls(response) => {
                // A command already pipelined ahead of the handshake would be
                // plaintext smuggled under the coming TLS session — the same
                // STARTTLS injection flaw `submission.rs` guards against.
                if !reader.buffer().is_empty() {
                    send(
                        peer,
                        reader.get_mut(),
                        &[IResponse::untagged("BAD pipelining after STARTTLS is not allowed")],
                    )
                    .await?;
                    return Ok(Flow::Done);
                }
                send(peer, reader.get_mut(), &[response]).await?;
                return Ok(Flow::StartTls);
            }
            IAction::Login { tag, username, password } => {
                let authenticated = server.authenticator.verify(&username, &password);
                let responses = session.login_result(&tag, authenticated);
                send(peer, reader.get_mut(), &responses).await?;
            }
            IAction::Select { tag, mailbox, read_only } => {
                let responses = match select_or_status_data(server, session, &mailbox).await {
                    Ok(data) => session.select_result(&tag, &mailbox, read_only, data),
                    Err(reason) => vec![IResponse::tagged(&tag, Status::No, reason)],
                };
                send(peer, reader.get_mut(), &responses).await?;
            }
            IAction::Status { tag, mailbox, items } => {
                let responses = match select_or_status_data(server, session, &mailbox).await {
                    Ok(data) => session.status_result(&tag, &mailbox, &items, &data),
                    Err(reason) => vec![IResponse::tagged(&tag, Status::No, reason)],
                };
                send(peer, reader.get_mut(), &responses).await?;
            }
            IAction::Fetch(plan) => {
                let responses = fetch(server, session, &plan).await;
                send(peer, reader.get_mut(), &responses).await?;
            }
            IAction::Store(plan) => {
                let responses = apply_store(server, session, &plan).await;
                send(peer, reader.get_mut(), &responses).await?;
            }
            IAction::Close(responses) => {
                send(peer, reader.get_mut(), &responses).await?;
                return Ok(Flow::Done);
            }
        }
    }
}

/// The enumeration `SELECT`/`EXAMINE`/`STATUS` all need: every UID in the
/// named mailbox, its validity token, the next UID, and the unseen count.
///
/// `Err` names the reason a tagged `NO` should give — an unrecognised
/// mailbox name (`ISession` has no store to check that against itself) or a
/// store error reading it.
async fn select_or_status_data(
    server: &ImapServer,
    session: &ISession,
    mailbox: &str,
) -> Result<SelectData, String> {
    let folder = folder_from_name(mailbox).ok_or_else(|| "no such mailbox".to_owned())?;
    let user = session.user().cloned().ok_or_else(|| "authenticate first".to_owned())?;
    enumerate(&server.store, &user, folder).await.map_err(|error| error.to_string())
}

/// Reads a folder's UIDs and derives the summary `SELECT`/`STATUS` report.
///
/// `\Recent` is not derivable from this store's public surface — see the
/// module doc — so it is always `0`, honestly, rather than a guess.
async fn enumerate(store: &Maildir, user: &Address, folder: Folder) -> Result<SelectData, StoreError> {
    let mut uids = store.list(user, folder).await?;
    uids.sort();
    let uid_validity = store.uid_validity(user).await;
    let uid_next = store.uid_next(user).await;

    let mut first_unseen = None;
    let mut unseen_count = 0u32;
    for (index, uid) in uids.iter().enumerate() {
        let flags = store.flags(user, folder, *uid).await.unwrap_or_default();
        if !flags.seen {
            unseen_count += 1;
            if first_unseen.is_none() {
                first_unseen = Some((index + 1) as u32);
            }
        }
    }

    Ok(SelectData {
        uids: uids.into_iter().map(|uid| uid.0).collect(),
        uid_validity,
        uid_next,
        recent: 0,
        first_unseen,
        unseen_count,
    })
}

/// Performs a `FETCH`: marks `\Seen` first when the plan requires it (so the
/// flags returned alongside a message are already current), loads every
/// message the plan could resolve, and skipped whatever load fails —
/// `fetch_complete` renders only what it is given, exactly as its own doc
/// promises.
async fn fetch(server: &ImapServer, session: &ISession, plan: &FetchPlan) -> Vec<IResponse> {
    let (Some(user), Some(folder)) = (session.user().cloned(), selected_folder(session)) else {
        return vec![IResponse::tagged(&plan.tag, Status::No, "no mailbox selected")];
    };

    if plan.marks_seen() {
        for target in &plan.messages {
            if let Ok(mut flags) = server.store.flags(&user, folder, Uid(target.uid)).await {
                flags.seen = true;
                let _ = server.store.set_flags(&user, folder, Uid(target.uid), flags).await;
            }
        }
    }

    let mut loaded = Vec::new();
    for target in &plan.messages {
        if let Ok(data) = load_message(&server.store, &user, folder, Uid(target.uid)).await {
            loaded.push(data);
        }
    }
    session.fetch_complete(plan, &loaded)
}

/// Performs a `STORE`: applies the flag change to each message's current
/// flags, persists it, and reads the result back so `store_complete` can echo
/// it (unless `.SILENT`).
async fn apply_store(server: &ImapServer, session: &ISession, plan: &StorePlan) -> Vec<IResponse> {
    let (Some(user), Some(folder)) = (session.user().cloned(), selected_folder(session)) else {
        return vec![IResponse::tagged(&plan.tag, Status::No, "no mailbox selected")];
    };

    let mut updated = Vec::new();
    for target in &plan.messages {
        let uid = Uid(target.uid);
        let Ok(current) = server.store.flags(&user, folder, uid).await else { continue };
        let next = apply_store_op(current, plan.op, &plan.flags);
        if server.store.set_flags(&user, folder, uid, next).await.is_err() {
            continue;
        }
        if let Ok(data) = load_message(&server.store, &user, folder, uid).await {
            updated.push(data);
        }
    }
    session.store_complete(plan, &updated)
}

/// The folder the session's selected mailbox name refers to, or `None` for
/// no selection or a name outside the fixed set — both already refused
/// before `FETCH`/`STORE` could reach `ISession`'s selected state with an
/// unrecognised name, so this is a defensive fallback, not the primary check.
fn selected_folder(session: &ISession) -> Option<Folder> {
    session.selected_mailbox().and_then(folder_from_name)
}

/// Loads one message's bytes, flags, and delivery time into the record
/// `FETCH`/`STORE` formatting reads.
async fn load_message(
    store: &Maildir,
    user: &Address,
    folder: Folder,
    uid: Uid,
) -> Result<MessageData, StoreError> {
    let message = store.fetch(user, folder, uid).await?;
    let flags = store.flags(user, folder, uid).await?;
    let when = store.internal_date(user, folder, uid).await?;
    Ok(MessageData {
        uid: uid.0,
        flags: imap_flags(flags),
        internal_date: format_internal_date(when),
        raw: message.as_bytes().to_vec(),
    })
}

/// Maps the fixed mailbox names `crate::imap` advertises to a store folder.
/// `None` for anything else — there is no dynamic folder creation here.
fn folder_from_name(name: &str) -> Option<Folder> {
    match name {
        "INBOX" => Some(Folder::Inbox),
        "Sent" => Some(Folder::Sent),
        "Drafts" => Some(Folder::Drafts),
        "Trash" => Some(Folder::Trash),
        "Junk" => Some(Folder::Junk),
        _ => None,
    }
}

/// Converts the store's flag bits to the wire enum `crate::imap` renders.
fn imap_flags(flags: StoreFlags) -> Vec<Flag> {
    let mut out = Vec::new();
    if flags.seen {
        out.push(Flag::Seen);
    }
    if flags.answered {
        out.push(Flag::Answered);
    }
    if flags.flagged {
        out.push(Flag::Flagged);
    }
    if flags.deleted {
        out.push(Flag::Deleted);
    }
    if flags.draft {
        out.push(Flag::Draft);
    }
    out
}

/// Applies a `STORE` operation to a message's current flags.
fn apply_store_op(current: StoreFlags, op: StoreOp, flags: &[Flag]) -> StoreFlags {
    match op {
        StoreOp::Replace => {
            let mut next = StoreFlags::default();
            for flag in flags {
                set_flag(&mut next, *flag, true);
            }
            next
        }
        StoreOp::Add => {
            let mut next = current;
            for flag in flags {
                set_flag(&mut next, *flag, true);
            }
            next
        }
        StoreOp::Remove => {
            let mut next = current;
            for flag in flags {
                set_flag(&mut next, *flag, false);
            }
            next
        }
    }
}

/// Sets or clears one flag bit.
fn set_flag(flags: &mut StoreFlags, flag: Flag, value: bool) {
    match flag {
        Flag::Seen => flags.seen = value,
        Flag::Answered => flags.answered = value,
        Flag::Flagged => flags.flagged = value,
        Flag::Deleted => flags.deleted = value,
        Flag::Draft => flags.draft = value,
    }
}

/// Renders a delivery time as IMAP's `INTERNALDATE`, e.g.
/// `07-Aug-2026 12:00:00 +0000`.
fn format_internal_date(time: SystemTime) -> String {
    let secs = crate::time::secs_since_epoch(time);
    let (_, year, month, day, hour, minute, second) = crate::time::civil(secs);
    let month_name = crate::time::MONTHS[(month - 1) as usize];
    format!("{day:02}-{month_name}-{year} {hour:02}:{minute:02}:{second:02} +0000")
}

/// Reads one command line, capped so an overlong line cannot exhaust memory.
///
/// `crate::imap::ISession::command` itself refuses anything past
/// [`crate::imap::MAX_COMMAND_LINE`]; the cap here is twice that so the
/// refusal is the one the client sees, not a silent truncation at exactly the
/// boundary.
async fn read_command_line<S>(reader: &mut BufReader<&mut S>, line: &mut String) -> io::Result<usize>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut raw = Vec::new();
    let cap = crate::imap::MAX_COMMAND_LINE * 2;
    loop {
        let mut byte = [0u8; 1];
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        raw.push(byte[0]);
        if byte[0] == b'\n' || raw.len() >= cap {
            break;
        }
    }
    *line = String::from_utf8_lossy(&raw).into_owned();
    Ok(raw.len())
}

/// Writes every response in order.
async fn write_responses<S>(stream: &mut S, responses: &[IResponse]) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    for response in responses {
        stream.write_all(response.to_wire()).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;
    use crate::submission::{hash_password, ConfigAuthenticator};
    use selfhost_config::Mailbox;
    use std::path::PathBuf;
    use std::time::UNIX_EPOCH;
    use tokio::io::duplex;

    fn temp_root(tag: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir =
            std::env::temp_dir().join(format!("selfhost-imapnet-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn addr(s: &str) -> Address {
        Address::parse(s).unwrap()
    }

    /// A server with one mailbox, `dave@example.com` / password `hunter2`,
    /// TLS not required — the network wiring (`STARTTLS`, cert loading) is
    /// already exercised by `submission.rs`'s and `receive.rs`'s own tests;
    /// this crate does not need to prove `tokio_rustls` a second time.
    fn server_with(root: &std::path::Path) -> ImapServer {
        let dave = addr("dave@example.com");
        let store = Maildir::open(root, std::slice::from_ref(&dave), &[]).unwrap();
        let mailbox = Mailbox {
            address: "dave@example.com".into(),
            password_hash: hash_password("hunter2").unwrap(),
            aliases: Vec::new(),
        };
        ImapServer {
            config: IConfig {
                hostname: "mail.example.com".into(),
                tls_available: false,
                require_tls_for_auth: false,
            },
            store,
            authenticator: Arc::new(ConfigAuthenticator::new(std::slice::from_ref(&mailbox))),
            tls: None,
            implicit_tls: false,
        }
    }

    /// Runs one scripted IMAP conversation against `converse` over an
    /// in-memory duplex and returns everything the server wrote back,
    /// greeting included. Mirrors `receive.rs`'s `run_conversation`.
    async fn run_conversation(server: &ImapServer, script: &str) -> String {
        let (mut client, mut server_side) = duplex(64 * 1024);
        let mut session = ISession::new(server.config.clone());
        server_side.write_all(session.greeting().to_wire()).await.unwrap();

        let server = server.clone();
        let peer: SocketAddr = "127.0.0.1:0".parse().expect("a valid dummy peer");
        let handle = tokio::spawn(async move {
            let _ = converse(&mut server_side, peer, &mut session, &server).await;
        });

        client.write_all(script.as_bytes()).await.unwrap();
        let mut out = String::new();
        client.read_to_string(&mut out).await.unwrap();
        handle.await.unwrap();
        out
    }

    #[tokio::test]
    async fn login_select_fetch_and_logout_walks_the_whole_conversation() {
        let root = temp_root("happy-path");
        let server = server_with(&root);
        server
            .store
            .deliver(&addr("dave@example.com"), &Message::parse(b"Subject: hi\r\n\r\nhello".to_vec()).unwrap())
            .await
            .unwrap();

        let script = "\
a LOGIN dave@example.com hunter2\r\n\
b SELECT INBOX\r\n\
c FETCH 1 (UID FLAGS BODY[])\r\n\
d LOGOUT\r\n";
        let out = run_conversation(&server, script).await;

        assert!(out.contains("a OK"), "{out}");
        assert!(out.contains("1 EXISTS"), "{out}");
        assert!(out.contains("c OK FETCH completed"), "{out}");
        assert!(out.contains("hello"), "the body must be in the FETCH response:\n{out}");
        assert!(out.contains("\\Seen"), "a non-peek BODY[] fetch must mark \\Seen:\n{out}");
        assert!(out.contains("d OK LOGOUT completed"), "{out}");
    }

    #[tokio::test]
    async fn a_wrong_password_is_refused() {
        let root = temp_root("wrong-password");
        let server = server_with(&root);

        let out = run_conversation(&server, "a LOGIN dave@example.com wrong\r\nb LOGOUT\r\n").await;
        assert!(out.contains("a NO"), "{out}");
    }

    #[tokio::test]
    async fn selecting_an_unrecognised_mailbox_name_is_refused_not_a_crash() {
        let root = temp_root("unknown-mailbox");
        let server = server_with(&root);

        let out = run_conversation(
            &server,
            "a LOGIN dave@example.com hunter2\r\nb SELECT Nonexistent\r\nc LOGOUT\r\n",
        )
        .await;
        assert!(out.contains("b NO"), "{out}");
    }

    #[tokio::test]
    async fn store_changes_flags_and_the_change_is_read_back() {
        let root = temp_root("store");
        let server = server_with(&root);
        let dave = addr("dave@example.com");
        server.store.deliver(&dave, &Message::parse(b"Subject: hi\r\n\r\nbody".to_vec()).unwrap()).await.unwrap();

        let script = "\
a LOGIN dave@example.com hunter2\r\n\
b SELECT INBOX\r\n\
c STORE 1 +FLAGS (\\Flagged)\r\n\
d LOGOUT\r\n";
        let out = run_conversation(&server, script).await;

        assert!(out.contains("c OK STORE completed"), "{out}");
        assert!(out.contains("\\Flagged"), "the echoed FETCH must show the new flag:\n{out}");

        let flags = server.store.flags(&dave, Folder::Inbox, Uid(1)).await.unwrap();
        assert!(flags.flagged, "the flag must actually be persisted, not just echoed");
    }

    #[tokio::test]
    async fn a_command_pipelined_ahead_of_starttls_is_refused_and_the_connection_dropped() {
        let root = temp_root("starttls-injection");
        let mut server = server_with(&root);
        server.config.tls_available = true;
        server.tls = None; // never reached: the pipelined command must be refused first

        // "STARTTLS" is immediately followed by a second command in the same
        // write, simulating an attacker who pipelines a plaintext command
        // hoping it is later treated as if it had arrived encrypted.
        let out =
            run_conversation(&server, "a STARTTLS\r\nb LOGIN dave@example.com hunter2\r\n").await;

        assert!(out.contains("BAD pipelining"), "{out}");
        // The untagged greeting itself says "OK"; what must never appear is
        // either command's own tag succeeding.
        assert!(!out.contains("a OK") && !out.contains("b OK"), "{out}");
    }
}
