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
//! - **`EXPUNGE`/`MOVE`/`COPY`/`CLOSE`'s actual store work.** `crate::imap`
//!   only resolves *which* UIDs a command names and *which* untagged
//!   responses their removal implies; this file is the one that calls
//!   [`Maildir::purge`]/[`Maildir::move_message`]/[`Maildir::save`] and
//!   decides which UIDs actually went through.
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
    CopyPlan, FetchPlan, Flag, IAction, IConfig, IResponse, ISession, MessageData, MovePlan,
    SelectData, Status, StoreOp, StorePlan,
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
    eprintln!("{} [imap] {peer} {}", crate::time::stamp(), message.as_ref());
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
        // A handshake failure is logged rather than silently propagated: a
        // client that aborts mid-handshake (certificate distrust, probe,
        // version mismatch) otherwise looks identical to one that never spoke.
        let mut tls_stream = match TlsAcceptor::from(tls).accept(stream).await {
            Ok(tls_stream) => tls_stream,
            Err(error) => {
                log_imap(peer, format!("TLS handshake failed: {error}"));
                return Err(error);
            }
        };
        session.tls_established();
        // The SNI name is the one hard fact about what a failing client asked
        // for — an auto-setup validator probes several hostname guesses, and
        // only this line says which guess a given connection was.
        let sni = tls_stream.get_ref().1.server_name().unwrap_or("<none>").to_owned();
        log_imap(peer, format!("TLS established (sni={sni})"));
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
            let mut tls_stream = match TlsAcceptor::from(tls).accept(stream).await {
                Ok(tls_stream) => tls_stream,
                Err(error) => {
                    log_imap(peer, format!("STARTTLS handshake failed: {error}"));
                    return Err(error);
                }
            };
            session.tls_established();
            let sni = tls_stream.get_ref().1.server_name().unwrap_or("<none>").to_owned();
            log_imap(peer, format!("TLS established via STARTTLS (sni={sni})"));
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

        // A bare CRLF between commands is tolerated silently (Postel's law):
        // Apple Mail opens its sync connections with one, and answering it
        // with a `BAD` makes the client drop the connection and give up. An
        // awaited SASL response or literal is exempt — there an empty line is
        // real input (a zero-length literal, or an aborted exchange).
        if line.trim().is_empty() && !session.awaiting_secret() && !session.awaiting_literal() {
            log_imap(peer, ">> (blank line ignored)");
            continue;
        }

        if session.awaiting_secret() {
            log_imap(peer, ">> <sasl credentials line>");
        } else if session.awaiting_literal() {
            // A LOGIN literal line is the username or password itself.
            log_imap(peer, ">> <literal octets>");
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
                if authenticated.is_none() {
                    // Names which half was wrong via the configured address —
                    // the client's own input never reaches the log (the
                    // username field may itself hold a mistyped password).
                    match server.authenticator.resolve(&username) {
                        Some(address) => log_imap(peer, format!("login failed: password mismatch for {address}")),
                        None => log_imap(peer, "login failed: unknown login name"),
                    }
                }
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
            IAction::Expunge { tag } => {
                let responses = apply_expunge(server, session, &tag).await;
                send(peer, reader.get_mut(), &responses).await?;
            }
            IAction::Move(plan) => {
                let responses = apply_move(server, session, &plan).await;
                send(peer, reader.get_mut(), &responses).await?;
            }
            IAction::Copy(plan) => {
                let responses = apply_copy(server, session, &plan).await;
                send(peer, reader.get_mut(), &responses).await?;
            }
            IAction::CloseMailbox { tag, mailbox } => {
                let responses = apply_close(server, session, &tag, &mailbox).await;
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
    let uid_validity = store.uid_validity(user, folder).await;
    let uid_next = store.uid_next(user, folder).await;

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

/// Performs an `EXPUNGE`: purges every `\Deleted` message in the selected
/// folder from the store, then reports the untagged `EXPUNGE`s and shrinks
/// the session's sequence-number view.
async fn apply_expunge(server: &ImapServer, session: &mut ISession, tag: &str) -> Vec<IResponse> {
    let (Some(user), Some(folder)) = (session.user().cloned(), selected_folder(session)) else {
        return vec![IResponse::tagged(tag, Status::No, "no mailbox selected")];
    };
    let removed = purge_deleted(server, &user, folder).await;
    session.expunge_complete(tag, &removed)
}

/// Performs a `MOVE`: moves each named message into the destination folder
/// (a new UID there, removed from the source — [`crate::store::Maildir`]'s
/// own `MOVE` semantics), then reports the source-side removals the same way
/// `EXPUNGE` does.
async fn apply_move(server: &ImapServer, session: &mut ISession, plan: &MovePlan) -> Vec<IResponse> {
    let (Some(user), Some(folder)) = (session.user().cloned(), selected_folder(session)) else {
        return vec![IResponse::tagged(&plan.tag, Status::No, "no mailbox selected")];
    };
    let Some(dest) = folder_from_name(&plan.destination) else {
        return vec![IResponse::tagged(&plan.tag, Status::No, "no such destination mailbox")];
    };
    if dest == folder {
        return vec![IResponse::tagged(&plan.tag, Status::No, "source and destination are the same")];
    }
    let mut moved = Vec::new();
    for target in &plan.messages {
        if server.store.move_message(&user, folder, Uid(target.uid), dest).await.is_ok() {
            moved.push(target.uid);
        }
    }
    session.move_complete(&plan.tag, &moved)
}

/// Performs a `COPY`: writes a duplicate of each named message into the
/// destination folder, leaving the source untouched — so, unlike `MOVE`, the
/// session's own view of the selected mailbox never changes.
async fn apply_copy(server: &ImapServer, session: &ISession, plan: &CopyPlan) -> Vec<IResponse> {
    let (Some(user), Some(folder)) = (session.user().cloned(), selected_folder(session)) else {
        return vec![IResponse::tagged(&plan.tag, Status::No, "no mailbox selected")];
    };
    let Some(dest) = folder_from_name(&plan.destination) else {
        return vec![IResponse::tagged(&plan.tag, Status::No, "no such destination mailbox")];
    };
    for target in &plan.messages {
        if let Ok(msg) = server.store.fetch(&user, folder, Uid(target.uid)).await {
            let _ = server.store.save(&user, dest, &msg).await;
        }
    }
    vec![IResponse::tagged(&plan.tag, Status::Ok, "COPY completed")]
}

/// Performs the purge half of `CLOSE`: same removal `EXPUNGE` performs, but
/// the caller reports no untagged responses for it (RFC 3501 §6.4.2) — the
/// session has already deselected the mailbox by the time this runs.
async fn apply_close(server: &ImapServer, session: &ISession, tag: &str, mailbox: &str) -> Vec<IResponse> {
    let (Some(user), Some(folder)) = (session.user().cloned(), folder_from_name(mailbox)) else {
        return vec![IResponse::tagged(tag, Status::Ok, "CLOSE completed")];
    };
    purge_deleted(server, &user, folder).await;
    vec![IResponse::tagged(tag, Status::Ok, "CLOSE completed")]
}

/// Purges every `\Deleted` message from one folder and returns the UIDs
/// actually removed, in ascending order — the store operation `EXPUNGE` and
/// `CLOSE` share, differing only in what they report about it afterward.
async fn purge_deleted(server: &ImapServer, user: &Address, folder: Folder) -> Vec<u32> {
    let Ok(uids) = server.store.list(user, folder).await else { return Vec::new() };
    let mut removed = Vec::new();
    for uid in uids {
        let deleted = server.store.flags(user, folder, uid).await.map(|f| f.deleted).unwrap_or(false);
        if deleted && server.store.purge(user, folder, uid).await.is_ok() {
            removed.push(uid.0);
        }
    }
    removed
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
    async fn a_blank_first_line_and_an_id_do_not_derail_the_conversation() {
        // The exact opening Apple Mail's sync connections use: a bare CRLF,
        // then ID, then authentication. The blank line must be swallowed
        // (not answered with BAD, which makes Mail hang up) and ID answered OK.
        let root = temp_root("apple-opening");
        let server = server_with(&root);
        let out = run_conversation(
            &server,
            "\r\nx1 ID (\"name\" \"Mac OS X Mail\")\r\nx2 LOGIN dave@example.com hunter2\r\nx3 LOGOUT\r\n",
        )
        .await;
        assert!(!out.contains("BAD"), "{out}");
        assert!(out.contains("* ID NIL"), "{out}");
        assert!(out.contains("x2 OK"), "{out}");
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
    async fn login_sent_as_literals_authenticates_end_to_end() {
        // The exact shape of Apple Mail's account-setup probe: username and
        // password as synchronising literals. Before literals were supported
        // this died with "BAD LOGIN requires a username" — surfacing in Mail
        // as "Unable to verify account name or password" — with the password
        // never even checked.
        let root = temp_root("literal-login");
        let server = server_with(&root);

        let script = "\
a1 LOGIN {16}\r\n\
dave@example.com {7}\r\n\
hunter2\r\n\
b LOGOUT\r\n";
        let out = run_conversation(&server, script).await;

        assert!(out.contains("+ "), "each {{n}} literal must be invited:\n{out}");
        assert!(out.contains("a1 OK"), "literal LOGIN must authenticate:\n{out}");
        assert!(!out.contains("BAD"), "{out}");
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
    async fn expunge_actually_removes_deleted_messages_from_disk() {
        // Regression: EXPUNGE used to be an honest no-op, so a client that
        // flagged \Deleted and expunged saw the message reappear on the next
        // SELECT — it was never removed.
        let root = temp_root("expunge");
        let server = server_with(&root);
        let dave = addr("dave@example.com");
        server.store.deliver(&dave, &Message::parse(b"Subject: gone\r\n\r\nbye".to_vec()).unwrap()).await.unwrap();
        server.store.deliver(&dave, &Message::parse(b"Subject: stays\r\n\r\nhi".to_vec()).unwrap()).await.unwrap();

        let script = "\
a LOGIN dave@example.com hunter2\r\n\
b SELECT INBOX\r\n\
c STORE 1 +FLAGS (\\Deleted)\r\n\
d EXPUNGE\r\n\
e LOGOUT\r\n";
        let out = run_conversation(&server, script).await;

        assert!(out.contains("* 1 EXPUNGE"), "{out}");
        assert!(out.contains("d OK EXPUNGE completed"), "{out}");

        let remaining = server.store.list(&dave, Folder::Inbox).await.unwrap();
        assert_eq!(remaining, vec![Uid(2)], "only the non-deleted message must survive");
    }

    #[tokio::test]
    async fn move_relocates_a_message_between_folders() {
        // Regression: MOVE (and COPY) were not implemented at all, so Mail's
        // drag-to-folder either errored outright or silently did nothing.
        let root = temp_root("move");
        let server = server_with(&root);
        let dave = addr("dave@example.com");
        server.store.deliver(&dave, &Message::parse(b"Subject: move me\r\n\r\nbody".to_vec()).unwrap()).await.unwrap();

        let script = "\
a LOGIN dave@example.com hunter2\r\n\
b SELECT INBOX\r\n\
c MOVE 1 Trash\r\n\
d LOGOUT\r\n";
        let out = run_conversation(&server, script).await;

        assert!(out.contains("* 1 EXPUNGE"), "{out}");
        assert!(out.contains("c OK MOVE completed"), "{out}");

        assert!(server.store.list(&dave, Folder::Inbox).await.unwrap().is_empty(), "gone from the source");
        let in_trash = server.store.list(&dave, Folder::Trash).await.unwrap();
        assert_eq!(in_trash.len(), 1, "landed in the destination");
        let moved = server.store.fetch(&dave, Folder::Trash, in_trash[0]).await.unwrap();
        assert_eq!(moved.body(), b"body");
    }

    #[tokio::test]
    async fn copy_duplicates_into_the_destination_and_leaves_the_source_alone() {
        let root = temp_root("copy");
        let server = server_with(&root);
        let dave = addr("dave@example.com");
        server.store.deliver(&dave, &Message::parse(b"Subject: dupe me\r\n\r\nbody".to_vec()).unwrap()).await.unwrap();

        let script = "\
a LOGIN dave@example.com hunter2\r\n\
b SELECT INBOX\r\n\
c COPY 1 Sent\r\n\
d LOGOUT\r\n";
        let out = run_conversation(&server, script).await;

        assert!(out.contains("c OK COPY completed"), "{out}");
        assert!(!out.contains("EXPUNGE"), "COPY must not touch the source mailbox's view:\n{out}");

        assert_eq!(server.store.list(&dave, Folder::Inbox).await.unwrap(), vec![Uid(1)], "source untouched");
        let in_sent = server.store.list(&dave, Folder::Sent).await.unwrap();
        assert_eq!(in_sent.len(), 1, "a duplicate landed in Sent");
    }

    #[tokio::test]
    async fn close_silently_purges_deleted_messages_with_no_untagged_expunge() {
        let root = temp_root("close-purge");
        let server = server_with(&root);
        let dave = addr("dave@example.com");
        server.store.deliver(&dave, &Message::parse(b"Subject: gone\r\n\r\nbye".to_vec()).unwrap()).await.unwrap();

        let script = "\
a LOGIN dave@example.com hunter2\r\n\
b SELECT INBOX\r\n\
c STORE 1 +FLAGS (\\Deleted)\r\n\
d CLOSE\r\n\
e LOGOUT\r\n";
        let out = run_conversation(&server, script).await;

        assert!(out.contains("d OK CLOSE completed"), "{out}");
        assert!(!out.contains("EXPUNGE"), "CLOSE reports no untagged EXPUNGE per RFC 3501:\n{out}");

        assert!(server.store.list(&dave, Folder::Inbox).await.unwrap().is_empty(), "purged on disk, not just flagged");
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
