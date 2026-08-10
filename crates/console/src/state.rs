//! What the console knows, shared between the frame loop and the poller.
//!
//! One lock over one struct. The interface reads it while drawing a frame and
//! the poller writes it after each round trip, and both are brief enough that
//! finer-grained locking would buy contention rather than remove it.
//!
//! Nothing here is derived from anything else. There is no cached count of
//! running services, no "is anything unhealthy" flag — those are computed from
//! [`Snapshot::services`] while drawing. A cached summary is a second copy of
//! the truth, and the first thing it does is disagree with the first copy.

use crate::nas::{Column, Listing, Share};
use crate::registry::{Person, Trail};
use crate::remote::{Agent, Node, Settings};
use selfhost_config::ServiceSpec;
use selfhost_firewall::FirewallState;
use selfhost_supervisor::state::ServiceStatus;
use std::collections::VecDeque;
use std::path::PathBuf;

/// How many log lines the console keeps for the service being watched.
///
/// The daemon's own ring is the authority; this is what fits on a screen and
/// then some. Older lines are dropped from the front, so a service that talks
/// constantly cannot grow the console's memory without bound.
pub const MAX_LOG_LINES: usize = 4_000;

/// Whether the daemon is answering.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Link {
    /// Nothing has been heard from it yet.
    ///
    /// The default, because that is what is true before the first poll returns —
    /// claiming either of the others would be a guess.
    #[default]
    Connecting,
    /// It answered the last request.
    Connected,
    /// It stopped answering, and this is what went wrong.
    Lost(String),
}

/// Where the SSH tunnel is, when the console is managing one.
///
/// Held apart from [`Link`] because they fail differently and are fixed
/// differently. "No daemon" over a working tunnel means the daemon is not
/// running; the same symptom with the tunnel down means the key was refused, or
/// the server is unreachable, and no amount of restarting the daemon would help.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tunnel {
    /// `ssh` has been started and the forwarded port is not accepting yet.
    Opening,
    /// The forwarded port accepts connections.
    Open,
    /// It is down, and being retried.
    Broken {
        /// What `ssh` said.
        reason: String,
        /// The one thing the operator can do about it, when it is known.
        advice: Option<String>,
    },
}

/// How prominent a notice is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeKind {
    /// Something worked.
    Done,
    /// Something did not.
    Problem,
}

/// A short message about the last thing that was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// What to say.
    pub text: String,
    /// How to say it.
    pub kind: NoticeKind,
}

/// One captured line of a service's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// Its position in the service's output.
    pub seq: u64,
    /// Whether the service wrote it to standard error.
    pub is_error: bool,
    /// The text.
    pub text: String,
}

/// The output collected for the service currently being watched.
#[derive(Debug, Clone, Default)]
pub struct Logs {
    /// Which service this output belongs to.
    ///
    /// Held so that a reply that arrives after the selection changed can be
    /// discarded rather than shown under the wrong name.
    pub service: String,
    /// The lines, oldest first.
    pub lines: VecDeque<LogLine>,
    /// The sequence number to ask for next.
    pub next_seq: u64,
    /// How many lines the daemon dropped before we asked for them.
    pub missed: u64,
    /// Whether the daemon has answered for this service at all.
    ///
    /// What tells "still fetching" from "printed nothing": a reply with no
    /// lines and no reply yet both leave [`Logs::lines`] empty, and the pane
    /// must not claim the first while the truth is the second.
    pub answered: bool,
}

impl Logs {
    /// Starts over for a different service.
    pub fn follow(&mut self, service: &str) {
        self.service = service.to_owned();
        self.lines.clear();
        self.next_seq = 0;
        self.missed = 0;
        self.answered = false;
    }

    /// Appends newly fetched lines, dropping the oldest to stay within bounds.
    pub fn append(&mut self, lines: impl IntoIterator<Item = LogLine>, next_seq: u64, missed: u64) {
        self.answered = true;
        self.lines.extend(lines);
        while self.lines.len() > MAX_LOG_LINES {
            self.lines.pop_front();
        }
        self.next_seq = next_seq;
        self.missed += missed;
    }
}

/// One file operation the operator asked for on a share.
///
/// Held apart from [`Command`]'s service actions because they answer a different
/// question — [`Command::service`] names the service a lifecycle action is
/// about, and none of these is about a service at all. Folding them into the
/// same variants would make that accessor lie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileAction {
    /// Make one directory, never a tree.
    ///
    /// One and not a tree because the daemon's `mkdir` is one, and because
    /// WebDAV's `MKCOL` must answer `409` for a missing parent — the two
    /// protocols must not disagree about what the same button does.
    Mkdir {
        /// Where it goes, as a plain share-relative path.
        path: String,
    },
    /// Move or rename one name to another, inside the same share.
    Rename {
        /// The name as it is.
        from: String,
        /// The name it becomes.
        to: String,
    },
    /// Remove one name, depth-infinity for a directory.
    Delete {
        /// What to remove.
        path: String,
    },
    /// Copy one file out of the share onto this machine.
    Download {
        /// What to fetch.
        path: String,
        /// Where to write it.
        to: PathBuf,
    },
    /// Copy one file from this machine into the share.
    Upload {
        /// What to read.
        from: PathBuf,
        /// Where it lands, as a plain share-relative path.
        path: String,
    },
}

impl FileAction {
    /// The path inside the share this acts on, for the message that reports it.
    fn subject(&self) -> &str {
        match self {
            Self::Mkdir { path } | Self::Delete { path } | Self::Download { path, .. } => path,
            Self::Rename { from, .. } => from,
            Self::Upload { path, .. } => path,
        }
    }
}

/// Something the operator asked for that the poller has to carry out.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    /// Start a service.
    Start(String),
    /// Stop a service.
    Stop(String),
    /// Stop and start a service.
    Restart(String),
    /// Remove a service from the catalogue.
    Uninstall(String),
    /// Install or replace a service.
    Install(Box<ServiceSpec>),
    /// Act on one name inside one share.
    Files {
        /// Which share.
        share: String,
        /// What to do in it.
        action: FileAction,
    },
    /// Take away one person's credential.
    ///
    /// The one thing the PEOPLE plate can change. Registering is a browser
    /// ceremony this program cannot perform; revoking is not, and an owner who
    /// has lost a device needs the shortest path to it.
    RevokePasskey {
        /// The credential's id.
        id: String,
        /// Whose it is, so the notice can say a name rather than a base64 blob.
        user: String,
    },
}

impl Command {
    /// The service this command is about, or the empty name for one that is
    /// about no service.
    ///
    /// The empty string rather than an `Option` because every caller of this is
    /// asking "is the rail's row for `name` waiting on something", and the empty
    /// name matches no service — so a file action or a revocation is invisible
    /// to the rail without every call site growing a `match`.
    pub fn service(&self) -> &str {
        match self {
            Self::Start(name) | Self::Stop(name) | Self::Restart(name) | Self::Uninstall(name) => {
                name
            }
            Self::Install(spec) => &spec.name,
            Self::Files { .. } | Self::RevokePasskey { .. } => "",
        }
    }

    /// What to say while it is queued and the poller has not run it yet.
    ///
    /// Present tense, trailed off: the press has been received and nothing has
    /// been confirmed, which is exactly what the words claim and no more.
    pub fn requested_message(&self) -> &'static str {
        match self {
            Self::Start(_) => "start requested…",
            Self::Stop(_) => "stop requested…",
            Self::Restart(_) => "restart requested…",
            Self::Uninstall(_) => "uninstall requested…",
            Self::Install(_) => "install requested…",
            Self::Files { action: FileAction::Mkdir { .. }, .. } => "creating the folder…",
            Self::Files { action: FileAction::Rename { .. }, .. } => "renaming…",
            Self::Files { action: FileAction::Delete { .. }, .. } => "deleting…",
            Self::Files { action: FileAction::Download { .. }, .. } => "downloading…",
            Self::Files { action: FileAction::Upload { .. }, .. } => "uploading…",
            Self::RevokePasskey { .. } => "revoking…",
        }
    }

    /// What to say once it has been accepted.
    pub fn done_message(&self) -> String {
        let name = self.service();
        match self {
            Self::Start(_) => format!("Starting {name}"),
            Self::Stop(_) => format!("Stopping {name}"),
            Self::Restart(_) => format!("Restarting {name}"),
            Self::Uninstall(_) => format!("Uninstalled {name}"),
            Self::Install(_) => format!("Installed {name}"),
            Self::Files { share, action } => {
                let subject = action.subject();
                // The share is named as well as the path, because the plate can
                // be showing a different share by the time the notice lands.
                match action {
                    FileAction::Mkdir { .. } => format!("Created {share}/{subject}"),
                    FileAction::Rename { to, .. } => format!("Renamed {subject} to {to}"),
                    FileAction::Delete { .. } => format!("Deleted {share}/{subject}"),
                    FileAction::Download { to, .. } => format!("Saved to {}", to.display()),
                    FileAction::Upload { .. } => format!("Uploaded {share}/{subject}"),
                }
            }
            Self::RevokePasskey { user, .. } => format!("Revoked a passkey held by {user}"),
        }
    }
}

/// Which of the console's four screens is open.
///
/// # Why the poller reads this
///
/// It looks like interface state, and it is — but it is also the one fact that
/// decides *what the daemon is asked for*. A console that fetched the audit
/// tail, every share's usage and every node's agent report on every poll would
/// be doing four times the work to draw one screen, and three quarters of it
/// for a plate nobody has open. This is the same argument the exposure map
/// makes about costing the log nothing: a panel that is not being read should
/// not be paid for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    /// The rail of services and one service in detail.
    #[default]
    Services,
    /// The shares, one directory at a time.
    Files,
    /// The peer picker, the session, and the viewport.
    Desktop,
    /// The identity registry and the audit tail.
    People,
}

impl Screen {
    /// The screens, in the order the tabs draw them.
    pub const ALL: [Screen; 4] = [Self::Services, Self::Files, Self::Desktop, Self::People];

    /// The word on the tab.
    pub fn label(self) -> &'static str {
        match self {
            Self::Services => "SERVICES",
            Self::Files => "FILES",
            Self::Desktop => "DESKTOP",
            Self::People => "PEOPLE",
        }
    }
}

/// Where the FILES plate is looking, and what it found.
///
/// Held in the snapshot rather than beside the form on the console, because the
/// poller is what fetches a listing and it has to know which directory of which
/// share is being read. The alternative — the interface asking for a listing
/// through the command queue — would make browsing a *command*, and a browse
/// that failed would then be indistinguishable from a delete that failed.
#[derive(Debug)]
pub struct Files {
    /// Every share this caller may open, or `None` until first fetched.
    ///
    /// `None` means "not answered yet" and `Some(vec![])` means "none of them
    /// are yours", which are different sentences — see
    /// [`crate::nas::shares_note`].
    pub shares: Option<Vec<Share>>,
    /// Which share is open, if any.
    pub share: Option<String>,
    /// The directory inside it, as a plain path; the root is empty.
    pub path: String,
    /// What that directory holds, once it has been read.
    pub listing: Option<Listing>,
    /// Why the last listing failed, in the daemon's own words.
    ///
    /// Kept beside the listing rather than replacing it: a refused refresh
    /// leaves the last good directory on screen with the reason above it, which
    /// is more use than a blank pane.
    pub trouble: Option<String>,
    /// Which column the rows are ordered by.
    pub column: Column,
    /// Whether that order runs up or down.
    pub ascending: bool,
    /// Which row is chosen, by name.
    ///
    /// By name and not by index, for the reason [`Snapshot::selected_service`]
    /// resolves a service by name: a directory can change between two frames and
    /// an index would then point at a different file entirely.
    pub selected: Option<String>,
}

impl Default for Files {
    /// A plate that has read nothing, ordered by name, smallest first.
    ///
    /// Written out rather than derived because exactly one field's derived
    /// default is wrong: `ascending` would be `false`, and a file browser that
    /// opened on Z-to-A is a file browser that looks broken. The rest are the
    /// honest empties.
    fn default() -> Self {
        Self {
            shares: None,
            share: None,
            path: String::new(),
            listing: None,
            trouble: None,
            column: Column::Name,
            ascending: true,
            selected: None,
        }
    }
}

impl Files {
    /// The share currently open, if it is still one this caller may see.
    pub fn share(&self) -> Option<&Share> {
        let id = self.share.as_deref()?;
        self.shares.as_ref()?.iter().find(|share| share.id == id)
    }

    /// The listing to draw, which is `None` while one for a different place is
    /// still the last thing that arrived.
    ///
    /// The guard that stops a reply that lost a race being drawn under the wrong
    /// heading — the same argument [`crate::poller`] makes about a log fetch.
    pub fn listing(&self) -> Option<&Listing> {
        let listing = self.listing.as_ref()?;
        (Some(listing.share.as_str()) == self.share.as_deref() && listing.path == self.path)
            .then_some(listing)
    }

    /// Opens a share at its root.
    pub fn open(&mut self, share: &str) {
        self.share = Some(share.to_owned());
        self.go(String::new());
    }

    /// Walks to a directory inside the open share.
    pub fn go(&mut self, path: String) {
        self.path = path;
        self.selected = None;
        self.trouble = None;
    }
}

/// What the DESKTOP plate knows about the deployment and the fleet.
///
/// The *stream* is not here. Pixels arrive on their own thread at up to thirty
/// frames a second, and putting them behind the lock the whole interface reads
/// through would make every other plate wait on a screen — see
/// [`crate::channel`], which owns the picture and publishes it separately.
#[derive(Debug, Default)]
pub struct Desk {
    /// The operator's switches, or `None` when this deployment serves no
    /// desktop — which is the ordinary case and is drawn as a sentence.
    pub settings: Option<Settings>,
    /// The machines this caller may watch, or `None` until first fetched.
    pub nodes: Option<Vec<Node>>,
    /// Which machine the plate is pointed at.
    pub peer: Option<String>,
    /// What the capture agent on that machine is doing.
    pub agent: Option<Agent>,
}

impl Desk {
    /// The machine the plate is pointed at, if it is still one that is offered.
    pub fn peer(&self) -> Option<&Node> {
        let name = self.peer.as_deref()?;
        self.nodes.as_ref()?.iter().find(|node| node.node == name)
    }
}

/// Who holds authority on this box, and what it has been used for.
#[derive(Debug, Default)]
pub struct People {
    /// Everyone who holds a credential, or `None` until first fetched.
    pub holders: Option<Vec<Person>>,
    /// Why the registry could not be read — on a deployment where this
    /// console's credential is not the owner, both halves answer `401`.
    pub trouble: Option<String>,
    /// The tail of the control-action record.
    pub trail: Option<Trail>,
    /// Whether the pointer's own records are hidden.
    ///
    /// Defaults to hidden: a desktop session writes one record per authorised
    /// pointer move, and a trail that opens on ten thousand of them is a trail
    /// in which the one keystroke that matters cannot be found.
    pub hide_pointer_noise: bool,
}

/// Everything both threads can see.
#[derive(Debug, Default)]
pub struct Snapshot {
    /// Whether the daemon is answering.
    pub link: Link,
    /// Where the SSH tunnel is, or `None` when the console is not managing one.
    pub tunnel: Option<Tunnel>,
    /// Every service the daemon knows about, as of the last poll.
    pub services: Vec<ServiceStatus>,
    /// Which service the detail pane is showing.
    pub selected: Option<String>,
    /// The full definition of the selected service, once it has been fetched.
    ///
    /// Fetched separately from the list, which carries only live state. Held as
    /// an option rather than merged into [`Snapshot::services`] so that the pane
    /// can tell "not fetched yet" from "has no arguments", and can refuse to
    /// show one service's definition beside another's name.
    pub spec: Option<Box<ServiceSpec>>,
    /// The selected service's output.
    pub logs: Logs,
    /// The result of the last command.
    pub notice: Option<Notice>,
    /// The host firewall's exposure, or `None` until first fetched.
    ///
    /// Held as an option, defaulting to `None`, so the exposure map can tell "not
    /// polled yet" from "the daemon reports no managed firewall" and draw neither
    /// as the other.
    pub firewall: Option<FirewallState>,
    /// Which screen is open, and so what the poller fetches.
    pub screen: Screen,
    /// Where the FILES plate is looking, and what it found.
    pub files: Files,
    /// What the DESKTOP plate knows about the deployment and the fleet.
    pub desk: Desk,
    /// Who holds authority here, and what it has been used for.
    pub people: People,
    /// Commands the interface has asked for and the poller has not run yet.
    pub commands: VecDeque<Command>,
}

impl Snapshot {
    /// The service the detail pane should show, if it still exists.
    ///
    /// Looked up by name rather than held as a reference or an index: a service
    /// can be uninstalled, or the list reordered, between one frame and the
    /// next, and an index would then point at a different service entirely.
    pub fn selected_service(&self) -> Option<&ServiceStatus> {
        let name = self.selected.as_deref()?;
        self.services.iter().find(|service| service.name == name)
    }

    /// Moves the selection `step` rows through the rail, held at its ends.
    ///
    /// The keyboard's half of choosing: a click names a row, an arrow names a
    /// neighbour, and both end at the same field, so the rail cannot come to
    /// disagree with itself about what is chosen. With nothing selected yet the
    /// first press lands on the end it set off from — Down chooses the first
    /// service, Up the last — because an arrow into an unchosen list is a
    /// reader stepping in from that edge.
    pub fn select_step(&mut self, step: isize) {
        if self.services.is_empty() {
            return;
        }
        let last = self.services.len() - 1;
        let current = self
            .selected
            .as_deref()
            .and_then(|name| self.services.iter().position(|service| service.name == name));
        let next = match current {
            Some(index) => index.saturating_add_signed(step).min(last),
            None if step > 0 => 0,
            None => last,
        };
        self.selected = Some(self.services[next].name.clone());
    }

    /// Asks for a command to be carried out.
    pub fn enqueue(&mut self, command: Command) {
        self.commands.push_back(command);
    }

    /// The queued command naming `service`, while the poller has not run it.
    ///
    /// The queue is the console's own record of what it has asked for, so this
    /// is what lets the interface acknowledge a press before the daemon
    /// answers — and refuse to queue the same press twice.
    pub fn requested(&self, service: &str) -> Option<&Command> {
        self.commands.iter().find(|command| command.service() == service)
    }

    /// Reports something that worked.
    pub fn report_done(&mut self, text: impl Into<String>) {
        self.notice = Some(Notice { text: text.into(), kind: NoticeKind::Done });
    }

    /// Reports something that did not.
    pub fn report_problem(&mut self, text: impl Into<String>) {
        self.notice = Some(Notice { text: text.into(), kind: NoticeKind::Problem });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_supervisor::state::ServiceState;

    fn service(name: &str) -> ServiceStatus {
        ServiceStatus {
            name: name.into(),
            display_name: name.into(),
            description: String::new(),
            state: ServiceState::Stopped,
            start_mode: selfhost_config::StartMode::Manual,
            total_restarts: 0,
            log_seq: 0,
        }
    }

    fn line(seq: u64) -> LogLine {
        LogLine { seq, is_error: false, text: format!("line {seq}") }
    }

    #[test]
    fn a_new_console_has_not_reached_the_daemon_yet() {
        assert_eq!(Snapshot::default().link, Link::Connecting);
    }

    #[test]
    fn the_selection_is_resolved_by_name_so_a_reordered_list_cannot_mislead() {
        let mut snapshot = Snapshot { services: vec![service("a"), service("b")], ..Default::default() };
        snapshot.selected = Some("b".into());
        assert_eq!(snapshot.selected_service().map(|s| s.name.as_str()), Some("b"));

        snapshot.services.reverse();
        assert_eq!(snapshot.selected_service().map(|s| s.name.as_str()), Some("b"));
    }

    #[test]
    fn a_selection_that_no_longer_exists_simply_resolves_to_nothing() {
        let mut snapshot = Snapshot { services: vec![service("a")], ..Default::default() };
        snapshot.selected = Some("gone".into());
        assert!(snapshot.selected_service().is_none());
    }

    #[test]
    fn an_arrow_moves_the_selection_one_row_and_the_ends_hold() {
        let mut snapshot = Snapshot {
            services: vec![service("a"), service("b"), service("c")],
            ..Default::default()
        };
        snapshot.selected = Some("b".into());

        snapshot.select_step(1);
        assert_eq!(snapshot.selected.as_deref(), Some("c"));
        snapshot.select_step(1);
        assert_eq!(snapshot.selected.as_deref(), Some("c"), "the last row holds");

        snapshot.select_step(-1);
        snapshot.select_step(-1);
        snapshot.select_step(-1);
        assert_eq!(snapshot.selected.as_deref(), Some("a"), "and so does the first");
    }

    #[test]
    fn an_arrow_into_an_unchosen_rail_steps_in_from_the_edge_it_left() {
        let mut snapshot =
            Snapshot { services: vec![service("a"), service("b")], ..Default::default() };
        snapshot.select_step(1);
        assert_eq!(snapshot.selected.as_deref(), Some("a"), "Down chooses the first");

        snapshot.selected = None;
        snapshot.select_step(-1);
        assert_eq!(snapshot.selected.as_deref(), Some("b"), "Up chooses the last");

        let mut empty = Snapshot::default();
        empty.select_step(1);
        assert_eq!(empty.selected, None, "an empty rail has nothing to choose");
    }

    #[test]
    fn following_a_different_service_discards_the_previous_output() {
        let mut logs = Logs::default();
        logs.follow("one");
        logs.append([line(0), line(1)], 2, 0);
        assert_eq!(logs.lines.len(), 2);

        logs.follow("two");
        assert!(logs.lines.is_empty());
        assert_eq!(logs.next_seq, 0);
        assert_eq!(logs.service, "two");
    }

    #[test]
    fn output_is_bounded_by_dropping_the_oldest_lines() {
        let mut logs = Logs::default();
        logs.append((0..MAX_LOG_LINES as u64 + 50).map(line), 0, 0);
        assert_eq!(logs.lines.len(), MAX_LOG_LINES);
        assert_eq!(logs.lines.front().map(|l| l.seq), Some(50), "the oldest should go first");
    }

    #[test]
    fn dropped_lines_accumulate_rather_than_being_replaced() {
        let mut logs = Logs::default();
        logs.append([], 5, 3);
        logs.append([], 9, 4);
        assert_eq!(logs.missed, 7, "a second gap must not erase the first");
    }

    #[test]
    fn no_reply_and_an_empty_reply_are_two_different_facts() {
        // Both leave the lines empty; only one of them has learned anything.
        let mut logs = Logs::default();
        logs.follow("one");
        assert!(!logs.answered, "nothing has come back yet");

        logs.append([], 0, 0);
        assert!(logs.answered, "an empty reply is still a reply");

        logs.follow("two");
        assert!(!logs.answered, "a new service starts unlearned again");
    }

    #[test]
    fn a_queued_command_is_found_under_the_service_it_names() {
        let mut snapshot = Snapshot::default();
        snapshot.enqueue(Command::Stop("mongod".into()));
        assert_eq!(snapshot.requested("mongod"), Some(&Command::Stop("mongod".into())));
        assert_eq!(snapshot.requested("other"), None);
        assert_eq!(Command::Stop("mongod".into()).requested_message(), "stop requested…");
    }

    #[test]
    fn every_command_names_the_service_it_is_about() {
        assert_eq!(Command::Start("mongod".into()).service(), "mongod");
        let spec = ServiceSpec::new("api", "/usr/bin/api");
        assert_eq!(Command::Install(Box::new(spec)).service(), "api");
    }

    #[test]
    fn commands_are_carried_out_in_the_order_they_were_asked_for() {
        let mut snapshot = Snapshot::default();
        snapshot.enqueue(Command::Stop("a".into()));
        snapshot.enqueue(Command::Start("a".into()));
        assert_eq!(snapshot.commands.pop_front(), Some(Command::Stop("a".into())));
        assert_eq!(snapshot.commands.pop_front(), Some(Command::Start("a".into())));
    }

    #[test]
    fn a_notice_replaces_the_one_before_it() {
        let mut snapshot = Snapshot::default();
        snapshot.report_done("started");
        snapshot.report_problem("no such file");
        let notice = snapshot.notice.expect("a notice");
        assert_eq!(notice.kind, NoticeKind::Problem);
        assert_eq!(notice.text, "no such file");
    }
}
