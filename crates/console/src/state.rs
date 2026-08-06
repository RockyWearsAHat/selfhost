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

use selfhost_config::ServiceSpec;
use selfhost_supervisor::state::ServiceStatus;
use std::collections::VecDeque;

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
}

impl Logs {
    /// Starts over for a different service.
    pub fn follow(&mut self, service: &str) {
        self.service = service.to_owned();
        self.lines.clear();
        self.next_seq = 0;
        self.missed = 0;
    }

    /// Appends newly fetched lines, dropping the oldest to stay within bounds.
    pub fn append(&mut self, lines: impl IntoIterator<Item = LogLine>, next_seq: u64, missed: u64) {
        self.lines.extend(lines);
        while self.lines.len() > MAX_LOG_LINES {
            self.lines.pop_front();
        }
        self.next_seq = next_seq;
        self.missed += missed;
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
}

impl Command {
    /// The service this command is about.
    pub fn service(&self) -> &str {
        match self {
            Self::Start(name) | Self::Stop(name) | Self::Restart(name) | Self::Uninstall(name) => {
                name
            }
            Self::Install(spec) => &spec.name,
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
        }
    }
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
