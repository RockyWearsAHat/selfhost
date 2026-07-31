//! The console's interface: what is on screen, and where.
//!
//! # Shape
//!
//! A list of services on the left and one service in detail on the right. That
//! shape is chosen because of what the operator is usually doing: watching one
//! service's output while keeping an eye on whether anything else has gone
//! wrong. Tabs would hide the second half of that, and a single scrolling page
//! would make the output a thin strip at the bottom.
//!
//! Above both, two full-width strips that are about the machine rather than
//! about any one service: a masthead naming what this is and whether it is
//! connected, and a readout bank carrying the machine's own account of itself
//! beside the counts behind it. They are strips and not cards because they are
//! read in a glance and never dwelt on — the vertical space a card spends on
//! its own edges is space the log below it does not get.
//!
//! # What holds it together
//!
//! Rules, not boxes. Each block is introduced by a small-capital label with a
//! hairline running from it to the far edge, which states where the block ends
//! without drawing an outline around it. Nesting outlines is what made an
//! earlier revision read as a diagram of an interface rather than as one: four
//! rounded cards inside a rounded panel inside a window is three frames around
//! every fact. There are three framed surfaces on screen — the readout bank, the
//! rail and the detail pane — and everything inside them is separated by ruling.
//!
//! What each mark is *made* of, and why the console's own marks are chamfered
//! while everything the operator presses keeps the desktop's shape, is
//! [`style`]. Nothing here picks a colour or a corner for itself.
//!
//! # Every frame is described from the snapshot
//!
//! [`view`] is a function of [`Console`], and [`Console`] holds nothing but a
//! handle on the shared [`Snapshot`] and the state of the form. Nothing here
//! caches what the daemon said, so a service that has just died cannot still be
//! drawn as running by a widget that was not told.

mod detail;
mod install;
mod style;

use crate::state::{Command, Link, NoticeKind, Snapshot, Tunnel};
use install::InstallForm;
use rui::style::Justify;
use rui::{
    Align, App, El, Radius, Role, Status, Tone, button, caption, col, figure, heading, micro,
    paragraph, row, section, spacer, text, title,
};
use selfhost_supervisor::state::{ServiceState, ServiceStatus};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// What share of the window's width the rail of services takes.
///
/// A share rather than a width, held between [`RAIL_MIN`] and [`RAIL_MAX`]. A
/// fixed width is the defect this replaces: 292 units is a quarter of a large
/// window and over half of the smallest one the backend allows, so the pane
/// holding the log — the thing the operator is actually reading — was squeezed
/// to nothing exactly when there was least room to spare.
const RAIL_SHARE: f32 = 0.28;

/// The narrowest the rail may be drawn: a service name and its state.
const RAIL_MIN: f32 = 190.0;

/// The widest, past which it is only stretching a list of short names.
const RAIL_MAX: f32 = 300.0;

/// How tall one row of that list is.
const ROW_HEIGHT: f32 = 42.0;

/// How tall the masthead is: the mark, the name, and what it is connected to.
const MASTHEAD: f32 = 28.0;

/// How tall the readout bank is.
///
/// Taller than the strip it replaces. It carries the one line that reads as the
/// machine speaking — the condition — beside the counts that back it up, and a
/// sentence set at fifteen units in a cell of forty-six had nowhere to sit.
const BANK: f32 = 54.0;

/// How long the loop waits for input before drawing again anyway.
///
/// Matched to the poller's own interval: nothing new can have arrived from the
/// daemon in between, so a shorter wait would draw the same picture. It is not a
/// frame rate and it does not delay input — the wait ends the moment an event
/// arrives, and while anything is animating the loop uses its own shorter one.
const IDLE_REDRAW: Duration = Duration::from_millis(500);

/// The console.
pub struct Console {
    shared: Arc<Mutex<Snapshot>>,
    running: Arc<AtomicBool>,
    address: SocketAddr,
    /// The server the tunnel reaches, when the console is managing one.
    ///
    /// Shown beside the address so that a console pointed at loopback says which
    /// machine that loopback port actually leads to — two consoles open on two
    /// servers would otherwise both read `127.0.0.1:9191`.
    via: Option<String>,
    form: InstallForm,
}

impl Console {
    /// A console showing the daemon at `address`, reached over `via` if tunnelled.
    pub fn new(
        shared: Arc<Mutex<Snapshot>>,
        running: Arc<AtomicBool>,
        address: SocketAddr,
        via: Option<String>,
    ) -> Self {
        Self { shared, running, address, via, form: InstallForm::default() }
    }

    /// Opens the window and runs until it is closed.
    pub fn run(self, title: String) -> Result<(), rui::Error> {
        let running = Arc::clone(&self.running);
        App::new(title, self, view)
            .size(980.0, 680.0)
            .min_size(560.0, 420.0)
            .idle_timeout(IDLE_REDRAW)
            .while_running(move |_| running.load(Ordering::Relaxed))
            .run()
    }

    /// What the daemon last said.
    ///
    /// A poisoned lock is read through rather than treated as fatal: what is on
    /// screen is still the last thing the poller wrote, which is worth drawing,
    /// and a console that goes blank tells the operator less than a stale one.
    pub(crate) fn snapshot(&self) -> MutexGuard<'_, Snapshot> {
        match self.shared.lock() {
            Ok(snapshot) => snapshot,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Changes what the daemon last said — a selection, a dismissed notice, or a
    /// command queued for the poller.
    pub(crate) fn with_snapshot(&mut self, change: impl FnOnce(&mut Snapshot)) {
        change(&mut self.snapshot());
    }

    /// Asks the poller to carry a command out.
    pub(crate) fn request(&mut self, command: Command) {
        self.with_snapshot(|snapshot| snapshot.enqueue(command));
    }

    /// The form, for the panes that draw it.
    pub(crate) fn form(&self) -> &InstallForm {
        &self.form
    }

    /// The form, to be edited by whatever was just typed or pressed.
    pub(crate) fn form_mut(&mut self) -> &mut InstallForm {
        &mut self.form
    }

    /// Validates the form and asks for the install, or leaves it saying what is
    /// wrong.
    ///
    /// The handle is cloned out before the lock is taken so that holding the
    /// snapshot does not also hold a borrow of the console, which the form needs
    /// mutably.
    pub(crate) fn submit_form(&mut self) {
        let shared = Arc::clone(&self.shared);
        let mut snapshot = match shared.lock() {
            Ok(snapshot) => snapshot,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.form.submit(&mut snapshot);
    }
}

/// The whole console, as one description.
pub fn view(console: &Console) -> El<Console> {
    let snapshot = console.snapshot();

    col((
        header(console, &snapshot),
        tunnel_banner(&snapshot).map(banner),
        snapshot.notice.clone().map(notice),
        bank(&snapshot),
        row((rail(&snapshot), pane(console, &snapshot)))
            .gap(8.0)
            .grow(),
    ))
    .pad(16.0)
    .gap(8.0)
}

/// The masthead: what this is, whether it is connected, and to what.
///
/// The two ends are measured and a rule takes what is between them, so the bar
/// reads as one instrument however wide the window is. Left to a plain row, a
/// wide window put the mark at one edge and the address at the other with a
/// hand's width of nothing in the middle — which is not restraint, it is two
/// unrelated things that happen to share a strip.
///
/// The connection is a lamp and a word rather than a tag. A tag is a capsule
/// drawn around one word, and here the word is `CONNECTED` on nearly every
/// frame the console ever draws — so the capsule was chrome that lit the top of
/// the window green to say that nothing was wrong.
fn header(console: &Console, snapshot: &Snapshot) -> El<Console> {
    let (status, label, detail) =
        connection_summary(snapshot, console.address, console.via.as_deref());

    row((
        style::mark(),
        title("selfhost").align_self(Align::Center),
        style::rule(),
        style::state_mark(status, label.to_uppercase()),
        micro(detail).max_w(300.0).align_self(Align::Center),
    ))
    .gap(10.0)
    .h(MASTHEAD)
}

/// What the header says about the connection: a state, a word, and a detail.
///
/// Pure, and separate from the drawing, because it is the piece with the actual
/// judgement in it: a broken tunnel and a stopped daemon look identical from the
/// socket's point of view and have completely different fixes, so the tunnel is
/// reported ahead of the link whenever it is the thing that is wrong.
fn connection_summary(
    snapshot: &Snapshot,
    address: SocketAddr,
    via: Option<&str>,
) -> (Status, &'static str, String) {
    match &snapshot.tunnel {
        Some(Tunnel::Broken { reason, advice }) => {
            let detail = match advice {
                Some(advice) => format!("{reason} — {advice}"),
                None => reason.clone(),
            };
            (Status::Bad, "tunnel down", detail)
        }
        Some(Tunnel::Opening) if snapshot.link != Link::Connected => {
            (Status::Warn, "tunnelling", format!("opening ssh to {}", via.unwrap_or("the server")))
        }
        _ => {
            let (status, label) = match &snapshot.link {
                Link::Connecting => (Status::Warn, "connecting"),
                Link::Connected => (Status::Ok, "connected"),
                Link::Lost(_) => (Status::Bad, "no daemon"),
            };
            let detail = match (&snapshot.link, via) {
                (Link::Lost(reason), _) => reason.clone(),
                (_, Some(destination)) => format!("{address} · ssh {destination}"),
                (_, None) => address.to_string(),
            };
            (status, label, detail)
        }
    }
}

/// The bar reporting what the last command did.
///
/// A notice that cannot be dismissed either has to disappear on a timer — which
/// takes it away mid-sentence — or stay until the next command, which leaves a
/// stale success message sitting beside a failing service.
fn notice(notice: crate::state::Notice) -> El<Console> {
    let status = match notice.kind {
        NoticeKind::Done => Status::Ok,
        NoticeKind::Problem => Status::Bad,
    };
    alert(status).add((
        text(notice.text).grow(),
        // The multiplication sign, and not one of the several nicer-looking
        // crosses above U+2000. Neither face macOS ships has U+2715
        // MULTIPLICATION X, and a character no loaded face has is drawn as the
        // font's own empty box — so the one control that dismisses this bar was
        // a filled rectangle. See `rui::shell::fonts`, which asserts every mark
        // the console draws.
        style::icon_button("\u{00d7}", "Dismiss").color(Tone::ink(status)).on_click(
            |console: &mut Console| console.with_snapshot(|snapshot| snapshot.notice = None),
        ),
    ))
}

/// What to say about a broken tunnel, or `None` while it is working.
///
/// Separate from the header for a practical reason: the header is one line that
/// truncates, and the half that gets cut off is the instruction. `ssh`'s own
/// complaint says *what* happened and the advice says what to do about it, and
/// the second is the useful one — so it goes where there is room to read it.
fn tunnel_banner(snapshot: &Snapshot) -> Option<String> {
    match &snapshot.tunnel {
        Some(Tunnel::Broken { reason, advice }) => Some(match advice {
            Some(advice) => format!("The SSH tunnel is down. {reason} {advice}"),
            None => format!("The SSH tunnel is down. {reason}"),
        }),
        _ => None,
    }
}

/// The tunnel's complaint, across the width of the page.
fn banner(message: String) -> El<Console> {
    alert(Status::Bad).add(paragraph(message))
}

/// The surface a notice or a banner is written on: tinted, outlined, and flagged.
///
/// One element for both, because they are the same object — a strip that has
/// pushed its way in above the panes to say something went wrong — and drawing
/// them separately is how the two came to be a tinted box each.
///
/// The bar down the leading edge is the point. A pale tinted rectangle is easy
/// to read past, and these strips appear exactly when something must not be read
/// past; the bar is the same mark a status tag makes, in the same hue, so a
/// failure announces itself the way every other failure in the console does.
fn alert(status: Status) -> El<Console> {
    let ink = Tone::ink(status);
    row(style::flag(status))
        .min_h(30.0)
        .pad_each(6.0, 12.0, 6.0, 5.0)
        .gap(9.0)
        .fill(Tone::tint(status))
        .border(1.0, ink)
        .round(Radius::Control)
        .color(ink)
}

/// The readout bank: what the machine has to say about itself, and the counts
/// behind it.
///
/// One surface with hairlines through it, not four cards with a gap between
/// them. Four cards spend four sets of edges, four corner radii, and four
/// shadows on four small numbers, and they were taking a fifth of the window's
/// height to do it. The readings belong together — they are readings off the
/// same machine — so they are drawn as one instrument that happens to be ruled.
///
/// # The condition is a sentence, and it comes first
///
/// The leading cell is [`condition`]: one line, in words, saying what the
/// machine amounts to right now. It is the only text in the window that is
/// about the *whole* installation rather than about one service, and it is what
/// turns four numbers into a report. The numbers stay because a sentence cannot
/// say `2/4`, and the sentence stays because four numbers do not say whether
/// that is fine.
///
/// The count of services is gone from the bank: `RUNNING 2/4` already states
/// the total, and the rail's own heading states it again beside the list it
/// belongs to. A cell that repeats its neighbour's denominator is a cell spent
/// on nothing.
fn bank(snapshot: &Snapshot) -> El<Console> {
    let total = snapshot.services.len();
    let running = snapshot.services.iter().filter(|service| service.state.is_live()).count();
    let attention =
        snapshot.services.iter().filter(|service| service.state.needs_attention()).count();
    let restarts: u64 = snapshot.services.iter().map(|service| service.total_restarts).sum();

    // Exactly one of these can raise its voice, and it is the one that means
    // somebody has to do something. A ratio is not a verdict — a service the
    // operator stopped on purpose would turn RUNNING amber and leave it amber
    // for the rest of the day — and a restart is something that already
    // happened and that the supervisor already handled. A colour spent on
    // either is a colour the reader learns to look past, which is the colour
    // ATTENTION needs to still be worth something.
    let counts = [
        ("RUNNING", format!("{running}/{total}"), None),
        ("RESTARTS", restarts.to_string(), None),
        (
            "ATTENTION",
            attention.to_string(),
            (attention > 0).then_some(Status::Bad),
        ),
    ];

    let mut cells: Vec<El<Console>> = vec![condition_cell(snapshot)];
    for (label, value, alarm) in counts {
        cells.push(spacer().w(1.0).fill(Tone::Border).pad_y(6.0));
        let ink = alarm.map_or(Tone::Text, Tone::ink);
        cells.push(cell(label, figure(value).color(ink)).grow());
    }

    style::plate(row(cells).h(BANK)).pad_y(0.0).pad_x(0.0)
}

/// The leading cell: the machine's own account of itself.
///
/// It grows harder than the counts beside it, because a sentence needs room to
/// be a sentence and a count is four characters wide whatever room it is given.
/// A share and not a minimum: a minimum is added to a growing child's share
/// rather than absorbed by it, so a floor of 150 units here took the counts down
/// to 72 at the smallest window the backend allows — narrow enough that
/// `ATTENTION` was drawn as `ATTEN…`, which is a label that has stopped being
/// one.
fn condition_cell(snapshot: &Snapshot) -> El<Console> {
    cell("CONDITION", text(condition(snapshot)).text_size(15.0)).grow_by(2.2)
}

/// One reading: a small-capital label, and the value under it.
fn cell(label: &'static str, value: El<Console>) -> El<Console> {
    col((heading(label), value)).gap(3.0).justify(Justify::Center).pad_x(12.0)
}

/// What the machine amounts to, in one line.
///
/// Pure, and tested apart from the drawing, because it is the piece with the
/// judgement in it. The order is the order an operator would want to be told:
/// whether anyone is answering at all, then whether anything is broken, then
/// whether everything is up.
///
/// It names the service when exactly one wants looking at. "One service needs
/// attention" makes the operator go and find which; the rail is right there,
/// and saying the name is what saves the trip.
fn condition(snapshot: &Snapshot) -> String {
    if let Some(Tunnel::Broken { .. }) = &snapshot.tunnel {
        return "The tunnel to the server is down".into();
    }
    match &snapshot.link {
        Link::Connecting => return "Reaching the daemon".into(),
        Link::Lost(_) => return "The daemon is not answering".into(),
        Link::Connected => {}
    }

    let total = snapshot.services.len();
    if total == 0 {
        return "No services installed".into();
    }

    let mut wanting = snapshot.services.iter().filter(|service| service.state.needs_attention());
    match (wanting.next(), wanting.count()) {
        (Some(service), 0) => return format!("{} needs attention", display_name(service)),
        (Some(_), rest) => return format!("{} services need attention", rest + 1),
        (None, _) => {}
    }

    let running = snapshot.services.iter().filter(|service| service.state.is_live()).count();
    match running {
        0 => "Nothing is running".into(),
        _ if running == total => "Everything is running".into(),
        _ => format!("{running} of {total} running"),
    }
}

/// The rail of services, and the button that adds one.
///
/// The button is pinned to the bottom edge and runs the full width, rather than
/// sitting beside the heading. Two reasons, and the second is the one that
/// matters: a list rarely fills its rail, so the space under the last row was
/// the largest empty area in the window; and an action that adds to a list
/// belongs at the end of it, where the eye already is once it has read the list
/// and not found what it wanted.
fn rail(snapshot: &Snapshot) -> El<Console> {
    let rows: Vec<El<Console>> = snapshot
        .services
        .iter()
        .map(|service| {
            service_row(service, snapshot.selected.as_deref() == Some(service.name.as_str()))
        })
        .collect();

    let list: El<Console> = if rows.is_empty() {
        col(caption(match snapshot.link {
            Link::Connected => "The daemon is running no services yet.",
            _ => "Waiting for the daemon.",
        })
        .wrap()
        .center_text())
        .grow()
        .pad_y(24.0)
    } else {
        // A list of items, said as one. The role is what gives each row its
        // place in a set of four without anybody counting, and it is why a row
        // states its selection with `.selected` rather than with a fill: a
        // colour was never a semantic.
        col(rows).grow().gap(2.0).scroll().role(Role::List)
    };

    style::plate((
        section("SERVICES", Some(snapshot.services.len().to_string())),
        list,
        button("+  ADD SERVICE").on_click(|console: &mut Console| console.form_mut().open_blank()),
    ))
    .gap(8.0)
    // A share of the window, held between a minimum and a maximum: the layout
    // decides the width from the room there is, rather than a constant deciding
    // it from a window size nobody has.
    .w(rui::Length::Fraction(RAIL_SHARE))
    .min_w(RAIL_MIN)
    .max_w(RAIL_MAX)
}

/// One service in the rail: a lamp, a name, its state, and what it is doing.
///
/// The state's word is quiet unless it needs looking at, and the lamp carries
/// it the rest of the time — see [`style::state_ink`] for why a rail where
/// every healthy row is lit green cannot say when one is not.
fn service_row(service: &ServiceStatus, chosen: bool) -> El<Console> {
    let name = service.name.clone();
    let (status, _, summary) = present(&service.state);
    let state_label = service.state.label().to_uppercase();

    row((
        style::wedge(chosen),
        style::lamp(status),
        col((
            row((
                // The state is set bare rather than inside a tag. A tag is
                // chrome around one word, and on every row of a narrow rail
                // that chrome was taking the room the service's own name needed
                // — the name is what tells the rows apart, and it was the part
                // being truncated.
                text(display_name(service)).grow().text_size(13.5),
                style::state_word(status, state_label),
            ))
            .gap(4.0),
            caption(summary),
        ))
        .grow()
        .gap(1.0)
        .justify(Justify::Center),
    ))
    .key(&name)
    .h(ROW_HEIGHT)
    .gap(7.0)
    .pad_x(6.0)
    .round(Radius::Control)
    // A wash of the accent, and no outline: a filled row that is also outlined
    // in the same hue is a row wearing two selections, and against the hovered
    // row beside it the fill alone is already the difference.
    .fill(if chosen { Tone::Selection } else { Tone::Clear })
    .hover_fill(Tone::Raised)
    .role(Role::ListItem)
    .selected(chosen)
    .on_click(move |console: &mut Console| {
        let name = name.clone();
        console.with_snapshot(|snapshot| snapshot.selected = Some(name));
    })
}

/// The right-hand pane: the form if it is open, and the selected service if not.
fn pane(console: &Console, snapshot: &Snapshot) -> El<Console> {
    if console.form().is_open() {
        install::view(console)
    } else {
        detail::view(snapshot)
    }
    .grow()
}

/// What to show for a service's name.
fn display_name(service: &ServiceStatus) -> String {
    if service.display_name.is_empty() {
        service.name.clone()
    } else {
        service.display_name.clone()
    }
}

/// How a state should read: its colour, whether it can be started, and a summary.
///
/// One place, so the list, the detail pane, and the buttons cannot disagree
/// about whether a service is up.
pub(crate) fn present(state: &ServiceState) -> (Status, bool, String) {
    match state {
        ServiceState::Running { pid, uptime_secs } => {
            (Status::Ok, false, format!("pid {pid} · up {}", duration(*uptime_secs)))
        }
        ServiceState::Starting => (Status::Warn, false, "starting".into()),
        ServiceState::Stopping => (Status::Warn, false, "stopping".into()),
        ServiceState::Stopped => (Status::Idle, true, "not running".into()),
        ServiceState::Disabled => {
            (Status::Idle, false, "disabled; start requests are refused".into())
        }
        ServiceState::Exited { code } => (
            Status::Idle,
            true,
            match code {
                Some(0) => "exited cleanly".into(),
                Some(code) => format!("exited with code {code}"),
                None => "killed by a signal".into(),
            },
        ),
        ServiceState::Backoff { retry_in_secs, attempt } => (
            Status::Warn,
            false,
            format!("attempt {attempt} · retrying in {}", duration(*retry_in_secs)),
        ),
        ServiceState::GaveUp { attempts, reason } => {
            (Status::Bad, true, format!("gave up after {attempts} attempts · {reason}"))
        }
        ServiceState::Unstartable { reason } => (Status::Bad, true, reason.clone()),
    }
}

/// A number of seconds, in the largest two units that say something.
///
/// "6d 4h" rather than "534240s": the operator is judging whether a service has
/// been up long enough to trust, and that is a question about days and hours.
pub(crate) fn duration(seconds: u64) -> String {
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;

    match seconds {
        0..MINUTE => format!("{seconds}s"),
        MINUTE..HOUR => format!("{}m {}s", seconds / MINUTE, seconds % MINUTE),
        HOUR..DAY => format!("{}h {}m", seconds / HOUR, (seconds % HOUR) / MINUTE),
        _ => format!("{}d {}h", seconds / DAY, (seconds % DAY) / HOUR),
    }
}

/// A pane's title, with a rule running from it to the far edge.
///
/// The rule is what makes a title and whatever sits at the other end of its line
/// read as one line about one thing. Without it a wide pane puts a name at the
/// left edge and a tag at the right with a hand's width of nothing between,
/// which reads as two things that happen to share a strip.
pub(crate) fn title_rule(label: String, tail: Option<El<Console>>) -> El<Console> {
    row((title(label).align_self(Align::Center), style::rule(), tail)).gap(10.0).h(24.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rui::testing::Harness;
    use rui::{Appearance, FontId, LoadedFonts};
    use selfhost_config::StartMode;

    /// A snapshot with a service in each of the states the list can show.
    pub(crate) fn populated() -> Snapshot {
        let service = |name: &str, state: ServiceState| ServiceStatus {
            name: name.into(),
            display_name: String::new(),
            description: "notes".into(),
            state,
            start_mode: StartMode::Automatic,
            total_restarts: 3,
            log_seq: 0,
        };
        Snapshot {
            link: Link::Connected,
            services: vec![
                service("mongod", ServiceState::Running { pid: 4821, uptime_secs: 534_240 }),
                service("levelup-api", ServiceState::Running { pid: 5310, uptime_secs: 7_931 }),
                service("backups", ServiceState::Backoff { retry_in_secs: 40, attempt: 3 }),
                service(
                    "a-service-with-a-very-long-name",
                    ServiceState::Unstartable { reason: "no such file or directory".into() },
                ),
            ],
            selected: Some("levelup-api".into()),
            ..Default::default()
        }
    }

    /// A console showing `snapshot`, ready to be described or drawn.
    pub(crate) fn console(snapshot: Snapshot) -> Console {
        Console::new(
            Arc::new(Mutex::new(snapshot)),
            Arc::new(AtomicBool::new(true)),
            "127.0.0.1:9191".parse().expect("a valid address"),
            None,
        )
    }

    /// Draws one whole frame at a given size, with no window and no faces.
    ///
    /// No faces is the point: text measures to nothing, so every rectangle comes
    /// out at its minimum and anything that only fits because a label happened
    /// to be short is caught here rather than on someone's screen.
    fn draw_frame(width: u32, height: u32, console: Console) {
        let mut fonts = LoadedFonts {
            fonts: rui::Fonts::new(),
            ui_font: FontId::FIRST,
            mono_font: FontId::FIRST,
        };
        let mut app = App::new("test", console, view);
        app.render(width, height, 1.0, Appearance::Dark, &mut fonts);
    }

    #[test]
    fn a_frame_is_described_and_drawn_at_the_smallest_window_the_backend_allows() {
        draw_frame(560, 420, console(populated()));
    }

    #[test]
    fn a_frame_is_described_and_drawn_before_the_daemon_has_answered() {
        draw_frame(980, 680, console(Snapshot::default()));
    }

    #[test]
    fn a_frame_is_described_and_drawn_with_a_notice_and_a_broken_tunnel() {
        let mut snapshot = populated();
        snapshot.report_problem("mongod would not start");
        snapshot.tunnel = Some(Tunnel::Broken {
            reason: "ssh: connect to host example.com port 22: Connection refused".into(),
            advice: Some("Check that the server is reachable.".into()),
        });
        draw_frame(980, 680, console(snapshot));
    }

    #[test]
    fn a_frame_is_described_and_drawn_with_the_form_open() {
        let mut console = console(populated());
        console.form_mut().open_blank();
        draw_frame(980, 680, console);
    }

    #[test]
    fn choosing_a_row_selects_that_service_by_name() {
        // What the handler model buys: the behaviour attached to a row is an
        // ordinary function of the console, so it is tested without a frame,
        // a pointer, or a window.
        let mut console = console(populated());
        let row = service_row(&console.snapshot().services[0].clone(), false);
        (row.click_action().expect("a row is clickable"))(&mut console);
        assert_eq!(console.snapshot().selected.as_deref(), Some("mongod"));
    }

    #[test]
    fn a_broken_tunnel_is_reported_ahead_of_the_link_it_broke() {
        let mut snapshot = populated();
        snapshot.link = Link::Lost("connection refused".into());
        snapshot.tunnel = Some(Tunnel::Broken {
            reason: "permission denied".into(),
            advice: Some("Add your key to the server.".into()),
        });
        let (status, label, detail) =
            connection_summary(&snapshot, "127.0.0.1:9191".parse().unwrap(), Some("host"));
        assert_eq!(status, Status::Bad);
        assert_eq!(label, "tunnel down");
        assert!(detail.contains("Add your key"), "the advice is the useful half");
    }

    #[test]
    fn a_long_uptime_is_read_in_days_and_hours() {
        assert_eq!(duration(45), "45s");
        assert_eq!(duration(534_240), "6d 4h");
    }

    #[test]
    fn the_condition_names_the_one_service_that_wants_looking_at() {
        // The whole argument for a sentence: "one service needs attention"
        // makes the operator go and find which one.
        assert_eq!(condition(&populated()), "a-service-with-a-very-long-name needs attention");
    }

    #[test]
    fn the_condition_counts_them_once_there_is_more_than_one() {
        let mut snapshot = populated();
        snapshot.services[0].state =
            ServiceState::GaveUp { attempts: 5, reason: "no such file".into() };
        assert_eq!(condition(&snapshot), "2 services need attention");
    }

    #[test]
    fn a_service_merely_retrying_is_not_reported_as_needing_attention() {
        // Backoff is the supervisor doing its job. A condition line that called
        // it an alarm would be alarming on every restart of every service.
        let mut snapshot = populated();
        snapshot.services.retain(|service| !service.state.needs_attention());
        assert_eq!(condition(&snapshot), "2 of 3 running");
    }

    #[test]
    fn a_healthy_machine_is_told_so_in_one_line() {
        let mut snapshot = populated();
        snapshot.services.retain(|service| service.state.is_live());
        assert_eq!(condition(&snapshot), "Everything is running");
    }

    #[test]
    fn nothing_answering_is_reported_ahead_of_anything_it_would_have_said() {
        // A count of running services read off a snapshot nobody has confirmed
        // is a number about the last poll, not about the machine.
        let mut snapshot = populated();
        snapshot.link = Link::Lost("connection refused".into());
        assert_eq!(condition(&snapshot), "The daemon is not answering");

        snapshot.tunnel = Some(Tunnel::Broken { reason: "denied".into(), advice: None });
        assert_eq!(condition(&snapshot), "The tunnel to the server is down");
    }

    // -----------------------------------------------------------------------
    // What the console means, for anything that cannot see it
    // -----------------------------------------------------------------------

    /// Every screen the console can be on, driven through a real frame.
    ///
    /// Named so a failure says which one, since [`Harness::assert_accessible`]
    /// reports the offending element and not the screen it was on.
    fn screens() -> Vec<(&'static str, Console, (f32, f32))> {
        let mut form_open = console(busy());
        form_open.form_mut().open_blank();

        let mut announcing = busy();
        announcing.report_problem("mongod would not start");
        announcing.tunnel = Some(Tunnel::Broken {
            reason: "ssh: connect to host example.com port 22: Connection refused".into(),
            advice: Some("Check that the server is reachable.".into()),
        });

        vec![
            ("a console watching a service", console(busy()), (980.0, 680.0)),
            ("a console that has not connected", console(Snapshot::default()), (980.0, 680.0)),
            ("a console announcing a failure", console(announcing), (980.0, 680.0)),
            ("the install form", form_open, (980.0, 680.0)),
            ("the smallest window the backend allows", console(busy()), (560.0, 420.0)),
        ]
    }

    #[test]
    fn every_screen_is_reachable_named_and_ordered() {
        for (name, console, (width, height)) in screens() {
            println!("auditing {name}");
            let mut harness = Harness::new(console, view).size(width, height);
            harness.assert_accessible();
            harness.assert_tab_order();
        }
    }

    #[test]
    fn the_rail_is_a_list_whose_chosen_row_says_so_without_relying_on_its_colour() {
        let mut harness = Harness::new(console(busy()), view).size(980.0, 680.0);
        harness.frame();

        let rows: Vec<&rui::AccessNode> = harness
            .accessibility()
            .nodes()
            .iter()
            .filter(|node| node.role == Role::ListItem)
            .collect();
        assert_eq!(rows.len(), 4, "one item per service");
        assert!(
            rows.iter().all(|row| row.set_size == Some(4)),
            "containment is what gives a row its place in the set"
        );

        let chosen: Vec<&str> = rows
            .iter()
            .filter(|row| row.state.selected == Some(true))
            .map(|row| row.name.as_str())
            .collect();
        assert_eq!(chosen.len(), 1, "exactly one row is chosen");
        assert!(chosen[0].contains("levelup-api"), "and it is the selected one: {chosen:?}");
    }

    #[test]
    fn nothing_the_operator_can_reach_is_left_unnamed() {
        // The two controls with no words of their own — the cross that dismisses
        // a notice, and the minus beside each argument — are the ones a name has
        // to be written for. Asserted apart from the audit so that removing
        // their labels fails with the reason rather than with a role.
        let mut announcing = busy();
        announcing.report_problem("mongod would not start");
        let mut harness = Harness::new(console(announcing), view).size(980.0, 680.0);
        harness.frame();

        let named: Vec<&str> = harness
            .accessibility()
            .nodes()
            .iter()
            .filter(|node| node.role == Role::Button)
            .map(|node| node.name.as_str())
            .collect();
        assert!(named.contains(&"Dismiss"), "the notice's cross is named: {named:?}");
        assert!(named.iter().all(|name| !name.trim().is_empty()));
    }

    /// A console that has been connected for a while.
    ///
    /// Everything the panes can show at once: a definition that has arrived,
    /// output long enough to scroll, and a line on standard error.
    fn busy() -> Snapshot {
        let mut snapshot = populated();
        snapshot.spec = Some(Box::new({
            let mut spec = selfhost_config::ServiceSpec::new("levelup-api", "/usr/local/bin/node");
            spec.args = vec!["server.js".into(), "--port".into(), "8080".into()];
            spec
        }));
        snapshot.logs.service = "levelup-api".into();
        snapshot.logs.lines = (0..24)
            .map(|seq| crate::state::LogLine {
                seq,
                is_error: seq % 7 == 3,
                text: format!("[{seq:04}] listening on 127.0.0.1:8080, {seq} requests served"),
            })
            .collect();
        snapshot
    }

    /// The window sizes the reference frames are drawn at.
    ///
    /// The smallest the backend allows, the size the window opens at, and one
    /// larger — because a layout is wrong at the extremes long before it is
    /// wrong in the middle.
    const FRAME_SIZES: [(u32, u32); 3] = [(560, 420), (980, 680), (1180, 760)];

    /// Writes what the console actually looks like, and what a frame costs.
    ///
    /// Skipped unless `SELFHOST_FRAME_DIR` names a directory to write into,
    /// because what it produces is something a person looks at rather than
    /// something a machine can assert. It exists because the frame tests above
    /// deliberately run with no faces loaded — they prove every rectangle
    /// survives, and they cannot say whether the result is legible.
    ///
    /// Run it in release when the timings are what is wanted; a debug build
    /// measures the rasteriser with its optimisations off, which is a number
    /// about `cargo` rather than about the interface.
    #[test]
    fn reference_frames() {
        /// How many frames each timing is averaged over, after a warm-up.
        const RUNS: u32 = 200;

        let Ok(directory) = std::env::var("SELFHOST_FRAME_DIR") else {
            println!("skipped: set SELFHOST_FRAME_DIR to a directory to write reference frames");
            return;
        };
        let Ok(mut fonts) = rui::shell::load_system_fonts() else {
            println!("skipped: no font on this machine");
            return;
        };

        // The window as it opens, the smallest the backend allows, and the
        // first frame anybody ever sees — a console with nothing in it. A
        // layout is wrong at the extremes long before it is wrong in the
        // middle, and a decision about appearance made from one comfortable
        // size is a decision nobody has actually looked at.
        let alarmed = {
            let mut snapshot = busy();
            snapshot.report_problem("mongod would not start");
            snapshot.tunnel = Some(Tunnel::Broken {
                reason: "ssh: connect to host example.com port 22: Connection refused".into(),
                advice: Some("Check that the server is reachable.".into()),
            });
            snapshot
        };

        for (name, snapshot, open_form, (width, height)) in [
            ("console", busy(), false, (1000, 660)),
            ("install", busy(), true, (1000, 660)),
            ("console-narrow", busy(), false, (560, 420)),
            ("console-empty", Snapshot::default(), false, (1000, 660)),
            ("console-alarmed", alarmed, false, (1000, 660)),
        ] {
            let mut console = console(snapshot);
            if open_form {
                console.form_mut().open_blank();
            }
            let mut app = App::new("selfhost", console, view);

            for (suffix, appearance) in [("light", Appearance::Light), ("dark", Appearance::Dark)] {
                let canvas = app.render(width, height, 2.0, appearance, &mut fonts);
                let pixels = rui::image::rgba(&canvas);
                let png = rui::image::png(canvas.width(), canvas.height(), &pixels)
                    .expect("a frame should encode");
                let path = format!("{directory}/{name}-{suffix}.png");
                std::fs::write(&path, png).expect("the directory should be writable");
                println!("wrote {path}");
            }
        }

        // What a frame costs, at the sizes the window is actually used at. The
        // glyph cache is warmed first: the first frame at a new size rasterises
        // every glyph in it, and that is a start-up cost rather than a frame's.
        let mut app = App::new("selfhost", console(busy()), view);
        println!("\n| window | pixels | draw the whole interface | describe it |");
        println!("|---|---|---|---|");
        for (width, height) in FRAME_SIZES {
            // Into a canvas that already exists, with the scroll state carried
            // between frames, because that is what the loop in a window does. A
            // fresh surface per frame would be measuring the allocator.
            let mut canvas = rui::Canvas::new(width * 2, height * 2, 2.0);
            let mut memory = rui::Memory::new();
            app.draw_into(&mut canvas, &mut fonts, Appearance::Dark, &mut memory);

            let started = std::time::Instant::now();
            for _ in 0..RUNS {
                app.draw_into(&mut canvas, &mut fonts, Appearance::Dark, &mut memory);
            }
            let each = started.elapsed() / RUNS;

            // What the description itself costs, apart from drawing it. The
            // interesting number: if building the whole tree of elements every
            // frame were expensive, the declarative model would be paid for in
            // frames rather than in clarity.
            let describing = std::time::Instant::now();
            for _ in 0..RUNS {
                std::hint::black_box(view(app.state()));
            }
            let describe = describing.elapsed() / RUNS;
            let pixels = (width * 2) as f32 * (height * 2) as f32 / 1_000_000.0;
            println!(
                "| {width} × {height} | {pixels:.1} M | **{:.1} ms** | {:.0} µs |",
                each.as_secs_f32() * 1000.0,
                describe.as_secs_f32() * 1_000_000.0
            );
        }
    }
}

