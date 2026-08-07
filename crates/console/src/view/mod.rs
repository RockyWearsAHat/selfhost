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
//! connected, and a readout bank in which the machine states its own condition
//! in a sentence, cites the counts it read that off, and says what it is about
//! to do next. They are strips and not cards because they are read in a glance
//! and never dwelt on — the vertical space a card spends on its own edges is
//! space the log below it does not get.
//!
//! The sentence is the largest type in the window. That is the one hierarchy
//! decision everything else here defers to: the console's job is to tell the
//! operator what is going on before being asked, and a report is a line of
//! words. Numbers sit under it as what it was read off, never beside it as its
//! equals — see [`bank`].
//!
//! The bank's other half is the tense the sentence cannot use. A condition is
//! written in the present: it says what the machine *is*. A supervisor that has
//! put a service in backoff has also decided what it will do and when, and that
//! is knowledge the console holds and used to throw away — so the right-hand
//! half of the bank states the next move and offers the one control that
//! changes it. See [`next_move`], which is where the deciding happens.
//!
//! # What holds it together
//!
//! Rules, not boxes. Each block is introduced by a small-capital label with a
//! ticked hairline running from it to the far edge, which states where the block
//! ends without drawing an outline around it. Nesting outlines is what made an
//! earlier revision read as a diagram of an interface rather than as one: four
//! rounded cards inside a rounded panel inside a window is three frames around
//! every fact. There are three framed surfaces on screen — the readout bank,
//! the rail and the detail pane — and everything inside them is separated by
//! ruling. Each is a square plate one value above the ground, told by a grey
//! hairline: an outline that says where a reading is taken, and nothing inside
//! it repeating the claim. The masthead is not framed at all — a nameplate is
//! not a reading, so the wordmark sits directly on the black.
//!
//! What each mark is *made* of, and why everything in the window — the marks
//! the console draws and the controls the operator presses alike — is cut from
//! the same stock, is [`style`]. Nothing here picks a colour or a corner for
//! itself.
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
    Align, App, El, Key, Role, Status, Tone, button, caption, col, figure, heading, micro,
    paragraph, row, spacer, text, title,
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
const MASTHEAD: f32 = 30.0;

/// How far the wordmark's capitals are opened up.
///
/// More than any heading in the window, because it is the one piece of type that
/// is not reporting anything: a name held open reads as a plate screwed to the
/// front of an instrument, which is what the strip carrying it is.
const WORDMARK: f32 = 2.4;

/// How wide the gutter carrying a row's unit number is.
const UNIT_GUTTER: f32 = 16.0;

/// The width a *quiet* row's state word may be squeezed to, and no further.
///
/// On a narrow rail the name and the state want the same line, and the name is
/// the only thing telling the rows apart — the state is already said twice by
/// the lamp, in a hue and in a fill. The name therefore grows *from its words*
/// and the state word is what gives way when the line is short: without that,
/// the name was the payer by construction — it was the grower, a grower's
/// floor is zero, and the layout never takes from a content-sized child while
/// a grower can still give — so `backups` read `back…` beside an untouched
/// `RESTARTING`, the priority exactly inverted. The floor is what stops the
/// trade at the other extreme: a state squeezed to nothing is a fact deleted,
/// not a fact deferred, so the word keeps enough room to open with a few
/// characters and say the rest with its ellipsis. It is below the narrowest
/// word a state can be, so a row with room never draws a wider element than
/// its own text.
///
/// A red word pays nothing, though — and only a red one. [`Status::Bad`] is
/// the hue of *somebody must act*, and a red `CAN…` is that summons cut to a
/// syllable on exactly the row that earned the words; so [`service_row`]
/// floors a red word at its own full width and lets the name pay, which the
/// name can afford — it is still told by the summary under it and by being
/// chosen. An amber word stays a payer with the rest: amber is the machine
/// already handling it, its countdown is restated in the summary below, and
/// holding `RESTARTING` whole was measured to cut `backups` to `b…` — the
/// priority inversion this floor exists to prevent.
const STATE_FLOOR: f32 = 36.0;

/// The width one character of a red state word is guaranteed, in units.
///
/// The layout's shrink pass takes from content-sized children first, floored
/// at each one's stated minimum — a floor is the only guarantee a squeezed
/// row honours, so "give the alarm its words" has to be said in units, and
/// the units have to come from the word: a floor sized to the vocabulary's
/// widest entry taxes a short alarm for letters it does not have. One unit is
/// a small-capital character of the state's face with its tracking and a
/// little air; a face change shows up as a cut alarm in the reference frames,
/// which is where this gets re-measured.
const ALARM_UNIT: f32 = 7.1;

/// How tall the readout bank is at rest.
///
/// Unchanged by the restaging that put the condition above the counts rather
/// than beside them, and deliberately so: a label stacked over a figure and a
/// sentence stacked over a line of readings come to the same two lines of type,
/// so the bank now says something quite different for exactly the height it
/// cost before. Height is what the log below it does not get, and a change in
/// hierarchy should not be charged to the log.
///
/// A minimum, not a size: on a window too narrow for the sentence, the strip
/// grows so the words wrap whole rather than truncating mid-verdict — and it
/// is allowed [`BANK_GROWTH`] more units and no further, because every unit
/// past that is taken off the log below it.
const BANK: f32 = 54.0;

/// The most the bank may grow past [`BANK`] to keep its words whole.
///
/// One more line of the sentence, roughly. A cap because the bank and the log
/// want the same room and the log is why the console is open: a report may
/// cost a line, but it may not cost the evidence.
const BANK_GROWTH: f32 = 26.0;

/// What share of the bank the next move takes, at the far end of it.
///
/// A share and not a width, for the reason [`RAIL_SHARE`] is one: the condition
/// is a sentence whose length nobody controls, and a fixed column beside it
/// would be a third of the smallest window and a tenth of the largest.
///
/// Stated against the bank rather than grown from what the block asks for, and
/// that is the part worth defending. The block's own content is a countdown —
/// `retries in 40s`, then `retries in 9s` a moment later — so a block sized to
/// it would be a block that changed width every time the daemon answered, and
/// the control at the end of it would walk left and right under the pointer
/// reaching for it. A share holds the button still while the words inside it
/// change, which is the whole of what a strip of instruments is for.
const NEXT_SHARE: f32 = 0.34;

/// The widest it is drawn, past which it is a short line of words in a hall.
const NEXT_MAX: f32 = 380.0;

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
        application(title, self)
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

/// The console as an application, drawn in the console's own theme.
///
/// One place, so that a frame drawn by a test is the frame the window shows.
/// The palette reaches every widget through [`rui::App::theme`] and nowhere
/// else, and an `App` built without it would be this same layout in the
/// library's own colours — which is a thing worth being unable to do by
/// accident. See [`style::theme`].
pub(crate) fn application(title: impl Into<String>, console: Console) -> App<Console> {
    App::new(title, console, view).theme(style::theme).ground(style::ground)
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
/// Unframed, alone among the window's strips: a nameplate is not a reading,
/// and boxing the name gave the window one more outline saying nothing. The
/// wordmark and the connection sit directly on the black, under the ground's
/// own ruler, which is what an engraved front panel is.
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
///
/// While the console is still reaching — the first poll, or an `ssh` that has
/// been started and is not forwarding yet — the lamp is a sweep going round
/// instead. That is the one place a loop is worth the frames it asks for: a
/// connection being made is a fact with a duration, and a still mark for it says
/// only that something is amber.
fn header(console: &Console, snapshot: &Snapshot) -> El<Console> {
    let (status, label, detail) =
        connection_summary(snapshot, console.address, console.via.as_deref());
    let reaching =
        snapshot.link == Link::Connecting || matches!(snapshot.tunnel, Some(Tunnel::Opening));

    row((
        style::mark(),
        title("SELFHOST").tracking(WORDMARK).align_self(Align::Center),
        // The instrument's designation, in the voice a block label uses. A
        // wordmark alone names a product; a wordmark with what the instrument
        // *is* set quietly beside it names a machine's front panel, and the
        // masthead is the one strip in the window that is a panel rather than
        // a reading.
        heading("SUPERVISOR CONSOLE").tracking(1.8).align_self(Align::Center),
        style::rule(),
        style::link_mark(status, label.to_uppercase(), reaching),
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
            // The reason is `ssh`'s own sentence and the advice is this
            // program's; a dash keeps them two voices rather than running the
            // tool's complaint into the console's instruction mid-line.
            Some(advice) => format!("The SSH tunnel is down. {reason} — {advice}"),
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
        // Outlined in the status's own hue rather than the structural grey:
        // an alert is the one strip that has pushed its way in above the
        // panes, and its frame is part of the announcement.
        .border(1.0, ink)
        .color(ink)
}

/// The readout bank: the machine's own account of itself, and the counts it
/// rests on.
///
/// One surface, not four cards with a gap between them. Four cards spend four
/// sets of edges, four corner radii, and four shadows on four small numbers,
/// and they were taking a fifth of the window's height to do it.
///
/// # The sentence is the report; the counts are its evidence
///
/// [`condition`] is one line, in words, saying what the machine amounts to
/// right now. It is the only text in the window about the *whole* installation
/// rather than about one service, and it is the console's answer to the
/// question anybody actually opened it with. So it is set at the largest size
/// the type scale has and given the width of the window to be a sentence in.
///
/// The counts used to sit beside it in cells of their own, three figures at the
/// same size as each other and larger than the line that interpreted them —
/// which made the bank a row of four equals where only one of them was a
/// verdict. `2/4` is not a report. It is what the report is *based on*, and it
/// now reads as that: one quiet line underneath, in the size a citation is set
/// in. Nothing was removed; the hierarchy was.
///
/// There is no `CONDITION` label above the sentence any more. A block in this
/// window is introduced by a small-capital label because a block holds several
/// facts and the label says what they have in common — and a single sentence
/// naming its own subject does not need telling that it is a condition. The
/// masthead carries no label either, for the same reason.
///
/// With nothing installed there is nothing for the counts to be evidence of,
/// and `RUNNING 0/0 · RESTARTS 0 · ATTENTION 0` is three readings of a machine
/// that has not been asked to do anything. The line goes; the sentence still
/// says what is happening.
///
/// # What the other half is for
///
/// Report on the left, intention on the right, and the two are different tenses
/// rather than two halves of one statement — which is why they are set as two
/// columns and not as one wrapping paragraph. The right-hand half appears only
/// when there is a next move to state; on a machine with nothing outstanding
/// the bank is the sentence and its evidence, exactly as it was, and the room
/// is left empty rather than filled with a line saying that nothing is
/// happening. An instrument that reports when it has nothing to report is an
/// instrument nobody reads.
fn bank(snapshot: &Snapshot) -> El<Console> {
    style::plate(
        row((
            live_share(snapshot).map(style::gauge),
            // The sentence wraps and the strip states its height as a
            // minimum, so a narrow window pays for the report in height —
            // which the layout takes back off the log — rather than in
            // legibility. A verdict cut to an ellipsis mid-clause is the one
            // thing the bank must never show: the clause it cuts is the
            // verdict.
            col((figure(condition(snapshot)).wrap(), evidence(snapshot)))
                .gap(3.0)
                .justify(Justify::Center)
                .grow(),
            next_move(snapshot).map(upcoming),
        ))
        .gap(12.0)
        .min_h(BANK)
        .max_h(BANK + BANK_GROWTH)
        // The plate's own padding, applied here instead: the surface has to
        // carry the sentence's full height itself, so it is the strip
        // inside that is inset — and at the same twelve units every other
        // plate in the window insets by, or the report would start a
        // couple of units off the line SERVICES starts on.
        .pad_x(12.0),
    )
    .pad_y(0.0)
    .pad_x(0.0)
}

/// How much of the machine is up, as a share, or `None` with nothing installed.
///
/// The gauge drawn from it is the one mark in the bank that is read without
/// being read *out*: an arc at a quarter and an arc at a whole turn are told
/// apart across a room, which is what a strip glanced at from a desk chair is
/// for. It states the same ratio the RUNNING reading beside it does, and that
/// repetition is the point — the words are the exact figure and the arc is the
/// proportion, and neither is the other.
///
/// Absent for the same reason the readings are: on a machine with nothing
/// installed, an empty gauge would report that none of nothing is running.
fn live_share(snapshot: &Snapshot) -> Option<f32> {
    let total = snapshot.services.len();
    if total == 0 {
        return None;
    }
    let running = snapshot.services.iter().filter(|service| service.state.is_live()).count();
    Some(running as f32 / total as f32)
}

/// The counts the condition was read off, or nothing when there is none.
///
/// Exactly one of them can raise its voice, and it is the one that means
/// somebody has to do something. A ratio is not a verdict — a service the
/// operator stopped on purpose would turn RUNNING amber and leave it amber for
/// the rest of the day — and a restart is something that already happened and
/// that the supervisor already handled. A colour spent on either is a colour the
/// reader learns to look past, which is the colour ATTENTION needs to still be
/// worth something.
///
/// The count of services is not among them: `RUNNING 2/4` already states the
/// total, and the rail's own heading states it again beside the list it belongs
/// to. A reading that repeats its neighbour's denominator is spent on nothing.
fn evidence(snapshot: &Snapshot) -> Option<El<Console>> {
    let total = snapshot.services.len();
    if total == 0 {
        return None;
    }
    let running = snapshot.services.iter().filter(|service| service.state.is_live()).count();
    let attention =
        snapshot.services.iter().filter(|service| service.state.needs_attention()).count();
    let restarts: u64 = snapshot.services.iter().map(|service| service.total_restarts).sum();

    Some(
        // A flow, not a row: a reading squeezed to an ellipsis reports
        // nothing, so on a rail-narrow window the readings run onto a second
        // line whole rather than truncating on one. On any window worth
        // having they are one line, exactly as a row would have drawn them.
        row((
            style::reading("RUNNING", format!("{running}/{total}"), None),
            style::reading("RESTARTS", restarts.to_string(), None),
            style::reading(
                "ATTENTION",
                attention.to_string(),
                (attention > 0).then_some(Status::Bad),
            ),
        ))
        .flow()
        .gap(14.0),
    )
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

/// What the machine is about to do, and the one control that changes it.
///
/// Held as a struct rather than a formatted line because the block draws four
/// separate marks from it — a lamp, a headline, its evidence, and a control —
/// and a function that returned a sentence would have the view unpicking it
/// again to find the service name to send the command about.
struct NextMove {
    /// How pressing the state is, which is what its lamp is lit from.
    status: Status,
    /// What is going to happen, in words: `backups retries in 40s`.
    headline: String,
    /// What that was read off, and what else is queued behind it.
    detail: String,
    /// The word on the control, and what pressing it asks the poller for.
    control: (&'static str, Command),
}

/// What the machine will do next by itself, or `None` when it will do nothing.
///
/// Pure, and tested apart from the drawing, for the same reason [`condition`]
/// is: this is the piece with the judgement in it, and the judgement is the
/// whole of the block.
///
/// # Nothing is claimed about a machine that is not answering
///
/// A countdown is a live number. `retries in 40s` read off a poll that failed
/// is not stale in the way a count is stale — it is wrong, and it goes on
/// counting down convincingly while nothing at all is happening on the server.
/// So a lost link or a broken tunnel suppresses the block outright, in the same
/// order [`condition`] puts them: whether anyone is answering comes before
/// anything they might have said.
///
/// # What gets the space when several want it
///
/// Whatever has a *when* first, soonest first — and that is the whole rule.
///
/// It is worth saying why this is not ranked by severity, because severity is
/// the obvious answer and it is wrong here. A service that cannot start is
/// already stated four times over on this screen: the condition names it, the
/// ATTENTION count counts it, its row is lit red, and its state word is one of
/// the two in the rail set in a colour. A supervisor quietly counting down to
/// its third restart of `backups` is stated nowhere. Repeating the loudest fact
/// in the window in the one place that had room for a new one is how a strip
/// full of readings comes to say one thing.
///
/// So the block leads with the move that has a clock on it, and falls back to
/// what has stalled — `Cannot start`, `Gave up` — only when nothing is
/// scheduled, where it earns its place by carrying the reason and the control
/// rather than the name a reader already has.
///
/// [`ServiceState::Starting`] and [`ServiceState::Stopping`] are deliberately
/// not candidates. Both are moves already under way rather than ones about to
/// be made, neither carries a time to state, and the only control that would
/// change either is the one that fights it.
fn next_move(snapshot: &Snapshot) -> Option<NextMove> {
    if matches!(snapshot.tunnel, Some(Tunnel::Broken { .. })) || snapshot.link != Link::Connected {
        return None;
    }

    let mut candidates: Vec<(u8, u64, NextMove)> =
        snapshot.services.iter().filter_map(outstanding).collect();
    // Sorted rather than picked with a minimum so that the count of what is left
    // is the count of what this one is standing in front of, not a second walk
    // that could disagree with the first about which was chosen.
    candidates.sort_by_key(|(rank, due, _)| (*rank, *due));

    let mut waiting = candidates.into_iter();
    let (_, _, mut next) = waiting.next()?;
    match waiting.count() {
        0 => {}
        1 => next.detail = format!("{} · 1 more waiting", next.detail),
        more => next.detail = format!("{} · {more} more waiting", next.detail),
    }
    Some(next)
}

/// What one service is waiting on, ranked, or `None` when it wants nothing.
///
/// The rank is the order [`next_move`] argues for and the number beside it is
/// how soon, in seconds, so that two services in backoff are separated by which
/// one moves first rather than by where they happen to sit in the list.
fn outstanding(service: &ServiceStatus) -> Option<(u8, u64, NextMove)> {
    /// A move the supervisor has already scheduled.
    const SOON: u8 = 0;
    /// A service that has stopped and will not resume without being asked.
    const STALLED: u8 = 1;

    let name = display_name(service);
    let (status, ..) = present(&service.state);
    let move_of = |headline, detail, control| NextMove { status, headline, detail, control };

    match &service.state {
        ServiceState::Backoff { retry_in_secs, attempt } => Some((
            SOON,
            *retry_in_secs,
            move_of(
                format!("{name} retries in {}", duration(*retry_in_secs)),
                format!("attempt {attempt}"),
                // Restart and not Start: the supervisor is going to make this
                // attempt anyway, and what the operator is asking for is that it
                // be made now instead of at the end of the delay. Restart is the
                // one command the daemon accepts whatever the state.
                ("Retry now", Command::Restart(service.name.clone())),
            ),
        )),
        ServiceState::GaveUp { attempts, reason } => Some((
            STALLED,
            0,
            move_of(
                format!("{name} gave up after {attempts} attempts"),
                reason.clone(),
                ("Start", Command::Start(service.name.clone())),
            ),
        )),
        ServiceState::Unstartable { reason } => Some((
            STALLED,
            0,
            move_of(
                format!("{name} cannot start"),
                reason.clone(),
                // Offered even though it will fail again until whatever the
                // reason names is fixed. That is what makes it the control that
                // changes the outcome: it is the thing to press *after* fixing
                // it, and a console that hid it would leave the operator
                // hunting the rail for a way to try again.
                ("Start", Command::Start(service.name.clone())),
            ),
        )),
        _ => None,
    }
}

/// The next move, drawn at the far end of the bank.
///
/// A hairline stands between it and the condition. The alternative was a second
/// plate, and two surfaces touching along an edge is the four-cards defect the
/// bank was restaged to be rid of — the strip is one instrument reporting two
/// tenses, and one rule is what says so without drawing a box to say it.
///
/// The control is an ordinary button and not the primary one. The accent is
/// spent on the action a screen is *for* and on which row is chosen, and the
/// pane below already carries a primary; a second one on the same screen would
/// make the accent mean "a button" rather than "the action". What earns this
/// button its notice is that it is the only control in the window that is about
/// a service the operator did not select.
///
/// The headline is the one line of ordinary type in the window set in a status's
/// own hue, and it is set in one under exactly the rule [`style::state_ink`]
/// applies everywhere else: a countdown is amber because something is waiting,
/// and a service that has stalled is red because something has stopped. Neither
/// appears without a cause, because the block itself does not.
fn upcoming(next: NextMove) -> El<Console> {
    let (label, command) = next.control;
    row((
        style::standing_rule(),
        style::lamp(next.status),
        col((
            // Wrapped, never cut: the headline is a countdown, and an
            // ellipsis lands exactly on the clause with the clock in it.
            text(next.headline).text_size(13.5).color(style::state_ink(next.status)).wrap(),
            // The detail stays one line and truncates. Wrapping it was tried:
            // in a bank whose height is capped, the detail's second line is
            // taken from the headline's last — which on a narrow window is the
            // clause with the clock in it. Of the two, the ellipsis belongs on
            // the tail of the evidence, never on the countdown.
            caption(next.detail),
        ))
            .gap(1.0)
            .grow()
            .justify(Justify::Center),
        button(label)
            .on_click(move |console: &mut Console| console.request(command.clone()))
            .align_self(Align::Center),
    ))
    .gap(10.0)
    .w(rui::Length::Fraction(NEXT_SHARE))
    .max_w(NEXT_MAX)
}

/// The rail of services, and the button that adds one.
///
/// The button runs the full width and follows the last row, rather than sitting
/// beside the heading or pinned to the foot of the rail. An action that adds to
/// a list belongs at the end of the list, where the eye already is once it has
/// read down it and not found what it wanted.
///
/// It used to be pinned to the bottom edge, and the reason given for that was
/// that a list rarely fills its rail and the room under the last row was the
/// largest empty area in the window. That is a true observation and the wrong
/// conclusion — pinning the button to the floor does not spend the room, it
/// puts the room *above* the button, which is the one place a gap cannot be
/// read as a list that has ended. Four services followed by a hand's width of
/// nothing and then a control read as a row that had failed to draw. Below the
/// button the same emptiness reads as what it is: a rail with space for more.
///
/// The list keeps its own scrolling, so a rail with more services than fit
/// still shows them all — what shrinks when the room runs out is the list,
/// which was going to be scrolled anyway, and never the button.
fn rail(snapshot: &Snapshot) -> El<Console> {
    let rows: Vec<El<Console>> = snapshot
        .services
        .iter()
        .enumerate()
        .map(|(index, service)| {
            service_row(index, service, snapshot.selected.as_deref() == Some(service.name.as_str()))
        })
        .collect();

    let list: El<Console> = if rows.is_empty() {
        col(caption(match snapshot.link {
            Link::Connected => "The daemon is running no services yet.",
            _ => "Waiting for the daemon.",
        })
        .wrap()
        .center_text())
        .pad_y(24.0)
    } else {
        // A list of items, said as one. The role is what gives each row its
        // place in a set of four without anybody counting, and it is why a row
        // states its selection with `.selected` rather than with a fill: a
        // colour was never a semantic.
        col(rows).gap(2.0).scroll().role(Role::List)
    };

    style::plate((
        style::section_rule("SERVICES", Some(snapshot.services.len().to_string())),
        list,
        button("+  ADD SERVICE").on_click(|console: &mut Console| console.form_mut().open_blank()),
        // The room the list did not need, kept below everything rather than
        // between the list and the button. It grows so that it is what gives
        // way first when the list is long: a rail that has run out of room
        // takes it back from here before it takes anything from the list.
        spacer().grow(),
    ))
    .gap(8.0)
    // A share of the window, held between a minimum and a maximum: the layout
    // decides the width from the room there is, rather than a constant deciding
    // it from a window size nobody has.
    .w(rui::Length::Fraction(RAIL_SHARE))
    .min_w(RAIL_MIN)
    .max_w(RAIL_MAX)
}

/// One service in the rail: its unit number, a lamp, a name, its state, and
/// what it is doing.
///
/// The number is the row's position in the rack, in the gutter's dimmest ink.
/// A rack's units are numbered whether or not anything is bolted into them,
/// and the count is what lets two operators on a call say "unit three" instead
/// of spelling a service's name at each other — the same job the log's
/// sequence gutter does, done in the same voice: a column to be pointed at,
/// never read.
///
/// The state's word is quiet unless it needs looking at, and the lamp carries
/// it the rest of the time — see [`style::state_ink`] for why a rail where
/// every healthy row is lit green cannot say when one is not.
///
/// The chosen row is *lit* rather than washed: a white hairline over the
/// ground every other row sits on, and the lit bar of the wedge at its edge.
/// A wash of the accent is what a desktop list does, and on a ground this dark
/// it is a change of value so small that the wedge was doing all the work
/// anyway — while a row whose outline has been switched on is what a selected
/// channel looks like on an instrument. It does not glow: light here is
/// stated by value, and the halo is kept for the marks that are waiting.
fn service_row(index: usize, service: &ServiceStatus, chosen: bool) -> El<Console> {
    let name = service.name.clone();
    let (status, _, _) = present(&service.state);
    let state_label = service.state.label().to_uppercase();
    let summary = rail_summary(service);

    let row = row((
        style::wedge(chosen),
        micro(format!("{:02}", index + 1))
            .color(Tone::Idle)
            .w(UNIT_GUTTER)
            .text_align(Align::End)
            .align_self(Align::Center),
        style::lamp(status),
        col((
            row((
                // The state is set bare rather than inside a tag. A tag is
                // chrome around one word, and on every row of a narrow rail
                // that chrome was taking the room the service's own name needed
                // — the name is what tells the rows apart, and it was the part
                // being truncated. Growing the name from its words finishes
                // that argument: a short line takes from a quiet state word
                // first, down to [`STATE_FLOOR`], and only then from the name.
                // A troubled word is the exception argued at the floor's own
                // doc: it keeps its words, and the name is the payer.
                text(display_name(service)).grow_from_content().text_size(13.5),
                match status {
                    // Floored at the word's own width so it stands whole, and
                    // flush against the row's end so it sits where every other
                    // state word sits when the floor lands a unit wide.
                    Status::Bad => {
                        let whole = state_label.len() as f32 * ALARM_UNIT;
                        style::state_word(status, state_label)
                            .min_w(whole)
                            .text_align(Align::End)
                    }
                    _ => style::state_word(status, state_label).min_w(STATE_FLOOR),
                },
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
    .hover_fill(Tone::Raised)
    .role(Role::ListItem)
    .selected(chosen)
    .on_click(move |console: &mut Console| {
        let name = name.clone();
        console.with_snapshot(|snapshot| snapshot.selected = Some(name));
    })
    // The arrows walk the rail from whichever row holds the keyboard. The
    // handler reads the selection rather than this row's own index, so two
    // presses from one focused row move two rows — focus and selection are
    // different facts, and it is the selection being driven.
    .on_key(|console: &mut Console, key, _modifiers| {
        let step = match key {
            Key::Up => -1,
            Key::Down => 1,
            _ => return,
        };
        console.with_snapshot(|snapshot| snapshot.select_step(step));
    });

    if chosen { row.border(1.0, Tone::Accent) } else { row }
}

/// What a rail row says under a service's name.
///
/// A running service wears its restart count: `pid 4821 · up 2h` on a service
/// that has crashed twelve times today reads as health, and the rail is where
/// a flapping service has to be *noticed* — the detail pane states the count
/// only after the row has already been chosen. Only a live service carries it;
/// every troubled state's summary already accounts for its restarts in its own
/// words, and a stopped service's count is history rather than a warning.
///
/// Pure, so the rule about who carries the count is asserted without a frame.
fn rail_summary(service: &ServiceStatus) -> String {
    let (_, _, summary) = present(&service.state);
    match service.total_restarts {
        0 => summary,
        _ if !service.state.is_live() => summary,
        1 => format!("{summary} · 1 restart"),
        restarts => format!("{summary} · {restarts} restarts"),
    }
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
        let mut app = application("test", console);
        app.render(width, height, 1.0, Appearance::Dark, &mut fonts);
    }

    #[test]
    fn only_a_live_service_wears_its_restart_count_in_the_rail() {
        let snapshot = populated();
        let running = &snapshot.services[0];
        assert!(rail_summary(running).ends_with("· 3 restarts"), "a live flapper says so");

        let backoff = &snapshot.services[2];
        assert!(
            !rail_summary(backoff).contains("restarts"),
            "a troubled state's own words already account for its restarts"
        );

        let mut quiet = running.clone();
        quiet.total_restarts = 0;
        assert!(!rail_summary(&quiet).contains("restart"), "a clean service says nothing");
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
        let row = service_row(0, &console.snapshot().services[0].clone(), false);
        (row.click_action().expect("a row is clickable"))(&mut console);
        assert_eq!(console.snapshot().selected.as_deref(), Some("mongod"));
    }

    #[test]
    fn an_arrow_on_any_row_moves_the_selection_through_the_rail() {
        // The handler is an ordinary function of the console, so the keyboard's
        // half of choosing is tested the same way the pointer's half is: no
        // frame, no window, no synthetic keystroke.
        let mut console = console(populated());
        let row = service_row(0, &console.snapshot().services[0].clone(), false);
        let keys = row.key_action().expect("a row listens to the keyboard");

        keys(&mut console, Key::Down, rui::Modifiers::NONE);
        assert_eq!(console.snapshot().selected.as_deref(), Some("backups"));
        keys(&mut console, Key::Up, rui::Modifiers::NONE);
        assert_eq!(console.snapshot().selected.as_deref(), Some("levelup-api"));
        keys(&mut console, Key::Enter, rui::Modifiers::NONE);
        assert_eq!(
            console.snapshot().selected.as_deref(),
            Some("levelup-api"),
            "other keys are left to the controls that own them"
        );
    }

    #[test]
    fn a_quiet_state_word_gives_way_and_a_troubled_one_keeps_its_words() {
        // The synthetic face makes the widths exact: every character is half
        // its text size wide, plus its tracking.
        let width_of = |word: &str| word.len() as f32 * (10.5 / 2.0 + 0.4);

        // A red word is the summons to act, so it is never the payer: CANNOT
        // START stands whole on the narrowest rail the layout allows, and the
        // long name beside it is what truncates.
        let mut harness =
            Harness::new(console(populated()), |console: &Console| rail(&console.snapshot()))
                .size(RAIL_MIN, 420.0);
        harness.frame();
        let state = harness.rect_of("CANNOT START").expect("the state is drawn");
        assert!(state.w >= width_of("CANNOT START") - 0.5, "an alarm is never cut: {}", state.w);
        // An amber word is a payer like any quiet one — the machine is
        // handling it and the summary restates the countdown — but on a row
        // whose own line has room, nothing is taken from it.
        assert!(
            harness.rect_of("RESTARTING").expect("the state is drawn").w
                >= width_of("RESTARTING") - 0.5,
            "a fitting row gives nothing"
        );

        // A quiet word is already said twice by the lamp, so on a short line
        // it is squeezed to its floor and the name keeps the difference.
        let mut long_running = populated();
        long_running.services.truncate(1);
        long_running.services[0].name = "a-very-long-name-for-a-running-service".into();
        let mut harness =
            Harness::new(console(long_running), |console: &Console| rail(&console.snapshot()))
                .size(RAIL_MIN, 420.0);
        harness.frame();
        let running = harness.rect_of("RUNNING").expect("the state is drawn");
        assert!(running.w <= STATE_FLOOR + 0.5, "a quiet word is the payer: {}", running.w);
        let name = harness
            .rect_of("a-very-long-name-for-a-running-service")
            .expect("the name is drawn");
        assert!(name.w > running.w, "what the floor spared goes to the name: {}", name.w);
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

    #[test]
    fn the_next_move_is_the_one_with_a_clock_on_it() {
        // `populated` holds both cases at once: a service that cannot start,
        // which the condition line already names, and a service the supervisor
        // is counting down to retrying, which nothing else on screen says.
        let next = next_move(&populated()).expect("a machine with something outstanding");
        assert_eq!(next.headline, "backups retries in 40s");
        assert_eq!(next.detail, "attempt 3 · 1 more waiting");
        assert_eq!(next.control.0, "Retry now");
        assert_eq!(next.control.1, Command::Restart("backups".into()));
    }

    #[test]
    fn two_services_counting_down_are_separated_by_which_one_moves_first() {
        let mut snapshot = populated();
        snapshot.services[0].state = ServiceState::Backoff { retry_in_secs: 9, attempt: 1 };
        let next = next_move(&snapshot).expect("two services in backoff");
        assert_eq!(next.headline, "mongod retries in 9s");
        assert_eq!(next.detail, "attempt 1 · 2 more waiting");
    }

    #[test]
    fn a_stalled_service_is_surfaced_once_nothing_is_scheduled() {
        // With the countdown gone, the one thing left waiting is waiting on a
        // person — and what the block adds over the condition line is the
        // reason and the button, not the name.
        let mut snapshot = populated();
        snapshot.services.retain(|service| !matches!(service.state, ServiceState::Backoff { .. }));
        let next = next_move(&snapshot).expect("a service that cannot start");
        assert_eq!(next.headline, "a-service-with-a-very-long-name cannot start");
        assert_eq!(next.detail, "no such file or directory");
        assert_eq!(next.control.1, Command::Start("a-service-with-a-very-long-name".into()));
    }

    #[test]
    fn a_machine_with_nothing_outstanding_states_no_next_move() {
        // The block is absent rather than saying so. A strip that reports when
        // it has nothing to report is a strip nobody reads.
        let mut snapshot = populated();
        snapshot.services.retain(|service| service.state.is_live());
        assert!(next_move(&snapshot).is_none());
        assert!(next_move(&Snapshot::default()).is_none());
    }

    #[test]
    fn nothing_is_claimed_about_a_machine_that_is_not_answering() {
        // A countdown read off a poll that failed is not merely stale. It goes
        // on counting down convincingly while nothing at all is happening.
        let mut snapshot = populated();
        snapshot.link = Link::Lost("connection refused".into());
        assert!(next_move(&snapshot).is_none());

        snapshot.link = Link::Connected;
        snapshot.tunnel = Some(Tunnel::Broken { reason: "denied".into(), advice: None });
        assert!(next_move(&snapshot).is_none());
    }

    #[test]
    fn the_next_move_acts_on_the_service_it_names_and_not_on_the_selected_one() {
        // The one control in the window that is about a service the operator
        // did not choose, which is the whole point of surfacing it.
        let mut console = console(populated());
        let next = next_move(&console.snapshot()).expect("something outstanding");
        let block = upcoming(next);
        let control = block.child(3).expect("the control at the end of the block");
        (control.click_action().expect("the control is clickable"))(&mut console);

        let snapshot = console.snapshot();
        assert_eq!(snapshot.selected.as_deref(), Some("levelup-api"), "the selection is untouched");
        assert_eq!(snapshot.commands.front(), Some(&Command::Restart("backups".into())));
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

        let mut form_editing = console(busy());
        {
            let spec = form_editing.snapshot().spec.clone().expect("busy carries a definition");
            form_editing.form_mut().open_edit(&spec);
        }

        let mut announcing = busy();
        announcing.report_problem("mongod would not start");
        announcing.tunnel = Some(Tunnel::Broken {
            reason: "ssh: connect to host example.com port 22: Connection refused".into(),
            advice: Some("Check that the server is reachable.".into()),
        });

        vec![
            ("a console watching a service", console(busy()), (980.0, 680.0)),
            ("a console that has not connected", console(Snapshot::default()), (980.0, 680.0)),
            // The one screen with a sweep on it rather than a lamp, so that the
            // mark which replaces the lamp is audited for saying what the lamp
            // said.
            ("a console opening a tunnel", console(reaching()), (980.0, 680.0)),
            ("a console announcing a failure", console(announcing), (980.0, 680.0)),
            ("the install form", form_open, (980.0, 680.0)),
            ("the form editing a service", form_editing, (980.0, 680.0)),
            ("the smallest window the backend allows", console(busy()), (560.0, 420.0)),
        ]
    }

    #[test]
    fn every_screen_is_reachable_named_and_ordered() {
        for (name, console, (width, height)) in screens() {
            println!("auditing {name}");
            // Through the console's own application, so what is audited is the
            // window as it is actually built rather than the same tree under the
            // library's default theme.
            let mut harness =
                Harness::with_app(application("selfhost", console)).size(width, height);
            harness.assert_accessible();
            harness.assert_tab_order();
        }
    }

    #[test]
    fn the_rail_is_a_list_whose_chosen_row_says_so_without_relying_on_its_colour() {
        let mut harness = Harness::with_app(application("selfhost", console(busy())))
            .size(980.0, 680.0);
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
        let mut harness =
            Harness::with_app(application("selfhost", console(announcing))).size(980.0, 680.0);
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

    #[test]
    fn the_window_moves_only_while_something_is_in_flux() {
        // What a loop costs: a frame that asks for one asks for another, so a
        // console watching a machine with nothing outstanding has to be able to
        // stop drawing. The two marks allowed a loop — the sweep while a link is
        // being made, and the pulse under a lamp that wants attention — are
        // therefore the two states this may be true in, and no others.
        let mut settled = Snapshot { link: Link::Connected, ..populated() };
        settled.services.retain(|service| service.state.is_live());
        settled.selected = None;

        let mut idle = Harness::with_app(application("selfhost", console(settled)));
        idle.frame();
        assert!(!idle.is_animating(), "a healthy machine must let the window idle");

        let mut sweeping = Harness::with_app(application("selfhost", console(reaching())));
        sweeping.frame();
        assert!(sweeping.is_animating(), "a link being made is drawn going round");

        let mut pulsing = Harness::with_app(application("selfhost", console(populated())));
        pulsing.frame();
        assert!(pulsing.is_animating(), "a service that wants attention pulses");
    }

    /// A console that has not reached the daemon yet: `ssh` is still opening.
    ///
    /// The one state the window animates in — the masthead sweeps instead of
    /// lamping — which makes it the one worth auditing and photographing apart
    /// from the state it becomes a moment later.
    fn reaching() -> Snapshot {
        Snapshot { tunnel: Some(Tunnel::Opening), ..Snapshot::default() }
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

        // Each state once, rather than each state in two appearances: the
        // console supplies its own palette and draws the same instrument under
        // either desktop, so a second pass would have written the same picture
        // beside itself under a name claiming it was different. What the room
        // freed pays for is the states that were missing — a link being made,
        // and a machine that is up but counting down to a retry.
        std::fs::create_dir_all(format!("{directory}/web"))
            .expect("the frame directory should be writable");
        let mut written = |name: &str, snapshot: Snapshot, prepare: fn(&mut Console), size: (u32, u32)| {
            let mut console = console(snapshot);
            prepare(&mut console);
            let mut app = application("selfhost", console);
            // Twice, at both densities a reader actually has: the 2× original
            // for pixel-level inspection, and a true 1× rasterisation in web/
            // small enough to embed where the original is past a size limit —
            // a real render at each density, never one image resampled into
            // the other's.
            for (scale, path) in [
                (2.0, format!("{directory}/{name}.png")),
                (1.0, format!("{directory}/web/{name}.png")),
            ] {
                let canvas = app.render(size.0, size.1, scale, Appearance::Dark, &mut fonts);
                let pixels = rui::image::rgba(&canvas);
                let png = rui::image::png(canvas.width(), canvas.height(), &pixels)
                    .expect("a frame should encode");
                std::fs::write(&path, png).expect("the directory should be writable");
                println!("wrote {path}");
            }
        };

        written("console", busy(), |_| {}, (1000, 660));
        written("install", busy(), |console| console.form_mut().open_blank(), (1000, 660));
        // The form as Edit opens it: filled from the fetched definition, with
        // the readback stating the exact invocation. The blank form cannot
        // show either — an empty program is no claim about what will run.
        written(
            "install-edit",
            busy(),
            |console| {
                let spec = console.snapshot().spec.clone().expect("busy carries a definition");
                console.form_mut().open_edit(&spec);
            },
            (1000, 660),
        );
        written("console-narrow", busy(), |_| {}, (560, 420));
        written("console-empty", Snapshot::default(), |_| {}, (1000, 660));
        written("console-alarmed", alarmed, |_| {}, (1000, 660));
        written("console-reaching", reaching(), |_| {}, (1000, 660));

        // What a frame costs, at the sizes the window is actually used at. The
        // glyph cache is warmed first: the first frame at a new size rasterises
        // every glyph in it, and that is a start-up cost rather than a frame's.
        let mut app = application("selfhost", console(busy()));
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

