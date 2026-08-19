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

mod desktop;
mod detail;
mod exposure;
pub(crate) mod files;
mod install;
mod lock;
mod machines;
mod people;
mod style;

use crate::channel::{Live, Session};
use crate::gate::Latch;
use crate::machines::{Machine, Machines};
use crate::nas;
use crate::remote::{self, ControlRefusal};
use crate::session::{self, Bound, Connector, Credential, Link as MachineLink, Pairing, Place, Target};
use crate::state::{Command, FileAction, Link, NoticeKind, Screen, Snapshot, Tunnel};
use machines::PairForm;
use files::FilesForm;
use install::InstallForm;
use rui::style::Justify;
use rui::{
    Align, App, Drag, El, Key, KeyStroke, Modifiers, Phase, Point, Pointing, Redraw, Role, Status,
    Tone, button, caption, col, figure, heading, micro, paragraph, row, spacer, tabs, text, title,
};
use selfhost_desk::wire::{Button, Message};
use selfhost_supervisor::state::{ServiceState, ServiceStatus};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

/// The margin the whole window is inset by.
///
/// Named because it is also an assertion: nothing the console draws may reach
/// into it, and a test says so — see
/// `nothing_on_a_new_screen_is_drawn_outside_the_page`.
const PAGE_PAD: f32 = 16.0;

/// How far one notch of a wheel turns the far machine's.
///
/// The desktop wire counts in 1/120ths of a notch, which is what Windows'
/// `WHEEL_DELTA` counts in and what every platform's high-resolution scrolling
/// is reported against. `rui` reports whole lines, so one line is one notch.
const NOTCH: f32 = 120.0;

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

// A quiet row's state word stands whole or is not drawn — `.whole()` in
// [`service_row`], no floor constant left to tune. The old trade squeezed the
// word to a floor and let it say the rest with an ellipsis, and the accepted
// cost was a selected narrow row reading `RUNNI…` — a fact half-deleted on
// exactly the row being looked at. The word's whole meaning is already said
// twice by the lamp, in a hue and in a fill, so when the line runs short the
// honest options are the word entire or the lamp alone; the layout now offers
// exactly those two. A red word is the one exception, argued at
// [`ALARM_UNIT`]: it is a summons, it never yields, and the name is the payer.

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
    /// What the open machine's threads write into, and this window reads.
    ///
    /// Replaced — not written through — when the operator changes machines: the
    /// new link brings its own, and the old one's threads keep writing into a
    /// snapshot nobody reads any more. See [`crate::session`].
    shared: Arc<Mutex<Snapshot>>,
    /// Which machine this window is showing, at what address, over what.
    bound: Bound,
    /// Where the operator is standing: on the machine, or above it.
    place: Place,
    /// Every machine paired on this computer, as the store last read.
    machines: Machines,
    /// Where that store lives, or `None` on an account with no home directory.
    store: Option<PathBuf>,
    /// The form on the overview that adds a machine.
    pair_form: PairForm,
    /// Where the console is talking and with what, behind the connector.
    ///
    /// `None` in a console that was never given a link — every frame test, and
    /// every reference frame.
    target: Option<Arc<Mutex<Target>>>,
    /// The threads keeping the open machine's connection up.
    link: Option<MachineLink>,
    /// Links told to stop, kept until their threads have noticed.
    ///
    /// A switch does not wait for the old threads: one may be half-way through
    /// a request that has yet to time out, and stalling the window on it would
    /// make changing machines feel like the program had hung. They are held
    /// rather than detached so that a window closing still joins them — a
    /// detached tunnel thread whose `ssh` outlives the process is a forward left
    /// open on somebody's machine.
    retiring: Vec<MachineLink>,
    form: InstallForm,
    /// The one text field the FILES plate uses, and what it is for.
    files_form: FilesForm,
    /// How to build a client, for the one thing that opens its own socket.
    ///
    /// `None` in a test, and in a console that has not been given one, so every
    /// frame test in this file draws without a daemon — which is what makes the
    /// reference frames producible on a machine with nothing running.
    connect: Option<Connector>,
    /// The handle that lets a stream ask for a frame.
    ///
    /// Set after the [`App`] is built, because the handle comes from it. A
    /// console with none can still draw everything; it simply cannot open a
    /// desktop session, which is exactly the state a frame test is in.
    redraw: Option<Redraw>,
    /// The desktop session, when one is open.
    session: Option<Session>,
    /// Why the last attempt to open one was refused, in its structured form.
    control_trouble: Option<ControlRefusal>,
    /// Whether the keyboard is aimed at the viewport.
    ///
    /// Held here rather than read from `rui`'s own focus, because what this
    /// decides is whether keys leave this machine — and that must be a fact the
    /// console owns, set by a press on the picture and cleared by the pointer
    /// leaving it, rather than something inferred from a focus ring.
    viewport_focus: bool,
    /// The modifier state last sent to the far machine.
    ///
    /// Diffed against every arriving keystroke, because neither platform
    /// delivers a modifier as an ordinary key event — see
    /// [`crate::remote::modifier_changes`], which is where the argument is.
    held: Modifiers,
    /// The last pixel of the far screen this console aimed its pointer at.
    ///
    /// Kept so that a movement naming the pixel already under the far pointer
    /// is not sent again — see [`Console::aim_far_pointer`]. It belongs to a
    /// session and to one display within it, so it is cleared whenever either
    /// changes: a remembered point from another screen would suppress the first
    /// real movement on this one.
    aimed: Option<(i32, i32)>,
    /// Whether a person has been proved to be at this computer.
    ///
    /// Held by the console rather than by the link, so that opening a second
    /// machine does not raise a second sheet: what was proved is that somebody is
    /// here, not that they are here for one particular server. [`Console::lock`]
    /// clears it, and every link opened afterwards finds it shut. See
    /// [`crate::gate`].
    proof: Arc<Latch>,
    /// The tunnel the open link is managed over, kept so it can be opened again.
    ///
    /// A relock is not a teardown: it stops the link and opens the same one
    /// afresh, which is what puts the gate back in front of it. That needs the
    /// spec the link was built with, and this is where it is kept.
    spec: Option<crate::tunnel::TunnelSpec>,
    /// Whether the window is filling the screen.
    ///
    /// Written by the person, through [`Console::toggle_full_screen`], and by
    /// the window itself through the binding in [`application`] — the green
    /// button and Control-Command-F both go around this program. One fact and
    /// not two, so the layout and the window cannot come to disagree about
    /// whether there is a title bar on screen. See [`desktop::stage`].
    full_screen: bool,
}

impl Console {
    /// A console drawing `shared`, pointed at whatever `bound` describes.
    ///
    /// It has no link of its own: nothing is polled, no tunnel is opened, and
    /// no daemon can be reached. That is what every frame test and every
    /// reference frame is built with, which is why they can be drawn on a
    /// machine with nothing running.
    pub fn showing(shared: Arc<Mutex<Snapshot>>, bound: Bound) -> Self {
        Self {
            shared,
            bound,
            place: Place::default(),
            machines: Machines::default(),
            store: None,
            pair_form: PairForm::default(),
            target: None,
            link: None,
            retiring: Vec::new(),
            form: InstallForm::default(),
            files_form: FilesForm::default(),
            connect: None,
            redraw: None,
            session: None,
            control_trouble: None,
            viewport_focus: false,
            held: Modifiers::default(),
            aimed: None,
            proof: Latch::shut(),
            spec: None,
            full_screen: false,
        }
    }

    /// A console that knows what is paired on this computer, showing nothing yet.
    ///
    /// [`Console::open`] is what gives it a machine. Splitting the two is what
    /// lets the window be built before anything connects — and it is the same
    /// path a switch takes later, so the launch case cannot work while the
    /// switch case rots.
    pub fn paired(machines: Machines, store: Option<PathBuf>) -> Self {
        let mut console = Self::showing(
            Arc::new(Mutex::new(Snapshot::default())),
            Bound::new(
                "127.0.0.1:9191".parse().expect("the default address is valid"),
                None,
            ),
        );
        console.machines = machines;
        console.store = store;
        // A console with no link has nothing behind a lock: no token has been
        // read, no tunnel exists and no daemon is being polled. Standing a lock
        // in front of *this* snapshot would be a door with nothing behind it —
        // and worse, an unopenable one, because the thread that answers UNLOCK is
        // the link's own gate and there is no link. Every link brings a snapshot
        // of its own, created shut. See [`crate::gate`].
        console.with_snapshot(|snapshot| snapshot.lock.state = crate::state::LockState::Open);
        // Said once, because nothing else will ever say it: a console with no
        // machine has no poller to report a link, so a snapshot left at its
        // default would claim it was connecting to an address nothing is
        // dialling. [`Console::open`] brings a fresh snapshot with it, so this
        // survives exactly as long as it is true.
        if console.machines.is_empty() {
            console.with_snapshot(|snapshot| snapshot.link = crate::state::Link::Unpaired);
        }
        console
    }

    /// Opens a connection, closing whatever was open before it.
    ///
    /// The one path onto a machine, taken by the launch and by every switch
    /// afterwards. The desktop session goes with the old machine — a ticket
    /// names the machine it was minted for — and the new link's snapshot
    /// replaces the old one wholesale, so nothing of the previous machine is
    /// left on screen to be read as this one's.
    pub fn open(&mut self, bound: Bound, target: Target, spec: Option<crate::tunnel::TunnelSpec>) {
        self.retire_link();
        let target = Arc::new(Mutex::new(target));
        let connect = session::connector(&target);
        let link = MachineLink::open(spec.clone(), Arc::clone(&connect), Arc::clone(&self.proof));
        self.shared = link.snapshot();
        self.spec = spec;
        self.target = Some(target);
        self.connect = Some(connect);
        self.link = Some(link);
        if let Some(name) = bound.machine.clone() {
            self.remember_opened(&name);
        }
        self.bound = bound;
        self.place = Place::Machine;
    }

    /// Stops the open link without waiting for its threads.
    ///
    /// Finished ones are dropped on the way past, so the list holds only what is
    /// still stopping and a long session does not accumulate handles.
    fn retire_link(&mut self) {
        self.close_session();
        self.retiring.retain(|link| !link.finished());
        if let Some(link) = self.link.take() {
            link.closing();
            self.retiring.push(link);
        }
    }

    /// Shuts the console, and opens the same connection again behind the lock.
    ///
    /// A relock is deliberately not a disconnection-and-forget: the machine on
    /// screen is still the machine this window is for, and being asked to prove
    /// somebody is here should not also cost the operator the machine they were
    /// on. So the latch is cleared and the link is opened afresh — and the link's
    /// own gate is what stands in front of it, exactly as it did at launch. The
    /// threads of the old one are stopped on the way past, so nothing carries on
    /// polling behind the plate.
    ///
    /// Does nothing on a console with no link. There is no connection to shut and
    /// no gate thread to answer UNLOCK, so a lock here would be one nothing could
    /// open — see [`Console::paired`].
    pub(crate) fn lock(&mut self) {
        let Some(connect) = self.connect.clone() else { return };
        self.proof.close();
        self.retire_link();
        let link = MachineLink::open(self.spec.clone(), connect, Arc::clone(&self.proof));
        self.shared = link.snapshot();
        self.link = Some(link);
    }

    /// Asks the gate to raise the system's sheet again.
    ///
    /// What UNLOCK does. The flag is taken by [`crate::gate`]'s own thread, which
    /// is the only thing that can raise a sheet — the window neither asks nor
    /// waits, so a person holding a mouse button down cannot queue up a second
    /// one behind the first.
    pub(crate) fn ask_again(&mut self) {
        self.with_snapshot(|snapshot| snapshot.lock.asked_again = true);
    }

    /// Where the lock is, for the plate that draws it.
    pub(crate) fn lock_state(&self) -> crate::state::Lock {
        self.snapshot().lock.clone()
    }

    /// Every machine paired on this computer, for the overview to draw.
    pub(crate) fn machines(&self) -> &Machines {
        &self.machines
    }

    /// Which machine this window is on, at what address, over what.
    pub(crate) fn bound(&self) -> &Bound {
        &self.bound
    }

    /// Where the operator is standing.
    pub(crate) fn place(&self) -> Place {
        self.place
    }

    /// The pairing form, for the plate that draws it.
    pub(crate) fn pair_form(&self) -> &PairForm {
        &self.pair_form
    }

    /// The same, to be edited by whatever was just typed.
    pub(crate) fn pair_form_mut(&mut self) -> &mut PairForm {
        &mut self.pair_form
    }

    /// Steps back to the list of machines.
    ///
    /// The link is left up. Standing above a machine is not leaving it: the
    /// poller keeps its snapshot current, so stepping back in finds the plates
    /// as they would have been rather than as they were, and a desktop session
    /// is not torn down by looking away from it for a moment.
    pub(crate) fn show_overview(&mut self) {
        // Read from disk rather than from memory, because the file is the truth:
        // a pairing made from this window is written by whichever thread first
        // proved the connection, and a machine paired by another console — or
        // by the command line — belongs on this list too.
        if let Some(path) = &self.store {
            if let Ok(paired) = Machines::load(path) {
                self.machines = paired;
            }
        }
        self.place = Place::Overview;
    }

    /// Steps back onto the machine this window is bound to.
    pub(crate) fn show_machine(&mut self) {
        self.place = Place::Machine;
    }

    /// Opens a machine already paired here, closing whatever was open.
    pub(crate) fn open_machine(&mut self, name: &str) {
        let Some(machine) = self.machines.get(name).cloned() else {
            self.with_snapshot(|snapshot| {
                snapshot.report_problem(format!("{name:?} is no longer paired on this computer."))
            });
            return;
        };
        self.open_paired(&machine, None);
    }

    /// Opens a paired machine, optionally saving it once it answers.
    fn open_paired(&mut self, machine: &Machine, pair: Option<Pairing>) {
        let spec = machine.tunnel();
        let target = Target::new(
            spec.local_address(),
            Credential::OverSsh {
                spec: spec.clone(),
                path: machine.remote_token.clone(),
                pair,
            },
        );
        self.open(Bound::of(machine), target, Some(spec));
    }

    /// Validates the pairing form and opens what it describes.
    ///
    /// **The store is not written here.** A pairing is a connection that has
    /// worked at least once, and nothing at this point has proved that one does
    /// — so the machine is opened carrying a note that saves it the moment a
    /// token actually arrives from it, on whichever thread gets one. A machine
    /// that never answers is therefore never written down, and the window says
    /// why in the words `ssh` used.
    pub(crate) fn submit_pair_form(&mut self) {
        let machine = match self.pair_form.submit() {
            Ok(machine) => machine,
            Err(problems) => {
                self.pair_form.trouble = problems;
                return;
            }
        };
        if self.store.is_none() {
            self.pair_form.trouble =
                vec!["this account has no home directory, so nothing can be paired".into()];
            return;
        }
        let pairing =
            self.store.clone().map(|store| Pairing { store, machine: machine.clone() });
        self.pair_form.close();
        self.open_paired(&machine, pairing);
    }

    /// Forgets a pairing, here and in the file.
    ///
    /// A machine that is open stays open — closing somebody's session because
    /// they tidied the list would be a surprise, and the window still says what
    /// it is connected to.
    pub(crate) fn forget_machine(&mut self, name: &str) {
        self.machines.forget(name);
        let Some(path) = &self.store else { return };
        if let Err(reason) = self.machines.save(path) {
            self.with_snapshot(|snapshot| snapshot.report_problem(reason));
        }
    }

    /// Records which machine is open, without letting that failure stop it.
    ///
    /// Best effort by design: the console is already connecting by the time this
    /// runs, and refusing to show a working machine because a note could not be
    /// written would trade the whole session for a preference.
    fn remember_opened(&mut self, name: &str) {
        let Some(path) = self.store.clone() else { return };
        let Ok(mut paired) = Machines::load(&path) else { return };
        paired.opened(name);
        if let Err(reason) = paired.save(&path) {
            eprintln!("selfhost-console: could not record which machine was open: {reason}");
        }
    }

    /// Opens the window and runs until it is closed.
    ///
    /// There is no second way out and no flag saying so. The window closing —
    /// by its own button, or by a Quit that `rui` turns into one — is what ends
    /// the loop, and returning from here is what runs this console's own
    /// destructor: the links are stopped and joined there, so nothing is left
    /// holding a forwarded port. An `AtomicBool` shutting the application down
    /// used to live here and was a predicate nothing ever cleared.
    pub fn run(self, title: String) -> Result<(), rui::Error> {
        let mut app = application(title, self)
            .size(980.0, 680.0)
            .min_size(560.0, 420.0)
            .idle_timeout(IDLE_REDRAW);
        // The handle exists only once there is a loop to ask for a frame, so it
        // is handed to the console here rather than at construction.
        let redraw = app.redraw();
        app.state_mut().redraw = Some(redraw);
        app.run()
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

    /// Opens a different screen, and tells the poller which one.
    ///
    /// The snapshot carries it as well as the console because that is what
    /// decides which routes are asked for — see [`Screen`]. Written in both
    /// places by this one method, so they cannot disagree.
    pub(crate) fn show(&mut self, screen: Screen) {
        // Leaving the desktop takes the keyboard with it. A window whose FILES
        // plate is open must not still be typing on somebody's machine.
        if screen != Screen::Desktop {
            self.release_far_keys();
        }
        self.with_snapshot(|snapshot| snapshot.screen = screen);
    }

    /// The FILES plate's field, for the pane that draws it.
    pub(crate) fn files_form(&self) -> &FilesForm {
        &self.files_form
    }

    /// The same field, to be edited by whatever was just typed or pressed.
    pub(crate) fn files_form_mut(&mut self) -> &mut FilesForm {
        &mut self.files_form
    }

    /// Validates the FILES field and asks for what it describes.
    ///
    /// The refusal stays on the form rather than becoming a notice, because it
    /// is about the thing still being typed: a notice would appear at the top of
    /// the window while the operator is looking at the bottom of it.
    pub(crate) fn submit_files_form(&mut self) {
        let (share, directory, selected) = {
            let snapshot = self.snapshot();
            (
                snapshot.files.share.clone(),
                snapshot.files.path.clone(),
                snapshot.files.selected.clone(),
            )
        };
        let Some(share) = share else {
            self.files_form.trouble = Some("Choose a share first.".into());
            return;
        };
        match self.files_form.submit(&share, &directory, selected.as_deref()) {
            Ok(command) => {
                self.files_form.close();
                self.request(command);
            }
            Err(reason) => self.files_form.trouble = Some(reason),
        }
    }

    /// Asks for one file to be copied out of the share.
    ///
    /// The destination is not asked for: this window has no file picker to open
    /// — the platform dialogue is one unsafe call per backend and `rui` has none
    /// — so a download lands beside the operator, in their downloads folder if
    /// there is one and their home if there is not, and the notice says exactly
    /// where. Silently choosing a path and *not* saying which would be the worse
    /// half of the same trade.
    pub(crate) fn download(&mut self, path: &str) {
        let (share, size) = {
            let snapshot = self.snapshot();
            let Some(share) = snapshot.files.share.clone() else {
                return;
            };
            let size = snapshot
                .files
                .listing()
                .and_then(|listing| {
                    listing.entries.iter().find(|entry| entry.path.as_deref() == Some(path))
                })
                .map_or(0, |entry| entry.size);
            (share, size)
        };
        // Refused before it is asked for, not while it is arriving. This client
        // holds a body whole, so a hundred-gigabyte film is an allocation that
        // fails — and under `panic = "abort"` a failed allocation is the console
        // going away rather than an error a person can read.
        if size > nas::MAX_TRANSFER {
            self.with_snapshot(|snapshot| {
                snapshot.report_problem(format!(
                    "This console downloads files up to {} at a time; that one is {}.                      Reach the share over SMB or WebDAV for anything larger.",
                    nas::size_text(nas::MAX_TRANSFER),
                    nas::size_text(size)
                ));
            });
            return;
        }
        let Some(name) = nas::path_segments(path).last().map(|name| name.to_string()) else {
            return;
        };
        let to = downloads_directory().join(name);
        self.request(Command::Files {
            share,
            action: FileAction::Download { path: path.to_owned(), to },
        });
    }

    /// Asks for one name to be removed.
    pub(crate) fn delete_entry(&mut self, path: &str) {
        let Some(share) = self.snapshot().files.share.clone() else {
            return;
        };
        self.request(Command::Files {
            share,
            action: FileAction::Delete { path: path.to_owned() },
        });
    }

    /// What the desktop session is doing, or `None` when there is none.
    pub(crate) fn session_live(&self) -> Option<Live> {
        self.session.as_ref().map(Session::live)
    }

    /// Whether the open session asked the daemon for a keyboard.
    ///
    /// The difference between this and [`Live::may_control`] is the sentence
    /// worth showing: a ticket can be minted for control and then *downgraded*
    /// between the mint and the handshake, and the agent's `Hello` is what says
    /// so. A console that only read what was granted would draw that as an
    /// ordinary watching session and leave the operator wondering why their
    /// keys do nothing.
    pub(crate) fn session_asked_for_control(&self) -> bool {
        self.session.as_ref().is_some_and(Session::asked_for_control)
    }

    /// Why the last attempt at a keyboard was refused.
    ///
    /// Read from the session first, because the daemon's refusal arrives on the
    /// stream thread after the press that asked for it has already returned.
    pub(crate) fn control_trouble(&self) -> Option<ControlRefusal> {
        self.session
            .as_ref()
            .and_then(|session| session.live().control_refusal)
            .or_else(|| self.control_trouble.clone())
    }

    /// The picture and the size cell the viewport draws through.
    pub(crate) fn viewport_handles(&self) -> Option<desktop::ViewportHandles> {
        let session = self.session.as_ref()?;
        Some((session.picture_handle(), session.fit_handle()))
    }

    /// Whether the keyboard is aimed at the viewport.
    pub(crate) fn viewport_has_keys(&self) -> bool {
        self.viewport_focus
    }

    /// Points the keyboard at the viewport.
    pub(crate) fn aim_at_viewport(&mut self) {
        self.viewport_focus = true;
    }

    /// Whether the window is filling the screen.
    pub(crate) fn full_screen(&self) -> bool {
        self.full_screen
    }

    /// Asks the window to fill the screen, or to stop.
    ///
    /// What a control in the interface presses. The window is not touched here
    /// — this console has none to touch — so the flag is a *request* until the
    /// binding in [`application`] carries it out; a platform that refuses puts
    /// it straight back, which is why nothing else is allowed to depend on the
    /// two having changed together.
    pub(crate) fn toggle_full_screen(&mut self) {
        self.full_screen = !self.full_screen;
    }

    /// Writes down that the window is, or is no longer, filling the screen.
    ///
    /// For the platform's own way in: the green button on macOS, a window
    /// manager's key, or Escape out of a full screen — none of which this
    /// program is asked about first.
    pub(crate) fn set_full_screen(&mut self, filling: bool) {
        self.full_screen = filling;
    }

    /// Watches a different machine, closing whatever session is open.
    ///
    /// A session belongs to the machine it was minted for — the ticket names it
    /// — so changing the machine cannot carry one over. Closing rather than
    /// re-opening is deliberate: the new machine may be one this credential may
    /// watch and not drive, and silently opening a session with whatever the
    /// last one asked for would be this console choosing an authorisation.
    pub(crate) fn watch_machine(&mut self, node: &str) {
        if self.snapshot().desk.peer.as_deref() == Some(node) {
            return;
        }
        self.close_session();
        let node = node.to_owned();
        self.with_snapshot(|snapshot| {
            snapshot.desk.peer = Some(node);
            snapshot.desk.agent = None;
        });
    }

    /// Opens a session on the chosen machine, asking for a keyboard or not.
    ///
    /// **The keyboard is a separate mint and this is the only way to it.** A
    /// session opened without `control` is a session that cannot be upgraded:
    /// asking for one closes this and opens another, which the daemon decides
    /// against its own freshness rule. That is the browser's behaviour, and it
    /// is not relaxed here.
    pub(crate) fn open_session(&mut self, control: bool) {
        self.close_session();
        self.control_trouble = None;
        let Some(peer) = self.snapshot().desk.peer.clone() else {
            self.with_snapshot(|snapshot| snapshot.report_problem("Choose a machine first."));
            return;
        };
        let (Some(connect), Some(redraw)) = (self.connect.clone(), self.redraw.clone()) else {
            self.with_snapshot(|snapshot| {
                snapshot.report_problem("This console was opened without a way to reach a daemon.");
            });
            return;
        };
        match connect() {
            Ok(client) => self.session = Some(Session::open(client, &peer, control, redraw)),
            Err(reason) => self.with_snapshot(|snapshot| snapshot.report_problem(reason)),
        }
    }

    /// Closes whatever session is open, releasing the far machine's keys.
    pub(crate) fn close_session(&mut self) {
        self.release_far_keys();
        self.aimed = None;
        // Dropping is what stops the thread: the flag is cleared and the read
        // deadline expires, so the daemon does not keep a place in its ceiling
        // for a viewer that has gone.
        self.session = None;
    }

    /// Asks the far machine for a whole frame rather than a difference.
    pub(crate) fn request_full_frame(&self) {
        if let Some(session) = &self.session {
            session.request_full_frame();
        }
    }

    /// Watches a different display of the same machine.
    ///
    /// The remembered aim goes with it: a pixel of the display just left names
    /// a different place on this one, and holding it would swallow the first
    /// movement made here.
    pub(crate) fn watch_monitor(&mut self, monitor: u8) {
        self.aimed = None;
        if let Some(session) = &self.session {
            session.watch(monitor);
        }
    }

    /// Lets go of every key and modifier the far machine is holding for us.
    pub(crate) fn release_far_keys(&mut self) {
        self.viewport_focus = false;
        self.held = Modifiers::default();
        if let Some(session) = &self.session {
            session.release_all();
        }
    }

    /// Puts the far machine's pointer where a position within the viewport
    /// says, and answers whether this session is taking input at all.
    ///
    /// The one place a [`Message::PointerMove`] is sent, so the two handlers
    /// that produce one — a hand moving over the picture, and a button being
    /// dragged across it — cannot come to disagree about where the far pointer
    /// is. The fraction is turned into a pixel of the *far* screen by
    /// [`Picture::remote_point`], which is the only thing that knows how the
    /// arriving frame was fitted into this pane.
    ///
    /// Repeats are dropped. A pane a third the width of the screen it shows
    /// maps three of this machine's pixels onto one of theirs, so a hand moving
    /// slowly produces frame after frame naming the same far pixel — and every
    /// one of them would be a message on a socket to say nothing changed. What
    /// is remembered is the point actually sent, so the next different one is
    /// sent whatever happened in between.
    ///
    /// [`Picture::remote_point`]: crate::channel::Picture::remote_point
    fn aim_far_pointer(&mut self, fraction: Point) -> bool {
        let Some(session) = &self.session else {
            return false;
        };
        let live = session.live();
        if !desktop::forwards_keys(&live, self.viewport_focus) {
            return false;
        }
        let Some(point) = session.picture().remote_point(fraction.x, fraction.y) else {
            return false;
        };
        if self.aimed != Some(point) {
            session.send(Message::PointerMove { monitor: live.monitor, x: point.0, y: point.1 });
        }
        self.aimed = Some(point);
        true
    }

    /// Follows a hand moving over the picture, with nothing pressed.
    ///
    /// The far pointer tracks this one exactly as the browser's does. It is a
    /// separate handler from [`Console::forward_pointer`] rather than a phase of
    /// it because the two answer different questions: a drag is a *gesture*,
    /// which continues wherever the pointer goes and so must be reported even
    /// once it has left the picture, while this is simply where the pointer is
    /// and stops at the edge of the pane — a hand moving off the viewport and
    /// across this window's own controls is not still pointing at the far
    /// machine.
    pub(crate) fn point_at(&mut self, pointing: Pointing) {
        self.aim_far_pointer(pointing.fraction());
    }

    /// Sends one pointer press, drag or release to the far machine.
    ///
    /// The press and the release are the whole of what this adds over
    /// [`Console::point_at`]: the position under a held button travels the same
    /// path every other position does, so a click lands where the picture says
    /// it will.
    pub(crate) fn forward_pointer(&mut self, drag: Drag) {
        if !self.aim_far_pointer(drag.fraction()) {
            return;
        }
        let Some(session) = &self.session else {
            return;
        };
        match drag.phase {
            Phase::Began => session.send(Message::Button { button: Button::Left, down: true }),
            Phase::Moved => {}
            Phase::Ended => session.send(Message::Button { button: Button::Left, down: false }),
        }
    }

    /// Sends one physical key movement, and whatever modifiers changed with it.
    ///
    /// The modifiers go first on a press and last on a release, which is the
    /// order a keyboard produces them in and the order the far machine has to
    /// see them in for `Shift+A` to be a capital rather than an `a` and a
    /// shift. A key with no position is dropped: `Usage` is a *physical*
    /// vocabulary, and a synthesized keystroke with no code names no key another
    /// machine could be told about.
    pub(crate) fn forward_key(&mut self, stroke: KeyStroke) {
        let driving = self
            .session
            .as_ref()
            .is_some_and(|session| desktop::forwards_keys(&session.live(), self.viewport_focus));
        if desktop::leaves_full_screen(stroke, self.full_screen, driving) {
            self.full_screen = false;
            return;
        }
        let Some(session) = &self.session else {
            return;
        };
        if !driving {
            return;
        }
        for (usage, down) in remote::keystroke_messages(self.held, stroke) {
            session.send(Message::Key { usage, down });
        }
        self.held = stroke.modifiers;
    }

    /// Sends one turn of the wheel.
    pub(crate) fn forward_scroll(&mut self, across: f32, down: f32) {
        let Some(session) = &self.session else {
            return;
        };
        if !desktop::forwards_keys(&session.live(), self.viewport_focus) {
            return;
        }
        let notches = |lines: f32| (lines * NOTCH).round().clamp(-120_000.0, 120_000.0) as i32;
        let (dx, dy) = (notches(across), notches(down));
        if dx != 0 || dy != 0 {
            session.send(Message::Scroll { dx, dy });
        }
    }
}

/// Where a download lands.
///
/// `~/Downloads` when there is one, the home directory when there is not, and
/// the working directory when even that cannot be found. Every step is a
/// directory that already exists rather than one this program creates: a console
/// that made a folder as a side effect of a download would be a console that
/// litters.
fn downloads_directory() -> std::path::PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from);
    let Some(home) = home else {
        return std::path::PathBuf::from(".");
    };
    let downloads = home.join("Downloads");
    if downloads.is_dir() { downloads } else { home }
}

/// The console as an application, drawn in the console's own theme.
///
/// One place, so that a frame drawn by a test is the frame the window shows.
/// The palette reaches every widget through [`rui::App::theme`] and nowhere
/// else, and an `App` built without it would be this same layout in the
/// library's own colours — which is a thing worth being unable to do by
/// accident. See [`style::theme`].
pub(crate) fn application(title: impl Into<String>, console: Console) -> App<Console> {
    App::new(title, console, view)
        .theme(style::theme)
        .ground(style::ground)
        // The one place the window's own state and the console's are tied
        // together. Both ends move it: FULL SCREEN and Escape from in here, the
        // green button and Control-Command-F from out there.
        .fullscreen(Console::full_screen, |console: &mut Console, filling| {
            console.set_full_screen(filling);
        })
}

/// The whole console, as one description.
///
/// # Four screens under one masthead
///
/// The masthead, the tunnel's complaint and the last command's notice are about
/// the *link* and are drawn on every screen, because a broken tunnel makes every
/// plate below it stale and a console that said so on only one of them would be
/// a console that lies on three.
///
/// Everything below the tabs belongs to one screen. The readout bank and the
/// exposure map stay on SERVICES, where they were: both are readings about the
/// supervised services, and carrying them onto a file browser would spend the
/// top fifth of that plate restating a fact about something else — the same
/// argument the bank itself makes about four cards for three numbers.
pub fn view(console: &Console) -> El<Console> {
    let snapshot = console.snapshot();
    let screen = snapshot.screen;

    // Before anything else, and returning before anything else is described. A
    // console whose lock is shut has connected to nothing, so there is no
    // masthead worth drawing — the link it would report is not being dialled —
    // and no plate under it holds a reading. See [`lock`].
    if !snapshot.lock.open() {
        drop(snapshot);
        return lock::view(console);
    }

    // A filled screen showing a machine's own screen is the far machine and
    // nothing else — no masthead, no tabs, no page margin. Only the DESKTOP
    // screen claims it: a window made full screen while a log is open is a
    // large window with a log in it, which is what its person asked for.
    if screen == Screen::Desktop && console.full_screen() && console.place == Place::Machine {
        drop(snapshot);
        return desktop::stage(console);
    }

    // Standing above the machines is a different place, not a fifth tab: the
    // tab row belongs to a machine, so it is absent here along with everything
    // under it. The masthead stays, because the link it reports is still up —
    // looking away from a machine does not disconnect it.
    if console.place == Place::Overview {
        drop(snapshot);
        return col((header(console, &console.snapshot()), machines::view(console)))
            .pad(PAGE_PAD)
            .gap(8.0);
    }

    col((
        header(console, &snapshot),
        screens(screen, snapshot.viewer.as_ref()),
        tunnel_banner(&snapshot).map(banner),
        snapshot.notice.clone().map(notice),
        match screen {
            Screen::Services => services(console, &snapshot),
            // The three new screens are drawn from the console rather than from
            // this borrow of the snapshot, so each takes its own: a plate that
            // needs the session as well as the snapshot cannot be handed a
            // guard this function is still holding.
            Screen::Files => {
                drop(snapshot);
                files::view(console)
            }
            Screen::Desktop => {
                drop(snapshot);
                desktop::view(console)
            }
            Screen::People => {
                drop(snapshot);
                people::view(console)
            }
        },
    ))
    .pad(PAGE_PAD)
    .gap(8.0)
}

/// The row of tabs naming the four screens.
///
/// Under the masthead and above everything else, which is where a person looks
/// for them and the one place they are not competing with a reading. The chosen
/// one is marked by a bar on a rule that runs the full width — the rule
/// separates the row from the page, not the tabs from each other.
fn screens(screen: Screen, viewer: Option<&crate::state::Viewer>) -> El<Console> {
    // The row is what this credential may open, not what the console can draw.
    // See `Screen::for_viewer`: a tab that answers 401 is a permission model
    // being discovered one refusal at a time.
    let open: Vec<Screen> = Screen::for_viewer(viewer);
    let labels: Vec<&str> = open.iter().map(|screen| screen.label()).collect();
    let chosen = open.iter().position(|candidate| *candidate == screen).unwrap_or(0);
    // The handler is a plain `Copy` closure, as every rui handler is, so the row
    // it dispatches through is a fixed array rather than the vector above.
    let mut row = [None; Screen::ALL.len()];
    for (slot, screen) in row.iter_mut().zip(open) {
        *slot = Some(screen);
    }
    tabs(&labels, chosen, move |console: &mut Console, index| {
        // A tab index that names no screen changes nothing, rather than falling
        // back to the first: an out-of-range index is a defect in this row, and
        // silently opening SERVICES would hide it.
        if let Some(Some(screen)) = row.get(index).copied() {
            console.show(screen);
        }
    })
}

/// The SERVICES screen: the bank, the exposure map, the rail and the pane.
fn services(console: &Console, snapshot: &Snapshot) -> El<Console> {
    col((
        bank(snapshot),
        // The exposure map is a full-width strip between the bank and the panes,
        // and only when the firewall is managed — it returns `None` otherwise, so
        // on the common unmanaged deployment it costs the log below it nothing.
        exposure::view(snapshot.firewall.as_ref()),
        row((rail(snapshot), pane(console, snapshot))).gap(8.0).grow(),
    ))
    .gap(8.0)
    .grow()
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
        connection_summary(snapshot, console.bound.address, console.bound.via.as_deref());
    let reaching =
        snapshot.link == Link::Connecting || matches!(snapshot.tunnel, Some(Tunnel::Opening));

    row((
        style::mark(),
        title("SELFHOST").tracking(WORDMARK).align_self(Align::Center).whole(),
        // The instrument's designation, in the voice a block label uses. A
        // wordmark alone names a product; a wordmark with what the instrument
        // *is* set quietly beside it names a machine's front panel, and the
        // masthead is the one strip in the window that is a panel rather than
        // a reading.
        //
        // It is the strip's payer, and it is the right one: it is the only
        // thing up here that reports nothing. When the window narrows past what
        // the mark, the name, the step control and the link state need, this
        // goes entirely rather than every one of them giving a syllable — a
        // masthead reading `SELFHO… SUPERVISOR CONS… ‹ MACHI… CONNECT…` is four
        // half-facts where there was room for three whole ones.
        heading("SUPERVISOR CONSOLE").tracking(1.8).align_self(Align::Center).whole(),
        // The one way between the two places, and the only control on the
        // masthead. It sits with the nameplate rather than beside the link mark
        // because it is about *which* machine, and the marks to its right are
        // about how that machine is.
        machines::step_control(console),
        style::rule(),
        style::link_mark(status, label.to_uppercase(), reaching),
        micro(detail).max_w(300.0).align_self(Align::Center),
        // The way out, beside the state of the connection it shuts. It is on the
        // masthead and not on a plate because it is about the whole window: what
        // it takes away is every plate at once, and a control that does that
        // belongs with the nameplate rather than inside one of the things it
        // closes.
        button("LOCK").on_click(|console: &mut Console| console.lock()).align_self(Align::Center),
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
                // Idle and not Bad: a console with nothing paired is not
                // broken, it is new. Empty is not the same fact as failed, and
                // the plate below it says what to do rather than what went
                // wrong.
                Link::Unpaired => (Status::Idle, "no machine"),
            };
            let detail = match (&snapshot.link, via) {
                (Link::Unpaired, _) => "nothing is paired on this computer yet".to_owned(),
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
    // Which face the gauge slot wears is a three-way fact, not a boolean: a
    // measured machine gets the reading, a machine not yet reached gets the
    // face with no reading on it (the share is unknown, not nought — see
    // [`style::gauge_unread`]), and a connected machine with nothing
    // installed gets nothing, exactly as `live_share` argues.
    let gauge = match live_share(snapshot) {
        Some(share) => Some(style::gauge(share)),
        None if !matches!(snapshot.link, Link::Connected) => Some(style::gauge_unread()),
        None => None,
    };
    style::plate(
        row((
            gauge,
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
        Link::Unpaired => return "No machine is paired".into(),
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
                ("RETRY NOW", Command::Restart(service.name.clone())),
            ),
        )),
        ServiceState::GaveUp { attempts, reason } => Some((
            STALLED,
            0,
            move_of(
                format!("{name} gave up after {attempts} attempts"),
                reason.clone(),
                ("START", Command::Start(service.name.clone())),
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
                ("START", Command::Start(service.name.clone())),
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
            style::emphatic(next.headline).color(style::state_ink(next.status)).wrap(),
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
            service_row(
                index,
                service,
                snapshot.selected.as_deref() == Some(service.name.as_str()),
                snapshot.requested(&service.name),
            )
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
fn service_row(
    index: usize,
    service: &ServiceStatus,
    chosen: bool,
    requested: Option<&Command>,
) -> El<Console> {
    let name = service.name.clone();
    let (status, _, _) = present(&service.state);
    let state_label = service.state.label().to_uppercase();
    let summary = rail_summary(service, requested);

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
                // that argument: a short line takes the quiet state word
                // first — whole, or not at all; the lamp still says it — and
                // only then takes from the name. A troubled word is the
                // exception argued at [`ALARM_UNIT`]: it keeps its words, and
                // the name is the payer.
                style::emphatic(display_name(service)).grow_from_content(),
                match status {
                    // Floored at the word's own width so it stands whole, and
                    // flush against the row's end so it sits where every other
                    // state word sits.
                    Status::Bad => {
                        let whole = state_label.len() as f32 * ALARM_UNIT;
                        style::state_word(status, state_label)
                            .min_w(whole)
                            .text_align(Align::End)
                    }
                    _ => style::state_word(status, state_label).whole(),
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
/// While a command naming the service is still queued for the poller, the
/// summary says the press was received — `stop requested…` — instead of a
/// state the console already knows is about to be wrong. A pure function of
/// the snapshot's own queue: no new state, and the words revert the frame the
/// poller takes the command.
///
/// Otherwise, a running service wears its restart count: `pid 4821 · up 2h`
/// on a service that has crashed twelve times today reads as health, and the
/// rail is where a flapping service has to be *noticed* — the detail pane
/// states the count only after the row has already been chosen. Only a live
/// service carries it; every troubled state's summary already accounts for
/// its restarts in its own words, and a stopped service's count is history
/// rather than a warning.
///
/// Pure, so the rule about who carries the count is asserted without a frame.
fn rail_summary(service: &ServiceStatus, requested: Option<&Command>) -> String {
    if let Some(command) = requested {
        return command.requested_message().to_owned();
    }
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

/// Closing the window stops every connection this console opened, and waits.
///
/// Waiting is right *here* and wrong during a switch. A command may be
/// half-written on a socket, and dropping the process on top of one leaves the
/// daemon reading a truncated request it then has to report as malformed; an
/// `ssh` left forwarding is worse still, because nothing afterwards owns it.
/// The links retired by earlier switches are joined too, which is why they were
/// kept rather than detached.
impl Drop for Console {
    fn drop(&mut self) {
        // The desktop stream first: it holds its own socket, and the daemon
        // keeps a place in its viewer ceiling until the far end notices.
        self.session = None;
        if let Some(link) = self.link.take() {
            link.shutdown();
        }
        for link in self.retiring.drain(..) {
            link.shutdown();
        }
    }
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
    ///
    /// Unlocked, and explicitly: this console has no link, so nothing here has
    /// read a credential or reached a machine and there is nothing for a lock to
    /// stand in front of — and the thread that would answer one is a link's own
    /// gate, which a console with no link does not have. Every frame in this file
    /// is a picture of a console somebody has already opened. [`locked`] is the
    /// one that photographs the other state.
    pub(crate) fn console(snapshot: Snapshot) -> Console {
        let console = Console::showing(
            Arc::new(Mutex::new(snapshot)),
            Bound::new("127.0.0.1:9191".parse().expect("a valid address"), None),
        );
        console.shared.lock().expect("a fresh lock").lock.state = crate::state::LockState::Open;
        console
    }

    /// The same, left shut — the console before anybody has proved they are here.
    pub(crate) fn locked(snapshot: Snapshot) -> Console {
        Console::showing(
            Arc::new(Mutex::new(snapshot)),
            Bound::new("127.0.0.1:9191".parse().expect("a valid address"), None),
        )
    }

    /// Re-fits the still-life session's picture to the pane it was last drawn
    /// into. See [`crate::channel::Session::settle`].
    pub(crate) fn settle_viewport(
        console: &Console,
        surface: &selfhost_desk::tiles::Surface,
    ) {
        if let Some(session) = &console.session {
            session.settle(surface);
        }
    }

    /// A copy of the still-life session's fitted picture, for the one
    /// measurement that times the blit apart from the frame it sits in.
    pub(crate) fn session_picture(console: &Console) -> Option<(Vec<u8>, u32, u32)> {
        let session = console.session.as_ref()?;
        let picture = session.picture();
        let (bytes, width, height) = picture.bgra()?;
        Some((bytes.to_vec(), width, height))
    }

    /// A console holding a session that never opened a socket.
    ///
    /// What makes the viewport photographable. Everything else on the DESKTOP
    /// plate is drawn from the snapshot and needs no daemon; the picture is the
    /// one thing that would otherwise only ever exist on somebody's screen.
    pub(crate) fn watching(snapshot: Snapshot, session: crate::channel::Session) -> Console {
        let mut console = console(snapshot);
        console.session = Some(session);
        console.viewport_focus = true;
        console
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
        assert!(rail_summary(running, None).ends_with("· 3 restarts"), "a live flapper says so");

        let backoff = &snapshot.services[2];
        assert!(
            !rail_summary(backoff, None).contains("restarts"),
            "a troubled state's own words already account for its restarts"
        );

        let mut quiet = running.clone();
        quiet.total_restarts = 0;
        assert!(!rail_summary(&quiet, None).contains("restart"), "a clean service says nothing");
    }

    #[test]
    fn a_queued_press_is_acknowledged_in_the_row_before_the_poll_answers() {
        // Pure function of the snapshot's queue: the row says the press was
        // received, and says the state again the frame the poller takes it.
        let snapshot = populated();
        let stop = Command::Stop("mongod".into());
        assert_eq!(rail_summary(&snapshot.services[0], Some(&stop)), "stop requested…");
        assert!(rail_summary(&snapshot.services[0], None).starts_with("pid"), "and reverts");
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
        let row = service_row(0, &console.snapshot().services[0].clone(), false, None);
        (row.click_action().expect("a row is clickable"))(&mut console);
        assert_eq!(console.snapshot().selected.as_deref(), Some("mongod"));
    }

    #[test]
    fn an_arrow_on_any_row_moves_the_selection_through_the_rail() {
        // The handler is an ordinary function of the console, so the keyboard's
        // half of choosing is tested the same way the pointer's half is: no
        // frame, no window, no synthetic keystroke.
        let mut console = console(populated());
        let row = service_row(0, &console.snapshot().services[0].clone(), false, None);
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

        // A quiet word is already said twice by the lamp, so on a line too
        // short to hold it whole it is not drawn at all — whole or nothing —
        // and every unit it held goes to the name.
        let mut long_running = populated();
        long_running.services.truncate(1);
        long_running.services[0].name = "a-very-long-name-for-a-running-service".into();
        let mut harness =
            Harness::new(console(long_running), |console: &Console| rail(&console.snapshot()))
                .size(RAIL_MIN, 420.0);
        harness.frame();
        assert!(
            harness.rect_of("RUNNING").is_none_or(|word| word.w <= 0.5),
            "a quiet word that cannot stand whole is not drawn"
        );
        let name = harness
            .rect_of("a-very-long-name-for-a-running-service")
            .expect("the name is drawn");
        assert!(name.w > width_of("RUNNING"), "the word's whole room goes to the name: {}", name.w);
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
        assert_eq!(next.control.0, "RETRY NOW");
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
            // The three screens the native console gained to reach parity with
            // the browser. Each is audited at both extremes, because a plate
            // with five fractional columns is wrong at 560 units long before it
            // is wrong at 980.
            ("the files plate", console(browsing()), (980.0, 680.0)),
            ("the files plate, narrow", console(browsing()), (560.0, 420.0)),
            ("the desktop plate with no session", console(fleet()), (980.0, 680.0)),
            ("the desktop plate driving a machine", watching(fleet(), still_session(true)), (980.0, 680.0)),
            ("the desktop plate, narrow", watching(fleet(), still_session(true)), (560.0, 420.0)),
            ("the people plate", console(roster()), (980.0, 680.0)),
            ("the people plate, narrow", console(roster()), (560.0, 420.0)),
            // The place above all of them, which is a place and not a fifth
            // tab: the list of machines, and the form that adds one.
            ("the machines overview", overview(), (980.0, 680.0)),
            ("the machines overview, narrow", overview(), (560.0, 420.0)),
            ("the machines overview with nothing paired", first_run(), (980.0, 680.0)),
        ]
    }

    /// A console standing above three paired machines, on one of them.
    pub(crate) fn overview() -> Console {
        let mut console = console(busy());
        console.machines = paired();
        console.bound = Bound::of(paired().get("alex-desktop").expect("paired"));
        console.place = Place::Overview;
        console
    }

    /// The first run: nothing paired, nothing open, and a form to fill in.
    pub(crate) fn first_run() -> Console {
        let mut console = console(Snapshot { link: Link::Unpaired, ..Snapshot::default() });
        console.place = Place::Overview;
        console
    }

    /// Three machines of the shape this project actually has.
    fn paired() -> Machines {
        let mut store = Machines::default();
        let mut desktop = Machine::new("alex-desktop", "alex@192.168.1.8");
        desktop.identity = Some(PathBuf::from("/Users/alex/.ssh/alexdesktop_ed25519"));
        // The finding that cost a session: the daemon's project directory over
        // there is not the login directory, so the token is not where the
        // default says it is.
        desktop.remote_token = "Self-Host/data/admin.token".into();
        store.pair(desktop);
        let mut pi = Machine::new("hallway-pi", "pi@192.168.1.20");
        pi.ssh_port = Some(2222);
        store.pair(pi);
        store.pair(Machine::new("workshop", "rocky@10.0.0.4"));
        store.opened("alex-desktop");
        store
    }

    #[test]
    fn every_new_screen_survives_the_smallest_window_with_no_face_loaded() {
        // The same argument the existing frame tests make: with no faces every
        // rectangle comes out at its minimum, so anything that only fits
        // because a label happened to be short is caught here rather than on
        // somebody's screen.
        for (name, snapshot) in
            [("files", browsing()), ("desktop", fleet()), ("people", roster())]
        {
            println!("drawing {name} at the smallest window");
            draw_frame(560, 420, console(snapshot));
        }
        draw_frame(560, 420, watching(fleet(), still_session(true)));
        draw_frame(560, 420, overview());
        draw_frame(560, 420, first_run());
    }

    #[test]
    fn a_tab_opens_its_screen_and_tells_the_poller_which_one() {
        // The snapshot carries the screen because that is what decides which
        // routes are asked for; a tab that changed only the drawing would leave
        // the poller fetching the wrong plate's data for ever.
        let mut harness =
            Harness::with_app(application("selfhost", console(busy()))).size(980.0, 680.0);
        harness.frame();
        harness.click_text("FILES");
        assert_eq!(harness.state().snapshot().screen, Screen::Files);
        harness.click_text("PEOPLE");
        assert_eq!(harness.state().snapshot().screen, Screen::People);
    }

    #[test]
    fn leaving_the_desktop_screen_takes_the_keyboard_with_it() {
        // A window whose FILES plate is open must not still be typing on
        // somebody's machine, and the release is what tells the far end to let
        // go of whatever is held.
        let mut console = watching(fleet(), still_session(true));
        assert!(console.viewport_has_keys());
        console.show(Screen::Files);
        assert!(!console.viewport_has_keys());
        assert_eq!(console.snapshot().screen, Screen::Files);
    }

    #[test]
    fn the_files_plate_keeps_its_columns_at_the_narrowest_window() {
        let mut harness =
            Harness::with_app(application("selfhost", console(browsing()))).size(560.0, 420.0);
        harness.frame();
        // The chosen column wears its direction, so the heading it is looked
        // up by is the whole word the plate actually draws.
        for column in ["NAME \u{25b2}", "SIZE", "MODIFIED"] {
            assert!(
                harness.rect_of(column).is_some(),
                "the {column} heading is drawn at 560 units"
            );
        }
        assert!(harness.rect_of("VAULT").is_some(), "the breadcrumb still names the share");
    }

    #[test]
    fn nothing_on_a_new_screen_is_drawn_outside_the_page() {
        // The defect this exists for: the FILES listing's four columns are
        // fractions that sum to one, and a gap *between* them is width the row
        // does not have — the row overflowed and the cell at the end, carrying
        // that row's own download and delete, was pushed off the plate. It
        // looked like a missing feature and it was a layout arithmetic error,
        // which is exactly the class of defect a reference frame catches and a
        // unit test should stop coming back.
        for (name, snapshot) in
            [("files", browsing()), ("desktop", fleet()), ("people", roster())]
        {
            for (width, height) in [(560.0, 420.0), (980.0, 680.0)] {
                let mut harness =
                    Harness::with_app(application("selfhost", console(snapshot_of(&snapshot))))
                        .size(width, height);
                harness.frame();
                let edge = width - PAGE_PAD;
                for probe in harness.probes() {
                    // The root fills the window; the margin is inside it, and
                    // the rule is about what the page draws in that margin.
                    if probe.rect.w >= width {
                        continue;
                    }
                    assert!(
                        probe.rect.x + probe.rect.w <= edge + 0.5,
                        "{name} at {width}×{height} draws {:?} into the page margin: {:?}",
                        probe.text,
                        probe.rect
                    );
                }
            }
        }
    }

    /// A fresh copy of a fixture, so one can be drawn at several sizes.
    ///
    /// [`Snapshot`] holds a queue and a listing and is deliberately not `Clone`
    /// — the console has exactly one of it — so a test that needs two rebuilds
    /// the parts it asserts on rather than teaching the type to copy itself.
    fn snapshot_of(source: &Snapshot) -> Snapshot {
        Snapshot {
            link: source.link.clone(),
            services: source.services.clone(),
            selected: source.selected.clone(),
            screen: source.screen,
            files: crate::state::Files {
                shares: source.files.shares.clone(),
                share: source.files.share.clone(),
                path: source.files.path.clone(),
                listing: source.files.listing.clone(),
                trouble: source.files.trouble.clone(),
                column: source.files.column,
                ascending: source.files.ascending,
                selected: source.files.selected.clone(),
            },
            desk: crate::state::Desk {
                settings: source.desk.settings,
                nodes: source.desk.nodes.clone(),
                peer: source.desk.peer.clone(),
                agent: source.desk.agent.clone(),
            },
            people: crate::state::People {
                holders: source.people.holders.clone(),
                trouble: source.people.trouble.clone(),
                trail: source.people.trail.clone(),
                hide_pointer_noise: source.people.hide_pointer_noise,
            },
            ..Default::default()
        }
    }

    #[test]
    fn a_download_larger_than_this_console_can_hold_is_refused_before_it_is_asked_for() {
        // This client buffers a body whole, so the alternative is an allocation
        // that fails — and under `panic = "abort"` that is the window going away
        // rather than a sentence a person can act on.
        let mut console = console(browsing());
        console.download("photos/2024/raw negatives.tar");
        let snapshot = console.snapshot();
        assert!(snapshot.commands.is_empty(), "nothing was asked of the daemon");
        let notice = snapshot.notice.as_ref().expect("a refusal");
        assert_eq!(notice.kind, NoticeKind::Problem);
        assert!(notice.text.contains("512 MB"), "it names the limit: {}", notice.text);
        assert!(notice.text.contains("SMB"), "and what to use instead: {}", notice.text);
    }

    #[test]
    fn an_ordinary_download_is_queued_with_a_destination_that_names_the_file() {
        let mut console = console(browsing());
        console.download("photos/2024/contact sheet.pdf");
        let snapshot = console.snapshot();
        let Some(Command::Files { share, action: FileAction::Download { path, to } }) =
            snapshot.commands.front()
        else {
            panic!("a download was not queued: {:?}", snapshot.commands);
        };
        assert_eq!(share, "vault");
        assert_eq!(path, "photos/2024/contact sheet.pdf");
        assert!(to.ends_with("contact sheet.pdf"), "it lands under its own name: {to:?}");
    }

    #[test]
    fn a_name_the_daemon_cannot_address_says_why_rather_than_offering_a_link() {
        let mut harness =
            Harness::with_app(application("selfhost", console(browsing()))).size(980.0, 680.0);
        harness.frame();
        assert!(
            harness.rect_of("the name contains a path separator").is_some(),
            "an unreachable row carries its reason"
        );
    }

    #[test]
    fn the_desktop_plate_says_what_the_far_machine_says_about_itself() {
        // The words are `selfhost-desk`'s, so a change of wording there is a
        // change of wording here — which is the whole point of the two consoles
        // sharing the vocabulary and nothing else.
        let mut harness =
            Harness::with_app(application("selfhost", watching(fleet(), still_session(true))))
                .size(980.0, 680.0);
        harness.frame();
        assert!(harness.rect_of("live").is_some(), "the session's own notice is drawn");
        assert!(harness.rect_of("DRIVING").is_some(), "and where the keyboard is pointed");
    }

    #[test]
    fn a_watching_session_never_draws_the_word_driving() {
        let mut harness =
            Harness::with_app(application("selfhost", watching(fleet(), still_session(false))))
                .size(980.0, 680.0);
        harness.frame();
        assert!(harness.rect_of("WATCHING").is_some());
        assert!(harness.rect_of("DRIVING").is_none(), "a view is never drawn as control");
    }

    #[test]
    fn a_hand_moving_over_the_picture_moves_the_far_machines_pointer() {
        // The gap this closes, and it was a library gap: before
        // `rui::El::on_pointer_move` a position reached this console only while
        // a button was held, so the far pointer stood still until something was
        // dragged. The browser console has always tracked; the two now agree.
        let (session, sent) = recorded_session(true);
        let mut harness =
            Harness::with_app(application("selfhost", watching(fleet(), session))).size(980.0, 680.0);
        harness.frame();
        let screen = harness.find_key("screen").expect("the viewport is drawn").rect;

        harness.move_pointer(rui::Point::new(screen.x + screen.w * 0.25, screen.y + screen.h * 0.5));
        let first = sent.try_recv().expect("nothing was sent for a hand moving over the picture");
        let Message::PointerMove { x, y, .. } = first else {
            panic!("the far machine was told {first:?} rather than where to point");
        };
        assert!(x > 0 && y > 0, "a quarter of the way across the picture is not its corner");

        // Moving again, far enough to land on a different pixel of the far
        // screen, is a second message.
        harness.move_pointer(rui::Point::new(screen.x + screen.w * 0.75, screen.y + screen.h * 0.5));
        let second = sent.try_recv().expect("the second movement was not sent");
        let Message::PointerMove { x: further, .. } = second else {
            panic!("the far machine was told {second:?}");
        };
        assert!(further > x, "the far pointer went the way the hand did");
    }

    #[test]
    fn a_movement_landing_on_the_pixel_the_far_pointer_is_already_on_is_not_sent_twice() {
        // A pane a third the width of the screen it shows maps three of this
        // machine's pixels onto one of theirs, so a hand moving slowly produces
        // frame after frame naming the same far pixel. Every one of them would
        // be a message saying nothing changed.
        let (session, sent) = recorded_session(true);
        let mut harness =
            Harness::with_app(application("selfhost", watching(fleet(), session))).size(980.0, 680.0);
        harness.frame();
        let screen = harness.find_key("screen").expect("the viewport is drawn").rect;

        let at = rui::Point::new(screen.x + screen.w * 0.5, screen.y + screen.h * 0.5);
        harness.move_pointer(at);
        assert!(matches!(sent.try_recv(), Ok(Message::PointerMove { .. })), "the first is sent");

        // A movement of a fraction of a pixel of the far screen: a different
        // place in this window, the same place over there.
        harness.move_pointer(rui::Point::new(at.x + 0.01, at.y));
        assert!(sent.try_recv().is_err(), "the far pointer was told to stay where it already was");
    }

    #[test]
    fn a_watching_session_moves_nothing_when_the_pointer_crosses_the_picture() {
        // Viewing and driving are separate capabilities and the daemon decides
        // them; a pointer that moved the far machine's under a view-only ticket
        // would be this console driving without one.
        let (session, sent) = recorded_session(false);
        let mut harness =
            Harness::with_app(application("selfhost", watching(fleet(), session))).size(980.0, 680.0);
        harness.frame();
        let screen = harness.find_key("screen").expect("the viewport is drawn").rect;

        harness.move_pointer(screen.center());
        assert!(sent.try_recv().is_err(), "a watching session sent the far machine a pointer");
    }

    #[test]
    fn a_full_screen_desktop_gives_the_far_machine_the_whole_window() {
        // What "like its own whole application" has to mean to be worth the
        // name: the picture takes the room the masthead, the tabs, the picker
        // and the page margin were using, and the way back is still on screen.
        let mut harness =
            Harness::with_app(application("selfhost", watching(fleet(), still_session(false))))
                .size(980.0, 680.0);
        harness.frame();
        let pane = harness.find_key("screen").expect("the viewport is drawn").rect;
        assert!(harness.rect_of("SERVICES").is_some(), "the tabs are there to begin with");

        harness.click_text("FULL SCREEN");
        harness.frame();
        assert!(harness.state().full_screen(), "the window was asked to fill the screen");
        assert!(harness.rect_of("SERVICES").is_none(), "the tab row went with the chrome");
        assert!(harness.rect_of("MACHINES").is_none(), "and so did the picker");
        let stage = harness.find_key("screen").expect("the viewport is still drawn").rect;
        assert!(stage.w > pane.w && stage.h > pane.h, "{stage:?} is no larger than {pane:?}");
        assert!(harness.rect_of("EXIT FULL SCREEN").is_some(), "the way out is on screen");
    }

    #[test]
    fn leaving_a_full_screen_puts_the_console_back() {
        let mut harness =
            Harness::with_app(application("selfhost", watching(fleet(), still_session(false))))
                .size(980.0, 680.0);
        harness.frame();
        harness.click_text("FULL SCREEN");
        harness.frame();
        harness.click_text("EXIT FULL SCREEN");
        harness.frame();
        assert!(!harness.state().full_screen());
        assert!(harness.rect_of("SERVICES").is_some(), "the console came back whole");
    }

    #[test]
    fn a_window_filling_the_screen_on_another_plate_is_only_a_large_window() {
        // The stage belongs to the DESKTOP screen. A person who made the window
        // full screen while reading a log asked for a bigger log, not for the
        // console to be taken away from them.
        let mut harness =
            Harness::with_app(application("selfhost", console(busy()))).size(980.0, 680.0);
        harness.state_mut().set_full_screen(true);
        harness.frame();
        assert!(harness.rect_of("SERVICES").is_some(), "the tabs stayed on a services plate");
    }

    #[test]
    fn the_masthead_steps_back_to_the_machines_and_forward_onto_the_open_one() {
        // The one way between the two places. It is a step and not a tab: the
        // tab row belongs to a machine, so it is not drawn at all up here.
        let mut harness =
            Harness::with_app(application("selfhost", console(busy()))).size(980.0, 680.0);
        harness.frame();
        assert!(harness.rect_of("SERVICES").is_some(), "the tabs belong to the machine");

        harness.click_text("\u{2039} MACHINES");
        assert_eq!(harness.state().place(), Place::Overview);
        harness.frame();
        assert!(harness.rect_of("SERVICES").is_none(), "the tab row followed the machine");
        assert!(harness.rect_of("PAIR A MACHINE").is_some(), "and the overview is drawn");
    }

    #[test]
    fn the_overview_lists_every_paired_machine_and_marks_the_open_one() {
        let mut harness =
            Harness::with_app(application("selfhost", overview())).size(980.0, 680.0);
        harness.frame();
        for name in ["alex-desktop", "hallway-pi", "workshop"] {
            assert!(harness.rect_of(name).is_some(), "{name} is not on the list");
        }
        assert!(
            harness.find_key("open alex-desktop").is_none(),
            "the machine already open was offered an OPEN it does not need"
        );
        assert!(harness.find_key("open workshop").is_some(), "every other machine opens");
        // The token path that is not the default is stated, because it is the
        // one that bites: the daemon's project directory on ALEX-DESKTOP is not
        // the login directory, and a pairing that does not say so cannot read a
        // token at all.
        let drawn = harness.text().join("\n");
        assert!(drawn.contains("Self-Host/data/admin.token"), "{drawn}");
        assert!(drawn.contains("alex@192.168.1.8"), "the address is stated too: {drawn}");
    }

    #[test]
    fn a_console_with_nothing_paired_says_so_and_shows_the_form() {
        // The first run, and the state a fresh install is in. An empty list is
        // furnished rather than blank: empty is not broken.
        let mut harness =
            Harness::with_app(application("selfhost", first_run())).size(980.0, 680.0);
        harness.frame();
        assert!(harness.rect_of("No machine is paired on this computer yet.").is_some());
        assert!(harness.find_key("pair-name").is_some(), "the form is what the place is for");
    }

    #[test]
    fn forgetting_a_machine_takes_it_off_the_list() {
        let mut console = overview();
        assert_eq!(console.machines().entries().len(), 3);
        console.forget_machine("workshop");
        assert!(console.machines().get("workshop").is_none());
        assert_eq!(console.machines().entries().len(), 2, "and nothing else went with it");
    }

    #[test]
    fn opening_a_machine_that_is_no_longer_paired_says_so_rather_than_doing_nothing() {
        // The race a second console makes possible: this one forgot the machine
        // while that one was still showing it.
        let mut console = overview();
        console.open_machine("imaginary");
        let snapshot = console.snapshot();
        let notice = snapshot.notice.as_ref().expect("a notice");
        assert!(notice.text.contains("imaginary"), "{}", notice.text);
    }

    #[test]
    fn the_pairing_form_states_every_problem_at_once() {
        // The refusal stays on the form, beside what is being typed, rather
        // than becoming a notice at the top of a window nobody is looking at.
        let mut console = first_run();
        console.pair_form_mut().name = "Alex Desktop".into();
        console.submit_pair_form();
        assert!(!console.pair_form().trouble.is_empty());
        assert_eq!(console.place(), Place::Overview, "a refused form does not navigate");
    }

    #[test]
    fn the_people_plate_shows_the_roster_beside_the_trail() {
        let mut harness =
            Harness::with_app(application("selfhost", console(roster()))).size(980.0, 680.0);
        harness.frame();
        assert!(harness.rect_of("alex").is_some(), "a holder by name");
        assert!(harness.rect_of("YubiKey 5C").is_some(), "and the device under it");
        assert!(harness.rect_of("AUDIT").is_some(), "with the trail beside it");
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

    /// A console browsing a share.
    ///
    /// Everything the FILES plate has to lay out at once: a share near its
    /// ceiling and one whose usage could not be read, a directory two levels
    /// down so the trail has crumbs in it, a name long enough to compete for the
    /// row, and a name the daemon says cannot be addressed at all.
    pub(crate) fn browsing() -> Snapshot {
        use crate::nas::{Entry, Kind, Listing, Share};
        let share = |id: &str, used: Option<u64>, quota: Option<u64>, writable: bool| Share {
            id: id.into(),
            read_only: !writable,
            browsable: true,
            writable,
            quota_bytes: quota,
            available_bytes: Some(48_000_000_000),
            used_bytes: used,
            smb: (id == "vault").then(|| "Vault".to_owned()),
        };
        let entry = |name: &str, kind: Kind, size: u64, modified: Option<u64>| Entry {
            name: name.into(),
            kind,
            size,
            modified,
            path: crate::nas::join_path("photos/2024", name),
            blocked: None,
        };

        let mut snapshot = populated();
        snapshot.screen = Screen::Files;
        snapshot.files.shares = Some(vec![
            share("vault", Some(478_000_000_000), Some(500_000_000_000), true),
            share("photos", Some(12_400_000_000), None, true),
            share("archive", None, Some(2_000_000_000_000), false),
        ]);
        snapshot.files.share = Some("vault".into());
        snapshot.files.path = "photos/2024".into();
        snapshot.files.selected = Some("beach at golden hour.jpg".into());
        snapshot.files.listing = Some(Listing {
            share: "vault".into(),
            path: "photos/2024".into(),
            entries: vec![
                entry("summer", Kind::Directory, 0, Some(1_712_000_000)),
                entry("winter", Kind::Directory, 0, Some(1_704_100_000)),
                entry("beach at golden hour.jpg", Kind::File, 8_412_672, Some(1_719_000_000)),
                entry("contact sheet.pdf", Kind::File, 1_204_000, Some(1_718_000_000)),
                entry("raw negatives.tar", Kind::File, 41_203_400_000, Some(1_700_000_000)),
                Entry {
                    name: "scan\\001.tif".into(),
                    kind: Kind::File,
                    size: 92_000,
                    modified: Some(1_690_000_000),
                    path: None,
                    blocked: Some("the name contains a path separator".into()),
                },
            ],
        });
        snapshot
    }

    /// A console looking at the fleet, with no session open.
    ///
    /// The picker's three cases at once: the machine the daemon runs on, one
    /// that is up, and one that is down with a reason and a last-seen time.
    pub(crate) fn fleet() -> Snapshot {
        use crate::remote::{Agent, Node, Settings};
        let mut snapshot = populated();
        snapshot.screen = Screen::Desktop;
        snapshot.desk.settings = Some(Settings {
            enabled: true,
            allow_input: true,
            allow_clipboard: false,
            bearer_may_control: true,
            max_viewers: 2,
            max_fps: 30,
            tile: 64,
            reauth_window_secs: 120,
            max_session_secs: 14_400,
        });
        snapshot.desk.nodes = Some(vec![
            Node { node: "self".into(), live: true, last_seen_secs: Some(0), reason: None },
            Node {
                node: "alex-desktop".into(),
                live: true,
                last_seen_secs: Some(2),
                reason: None,
            },
            Node {
                node: "studio-mac".into(),
                live: false,
                last_seen_secs: Some(5_400),
                reason: Some("the link was closed by the peer".into()),
            },
        ]);
        snapshot.desk.peer = Some("alex-desktop".into());
        snapshot.desk.agent = Some(Agent {
            node: "alex-desktop".into(),
            live: true,
            sentence: "agent live in session 1 as ALEX · WinSta0\\Default · 2 monitors · \
                       per-monitor DPI · medium integrity"
                .into(),
            monitors: 2,
            respawns: 1,
        });
        snapshot
    }

    /// A synthetic far screen: a graded ground with a window on it.
    ///
    /// Graded deliberately. A flat picture would look the same fitted, sheared,
    /// or upside down; a vertical grade with one bright rectangle in it makes
    /// every one of those obvious in the reference frame.
    pub(crate) fn synthetic_screen() -> selfhost_desk::tiles::Surface {
        use selfhost_desk::tiles::Surface;
        const WIDTH: u32 = 1920;
        const HEIGHT: u32 = 1080;
        let mut pixels = vec![0u8; WIDTH as usize * HEIGHT as usize * 4];
        for y in 0..HEIGHT as usize {
            for x in 0..WIDTH as usize {
                let at = (y * WIDTH as usize + x) * 4;
                let in_window = (200..1500).contains(&x) && (140..820).contains(&y);
                let shade = if in_window {
                    [0x2a, 0x24, 0x1e, 0xff]
                } else {
                    // A vertical grade, so a picture that is fitted upside down
                    // or sheared is obvious in the reference frame rather than
                    // plausible.
                    let value = 0x10 + (y * 0x50 / HEIGHT as usize) as u8;
                    [value, value.saturating_sub(4), value.saturating_sub(8), 0xff]
                };
                if let Some(cell) = pixels.get_mut(at..at + 4) {
                    cell.copy_from_slice(&shade);
                }
            }
        }
        Surface::new(WIDTH, HEIGHT, pixels).expect("a surface")
    }

    /// A session holding one picture, without ever opening a socket.
    ///
    /// The picture goes through the real fitting path, so what a frame
    /// photographs is the blit a stream would have produced and not a
    /// hand-built buffer.
    pub(crate) fn still_session(control: bool) -> crate::channel::Session {
        use crate::channel::{Picture, Session};
        let (live, surface) = still_parts(control);
        Session::still_life("alex-desktop", control, live, Picture::fitted(&surface, 1_400, 900))
    }

    /// The same session, keeping every message the console sends it.
    ///
    /// What proves a pointer or a key actually left this window, as against
    /// merely being handled: the still life above drops its receiver.
    pub(crate) fn recorded_session(
        control: bool,
    ) -> (crate::channel::Session, std::sync::mpsc::Receiver<selfhost_desk::wire::Message>) {
        use crate::channel::{Picture, Session};
        let (live, surface) = still_parts(control);
        Session::recorded("alex-desktop", control, live, Picture::fitted(&surface, 1_400, 900))
    }

    /// What a still session is made of: a link that is up, and a screen.
    fn still_parts(control: bool) -> (crate::channel::Live, selfhost_desk::tiles::Surface) {
        use crate::channel::{LinkState, Live};
        use selfhost_desk::grant::Capabilities;
        use selfhost_desk::state::Notice;
        use selfhost_desk::wire::Monitor;

        let surface = synthetic_screen();
        let mut live = Live::opening();
        live.state = LinkState::Open;
        live.notice = Some(Notice::Live);
        live.capabilities = if control {
            Capabilities::VIEW.with(Capabilities::CONTROL)
        } else {
            Capabilities::VIEW
        };
        live.monitors = vec![
            Monitor {
                id: 0,
                origin_x: 0,
                origin_y: 0,
                width: surface.width(),
                height: surface.height(),
                scale_permille: 1000,
                primary: true,
            },
            Monitor {
                id: 1,
                origin_x: 1920,
                origin_y: 0,
                width: 2560,
                height: 1440,
                scale_permille: 1500,
                primary: false,
            },
        ];
        live.frames = 1_284;
        live.bytes = 41_200_512;

        (live, surface)
    }

    /// A console reading the registry and the trail.
    pub(crate) fn roster() -> Snapshot {
        use crate::registry::{Person, Record, Trail};
        let mut snapshot = populated();
        snapshot.screen = Screen::People;
        snapshot.people.holders = Some(vec![
            Person {
                id: "q0Zm-x_9AAbb".into(),
                user: "alex".into(),
                label: "MacBook Pro · Touch ID".into(),
                created_unix: 1_712_000_000,
            },
            Person {
                id: "K3lp_zzQ11".into(),
                user: "alex".into(),
                label: "iPhone · Face ID".into(),
                created_unix: 1_716_400_000,
            },
            Person {
                id: "b9-Ww_04zz".into(),
                user: "rocky".into(),
                label: "YubiKey 5C".into(),
                created_unix: 1_700_000_000,
            },
        ]);
        let record = |id: &str, at: u64, who: &str, capability: &str, target: &str, outcome: &str,
                      reason: &str, detail: &str| Record {
            id: id.into(),
            at_unix: at,
            identity: "owner".into(),
            who: who.into(),
            capability: capability.into(),
            target: target.into(),
            outcome: outcome.into(),
            reason: reason.into(),
            detail: detail.into(),
        };
        snapshot.people.trail = Some(Trail {
            records: vec![
                record("r7", 1_723_000_400, "alex", "desktop.control", "alex-desktop", "allow", "", "key 0x04 down"),
                record("r6", 1_723_000_380, "alex", "desktop.control", "alex-desktop", "allow", "", "pointer 1204,880"),
                record("r5", 1_723_000_360, "rocky", "desktop.control", "alex-desktop", "deny", "stale-login", "ticket refused"),
                record("r4", 1_723_000_100, "alex", "desktop.view", "alex-desktop", "allow", "", "stream opened"),
                record("r3", 1_722_900_000, "alex", "files.write", "vault", "allow", "", "vault · rename"),
                record("r2", 1_722_800_000, "rocky", "files.read", "archive", "deny", "no-grant", "archive · list"),
                record("r1", 1_722_700_000, "alex", "console.read", "", "allow", "", "session opened"),
            ],
            scanned: 412,
            unreadable: 0,
        });
        snapshot
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
        snapshot.logs.answered = true;
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

        // The first thing anybody now sees, before the console has connected to
        // anything: the lock. Photographed at both sizes, because it is the one
        // screen every launch goes through and a sentence that wraps badly at
        // 560 is a sentence read badly every single time.
        for (name, size) in [("locked", (1000, 660)), ("locked-narrow", (560, 420))] {
            written(
                name,
                Snapshot::default(),
                |console| {
                    console.with_snapshot(|snapshot| {
                        snapshot.lock.state = crate::state::LockState::Shut;
                    });
                },
                size,
            );
        }

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

        // The three screens that bring the native console to parity with the
        // browser, each at both sizes — because a plate with five fractional
        // columns and a viewport is wrong at 560 units long before it is wrong
        // at 1000, and a screen nobody has looked at is a screen nobody has
        // reviewed.
        for (name, size) in [("files", (1000, 660)), ("files-narrow", (560, 420))] {
            written(name, browsing(), |_| {}, size);
        }
        written("desktop", fleet(), |_| {}, (1000, 660));
        for (name, size) in [("people", (1000, 660)), ("people-narrow", (560, 420))] {
            written(name, roster(), |_| {}, size);
        }

        // The place above the machine: the list, the form, and the first-run
        // state of both, which is the very first thing a fresh install draws.
        // It takes its console whole rather than through `written`, because
        // what makes it the overview is the console and not the snapshot.
        let mut place = |name: &str, console: Console, size: (u32, u32)| {
            let mut app = application("selfhost", console);
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
        place("machines", overview(), (1000, 660));
        place("machines-narrow", overview(), (560, 420));
        place("machines-empty", first_run(), (1000, 660));

        // The viewport, which is the one screen whose drawing cannot be
        // photographed from a snapshot: it needs a session holding pixels. The
        // picture goes through the real fitting path and the real
        // `Canvas::blit_bgra`, so what is in the image is what a live stream
        // would put there.
        let screen = synthetic_screen();
        let mut viewport = |name: &str, size: (u32, u32)| {
            let console = watching(fleet(), still_session(true));
            let mut app = application("selfhost", console);
            for (scale, path) in
                [(2.0, format!("{directory}/{name}.png")), (1.0, format!("{directory}/web/{name}.png"))]
            {
                // The first frame states the pane's device size into the
                // session's fit cell; the picture is then fitted to it and the
                // second frame draws it. That is exactly the settling a resized
                // window does, and doing it by hand here is what makes the
                // image a photograph of the real path rather than of a
                // hand-sized buffer.
                app.render(size.0, size.1, scale, Appearance::Dark, &mut fonts);
                settle_viewport(app.state(), &screen);
                let canvas = app.render(size.0, size.1, scale, Appearance::Dark, &mut fonts);
                let pixels = rui::image::rgba(&canvas);
                let png = rui::image::png(canvas.width(), canvas.height(), &pixels)
                    .expect("a frame should encode");
                std::fs::write(&path, png).expect("the directory should be writable");
                println!("wrote {path}");
            }
        };
        viewport("desktop-live", (1000, 660));
        viewport("desktop-narrow", (560, 420));

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

        // What a live viewport adds, measured beside the figures above rather
        // than asserted. Three numbers, because the cost of a remote desktop in
        // this window is three separate things and only one of them is in the
        // frame loop: fitting an arriving frame to the pane (on the stream's own
        // thread, once per *frame received*), blitting the result (in the frame
        // loop, once per *frame drawn*), and drawing the rest of the interface
        // around it.
        let mut app = application("selfhost", watching(fleet(), still_session(true)));
        let screen = synthetic_screen();
        println!("\n| viewport at | fit a 1920×1080 frame | blit it | whole interface with it |");
        println!("|---|---|---|---|");
        for (width, height) in FRAME_SIZES {
            let mut canvas = rui::Canvas::new(width * 2, height * 2, 2.0);
            let mut memory = rui::Memory::new();
            app.draw_into(&mut canvas, &mut fonts, Appearance::Dark, &mut memory);
            settle_viewport(app.state(), &screen);
            app.draw_into(&mut canvas, &mut fonts, Appearance::Dark, &mut memory);

            let fitting = std::time::Instant::now();
            for _ in 0..RUNS {
                settle_viewport(app.state(), &screen);
            }
            let fit = fitting.elapsed() / RUNS;

            let drawing = std::time::Instant::now();
            for _ in 0..RUNS {
                app.draw_into(&mut canvas, &mut fonts, Appearance::Dark, &mut memory);
            }
            let whole = drawing.elapsed() / RUNS;

            // The blit alone, against the same canvas the loop draws into.
            let (bytes, source_width, source_height) =
                session_picture(app.state()).expect("a fitted picture");
            let blitting = std::time::Instant::now();
            for _ in 0..RUNS {
                if let Some(bgra) = rui::Bgra::packed(source_width, source_height, &bytes) {
                    canvas.blit_bgra(rui::Rect::new(0.0, 0.0, width as f32, height as f32), &bgra);
                }
            }
            let blit = blitting.elapsed() / RUNS;

            println!(
                "| {width} × {height} | {:.2} ms | {:.2} ms | **{:.1} ms** |",
                fit.as_secs_f32() * 1000.0,
                blit.as_secs_f32() * 1000.0,
                whole.as_secs_f32() * 1000.0
            );
        }
    }
}
