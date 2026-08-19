//! The lock in front of a connection: prove a person is here, then dial.
//!
//! # The defect this exists for
//!
//! The console reached the daemon the instant it was launched. A double-click on
//! the Dock icon read the machine it was last on, started `ssh` to it, read that
//! deployment's admin token off the far side and began polling — all of it before
//! anything was drawn, and none of it having asked anybody anything. Every
//! credential involved is one a program replays without a person: a token file, a
//! key with no passphrase, a store of remembered machines. Whoever could reach
//! this laptop's keyboard could operate the server, and the only thing between
//! the two was the screen saver.
//!
//! # Where the lock stands
//!
//! In front of **both** threads, which is the whole of what makes it a lock. The
//! tunnel is not started, the token is not read and no request is composed until
//! [`stand_guard`] has an answer it accepts — so a console that is refused has
//! not touched the network, rather than having connected behind a curtain. That
//! is why this thread spawns the other two rather than running beside them: the
//! order is a fact about the code, not a flag they are each supposed to check.
//!
//! # Who answers
//!
//! The operating system, in its own sheet: a fingerprint, or the account password
//! behind it — see [`selfhost_presence`]. Nothing here reads a password, and
//! there is no field in this program to type one into.
//!
//! # The proof outlives the link
//!
//! A [`Latch`] is held by the console, not by the link, so changing machines does
//! not ask again — the person proved they were here, not that they were here *for
//! that server*. Locking the console clears it, and every link opened afterwards
//! finds it shut. That is also how the LOCK control works: it clears the latch and
//! opens the link again, and the link's own gate does the rest.

use crate::poller;
use crate::session::Connector;
use crate::state::{Lock, LockState, Snapshot};
use crate::tunnel::{self, TunnelSpec};
use selfhost_presence::Presence;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// What the system's sheet says this program is trying to do.
///
/// It is shown after the application's name — "Selfhost Console is trying to…" —
/// so it is written as the act, and it names the consequence rather than the
/// program: what is being unlocked is a server, and that is what the person is
/// being asked about.
const REASON: &str = "connect to your server";

/// How often the gate looks up from waiting to see whether the window is still
/// open, or whether UNLOCK has been pressed.
///
/// Short enough that closing a window with a sheet standing on it does not feel
/// like a hang, long enough that a locked console costs nothing.
const TICK: Duration = Duration::from_millis(120);

/// Whether a person has been proved to be at this computer, for this console.
///
/// One per console rather than one per link — see the module note. An
/// [`AtomicBool`] and not a lock: it is written by the gate thread and by the
/// window, read by the gate thread, and there is nothing to wait on.
#[derive(Debug, Default)]
pub struct Latch {
    proved: AtomicBool,
}

impl Latch {
    /// A latch nobody has opened.
    pub fn shut() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Whether somebody has proved they are here since it was last shut.
    pub fn proved(&self) -> bool {
        self.proved.load(Ordering::Relaxed)
    }

    /// Records that somebody has.
    pub fn prove(&self) {
        self.proved.store(true, Ordering::Relaxed);
    }

    /// Forgets it. The next link opened will ask again.
    pub fn close(&self) {
        self.proved.store(false, Ordering::Relaxed);
    }
}

/// Starts the gate, and behind it the connection.
///
/// The handle returned is the only one the link keeps: it does not finish until
/// the tunnel and the poller have, because it joins them. A window that closes
/// while the lock is still shut ends it within one [`TICK`].
pub fn spawn(
    spec: Option<TunnelSpec>,
    connect: Connector,
    shared: Arc<Mutex<Snapshot>>,
    alive: Arc<AtomicBool>,
    proof: Arc<Latch>,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("selfhost-console-gate".into())
        .spawn(move || {
            if !stand_guard(&shared, &alive, &proof, || selfhost_presence::demand(REASON)) {
                return;
            }
            let mut threads = Vec::new();
            if let Some(spec) = spec {
                threads.push(tunnel::spawn(spec, Arc::clone(&shared), Arc::clone(&alive)));
            }
            threads.push(poller::spawn(move || connect(), shared, alive));
            for thread in threads {
                let _ = thread.join();
            }
        })
        .expect("the operating system refused to start a thread")
}

/// Asks until somebody proves they are here, the window closes, or nobody asks
/// again.
///
/// `ask` is the question, taken as a function so that the loop around it — which
/// is where every decision lives — is tested without a fingerprint sensor.
///
/// Answers `true` only on a proof. **Every other way out is `false`**, including
/// a window that closed while the sheet was standing: this is the one predicate
/// deciding whether a connection happens, so it is written so that the failure
/// paths cannot accidentally join the success path.
fn stand_guard<Ask>(
    shared: &Arc<Mutex<Snapshot>>,
    alive: &AtomicBool,
    proof: &Latch,
    ask: Ask,
) -> bool
where
    Ask: Fn() -> Presence + Send + Sync + Clone + 'static,
{
    // A console that has already been unlocked does not ask again when the
    // operator opens a second machine. What was proved is that a person is at
    // this computer, and opening another window's worth of the same session does
    // not make that less true.
    if proof.proved() {
        report(shared, LockState::Open, None);
        return true;
    }

    loop {
        if !alive.load(Ordering::Relaxed) {
            return false;
        }
        report(shared, LockState::Asking, None);

        // Asked on a thread of its own so that a window closed while the sheet
        // is standing is noticed within a tick. The sheet belongs to the system
        // and outlives this thread perfectly well; what must not outlive the
        // window is something the window is waiting to join.
        let (answered, answer) = std::sync::mpsc::channel();
        let asking = ask.clone();
        std::thread::Builder::new()
            .name("selfhost-console-presence".into())
            .spawn(move || {
                let _ = answered.send(asking());
            })
            .expect("the operating system refused to start a thread");

        let presence = loop {
            match answer.recv_timeout(TICK) {
                Ok(presence) => break presence,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if !alive.load(Ordering::Relaxed) {
                        return false;
                    }
                }
                // The asking thread died without answering. Treated as a refusal
                // and not as a proof, which is the rule this whole file is.
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    break Presence::Unavailable(
                        "the request to prove somebody is here did not finish".to_owned(),
                    );
                }
            }
        };

        if presence.proved() {
            proof.prove();
            report(shared, LockState::Open, None);
            return true;
        }

        report(shared, LockState::Shut, presence.trouble());
        if !wait_to_be_asked_again(shared, alive) {
            return false;
        }
    }
}

/// Waits for UNLOCK, or for the window to close.
///
/// Answers `true` when the person asked again. Polled rather than signalled
/// because the flag lives in the snapshot both threads already share, and adding
/// a condvar beside it would be a second way for the same fact to be told.
fn wait_to_be_asked_again(shared: &Arc<Mutex<Snapshot>>, alive: &AtomicBool) -> bool {
    while alive.load(Ordering::Relaxed) {
        {
            let mut snapshot = shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if std::mem::take(&mut snapshot.lock.asked_again) {
                return true;
            }
        }
        std::thread::sleep(TICK);
    }
    false
}

/// Writes where the lock is, for the window to draw.
fn report(shared: &Arc<Mutex<Snapshot>>, state: LockState, trouble: Option<String>) {
    let mut snapshot = shared.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    snapshot.lock = Lock { state, trouble, asked_again: false };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> Arc<Mutex<Snapshot>> {
        Arc::new(Mutex::new(Snapshot::default()))
    }

    fn state(shared: &Arc<Mutex<Snapshot>>) -> Lock {
        shared.lock().expect("not poisoned").lock.clone()
    }

    #[test]
    fn a_proof_opens_the_lock_and_lets_the_connection_start() {
        let shared = snapshot();
        let alive = AtomicBool::new(true);
        let proof = Latch::default();
        assert!(stand_guard(&shared, &alive, &proof, || Presence::Proved));
        assert_eq!(state(&shared).state, LockState::Open);
        assert!(proof.proved(), "the console stays unlocked for the next link");
    }

    #[test]
    fn a_refusal_connects_nothing_and_says_why() {
        // The load-bearing assertion of this file: `stand_guard` answering false
        // is the reason `ssh` is never started and the token is never read.
        let shared = snapshot();
        let alive = Arc::new(AtomicBool::new(true));
        let proof = Latch::default();

        // Nobody presses UNLOCK; the window is closed instead.
        let closing = Arc::clone(&alive);
        std::thread::spawn(move || {
            std::thread::sleep(TICK * 3);
            closing.store(false, Ordering::Relaxed);
        });

        assert!(!stand_guard(&shared, &alive, &proof, || Presence::Declined));
        assert!(!proof.proved(), "a refusal must not leave a console unlocked");
        let lock = state(&shared);
        assert_eq!(lock.state, LockState::Shut);
        assert!(lock.trouble.is_some(), "a shut lock says why");
    }

    #[test]
    fn pressing_unlock_asks_again() {
        let shared = snapshot();
        let alive = AtomicBool::new(true);
        let proof = Latch::default();
        let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // The window's half, from a thread: the first answer is a refusal, and
        // the person presses UNLOCK, and the second answer is a proof.
        let pressing = Arc::clone(&shared);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(TICK);
                let mut snapshot =
                    pressing.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                if snapshot.lock.state == LockState::Shut {
                    snapshot.lock.asked_again = true;
                    return;
                }
            }
        });

        let counter = Arc::clone(&asked);
        assert!(stand_guard(&shared, &alive, &proof, move || {
            if counter.fetch_add(1, Ordering::Relaxed) == 0 {
                Presence::Refused
            } else {
                Presence::Proved
            }
        }));
        assert_eq!(asked.load(Ordering::Relaxed), 2, "asked once, refused, asked again");
        assert_eq!(state(&shared).state, LockState::Open);
    }

    #[test]
    fn a_console_already_unlocked_does_not_ask_when_another_machine_is_opened() {
        let shared = snapshot();
        let alive = AtomicBool::new(true);
        let proof = Latch::default();
        proof.prove();
        assert!(stand_guard(&shared, &alive, &proof, || {
            panic!("a proved console must not raise a second sheet")
        }));
        assert_eq!(state(&shared).state, LockState::Open);
    }

    #[test]
    fn a_machine_that_cannot_be_asked_stays_shut_rather_than_opening() {
        // The fail-closed rule, asserted where it matters. `Unavailable` is what
        // a platform with no presence check answers, and it must connect nothing.
        let shared = snapshot();
        let alive = Arc::new(AtomicBool::new(true));
        let proof = Latch::default();
        let closing = Arc::clone(&alive);
        std::thread::spawn(move || {
            std::thread::sleep(TICK * 3);
            closing.store(false, Ordering::Relaxed);
        });
        assert!(!stand_guard(&shared, &alive, &proof, || Presence::Unavailable(
            "no sensor on this computer".into()
        )));
        assert_eq!(state(&shared).trouble.as_deref(), Some("no sensor on this computer"));
    }

    #[test]
    fn a_window_closed_while_the_sheet_stands_ends_the_gate() {
        let shared = snapshot();
        let alive = Arc::new(AtomicBool::new(true));
        let proof = Latch::default();
        let closing = Arc::clone(&alive);
        std::thread::spawn(move || {
            std::thread::sleep(TICK * 2);
            closing.store(false, Ordering::Relaxed);
        });
        // A sheet nobody ever answers: the asking thread sleeps far longer than
        // the window lasts.
        let began = std::time::Instant::now();
        assert!(!stand_guard(&shared, &alive, &proof, || {
            std::thread::sleep(Duration::from_secs(30));
            Presence::Proved
        }));
        assert!(began.elapsed() < Duration::from_secs(5), "the gate waited for the sheet");
    }
}
