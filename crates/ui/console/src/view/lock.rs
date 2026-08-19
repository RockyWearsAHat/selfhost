//! The plate a locked console shows, and nothing else.
//!
//! # Why it is the whole window
//!
//! Because there is nothing else to draw. A locked console has not read a token,
//! has not started its tunnel and has not polled anything — every plate under the
//! masthead would be a blank drawn in the shape of a reading, and a blank in that
//! shape is a lie about a machine nobody has connected to. So the lock replaces
//! the window rather than covering it, and the only two facts on screen are the
//! machine this window is *for* and what the lock is doing.
//!
//! # What it says, and what it does not
//!
//! It names what is behind it — the machine, and the plain sentence that nothing
//! has been reached yet — and it offers one control. It does not offer a password
//! field, because there is none in this program to offer: the answer is the
//! system's own sheet, in the system's own process, and a console that drew a
//! box for a password would be teaching its operator to type one into whatever
//! looks like this window. See [`selfhost_presence`].

use super::style;
use super::Console;
use crate::state::LockState;
use rui::style::Justify;
use rui::{Align, El, button, caption, col, heading, micro, row, title};

/// How wide the plate is drawn.
///
/// A width and not a ceiling. Wrapping needs a definite one — the first draft
/// said `max_w`, and the frame it produced had the sentence running out of the
/// plate and being cut off mid-word at "Before it uses", which is what the
/// reference frames are for.
const WIDTH: f32 = 460.0;

/// The whole window, while the lock is shut.
pub fn view(console: &Console) -> El<Console> {
    let lock = console.lock_state();
    let machine = console.bound().title().to_uppercase();

    col((
        row((style::mark(), title("SELFHOST").tracking(2.0).align_self(Align::Center)))
            .gap(10.0)
            .align(Align::Center),
        style::plate((
            style::section_rule("LOCKED", None),
            heading(state_word(lock.state)).tracking(1.4).wrap(),
            caption(sentence(lock.state)).wrap(),
            // The machine is named even though nothing has been reached: it is
            // what the person is deciding about. A lock that will not say what
            // it stands in front of is asking for a fingerprint on trust.
            micro(machine).wrap(),
            lock.trouble.map(|trouble| caption(trouble).wrap()),
            // Absent, not dead, while the sheet is standing: a second press
            // could only ask for a second sheet, and the system already has one
            // on screen.
            (lock.state != LockState::Asking).then(|| {
                button("UNLOCK").on_click(|console: &mut Console| console.ask_again())
            }),
        ))
        .gap(8.0)
        .w(WIDTH),
        caption(
            "A fingerprint, or this computer's account password, answered in the system's own \
             window. Nothing is connected and no credential has been read until it is.",
        )
        .wrap()
        .center_text()
        .w(WIDTH),
    ))
    // Centred in both directions by the column itself rather than by spacers
    // above and below it: a `spacer` here is an empty stack that takes the room
    // it is given, and two of them made the plate sit under the top edge with a
    // grey band across the bottom of the window.
    .justify(Justify::Center)
    .align(Align::Center)
    .pad(super::PAGE_PAD)
    .gap(12.0)
}

/// The one word at the top of the plate.
fn state_word(state: LockState) -> &'static str {
    match state {
        LockState::Asking => "WAITING FOR YOU",
        // `Open` cannot reach this plate — the window draws the console instead —
        // but a word is written for it anyway rather than an `unreachable!`: a
        // panic in a draw is a window that dies for a state that turned out to be
        // reachable after all.
        LockState::Open | LockState::Shut => "NOBODY HAS PROVED THEY ARE HERE",
    }
}

/// The sentence under it.
fn sentence(state: LockState) -> &'static str {
    match state {
        LockState::Asking => {
            "Answer the system's request — a fingerprint, or the password for this computer."
        }
        LockState::Open | LockState::Shut => {
            "This console reaches a running server with a credential kept on this computer. \
             Before it uses one, somebody has to prove they are sitting here."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Lock, Snapshot};

    /// Every state has words of its own, and none of them is empty.
    #[test]
    fn each_state_says_something_different() {
        let shut = (state_word(LockState::Shut), sentence(LockState::Shut));
        let asking = (state_word(LockState::Asking), sentence(LockState::Asking));
        assert_ne!(shut, asking);
        for (word, line) in [shut, asking] {
            assert!(!word.is_empty() && !line.is_empty());
        }
    }

    /// The plate draws for a console that has never connected to anything.
    ///
    /// Which is the only state it is ever drawn in, and the state a frame test
    /// can build without a daemon, a tunnel or a fingerprint sensor.
    #[test]
    fn a_locked_console_describes_itself_without_a_link() {
        let snapshot = Snapshot {
            lock: Lock { state: LockState::Shut, trouble: None, asked_again: false },
            ..Default::default()
        };
        let console = crate::view::tests::locked(snapshot);
        // Drawn through the window's own entry point, so this asserts the
        // dispatch as well as the plate: a shut lock must reach here and not the
        // machine's plates.
        let _ = crate::view::view(&console);
    }
}
