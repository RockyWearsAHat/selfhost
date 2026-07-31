//! Developer reload: getting a rebuilt program back where it was.
//!
//! Off unless the crate is built with `--features reload`. Nothing in this
//! module is compiled into a release build, and no application pays anything
//! for its existence.
//!
//! ```text
//! cargo run -p rui --features reload --example counter
//! # then, in another terminal, edit the example and:
//! cargo build -p rui --features reload --example counter
//! ```
//!
//! The window notices that the file it is running from has changed, saves
//! everything worth keeping, and starts the new build in its own place.
//!
//! # It is a restart, not hot module replacement
//!
//! Nothing is patched into a running process. The program saves its state,
//! replaces itself with the new executable, and reads the state back. Say that
//! plainly, because the difference shows: the window closes and opens, and any
//! work that was in flight — a thread, an open socket, a file being written —
//! is gone unless the application's own `save` carried it.
//!
//! What a restart buys instead is that it survives *any* edit. A change to a
//! layout rule, a widget, the renderer, or a `struct` field all reload the same
//! way, because the new build is a whole program and not a fragment being
//! reconciled with an old one. That is worth more here than true replacement
//! would be: a Rust edit costs a compile either way, and this needs no dynamic
//! linking, no stable ABI, and no `unsafe`.
//!
//! # Why it is this cheap
//!
//! A view is a plain `fn(&S) -> El<S>` and this library keeps no state of its
//! own but [`Memory`], which holds the interaction and nothing about what is on
//! screen. So there is no widget tree to rebuild, nothing to reconcile, and no
//! migration to write: restore the state, describe a frame from it, and the
//! interface is right by construction.
//!
//! # What crosses the restart
//!
//! - **The application's state**, exactly as far as its own `save` and
//!   `restore` carry it. This library never learns what `S` is, which is why it
//!   needs no serialisation dependency — see [`crate::App::reloadable`].
//! - **Scroll offsets and the keyboard's focus**, by *position in the frame's
//!   traversal*: the element that was scrolled is the nth element the frame
//!   described, and the nth element of the new build's frame is scrolled to
//!   match. Identity cannot be used, because an [`Id`] is a hash of an
//!   element's path through the tree and the edit being reloaded is quite
//!   likely the thing that changed that path. Position is the same guess a
//!   person makes, and it is right whenever the edit was below or beside the
//!   list rather than above it.
//!
//! # What does not
//!
//! The pointer's hover, what was being pressed, caret offsets within a field,
//! how far each animation had eased, and anything the platform owned — the
//! window's size and position, whether it was focused. A restarted window opens
//! at its declared size. The first frame after a restart is described before
//! the scroll offsets are known, so a scrolled list jumps into place on the
//! frame after it.
//!
//! # Nothing here reads a clock
//!
//! The trigger is a comparison of two modification times that the filesystem
//! reported, never a question about what time it is now. [`Memory`] is still
//! told how long a frame took and still never asks, so an animation stays as
//! assertable in a test as it was — and a test cannot observe this module at
//! all, because the watch is armed by [`crate::App::run`] and by nothing else.
//! [`crate::App::render`] and [`crate::testing::Harness`] never arm it.

use crate::app::App;
use crate::memory::{Id, Memory};
use crate::shell::{Error, LoadedFonts, WindowOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

/// The environment variable a restarted program is told its handoff file
/// through.
///
/// Set on the new process and nowhere else, so a program started by hand never
/// picks up a handoff meant for another one. Worth knowing if the program is
/// run under something that filters the environment — a debugger, `sudo`, a
/// wrapper script — because a restart that loses this variable is a restart
/// that comes back with a fresh state.
pub const HANDOFF: &str = "RUI_RELOAD_HANDOFF";

/// The first line of a handoff file: what it is, and which version of this.
const MAGIC: &str = "rui-reload 1";

/// How an application writes its own state down, supplied by the application.
///
/// The whole of what this library knows about `S`: it asks for bytes and hands
/// the same bytes back, and never looks inside them.
pub(crate) type Save<S> = Box<dyn Fn(&S) -> Vec<u8>>;

/// What an application needs to reload itself, once it has asked to.
///
/// Held by [`App`] behind the `reload` feature. Inert until [`Reload::arm`],
/// which only a window run performs.
pub(crate) struct Reload<S> {
    /// How the application writes itself down.
    save: Save<S>,
    /// Interaction state read from a handoff, waiting for a described frame to
    /// apply it to.
    pending: Option<Interaction>,
    /// The executable being watched, once a window is running it.
    watch: Option<Watch>,
    /// Whether a restart has been decided, which is what stops the loop.
    restarting: bool,
}

/// The executable this program is running from, and what it looked like.
struct Watch {
    /// The file to compare against.
    exe: PathBuf,
    /// Where this run would leave a handoff for its successor.
    handoff: PathBuf,
    /// What the executable was when the run began, or when a change was last
    /// acted on.
    stamp: Stamp,
    /// A change seen once and not yet acted on.
    ///
    /// A build writes its output over some non-zero span of time, and a program
    /// that restarted the instant the file first differed would restart into
    /// half a binary. Requiring the same reading twice costs one poll and
    /// removes that race.
    settling: Option<Stamp>,
}

/// How to start the program again, kept outside the application so it survives
/// the application being dropped.
pub(crate) struct Relaunch {
    /// The file to run, which by then is the new build.
    exe: PathBuf,
    /// Where the run that just ended would have left its state.
    handoff: PathBuf,
}

/// What a file was, as far as a rebuild can be told from outside it.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    /// When the filesystem says it last changed.
    ///
    /// `None` on a filesystem that does not record one, where a rebuild is
    /// noticed only if it changed the size. That is a real gap and it is the
    /// filesystem's, not something this can work around.
    modified: Option<SystemTime>,
    /// How many bytes it holds.
    len: u64,
}

/// The interaction state carried across a restart.
///
/// Positions in the frame's traversal rather than identifiers; see this
/// module's header for why.
struct Interaction {
    /// Which element had the keyboard.
    focus: Option<usize>,
    /// How far each scrolled element was scrolled, in logical units.
    scroll: Vec<(usize, f32)>,
}

/// Prepares an application to reload itself, restoring the previous run's state
/// if this process is a restart of one.
///
/// Answers the reload state to hold, and the state to show if there was one to
/// read. Errors rather than starting fresh: a developer whose restore is broken
/// needs to be told, not handed an empty window and left to wonder.
pub(crate) fn begin<S>(
    save: Save<S>,
    restore: &dyn Fn(&[u8]) -> Result<S, String>,
) -> Result<(Reload<S>, Option<S>), Error> {
    let mut reload =
        Reload { save, pending: None, watch: None, restarting: false };
    let Some(path) = std::env::var_os(HANDOFF) else {
        return Ok((reload, None));
    };
    let (interaction, saved) = take_handoff(Path::new(&path))?;
    let state = restore(&saved).map_err(|message| {
        malformed(format!("the application could not read its own saved state: {message}"))
    })?;
    reload.pending = Some(interaction);
    Ok((reload, Some(state)))
}

/// Runs `app` in a window, and starts the program again if it asked to.
///
/// The same call [`crate::shell::run`] would have been, wrapped. Everything the
/// reload does happens either side of that: the watch is armed before the
/// window opens, and the successor is started after it has closed — never from
/// inside a frame, so a window is always taken down properly first.
pub(crate) fn run<S>(
    options: WindowOptions,
    fonts: LoadedFonts,
    mut app: App<S>,
) -> Result<(), Error> {
    let relaunch = match app.reload.as_mut() {
        Some(reload) => Some(reload.arm()?),
        None => None,
    };
    crate::shell::run(options, fonts, app)?;
    match relaunch {
        Some(relaunch) => relaunch.perform(),
        None => Ok(()),
    }
}

impl<S> Reload<S> {
    /// Begins watching the file this program is running from.
    ///
    /// Answers how to start it again once this run is over.
    fn arm(&mut self) -> Result<Relaunch, Error> {
        let exe = std::env::current_exe().map_err(Error::Io)?;
        let stamp = Stamp::of(&exe).map_err(Error::Io)?;
        let handoff = handoff_path(&exe);
        // A run that died between saving and restarting leaves a file behind,
        // and this process could be given the same identifier later. Clearing
        // it makes the file mean exactly one thing: *this* run asked to
        // restart.
        match std::fs::remove_file(&handoff) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::Io(error)),
        }
        self.watch =
            Some(Watch { exe: exe.clone(), handoff: handoff.clone(), stamp, settling: None });
        Ok(Relaunch { exe, handoff })
    }

    /// Whether a window run has armed this, which is the only thing that makes
    /// a frame do any of the work below.
    pub(crate) fn is_armed(&self) -> bool {
        self.watch.is_some()
    }

    /// Whether a restart has been decided, and the loop should therefore stop.
    pub(crate) fn is_restarting(&self) -> bool {
        self.restarting
    }

    /// Restores a previous run's interaction state onto the frame just
    /// described, and looks for a new build to restart into.
    ///
    /// `order` is every element the frame described, parents before children —
    /// the traversal both halves of the interaction state are indexed by.
    pub(crate) fn after_frame(&mut self, state: &S, memory: &mut Memory, order: &[Id]) {
        if let Some(interaction) = self.pending.take() {
            interaction.apply(memory, order);
            // What was just changed is not what was just drawn. The same
            // request a handler makes, for the same reason.
            memory.request_frame();
        }
        if self.restarting {
            return;
        }
        let Some(watch) = self.watch.as_mut() else {
            return;
        };
        if !watch.rebuilt() {
            return;
        }
        let interaction = Interaction::capture(memory, order);
        let saved = (self.save)(state);
        match write_handoff(&watch.handoff, &interaction, &saved) {
            Ok(()) => self.restarting = true,
            // Said here rather than returned, because a frame has nowhere to
            // return to and the run is not over. Nothing has been lost — the
            // program is still holding the state it failed to write down — so
            // the honest outcome is to keep running the old build and say why.
            // The next rebuild tries again.
            Err(error) => eprintln!(
                "rui: could not save state for a reload, so this window is still \
                 running the previous build: {error}"
            ),
        }
    }
}

impl Watch {
    /// Whether the file this program is running from has become a different
    /// one, and has finished becoming it.
    ///
    /// A file that cannot be read is a build partway through replacing it, not
    /// a failure: the answer is simply "not yet", and the next frame asks
    /// again.
    fn rebuilt(&mut self) -> bool {
        let Ok(now) = Stamp::of(&self.exe) else {
            return false;
        };
        if now == self.stamp {
            self.settling = None;
            return false;
        }
        if self.settling == Some(now) {
            // Taken as handled whichever way the restart goes, so a build that
            // cannot be saved for is not asked about on every frame after.
            self.stamp = now;
            self.settling = None;
            return true;
        }
        self.settling = Some(now);
        false
    }
}

impl Stamp {
    /// What the file at `path` currently is.
    fn of(path: &Path) -> io::Result<Self> {
        let file = std::fs::metadata(path)?;
        Ok(Self { modified: file.modified().ok(), len: file.len() })
    }
}

impl Relaunch {
    /// Starts the program again, if the run that just ended asked to.
    ///
    /// The handoff file is the whole of the question: a window that was simply
    /// closed leaves none, and nothing happens.
    fn perform(self) -> Result<(), Error> {
        if !self.handoff.exists() {
            return Ok(());
        }
        let mut command = Command::new(&self.exe);
        command.args(std::env::args_os().skip(1)).env(HANDOFF, &self.handoff);
        start(command)
    }
}

/// Replaces this process with `command`.
///
/// `exec` returns only when it failed, so everything after it is the error
/// path. Replacing rather than spawning keeps the terminal, the exit status,
/// and the parent process the developer started this from — `cargo run` waits
/// for the new build exactly as it waited for the old one.
#[cfg(unix)]
fn start(mut command: Command) -> Result<(), Error> {
    use std::os::unix::process::CommandExt;
    Err(Error::Io(command.exec()))
}

/// Starts `command` and lets this process end.
///
/// Windows has no way for a process to become another one, so the successor is
/// a child and this run returns normally into whatever started it.
#[cfg(not(unix))]
fn start(mut command: Command) -> Result<(), Error> {
    command.spawn().map_err(Error::Io)?;
    Ok(())
}

impl Interaction {
    /// What is worth carrying out of the frame just described.
    ///
    /// Only areas actually scrolled away from the top are recorded, so the file
    /// is a handful of lines rather than one per element.
    fn capture(memory: &Memory, order: &[Id]) -> Self {
        let focused = memory.focused();
        Self {
            focus: focused.and_then(|id| order.iter().position(|&other| other == id)),
            scroll: order
                .iter()
                .enumerate()
                .filter_map(|(index, &id)| {
                    let offset = memory.scroll_offset(id);
                    (offset != 0.0).then_some((index, offset))
                })
                .collect(),
        }
    }

    /// Puts it back onto the frame the new build has just described.
    ///
    /// Positions the new frame does not reach are dropped: the edit being
    /// reloaded may have removed the element that was scrolled, and there is
    /// nothing to restore it onto.
    fn apply(&self, memory: &mut Memory, order: &[Id]) {
        for &(index, offset) in &self.scroll {
            if let Some(&id) = order.get(index) {
                memory.set_scroll_offset(id, offset);
            }
        }
        if let Some(&id) = self.focus.and_then(|index| order.get(index)) {
            memory.set_focus(Some(id));
        }
    }
}

/// Where this run would leave a handoff for its successor.
///
/// Named after the program and this process, so two programs reloading at once
/// cannot read each other's, and so a file left behind by a run that died can
/// be recognised and cleared by the run that owns the name next.
fn handoff_path(exe: &Path) -> PathBuf {
    let name = exe.file_name().unwrap_or(std::ffi::OsStr::new("rui"));
    let name = name.to_string_lossy();
    std::env::temp_dir().join(format!("rui-reload-{name}-{}.state", std::process::id()))
}

/// Writes the interaction state and the application's own bytes as one file.
///
/// Text lines up to a blank one, then whatever the application wrote, byte for
/// byte. The application's half is last and unescaped so that it can be
/// anything at all — this library never looks inside it.
fn write_handoff(path: &Path, interaction: &Interaction, saved: &[u8]) -> io::Result<()> {
    let mut header = String::from(MAGIC);
    header.push('\n');
    if let Some(index) = interaction.focus {
        header.push_str(&format!("focus {index}\n"));
    }
    for (index, offset) in &interaction.scroll {
        header.push_str(&format!("scroll {index} {offset}\n"));
    }
    header.push('\n');

    let mut bytes = header.into_bytes();
    bytes.extend_from_slice(saved);
    std::fs::write(path, bytes)
}

/// Reads a handoff file, and removes it.
///
/// Removed whether or not it parses, because it describes exactly one restart:
/// leaving it would let a later run restore a window it has nothing to do with.
fn take_handoff(path: &Path) -> Result<(Interaction, Vec<u8>), Error> {
    let bytes = std::fs::read(path).map_err(Error::Io)?;
    std::fs::remove_file(path).map_err(Error::Io)?;
    parse_handoff(&bytes)
}

/// Splits a handoff file into the interaction state and the application's own
/// bytes.
fn parse_handoff(bytes: &[u8]) -> Result<(Interaction, Vec<u8>), Error> {
    let blank = bytes
        .windows(2)
        .position(|pair| pair == b"\n\n")
        .ok_or_else(|| malformed("no blank line between the two halves of the handoff"))?;
    let (header, payload) = bytes.split_at(blank);
    let header = std::str::from_utf8(header)
        .map_err(|_| malformed("the interaction state is not text"))?;

    let mut lines = header.lines();
    if lines.next() != Some(MAGIC) {
        return Err(malformed(format!("not a handoff file: expected {MAGIC:?} on its first line")));
    }

    let mut interaction = Interaction { focus: None, scroll: Vec::new() };
    for line in lines {
        let mut words = line.split(' ');
        match (words.next(), words.next(), words.next()) {
            (Some("focus"), Some(index), None) => interaction.focus = Some(index_of(index)?),
            (Some("scroll"), Some(index), Some(offset)) => {
                let offset = offset
                    .parse::<f32>()
                    .map_err(|_| malformed(format!("{offset:?} is not a scroll offset")))?;
                interaction.scroll.push((index_of(index)?, offset));
            }
            _ => return Err(malformed(format!("{line:?} is not a line of a handoff file"))),
        }
    }
    Ok((interaction, payload[2..].to_vec()))
}

/// A position in a frame's traversal, as written in a handoff file.
fn index_of(word: &str) -> Result<usize, Error> {
    word.parse().map_err(|_| malformed(format!("{word:?} is not a position in a frame")))
}

/// A handoff file that could not be understood.
///
/// [`Error::Io`] because that is what this is: a file that could not be read.
fn malformed(message: impl Into<String>) -> Error {
    Error::Io(io::Error::new(io::ErrorKind::InvalidData, message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What is written comes back, which is the whole contract of the file.
    #[test]
    fn a_handoff_round_trips() {
        let interaction =
            Interaction { focus: Some(7), scroll: vec![(2, -120.5), (9, 33.25)] };
        let mut bytes = Vec::new();
        let path = std::env::temp_dir().join("rui-reload-round-trip.state");
        write_handoff(&path, &interaction, b"count=3\nname=\xffnot utf8").unwrap();
        bytes.extend_from_slice(&std::fs::read(&path).unwrap());
        std::fs::remove_file(&path).unwrap();

        let (read, payload) = parse_handoff(&bytes).unwrap();
        assert_eq!(read.focus, Some(7));
        assert_eq!(read.scroll, vec![(2, -120.5), (9, 33.25)]);
        assert_eq!(payload, b"count=3\nname=\xffnot utf8");
    }

    /// A frame with nothing scrolled and nothing focused still round-trips.
    #[test]
    fn an_empty_interaction_round_trips() {
        let path = std::env::temp_dir().join("rui-reload-empty.state");
        write_handoff(&path, &Interaction { focus: None, scroll: Vec::new() }, b"").unwrap();
        let bytes = std::fs::read(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        let (read, payload) = parse_handoff(&bytes).unwrap();
        assert_eq!(read.focus, None);
        assert!(read.scroll.is_empty());
        assert!(payload.is_empty());
    }

    /// A rebuild is acted on once it has stopped changing, and what it saves is
    /// what the frame was showing.
    #[test]
    fn a_rebuild_is_noticed_and_carried_over() {
        let exe = std::env::temp_dir().join("rui-reload-test-exe");
        let handoff = std::env::temp_dir().join("rui-reload-test-exe.state");
        std::fs::write(&exe, b"the first build").unwrap();

        let mut reload = Reload {
            save: Box::new(|count: &i32| count.to_string().into_bytes()),
            pending: None,
            watch: Some(Watch {
                exe: exe.clone(),
                handoff: handoff.clone(),
                stamp: Stamp::of(&exe).unwrap(),
                settling: None,
            }),
            restarting: false,
        };

        let order = vec![Id::new("first"), Id::new("second")];
        let mut memory = Memory::new();
        memory.set_focus(Some(order[0]));
        memory.set_scroll_offset(order[1], -40.5);

        reload.after_frame(&3, &mut memory, &order);
        assert!(!reload.is_restarting(), "nothing has been rebuilt");

        std::fs::write(&exe, b"the second build, which is longer").unwrap();
        reload.after_frame(&3, &mut memory, &order);
        assert!(!reload.is_restarting(), "a change is given a frame to settle");
        reload.after_frame(&3, &mut memory, &order);
        assert!(reload.is_restarting(), "and is acted on once it has");

        let (interaction, saved) = take_handoff(&handoff).unwrap();
        std::fs::remove_file(&exe).unwrap();
        assert_eq!(saved, b"3", "the application's own state, as it wrote it");
        assert_eq!(interaction.focus, Some(0));
        assert_eq!(interaction.scroll, vec![(1, -40.5)]);

        // And the new build's frame, whose elements are different elements
        // entirely, is put back where the old one was.
        let rebuilt = vec![Id::new("rebuilt first"), Id::new("rebuilt second")];
        let mut fresh = Memory::new();
        interaction.apply(&mut fresh, &rebuilt);
        assert_eq!(fresh.focused(), Some(rebuilt[0]));
        assert_eq!(fresh.scroll_offset(rebuilt[1]), -40.5);
    }

    /// Anything else says so rather than being restored as a blank interface.
    #[test]
    fn something_else_entirely_is_refused() {
        assert!(parse_handoff(b"hello\n\nworld").is_err());
        assert!(parse_handoff(b"rui-reload 1\nfocus\n\n").is_err());
        assert!(parse_handoff(b"rui-reload 1\nscroll 2 sideways\n\n").is_err());
        assert!(parse_handoff(b"rui-reload 1\n").is_err());
    }
}
