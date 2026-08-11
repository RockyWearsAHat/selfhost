//! The machines this console is paired with, and which one it opened last.
//!
//! # Why the console remembers anything at all
//!
//! Before this, it did not. The server was named by `--ssh` on the command line
//! and nowhere else, so a console launched from the Dock — which is how an
//! application is normally opened — had no server, fell back to looking for a
//! local daemon's token, and reported that it could not find one. That report
//! was accurate and useless: the operator's machine is reached over SSH, and the
//! console had just thrown away the only place that fact could have been kept.
//!
//! # Paired, and exclusively bound
//!
//! A machine is *paired* once: named, given an SSH destination and whatever key
//! and port that destination needs, and then verified — a pairing that cannot
//! read the daemon's token over that connection is refused rather than saved, so
//! an entry in this file is a connection that worked at least once. The console
//! is bound to exactly one paired machine at a time; the overview of all of them
//! is a step back from the machine, not a tab beside its plates.
//!
//! # What is kept here, and what is deliberately not
//!
//! A destination, a port, a key *path*, and a remote token *path*. **No token
//! and no key material.** The token is fetched over SSH on every open, because
//! the daemon rewrites it whenever it restarts and a copy kept here would be a
//! stale secret that produces a confusing `401` instead of a reconnection. The
//! file is still written `0600`: it names an operator's servers and the key each
//! one answers to, which is a map worth not leaving world-readable even though
//! nothing in it opens a door by itself.
//!
//! # The format
//!
//! Written by hand rather than through a serialiser, and the reason is the same
//! one the rest of this project gives: the file is four fields and a name, the
//! parser is fifty lines that can be read in one sitting, and the console does
//! not otherwise link a serialisation library at all. It is a header line naming
//! the machine opened last, then one block per machine:
//!
//! ```text
//! last = alex-desktop
//!
//! [alex-desktop]
//! destination = alex@192.168.1.8
//! port = 9191
//! identity = /Users/alex/.ssh/alexdesktop_ed25519
//! token = data/admin.token
//! ```
//!
//! Unknown keys are ignored rather than refused, so a file written by a later
//! version opens here instead of locking the operator out of their own console.

use std::path::{Path, PathBuf};

/// What the file is called inside the platform's state directory.
const FILE_NAME: &str = "machines";

/// The control port a paired machine is assumed to serve on.
///
/// The daemon's own default, repeated here rather than imported so that pairing
/// a machine never depends on this console having parsed that machine's config —
/// which it cannot do, since reading it requires the connection being set up.
pub const DEFAULT_PORT: u16 = 9191;

/// Where the daemon writes its token on the server, relative to the login
/// directory. The same default [`crate::tunnel::DEFAULT_REMOTE_TOKEN`] states,
/// and the value a pairing gets when the operator does not override it.
pub const DEFAULT_REMOTE_TOKEN: &str = crate::tunnel::DEFAULT_REMOTE_TOKEN;

/// The longest a machine name may be, so one cannot push the interface around.
const MAX_NAME: usize = 32;

/// One machine this console is paired with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Machine {
    /// What the operator calls it. Also the key in the file and the word the
    /// overview draws, so it is constrained the way every other id in this
    /// project is: lowercase letters, digits and hyphens.
    pub name: String,
    /// The server as `ssh` takes it — `host` or `user@host`.
    pub destination: String,
    /// The port `sshd` listens on, when it is not 22.
    pub ssh_port: Option<u16>,
    /// A private key to use, when the agent's default is not the right one.
    pub identity: Option<PathBuf>,
    /// The control port the daemon serves on over there, forwarded to the same
    /// port here.
    pub port: u16,
    /// Where that machine's daemon writes its token, relative to the login
    /// directory.
    pub remote_token: String,
}

impl Machine {
    /// A machine with the defaults every field but the first two can take.
    pub fn new(name: impl Into<String>, destination: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            destination: destination.into(),
            ssh_port: None,
            identity: None,
            port: DEFAULT_PORT,
            remote_token: DEFAULT_REMOTE_TOKEN.to_owned(),
        }
    }

    /// The tunnel this machine is reached through.
    ///
    /// The one place a paired machine becomes a connection, so that the store
    /// and the tunnel cannot drift apart on what a field meant.
    pub fn tunnel(&self) -> crate::tunnel::TunnelSpec {
        let mut spec = crate::tunnel::TunnelSpec::new(self.destination.clone(), self.port);
        spec.ssh_port = self.ssh_port;
        spec.identity = self.identity.clone();
        spec
    }

    /// Every reason this machine could not be saved, or an empty list.
    ///
    /// Returns all of them rather than the first: a form that reports one
    /// problem per attempt is a form filled in three times.
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.name.is_empty() {
            problems.push("a machine needs a name".into());
        } else if self.name.len() > MAX_NAME {
            problems.push(format!("the name is longer than {MAX_NAME} characters"));
        } else if !self
            .name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            problems.push("a name may hold lowercase letters, digits and hyphens".into());
        }
        if self.destination.trim().is_empty() {
            problems.push("a machine needs an SSH destination, like alex@192.168.1.8".into());
        } else if self.destination.split_whitespace().count() > 1 {
            problems.push("the destination is one word: [user@]host".into());
        } else if self.destination.starts_with('-') {
            problems.push("the destination looks like an option, not a server".into());
        }
        if self.port == 0 {
            problems.push("the control port cannot be 0".into());
        }
        if self.remote_token.trim().is_empty() {
            problems.push("the remote token path cannot be empty".into());
        }
        problems
    }
}

/// Every paired machine, and which one was opened last.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Machines {
    /// In the order they were paired, which is the order the overview draws.
    entries: Vec<Machine>,
    /// The name of the machine to open on launch, when it is still paired.
    last: Option<String>,
}

impl Machines {
    /// The paired machines, in the order the overview draws them.
    pub fn entries(&self) -> &[Machine] {
        &self.entries
    }

    /// Whether nothing is paired yet — the state that opens the overview.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The machine to open on launch.
    ///
    /// The one opened last if it is still paired, otherwise the first, otherwise
    /// nothing. Falling through rather than returning `None` for a forgotten
    /// name is what stops a `forget` from leaving the console with no way in but
    /// the overview it would then be stuck on.
    pub fn opening(&self) -> Option<&Machine> {
        self.last
            .as_deref()
            .and_then(|name| self.get(name))
            .or_else(|| self.entries.first())
    }

    /// One machine by name.
    pub fn get(&self, name: &str) -> Option<&Machine> {
        self.entries.iter().find(|machine| machine.name == name)
    }

    /// Adds a machine, or replaces the one already holding that name.
    ///
    /// Replacing rather than refusing: re-pairing is how an operator corrects a
    /// key path or a moved address, and making them forget the machine first
    /// would mean the correction is two steps, the first of which loses the
    /// entry if the second fails.
    pub fn pair(&mut self, machine: Machine) {
        match self.entries.iter_mut().find(|held| held.name == machine.name) {
            Some(held) => *held = machine,
            None => self.entries.push(machine),
        }
    }

    /// Removes a machine, and any memory of having opened it.
    pub fn forget(&mut self, name: &str) {
        self.entries.retain(|machine| machine.name != name);
        if self.last.as_deref() == Some(name) {
            self.last = None;
        }
    }

    /// Records that this machine is the one now open.
    pub fn opened(&mut self, name: &str) {
        if self.get(name).is_some() {
            self.last = Some(name.to_owned());
        }
    }

    /// Reads the store, treating "no file" as "nothing paired yet".
    ///
    /// A missing file is the first-run state and not a failure; anything else —
    /// a directory in its place, a permission refusal — is reported, because a
    /// store that silently reads as empty would offer to pair a machine that is
    /// already paired and then fail to save it.
    pub fn load(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Self::parse(&text)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(error) => Err(format!("cannot read {}: {error}", path.display())),
        }
    }

    /// Writes the store, creating the directory and narrowing the file to its
    /// owner.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        std::fs::write(path, self.render())
            .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
        restrict(path).map_err(|error| {
            format!("cannot narrow {} to its owner: {error}", path.display())
        })
    }

    /// The file's text.
    pub fn render(&self) -> String {
        let mut text = String::from("# selfhost console — paired machines\n");
        if let Some(last) = &self.last {
            text.push_str(&format!("last = {last}\n"));
        }
        for machine in &self.entries {
            text.push_str(&format!("\n[{}]\n", machine.name));
            text.push_str(&format!("destination = {}\n", machine.destination));
            if let Some(port) = machine.ssh_port {
                text.push_str(&format!("ssh_port = {port}\n"));
            }
            if let Some(identity) = &machine.identity {
                text.push_str(&format!("identity = {}\n", identity.display()));
            }
            text.push_str(&format!("port = {}\n", machine.port));
            text.push_str(&format!("token = {}\n", machine.remote_token));
        }
        text
    }

    /// Reads the file's text, ignoring what it does not understand.
    ///
    /// Total rather than fallible, and deliberately: every way this file can be
    /// malformed — a stray line, a port that is not a number, a block with no
    /// destination — has a reading that keeps the rest of the operator's
    /// machines working, and none of them is worth refusing to open the console
    /// over. A block that ends up without a destination is the one thing dropped,
    /// because it names no server and so cannot be opened or repaired from here.
    pub fn parse(text: &str) -> Self {
        let mut store = Self::default();
        let mut current: Option<Machine> = None;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(name) = line.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
                if let Some(machine) = current.take() {
                    store.finish(machine);
                }
                current = Some(Machine::new(name.trim(), ""));
                continue;
            }
            let Some((key, value)) = line.split_once('=') else { continue };
            let (key, value) = (key.trim(), value.trim());
            match (&mut current, key) {
                (None, "last") => store.last = Some(value.to_owned()),
                (Some(machine), "destination") => machine.destination = value.to_owned(),
                (Some(machine), "ssh_port") => machine.ssh_port = value.parse().ok(),
                (Some(machine), "identity") if !value.is_empty() => {
                    machine.identity = Some(PathBuf::from(value));
                }
                (Some(machine), "port") => {
                    if let Ok(port) = value.parse() {
                        machine.port = port;
                    }
                }
                (Some(machine), "token") if !value.is_empty() => {
                    machine.remote_token = value.to_owned();
                }
                _ => {}
            }
        }
        if let Some(machine) = current {
            store.finish(machine);
        }
        store
    }

    /// Keeps a parsed block if it names a server.
    fn finish(&mut self, machine: Machine) {
        if !machine.name.is_empty() && !machine.destination.is_empty() {
            self.entries.push(machine);
        }
    }
}

/// The store's path on this machine, beside the daemon's own note.
pub fn default_path() -> Option<PathBuf> {
    Some(selfhost_config::home::state_directory()?.join(FILE_NAME))
}

/// Narrows a file to its owner, where the platform has such a concept.
#[cfg(unix)]
fn restrict(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// The same, on platforms whose permissions do not work that way.
#[cfg(not(unix))]
fn restrict(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paired() -> Machines {
        let mut store = Machines::default();
        let mut machine = Machine::new("alex-desktop", "alex@192.168.1.8");
        machine.identity = Some(PathBuf::from("/Users/alex/.ssh/alexdesktop_ed25519"));
        store.pair(machine);
        store.pair(Machine::new("home", "pi@192.168.1.20"));
        store.opened("alex-desktop");
        store
    }

    #[test]
    fn a_rendered_store_reads_back_identical() {
        let store = paired();
        assert_eq!(Machines::parse(&store.render()), store);
    }

    #[test]
    fn the_machine_opened_last_is_the_one_that_opens() {
        let mut store = paired();
        store.opened("home");
        assert_eq!(store.opening().map(|machine| machine.name.as_str()), Some("home"));
    }

    #[test]
    fn forgetting_the_last_machine_falls_through_to_the_first() {
        let mut store = paired();
        store.forget("alex-desktop");
        assert_eq!(store.opening().map(|machine| machine.name.as_str()), Some("home"));
    }

    #[test]
    fn a_store_with_nothing_paired_opens_nothing() {
        assert!(Machines::default().opening().is_none());
    }

    #[test]
    fn pairing_the_same_name_twice_corrects_it_rather_than_duplicating_it() {
        let mut store = paired();
        store.pair(Machine::new("home", "pi@192.168.1.21"));
        assert_eq!(store.entries().len(), 2);
        assert_eq!(store.get("home").expect("still paired").destination, "pi@192.168.1.21");
    }

    #[test]
    fn a_name_that_is_no_longer_paired_does_not_become_the_opening_one() {
        let mut store = Machines::parse("last = gone\n\n[home]\ndestination = pi@host\n");
        assert_eq!(store.opening().map(|machine| machine.name.as_str()), Some("home"));
        store.opened("gone");
        assert_eq!(store.opening().map(|machine| machine.name.as_str()), Some("home"));
    }

    #[test]
    fn a_block_naming_no_server_is_dropped_and_the_rest_survive() {
        let store = Machines::parse("[broken]\nport = 9191\n\n[home]\ndestination = pi@host\n");
        assert_eq!(store.entries().len(), 1);
        assert_eq!(store.entries()[0].name, "home");
    }

    #[test]
    fn an_unreadable_port_leaves_the_default_rather_than_dropping_the_machine() {
        let store = Machines::parse("[home]\ndestination = pi@host\nport = wobble\n");
        assert_eq!(store.entries()[0].port, DEFAULT_PORT);
    }

    #[test]
    fn a_key_from_a_later_version_is_ignored_rather_than_refused() {
        let store = Machines::parse("[home]\ndestination = pi@host\nfuture_thing = 4\n");
        assert_eq!(store.entries().len(), 1);
    }

    #[test]
    fn a_machine_becomes_the_tunnel_it_describes() {
        let mut machine = Machine::new("home", "pi@host");
        machine.ssh_port = Some(2222);
        machine.port = 9292;
        let spec = machine.tunnel();
        assert_eq!(spec.destination, "pi@host");
        assert_eq!(spec.ssh_port, Some(2222));
        assert_eq!(spec.local_port, 9292);
        assert_eq!(spec.remote_port, 9292);
    }

    #[test]
    fn a_good_machine_has_no_problems() {
        assert!(Machine::new("alex-desktop", "alex@192.168.1.8").problems().is_empty());
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let machine = Machine::new("Alex Desktop", "  ");
        let problems = machine.problems();
        assert_eq!(problems.len(), 2, "{problems:?}");
    }

    #[test]
    fn a_destination_that_looks_like_an_option_is_refused() {
        let machine = Machine::new("home", "-oProxyCommand=touch /tmp/pwned");
        assert!(!machine.problems().is_empty());
    }

    #[test]
    fn a_missing_file_is_the_first_run_state_and_not_a_failure() {
        let path = std::env::temp_dir().join("selfhost-machines-absent-test").join("machines");
        let _ = std::fs::remove_dir_all(path.parent().expect("a parent"));
        assert_eq!(Machines::load(&path).expect("a missing file loads"), Machines::default());
    }

    #[test]
    fn a_saved_store_loads_back_identical() {
        let directory =
            std::env::temp_dir().join(format!("selfhost-machines-{}", std::process::id()));
        let path = directory.join("machines");
        let store = paired();
        store.save(&path).expect("the store saves");
        assert_eq!(Machines::load(&path).expect("the store loads"), store);
        let _ = std::fs::remove_dir_all(&directory);
    }
}
