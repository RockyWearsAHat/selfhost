//! The names and rooms a person gave things, kept across restarts.
//!
//! A driver reports what a manufacturer's firmware calls a device: `RINCON_…`,
//! `Living Room (2)`, `Wyze Bulb Color`. A person calls it "the reading lamp"
//! and says it is in the bedroom. That second set of facts is the only thing in
//! this crate that no protocol can rediscover — unplug the speaker, reboot the
//! machine, rewrite every driver, and the name is still whatever the household
//! decided it was. So it lives in one file, owned by this module, and every
//! other part of the system reads it through [`Registry::apply`] rather than
//! keeping a copy.
//!
//! The overlay is deliberately partial. [`Entry::name`] and [`Entry::room`] are
//! `Option`s, and `apply` writes only the ones that are `Some`, because "the
//! person has not renamed this" and "the person renamed this to the empty
//! string" are different facts and a registry that flattened them would erase a
//! speaker's own name the first time somebody opened a settings panel and
//! closed it again.
//!
//! # The file format, and why it is hand-written
//!
//! `<data_dir>/home.registry` is a line-based text file. One device per line:
//!
//! ```text
//! # selfhost-home device registry — one device per line, %XX is a percent-escape
//! sonos:rincon_7828ca1491ae01400 name=Kitchen room=Kitchen hidden=0
//! wyze:ab12 name=Reading%20Lamp room=Bedroom hidden=1
//! ```
//!
//! The grammar, exactly:
//!
//! - A line is an **id** followed by zero or more `key=value` **fields**,
//!   separated by runs of ASCII spaces or tabs. Leading and trailing ASCII
//!   whitespace on the line is ignored, which is what lets a file hand-edited on
//!   Windows and its `\r` line endings load unchanged.
//! - The keys are `name`, `room` and `hidden`. `name` and `room` are absent when
//!   the person never set them — absence is `None`, and `name=` with nothing
//!   after it is `Some("")`, a different thing. `hidden` is `0` or `1` and is
//!   always written, so a reader never has to guess a default.
//! - Every id and every value is **percent-escaped**: any ASCII whitespace,
//!   ASCII control character, `%`, `=` or `#` becomes `%XX` over that
//!   character's UTF-8 bytes. Everything else, non-ASCII included, is written
//!   literally — so `Küche` and `Alex's Büro 🎧` stay readable in the file while
//!   a name containing a newline, a tab or an `=` cannot break the line or the
//!   field split. This is the whole reason for an escape scheme: a person naming
//!   a speaker `Kitchen = Loud` is not doing anything wrong.
//! - A line whose first non-blank character is `#` is a comment, and a blank
//!   line is nothing. The file writes its own header comment so that whoever
//!   opens it in an editor is told what they are looking at.
//! - Unknown keys are ignored rather than fatal, so a newer build that adds a
//!   field does not make this build refuse the file. They are dropped on the
//!   next save; that is the accepted cost of not carrying a bag of unparsed
//!   text around.
//! - The last line naming an id wins, because the natural hand-edit is to
//!   append.
//!
//! [`write_line`] and [`read_line`] are exact inverses over every [`Entry`],
//! and that is the property the tests at the bottom of this file defend.
//!
//! **Why not TOML, or JSON, or a serialisation crate.** This crate has no
//! `serde` dependency and must not gain one; the workspace's own
//! `selfhost-json` exists and would do, but it would make a preference file a
//! document with nesting, quoting and escaping rules far larger than the four
//! facts stored per device. The failure this avoids is the one where a person
//! opens the file to fix a typo and produces a parse error the whole dashboard
//! reports instead of a house. A line is the unit a person can see, a line is
//! the unit an editor can fix, and a line is the unit this parser throws away.
//!
//! # A corrupt line is skipped, never fatal
//!
//! [`Registry::parse`] drops any line it cannot read whole — a bad
//! percent-escape, a field without `=`, a `hidden` that is not `0` or `1` — and
//! keeps every other line. The alternative, refusing to load, means one mangled
//! byte in a *cosmetic preference file* takes the entire house offline: no
//! lights, no speakers, no page, because somebody's editor wrote a stray
//! character into a nickname. The blast radius of a skipped line is that one
//! device shows the name its protocol reported, which is precisely the state
//! the system is designed to be correct in.
//!
//! The unit dropped is the line and not the field, deliberately. Half-reading a
//! line would leave a device wearing a name the file no longer says it has, and
//! a *wrong* name is worse than a missing one: the missing one is visibly the
//! driver's, and the person renames it again in five seconds.
//!
//! # Why the save is atomic
//!
//! [`Registry::save`] writes a temporary file beside the target, flushes it to
//! the disk, and renames it over the target — a rename within one directory is
//! atomic on every filesystem this deployment runs on. Writing in place would
//! mean that a crash, a power cut or a full disk partway through leaves a
//! truncated file: the last device on the list silently loses its name, or the
//! final line is half-written and is then skipped by the rule above, which is
//! the same loss with no error to show for it. Saving happens on every rename
//! and every room change, so "partway through" is not a rare window. The
//! temporary file is a sibling, not one in the system temp directory, because a
//! rename across filesystems is a copy and is not atomic.

use crate::device::{Capability, Device, DeviceId};
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// The header the file is written with, so a person who opens it is told what
/// it is and what the `%XX` sequences mean before they hand-edit it.
const HEADER: &str = "# selfhost-home device registry — one device per line, %XX is a percent-escape\n";

/// What one person decided about one device.
///
/// Only the facts a protocol cannot supply. Everything else about a device —
/// its address, what it can do, what it is playing — is discovered afresh at
/// every start and has no business being persisted, because a stale copy of it
/// is indistinguishable from a live one until somebody acts on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Which device this is about. Stored as the id and never as an address or
    /// a name, both of which change without anybody deciding they should.
    pub id: DeviceId,
    /// The name the person gave it, or `None` when they never gave one — in
    /// which case the device keeps whatever its protocol reported.
    pub name: Option<String>,
    /// The room they put it in, or `None` when they never said. Rooms are free
    /// text rather than a closed set: a household that has a "workshop" should
    /// not have to petition anybody for it.
    pub room: Option<String>,
    /// Whether the person asked for it to be kept off the page. Hiding rather
    /// than deleting, because a discovered device that was deleted comes back
    /// on the next scan and the person has to hide it again forever.
    pub hidden: bool,
    /// The pairing this box holds for the device, when its protocol needs one.
    ///
    /// Only a Fire TV uses this today: `crate::firetv` exchanges a PIN read off
    /// the television's own screen for a token, and that token is what every
    /// later key press carries. It is persisted rather than re-fetched because
    /// the pairing lives on the *television* until somebody removes it there —
    /// re-pairing on every start would put a PIN on a person's screen every
    /// time this process restarted.
    ///
    /// It is a credential in a plain file, and the file is readable by whoever
    /// can read the deployment's data directory. What it authorises is bounded
    /// and worth stating: pressing buttons on one television on this LAN. It
    /// grants no account access, survives no move to another network, and is
    /// revoked by unpairing on the device.
    pub token: Option<String>,
}

impl Entry {
    /// An entry that decides nothing, for a device just being spoken about.
    #[must_use]
    pub fn new(id: DeviceId) -> Self {
        Entry { id, name: None, room: None, hidden: false, token: None }
    }

    /// Whether this entry records no decision at all.
    ///
    /// Such an entry is pruned rather than stored: a file that accumulated one
    /// blank line per device ever seen would grow without limit on a network
    /// where a guest's phone appears once, and would say nothing when it did.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.name.is_none() && self.room.is_none() && !self.hidden && self.token.is_none()
    }
}

/// Every decision a person has made about the devices in the house.
///
/// Held in memory as a plain `Vec` and written whole on every change. The house
/// has tens of devices, not thousands, so an index would buy nothing and an
/// append-only log would buy a compaction problem; rewriting the file is a few
/// hundred bytes and one rename.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    /// The entries, in file order, at most one per id.
    entries: Vec<Entry>,
}

impl Registry {
    /// Reads the registry at `path`, treating every failure as "no preferences
    /// yet".
    ///
    /// There is no error to return, and that is the design. A missing file is
    /// the normal state of a deployment that has never been customised, not a
    /// fault; a file that cannot be read is a fault, but not one worth refusing
    /// to show the house over. Both land in the same place — an empty registry —
    /// and every device wears the name its driver reported, which is a working
    /// dashboard rather than an error page. Bytes that are not valid UTF-8 are
    /// decoded lossily so that the lines around them still load.
    #[must_use]
    pub fn load(path: &Path) -> Registry {
        match std::fs::read(path) {
            Ok(bytes) => Registry::parse(&String::from_utf8_lossy(&bytes)),
            Err(_) => Registry::default(),
        }
    }

    /// Reads a registry from the text of a file, skipping lines it cannot read.
    ///
    /// Separate from [`Registry::load`] so the format can be exercised without a
    /// filesystem, and so a future import path has something to call.
    #[must_use]
    pub fn parse(text: &str) -> Registry {
        let mut registry = Registry::default();
        for line in text.lines() {
            if let Some(entry) = read_line(line) {
                registry.put(entry);
            }
        }
        registry
    }

    /// The registry as it is written to disk, header included.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut text = String::from(HEADER);
        for entry in &self.entries {
            text.push_str(&write_line(entry));
            text.push('\n');
        }
        text
    }

    /// Writes the registry to `path`, atomically.
    ///
    /// A temporary sibling is written, flushed to the disk and renamed over the
    /// target, so an interrupted save leaves the previous file intact rather
    /// than a truncated one — see this module's documentation for why that
    /// window is worth closing. The parent directory is created if it is
    /// missing, because the first rename in a deployment routinely happens
    /// before anything else has had cause to create the data directory.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let temporary = temporary_path(path);
        let write = || -> io::Result<()> {
            let mut file = std::fs::File::create(&temporary)?;
            file.write_all(self.to_text().as_bytes())?;
            // Flushed before the rename, not after: a rename that lands ahead
            // of the data is a file that exists and is empty.
            file.sync_all()
        };
        if let Err(error) = write() {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = std::fs::rename(&temporary, path) {
            let _ = std::fs::remove_file(&temporary);
            return Err(error);
        }
        Ok(())
    }

    /// Overlays this person's decisions onto a device a driver just reported.
    ///
    /// Only the fields the person actually set are written. A device nobody has
    /// renamed keeps the name its protocol gave it, and a device nobody has
    /// placed keeps whatever room the protocol knew about — Sonos, for one,
    /// really does know its own zone name, and discarding that in favour of
    /// `None` would empty the room grouping on a fresh install.
    pub fn apply(&self, device: &mut Device) {
        let Some(entry) = self.entry(&device.id) else {
            return;
        };
        if let Some(name) = &entry.name {
            device.name = name.clone();
        }
        if let Some(room) = &entry.room {
            device.room = Some(room.clone());
        }
        // A pairing is a capability, not a preference, and this is the one
        // place that knows about it. A Fire TV takes keys and transport only
        // once somebody has read a PIN off its screen, so a television with a
        // token on file grows those controls and one without keeps only the
        // application and power controls its protocol offers unpaired. The
        // page renders what a device advertises, so this is what stops it
        // drawing a d-pad that would answer every press with a refusal.
        if entry.token.is_some() && device.id.driver() == crate::dial::DRIVER {
            *device = device.clone().advertise(&[Capability::Keys, Capability::Transport]);
        }
    }

    /// Names a device, or clears the name with `None`.
    ///
    /// The text is trimmed, and a name that is empty or all whitespace clears
    /// the entry rather than being stored: a person who selects the name, wipes
    /// it and presses enter is asking for the device's own name back, and a
    /// blank card on the page is nobody's intention.
    pub fn set_name(&mut self, id: &DeviceId, name: Option<String>) {
        let name = name.and_then(meaningful);
        self.change(id, |entry| entry.name = name);
    }

    /// Puts a device in a room, or takes it out of one with `None`.
    ///
    /// Trimmed and emptied to `None` on the same reasoning as
    /// [`Registry::set_name`], with one addition: an untrimmed room name would
    /// make `Kitchen` and `Kitchen ` two rooms on the page, and the person who
    /// typed the trailing space would never work out why.
    pub fn set_room(&mut self, id: &DeviceId, room: Option<String>) {
        let room = room.and_then(meaningful);
        self.change(id, |entry| entry.room = room);
    }

    /// Keeps a device off the page, or puts it back.
    pub fn set_hidden(&mut self, id: &DeviceId, hidden: bool) {
        self.change(id, |entry| entry.hidden = hidden);
    }

    /// Whether the person asked for this device to be kept off the page.
    ///
    /// Asked here rather than applied in [`Registry::apply`] because a
    /// [`Device`] has no "hidden" field and should not: hiding is a decision
    /// about a *view*, and the API layer that renders a list is the only thing
    /// that can honour it without making every other reader — a command route,
    /// a group operation — pretend the device does not exist.
    #[must_use]
    pub fn hidden(&self, id: &DeviceId) -> bool {
        self.entry(id).is_some_and(|entry| entry.hidden)
    }

    /// Records the pairing this box holds for a device, or clears it.
    ///
    /// Clearing is what a failed command should do when the television reports
    /// the pairing gone: keeping a token that is known not to work turns every
    /// later press into the same slow refusal, and the page cannot offer to
    /// pair again while a stale one is on file.
    pub fn set_token(&mut self, id: &DeviceId, token: Option<String>) {
        let token = token.filter(|token| !token.is_empty());
        self.change(id, |entry| entry.token = token.clone());
    }

    /// The pairing on file for a device, if any.
    #[must_use]
    pub fn token(&self, id: &DeviceId) -> Option<&str> {
        self.entry(id).and_then(|entry| entry.token.as_deref())
    }

    /// Every room a person has named, sorted and without duplicates.
    ///
    /// Compared case-insensitively so that typing `kitchen` once does not add a
    /// second Kitchen to the room picker; the first spelling in sort order is
    /// the one shown, because picking a "canonical" capitalisation on a person's
    /// behalf is how a household ends up with a room it did not name.
    #[must_use]
    pub fn rooms(&self) -> Vec<String> {
        let mut rooms: Vec<String> =
            self.entries.iter().filter_map(|entry| entry.room.clone()).collect();
        rooms.sort_by_key(|room| room.to_lowercase());
        rooms.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
        rooms
    }

    /// What the person decided about one device, if anything.
    #[must_use]
    pub fn entry(&self, id: &DeviceId) -> Option<&Entry> {
        self.entries.iter().find(|entry| &entry.id == id)
    }

    /// Every decision on record, in file order.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Whether anybody has decided anything yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Inserts an entry, replacing any earlier one for the same device.
    ///
    /// The later line wins because appending is what a hand-edit does, and
    /// because a file written by [`Registry::save`] never contains a duplicate
    /// for either rule to arbitrate.
    fn put(&mut self, entry: Entry) {
        if entry.is_empty() {
            return;
        }
        match self.entries.iter_mut().find(|existing| existing.id == entry.id) {
            Some(existing) => *existing = entry,
            None => self.entries.push(entry),
        }
    }

    /// Applies one change to a device's entry, creating it if needed and
    /// pruning it if the change left it saying nothing.
    fn change(&mut self, id: &DeviceId, change: impl FnOnce(&mut Entry)) {
        let index = match self.entries.iter().position(|entry| &entry.id == id) {
            Some(index) => index,
            None => {
                self.entries.push(Entry::new(id.clone()));
                self.entries.len() - 1
            }
        };
        change(&mut self.entries[index]);
        if self.entries[index].is_empty() {
            self.entries.remove(index);
        }
    }
}

/// Writes one entry as one line, with no trailing newline.
///
/// The exact inverse of [`read_line`] for every possible entry, which is what
/// lets a name hold an `=`, a tab or a newline without a special case anywhere
/// else in the system.
fn write_line(entry: &Entry) -> String {
    let mut line = escape(entry.id.as_str());
    if let Some(name) = &entry.name {
        line.push_str(" name=");
        line.push_str(&escape(name));
    }
    if let Some(room) = &entry.room {
        line.push_str(" room=");
        line.push_str(&escape(room));
    }
    if let Some(token) = &entry.token {
        line.push_str(" token=");
        line.push_str(&escape(token));
    }
    line.push_str(if entry.hidden { " hidden=1" } else { " hidden=0" });
    line
}

/// Reads one line, or `None` for a line that is blank, a comment, or corrupt.
///
/// Every failure returns `None` and takes the whole line with it; see this
/// module's documentation for why the line and not the field is the unit that
/// gets dropped.
fn read_line(line: &str) -> Option<Entry> {
    // Trimmed against ASCII whitespace only, never `str::trim`: a name may end
    // in a non-breaking space, and `trim` would eat the one the escape scheme
    // went to the trouble of preserving.
    let line = line.trim_matches(|c: char| c.is_ascii_whitespace());
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut fields = line.split_ascii_whitespace();
    let id = unescape(fields.next()?)?;
    if id.is_empty() {
        return None;
    }
    let mut entry = Entry::new(DeviceId::from_wire(&id));
    for field in fields {
        let (key, value) = field.split_once('=')?;
        match key {
            "name" => entry.name = Some(unescape(value)?),
            "room" => entry.room = Some(unescape(value)?),
            "token" => entry.token = Some(unescape(value)?),
            "hidden" => {
                entry.hidden = match value {
                    "0" => false,
                    "1" => true,
                    _ => return None,
                }
            }
            // A key from a newer build. Ignored rather than fatal, so that
            // downgrading a deployment costs the unknown field and not the file.
            _ => {}
        }
    }
    Some(entry)
}

/// Percent-escapes everything that would otherwise break the line format.
///
/// Escaped: ASCII whitespace, ASCII control characters, `%`, `=` and `#`. Left
/// alone: everything else, including every non-ASCII character, so that a room
/// called `Küche` reads as `Küche` in the file. The set is chosen to be exactly
/// the characters the grammar gives a meaning to, plus `%` itself — escaping
/// more would make the file less readable for no gain in safety.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_ascii_whitespace() || ch.is_ascii_control() || matches!(ch, '%' | '=' | '#') {
            let mut buffer = [0u8; 4];
            for byte in ch.encode_utf8(&mut buffer).as_bytes() {
                out.push('%');
                out.push(hex_digit(byte >> 4));
                out.push(hex_digit(byte & 0x0f));
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// Expands `%XX` escapes, or `None` if the text is not a valid escaping.
///
/// A truncated escape, a non-hex digit, or bytes that do not form UTF-8 all
/// return `None` and cost the caller its line. Decoding through a byte buffer
/// rather than character by character is what makes a multi-byte character
/// written as several escapes reassemble correctly.
fn unescape(text: &str) -> Option<String> {
    if !text.contains('%') {
        return Some(text.to_owned());
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let high = hex_value(*bytes.get(i + 1)?)?;
            let low = hex_value(*bytes.get(i + 2)?)?;
            out.push(high << 4 | low);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// One uppercase hex digit for the low nibble of `value`.
fn hex_digit(value: u8) -> char {
    char::from(match value {
        0..=9 => b'0' + value,
        _ => b'A' + value - 10,
    })
}

/// The value of one hex digit, either case, or `None` if it is not one.
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// The path of the temporary file a save writes before renaming.
///
/// A hidden sibling in the same directory, because the rename that follows is
/// only atomic within one filesystem and the system temp directory is very
/// often a different one.
fn temporary_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(".");
    name.push(path.file_name().unwrap_or_else(|| OsStr::new("home.registry")));
    name.push(".new");
    path.with_file_name(name)
}

/// Trims a value the person typed, and reads an empty one as no value at all.
fn meaningful(text: String) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::Kind;

    fn id(key: &str) -> DeviceId {
        DeviceId::new("sonos", key)
    }

    /// The property the whole format rests on: whatever an entry holds, the
    /// line it is written as reads back as the same entry.
    fn round_trips(entry: &Entry) {
        let line = write_line(entry);
        assert!(!line.contains('\n'), "a record must not span lines: {line:?}");
        assert_eq!(read_line(&line).as_ref(), Some(entry), "line was {line:?}");
    }

    /// A pairing survives the file, escapes included. Fire TV tokens are
    /// URL-safe base64 and so contain `-` and `_`, which the format leaves
    /// alone; the test uses a token with `=` in it anyway, because the escape
    /// scheme and not the observed alphabet is what has to be right.
    #[test]
    fn a_pairing_token_round_trips() {
        let entry = Entry {
            id: DeviceId::new("dial", "uuid-a"),
            name: None,
            room: None,
            hidden: false,
            token: Some("z-1_ydta2Q==".to_owned()),
        };
        round_trips(&entry);
        assert_eq!(write_line(&entry), "dial:uuid-a token=z-1_ydta2Q%3D%3D hidden=0");
    }

    /// An entry holding only a pairing is a decision and must not be pruned.
    /// Getting this wrong would lose the token on the next save and put a PIN
    /// back on somebody's screen.
    #[test]
    fn an_entry_holding_only_a_token_is_not_empty() {
        let mut entry = Entry::new(id("a"));
        assert!(entry.is_empty());
        entry.token = Some("tok".to_owned());
        assert!(!entry.is_empty());
    }

    /// A paired television grows the controls the pairing bought, and an
    /// unpaired one does not. This is what stops the page drawing a d-pad
    /// whose every press would be refused.
    #[test]
    fn a_pairing_grows_the_remote_and_nothing_else_does() {
        use crate::device::{Capability, Kind};

        let television = || {
            Device::new(DeviceId::new(crate::dial::DRIVER, "uuid-a"), "Bedroom TV", Kind::Television)
                .advertise(&[Capability::Apps, Capability::Power])
        };

        let mut registry = Registry::default();
        let mut unpaired = television();
        registry.apply(&mut unpaired);
        assert!(!unpaired.can(Capability::Keys), "an unpaired television takes no keys");

        registry.set_token(&television().id, Some("tok".to_owned()));
        let mut paired = television();
        registry.apply(&mut paired);
        assert!(paired.can(Capability::Keys));
        assert!(paired.can(Capability::Transport));
        // Power was never gated on the pairing: a wake needs no token.
        assert!(paired.can(Capability::Power));
    }

    /// A speaker is not given a d-pad because somebody once stored a token
    /// against it. The driver is part of the condition, not just the token.
    #[test]
    fn a_token_on_a_non_television_grows_nothing() {
        use crate::device::{Capability, Kind};

        let mut registry = Registry::default();
        let mut speaker = Device::new(id("rincon_a"), "Kitchen", Kind::Speaker);
        registry.set_token(&id("rincon_a"), Some("tok".to_owned()));
        registry.apply(&mut speaker);
        assert!(!speaker.can(Capability::Keys));
    }

    #[test]
    fn a_missing_file_loads_as_an_empty_registry() {
        let path = temp_path("missing");
        assert!(!path.exists());
        let registry = Registry::load(&path);
        assert!(registry.is_empty());
        assert!(registry.rooms().is_empty());
    }

    #[test]
    fn a_plain_record_reads_the_way_it_is_documented() {
        let registry = Registry::parse(
            "sonos:rincon_7828ca1491ae01400 name=Kitchen room=Kitchen hidden=0\n",
        );
        let entry = registry.entry(&DeviceId::from_wire("sonos:rincon_7828ca1491ae01400")).unwrap();
        assert_eq!(entry.name.as_deref(), Some("Kitchen"));
        assert_eq!(entry.room.as_deref(), Some("Kitchen"));
        assert!(!entry.hidden);
    }

    /// `Kitchen = Loud` is a perfectly reasonable thing to call a speaker, and
    /// the field separator must not be able to be smuggled in by one.
    #[test]
    fn a_name_containing_an_equals_sign_round_trips() {
        let entry = Entry {
            id: id("a"),
            name: Some("Kitchen = Loud".to_owned()),
            room: Some("Kitchen=1".to_owned()),
            hidden: false,
            token: None,
        };
        round_trips(&entry);
        assert!(!write_line(&entry).contains("= "));
    }

    /// A name pasted out of a text editor can carry a newline, and one record
    /// silently becoming two would attach half a name to a device that does not
    /// exist.
    #[test]
    fn a_name_containing_a_newline_round_trips() {
        let entry = Entry {
            id: id("a"),
            name: Some("Kitchen\nSpeaker\r\n".to_owned()),
            room: None,
            hidden: true,
            token: None,
        };
        round_trips(&entry);
        let line = write_line(&entry);
        assert!(!line.contains('\r'));
        assert_eq!(Registry::parse(&format!("{line}\n")).entries().len(), 1);
    }

    #[test]
    fn a_name_containing_a_tab_round_trips() {
        round_trips(&Entry {
            id: id("a"),
            name: Some("Kitchen\tSpeaker".to_owned()),
            room: Some("\tBack Room ".to_owned()),
            hidden: false,
            token: None,
        });
    }

    /// An empty name is not the same fact as no name: the field is present and
    /// reads back as `Some("")`, while an absent field reads as `None`.
    #[test]
    fn an_empty_name_round_trips_and_is_not_an_absent_one() {
        let empty = Entry { id: id("a"), name: Some(String::new()), room: None, hidden: false, token: None };
        round_trips(&empty);
        assert_eq!(write_line(&empty), "sonos:a name= hidden=0");

        let absent = Entry { id: id("a"), name: None, room: None, hidden: true, token: None };
        round_trips(&absent);
        assert_eq!(write_line(&absent), "sonos:a hidden=1");
    }

    /// Non-ASCII is written literally so the file stays readable, which means
    /// the escaping has to be right about which characters it leaves alone —
    /// including a non-breaking space, which is whitespace to Unicode but not to
    /// the line format.
    #[test]
    fn a_unicode_name_round_trips_and_stays_readable() {
        let entry = Entry {
            id: id("a"),
            name: Some("Küche 🎧".to_owned()),
            room: Some("Büro\u{a0}".to_owned()),
            hidden: false,
            token: None,
        };
        round_trips(&entry);
        let line = write_line(&entry);
        assert!(line.contains("Küche"), "line was {line:?}");
        assert!(line.contains('🎧'), "line was {line:?}");
    }

    #[test]
    fn an_id_that_needs_escaping_round_trips() {
        round_trips(&Entry {
            id: DeviceId::from_wire("odd:# =\tone"),
            name: Some("Odd".to_owned()),
            room: None,
            hidden: false,
            token: None,
        });
    }

    /// The decision this module argues for: one mangled line costs one device
    /// its nickname, and never costs the household its dashboard.
    #[test]
    fn a_corrupt_line_is_skipped_and_the_rest_survive() {
        let registry = Registry::parse(concat!(
            "sonos:a name=Kitchen hidden=0\n",
            "sonos:b name=Bad%ZZ hidden=0\n",   // not hex
            "sonos:c name=Truncated%4 hidden=0\n", // escape runs off the end
            "sonos:d nameKitchen hidden=0\n",   // field with no '='
            "sonos:e name=Living hidden=maybe\n", // not a boolean
            "sonos:f name=Study hidden=1\n",
        ));
        let named: Vec<&str> = registry.entries().iter().map(|e| e.id.key()).collect();
        assert_eq!(named, ["a", "f"]);
    }

    #[test]
    fn blank_lines_comments_and_carriage_returns_are_not_records() {
        let registry = Registry::parse("\n  \n# a comment\r\nsonos:a name=Kitchen hidden=0\r\n");
        assert_eq!(registry.entries().len(), 1);
        assert_eq!(registry.entry(&id("a")).unwrap().name.as_deref(), Some("Kitchen"));
    }

    /// A field a newer build wrote must cost the reader that field and not the
    /// device, or downgrading a deployment would wipe the registry.
    #[test]
    fn an_unknown_key_is_ignored_rather_than_fatal() {
        let registry = Registry::parse("sonos:a name=Kitchen order=3 hidden=1\n");
        let entry = registry.entry(&id("a")).unwrap();
        assert_eq!(entry.name.as_deref(), Some("Kitchen"));
        assert!(entry.hidden);
    }

    #[test]
    fn the_last_line_naming_a_device_wins() {
        let registry = Registry::parse("sonos:a name=First hidden=0\nsonos:a name=Second hidden=0\n");
        assert_eq!(registry.entries().len(), 1);
        assert_eq!(registry.entry(&id("a")).unwrap().name.as_deref(), Some("Second"));
    }

    #[test]
    fn a_renamed_device_wears_the_persons_name_and_room() {
        let mut registry = Registry::default();
        registry.set_name(&id("a"), Some("Reading Lamp".to_owned()));
        registry.set_room(&id("a"), Some("Bedroom".to_owned()));

        let mut device = Device::new(id("a"), "Sonos One (2)", Kind::Speaker);
        device.room = Some("Living Room".to_owned());
        registry.apply(&mut device);

        assert_eq!(device.name, "Reading Lamp");
        assert_eq!(device.room.as_deref(), Some("Bedroom"));
    }

    /// The partial overlay: a device the person never touched must keep every
    /// fact its protocol reported, including the room Sonos knows for itself.
    #[test]
    fn a_device_nobody_renamed_keeps_what_its_protocol_said() {
        let mut registry = Registry::default();
        registry.set_hidden(&id("a"), true);
        registry.set_room(&id("a"), Some("Kitchen".to_owned()));

        let mut device = Device::new(id("a"), "Sonos One (2)", Kind::Speaker);
        device.room = Some("Living Room".to_owned());
        registry.apply(&mut device);
        assert_eq!(device.name, "Sonos One (2)");
        assert_eq!(device.room.as_deref(), Some("Kitchen"));

        let mut untouched = Device::new(id("z"), "Fire TV", Kind::Television);
        untouched.room = Some("Den".to_owned());
        registry.apply(&mut untouched);
        assert_eq!(untouched.name, "Fire TV");
        assert_eq!(untouched.room.as_deref(), Some("Den"));
    }

    /// Clearing the last decision about a device removes the record entirely,
    /// so the file does not accumulate a blank line per device ever seen.
    #[test]
    fn clearing_every_decision_prunes_the_entry() {
        let mut registry = Registry::default();
        registry.set_name(&id("a"), Some("Kitchen".to_owned()));
        assert_eq!(registry.entries().len(), 1);

        registry.set_name(&id("a"), None);
        assert!(registry.is_empty());
        assert_eq!(registry.to_text(), HEADER);
    }

    /// A person who wipes the name field is asking for the device's own name
    /// back, not for a blank card.
    #[test]
    fn a_blank_name_clears_rather_than_stores() {
        let mut registry = Registry::default();
        registry.set_hidden(&id("a"), true);
        registry.set_name(&id("a"), Some("   ".to_owned()));
        registry.set_room(&id("a"), Some("\t".to_owned()));
        let entry = registry.entry(&id("a")).unwrap();
        assert_eq!(entry.name, None);
        assert_eq!(entry.room, None);
    }

    #[test]
    fn a_room_is_trimmed_so_one_room_does_not_become_two() {
        let mut registry = Registry::default();
        registry.set_room(&id("a"), Some(" Kitchen ".to_owned()));
        registry.set_room(&id("b"), Some("Kitchen".to_owned()));
        assert_eq!(registry.rooms(), ["Kitchen"]);
    }

    #[test]
    fn rooms_are_sorted_deduplicated_and_case_insensitive() {
        let mut registry = Registry::default();
        registry.set_room(&id("a"), Some("Kitchen".to_owned()));
        registry.set_room(&id("b"), Some("bedroom".to_owned()));
        registry.set_room(&id("c"), Some("kitchen".to_owned()));
        registry.set_room(&id("d"), Some("Attic".to_owned()));
        assert_eq!(registry.rooms(), ["Attic", "bedroom", "Kitchen"]);
    }

    #[test]
    fn hiding_is_asked_of_the_registry_and_not_written_onto_the_device() {
        let mut registry = Registry::default();
        registry.set_hidden(&id("a"), true);
        assert!(registry.hidden(&id("a")));
        assert!(!registry.hidden(&id("b")));

        registry.set_hidden(&id("a"), false);
        assert!(!registry.hidden(&id("a")));
        assert!(registry.is_empty());
    }

    /// The end-to-end guarantee, through a real file: everything nasty a name
    /// can hold survives being written to disk and read back by a fresh
    /// process's worth of code.
    #[test]
    fn a_registry_round_trips_through_a_real_file() {
        let path = temp_path("round-trip");

        let mut registry = Registry::default();
        registry.set_name(&id("a"), Some("Kitchen = Loud".to_owned()));
        registry.set_room(&id("a"), Some("Küche 🎧".to_owned()));
        registry.set_name(&id("b"), Some("Two\tWords\nBroken".to_owned()));
        registry.set_hidden(&id("b"), true);
        // Trimmed to "Büro" by the setter — `str::trim` takes the trailing
        // non-breaking space, which is what a person who typed it wants. The
        // *format* keeps one, and that is asserted in the unicode test above.
        registry.set_room(&id("c"), Some("Büro\u{a0}".to_owned()));

        registry.save(&path).expect("the registry saves");
        let reloaded = Registry::load(&path);

        assert_eq!(reloaded.entries(), registry.entries());
        assert_eq!(reloaded.entry(&id("a")).unwrap().name.as_deref(), Some("Kitchen = Loud"));
        assert_eq!(reloaded.entry(&id("b")).unwrap().name.as_deref(), Some("Two\tWords\nBroken"));
        assert!(reloaded.hidden(&id("b")));
        assert_eq!(reloaded.rooms(), ["Büro", "Küche 🎧"]);

        // The temporary sibling must not survive a successful save.
        assert!(!temporary_path(&path).exists());
        let _ = std::fs::remove_file(&path);
    }

    /// Saving over a registry that already exists replaces it rather than
    /// appending to it, and leaves the file readable at every point a reader
    /// could observe it.
    #[test]
    fn a_second_save_replaces_the_first() {
        let path = temp_path("replace");

        let mut registry = Registry::default();
        registry.set_name(&id("a"), Some("First".to_owned()));
        registry.save(&path).expect("the first save works");

        registry.set_name(&id("a"), Some("Second".to_owned()));
        registry.set_name(&id("b"), Some("Another".to_owned()));
        registry.save(&path).expect("the second save works");

        let reloaded = Registry::load(&path);
        assert_eq!(reloaded.entries().len(), 2);
        assert_eq!(reloaded.entry(&id("a")).unwrap().name.as_deref(), Some("Second"));

        let text = std::fs::read_to_string(&path).expect("the file is readable");
        assert!(text.starts_with('#'), "the file explains itself: {text:?}");
        assert!(!text.contains("First"));

        let _ = std::fs::remove_file(&path);
    }

    /// A registry saved into a directory that does not exist yet still lands —
    /// the first rename in a deployment happens before anything has created the
    /// data directory.
    #[test]
    fn a_save_creates_the_directory_it_needs() {
        let directory = std::env::temp_dir().join(unique("nested"));
        let path = directory.join("home.registry");

        let mut registry = Registry::default();
        registry.set_name(&id("a"), Some("Kitchen".to_owned()));
        registry.save(&path).expect("the registry saves into a fresh directory");
        assert_eq!(Registry::load(&path).entries().len(), 1);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&directory);
    }

    /// Bytes that are not UTF-8 cost their own line and nothing else.
    #[test]
    fn a_file_that_is_not_valid_utf8_still_yields_its_readable_lines() {
        let path = temp_path("not-utf8");
        let mut bytes = b"sonos:a name=Kitchen hidden=0\nsonos:b name=".to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe]);
        bytes.extend_from_slice(b" hidden=0\nsonos:c name=Study hidden=0\n");
        std::fs::write(&path, &bytes).expect("the fixture writes");

        let registry = Registry::load(&path);
        let keys: Vec<&str> = registry.entries().iter().map(|e| e.id.key()).collect();
        assert!(keys.contains(&"a"), "keys were {keys:?}");
        assert!(keys.contains(&"c"), "keys were {keys:?}");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn the_temporary_file_is_a_sibling_so_the_rename_stays_atomic() {
        let path = Path::new("/var/lib/selfhost/home.registry");
        let temporary = temporary_path(path);
        assert_eq!(temporary.parent(), path.parent());
        assert_eq!(temporary.file_name().unwrap(), ".home.registry.new");
    }

    #[test]
    fn escaping_is_exactly_the_characters_the_grammar_uses() {
        assert_eq!(escape("Kitchen"), "Kitchen");
        assert_eq!(escape("a b"), "a%20b");
        assert_eq!(escape("a=b"), "a%3Db");
        assert_eq!(escape("100%"), "100%25");
        assert_eq!(escape("#1"), "%231");
        assert_eq!(escape("a\tb\nc"), "a%09b%0Ac");
        assert_eq!(escape("Küche"), "Küche");
    }

    #[test]
    fn unescaping_refuses_what_it_cannot_read() {
        assert_eq!(unescape("a%20b").as_deref(), Some("a b"));
        assert_eq!(unescape("a%2").as_deref(), None);
        assert_eq!(unescape("a%").as_deref(), None);
        assert_eq!(unescape("a%zzb").as_deref(), None);
        // A lone continuation byte is not UTF-8, and is refused rather than
        // silently replaced.
        assert_eq!(unescape("%80").as_deref(), None);
    }

    /// A file with a unique name in the system temp directory, removed by the
    /// test that made it. No temp-file crate, and no fixed name that two test
    /// binaries running at once could fight over.
    fn temp_path(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(unique(label));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// A name unique to this process, this thread and this call.
    fn unique(label: &str) -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNT: AtomicU32 = AtomicU32::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos());
        format!(
            "selfhost-home-{label}-{}-{nanos}-{}.registry",
            std::process::id(),
            COUNT.fetch_add(1, Ordering::Relaxed)
        )
    }
}
