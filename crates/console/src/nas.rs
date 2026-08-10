//! What the FILES plate knows: shares, one directory of one share, and the
//! transfers in flight.
//!
//! # Why this is a module and not part of the drawing
//!
//! The browser console is the reference implementation, and the two consoles
//! share no code by design. What keeps them honest is that every *decision* is
//! pure on both sides and asserted on both sides: which entry sorts first, what
//! a quota reading says, which path a breadcrumb leads to, whether a name can
//! appear in a request at all. Those live here, next to their tests, so the
//! plate below is only rectangles — and so a disagreement with `sites/console`
//! shows up as a failing assertion rather than as two consoles that behave
//! differently on the same share.
//!
//! Each function names its counterpart in `sites/console/app.js`. Change one,
//! change both.
//!
//! # Paths, and the two spellings every one of them has
//!
//! A path is carried twice, always: as the plain text a person reads, and as the
//! percent-encoded text a request may carry. They are not interchangeable — a
//! directory called `100%` proves it — so [`url_path`] is the only way a name in
//! this console becomes part of a URL, and a name that cannot be addressed at
//! all ([`join_path`] answering `None`) is drawn but never linked.

use selfhost_json::Json;
use rui::Status;

/// The largest share id this console will put in a request path.
///
/// The daemon's own grammar, mirrored rather than imported: `crates/identity`
/// owns the type, and depending on it from here to check thirty-two characters
/// would pull the whole authorisation model into a window that never decides
/// anything. Mirrored constants are checked by a test that spells the rule out.
const MAX_SHARE_ID: usize = 32;

/// The most bytes a download will be held in memory before it reaches a file.
///
/// A file plate that could be asked for a hundred-gigabyte film must not answer
/// by allocating one, and this console's HTTP client buffers a body whole. So a
/// download larger than this is refused *before* it is asked for, with a
/// sentence naming the limit, rather than being started and killing the process
/// under `panic = "abort"` when the allocation fails.
pub const MAX_TRANSFER: u64 = 512 * 1024 * 1024;

/// One share, as `GET /api/storage/shares` describes it.
///
/// Every measurement is an `Option` because the API answers `null` for a reading
/// it could not take — a share on a disk that has just been unplugged is still a
/// declared share — and treating an unmeasurable share as an empty one is the
/// single lie this type exists to refuse.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Share {
    /// The share's id, which is also its URL segment.
    pub id: String,
    /// Whether the *data* is read-only, which binds the owner too.
    pub read_only: bool,
    /// Whether it is advertised over DNS-SD.
    pub browsable: bool,
    /// Whether **this caller** may write to it, decided by the daemon.
    pub writable: bool,
    /// The declared ceiling, when there is one.
    pub quota_bytes: Option<u64>,
    /// Free space on the volume, when it could be read.
    pub available_bytes: Option<u64>,
    /// What the share holds, when it could be measured.
    pub used_bytes: Option<u64>,
    /// The SMB export's name, when the operator declared one.
    pub smb: Option<String>,
}

impl Share {
    /// Reads one share off the wire, or `None` for an object that is not one.
    ///
    /// The id is checked here rather than at the call site, because a share
    /// whose id cannot appear in a request path is a share this console can
    /// never open — drawing it would offer a row that refuses every press.
    pub fn from_json(value: &Json) -> Option<Self> {
        let id = value.get("id")?.as_str()?.to_owned();
        if !usable_share_id(&id) {
            return None;
        }
        Some(Self {
            id,
            read_only: value.get("readOnly").and_then(Json::as_bool).unwrap_or(false),
            browsable: value.get("browsable").and_then(Json::as_bool).unwrap_or(false),
            writable: value.get("writable").and_then(Json::as_bool).unwrap_or(false),
            quota_bytes: whole(value.get("quotaBytes")),
            available_bytes: whole(value.get("availableBytes")),
            used_bytes: whole(value.get("usedBytes")),
            smb: value
                .get("smb")
                .and_then(|smb| smb.get("name"))
                .and_then(Json::as_str)
                .map(str::to_owned),
        })
    }
}

/// What kind of thing an entry is.
///
/// A closed set rather than the wire's string, so the sort and the drawing
/// cannot disagree about what "directory" is spelled like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A directory, which the plate can open.
    Directory,
    /// An ordinary file.
    File,
    /// Anything else the daemon reported — a symlink, a device node.
    Other,
}

impl Kind {
    /// The kind named by the wire's tag.
    fn of(tag: Option<&str>) -> Self {
        match tag {
            Some("directory") => Self::Directory,
            Some("file") => Self::File,
            _ => Self::Other,
        }
    }
}

/// One name in a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The name as it is stored, which is what a person reads.
    pub name: String,
    /// What it is.
    pub kind: Kind,
    /// Its size in bytes; zero for a directory, which is not measured here.
    pub size: u64,
    /// When it was last written, in whole Unix seconds, when that is knowable.
    pub modified: Option<u64>,
    /// The share-relative plain path, or `None` for a name no request can
    /// address — the daemon says so with `reachable: false`.
    pub path: Option<String>,
    /// Why it cannot be addressed, for the row that says so.
    pub blocked: Option<String>,
}

impl Entry {
    /// Reads one entry off the wire, or `None` for an object that is not one.
    pub fn from_json(value: &Json, directory: &str) -> Option<Self> {
        let name = value.get("name")?.as_str()?.to_owned();
        let reachable = value.get("reachable").and_then(Json::as_bool).unwrap_or(true);
        Some(Self {
            kind: Kind::of(value.get("kind").and_then(Json::as_str)),
            size: value.get("size").and_then(Json::as_u64).unwrap_or(0),
            modified: value.get("modified").and_then(Json::as_u64),
            // The daemon's own `path` is percent-encoded for a link; this
            // console keeps plain paths and encodes on the way out, so the
            // plain one is rebuilt from the directory and the name rather than
            // decoded back. `join_path` refuses exactly the names the daemon
            // marks unreachable, which is the agreement being relied on.
            path: reachable.then(|| join_path(directory, &name)).flatten(),
            blocked: value.get("blockedReason").and_then(Json::as_str).map(str::to_owned),
            name,
        })
    }
}

/// One directory of one share.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Listing {
    /// Which share this came from, so a reply that arrives after the operator
    /// moved on can be discarded rather than drawn under the wrong heading.
    pub share: String,
    /// The plain path inside the share; the root is the empty string.
    pub path: String,
    /// The names, already in display order.
    pub entries: Vec<Entry>,
}

impl Listing {
    /// Reads a listing off the wire.
    ///
    /// The daemon's own `path` is trusted over the one that was asked for: a
    /// request for `a/./b` is answered for `a/b`, and drawing the request would
    /// leave a breadcrumb that does not lead where the listing came from.
    pub fn from_json(share: &str, value: &Json) -> Option<Self> {
        let path = plain_path(value.get("path")?.as_str().unwrap_or(""));
        let entries = value
            .get("entries")
            .and_then(Json::as_array)
            .unwrap_or(&[])
            .iter()
            .filter_map(|entry| Entry::from_json(entry, &path))
            .collect();
        let mut listing = Self { share: share.to_owned(), path, entries };
        sort_entries(&mut listing.entries, Column::Name, true);
        Some(listing)
    }
}

/// Which column the listing is ordered by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Column {
    /// The name, case-insensitively.
    #[default]
    Name,
    /// The size in bytes.
    Size,
    /// The modification time.
    Modified,
}

impl Column {
    /// The column's heading.
    pub fn label(self) -> &'static str {
        match self {
            Self::Name => "NAME",
            Self::Size => "SIZE",
            Self::Modified => "MODIFIED",
        }
    }
}

/// A quota reading: what to say, how much of the bar to light, and its colour.
#[derive(Debug, Clone, PartialEq)]
pub struct Quota {
    /// The words.
    pub text: String,
    /// The share of the bar to light, or `None` when there is no ceiling to
    /// take a share of.
    pub fraction: Option<f32>,
    /// How pressing it is.
    pub status: Status,
}

/// What a share's gauge shows.
///
/// Mirrors `quotaReading` in `sites/console/app.js`. A share with no declared
/// quota still reports its usage against the volume's free space, because "how
/// much room is left" is the question either way — and a share whose usage could
/// not be measured says so rather than showing an empty bar, which would read as
/// an empty share.
pub fn quota_reading(share: &Share) -> Quota {
    let Some(used) = share.used_bytes else {
        return Quota {
            text: "usage cannot be measured".into(),
            fraction: None,
            status: Status::Warn,
        };
    };
    match share.quota_bytes {
        Some(quota) if quota > 0 => {
            let fraction = (used as f32 / quota as f32).min(1.0);
            Quota {
                text: format!("{} of {}", size_text(used), size_text(quota)),
                fraction: Some(fraction),
                status: if fraction >= 0.95 {
                    Status::Bad
                } else if fraction >= 0.85 {
                    Status::Warn
                } else {
                    Status::Ok
                },
            }
        }
        _ => Quota {
            text: match share.available_bytes {
                Some(free) => format!("{} used · {} free", size_text(used), size_text(free)),
                None => format!("{} used", size_text(used)),
            },
            fraction: None,
            status: Status::Ok,
        },
    }
}

/// What the plate says when it has no share to draw, or nothing at all.
///
/// Mirrors `sharesNote`. Absence is a sentence and never an error: a deployment
/// with no `[[shares]]` is a correct deployment, and a caller who may read the
/// console while holding no share is a correct caller.
pub fn shares_note(shares: Option<&[Share]>) -> &'static str {
    match shares {
        None => "This deployment serves no shares.",
        Some([]) => "No share on this box is yours to open.",
        Some(_) => "",
    }
}

/// Bytes in the units a person reads, held to three significant figures.
///
/// Mirrors `sizeText`. Three figures rather than a fixed number of decimals so
/// that a column of them does not jitter as the values change width.
pub fn size_text(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "kB", "MB", "GB", "TB", "PB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    let name = UNITS.get(unit).copied().unwrap_or("B");
    if unit == 0 {
        return format!("{bytes} B");
    }
    if value < 10.0 {
        format!("{value:.2} {name}")
    } else if value < 100.0 {
        format!("{value:.1} {name}")
    } else {
        format!("{:.0} {name}", value)
    }
}

/// A Unix instant as a compact calendar day and clock time, or an honest dash.
///
/// **In UTC, and the column says so.** The browser shows the reader's own local
/// time because a browser is told what that is; nothing in this program's
/// dependencies knows the machine's zone, and a console that silently rendered
/// UTC as though it were local would be a console that is wrong by an hour for
/// most of the world. The two consoles therefore label the same instant
/// differently and agree about the instant, which is the honest half of the
/// parity rule — recorded as a stated difference in `console-lab.dx`.
///
/// The date arithmetic is `selfhost_http::date`'s and not a second copy: that
/// module already owns this workspace's civil-calendar conversion, its output
/// is the fixed IMF-fixdate shape RFC 9110 §5.6.7 defines, and this trims it.
pub fn when_text(unix: Option<u64>) -> String {
    let Some(seconds) = unix.filter(|seconds| *seconds > 0) else {
        return "—".into();
    };
    let Ok(seconds) = i64::try_from(seconds) else {
        return "—".into();
    };
    // `Sun, 06 Nov 1994 08:49:37 GMT` → `06 Nov 1994 08:49`.
    let formatted = selfhost_http::date::format_unix(seconds);
    let mut parts = formatted.split_whitespace().skip(1);
    let (Some(day), Some(month), Some(year), Some(clock)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return "—".into();
    };
    let minutes = clock.get(..5).unwrap_or(clock);
    format!("{day} {month} {year} {minutes}")
}

/// Puts entries in display order: directories first, then the chosen column.
///
/// Mirrors `sortEntries`, which mirrors `selfhost_storage::listing::sort`.
/// Directories lead whatever the column, because that is what a file manager
/// means by sorted; a folder buried between two files because it happens to be
/// zero bytes reads as a defect. The name comparison folds case with a
/// byte-order tiebreak, so the order is total and a refresh does not look like
/// the directory changed.
pub fn sort_entries(entries: &mut [Entry], column: Column, ascending: bool) {
    let by_name = |a: &Entry, b: &Entry| {
        folded(&a.name).cmp(&folded(&b.name)).then_with(|| a.name.cmp(&b.name))
    };
    entries.sort_by(|a, b| {
        let directories_first =
            (a.kind != Kind::Directory).cmp(&(b.kind != Kind::Directory));
        let within = match column {
            Column::Name => by_name(a, b),
            Column::Size => a.size.cmp(&b.size).then_with(|| by_name(a, b)),
            Column::Modified => {
                a.modified.unwrap_or(0).cmp(&b.modified.unwrap_or(0)).then_with(|| by_name(a, b))
            }
        };
        directories_first.then(if ascending { within } else { within.reverse() })
    });
}

/// The case-folded form used for ordering only.
fn folded(name: &str) -> String {
    name.chars().flat_map(char::to_lowercase).collect()
}

/// A share-relative path split into segments, dropping the empties and the `.`s.
///
/// Mirrors `pathSegments`. The share root is the empty list.
pub fn path_segments(path: &str) -> Vec<&str> {
    path.split('/').filter(|segment| !segment.is_empty() && *segment != ".").collect()
}

/// The plain path back from a possibly untidy one: what a person reads.
pub fn plain_path(path: &str) -> String {
    path_segments(path).join("/")
}

/// A plain path as it may appear in a URL.
///
/// Mirrors `urlPath`, which mirrors `RelativePath::to_url_path`. **The only way
/// a name in this console becomes part of a request**, and what makes a name
/// safe in a query string as well as in a path: `&`, `=` and `#` come back as
/// escapes, so a file called `a&b=c` cannot invent a second parameter.
pub fn url_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for (index, segment) in path_segments(path).into_iter().enumerate() {
        if index > 0 {
            out.push('/');
        }
        for byte in segment.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(byte as char);
                }
                other => out.push_str(&format!("%{other:02X}")),
            }
        }
    }
    out
}

/// A child's plain path inside a directory, or `None` for a name no request can
/// ever address.
///
/// Mirrors `joinPath`. A separator inside a stored name is not hypothetical:
/// `a\b.txt` is a legal filename on APFS and ext4, and the daemon maps `\` to
/// `/` unconditionally so that a Mac-written share cannot become traversable the
/// day it is served from the Windows box. The cost is that such a name is
/// unreachable — which the listing already reports — and answering `None` is
/// what stops this console building a link that would open something else.
pub fn join_path(directory: &str, name: &str) -> Option<String> {
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    if name.contains(['/', '\\', '\0']) {
        return None;
    }
    let mut segments: Vec<&str> = path_segments(directory);
    segments.push(name);
    Some(segments.join("/"))
}

/// The directory holding this path; the share root's parent is itself.
pub fn parent_path(path: &str) -> String {
    let mut segments = path_segments(path);
    segments.pop();
    segments.join("/")
}

/// The breadcrumb trail for a directory, outermost first, as `(label, path)`.
///
/// Mirrors `crumbs`, which mirrors `Listing::breadcrumbs`. The share root is not
/// in the trail — the plate draws it as the share's own id, which is what a
/// person calls it. Each crumb leads to a *prefix* of the path it came from,
/// which is the property that makes the trail a navigation rather than a
/// decoration.
pub fn crumbs(path: &str) -> Vec<(String, String)> {
    let mut trail = Vec::new();
    let mut walked: Vec<&str> = Vec::new();
    for segment in path_segments(path) {
        walked.push(segment);
        trail.push((segment.to_owned(), walked.join("/")));
    }
    trail
}

/// Whether a share id may appear in a request path.
///
/// Mirrors `usableShareId` and the daemon's own `ShareId::parse`: lower-case
/// alphanumerics and single interior separators, never leading or trailing.
/// Checked rather than escaped, for the reason `poller::service_path` gives: a
/// value that does not match the daemon's grammar did not come from the daemon.
pub fn usable_share_id(id: &str) -> bool {
    usable_token(id, MAX_SHARE_ID)
}

/// The grammar behind [`usable_share_id`] and its node-name counterpart.
///
/// Shared so that the two cannot drift apart in the way two hand-written
/// character loops always do; the only difference between them is the ceiling.
pub fn usable_token(text: &str, limit: usize) -> bool {
    if text.is_empty() || text.chars().count() > limit {
        return false;
    }
    let mut previous_was_separator = false;
    for (index, character) in text.chars().enumerate() {
        let separator = matches!(character, '-' | '_' | '.');
        let alphanumeric = character.is_ascii_lowercase() || character.is_ascii_digit();
        if !separator && !alphanumeric {
            return false;
        }
        if separator && (index == 0 || previous_was_separator) {
            return false;
        }
        previous_was_separator = separator;
    }
    !previous_was_separator
}

/// The sentence to show for a refused storage request.
///
/// Mirrors `refusalText`, and the ordering is the point. The storage API answers
/// `{"error": <stable tag>, "message": <prose>}`, where a 507 carries *"this
/// share is limited to N bytes and already holds M; the upload needs another K"*
/// — a number only the server knows, and the one thing that tells the operator
/// what to delete. So the prose wins, the tag is the fallback, and a sentence of
/// this console's own invention is the last resort.
pub fn refusal_text(status: u16, body: Option<&Json>) -> String {
    if let Some(message) =
        body.and_then(|body| body.get("message")).and_then(Json::as_str).map(str::trim)
    {
        if !message.is_empty() {
            return message.to_owned();
        }
    }
    if let Some(tag) = body.and_then(|body| body.get("error")).and_then(Json::as_str).map(str::trim)
    {
        if !tag.is_empty() {
            return tag.to_owned();
        }
    }
    match status {
        0 => "the server could not be reached".into(),
        401 => "not permitted".into(),
        404 => "there is nothing there".into(),
        code => format!("the server refused this ({code})"),
    }
}

/// A JSON number as whole bytes, or `None` for `null` and for anything that is
/// not a finite count.
///
/// `Number(null)` is nought in every language with an implicit conversion, and
/// nought is exactly the lie a NAS panel must not tell about a share it could
/// not measure.
fn whole(value: Option<&Json>) -> Option<u64> {
    let number = value?.as_f64()?;
    (number.is_finite() && number >= 0.0).then_some(number as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, kind: Kind, size: u64, modified: Option<u64>) -> Entry {
        Entry {
            name: name.into(),
            kind,
            size,
            modified,
            path: Some(name.into()),
            blocked: None,
        }
    }

    #[test]
    fn a_share_that_could_not_be_measured_is_not_reported_as_empty() {
        let value = Json::object([
            ("id", Json::string("vault")),
            ("usedBytes", Json::Null),
            ("quotaBytes", Json::Null),
        ]);
        let share = Share::from_json(&value).expect("a share");
        assert_eq!(share.used_bytes, None);
        let reading = quota_reading(&share);
        assert_eq!(reading.status, Status::Warn);
        assert!(reading.text.contains("cannot be measured"));
        assert_eq!(reading.fraction, None, "there is nothing to light");
    }

    #[test]
    fn a_share_whose_id_could_not_appear_in_a_request_is_not_drawn_at_all() {
        for bad in ["../etc", "Vault", "a b", "", "-lead", "trail-", "a--b"] {
            let value = Json::object([("id", Json::string(bad))]);
            assert!(Share::from_json(&value).is_none(), "accepted the share id {bad:?}");
        }
        assert!(usable_share_id("vault"));
        assert!(usable_share_id("photos-2024.raw"));
    }

    #[test]
    fn a_full_share_reads_red_and_a_comfortable_one_reads_green() {
        let share = |used: u64| Share {
            id: "vault".into(),
            used_bytes: Some(used),
            quota_bytes: Some(1000),
            ..Default::default()
        };
        assert_eq!(quota_reading(&share(100)).status, Status::Ok);
        assert_eq!(quota_reading(&share(900)).status, Status::Warn);
        assert_eq!(quota_reading(&share(990)).status, Status::Bad);
        assert_eq!(quota_reading(&share(2000)).fraction, Some(1.0), "never past full");
    }

    #[test]
    fn a_share_with_no_ceiling_reports_the_room_left_on_the_volume() {
        let share = Share {
            id: "vault".into(),
            used_bytes: Some(2048),
            available_bytes: Some(4096),
            ..Default::default()
        };
        let reading = quota_reading(&share);
        assert_eq!(reading.text, "2.00 kB used · 4.00 kB free");
        assert_eq!(reading.fraction, None, "there is no ceiling to take a share of");
    }

    #[test]
    fn bytes_are_read_in_the_units_a_person_uses() {
        assert_eq!(size_text(0), "0 B");
        assert_eq!(size_text(999), "999 B");
        assert_eq!(size_text(1024), "1.00 kB");
        assert_eq!(size_text(5 * 1024 * 1024 * 1024), "5.00 GB");
    }

    #[test]
    fn a_directory_leads_whatever_the_column_and_whichever_direction() {
        let mut entries = vec![
            entry("beta.txt", Kind::File, 10, Some(200)),
            entry("Alpha", Kind::Directory, 0, Some(100)),
            entry("apple.txt", Kind::File, 30, Some(50)),
        ];
        for (column, ascending) in
            [(Column::Name, true), (Column::Size, false), (Column::Modified, true)]
        {
            sort_entries(&mut entries, column, ascending);
            assert_eq!(entries[0].name, "Alpha", "a folder is never buried by a column");
        }
    }

    #[test]
    fn names_sort_the_way_the_daemon_already_sorted_them() {
        // Case-folded, byte-order tiebreak: the same rule as `listing::sort`,
        // so the console's own default agrees with the order the reply arrived
        // in and a refresh does not look like the directory changed.
        let mut entries = vec![
            entry("Zebra", Kind::File, 0, None),
            entry("apple", Kind::File, 0, None),
            entry("README", Kind::File, 0, None),
            entry("readme", Kind::File, 0, None),
        ];
        sort_entries(&mut entries, Column::Name, true);
        let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();
        assert_eq!(names, ["apple", "README", "readme", "Zebra"]);
    }

    #[test]
    fn a_name_no_request_can_address_gets_no_path_rather_than_a_wrong_one() {
        assert_eq!(join_path("a", "b.txt").as_deref(), Some("a/b.txt"));
        for bad in ["a/b", "a\\b", "..", ".", "", "a\0b"] {
            assert!(join_path("a", bad).is_none(), "accepted the name {bad:?}");
        }
    }

    #[test]
    fn every_crumb_leads_to_a_prefix_of_the_path_it_came_from() {
        let path = "photos/2024/summer";
        let trail = crumbs(path);
        assert_eq!(trail.len(), 3);
        for (label, target) in &trail {
            assert!(path.starts_with(target.as_str()), "{target} is not a prefix of {path}");
            assert!(target.ends_with(label.as_str()));
        }
        assert!(crumbs("").is_empty(), "the share root is drawn as the share");
    }

    #[test]
    fn a_name_with_a_reserved_character_cannot_invent_a_second_parameter() {
        assert_eq!(url_path("a&b=c"), "a%26b%3Dc");
        assert_eq!(url_path("100%"), "100%25");
        assert_eq!(url_path("/a/./b/"), "a/b");
        assert_eq!(url_path("tax/2019 return.pdf"), "tax/2019%20return.pdf");
    }

    #[test]
    fn the_parent_of_the_root_is_the_root() {
        assert_eq!(parent_path("a/b"), "a");
        assert_eq!(parent_path("a"), "");
        assert_eq!(parent_path(""), "");
    }

    #[test]
    fn a_refusal_shows_the_servers_own_sentence_before_its_tag() {
        let body = Json::object([
            ("error", Json::string("out-of-room")),
            ("message", Json::string("this share is limited to 500 GB and holds 499")),
        ]);
        assert_eq!(refusal_text(507, Some(&body)), "this share is limited to 500 GB and holds 499");

        let tag_only = Json::object([("error", Json::string("out-of-room"))]);
        assert_eq!(refusal_text(507, Some(&tag_only)), "out-of-room");
        assert_eq!(refusal_text(404, None), "there is nothing there");
        assert_eq!(refusal_text(0, None), "the server could not be reached");
    }

    #[test]
    fn an_absent_timestamp_is_a_dash_and_never_nineteen_seventy() {
        assert_eq!(when_text(None), "—");
        assert_eq!(when_text(Some(0)), "—");
        assert_eq!(when_text(Some(784_111_777)), "06 Nov 1994 08:49");
    }

    #[test]
    fn an_unreachable_entry_is_read_but_never_linked() {
        let value = Json::object([
            ("name", Json::string("a\\b.txt")),
            ("kind", Json::string("file")),
            ("reachable", Json::Bool(false)),
            ("blockedReason", Json::string("the name contains a separator")),
        ]);
        let entry = Entry::from_json(&value, "").expect("an entry");
        assert!(entry.path.is_none(), "a name with a separator gets no link");
        assert_eq!(entry.blocked.as_deref(), Some("the name contains a separator"));
    }

    #[test]
    fn a_listing_is_read_at_the_directory_the_daemon_answered_for() {
        let value = Json::object([
            ("path", Json::string("photos/2024")),
            (
                "entries",
                Json::array([Json::object([
                    ("name", Json::string("beach.jpg")),
                    ("kind", Json::string("file")),
                    ("size", Json::Number(2048.0)),
                ])]),
            ),
        ]);
        let listing = Listing::from_json("vault", &value).expect("a listing");
        assert_eq!(listing.path, "photos/2024");
        assert_eq!(listing.entries[0].path.as_deref(), Some("photos/2024/beach.jpg"));
    }

    #[test]
    fn absence_is_a_sentence_and_never_an_error() {
        assert!(shares_note(None).contains("no shares"));
        assert!(shares_note(Some(&[])).contains("yours to open"));
        assert_eq!(shares_note(Some(&[Share::default()])), "");
    }
}
