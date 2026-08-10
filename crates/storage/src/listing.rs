//! What one directory contains, as a value.
//!
//! Pure. Nothing here reads a directory — the filesystem layer does that and
//! hands the results in one entry at a time. That split is what lets the awkward
//! parts be tested without a disk: an entry whose name is not valid UTF-8, an
//! entry whose name this share would refuse to serve, a directory containing
//! forty thousand files, and the ordering a person expects to see.
//!
//! # Names that exist but cannot be served
//!
//! A share's contents were not all put there by the NAS. Somebody wrote files
//! over SMB, or restored a backup, or the volume came from another machine. So a
//! directory can genuinely contain a name that [`crate::path::validate_segment`]
//! refuses: a `CON.txt` written on a Mac, a name with a colon in it, a name that
//! is not UTF-8 at all.
//!
//! Three answers were available, and two of them are wrong:
//!
//! - **Hide it.** Then a person looking at Finder and at the console sees two
//!   different directories, and the one file they cannot find is the one they
//!   came to look for.
//! - **Serve it anyway.** Then the resolver's rules are advisory, which means
//!   they are not rules.
//! - **Show it, marked unreachable.** The listing tells the truth about what is
//!   on the volume, the console renders it greyed with a reason, and no URL
//!   exists that would fetch it. This is what [`Entry::reachable`] is for.
//!
//! # The JSON shape
//!
//! Hand-written camelCase, the same contract-with-the-console idiom
//! [`selfhost_firewall::state`](../../selfhost_firewall/state/index.html) and
//! [`selfhost_supervisor::state`](../../selfhost_supervisor/state/index.html)
//! use. Sizes are numbers and times are Unix seconds, because a JSON number is
//! the only representation the browser cannot get wrong; formatting a date is
//! the front end's job and it already knows the reader's locale.
//!
//! # The listing is where a stored name becomes a link, so it carries the URL
//!
//! Every reachable entry ships two spellings of itself: `name`, which is the
//! name as a person reads it, and `path`, which is the same name
//! [percent-encoded](crate::path::encode_segment) and joined onto the directory
//! it was found in. The console links to `path` and never builds one out of
//! `name`.
//!
//! That is not a convenience. `%` is a legal character in a filename, so a
//! directory can hold `a%2fb` — a name whose *own text*, put in a URL, asks for
//! `a/b` one directory down. The rule "every layer that renders a stored name
//! into a URL must encode it" cannot be enforced by writing it down, so it is
//! enforced by the type instead: [`Entry::to_json`] takes the parent path it
//! needs to produce `path`, which means no caller can render an entry without
//! having handed over what the encoder needs. [`crate::path`]'s module
//! documentation states the round-trip invariant this keeps.

use crate::path::{self, RelativePath};
use selfhost_json::Json;
use std::ffi::OsStr;
use std::time::{SystemTime, UNIX_EPOCH};

/// Whether an entry is a file or a directory.
///
/// There is no third variant. A symlink is never reported as itself: the
/// filesystem layer refuses to follow one and refuses to create one, so a
/// symlink found in a share is reported as [`Entry::reachable`] `== false` with
/// the same treatment as any other name that cannot be served. Giving it a
/// variant of its own would invite a caller to handle it, and the only correct
/// handling is to refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A file, whose bytes can be fetched.
    File,
    /// A directory, which can be listed.
    Directory,
}

impl Kind {
    /// The wire spelling.
    pub fn tag(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "dir",
        }
    }

    /// Reads a kind back from its spelling.
    pub fn from_tag(text: &str) -> Option<Self> {
        match text {
            "file" => Some(Self::File),
            "dir" => Some(Self::Directory),
            _ => None,
        }
    }
}

/// Why an entry cannot be served, when it cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreachable {
    /// The name on disk is not valid UTF-8, so it cannot be put in a URL, a
    /// JSON string, or a WebDAV `href` without becoming a different name.
    NotUtf8,
    /// The name is valid UTF-8 but breaks a rule the resolver enforces — a
    /// reserved device name, a colon, a trailing dot. It was almost certainly
    /// written by another operating system.
    Refused(path::Refusal),
}

impl Unreachable {
    /// A short reason a person reads, in the console's entry row.
    pub fn reason(self) -> String {
        match self {
            Self::NotUtf8 => "name is not valid UTF-8".to_string(),
            Self::Refused(refusal) => refusal.to_string(),
        }
    }
}

/// One name in a directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The name as it will be shown. For an unreachable non-UTF-8 name this is
    /// the lossy rendering, which is good enough to look at and deliberately not
    /// good enough to fetch — [`Entry::reachable`] is what a caller checks.
    pub name: String,
    /// File or directory.
    pub kind: Kind,
    /// Size in bytes. Zero for a directory: the number of bytes a directory
    /// *contains* is a recursive walk, and answering it on every listing would
    /// turn one `readdir` into a whole-subtree scan.
    pub size: u64,
    /// Last modification time, when the filesystem reported one.
    pub modified: Option<SystemTime>,
    /// `None` when the entry can be served under this name.
    pub blocked: Option<Unreachable>,
}

impl Entry {
    /// Builds an entry from a raw directory name, deciding reachability.
    ///
    /// Takes an [`OsStr`] because that is what `read_dir` yields and because the
    /// non-UTF-8 case must be *observed*, not lost: converting to a `String`
    /// before this function would either lose the failure or panic on it, and
    /// under `panic = "abort"` the second option is a whole-box outage caused by
    /// a filename.
    pub fn new(name: &OsStr, kind: Kind, size: u64, modified: Option<SystemTime>) -> Self {
        let (name, blocked) = match name.to_str() {
            None => (name.to_string_lossy().into_owned(), Some(Unreachable::NotUtf8)),
            Some(text) => match path::validate_segment(text) {
                Ok(()) => (text.to_string(), None),
                Err(refusal) => (text.to_string(), Some(Unreachable::Refused(refusal))),
            },
        };
        Self {
            name,
            kind,
            size: if kind == Kind::Directory { 0 } else { size },
            modified,
            blocked,
        }
    }

    /// Whether a URL exists that fetches this entry.
    pub fn reachable(&self) -> bool {
        self.blocked.is_none()
    }

    /// The entry as the console reads it, inside the directory it was found in.
    ///
    /// `parent` is required rather than optional because it is what makes the
    /// `path` field — the share-relative, percent-encoded URL for this entry —
    /// possible. A `to_json` that could be called without it would be a
    /// `to_json` that renders a name with no link, and the next person to need
    /// a link would build one by concatenating `name`, which is the bug this
    /// module's documentation describes.
    ///
    /// An unreachable entry gets no `path`: there is no URL that fetches it, and
    /// emitting one that resolves to something *else* — which is exactly what a
    /// name containing a backslash would do — is worse than emitting none. The
    /// console renders those rows greyed, with `blockedReason` as the tooltip.
    pub fn to_json(&self, parent: &RelativePath) -> Json {
        let mut fields = vec![
            ("name", Json::string(&self.name)),
            ("kind", Json::string(self.kind.tag())),
            ("size", Json::Number(self.size as f64)),
            ("reachable", Json::Bool(self.reachable())),
        ];
        if let Ok(path) = parent.join(&self.name) {
            fields.push(("path", Json::string(path.to_url_path())));
        }
        if let Some(seconds) = self.modified.and_then(unix_seconds) {
            fields.push(("modified", Json::Number(seconds as f64)));
        }
        if let Some(blocked) = self.blocked {
            fields.push(("blockedReason", Json::string(blocked.reason())));
        }
        Json::object(fields)
    }
}

/// One directory, as the API answers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    /// Where in the share this is, relative to its root.
    pub path: RelativePath,
    /// The entries, in the order they should be shown.
    pub entries: Vec<Entry>,
}

impl Listing {
    /// Builds a listing, putting the entries in display order.
    pub fn new(path: RelativePath, mut entries: Vec<Entry>) -> Self {
        sort(&mut entries);
        Self { path, entries }
    }

    /// The breadcrumb trail, outermost first, as `(label, url)` pairs.
    ///
    /// Derived here rather than in the front end so that the console and the
    /// native client cannot disagree about what a path means — and so the rule
    /// that each crumb leads to a *prefix* of this directory is asserted in a
    /// test rather than trusted to two implementations.
    ///
    /// The two halves of a pair are deliberately different spellings of the same
    /// thing: the label is the name as written, for a person to read, and the
    /// url is [percent-encoded](crate::path::encode_segment), for a link. A
    /// directory called `100%` proves why they cannot be one string.
    pub fn breadcrumbs(&self) -> Vec<(String, String)> {
        let mut trail = Vec::with_capacity(self.path.segments().len());
        let mut walked = RelativePath::default();
        for segment in self.path.segments() {
            // Every segment of a `RelativePath` has already been validated, so
            // this join cannot fail; if it somehow did, the honest answer is to
            // leave the crumb out rather than to emit a link to a different
            // directory.
            let Ok(next) = walked.join(segment) else {
                continue;
            };
            walked = next;
            trail.push((segment.clone(), walked.to_url_path()));
        }
        trail
    }

    /// The listing as the console reads it.
    ///
    /// `path` is the directory as a person reads it and `urlPath` is the same
    /// directory encoded for a link — the same two spellings every entry
    /// carries, and for the same reason.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("path", Json::string(self.path.to_string())),
            ("urlPath", Json::string(self.path.to_url_path())),
            (
                "entries",
                Json::array(self.entries.iter().map(|entry| entry.to_json(&self.path))),
            ),
        ])
    }
}

/// Puts entries in the order a person expects: directories first, then names.
///
/// Names sort case-insensitively, because a listing that puts `Zebra` before
/// `apple` is sorting by an encoding rather than by a name, and nobody reads it
/// that way. Ties inside the fold — `README` and `readme`, which are two files
/// on ext4 — fall back to the byte order so the sort is total and the output is
/// stable between calls; an unstable listing makes every console refresh look
/// like the directory changed.
pub fn sort(entries: &mut [Entry]) {
    entries.sort_by(|a, b| {
        let directories_first = (a.kind != Kind::Directory).cmp(&(b.kind != Kind::Directory));
        directories_first
            .then_with(|| folded(&a.name).cmp(&folded(&b.name)))
            .then_with(|| a.name.cmp(&b.name))
    });
}

/// The case-folded form used for ordering only.
fn folded(name: &str) -> String {
    name.chars().flat_map(char::to_lowercase).collect()
}

/// A modification time as whole Unix seconds, or `None` if it predates 1970.
///
/// A pre-epoch timestamp is not an error worth failing a whole listing over —
/// it is a file with a strange date, usually restored from a backup — so the
/// field is simply omitted and the console shows no date for that row.
fn unix_seconds(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn file(name: &str) -> Entry {
        Entry::new(OsStr::new(name), Kind::File, 10, None)
    }

    fn directory(name: &str) -> Entry {
        Entry::new(OsStr::new(name), Kind::Directory, 0, None)
    }

    #[test]
    fn a_serveable_name_is_reachable() {
        let entry = file("notes.txt");
        assert!(entry.reachable());
        assert_eq!(entry.blocked, None);
        assert_eq!(entry.name, "notes.txt");
    }

    #[test]
    fn a_name_this_share_would_refuse_is_shown_but_not_served() {
        // Written over SMB from a machine with different rules, or restored
        // from a backup. It exists; pretending otherwise would mean the console
        // and Finder show different directories.
        for name in ["CON.txt", "readme.txt:evil", "trailing.", "PROGRA~1"] {
            let entry = file(name);
            assert!(!entry.reachable(), "{name} should be listed as unreachable");
            assert_eq!(entry.name, name, "the name is still shown");
            assert!(!entry.blocked.expect("a reason").reason().is_empty());
        }
    }

    #[test]
    fn a_non_utf8_name_is_lossy_to_look_at_and_impossible_to_fetch() {
        // Only unix filesystems permit arbitrary bytes in a name, so the case
        // can only be built there — but the *policy* is stated for every
        // platform and the field exists on all of them.
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let raw = OsStr::from_bytes(b"bad\xffname");
            let entry = Entry::new(raw, Kind::File, 4, None);
            assert_eq!(entry.blocked, Some(Unreachable::NotUtf8));
            assert!(!entry.reachable());
            assert!(entry.name.contains("bad"));
        }
        assert_eq!(Unreachable::NotUtf8.reason(), "name is not valid UTF-8");
    }

    #[test]
    fn a_directory_reports_no_size() {
        // The bytes a directory contains is a recursive walk, and doing one per
        // listing turns a `readdir` into a subtree scan.
        let entry = Entry::new(OsStr::new("photos"), Kind::Directory, 4096, None);
        assert_eq!(entry.size, 0);
    }

    #[test]
    fn directories_come_first_then_names_read_the_way_people_read_them() {
        let mut entries = vec![
            file("Zebra.txt"),
            file("apple.txt"),
            directory("photos"),
            directory("Archive"),
            file("Banana.txt"),
        ];
        sort(&mut entries);
        let order: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(order, ["Archive", "photos", "apple.txt", "Banana.txt", "Zebra.txt"]);
    }

    #[test]
    fn the_order_is_total_so_a_refresh_does_not_look_like_a_change() {
        // `README` and `readme` are two files on ext4 and fold to the same key,
        // so the fold alone is not an ordering.
        let mut entries = vec![file("readme"), file("README"), file("ReadMe")];
        sort(&mut entries);
        let first: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        sort(&mut entries);
        let second: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        assert_eq!(first, second);
        assert_eq!(first, ["README", "ReadMe", "readme"]);
    }

    #[test]
    fn breadcrumbs_lead_to_prefixes_of_the_directory_they_are_shown_in() {
        let path = RelativePath::default()
            .join("photos")
            .unwrap()
            .join("2026")
            .unwrap()
            .join("june")
            .unwrap();
        let listing = Listing::new(path, Vec::new());
        assert_eq!(
            listing.breadcrumbs(),
            vec![
                ("photos".to_string(), "photos".to_string()),
                ("2026".to_string(), "photos/2026".to_string()),
                ("june".to_string(), "photos/2026/june".to_string()),
            ]
        );

        for (_, crumb) in listing.breadcrumbs() {
            assert!(listing.path.to_url_path().starts_with(&crumb));
        }

        assert!(Listing::new(RelativePath::default(), Vec::new()).breadcrumbs().is_empty());
    }

    /// A crumb's label is for a person and its url is for a browser, and the two
    /// are different strings whenever the name is interesting.
    #[test]
    fn a_breadcrumb_label_is_read_and_its_url_is_followed() {
        let path = RelativePath::default().join("100% done").unwrap().join("a%2fb").unwrap();
        let listing = Listing::new(path, Vec::new());
        assert_eq!(
            listing.breadcrumbs(),
            vec![
                ("100% done".to_string(), "100%25%20done".to_string()),
                ("a%2fb".to_string(), "100%25%20done/a%252fb".to_string()),
            ]
        );
    }

    #[test]
    fn the_json_is_the_shape_the_console_reads() {
        let modified = UNIX_EPOCH + Duration::from_secs(1_770_000_000);
        let entries = vec![
            Entry::new(OsStr::new("photos"), Kind::Directory, 0, Some(modified)),
            Entry::new(OsStr::new("notes.txt"), Kind::File, 42, Some(modified)),
            Entry::new(OsStr::new("CON.txt"), Kind::File, 7, None),
        ];
        let listing = Listing::new(RelativePath::default().join("work").unwrap(), entries);
        assert_eq!(
            listing.to_json().to_text(),
            concat!(
                r#"{"entries":["#,
                r#"{"kind":"dir","modified":1770000000,"name":"photos","path":"work/photos","#,
                r#""reachable":true,"size":0},"#,
                r#"{"blockedReason":"segment names a reserved device","kind":"file","#,
                r#""name":"CON.txt","reachable":false,"size":7},"#,
                r#"{"kind":"file","modified":1770000000,"name":"notes.txt","#,
                r#""path":"work/notes.txt","reachable":true,"size":42}"#,
                r#"],"path":"work","urlPath":"work"}"#,
            )
        );
    }

    /// The link a listing hands out fetches the file it was rendered from.
    ///
    /// This is the invariant `path.rs` states, asserted at the layer where it is
    /// actually at risk: a name holding a `%` renders into a link that names a
    /// *different* file the moment somebody builds the URL out of `name`. The
    /// unreachable row is the other half — no `path` at all, because the honest
    /// answer for a name no URL can express is no URL.
    #[test]
    fn the_link_in_a_listing_resolves_back_to_the_entry_it_came_from() {
        let root = std::path::Path::new("/srv/share");
        let directory = RelativePath::default().join("work").unwrap();
        for name in ["notes.txt", "a%2fb", "100% done", "caf\u{e9}.txt", "a b#c"] {
            let entry = Entry::new(OsStr::new(name), Kind::File, 1, None);
            let json = entry.to_json(&directory).to_text();
            let encoded = directory.join(name).unwrap().to_url_path();
            assert!(json.contains(&format!(r#""path":"{encoded}""#)), "{name}: {json}");

            let resolved = path::resolve(root, &format!("/{encoded}")).expect("a legal name");
            assert_eq!(resolved.relative().segments(), ["work", name], "round trip of {name:?}");
        }

        // A name no request can express carries no link at all.
        let blocked = Entry::new(OsStr::new("a\\b.txt"), Kind::File, 1, None);
        assert!(!blocked.reachable());
        assert!(!blocked.to_json(&directory).to_text().contains(r#""path""#));
    }

    #[test]
    fn a_pre_epoch_timestamp_omits_the_field_rather_than_failing() {
        let ancient = UNIX_EPOCH - Duration::from_secs(1);
        let entry = Entry::new(OsStr::new("old.txt"), Kind::File, 1, Some(ancient));
        assert!(!entry.to_json(&RelativePath::default()).to_text().contains("modified"));
        assert_eq!(unix_seconds(ancient), None);
        assert_eq!(unix_seconds(UNIX_EPOCH), Some(0));
    }

    #[test]
    fn kinds_round_trip_through_their_spelling() {
        for kind in [Kind::File, Kind::Directory] {
            assert_eq!(Kind::from_tag(kind.tag()), Some(kind));
        }
        assert_eq!(Kind::from_tag("symlink"), None);
    }
}
