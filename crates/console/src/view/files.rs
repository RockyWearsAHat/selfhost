//! The FILES screen: every share this credential may open, one directory at a
//! time, with the four things a person does to a file.
//!
//! # Shape, and why it is the rail again
//!
//! A rail of shares on the left and one directory on the right, which is the
//! shape the SERVICES screen already uses and the shape every file manager
//! uses. The argument is the same one the module documentation of
//! [`super`] makes about services: the operator is working inside one directory
//! while keeping an eye on how much room is left in the others, and tabs would
//! hide the second half of that.
//!
//! # What raises its voice
//!
//! A quota near its ceiling, and nothing else. Every row in a listing is
//! ordinary — that is what a listing is — so the plate is deliberately quiet:
//! sizes and dates in the citation face, names in the reading face, and colour
//! spent only on a share that is nearly full and on a name the daemon says
//! cannot be addressed at all. A file manager where every row was lit would be
//! one where a full disk is invisible.
//!
//! # Nothing here decides anything
//!
//! Every judgement — what sorts first, what a quota reading says, which path a
//! crumb leads to, whether a name can appear in a request — is
//! [`crate::nas`]'s, tested there beside its counterpart in the browser. This
//! module is rectangles.

use super::style;
use super::Console;
use crate::nas::{self, Column, Entry, Kind, Listing, Share};
use crate::state::{Command, FileAction};
use rui::style::Justify;
use rui::{
    Align, El, Length, Role, Status, button, caption, col, field, micro, row, spacer, text,
};

/// The share of the row each column takes.
///
/// Fractions rather than widths, for the reason [`super::exposure`]'s columns
/// are fractions: the header and every row then line up by share of the plate's
/// width however long the names in them are.
const NAME_W: f32 = 0.46;
/// See [`NAME_W`].
const SIZE_W: f32 = 0.16;
/// See [`NAME_W`].
const WHEN_W: f32 = 0.24;
/// See [`NAME_W`].
const ACT_W: f32 = 0.14;

/// How tall one row of the listing is.
///
/// Shorter than the rail's own [`super::ROW_HEIGHT`]: a service's row carries a
/// name over a summary and this carries one line, and a directory of forty
/// entries at forty-two units each is a directory nobody can see the end of.
const ROW: f32 = 24.0;

/// The narrowest the share rail may be drawn.
const RAIL_MIN: f32 = 180.0;

/// The widest, past which it is stretching a list of short names.
const RAIL_MAX: f32 = 280.0;

/// What share of the window the rail takes.
const RAIL_SHARE: f32 = 0.26;

/// The whole screen: the shares, and the directory that is open.
pub fn view(console: &Console) -> El<Console> {
    let snapshot = console.snapshot();
    row((shares(&snapshot), directory(console, &snapshot))).gap(8.0).grow()
}

/// The rail of shares, each with what it holds and how much room is left.
fn shares(snapshot: &crate::state::Snapshot) -> El<Console> {
    let declared = snapshot.files.shares.as_deref();
    let note = nas::shares_note(declared);
    let body: El<Console> = if note.is_empty() {
        let chosen = snapshot.files.share.as_deref();
        col(declared
            .unwrap_or(&[])
            .iter()
            .map(|share| share_row(share, chosen == Some(share.id.as_str())))
            .collect::<Vec<_>>())
        .gap(2.0)
        .scroll()
        .role(Role::List)
    } else {
        col(caption(note).wrap().center_text()).pad_y(24.0)
    };

    style::plate((
        style::section_rule("SHARES", declared.map(|shares| shares.len().to_string())),
        // The list takes the room the rail has left rather than a spacer under
        // it: what is below the last share is a rail with space for more, and a
        // spacer that grew would push nothing anywhere.
        body.grow(),
    ))
    .gap(8.0)
    .w(Length::Fraction(RAIL_SHARE))
    .min_w(RAIL_MIN)
    .max_w(RAIL_MAX)
}

/// One share in the rail: its id, what it is, and its quota.
///
/// The gauge is a bar and not the bank's arc, because a share's fullness is read
/// *against the ones above and below it* — four bars in a column are compared at
/// a glance and four arcs are not — and because a bar can carry its own words on
/// the line beneath without becoming a dial with a caption.
fn share_row(share: &Share, chosen: bool) -> El<Console> {
    let reading = nas::quota_reading(share);
    let id = share.id.clone();
    col((
        row((
            style::wedge(chosen),
            text(share.id.clone()).grow(),
            // Only the facts that change what may be done. `browsable` is not
            // among them: whether a share is advertised over DNS-SD says
            // nothing about what this window can do with it.
            share.read_only.then(|| micro("READ ONLY").tracking(1.0)),
            share.smb.as_ref().map(|name| micro(format!("SMB {name}")).tracking(1.0)),
        ))
        // Stated, not derived. `style::wedge` takes a *fraction* of the height
        // it is given, so a row that sized itself from its own content would be
        // asking the wedge how tall it is while the wedge asks the row — and
        // the layout resolves that circle by growing without bound.
        .h(18.0)
        .gap(6.0)
        .align(Align::Center),
        // Only where there is a ceiling to take a share of. An empty track
        // under a share with no quota reads as *nought used*, which is the one
        // thing `quota_reading` refuses to say in words — and a bar drawn to
        // nought is a louder claim than the sentence beneath it.
        reading.fraction.map(|share| rui::meter(share, style::state_ink(reading.status))),
        caption(reading.text),
    ))
    .gap(3.0)
    .pad_each(5.0, 8.0, 5.0, 4.0)
    .min_h(52.0)
    .hover_fill(rui::Tone::Raised)
    .role(Role::ListItem)
    .selected(chosen)
    .key(share.id.clone())
    .on_click(move |console: &mut Console| {
        console.with_snapshot(|snapshot| snapshot.files.open(&id));
    })
}

/// The right-hand pane: where we are, what is in it, and what can be done.
fn directory(console: &Console, snapshot: &crate::state::Snapshot) -> El<Console> {
    let Some(share) = snapshot.files.share() else {
        return style::plate((
            super::title_rule("FILES".into(), None),
            col(caption("Choose a share.").wrap().center_text()).pad_y(24.0).grow(),
        ))
        .gap(8.0)
        .grow();
    };
    let writable = share.writable;

    style::plate((
        super::title_rule(
            share.id.to_uppercase(),
            Some(micro(nas::quota_reading(share).text).align_self(Align::Center)),
        ),
        breadcrumb(&snapshot.files.path, &share.id),
        snapshot.files.trouble.clone().map(trouble),
        header_row(snapshot.files.column, snapshot.files.ascending),
        listing(snapshot.files.listing(), snapshot.files.selected.as_deref(), writable),
        actions(console, snapshot, writable),
    ))
    .gap(6.0)
    .grow()
}

/// Why the last listing was refused, in the daemon's own words.
fn trouble(reason: String) -> El<Console> {
    row((style::lamp(Status::Bad), caption(reason).wrap().grow()))
        .gap(6.0)
        .align(Align::Center)
}

/// The trail back to the share's root.
///
/// The root is the share's own id rather than a slash, because that is what a
/// person calls it, and every crumb leads to a prefix of where we are — which is
/// what makes the trail a navigation rather than a decoration.
fn breadcrumb(path: &str, share: &str) -> El<Console> {
    let mut trail: Vec<El<Console>> = vec![crumb(share.to_uppercase(), String::new())];
    for (label, target) in nas::crumbs(path) {
        trail.push(micro("/"));
        trail.push(crumb(label, target));
    }
    row(trail).gap(4.0).flow().min_h(18.0).align(Align::Center)
}

/// One step of the trail.
fn crumb(label: String, target: String) -> El<Console> {
    micro(label)
        .tracking(0.8)
        .hover_color(rui::Tone::Text)
        .on_click(move |console: &mut Console| {
            let target = target.clone();
            console.with_snapshot(|snapshot| snapshot.files.go(target));
        })
}

/// The heading naming the four columns, each of the first three a sort control.
///
/// Pressing a column that is already the sort reverses it, which is what every
/// file manager does and what a person tries first.
fn header_row(column: Column, ascending: bool) -> El<Console> {
    let heading = move |which: Column, width: f32| {
        let chosen = which == column;
        let arrow = match (chosen, ascending) {
            (false, _) => "",
            (true, true) => " ▲",
            (true, false) => " ▼",
        };
        micro(format!("{}{arrow}", which.label()))
            .tracking(1.2)
            .w(Length::Fraction(width))
            .color(if chosen { rui::Tone::Text } else { rui::Tone::Muted })
            .hover_color(rui::Tone::Text)
            .on_click(move |console: &mut Console| {
                console.with_snapshot(|snapshot| {
                    if snapshot.files.column == which {
                        snapshot.files.ascending = !snapshot.files.ascending;
                    } else {
                        snapshot.files.column = which;
                        snapshot.files.ascending = true;
                    }
                    // Re-ordered here rather than waited for: the next poll is
                    // half a second away and a header that does not answer the
                    // press reads as one that did nothing.
                    let (column, ascending) = (snapshot.files.column, snapshot.files.ascending);
                    if let Some(listing) = snapshot.files.listing.as_mut() {
                        nas::sort_entries(&mut listing.entries, column, ascending);
                    }
                });
            })
    };
    row((
        heading(Column::Name, NAME_W),
        heading(Column::Size, SIZE_W),
        heading(Column::Modified, WHEN_W),
        micro("").w(Length::Fraction(ACT_W)),
    ))
    .min_h(14.0)
}

/// The directory's names, or the sentence that stands in for them.
fn listing(
    listing: Option<&Listing>,
    selected: Option<&str>,
    writable: bool,
) -> El<Console> {
    let Some(listing) = listing else {
        // Not "empty": a directory that has not been read and one that holds
        // nothing both draw no rows, and only one of them is a fact.
        return col(caption("Reading the directory…").wrap().center_text()).pad_y(24.0).grow();
    };
    if listing.entries.is_empty() {
        return col(caption("This folder is empty.").wrap().center_text()).pad_y(24.0).grow();
    }
    col(listing
        .entries
        .iter()
        .map(|entry| entry_row(entry, selected == Some(entry.name.as_str()), writable))
        .collect::<Vec<_>>())
    .gap(1.0)
    .scroll()
    .grow()
    .role(Role::List)
}

/// One name: what it is, how big, when, and the one control it carries.
///
/// A directory opens on a press and a file is chosen by one, which is the
/// difference every file manager draws and the reason the two are not the same
/// row. A name the daemon says cannot be addressed is drawn in the idle ink with
/// its reason beside it and answers no press at all — there is no request that
/// would reach it, and a row that looked ordinary and refused every press would
/// be worse than one that says why.
fn entry_row(entry: &Entry, chosen: bool, writable: bool) -> El<Console> {
    let name = entry.name.clone();
    let is_directory = entry.kind == Kind::Directory;
    let mark = match entry.kind {
        Kind::Directory => "▸",
        Kind::File => "·",
        Kind::Other => "?",
    };

    let Some(path) = entry.path.clone() else {
        return row((
            micro(mark).w(14.0),
            text(entry.name.clone()).color(rui::Tone::Idle).grow(),
            caption(entry.blocked.clone().unwrap_or_else(|| "unreachable".into())),
        ))
        .gap(6.0)
        .min_h(ROW)
        .align(Align::Center);
    };

    let opened = path.clone();
    let chosen_name = name.clone();
    row((
        row((
            micro(mark).w(14.0),
            // Truncated rather than dropped when the line runs short. The rail's
            // state word may vanish because the lamp beside it already said the
            // same thing; a file's name is said nowhere else, and half a name is
            // still a row a person can recognise.
            text(entry.name.clone()),
        ))
        .gap(4.0)
        .w(Length::Fraction(NAME_W))
        // Air on the trailing edge rather than a gap on the row. The four
        // columns are fractions that sum to one, so a gap *between* them is
        // width the row does not have — it overflowed, and the cell at the end
        // carrying the row's own controls was the part pushed off the plate.
        .pad_each(0.0, 8.0, 0.0, 0.0)
        .align(Align::Center),
        caption(if is_directory { String::new() } else { nas::size_text(entry.size) })
            .w(Length::Fraction(SIZE_W)),
        caption(nas::when_text(entry.modified)).w(Length::Fraction(WHEN_W)),
        row((
            (!is_directory).then(|| {
                let path = path.clone();
                style::icon_button("\u{2193}", "Download")
                    // Keyed by the entry: two rows' controls are the same mark
                    // and the same name, and identity derived from the drawing
                    // alone would make them the same control.
                    .key(format!("download {path}"))
                    .on_click(move |console: &mut Console| console.download(&path))
            }),
            writable.then(|| {
                let path = path.clone();
                style::icon_button("\u{00d7}", "Delete")
                    .key(format!("delete {path}"))
                    .on_click(move |console: &mut Console| console.delete_entry(&path))
            }),
        ))
        .gap(2.0)
        .w(Length::Fraction(ACT_W))
        .justify(Justify::End)
        .align(Align::Center),
    ))
    .min_h(ROW)
    .align(Align::Center)
    .hover_fill(rui::Tone::Raised)
    .role(Role::ListItem)
    .selected(chosen)
    .key(name)
    .on_click(move |console: &mut Console| {
        if is_directory {
            let target = opened.clone();
            console.with_snapshot(|snapshot| snapshot.files.go(target));
        } else {
            let chosen = chosen_name.clone();
            console.with_snapshot(|snapshot| snapshot.files.selected = Some(chosen));
        }
    })
}

/// The controls under the listing: up, a new folder, rename, and upload.
///
/// Every one of them is disabled rather than hidden when it cannot be used, and
/// the reason is the reason the detail pane keeps a Start button on a service
/// that cannot start: a control that vanishes leaves the operator looking for
/// it, and a control that is greyed says *this is the thing, and it is not
/// available to you here*. A read-only share therefore keeps its whole set,
/// greyed, and the share row says READ ONLY beside its name.
fn actions(console: &Console, snapshot: &crate::state::Snapshot, writable: bool) -> El<Console> {
    let at_root = snapshot.files.path.is_empty();
    let selected = snapshot.files.selected.clone();
    let form = console.files_form();

    let entry: El<Console> = field(form.text.clone())
        .grow()
        .label(form.purpose.label())
        .on_input(|console: &mut Console, typed| console.files_form_mut().text = typed)
        .on_submit(|console: &mut Console| console.submit_files_form());

    col((
        row((
            button("UP")
                .disabled(at_root)
                .on_click(|console: &mut Console| {
                    console.with_snapshot(|snapshot| {
                        let up = nas::parent_path(&snapshot.files.path);
                        snapshot.files.go(up);
                    });
                }),
            button("NEW FOLDER").disabled(!writable).on_click(|console: &mut Console| {
                console.files_form_mut().open(Purpose::NewFolder, String::new());
            }),
            button("RENAME").disabled(!writable || selected.is_none()).on_click(
                move |console: &mut Console| {
                    let name = console.snapshot().files.selected.clone().unwrap_or_default();
                    console.files_form_mut().open(Purpose::Rename, name);
                },
            ),
            button("UPLOAD").disabled(!writable).on_click(|console: &mut Console| {
                console.files_form_mut().open(Purpose::Upload, String::new());
            }),
            spacer().grow(),
        ))
        // A flow, not a row: four words in a pane 318 units wide are four words
        // cut to their first syllable, and a button whose label is an ellipsis
        // is a button nobody presses. They run onto a second line whole.
        .flow()
        .gap(6.0),
        form.is_open().then(|| {
            row((
                micro(form.purpose.label()).tracking(1.2).w(96.0).align_self(Align::Center),
                entry,
                button("OK").on_click(|console: &mut Console| console.submit_files_form()),
                style::icon_button("\u{00d7}", "Cancel")
                    .on_click(|console: &mut Console| console.files_form_mut().close()),
            ))
            .gap(6.0)
            .align(Align::Center)
        }),
        form.trouble.clone().map(|reason| caption(reason).color(rui::Tone::ink(Status::Bad)).wrap()),
        form.is_open().then(|| caption(form.purpose.hint()).wrap()),
    ))
    .gap(5.0)
}

/// What the one text field on this plate is being used for.
///
/// One field and not three, because all three ask the same question — *what
/// name* — and three fields stacked under a listing is three-quarters of the
/// pane spent on controls that are empty most of the time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Purpose {
    /// Nothing is being asked.
    #[default]
    Idle,
    /// A directory to create in the directory that is open.
    NewFolder,
    /// A new name for the chosen entry.
    Rename,
    /// A path on *this* machine to send into the share.
    Upload,
}

impl Purpose {
    /// The word beside the field.
    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "",
            Self::NewFolder => "NEW FOLDER",
            Self::Rename => "RENAME TO",
            Self::Upload => "UPLOAD FILE",
        }
    }

    /// What the field wants, said once so nobody has to guess.
    ///
    /// The upload case is the one that has to be said. A browser opens a file
    /// picker; this window has no picker to open — the platform dialogue is one
    /// unsafe call per backend and `rui` has none — so it asks for a path on
    /// this machine, and it says so rather than leaving a person typing a name
    /// into a field that wanted a path.
    pub fn hint(self) -> &'static str {
        match self {
            Self::Idle => "",
            Self::NewFolder => "One folder, inside the directory above. Not a path.",
            Self::Rename => "The new name. It stays in the same folder.",
            Self::Upload => {
                "The full path of a file on this machine. This window has no file picker — \
                 drag one onto a terminal to read its path."
            }
        }
    }
}

/// The one text field the FILES plate uses, and what it is for.
#[derive(Debug, Clone, Default)]
pub struct FilesForm {
    /// What is being asked.
    pub purpose: Purpose,
    /// What has been typed.
    pub text: String,
    /// Why the last attempt was refused before it was sent.
    pub trouble: Option<String>,
}

impl FilesForm {
    /// Whether the field is on screen.
    pub fn is_open(&self) -> bool {
        self.purpose != Purpose::Idle
    }

    /// Opens it for a purpose, with whatever it should start holding.
    pub fn open(&mut self, purpose: Purpose, text: String) {
        self.purpose = purpose;
        self.text = text;
        self.trouble = None;
    }

    /// Puts it away.
    pub fn close(&mut self) {
        *self = Self::default();
    }

    /// The command this form asks for, or the reason it cannot.
    ///
    /// Pure, and the piece with the judgement in it, so the refusals are
    /// asserted without a window: a name with a separator in it, a rename with
    /// nothing chosen, an upload of a path that names no file. Every one of
    /// those would otherwise be a request the daemon refuses, and a refusal that
    /// could have been caught here costs a round trip and reads as a fault.
    pub fn submit(
        &self,
        share: &str,
        directory: &str,
        selected: Option<&str>,
    ) -> Result<Command, String> {
        let typed = self.text.trim();
        if typed.is_empty() {
            return Err(format!("{} needs a name.", self.purpose.label().to_lowercase()));
        }
        let action = match self.purpose {
            Purpose::Idle => return Err("nothing is being asked".into()),
            Purpose::NewFolder => {
                let path = nas::join_path(directory, typed)
                    .ok_or("A folder is one name, with no slashes in it.")?;
                FileAction::Mkdir { path }
            }
            Purpose::Rename => {
                let name = selected.ok_or("Choose a file first.")?;
                let from = nas::join_path(directory, name)
                    .ok_or("That name cannot be addressed.")?;
                let to = nas::join_path(directory, typed)
                    .ok_or("A name is one name, with no slashes in it.")?;
                FileAction::Rename { from, to }
            }
            Purpose::Upload => {
                let from = std::path::PathBuf::from(typed);
                let name = from
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or("That path does not end in a file name.")?;
                let path = nas::join_path(directory, name)
                    .ok_or("That file's name cannot be addressed inside a share.")?;
                FileAction::Upload { from, path }
            }
        };
        Ok(Command::Files { share: share.to_owned(), action })
    }
}

#[cfg(test)]
impl Purpose {
    /// Whether this purpose puts a word beside the field, for the test that
    /// asserts the idle one does not.
    fn is_open_label(self) -> bool {
        !self.label().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(purpose: Purpose, text: &str) -> FilesForm {
        FilesForm { purpose, text: text.into(), trouble: None }
    }

    #[test]
    fn a_new_folder_is_one_name_inside_the_directory_that_is_open() {
        let command = form(Purpose::NewFolder, "summer").submit("vault", "photos/2024", None);
        assert_eq!(
            command,
            Ok(Command::Files {
                share: "vault".into(),
                action: FileAction::Mkdir { path: "photos/2024/summer".into() },
            })
        );
    }

    #[test]
    fn a_name_with_a_separator_is_refused_here_rather_than_by_the_daemon() {
        // A round trip that could have been avoided reads as a fault, and the
        // daemon's own refusal would be the uniform one.
        for typed in ["a/b", "..", "a\\b", "   "] {
            assert!(
                form(Purpose::NewFolder, typed).submit("vault", "", None).is_err(),
                "accepted {typed:?}"
            );
        }
    }

    #[test]
    fn a_rename_with_nothing_chosen_says_so_instead_of_guessing() {
        let refusal = form(Purpose::Rename, "new.txt")
            .submit("vault", "", None)
            .expect_err("a refusal");
        assert!(refusal.contains("Choose a file"));
    }

    #[test]
    fn a_rename_keeps_the_entry_in_the_folder_it_was_in() {
        let command = form(Purpose::Rename, "after.txt")
            .submit("vault", "notes", Some("before.txt"))
            .expect("a command");
        assert_eq!(
            command,
            Command::Files {
                share: "vault".into(),
                action: FileAction::Rename {
                    from: "notes/before.txt".into(),
                    to: "notes/after.txt".into(),
                },
            }
        );
    }

    #[test]
    fn an_upload_lands_under_the_files_own_name() {
        let command = form(Purpose::Upload, "/home/alex/tax return.pdf")
            .submit("vault", "docs", None)
            .expect("a command");
        let Command::Files { action: FileAction::Upload { from, path }, .. } = command else {
            panic!("not an upload");
        };
        assert_eq!(path, "docs/tax return.pdf");
        assert_eq!(from, std::path::PathBuf::from("/home/alex/tax return.pdf"));
    }

    #[test]
    fn a_path_that_names_no_file_is_refused() {
        assert!(form(Purpose::Upload, "/").submit("vault", "", None).is_err());
        assert!(form(Purpose::Upload, "..").submit("vault", "", None).is_err());
    }

    #[test]
    fn the_field_says_what_it_wants_for_every_purpose_that_uses_it() {
        for purpose in [Purpose::NewFolder, Purpose::Rename, Purpose::Upload] {
            assert!(!purpose.label().is_empty());
            assert!(!purpose.hint().is_empty(), "{purpose:?} leaves a person guessing");
        }
        assert!(!Purpose::Idle.is_open_label());
    }

    #[test]
    fn opening_the_field_clears_whatever_the_last_attempt_said() {
        let mut form = FilesForm { trouble: Some("no".into()), ..FilesForm::default() };
        form.open(Purpose::Rename, "a.txt".into());
        assert_eq!(form.trouble, None);
        assert!(form.is_open());
        form.close();
        assert!(!form.is_open());
    }
}
