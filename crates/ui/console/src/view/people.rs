//! The PEOPLE screen: who holds authority on this box, and what that authority
//! has been used to do.
//!
//! # Why the roster and the trail share a screen
//!
//! Because neither means anything alone. A list of credentials is a list of who
//! *may*; the trail is the record of who *did*, and whether the daemon allowed
//! it. On two screens the second is the one nobody opens, which is precisely the
//! failure `crates/admin`'s audit route was added to close.
//!
//! # What this plate can change, and what it deliberately cannot
//!
//! It revokes and it does not register. Registering a passkey is a browser
//! ceremony — a platform authenticator, an origin, a challenge — and the daemon
//! allows it only to an already-authenticated caller, so a REGISTER button here
//! could only ever be a button that fails. Revoking needs no ceremony, and an
//! owner who has lost a device needs the shortest path to taking it out.
//!
//! # Absence is a sentence
//!
//! Both routes are owner-only, so both answer `401` on a deployment where this
//! console's credential is not the owner. That is drawn as the refusal it is and
//! never as an empty list: an empty registry and a refused one are different
//! facts and only one of them is reassuring.

use super::style;
use super::Console;
use crate::nas;
use crate::registry::{self, Person, Record, Trail};
use crate::state::Command;
use rui::style::Justify;
use rui::{
    Align, El, Length, Role, Status, button, caption, code, col, micro, row, spacer, text,
};

/// The share of an audit row each column takes.
const WHEN_W: f32 = 0.27;
/// See [`WHEN_W`].
const WHO_W: f32 = 0.15;
/// See [`WHEN_W`].
const WHAT_W: f32 = 0.58;

/// How tall one row of either list is.
const ROW: f32 = 24.0;

/// What share of the window the roster takes.
const ROSTER_SHARE: f32 = 0.34;

/// The narrowest the roster may be drawn.
const ROSTER_MIN: f32 = 220.0;

/// The widest, past which it is a column of names in a hall.
const ROSTER_MAX: f32 = 360.0;

/// The whole screen: the roster, and the trail beside it.
pub fn view(console: &Console) -> El<Console> {
    let snapshot = console.snapshot();
    row((roster(&snapshot), trail(&snapshot))).gap(8.0).grow()
}

/// Everyone who holds a credential on this box.
fn roster(snapshot: &crate::state::Snapshot) -> El<Console> {
    let holders = snapshot.people.holders.as_deref();
    let body: El<Console> = match (holders, snapshot.people.trouble.as_deref()) {
        (_, Some(reason)) => col((
            row((style::lamp(Status::Warn), caption(reason.to_owned()).wrap().grow()))
                .gap(6.0)
                .align(Align::Center),
            caption(
                "The registry is the owner's to read. This console's credential is not \
                 the owner's, or the daemon refused it.",
            )
            .wrap(),
        ))
        .gap(4.0)
        .pad_y(12.0),
        (None, None) => col(caption("Reading the registry…").wrap().center_text()).pad_y(24.0),
        (Some([]), None) => col(caption(
            "Nobody holds a passkey here yet. The console password is still the root \
             credential; register a passkey from the browser console.",
        )
        .wrap()
        .center_text())
        .pad_y(24.0),
        (Some(people), None) => col(people
            .iter()
            .map(person_row)
            .collect::<Vec<_>>())
        .gap(2.0)
        .scroll()
        .role(Role::List),
    };

    style::plate((
        style::section_rule("PEOPLE", holders.map(|people| people.len().to_string())),
        body.grow(),
        caption(
            "A passkey is registered in a browser, on the device that holds it. This window \
             can take one away and cannot mint one.",
        )
        .wrap(),
    ))
    .gap(8.0)
    .w(Length::Fraction(ROSTER_SHARE))
    .min_w(ROSTER_MIN)
    .max_w(ROSTER_MAX)
}

/// One holder: the person, the device, when it was registered, and REVOKE.
///
/// The person's name is the reading and the device is the citation beneath it,
/// because the registry is a roster of people and not of hardware — two rows
/// with the same name are one person with two devices, which is exactly what
/// the design intends and what the name-first order makes legible.
fn person_row(person: &Person) -> El<Console> {
    let id = person.id.clone();
    let user = person.display_name().to_owned();
    let revoked = user.clone();
    col((
        row((
            text(person.display_name().to_owned()).grow(),
            button("REVOKE").key(format!("revoke {}", person.id)).on_click(move |console: &mut Console| {
                console.request(Command::RevokePasskey {
                    id: id.clone(),
                    user: revoked.clone(),
                });
            }),
        ))
        .gap(6.0)
        .align(Align::Center),
        row((
            caption(if person.label.is_empty() {
                "an unnamed device".to_owned()
            } else {
                person.label.clone()
            })
            .grow(),
            caption(nas::when_text(Some(person.created_unix))),
        ))
        .gap(6.0),
    ))
    .gap(2.0)
    .pad_each(5.0, 6.0, 5.0, 6.0)
    .min_h(44.0)
    .hover_fill(rui::Tone::Raised)
    .role(Role::ListItem)
    .key(person.id.clone())
}

/// The tail of the control-action record.
fn trail(snapshot: &crate::state::Snapshot) -> El<Console> {
    let Some(tail) = snapshot.people.trail.as_ref() else {
        return style::plate((
            super::title_rule("AUDIT".into(), None),
            col(caption("Reading the trail…").wrap().center_text()).pad_y(24.0).grow(),
        ))
        .gap(8.0)
        .grow();
    };
    let hiding = snapshot.people.hide_pointer_noise;
    let shown = visible(tail, hiding);
    let (status, note) = tail.note();

    style::plate((
        super::title_rule(
            "AUDIT".into(),
            Some(micro(format!("{} of {} lines", tail.records.len(), tail.scanned)).align_self(Align::Center)),
        ),
        row((style::lamp(status), caption(note).wrap().grow())).gap(6.0).align(Align::Center),
        head_row(),
        if shown.is_empty() {
            col(caption(if hiding && !tail.records.is_empty() {
                "Every record in this window is the pointer moving."
            } else {
                "Nothing to show."
            })
            .wrap()
            .center_text())
            .pad_y(24.0)
            .grow()
        } else {
            col(shown.iter().map(|record| record_row(record)).collect::<Vec<_>>())
                .gap(1.0)
                .scroll()
                .grow()
                .role(Role::List)
        },
        row((
            button(if hiding { "SHOW POINTER MOVES" } else { "HIDE POINTER MOVES" }).on_click(
                |console: &mut Console| {
                    console.with_snapshot(|snapshot| {
                        snapshot.people.hide_pointer_noise = !snapshot.people.hide_pointer_noise;
                    });
                },
            ),
            spacer().grow(),
            (tail.unreadable > 0).then(|| {
                style::reading("UNREADABLE", tail.unreadable.to_string(), Some(Status::Bad))
            }),
        ))
        .gap(6.0)
        .align(Align::Center),
    ))
    .gap(6.0)
    .grow()
}

/// The records to draw, once the pointer's own have been folded away.
///
/// Pure and separate from the drawing, so the rule about what counts as noise is
/// asserted rather than trusted. It is deliberately narrow — only an *allowed*
/// pointer move — because a refused one is the wall holding, which is the thing
/// an audit trail exists to record.
fn visible(tail: &Trail, hiding: bool) -> Vec<&Record> {
    tail.records
        .iter()
        .filter(|record| !(hiding && registry::is_pointer_noise(record)))
        .collect()
}

/// The heading naming the three columns.
fn head_row() -> El<Console> {
    row((
        micro("WHEN").tracking(1.2).w(Length::Fraction(WHEN_W)),
        micro("WHO").tracking(1.2).w(Length::Fraction(WHO_W)),
        micro("WHAT").tracking(1.2).w(Length::Fraction(WHAT_W)),
    ))
    .min_h(14.0)
}

/// One line of the record.
///
/// The lamp is the only colour on the row, and a refusal is amber rather than
/// red: a denied capability is the wall working. Red is kept for the count of
/// lines the daemon could not read at all, which is the one thing on this plate
/// that means the evidence itself is in doubt.
fn record_row(record: &Record) -> El<Console> {
    row((
        row((style::lamp(record.status()), caption(nas::when_text(Some(record.at_unix)))))
            .gap(6.0)
            .w(Length::Fraction(WHEN_W))
            .align(Align::Center)
            .justify(Justify::Start),
        text(record.actor()).w(Length::Fraction(WHO_W)),
        code(record.action()).w(Length::Fraction(WHAT_W)).whole(),
    ))
    .min_h(ROW)
    .align(Align::Center)
    .hover_fill(rui::Tone::Raised)
    .key(record.id.clone())
    .role(Role::ListItem)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(capability: &str, outcome: &str, detail: &str, id: &str) -> Record {
        Record {
            id: id.into(),
            at_unix: 1_700_000_000,
            identity: "owner".into(),
            who: "alex".into(),
            capability: capability.into(),
            target: "self".into(),
            outcome: outcome.into(),
            reason: String::new(),
            detail: detail.into(),
        }
    }

    #[test]
    fn hiding_the_pointer_leaves_every_keystroke_and_every_refusal() {
        let tail = Trail {
            records: vec![
                record("desktop.control", "allow", "pointer 1,2", "a"),
                record("desktop.control", "allow", "key 0x04 down", "b"),
                record("desktop.control", "deny", "pointer 3,4", "c"),
                record("files.write", "allow", "vault/x", "d"),
            ],
            scanned: 4,
            unreadable: 0,
        };
        let kept: Vec<&str> = visible(&tail, true).iter().map(|record| record.id.as_str()).collect();
        assert_eq!(kept, ["b", "c", "d"], "only the allowed pointer move is noise");
        assert_eq!(visible(&tail, false).len(), 4, "and showing them shows all of them");
    }

    #[test]
    fn a_trail_of_nothing_but_pointer_moves_says_so_rather_than_looking_empty() {
        // The difference between "nothing happened" and "everything that
        // happened is hidden" is a difference an operator has to be told.
        let tail = Trail {
            records: vec![record("desktop.control", "allow", "pointer 1,2", "a")],
            scanned: 1,
            unreadable: 0,
        };
        assert!(visible(&tail, true).is_empty());
        assert!(!tail.records.is_empty());
    }
}
