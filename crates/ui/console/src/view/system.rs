//! The SYSTEM panel: the daemon's own internal parts — proxy, admin API, VPN
//! relays, the VPN updater, reports, mail — read from `GET /api/system` and
//! never mixed into the hosted [`crate::state::Snapshot::services`] list. See
//! `is_system` in `crates/app/admin/src/lib.rs`, which decides the same split
//! on the daemon's side.
//!
//! Deliberately plain next to [`super::exposure`]'s judged columns: there is no
//! chain of judgement to draw here, just a name, the daemon's own word for its
//! state, and — only when something is wrong — why.

use super::style;
use super::Console;
use crate::state::SystemPart;
use rui::{Align, El, Length, Status, caption, col, row, text};

/// The name column's share of the row's width. See `exposure::SERVICE_W` for
/// why a fraction rather than a fixed width: the plate's own width still
/// governs, whatever the window is resized to.
const NAME_W: f32 = 0.28;
/// The state column's share.
const STATE_W: f32 = 0.26;

/// The SYSTEM panel, or `None` while nothing has been fetched yet.
///
/// Unlike the exposure map, this never hides on an empty list once fetched —
/// the daemon always has at least itself and the proxy to report — so an empty
/// answer here is treated the same as no answer at all rather than drawn as a
/// bare frame.
pub fn view(parts: Option<&[SystemPart]>) -> Option<El<Console>> {
    let parts = parts?;
    if parts.is_empty() {
        return None;
    }
    let rows: Vec<El<Console>> = parts.iter().map(part_row).collect();
    Some(style::plate((style::section_rule("SYSTEM", None), col(rows).gap(3.0))).gap(6.0))
}

/// One part's row: its name, a lamp-and-word state, and its reason when unhealthy.
fn part_row(part: &SystemPart) -> El<Console> {
    let status = if part.reason.is_some() {
        Status::Bad
    } else if part.state == "not configured" {
        Status::Warn
    } else {
        Status::Ok
    };
    row((
        text(part.name.clone()).w(Length::Fraction(NAME_W)),
        row((style::lamp(status), caption(part.state.to_uppercase())))
            .gap(6.0)
            .align(Align::Center)
            .w(Length::Fraction(STATE_W)),
        caption(part.reason.clone().unwrap_or_default()).grow(),
    ))
    .min_h(20.0)
    .align(Align::Center)
}
