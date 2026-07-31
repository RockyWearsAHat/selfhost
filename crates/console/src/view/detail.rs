//! One service in detail: what it is, what it is doing, and what it has printed.

use super::style;
use super::{Console, present, title_rule};
use crate::state::{Command, LogLine, Snapshot};
use rui::style::Justify;
use rui::{
    Align, El, Radius, Tone, button, caption, code, col, field_row, micro, row, section, spacer,
    text,
};
use selfhost_config::{RestartPolicy, ServiceSpec, StartMode};
use selfhost_supervisor::state::ServiceState;

/// How wide each lifecycle button is drawn when there is room for it.
///
/// One width for all four rather than each fitted to its own label, so the row
/// does not shuffle sideways when a service's state changes which of them are
/// available. It is a maximum and not a fixed size: on a narrow pane the four
/// share what there is instead of keeping their preferred width and overflowing,
/// which was a real defect — the fixed width ran Restart off the right edge of
/// the pane at the smallest window the backend allows.
const ACTION_WIDTH: f32 = 82.0;

/// How wide the gutter of sequence numbers beside the output is.
const SEQ_GUTTER: f32 = 34.0;

/// How tall the output pane is promised, whatever else wants the room.
///
/// The log is why the console is open. Both blocks want the same space and only
/// one of them changes: a specification is read once and is the same the next
/// time it is looked at, while the output is arriving. So the definition is what
/// scrolls when the pane is short, and the log keeps its minimum.
const LOG_MIN: f32 = 108.0;

/// The detail pane for whichever service is selected.
pub fn view(snapshot: &Snapshot) -> El<Console> {
    let Some(service) = snapshot.selected_service() else {
        return style::plate(
            col(caption("Choose a service on the left, or add one.").center_text())
                .grow()
                .justify(Justify::Center),
        );
    };

    let name = service.name.clone();
    let label = super::display_name(service);
    let (status, startable, summary) = present(&service.state);
    let state_label = service.state.label().to_uppercase();

    style::plate((
            // A lamp and a word, the same mark the rail makes and the masthead
            // makes. A tag here and a bare word in the rail would be the same
            // fact wearing two costumes on one screen.
            title_rule(label, Some(style::state_mark(status, state_label))),
            caption(summary),
            actions(&name, &service.state, startable),
            section("DEFINITION", None),
            definition(snapshot, service),
            section(
                "OUTPUT",
                Some(match snapshot.logs.missed {
                    0 => "LIVE".to_owned(),
                    missed => format!("{missed} EARLIER LINES DROPPED"),
                }),
            ),
            output(snapshot),
    ))
    .gap(8.0)
}

/// The lifecycle buttons.
///
/// Which ones are live is decided from the state rather than from what the
/// operator last pressed, so a service that died on its own immediately offers
/// Start again.
///
/// They sit in a well rather than loose on the panel. The row has a deliberate
/// hole in it — the destructive action is pushed to the far end, away from the
/// three ordinary ones — and on a wide pane that hole read as a button that had
/// failed to draw. A track around them says the space between is part of the
/// control and not a gap in it.
fn actions(name: &str, state: &ServiceState, startable: bool) -> El<Console> {
    let stoppable = state.is_live();
    let action = |label: &str, command: Command| {
        button(label)
            .key(label)
            .grow()
            .max_w(ACTION_WIDTH)
            .on_click(move |console: &mut Console| console.request(command.clone()))
    };

    row((
        action(
            "Start",
            Command::Start(name.to_owned()),
        )
        .primary()
        .disabled(!startable),
        action("Stop", Command::Stop(name.to_owned())).disabled(!stoppable),
        // Restart is offered whatever the state: on a stopped service it means
        // "start", and the supervisor treats it that way. Greying it out would
        // make the operator work out which of two buttons is the live one.
        action("Restart", Command::Restart(name.to_owned())),
        // A rule across the space between the two groups, with a tick at the end
        // of it. On a wide pane that space is most of the row, and empty it read
        // as a button that had failed to draw rather than as distance kept on
        // purpose. The rule says the gap is the point.
        // The rule takes a full share, not a smaller one. A smaller share looks
        // like the fix for the narrow window — the four labels get more room
        // and stop being cut — but the buttons are capped at [`ACTION_WIDTH`],
        // and a share this row hands to a child that cannot take it is a share
        // nothing gets: on a wide pane the rule shrank to a stub and left a
        // hand's width of nothing between it and Uninstall, which is the exact
        // defect the rule was drawn to answer.
        row((
            spacer().h(1.0).grow().fill(Tone::Border),
            spacer().w(1.0).h(7.0).fill(Tone::Border),
        ))
        .grow()
        .pad_x(12.0)
        .align(Align::Center),
        action("Uninstall", Command::Uninstall(name.to_owned())).danger(),
    ))
    .h(36.0)
    .pad(4.0)
    .gap(4.0)
    .fill(Tone::Sunken)
    .border(1.0, Tone::Border)
    .round(Radius::Control)
}

/// What the service is configured to be.
///
/// Scrolls when the block was given less room than its rows need, because a
/// definition that is merely cut off looks exactly like one the daemon did not
/// send. Its rows are one per fact rather than one per argument: the form is
/// where arguments are read individually.
fn definition(snapshot: &Snapshot, service: &selfhost_supervisor::state::ServiceStatus) -> El<Console> {
    let mut rows: Vec<El<Console>> = Vec::new();

    match spec_of(snapshot, &service.name) {
        Some(spec) => {
            rows.push(field_row("PROGRAM", code(spec.program.display().to_string())));
            rows.push(field_row(
                "ARGUMENTS",
                code(if spec.args.is_empty() { "none".to_owned() } else { spec.args.join(" ") }),
            ));
            rows.push(field_row(
                "RUNS IN",
                code(match &spec.cwd {
                    Some(path) => path.display().to_string(),
                    None => "the daemon's data directory".to_owned(),
                }),
            ));
            rows.push(field_row(
                "POLICY",
                text(format!(
                    "{} · restart {} · give up after {}",
                    start_mode_label(service.start_mode),
                    restart_label(spec.restart),
                    match spec.max_restarts {
                        0 => "never".to_owned(),
                        most => format!("{most} attempts"),
                    }
                )),
            ));
        }
        // Before the definition has been fetched, the live status is all there
        // is. Showing empty rows for the rest would claim the daemon had
        // answered with nothing rather than not having answered yet.
        None => rows.push(field_row("START MODE", text(start_mode_label(service.start_mode)))),
    }

    rows.push(field_row(
        "RESTARTS",
        text(format!("{} since the daemon started", service.total_restarts)),
    ));
    if !service.description.is_empty() {
        rows.push(field_row("NOTES", caption(service.description.clone()).wrap()));
    }

    col(rows).gap(2.0).scroll()
}

/// The service's captured output.
///
/// Pinned to the newest line until the reader scrolls back, and pinned again
/// once they scroll to the end — see [`rui::El::follow`], which decides that
/// from where the reader actually is rather than from a flag this has to keep.
fn output(snapshot: &Snapshot) -> El<Console> {
    let lines: Vec<El<Console>> = snapshot.logs.lines.iter().map(log_line).collect();

    let body: El<Console> = if lines.is_empty() {
        col(caption(if snapshot.logs.service.is_empty() {
            "No service selected."
        } else {
            "This service has printed nothing since the daemon started."
        }))
        .grow()
    } else {
        col(lines).key(&snapshot.logs.service).gap(1.0).follow()
    };

    col(body)
        .grow()
        .min_h(LOG_MIN)
        .pad(8.0)
        .fill(Tone::Sunken)
        .border(1.0, Tone::Border)
        .round(Radius::Control)
}

/// One captured line: its sequence number, and what the service printed.
///
/// The number is the daemon's own count, so it is what says *how much* was
/// dropped when lines were missed, and what two people comparing the same log
/// can point at. It sits in a gutter of its own so the output beside it stays in
/// the columns the program printed it in.
fn log_line(line_of: &LogLine) -> El<Console> {
    let text = code(line_of.text.clone()).grow();
    row((
        micro(line_of.seq.to_string()).w(SEQ_GUTTER).text_align(Align::End),
        if line_of.is_error {
            // A bar as well as a colour. Standard error is the half of the
            // output that matters, and a hue alone is exactly what a
            // colour-blind reader does not receive. It is the same flag the
            // banner across the top of the window flies, at the same width.
            row((style::flag(rui::Status::Bad), text.color(Tone::Bad)))
                .gap(6.0)
                .grow()
                .fill(Tone::BadTint)
        } else {
            row(text).grow()
        },
    ))
    .gap(8.0)
    .min_h(15.0)
}

/// The spec for a service, when the poller has fetched a matching one.
fn spec_of<'a>(snapshot: &'a Snapshot, name: &str) -> Option<&'a ServiceSpec> {
    snapshot.spec.as_deref().filter(|spec| spec.name == name)
}

/// A start mode in the words the configuration uses.
pub(crate) fn start_mode_label(mode: StartMode) -> &'static str {
    match mode {
        StartMode::Automatic => "starts with the daemon",
        StartMode::Manual => "started by hand",
        StartMode::Disabled => "disabled",
    }
}

/// A restart policy in the words the configuration uses.
pub(crate) fn restart_label(policy: RestartPolicy) -> &'static str {
    match policy {
        RestartPolicy::Never => "never",
        RestartPolicy::OnFailure => "on failure",
        RestartPolicy::Always => "always",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::tests::{console, populated};

    #[test]
    fn a_spec_for_a_different_service_is_not_shown_under_this_one() {
        let snapshot = Snapshot {
            spec: Some(Box::new(ServiceSpec::new("other", "/usr/bin/other"))),
            ..Default::default()
        };
        assert!(spec_of(&snapshot, "mongod").is_none());
        assert!(spec_of(&snapshot, "other").is_some());
    }

    /// Whether each lifecycle button is offered, in the order they are drawn.
    fn availability(state: &ServiceState, startable: bool) -> Vec<bool> {
        actions("mongod", state, startable)
            .children()
            .iter()
            .map(|button| !button.is_disabled())
            .collect()
    }

    #[test]
    fn which_lifecycle_buttons_are_live_follows_the_state_and_not_the_last_press() {
        let stopped = availability(&ServiceState::Stopped, true);
        assert!(stopped[0], "a stopped service can be started");
        assert!(!stopped[1], "and cannot be stopped");

        let running = availability(&ServiceState::Running { pid: 1, uptime_secs: 1 }, false);
        assert!(!running[0], "a running service cannot be started again");
        assert!(running[1], "and can be stopped");
        assert!(running[2], "restart is offered whatever the state");
    }

    #[test]
    fn pressing_start_asks_the_poller_to_start_that_service() {
        let mut console = console(populated());
        let element = actions("mongod", &ServiceState::Stopped, true);
        let start = element.child(0).expect("the first action");
        (start.click_action().expect("Start is clickable"))(&mut console);

        let snapshot = console.snapshot();
        assert_eq!(snapshot.commands.front(), Some(&Command::Start("mongod".into())));
    }

    #[test]
    fn a_service_with_no_definition_yet_still_shows_what_is_known() {
        let snapshot = populated();
        let service = snapshot.selected_service().expect("a selection").clone();
        let block = definition(&snapshot, &service);
        assert!(block.child(0).is_some(), "the block should not be empty");
    }

}
