//! The form that installs a service, or edits one that is already installed.
//!
//! # Arguments get a field each
//!
//! There is no single "arguments" box to type a command line into. A command
//! line has to be split by *someone*, every implementation splits quoting
//! differently, and the case that breaks — a program path containing a space —
//! breaks silently at start-up on the operator's machine rather than here. The
//! service model stores arguments already split for exactly that reason, and a
//! form that undid it by joining them into one box and splitting them again
//! would reintroduce the defect the model exists to prevent.
//!
//! So each argument is its own field, added and removed one at a time. It is
//! more clicks and it cannot be wrong.

use super::style;
use super::{Console, title_rule};
use crate::state::{Command, Snapshot};
use rui::style::Justify;
use rui::{
    El, Radius, Tone, button, caption, code, col, field, field_row, row, section, segmented,
    spacer,
};
use selfhost_config::{RestartPolicy, ServiceSpec, StartMode};

/// The start modes, in the order the control shows them.
const START_MODES: [(StartMode, &str); 3] = [
    (StartMode::Automatic, "Automatic"),
    (StartMode::Manual, "Manual"),
    (StartMode::Disabled, "Disabled"),
];

/// The restart policies, in the order the control shows them.
const RESTART_POLICIES: [(RestartPolicy, &str); 3] = [
    (RestartPolicy::Never, "Never"),
    (RestartPolicy::OnFailure, "On failure"),
    (RestartPolicy::Always, "Always"),
];

/// The widest a single-line field is drawn, however wide the pane is.
///
/// A text field is a place to type one short string — a service's name, a path —
/// and a box stretched across a wide window says the opposite: that a paragraph
/// is wanted. It also puts the caret a long way from the label that says what
/// the field is for. This is about the width of a long filesystem path, which is
/// the longest thing any of these fields actually holds.
const FIELD_MAX: f32 = 460.0;

/// The most arguments the form will let one service take.
///
/// Not a limit of the model — it is a limit on how far a stuck key can grow the
/// form before the panel stops being usable.
const MAX_ARGUMENTS: usize = 32;

/// The state of the install form, while it is open.
#[derive(Debug, Default)]
pub struct InstallForm {
    open: bool,
    /// The service being replaced, when editing rather than adding.
    replacing: Option<String>,
    name: String,
    program: String,
    arguments: Vec<String>,
    working_directory: String,
    description: String,
    start_mode: usize,
    restart: usize,
    /// What was wrong the last time Install was pressed.
    problems: Vec<String>,
}

impl InstallForm {
    /// Whether the form is showing instead of the detail pane.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Opens the form empty, to add a new service.
    ///
    /// Every field is reset. A form that remembered what was typed the last time
    /// it was cancelled would install a service nobody meant to describe.
    pub fn open_blank(&mut self) {
        *self = Self {
            open: true,
            // Manual, because a service being added has not been shown to work
            // yet, and one that starts with the daemon and crashes turns the
            // next restart of the machine into a puzzle.
            start_mode: index_of_start_mode(StartMode::Manual),
            restart: index_of_restart(RestartPolicy::OnFailure),
            ..Default::default()
        };
    }

    /// Closes the form, discarding what was typed.
    fn close(&mut self) {
        self.open = false;
    }

    /// Validates the form and asks for the install, or reports what is wrong.
    ///
    /// Validation runs against the *same* [`ServiceSpec::check`] the daemon
    /// uses, rather than against a copy of its rules written here. A second copy
    /// is a second thing to keep in step, and the first time they drift the
    /// console accepts something the daemon then refuses.
    pub(crate) fn submit(&mut self, snapshot: &mut Snapshot) {
        self.problems.clear();

        let name = self.name.trim();
        let program = self.program.trim();
        if name.is_empty() {
            self.problems.push("A service needs a name.".into());
        }
        if program.is_empty() {
            self.problems.push("A service needs a program to run.".into());
        }
        if !self.problems.is_empty() {
            return;
        }

        let mut spec = ServiceSpec::new(name, program);
        spec.args = self
            .arguments
            .iter()
            .map(|argument| argument.trim().to_owned())
            .filter(|argument| !argument.is_empty())
            .collect();
        spec.description = self.description.trim().to_owned();
        let directory = self.working_directory.trim();
        spec.cwd = (!directory.is_empty()).then(|| directory.into());
        spec.start_mode = START_MODES[self.start_mode.min(START_MODES.len() - 1)].0;
        spec.restart = RESTART_POLICIES[self.restart.min(RESTART_POLICIES.len() - 1)].0;

        let mut problems = Vec::new();
        spec.check("service", &[], &mut problems);
        if !problems.is_empty() {
            self.problems = problems.iter().map(|problem| problem.message.clone()).collect();
            return;
        }

        snapshot.enqueue(Command::Install(Box::new(spec)));
        self.close();
    }
}

/// The form, as one description.
///
/// Split under two headings, because it asks two different questions. Everything
/// above POLICY describes *what to run* and is copied from somewhere — a path, a
/// flag, a directory. Everything below it decides *how the machine should treat
/// it*, and is the half an operator changes later without touching the first.
/// Ruling them apart is what stops eight rows of label-and-box reading as one
/// undifferentiated form.
pub fn view(console: &Console) -> El<Console> {
    let form = console.form();
    let heading = match &form.replacing {
        Some(name) => format!("Edit {name}"),
        None => "Add a service".to_owned(),
    };

    style::plate((
            title_rule(heading, None),
            col((
                // The name identifies the service and is also its log filename,
                // so changing it on an existing service would be an install of a
                // different one rather than an edit. The daemon would agree, and
                // leave two.
                match &form.replacing {
                    Some(name) => field_row("NAME", code(name.clone())),
                    None => text_row("NAME", &form.name, "mongod", |form, value| form.name = value),
                },
                text_row("PROGRAM", &form.program, "/usr/local/bin/mongod", |form, value| {
                    form.program = value
                }),
                arguments(form),
                text_row(
                    "RUNS IN",
                    &form.working_directory,
                    "left blank: the daemon's data directory",
                    |form, value| form.working_directory = value,
                ),
                text_row("NOTES", &form.description, "what this is for", |form, value| {
                    form.description = value
                }),
                section("POLICY", None),
                field_row(
                    "STARTS",
                    segmented(&labels(&START_MODES), form.start_mode, |console: &mut Console, mode| {
                        console.form_mut().start_mode = mode
                    })
                    .max_w(FIELD_MAX),
                ),
                field_row(
                    "RESTART",
                    segmented(&labels(&RESTART_POLICIES), form.restart, |console: &mut Console, policy| {
                        console.form_mut().restart = policy
                    })
                    .max_w(FIELD_MAX),
                ),
                problems(form),
            ))
            .gap(8.0)
            .grow()
            .scroll(),
            footer(form),
    ))
    .gap(10.0)
}

/// One labelled field, and what typing in it does to the form.
fn text_row(
    label: &'static str,
    value: &str,
    placeholder: &'static str,
    set: impl Fn(&mut InstallForm, String) + 'static,
) -> El<Console> {
    field_row(
        label,
        field(value)
            .key(label)
            .placeholder(placeholder)
            .max_w(FIELD_MAX)
            .on_input(move |console: &mut Console, value| set(console.form_mut(), value)),
    )
}

/// The argument fields, and the controls that add and remove them.
fn arguments(form: &InstallForm) -> El<Console> {
    let rows: Vec<El<Console>> = form
        .arguments
        .iter()
        .enumerate()
        .map(|(index, argument)| {
            row((
                field(argument)
                    .grow()
                    .max_w(FIELD_MAX)
                    .placeholder("one argument")
                    .on_input(move |console: &mut Console, value| {
                        if let Some(slot) = console.form_mut().arguments.get_mut(index) {
                            *slot = value;
                        }
                    }),
                // The remove button sits just past the field rather than at the
                // far edge of the pane, so it stays beside the argument it
                // removes.
                style::icon_button("\u{2212}", format!("Remove argument {}", index + 1))
                    .on_click(move |console: &mut Console| {
                        let arguments = &mut console.form_mut().arguments;
                        if index < arguments.len() {
                            arguments.remove(index);
                        }
                    }),
            ))
            .key(format!("argument-{index}"))
            .gap(4.0)
        })
        .collect();

    let full = form.arguments.len() >= MAX_ARGUMENTS;
    field_row(
        "ARGUMENTS",
        col((
            col(rows).gap(4.0),
            button("+ Argument")
                .w(128.0)
                .disabled(full)
                .on_click(|console: &mut Console| console.form_mut().arguments.push(String::new())),
        ))
        .gap(4.0),
    )
}

/// What was wrong the last time Install was pressed.
fn problems(form: &InstallForm) -> Option<El<Console>> {
    (!form.problems.is_empty()).then(|| {
        col(form
            .problems
            .iter()
            .map(|problem| caption(problem.clone()).color(Tone::Bad).wrap())
            .collect::<Vec<_>>())
        .gap(2.0)
        .pad(8.0)
        .fill(Tone::BadTint)
        .round(Radius::Control)
    })
}

/// The Install and Cancel buttons.
fn footer(form: &InstallForm) -> El<Console> {
    let submit = if form.replacing.is_some() { "Save" } else { "Install" };
    row((
        spacer().grow(),
        button("Cancel").w(96.0).on_click(|console: &mut Console| console.form_mut().close()),
        button(submit).primary().w(110.0).on_click(Console::submit_form),
    ))
    .gap(8.0)
    .justify(Justify::End)
}

/// The words a set of options is shown under.
fn labels<T>(options: &[(T, &'static str)]) -> Vec<&'static str> {
    options.iter().map(|(_, label)| *label).collect()
}

/// Where a start mode sits in the control.
fn index_of_start_mode(mode: StartMode) -> usize {
    START_MODES.iter().position(|(candidate, _)| *candidate == mode).unwrap_or(0)
}

/// Where a restart policy sits in it.
fn index_of_restart(policy: RestartPolicy) -> usize {
    RESTART_POLICIES.iter().position(|(candidate, _)| *candidate == policy).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled() -> InstallForm {
        let mut form = InstallForm::default();
        form.open_blank();
        form.name = "mongod".into();
        form.program = "/usr/local/bin/mongod".into();
        form
    }

    #[test]
    fn a_new_form_defaults_to_manual_and_restart_on_failure() {
        let mut form = InstallForm::default();
        form.open_blank();
        assert_eq!(START_MODES[form.start_mode].0, StartMode::Manual);
        assert_eq!(RESTART_POLICIES[form.restart].0, RestartPolicy::OnFailure);
    }

    #[test]
    fn opening_the_form_clears_what_was_typed_before() {
        let mut form = filled();
        form.close();
        form.open_blank();
        assert!(form.name.is_empty());
        assert!(form.program.is_empty());
        assert!(form.arguments.is_empty());
    }

    #[test]
    fn a_form_missing_a_name_or_a_program_reports_it_and_asks_for_nothing() {
        let mut snapshot = Snapshot::default();
        let mut form = InstallForm::default();
        form.open_blank();
        form.submit(&mut snapshot);

        assert_eq!(form.problems.len(), 2);
        assert!(snapshot.commands.is_empty(), "an invalid form must not reach the daemon");
        assert!(form.is_open(), "the form stays open so the problems can be read");
    }

    #[test]
    fn a_valid_form_asks_for_the_install_and_closes() {
        let mut snapshot = Snapshot::default();
        let mut form = filled();
        form.submit(&mut snapshot);

        assert!(form.problems.is_empty());
        assert!(!form.is_open());
        match snapshot.commands.pop_front() {
            Some(Command::Install(spec)) => {
                assert_eq!(spec.name, "mongod");
                assert_eq!(spec.program.display().to_string(), "/usr/local/bin/mongod");
            }
            other => panic!("expected an install, got {other:?}"),
        }
    }

    #[test]
    fn empty_argument_fields_are_dropped_rather_than_passed_as_empty_arguments() {
        let mut snapshot = Snapshot::default();
        let mut form = filled();
        form.arguments = vec!["--config".into(), "  ".into(), " /etc/mongod.conf ".into()];
        form.submit(&mut snapshot);

        match snapshot.commands.pop_front() {
            Some(Command::Install(spec)) => {
                assert_eq!(spec.args, vec!["--config", "/etc/mongod.conf"]);
            }
            other => panic!("expected an install, got {other:?}"),
        }
    }

    #[test]
    fn arguments_are_never_split_or_joined() {
        let mut snapshot = Snapshot::default();
        let mut form = filled();
        // One argument that contains a space stays one argument. Joining and
        // re-splitting is exactly what this form exists to avoid.
        form.arguments = vec!["/Applications/My Server/run.sh".into()];
        form.submit(&mut snapshot);

        match snapshot.commands.pop_front() {
            Some(Command::Install(spec)) => assert_eq!(spec.args.len(), 1),
            other => panic!("expected an install, got {other:?}"),
        }
    }

    #[test]
    fn a_blank_working_directory_means_the_default_rather_than_an_empty_path() {
        let mut snapshot = Snapshot::default();
        let mut form = filled();
        form.working_directory = "   ".into();
        form.submit(&mut snapshot);

        match snapshot.commands.pop_front() {
            Some(Command::Install(spec)) => assert!(spec.cwd.is_none()),
            other => panic!("expected an install, got {other:?}"),
        }
    }

    #[test]
    fn the_daemons_own_rules_reject_a_name_it_could_not_use_as_a_filename() {
        let mut snapshot = Snapshot::default();
        let mut form = filled();
        form.name = "../escape".into();
        form.submit(&mut snapshot);

        assert!(!form.problems.is_empty(), "the shared validator should have refused this");
        assert!(snapshot.commands.is_empty());
        assert!(form.is_open());
    }

    #[test]
    fn the_chosen_policies_reach_the_spec() {
        let mut snapshot = Snapshot::default();
        let mut form = filled();
        form.start_mode = index_of_start_mode(StartMode::Automatic);
        form.restart = index_of_restart(RestartPolicy::Always);
        form.submit(&mut snapshot);

        match snapshot.commands.pop_front() {
            Some(Command::Install(spec)) => {
                assert_eq!(spec.start_mode, StartMode::Automatic);
                assert_eq!(spec.restart, RestartPolicy::Always);
            }
            other => panic!("expected an install, got {other:?}"),
        }
    }

    #[test]
    fn an_out_of_range_selection_cannot_index_past_the_options() {
        let mut snapshot = Snapshot::default();
        let mut form = filled();
        form.start_mode = 99;
        form.restart = 99;
        form.submit(&mut snapshot);
        assert!(snapshot.commands.pop_front().is_some());
    }

    #[test]
    fn typing_in_a_field_reaches_the_form_it_belongs_to() {
        // The description is a value and its handlers are ordinary functions, so
        // what typing *does* is asserted without a window or a keystroke.
        let mut console = crate::view::tests::console(Snapshot::default());
        console.form_mut().open_blank();

        let row = text_row("PROGRAM", "", "hint", |form, value| form.program = value);
        let field = row.child(1).expect("the field beside the label");
        (field.input_action().expect("the field takes typing"))(
            &mut console,
            "/usr/bin/true".to_owned(),
        );
        assert_eq!(console.form().program, "/usr/bin/true");
    }
}
