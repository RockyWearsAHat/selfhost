//! The overview: every machine this console is paired with, and the form that
//! adds one.
//!
//! # One step back, not a fifth tab
//!
//! SERVICES, FILES, DESKTOP and PEOPLE are all plates of *one machine*, so the
//! list of machines cannot be a fifth one beside them — that would say choosing
//! which machine to look at is the same kind of act as choosing which of its
//! readings to read. It is a place you stand above the machine, reached from the
//! masthead and left by opening something.
//!
//! # What a row can honestly claim
//!
//! Only the open machine has a connection, so only the open machine has a state
//! to report. Every other row says what it *is* — a destination, a port, the key
//! it answers to — and says plainly that it has not been opened in this session.
//! Drawing a lamp per row would mean either probing every paired machine on
//! every frame, or drawing a grey lamp that reads as "down" for a machine that
//! is perfectly well.
//!
//! # Pairing is not saving
//!
//! The form does not write the store. It opens what it describes, carrying a
//! note that saves the machine the moment a token actually arrives from it — so
//! an entry in the file is always a connection that has worked at least once,
//! and a machine that never answers is reported in `ssh`'s own words rather than
//! written down as though it were fine. See [`Console::submit_pair_form`].

use super::style;
use super::Console;
use crate::machines::{Machine, DEFAULT_PORT, DEFAULT_REMOTE_TOKEN};
use crate::session::Place;
use rui::style::Justify;
use rui::{
    Align, El, Length, Role, Tone, button, caption, code, col, field, field_row, micro, row,
    spacer, text,
};
use std::path::PathBuf;

/// What share of the window the list takes.
const LIST_SHARE: f32 = 0.58;

/// The narrowest the list may be drawn.
const LIST_MIN: f32 = 260.0;

/// The least room one machine's row takes.
///
/// A floor and not a height: the row holds a name, an address with its controls
/// and a line of detail, and what that comes to depends on the face. The *inner*
/// row carrying the wedge is the one that states a height, which is the rule
/// every wedge-bearing row in this console follows — see [`machine_row`].
const ROW: f32 = 52.0;

/// The widest a field is drawn, past which it is a hall with a word in it.
const FIELD_MAX: f32 = 320.0;

/// The whole overview: the machines, and the form beside them.
pub fn view(console: &Console) -> El<Console> {
    row((list(console), pairing(console))).gap(8.0).grow()
}

/// Every paired machine, with the open one marked.
fn list(console: &Console) -> El<Console> {
    let paired = console.machines();
    let open = console.bound().machine.as_deref();
    let body: El<Console> = if paired.is_empty() {
        col((
            caption("No machine is paired on this computer yet.").wrap().center_text(),
            caption(
                "Pair one with the form beside this. It is opened straight away, and \
                 remembered once it answers.",
            )
            .wrap()
            .center_text(),
        ))
        .gap(6.0)
        .pad_y(24.0)
    } else {
        col(paired
            .entries()
            .iter()
            .map(|machine| machine_row(machine, open == Some(machine.name.as_str())))
            .collect::<Vec<_>>())
        .gap(2.0)
        .scroll()
        .role(Role::List)
    };

    style::plate((
        style::section_rule("MACHINES", Some(paired.entries().len().to_string())),
        body.grow(),
        caption(
            "A machine is reached over SSH, so the encryption and the authentication are \
             OpenSSH's. Nothing here holds a token or any key material — only the path of a key.",
        )
        .wrap(),
    ))
    .gap(8.0)
    .w(Length::Fraction(LIST_SHARE))
    .min_w(LIST_MIN)
}

/// One machine: what it is, whether it is the open one, and the two things a
/// person does to it.
fn machine_row(machine: &Machine, open: bool) -> El<Console> {
    let name = machine.name.clone();
    let forgotten = machine.name.clone();
    col((
        row((
            style::wedge(open),
            text(machine.name.clone()).grow(),
            micro(if open { "OPEN" } else { "PAIRED" }).tracking(1.2).align_self(Align::Center),
        ))
        // Stated for the reason `desktop::machine_row` states its own: the
        // wedge is a fraction of the height it is handed, so a row that took
        // its height from its content would ask the wedge how tall it was while
        // the wedge asked the row, and the layout would resolve the circle by
        // growing without bound.
        .h(18.0)
        .gap(6.0)
        .align(Align::Center),
        row((
            code(machine.destination.clone()).grow(),
            // Absent on the machine already open rather than greyed: a control
            // is worth drawing dead only when the reason it is dead is a state
            // that will pass, and "this is the one you are on" is not one.
            (!open).then(|| {
                button("OPEN").key(format!("open {name}")).on_click(move |console: &mut Console| {
                    console.open_machine(&name);
                })
            }),
            button("FORGET").key(format!("forget {forgotten}")).on_click(
                move |console: &mut Console| console.forget_machine(&forgotten),
            ),
        ))
        .gap(6.0)
        .align(Align::Center),
        caption(detail(machine)).wrap(),
    ))
    .gap(2.0)
    .min_h(ROW)
    .pad_each(5.0, 6.0, 5.0, 6.0)
    .hover_fill(Tone::Raised)
    .role(Role::ListItem)
    .key(machine.name.clone())
}

/// The line under a machine's address: its ports, its key, and its token path.
///
/// Every one of them is a thing that has been got wrong at least once on this
/// project — a daemon on a non-default port, a key the agent does not hold, and
/// a project directory that is not the login directory — so the row states them
/// rather than making the operator open a file to find out what a name means.
fn detail(machine: &Machine) -> String {
    let mut parts = vec![format!("port {}", machine.port)];
    if let Some(port) = machine.ssh_port {
        parts.push(format!("ssh {port}"));
    }
    if let Some(identity) = &machine.identity {
        parts.push(format!("key {}", identity.display()));
    }
    if machine.remote_token != DEFAULT_REMOTE_TOKEN {
        parts.push(format!("token {}", machine.remote_token));
    }
    parts.join(" · ")
}

/// The form that adds a machine.
fn pairing(console: &Console) -> El<Console> {
    let form = console.pair_form();
    style::plate((
        style::section_rule("PAIR A MACHINE", None),
        col((
            field_row(
                "NAME",
                field(&form.name)
                    .key("pair-name")
                    .placeholder("e.g. alex-desktop")
                    .max_w(FIELD_MAX)
                    .on_input(|console: &mut Console, value| {
                        console.pair_form_mut().name = value;
                    }),
            ),
            field_row(
                "SSH",
                field(&form.destination)
                    .key("pair-destination")
                    .placeholder("e.g. alex@192.168.1.8")
                    .max_w(FIELD_MAX)
                    .on_input(|console: &mut Console, value| {
                        console.pair_form_mut().destination = value;
                    }),
            ),
            field_row(
                "PORT",
                field(&form.port)
                    .key("pair-port")
                    .placeholder("e.g. 9191")
                    .max_w(FIELD_MAX)
                    .on_input(|console: &mut Console, value| {
                        console.pair_form_mut().port = value;
                    }),
            ),
            field_row(
                "KEY",
                field(&form.identity)
                    .key("pair-identity")
                    .placeholder("e.g. ~/.ssh/id_ed25519 — blank uses the agent")
                    .max_w(FIELD_MAX)
                    .on_input(|console: &mut Console, value| {
                        console.pair_form_mut().identity = value;
                    }),
            ),
            field_row(
                "TOKEN",
                field(&form.remote_token)
                    .key("pair-token")
                    .placeholder(DEFAULT_REMOTE_TOKEN)
                    .max_w(FIELD_MAX)
                    .on_input(|console: &mut Console, value| {
                        console.pair_form_mut().remote_token = value;
                    }),
            ),
            problems(form),
            caption(
                "The token path is relative to the login directory over there. If the daemon's \
                 project directory is not the login directory — which on ALEX-DESKTOP it is not \
                 — say so here.",
            )
            .wrap(),
        ))
        .gap(8.0)
        .grow()
        .scroll(),
        row((
            spacer().grow(),
            button("PAIR AND OPEN").primary().on_click(Console::submit_pair_form),
        ))
        .gap(8.0)
        .justify(Justify::End),
    ))
    .gap(8.0)
    .grow()
}

/// Everything wrong with the form, or nothing at all.
fn problems(form: &PairForm) -> Option<El<Console>> {
    (!form.trouble.is_empty()).then(|| {
        col(form
            .trouble
            .iter()
            .map(|problem| caption(problem.clone()).color(Tone::Bad).wrap())
            .collect::<Vec<_>>())
        .gap(2.0)
        .pad(8.0)
        .fill(Tone::BadTint)
        .border(1.0, Tone::Bad)
    })
}

/// The masthead's step-back control.
///
/// The one way between the two places, and it names where it goes rather than
/// where it is: a control labelled with the machine you are already on is a
/// control that could mean either thing.
pub fn step_control(console: &Console) -> Option<El<Console>> {
    match console.place() {
        Place::Machine => Some(
            button("\u{2039} MACHINES")
                .key("to-machines")
                .on_click(Console::show_overview)
                .align_self(Align::Center),
        ),
        // Nothing to step forward to on a console that has never opened
        // anything, which is exactly the first run: the overview is where it
        // starts and the form beside it is what it is for.
        Place::Overview => console.bound().machine.as_ref().map(|name| {
            button(format!("{} \u{203a}", name.to_uppercase()))
                .key("to-machine")
                .on_click(Console::show_machine)
                .align_self(Align::Center)
        }),
    }
}

/// What the pairing form holds while it is being filled in.
///
/// Text, all of it, including the port. A form that refuses a keystroke because
/// the number is not finished being typed is a form that cannot be typed into;
/// the reading happens once, in [`PairForm::submit`], where a refusal can be
/// said in words.
#[derive(Debug, Default)]
pub struct PairForm {
    /// What the operator calls the machine.
    pub name: String,
    /// The server as `ssh` takes it — `host` or `user@host`.
    pub destination: String,
    /// The daemon's control port over there.
    pub port: String,
    /// A private key to use, when the agent's default is not the right one.
    pub identity: String,
    /// Where the daemon writes its token, relative to the login directory.
    pub remote_token: String,
    /// Everything wrong with what has been typed, once it has been submitted.
    pub trouble: Vec<String>,
}

impl PairForm {
    /// Empties the form.
    pub fn close(&mut self) {
        *self = Self::default();
    }

    /// The machine this form describes, or every reason it describes none.
    ///
    /// Pure, so the rules are asserted without a window: what a blank port
    /// means, what a blank token path means, and which of the fields are
    /// answered by [`Machine::problems`] rather than here.
    pub fn submit(&self) -> Result<Machine, Vec<String>> {
        let mut problems = Vec::new();
        let mut machine = Machine::new(self.name.trim(), self.destination.trim());

        // Blank is not zero and not an error: it is "the daemon's own default",
        // which is what the placeholder says and what nearly every deployment
        // uses.
        let port = self.port.trim();
        if port.is_empty() {
            machine.port = DEFAULT_PORT;
        } else {
            match port.parse::<u16>() {
                Ok(0) | Err(_) => problems.push(format!("{port:?} is not a port number")),
                Ok(port) => machine.port = port,
            }
        }

        let identity = self.identity.trim();
        if !identity.is_empty() {
            machine.identity = Some(PathBuf::from(identity));
        }

        let token = self.remote_token.trim();
        if !token.is_empty() {
            machine.remote_token = token.to_owned();
        }

        problems.extend(machine.problems());
        if problems.is_empty() { Ok(machine) } else { Err(problems) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled() -> PairForm {
        PairForm {
            name: "alex-desktop".into(),
            destination: "alex@192.168.1.8".into(),
            port: "9191".into(),
            identity: "  ".into(),
            remote_token: "Self-Host/data/admin.token".into(),
            trouble: Vec::new(),
        }
    }

    #[test]
    fn a_filled_form_describes_the_machine_it_says() {
        let machine = filled().submit().expect("the form is complete");
        assert_eq!(machine.name, "alex-desktop");
        assert_eq!(machine.destination, "alex@192.168.1.8");
        assert_eq!(machine.port, 9191);
        assert_eq!(machine.remote_token, "Self-Host/data/admin.token");
        assert!(machine.identity.is_none(), "whitespace is not a key path");
    }

    #[test]
    fn a_blank_port_and_a_blank_token_take_the_daemons_own_defaults() {
        // The alternative is a form that cannot be submitted without typing two
        // values that are right for nearly every deployment.
        let form = PairForm { port: String::new(), remote_token: String::new(), ..filled() };
        let machine = form.submit().expect("blank is a default, not a refusal");
        assert_eq!(machine.port, DEFAULT_PORT);
        assert_eq!(machine.remote_token, DEFAULT_REMOTE_TOKEN);
    }

    #[test]
    fn every_problem_is_reported_at_once_rather_than_one_per_attempt() {
        let form = PairForm {
            name: "Alex Desktop".into(),
            destination: String::new(),
            port: "wobble".into(),
            ..filled()
        };
        let problems = form.submit().expect_err("three things are wrong");
        assert_eq!(problems.len(), 3, "{problems:?}");
        assert!(problems.iter().any(|problem| problem.contains("wobble")), "{problems:?}");
    }

    #[test]
    fn a_destination_that_looks_like_an_option_is_refused() {
        // `ssh` reads a leading dash as a flag, so a destination that starts
        // with one is an argument injection and not a server.
        let form = PairForm { destination: "-oProxyCommand=touch /tmp/x".into(), ..filled() };
        assert!(form.submit().is_err());
    }

    #[test]
    fn the_detail_line_names_only_what_is_not_the_default() {
        let plain = Machine::new("home", "pi@host");
        assert_eq!(detail(&plain), "port 9191", "a default deployment says one thing");

        let mut fussy = Machine::new("desk", "alex@host");
        fussy.ssh_port = Some(2222);
        fussy.identity = Some(PathBuf::from("/k"));
        fussy.remote_token = "Self-Host/data/admin.token".into();
        let line = detail(&fussy);
        assert!(line.contains("ssh 2222"), "{line}");
        assert!(line.contains("key /k"), "{line}");
        assert!(line.contains("Self-Host"), "{line}");
    }
}
