//! The exposure map: every public listener's path from its bind to the outside
//! world, read as a row of green/amber/red judgements.
//!
//! # Why a map and not a list of open ports
//!
//! "Port 443 is allowed" is not the question an operator opens this with. The
//! question is *can someone actually reach my site* — and the honest answer is a
//! chain: the service has to be bound where the network can see it, the host
//! firewall has to admit the traffic, and the router in front has to forward it.
//! A single green "allowed" hides which of those three is the one still in the
//! way, which on a home connection is nearly always the router — see the memory
//! of a deployment that was reachable on the LAN and still NAT-blocked from the
//! internet.
//!
//! So each listener is one row across five columns — Service, Bind, Firewall,
//! Router, Reachability — and Reachability is the *weakest* link of the three
//! that precede it, never brighter than the dimmest. A row is green only when the
//! whole path is; an amber Router pulls Reachability to amber however open the
//! firewall is.
//!
//! # What the daemon can and cannot see
//!
//! It reads its own binds and drives its own host firewall, so those two columns
//! are fact. It cannot see the router it sits behind, so the Router column is a
//! judgement, not a reading: LAN scope needs no forward and is stated green,
//! Internet scope needs one this program cannot verify and is stated amber. That
//! amber is the point — it says *this is the link I cannot confirm for you*,
//! rather than a green that would claim a reachability the daemon never tested.
//!
//! # When it is drawn
//!
//! Only when the firewall is *managed*. An unmanaged firewall (the default first
//! run) is left exactly as the operator set it, the daemon asserts nothing about
//! it, and a map claiming to chart an exposure it does not govern would be a
//! fiction — so the strip is omitted, the same way the readout bank omits its
//! counts with nothing installed. This is a pure function of the snapshot: it
//! caches nothing and picks no colour of its own, all of it through [`style`].

use super::style;
use super::Console;
use rui::style::Justify;
use rui::{Align, El, Length, Status, caption, code, col, micro, row, text};
use selfhost_firewall::{BackendKind, FirewallState, RuleState, Scope};

/// The share of the row each column takes. They sum to one, so the header and
/// every body row line up by fraction of the plate's width regardless of the
/// text in any cell — the one layout that keeps a table's columns true when the
/// words in them change.
const SERVICE_W: f32 = 0.17;
/// See [`SERVICE_W`].
const BIND_W: f32 = 0.15;
/// See [`SERVICE_W`].
const FIREWALL_W: f32 = 0.22;
/// See [`SERVICE_W`].
const ROUTER_W: f32 = 0.24;
/// See [`SERVICE_W`].
const REACH_W: f32 = 0.22;

/// The exposure map, or `None` when there is nothing to chart.
///
/// `None` on three counts, each drawn as nothing rather than as an empty frame:
/// the daemon has not answered yet (`state` is `None`), or the firewall is
/// unmanaged (the daemon governs no exposure to report).
pub fn view(state: Option<&FirewallState>) -> Option<El<Console>> {
    let state = state?;
    if !state.managed {
        return None;
    }

    let body: El<Console> = match state.backend {
        // A backend the daemon cannot drive cannot be read either: say so plainly
        // rather than draw a table of judgements resting on nothing.
        BackendKind::Unsupported => caption(
            "This platform has no firewall backend selfhost can drive, so the \
             exposure here cannot be verified.",
        )
        .wrap(),
        // Managed, but every bind is loopback: the default block is the whole
        // policy and nothing off this machine can reach in. That is a state to
        // state, not an empty table.
        _ if state.rules.is_empty() => caption(
            "No public listeners — every bind is loopback, so nothing off this \
             machine can reach it.",
        )
        .wrap(),
        _ => {
            let mut lines = vec![head_row()];
            lines.extend(state.rules.iter().map(|rule| exposure_row(&exposure_of(rule))));
            col(lines).gap(3.0)
        }
    };

    Some(
        style::plate((
            style::section_rule("EXPOSURE MAP", Some(state.backend.label().to_string())),
            inbound_note(state),
            body,
        ))
        .gap(6.0),
    )
}

/// The five judgements for one public listener.
///
/// A struct rather than a formatted line because the row draws each cell as its
/// own lamp-and-word, and a function that returned a sentence would have the view
/// unpicking it again to find the colour of each column.
struct Exposure {
    /// The opening's label — `http`, `https`, `ssh`.
    service: String,
    /// The port and transport, as the machine names them: `443/tcp`.
    bind: String,
    /// Whether the host firewall actually holds the opening.
    firewall: (Status, &'static str),
    /// Whether the traffic reaches this host past the router.
    router: (Status, &'static str),
    /// The end-to-end verdict: the weakest link of the three before it.
    reach: (Status, &'static str),
}

/// Reads one rule's opening into the five judgements the row draws.
///
/// Pure, and the piece with the reasoning in it, so it is asserted directly:
///
/// - **Firewall** is fact — the backend reported whether the live ruleset holds
///   the opening. Not applied is red: the daemon meant to open it and the host
///   has not.
/// - **Router** is a judgement the daemon cannot verify. `Lan` scope reaches the
///   local network without any forward, so it is green; `Internet` scope needs a
///   port-forward this program cannot see, so it is amber — the honest "I cannot
///   confirm this link", never a green that would claim otherwise.
/// - **Reachability** is the weakest of the chain: red if the firewall has not
///   opened it, else amber while the router link is unverified, else green.
fn exposure_of(rule_state: &RuleState) -> Exposure {
    let rule = &rule_state.rule;

    let firewall = if rule_state.applied {
        (Status::Ok, "open")
    } else {
        (Status::Bad, "not applied")
    };

    let router = match rule.scope {
        Scope::Lan => (Status::Ok, "LAN — no forward"),
        Scope::Internet => (Status::Warn, "forward unverified"),
        // A rule under loopback scope is never emitted (`desired_rules` returns
        // none), so this is unreachable in practice; stated for completeness so
        // the match is closed rather than defaulted.
        Scope::Loopback => (Status::Idle, "this machine only"),
    };

    let reach = if !rule_state.applied {
        (Status::Bad, "blocked at host")
    } else {
        match rule.scope {
            Scope::Lan => (Status::Ok, "reachable on LAN"),
            Scope::Internet => (Status::Warn, "internet unverified"),
            Scope::Loopback => (Status::Idle, "this machine only"),
        }
    };

    Exposure {
        service: rule.tag.clone(),
        bind: format!("{}/{}", rule.port, rule.proto.tag()),
        firewall,
        router,
        reach,
    }
}

/// Whether inbound is default-deny, stated once above the rows it governs.
///
/// Green when default-deny — only the openings below are reachable — and amber
/// when default-allow, because then a port is reachable whether or not the daemon
/// opened it, which is exactly the thing the map cannot otherwise show.
fn inbound_note(state: &FirewallState) -> El<Console> {
    let (status, message) = if state.default_inbound_block {
        (Status::Ok, "inbound default-deny · only the openings below are reachable")
    } else {
        (Status::Warn, "inbound default-allow · ports may be reachable without an opening")
    };
    row((style::lamp(status), caption(message))).gap(6.0).align(Align::Center)
}

/// The header naming the five columns, in the label voice the block rules use.
fn head_row() -> El<Console> {
    row((
        micro("SERVICE").tracking(1.2).w(Length::Fraction(SERVICE_W)),
        micro("BIND").tracking(1.2).w(Length::Fraction(BIND_W)),
        micro("FIREWALL").tracking(1.2).w(Length::Fraction(FIREWALL_W)),
        micro("ROUTER").tracking(1.2).w(Length::Fraction(ROUTER_W)),
        micro("REACHABILITY").tracking(1.2).w(Length::Fraction(REACH_W)),
    ))
    .min_h(14.0)
}

/// One listener's row: its label and bind, then three lamp-and-word verdicts.
///
/// It answers the pointer with the same raised fill every other row in the
/// window answers with — the rail's rows, most visibly. A table whose rows
/// ignore the pointer reads as a legend printed on the panel rather than as
/// part of the instrument.
fn exposure_row(exposure: &Exposure) -> El<Console> {
    row((
        text(exposure.service.clone()).w(Length::Fraction(SERVICE_W)),
        code(exposure.bind.clone()).w(Length::Fraction(BIND_W)),
        verdict(FIREWALL_W, exposure.firewall.0, exposure.firewall.1),
        verdict(ROUTER_W, exposure.router.0, exposure.router.1),
        verdict(REACH_W, exposure.reach.0, exposure.reach.1),
    ))
    .min_h(20.0)
    .align(Align::Center)
    .hover_fill(rui::Tone::Raised)
}

/// One verdict cell: the status lamp and the word it carries, in a fixed column.
///
/// The word follows [`style::state_word`], so a healthy green verdict is stated
/// quietly by the lamp alone and only amber and red raise their voice — the same
/// rule the rail is built on, carried to the map: a table where every reachable
/// row lit up green could not say which one is blocked.
fn verdict(width: f32, status: Status, label: &str) -> El<Console> {
    let word = label.to_uppercase();
    // Floored at the word's own width, the same guarantee [`super::ALARM_UNIT`]
    // gives the rail's red state word: a verdict is the one word the map
    // exists to say, and "NOT APPLIED" cut to an ellipsis fails at exactly
    // the moment the map matters.
    let whole = word.len() as f32 * super::ALARM_UNIT;
    row((style::lamp(status), style::state_word(status, word).min_w(whole)))
        .w(Length::Fraction(width))
        .gap(6.0)
        .align(Align::Center)
        .justify(Justify::Start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_firewall::{AllowRule, Proto};

    fn rule(port: u16, tag: &str, scope: Scope, applied: bool) -> RuleState {
        RuleState {
            rule: AllowRule { port, proto: Proto::Tcp, scope, tag: tag.into() },
            applied,
        }
    }

    fn state(managed: bool, backend: BackendKind, rules: Vec<RuleState>) -> FirewallState {
        FirewallState { backend, managed, default_inbound_block: true, rules }
    }

    #[test]
    fn a_firewall_that_has_not_applied_the_opening_reads_red_end_to_end() {
        let exposure = exposure_of(&rule(443, "https", Scope::Internet, false));
        assert_eq!(exposure.firewall.0, Status::Bad);
        assert_eq!(exposure.reach.0, Status::Bad, "an unopened port is not reachable");
    }

    #[test]
    fn an_applied_lan_opening_is_reachable_all_the_way() {
        let exposure = exposure_of(&rule(80, "http", Scope::Lan, true));
        assert_eq!(exposure.firewall.0, Status::Ok);
        assert_eq!(exposure.router.0, Status::Ok, "the LAN needs no forward");
        assert_eq!(exposure.reach.0, Status::Ok);
    }

    #[test]
    fn an_internet_opening_is_amber_because_the_forward_cannot_be_seen() {
        // The row the memory of a NAT-blocked deployment argues for: open at the
        // host, and honestly unverified past the router rather than falsely green.
        let exposure = exposure_of(&rule(443, "https", Scope::Internet, true));
        assert_eq!(exposure.router.0, Status::Warn);
        assert_eq!(exposure.reach.0, Status::Warn);
    }

    #[test]
    fn the_bind_names_the_port_and_transport() {
        assert_eq!(exposure_of(&rule(443, "https", Scope::Lan, true)).bind, "443/tcp");
    }

    #[test]
    fn an_unmanaged_or_unanswered_firewall_shows_no_map() {
        assert!(view(None).is_none(), "the daemon has not answered yet");
        let unmanaged = state(false, BackendKind::Pf, vec![rule(443, "https", Scope::Lan, true)]);
        assert!(view(Some(&unmanaged)).is_none(), "an unmanaged firewall governs no exposure");
    }

    #[test]
    fn a_managed_firewall_with_public_openings_draws_the_map() {
        let managed = state(true, BackendKind::Pf, vec![rule(443, "https", Scope::Internet, true)]);
        assert!(view(Some(&managed)).is_some());
    }

    #[test]
    fn a_managed_firewall_with_only_loopback_still_says_so() {
        let loopback_only = state(true, BackendKind::Pf, vec![]);
        assert!(view(Some(&loopback_only)).is_some(), "managed always states its condition");
    }

    #[test]
    fn an_exposure_row_answers_the_pointer_like_every_other_row() {
        // The raised hover fill is the window's one pointer answer for a row;
        // a table that ignores the pointer reads as a legend, not a control
        // surface.
        let row = exposure_row(&exposure_of(&rule(443, "https", Scope::Lan, true)));
        assert_eq!(row.style().hover.fill, Some(rui::Tone::Raised));
    }

    #[test]
    fn the_map_draws_its_columns_at_the_smallest_window_the_backend_allows() {
        // The layout concern: five fractional columns and their lamp-and-word
        // cells must fit — and the header still be found — on the narrowest
        // window the backend allows, with no face loaded so every cell is at its
        // minimum. The same harness the rail's own width tests use.
        use crate::state::{Link, Snapshot};
        use crate::view::Console;

        let firewall = state(
            true,
            BackendKind::Pf,
            vec![
                rule(443, "https", Scope::Internet, true),
                rule(80, "http", Scope::Internet, false),
                rule(22, "ssh", Scope::Lan, true),
            ],
        );
        let snapshot = Snapshot { link: Link::Connected, firewall: Some(firewall), ..Default::default() };

        let mut harness = rui::testing::Harness::new(
            crate::view::tests::console(snapshot),
            |console: &Console| {
                super::view(console.snapshot().firewall.as_ref())
                    .expect("a managed firewall draws a map")
            },
        )
        .size(560.0, 420.0);
        harness.frame();
        assert!(harness.rect_of("REACHABILITY").is_some(), "the header column is drawn");

        // A verdict's word stands whole at the narrowest window — floored the
        // way the rail floors its red state word, and measured the same way:
        // the synthetic face sets every character at half its size plus its
        // tracking.
        let width_of = |word: &str| word.len() as f32 * (10.5 / 2.0 + 0.4);
        let verdict = harness.rect_of("NOT APPLIED").expect("the failed verdict is drawn");
        assert!(verdict.w >= width_of("NOT APPLIED") - 0.5, "a verdict is never cut: {}", verdict.w);
    }
}
