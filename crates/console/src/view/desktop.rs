//! The DESKTOP screen: which machine, what its session is doing, and — when
//! there is one — the screen itself, live, in this window.
//!
//! # The three states this plate has to keep apart
//!
//! *Whether this deployment has a desktop at all*, *whether the machine is
//! reachable*, and *whether the session is taking input* are three different
//! facts with three different fixes, and every earlier remote-desktop client
//! this project looked at collapses at least two of them into "disconnected".
//! So the plate states them separately: the switches at the top, the picker in
//! the middle, and the session's own [`Notice`] — the far machine's account of
//! itself, in `selfhost-desk`'s own words — over the viewport.
//!
//! # Control is a separate, explicitly authorised action, exactly as in the
//! browser
//!
//! WATCH opens a session asking for `desktop.view` and nothing else. TAKE
//! CONTROL closes it and opens a *new* one asking for `desktop.control`, which
//! the daemon decides against `[desktop].reauth_window` — the freshness rule —
//! and against `[desktop].allow_input` and `bearer_may_control`. There is no
//! path in this file that turns a watching session into a driving one without a
//! mint the daemon can refuse, and the rule is not weakened because this is a
//! native program: it lives in the daemon, and this end can only ask.
//!
//! What *is* different here, and is said in as many words on screen, is what a
//! person can do about a refusal. A browser answers a stale login with a passkey
//! prompt; this console holds a bearer token and has no prompt to offer, so
//! [`ControlRefusal::sentence`] sends them to the browser console rather than
//! offering a re-authentication this program cannot perform.
//!
//! # What the viewport can and cannot carry
//!
//! Measured, not assumed — the numbers are in `console-lab.dx`. Fitting a
//! 1920×1080 frame to a 1000×660 pane costs about 1.5 ms on this machine and
//! blitting it about 0.2 ms, against 2.3 ms for the whole interface, and the
//! fit happens on the stream's own thread rather than in the frame loop. Thirty
//! frames a second is therefore comfortably inside a tenth of one core.
//!
//! One gap is real and is recorded as OPEN in the lab rather than hidden: **the
//! far machine's cursor is whatever its own capture drew into the frame**,
//! because this console has no sub-frame layer to track one on. The browser
//! draws the far pointer on a second canvas moved by CSS transform, so it
//! tracks between frames; here the picture is the whole of what is shown.
//!
//! The pointer itself does track. A hand moving over the picture with nothing
//! pressed moves the far pointer, through `rui`'s `on_pointer_move` — the
//! library primitive this console's viewport was the reason for, since a drag
//! reports a position only while a button is held and a screen you can click
//! but not point at is not a remote desktop.

use super::style;
use super::Console;
use crate::channel::{LinkState, Live, Picture};
use crate::remote::{self, Agent, Mode, Node, Settings};
use rui::style::Justify;
use rui::{
    Align, El, Length, Rect, Role, Size, Status, Tone, button, caption, code, col, draw,
    micro, row, spacer, text,
};
use selfhost_desk::grant::Capabilities;
use selfhost_desk::wire::Monitor;
use std::sync::{Arc, Mutex};

/// What share of the window the machine picker takes.
const RAIL_SHARE: f32 = 0.26;

/// The narrowest the picker may be drawn.
const RAIL_MIN: f32 = 180.0;

/// The widest, past which it is a list of short names in a hall.
const RAIL_MAX: f32 = 280.0;

/// The smallest the viewport is ever drawn.
///
/// Deliberately small, and it is a *floor* rather than a size: the viewport
/// takes whatever the plate has left after the readings above and the controls
/// below have had theirs, which on a large window is most of it. A larger floor
/// was tried and is wrong — at 560 × 420 it pushed the controls off the bottom
/// of the plate and the monitor picker underneath them, because the layout will
/// not shrink a child past its stated minimum and something has to give. What
/// gives is the picture, which is the one thing on this plate that is still
/// legible at a quarter of the size. What absorbs the rest is the pane's own
/// scroll — see [`session`].
const VIEWPORT_MIN: f32 = 140.0;

/// The whole screen: the machines, and the session on the one that is chosen.
pub fn view(console: &Console) -> El<Console> {
    let snapshot = console.snapshot();
    row((machines(&snapshot), session(console, &snapshot))).gap(8.0).grow()
}

/// The far screen with nothing else on it: what a full screen is *for*.
///
/// # Why this is a different description and not the same one with the rail
/// hidden
///
/// A remote desktop shown inside a console is a picture among readings, and the
/// readings are why the console exists. A remote desktop filling a screen is the
/// far machine *being* this window — the thing a person asked for when they made
/// it full screen — and every unit spent on a plate edge, a page margin or a tab
/// row is a unit the picture does not get. So the stage draws two things: one
/// strip that says whose screen this is and how to get out, and the picture.
///
/// Nothing here is a second implementation of the viewport. It is
/// [`viewport`] — the same element, the same handles, the same forwarding — so
/// a keyboard that works in the pane works here, and neither can be fixed
/// without the other.
pub fn stage(console: &Console) -> El<Console> {
    let live = console.session_live();
    col((bar(console, live.as_ref()), viewport(console, live.as_ref()))).gap(2.0).grow()
}

/// The one strip of console left on the stage: where this is, and the way out.
///
/// Deliberately not a summary of the pane below it. Three facts earn their
/// height at the top of a filled screen: which machine is under the pointer,
/// whether what is typed reaches it, and how to leave — the last because a
/// window with no title bar has taken away the way a person would otherwise
/// close it, and hiding the replacement would be the defect this whole screen
/// exists to avoid.
fn bar(console: &Console, live: Option<&Live>) -> El<Console> {
    let peer = console
        .snapshot()
        .desk
        .peer()
        .map_or_else(|| "NO MACHINE".to_owned(), |peer| peer.node.to_uppercase());
    let driving = live.is_some_and(Live::may_control);
    let mode = live.map(|live| {
        Mode::of(live.may_control(), live.far_end_is_live(), console.viewport_has_keys())
    });
    row((
        micro(peer).tracking(1.2),
        mode.map(|mode| {
            row((style::lamp(mode.status()), style::state_word(mode.status(), mode.word().to_owned())))
                .gap(6.0)
                .align(Align::Center)
        }),
        spacer().grow(),
        // Absent while the keyboard is held, for the reason `controls` gives:
        // it is not unavailable, it is done.
        (!driving).then(|| {
            button("TAKE CONTROL")
                .key("stage-control")
                .on_click(|console: &mut Console| console.open_session(true))
        }),
        button("EXIT FULL SCREEN")
            .key("stage-exit")
            .on_click(|console: &mut Console| console.toggle_full_screen()),
        // The words rather than a hint that fades: a person who has just lost
        // the title bar is looking for exactly this, and a session holding the
        // keyboard has no Escape to spare — see [`leaves_full_screen`].
        caption(if driving { "⌃⌘F leaves" } else { "Esc leaves" }),
    ))
    .gap(10.0)
    .pad_each(4.0, 8.0, 4.0, 8.0)
    .align(Align::Center)
}

/// The picker: every machine this credential may watch, and how it is.
///
/// Absence is never the answer. A machine that is down is drawn with the reason
/// its link ended and when it was last seen, because a picker that silently
/// omitted it would tell an operator their configuration is wrong when the
/// truth is that a laptop is asleep.
fn machines(snapshot: &crate::state::Snapshot) -> El<Console> {
    let nodes = snapshot.desk.nodes.as_deref();
    let chosen = snapshot.desk.peer.as_deref();
    let body: El<Console> = match nodes {
        None => col(caption("This deployment serves no desktop.").wrap().center_text()).pad_y(24.0),
        Some([]) => {
            col(caption("No machine on this deployment is yours to watch.").wrap().center_text())
                .pad_y(24.0)
        }
        Some(nodes) => col(nodes
            .iter()
            .map(|node| machine_row(node, chosen == Some(node.node.as_str())))
            .collect::<Vec<_>>())
        .gap(2.0)
        .scroll()
        .role(Role::List),
    };

    style::plate((
        style::section_rule("MACHINES", nodes.map(|nodes| nodes.len().to_string())),
        body.grow(),
        snapshot.desk.settings.map(switches),
    ))
    .gap(8.0)
    .w(Length::Fraction(RAIL_SHARE))
    .min_w(RAIL_MIN)
    .max_w(RAIL_MAX)
}

/// One machine in the picker.
fn machine_row(node: &Node, chosen: bool) -> El<Console> {
    let name = node.node.clone();
    let summary = node.summary();
    col((
        row((style::wedge(chosen), style::lamp(node.status()), text(node.node.clone()).grow()))
            // Stated for the reason `files::share_row` states its own: the
            // wedge is a fraction of the height it is handed, so a row that
            // took its height from its content would grow without bound.
            .h(18.0)
            .gap(6.0)
            .align(Align::Center),
        (!summary.is_empty()).then(|| caption(summary).wrap()),
    ))
    .gap(2.0)
    .pad_each(5.0, 8.0, 5.0, 4.0)
    .min_h(30.0)
    .hover_fill(Tone::Raised)
    .role(Role::ListItem)
    .selected(chosen)
    .key(node.node.clone())
    .on_click(move |console: &mut Console| console.watch_machine(&name))
}

/// The deployment's own switches, under the picker.
///
/// Read off `GET /api/desktop` and drawn because they are the answer to the
/// question a refused keyboard raises. Every one of them is a line in a file on
/// the box, and none of them can be changed from here — which the plate says by
/// drawing them as readings and not as controls.
fn switches(settings: Settings) -> El<Console> {
    let word = |on: bool| if on { "on" } else { "off" };
    col((
        style::section_rule("DEPLOYMENT", None),
        style::reading("INPUT", word(settings.allow_input).into(), None),
        style::reading(
            "BEARER MAY DRIVE",
            word(settings.bearer_may_control).into(),
            // Amber, on this console specifically: it authenticates with the
            // bearer token, so this switch being off is the reason TAKE
            // CONTROL will be refused however fresh anything else is.
            (!settings.bearer_may_control).then_some(Status::Warn),
        ),
        style::reading("CLIPBOARD", word(settings.allow_clipboard).into(), None),
        style::reading("MAX FPS", settings.max_fps.to_string(), None),
        style::reading(
            "RE-AUTH WINDOW",
            super::duration(settings.reauth_window_secs),
            None,
        ),
    ))
    .gap(3.0)
}

/// The right-hand pane: the agent, the session, and the picture.
fn session(console: &Console, snapshot: &crate::state::Snapshot) -> El<Console> {
    let Some(peer) = snapshot.desk.peer() else {
        return style::plate((
            super::title_rule("DESKTOP".into(), None),
            col(caption("Choose a machine.").wrap().center_text()).pad_y(24.0).grow(),
        ))
        .gap(8.0)
        .grow();
    };
    let live = console.session_live();

    style::plate((
        super::title_rule(
            peer.node.to_uppercase(),
            Some(
                micro(match &live {
                    Some(live) => link_word(&live.state),
                    None => "NO SESSION".into(),
                })
                .tracking(1.2)
                .align_self(Align::Center),
            ),
        ),
        // Everything under the title scrolls, and that is not a detail. The
        // readings, the picture and the controls together want more room than a
        // 560 × 420 window has, and a column that could not scroll resolved that
        // by drawing its last children past the bottom of the plate — the
        // monitor picker under the buttons, the diagnostics off the window. A
        // scroll makes the overflow a thing a person can reach instead of a
        // thing that is lost, and on any window worth having there is nothing to
        // scroll.
        col((
            snapshot.desk.agent.as_ref().map(agent_line),
            state_line(live.as_ref()),
            live.as_ref().map(|live| mode_line(console, live)),
            downgraded(console, live.as_ref()).map(trouble),
            console.control_trouble().map(|refusal| trouble(refusal.sentence())),
            live.as_ref().and_then(refusal_line),
            viewport(console, live.as_ref()),
            live.as_ref().map(|live| monitors(&live.monitors, live.monitor)),
            controls(snapshot, live.as_ref()),
        ))
        .gap(6.0)
        .scroll()
        .grow(),
    ))
    .gap(6.0)
    .grow()
}

/// What the capture agent on the chosen machine says about itself.
///
/// Its own sentence, verbatim: the session it landed in, the window station,
/// the desktop, the monitor count, the integrity level. Every field of that is
/// a fact only the agent can state, and paraphrasing it here would be this
/// console guessing at a Windows detail it has never seen.
fn agent_line(agent: &Agent) -> El<Console> {
    let status = if agent.live { Status::Ok } else { Status::Warn };
    // A flow, not a row: the agent's sentence is as long as the far machine
    // wants it to be, and on a narrow pane a respawn count squeezed beside it is
    // a reading cut in half. It drops to the next line whole instead.
    row((
        row((style::lamp(status), caption(agent.sentence.clone()).wrap().grow()))
            .gap(6.0)
            .grow(),
        (agent.respawns > 0).then(|| {
            style::reading("RESPAWNS", agent.respawns.to_string(), Some(Status::Warn))
        }),
    ))
    .flow()
    .gap(6.0)
}

/// The session's own state, in the far machine's words.
fn state_line(live: Option<&Live>) -> El<Console> {
    let (status, sentence) = match live {
        None => (Status::Idle, "No session. WATCH opens one.".to_owned()),
        Some(live) => match &live.state {
            LinkState::Dialling => (Status::Warn, "opening the session…".to_owned()),
            LinkState::Ended(reason) => (Status::Bad, reason.clone()),
            LinkState::Open => match live.notice {
                // The words are `selfhost-desk`'s, written once so the two
                // consoles cannot come to say the same state differently.
                Some(notice) => (notice_status(notice), notice.sentence().to_owned()),
                None => (Status::Warn, "connected — waiting for the agent".to_owned()),
            },
        },
    };
    row((style::lamp(status), style::emphatic(sentence).color(style::state_ink(status)).wrap()))
        .gap(8.0)
        .align(Align::Center)
}

/// How pressing a session notice is.
///
/// Live is green, a state that will clear on its own is amber, and one that
/// needs somebody to do something is red. The mapping is here and not in
/// `selfhost-desk` because it is a *console's* judgement about emphasis, and the
/// crate deliberately owns only the words.
fn notice_status(notice: selfhost_desk::state::Notice) -> Status {
    use selfhost_desk::state::Notice;
    match notice {
        Notice::Live => Status::Ok,
        Notice::Starting | Notice::Recovering | Notice::SecureDesktop | Notice::SessionMoved => {
            Status::Warn
        }
        Notice::NoUser | Notice::PermissionDenied | Notice::GaveUp | Notice::Stopped => Status::Bad,
    }
}

/// Where the keyboard is pointed, and what happens to the next key pressed.
fn mode_line(console: &Console, live: &Live) -> El<Console> {
    let mode = Mode::of(live.may_control(), live.far_end_is_live(), console.viewport_has_keys());
    row((
        style::lamp(mode.status()),
        style::state_word(mode.status(), mode.word().to_owned()),
        caption(mode.line()).wrap().grow(),
    ))
    .gap(8.0)
    .align(Align::Center)
}

/// The last input refusal, with what to do about it.
fn refusal_line(live: &Live) -> Option<El<Console>> {
    let (refusal, count) = live.refusal?;
    Some(
        col((
            row((
                style::lamp(Status::Warn),
                text(remote::refusal_headline(refusal, count))
                    .color(style::state_ink(Status::Warn))
                    .wrap()
                    .grow(),
            ))
            .gap(6.0)
            .align(Align::Center),
            caption(remote::refusal_advice(refusal)).wrap(),
        ))
        .gap(2.0),
    )
}

/// The sentence for a session that asked for a keyboard and was given a view.
///
/// A ticket carrying control can still be downgraded between the mint and the
/// handshake — `upgrade::still_permitted` re-decides every ability against the
/// caller's standing — and the agent's `Hello` echoes what survived. This is the
/// one place the difference between *asked* and *granted* becomes words; without
/// it, a downgrade looks exactly like an ordinary watching session and the
/// operator is left wondering why their keys do nothing.
fn downgraded(console: &Console, live: Option<&Live>) -> Option<String> {
    let live = live?;
    let asked = console.session_asked_for_control();
    (asked && live.state.is_open() && !live.may_control()).then(|| {
        "This session asked for a keyboard and the daemon granted it a view. Nothing typed \
         here reaches that machine."
            .to_owned()
    })
}

/// Something the plate could not do, said where the operator is looking.
fn trouble(sentence: String) -> El<Console> {
    row((style::lamp(Status::Bad), caption(sentence).wrap().grow())).gap(6.0).align(Align::Center)
}

/// The live picture, or the reticle standing in for it.
///
/// # How the pixels get here
///
/// The stream thread has already fitted the frame to the size this element
/// asked for last time it drew, so what happens here is a clipped copy and
/// nothing else — [`rui::Canvas::blit_bgra`], one source pixel per device
/// pixel, no resample. The element states its new device size on the way past,
/// which is how a window being resized settles: one frame at the old size, then
/// every frame at the new one.
fn viewport(console: &Console, live: Option<&Live>) -> El<Console> {
    let Some(handles) = console.viewport_handles() else {
        return col((style::reticle(), caption("No session.").center_text()))
            .gap(8.0)
            .min_h(VIEWPORT_MIN)
            .grow()
            .justify(Justify::Center)
            .align(Align::Center);
    };
    let (picture, fit) = handles;
    let armed = live.is_some_and(Live::may_control);
    let focused = console.viewport_has_keys();

    draw(Size::new(VIEWPORT_MIN, VIEWPORT_MIN), move |painter, rect: Rect| {
        let scale = painter.canvas().scale();
        let device = |value: f32| (value * scale).max(0.0) as u32;
        // Said every frame rather than on a resize the element cannot see: the
        // layout decides this rectangle, and the only place it is known is
        // here, while it is being drawn into.
        *fit.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            (device(rect.w), device(rect.h));

        let held = picture.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some((bytes, width, height)) = held.bgra() else {
            return;
        };
        let Some(bgra) = rui::Bgra::packed(width, height, bytes) else {
            return;
        };
        // Centred in the pane. The fit preserved the far screen's shape, so
        // one of the two axes has room left over, and putting it all on one
        // side would make a 16:9 screen sit against the top of a square pane.
        let left = rect.x + (rect.w - width as f32 / scale).max(0.0) / 2.0;
        let top = rect.y + (rect.h - height as f32 / scale).max(0.0) / 2.0;
        painter.canvas().blit_bgra(Rect::new(left, top, rect.w, rect.h), &bgra);
    })
    .min_h(VIEWPORT_MIN)
    .grow()
    .fill(Tone::SurfaceDeep)
    .border(1.0, if focused { Tone::Accent } else { Tone::Border })
    .clip()
    .focusable()
    // Named, so a test can aim the pointer at the picture rather than at
    // whatever happens to be under a guessed coordinate. It is also the one
    // element on this plate whose identity must not move when the controls
    // above it change, since its scroll and focus are stored under it.
    .key("screen")
    .role(Role::Image)
    .label("The remote screen")
    // A press is what aims the keyboard, and it is also the first thing a
    // pointer forwarder has to send. Both happen here so that clicking the
    // picture does what clicking a remote screen means.
    .on_drag(move |console: &mut Console, drag| {
        console.aim_at_viewport();
        if armed {
            console.forward_pointer(drag);
        }
    })
    // And a hand moving over the picture with nothing pressed, which is the
    // other half of pointing at a screen: the far pointer tracks this one
    // rather than jumping to wherever the next click lands. It does not aim the
    // keyboard — passing over a window is not asking to type into it.
    .on_pointer_move(move |console: &mut Console, at| {
        if armed {
            console.point_at(at);
        }
    })
    // Both directions of every key, through the physical path: `Key` has no
    // function row, no keypad and no left-right modifiers, and a session that
    // could not send those is a session that cannot press F2 or Ctrl.
    .on_raw_key(move |console: &mut Console, stroke| console.forward_key(stroke))
    .on_scroll(move |console: &mut Console, across, down| console.forward_scroll(across, down))
    // Losing the keyboard releases everything held on the far machine. Without
    // this a modifier that went down in this window stays down over there,
    // which is the failure `selfhost_desk::keys::HeldKeys` exists to insist on.
    .on_hover(|console: &mut Console, inside| {
        if !inside {
            console.release_far_keys();
        }
    })
}

/// The displays the agent advertised, when there is more than one.
///
/// Absent for a single monitor: a row of one button that cannot change anything
/// is chrome, and the machine's own name is already above it.
fn monitors(monitors: &[Monitor], watching: u8) -> Option<El<Console>> {
    if monitors.len() < 2 {
        return None;
    }
    Some(
        row(monitors
            .iter()
            .map(|monitor| {
                let id = monitor.id;
                let label = format!(
                    "{}×{}{}",
                    monitor.width,
                    monitor.height,
                    if monitor.primary { " ·" } else { "" }
                );
                // Marked rather than greyed. The display being watched is a
                // *choice*, and the console says which one is chosen with the
                // same selected mark every other row uses; greying it would say
                // "unavailable" about the one thing that is on screen. Pressing
                // it again asks for a fresh frame of it, which is the only
                // sensible reading of pressing the display you are watching.
                button(label)
                    .selected(id == watching)
                    .key(format!("monitor-{id}"))
                    .on_click(move |console: &mut Console| console.watch_monitor(id))
            })
            .collect::<Vec<_>>())
        .gap(6.0)
        .flow(),
    )
}

/// The controls: open a session, take the keyboard, ask for a fresh frame.
///
/// WATCH and TAKE CONTROL are two buttons and not one with a switch beside it,
/// because they ask the daemon for two different things and one of them can be
/// refused for reasons the other cannot.
///
/// # Absent when it does not apply, greyed when it is not permitted
///
/// The two are different facts and the console draws them differently. A
/// DISCONNECT with no session to close is not *unavailable*, it is about
/// nothing — the same argument the readout bank makes for showing its next-move
/// block only when there is a next move — so it is absent. TAKE CONTROL with
/// `[desktop].allow_input` off is a control that exists and is closed to this
/// caller, so it stays, greyed, and the DEPLOYMENT readings beside the picker
/// say which switch is the reason. A control that vanished for *that* would
/// leave the operator hunting for a keyboard the console had simply hidden.
fn controls(snapshot: &crate::state::Snapshot, live: Option<&Live>) -> El<Console> {
    let settings = snapshot.desk.settings.unwrap_or_default();
    let open = live.is_some();
    let driving = live.is_some_and(Live::may_control);
    let may_ask_for_keys = settings.enabled && settings.allow_input && settings.bearer_may_control;

    row((
        button(if open { "RECONNECT" } else { "WATCH" })
            .disabled(!settings.enabled)
            .on_click(|console: &mut Console| console.open_session(false)),
        // Absent once the keyboard is held: it is not unavailable, it is done.
        (!driving).then(|| {
            button("TAKE CONTROL")
                .disabled(!may_ask_for_keys)
                .on_click(|console: &mut Console| console.open_session(true))
        }),
        open.then(|| {
            button("DISCONNECT").on_click(|console: &mut Console| console.close_session())
        }),
        open.then(|| {
            button("FULL FRAME").on_click(|console: &mut Console| console.request_full_frame())
        }),
        // Present whether or not a session is open, and never greyed: making
        // the window fill the screen is this window's own business, and a
        // person who has just chosen a machine is entitled to give it the
        // screen before the picture arrives.
        button("FULL SCREEN")
            .key("full-screen")
            .on_click(|console: &mut Console| console.toggle_full_screen()),
        spacer().grow(),
        live.map(diagnostics),
    ))
    .gap(6.0)
    .flow()
    .align(Align::Center)
}

/// What the stream has actually carried, for the plate that has to prove it.
///
/// Frames and bytes rather than a frame rate: a rate computed over a second in
/// which the far screen did not change is nought, and a viewer would read that
/// as a broken stream rather than as a still desktop.
fn diagnostics(live: &Live) -> El<Console> {
    let seconds = live.since.elapsed().as_secs();
    row((
        style::reading("FRAMES", live.frames.to_string(), None),
        style::reading("READ", crate::nas::size_text(live.bytes), None),
        style::reading("OPEN", super::duration(seconds), None),
        code(capability_words(live.capabilities)),
    ))
    .gap(12.0)
    .flow()
    .align(Align::Center)
}

/// What a session was actually granted, in words.
///
/// Echoed from the agent's `Hello` rather than from what was asked for, which is
/// the whole reason the field is on the wire: a ticket downgraded between the
/// mint and the handshake would otherwise be drawn as the keyboard the operator
/// asked for and does not have.
pub fn capability_words(capabilities: Capabilities) -> String {
    let mut words = Vec::new();
    if capabilities.contains(Capabilities::VIEW) {
        words.push("view");
    }
    if capabilities.contains(Capabilities::CONTROL) {
        words.push("control");
    }
    if capabilities.contains(Capabilities::CLIPBOARD) {
        words.push("clipboard");
    }
    if words.is_empty() {
        return "nothing granted".into();
    }
    words.join(" · ")
}

/// The word for where the socket is, for the tail of the title rule.
pub fn link_word(state: &LinkState) -> String {
    match state {
        LinkState::Dialling => "OPENING".into(),
        LinkState::Open => "OPEN".into(),
        LinkState::Ended(_) => "ENDED".into(),
    }
}

/// The picture handle and the size cell a viewport draws through.
pub type ViewportHandles = (Arc<Mutex<Picture>>, Arc<Mutex<(u32, u32)>>);

/// Whether a keystroke should be forwarded at all.
///
/// Pure, and the piece with the judgement in it, so the rule is asserted without
/// a socket. Three things have to be true, and each is a different kind of
/// fact: the session was granted a keyboard, the far machine is taking input,
/// and this window has the keys aimed at the picture. The last is what stops a
/// console in the background typing into somebody's machine.
pub fn forwards_keys(live: &Live, aimed: bool) -> bool {
    Mode::of(live.may_control(), live.far_end_is_live(), aimed) == Mode::Driving
}

/// Whether a keystroke is this window being asked to leave the full screen.
///
/// Escape, and only while the session is *watching*. A session holding the
/// keyboard needs Escape on the far machine far more than it needs a second way
/// out of a full screen — a remote desktop that swallowed it could not close a
/// dialogue over there — so a driving session leaves by the control on the bar
/// or by the platform's own shortcut, which never reaches this program at all.
/// Pure, so the rule is asserted without a window.
pub fn leaves_full_screen(stroke: rui::KeyStroke, full_screen: bool, driving: bool) -> bool {
    full_screen && !driving && stroke.is_down() && stroke.key == Some(rui::Key::Escape)
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_desk::state::Notice;

    fn live(capabilities: Capabilities, notice: Option<Notice>, state: LinkState) -> Live {
        let mut live = Live::opening();
        live.capabilities = capabilities;
        live.notice = notice;
        live.state = state;
        live
    }

    #[test]
    fn a_watching_session_forwards_no_key_however_aimed_it_is() {
        let watching = live(Capabilities::VIEW, Some(Notice::Live), LinkState::Open);
        assert!(!forwards_keys(&watching, true));
    }

    #[test]
    fn a_driving_session_forwards_only_while_the_keys_are_aimed_at_it() {
        let driving =
            live(Capabilities::VIEW.with(Capabilities::CONTROL), Some(Notice::Live), LinkState::Open);
        assert!(forwards_keys(&driving, true));
        assert!(!forwards_keys(&driving, false), "a background window must not type");
    }

    #[test]
    fn a_suspended_far_machine_takes_no_keys_even_from_a_granted_session() {
        let suspended = live(
            Capabilities::VIEW.with(Capabilities::CONTROL),
            Some(Notice::SecureDesktop),
            LinkState::Open,
        );
        assert!(!forwards_keys(&suspended, true));
    }

    #[test]
    fn a_session_whose_socket_has_died_takes_no_keys() {
        let dead = live(
            Capabilities::VIEW.with(Capabilities::CONTROL),
            Some(Notice::Live),
            LinkState::Ended("the daemon closed the session".into()),
        );
        assert!(!forwards_keys(&dead, true), "a notice with no socket under it is stale");
    }

    #[test]
    fn what_was_granted_is_said_in_words_and_never_inferred() {
        assert_eq!(capability_words(Capabilities::none()), "nothing granted");
        assert_eq!(capability_words(Capabilities::VIEW), "view");
        assert_eq!(
            capability_words(Capabilities::VIEW.with(Capabilities::CONTROL)),
            "view · control"
        );
    }

    #[test]
    fn every_session_notice_has_an_emphasis_and_the_live_one_is_the_only_green() {
        for notice in [
            Notice::Starting,
            Notice::Recovering,
            Notice::SecureDesktop,
            Notice::SessionMoved,
            Notice::NoUser,
            Notice::PermissionDenied,
            Notice::GaveUp,
            Notice::Stopped,
        ] {
            assert_ne!(notice_status(notice), Status::Ok, "{notice:?} is not health");
        }
        assert_eq!(notice_status(Notice::Live), Status::Ok);
    }

    #[test]
    fn a_state_that_will_clear_on_its_own_is_amber_and_one_that_will_not_is_red() {
        assert_eq!(notice_status(Notice::SecureDesktop), Status::Warn, "the prompt will go");
        assert_eq!(notice_status(Notice::Stopped), Status::Bad, "a kill switch will not");
    }

    #[test]
    fn one_display_draws_no_picker_and_two_do() {
        let monitor = |id: u8| Monitor {
            id,
            origin_x: 0,
            origin_y: 0,
            width: 1920,
            height: 1080,
            scale_permille: 1000,
            primary: id == 0,
        };
        assert!(monitors(&[monitor(0)], 0).is_none(), "a row of one button is chrome");
        assert!(monitors(&[monitor(0), monitor(1)], 0).is_some());
    }

    /// A key going down, with nothing held.
    fn pressed(key: rui::Key) -> rui::KeyStroke {
        rui::KeyStroke {
            code: None,
            key: Some(key),
            modifiers: rui::Modifiers::default(),
            phase: rui::KeyPhase::Down,
        }
    }

    #[test]
    fn escape_leaves_a_full_screen_that_is_only_being_watched() {
        assert!(leaves_full_screen(pressed(rui::Key::Escape), true, false));
    }

    #[test]
    fn escape_belongs_to_the_far_machine_while_the_keyboard_is_held() {
        // The failure this prevents is a dialogue on the far machine that
        // cannot be dismissed, because the one key that would do it closed a
        // full screen over here instead.
        assert!(!leaves_full_screen(pressed(rui::Key::Escape), true, true));
    }

    #[test]
    fn nothing_leaves_a_window_that_is_not_filling_the_screen() {
        assert!(!leaves_full_screen(pressed(rui::Key::Escape), false, false));
        assert!(!leaves_full_screen(pressed(rui::Key::Enter), true, false), "only Escape");
    }

    #[test]
    fn a_key_coming_back_up_leaves_nothing() {
        let mut release = pressed(rui::Key::Escape);
        release.phase = rui::KeyPhase::Up;
        assert!(!leaves_full_screen(release, true, false), "one press is one leaving");
    }

    #[test]
    fn the_socket_says_where_it_is_in_one_word() {
        assert_eq!(link_word(&LinkState::Dialling), "OPENING");
        assert_eq!(link_word(&LinkState::Open), "OPEN");
        assert_eq!(link_word(&LinkState::Ended(String::new())), "ENDED");
    }
}
