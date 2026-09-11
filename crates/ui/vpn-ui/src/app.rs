//! The window: its state, the actions its controls fire, and the one description
//! of everything on screen.
//!
//! The state a handler mutates is [`Panel`]. The tunnel and the slow actions
//! (rotating a key, opening the console) run off this thread and report back
//! through a shared [`Activity`]; the view reads both once per frame, so the
//! window never blocks on the network or a password prompt.

use crate::keys::{self, Identity};
use crate::tunnel::{Endpoint, Link, Phase, Tunnel};
use crate::{actions, hero, hud, style};
use rui::{
    App, El, Size, Status, Tone, button, caption, code, col, dot, field_row, micro, row, section,
    spacer, tag, title,
};
use rui::tray::{Tray, TrayEvent, TrayMenuItem};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// The console URL, reached portless through the loopback 443 gate.
pub const CONSOLE_URL: &str = "https://admin.rockywearsahat.com/";

/// The console host: answered by the split-DNS responder, mapped to loopback.
pub const CONSOLE_HOST: &str = "admin.rockywearsahat.com";

/// The SARA gateway URL, reached portless through the same loopback 443 gate.
pub const SARA_URL: &str = "https://sara.rockywearsahat.com/";

/// The SARA gateway host: answered by the split-DNS responder, mapped to loopback.
pub const SARA_HOST: &str = "sara.rockywearsahat.com";

/// The AI Studio URL, reached portless through the same loopback 443 gate.
pub const AI_URL: &str = "https://ai.rockywearsahat.com/";

/// The AI Studio host: answered by the split-DNS responder, mapped to loopback.
pub const AI_HOST: &str = "ai.rockywearsahat.com";

/// Every host the split-DNS responder answers for and the resolver install
/// routes to loopback. The console gate itself is host-agnostic (a byte
/// passthrough on `127.0.0.1:443`), so adding a gated site here is the only
/// step needed to route it through the tunnel.
pub const GATED_HOSTS: &[&str] = &[CONSOLE_HOST, SARA_HOST, AI_HOST];

/// What a slow, off-thread action is doing and what it last said.
#[derive(Default)]
pub struct Activity {
    /// The action in flight, if any, as a line to show ("Rotating keys…").
    pub busy: Option<String>,
    /// The last result: `true` for done, `false` for a problem, and the words.
    pub notice: Option<(bool, String)>,
    /// The client identity fingerprint, re-read after a rotation.
    pub client: Option<Identity>,
    /// The server identity fingerprint.
    pub server: Option<Identity>,
    /// When the client key was last rotated, as recorded on disk.
    pub last_rotation: Option<String>,
}

/// Everything the window is and can do.
pub struct Panel {
    pub tunnel: Tunnel,
    activity: Arc<Mutex<Activity>>,
    auto_rotate: Arc<AtomicBool>,
    running: Arc<AtomicBool>,
    /// The system tray icon, created in on_frame during the first loop iteration.
    tray: Option<Tray>,
    /// Whether the window is currently visible.
    window_visible: bool,
    /// Whether we've already attempted tray creation (on first frame).
    tray_created: bool,
}

impl Panel {
    /// A panel that dials `endpoint`, with the keys already read once.
    pub fn new(endpoint: Endpoint, running: Arc<AtomicBool>) -> Self {
        let (client, server) = keys::identities();
        let activity = Arc::new(Mutex::new(Activity {
            client,
            server,
            last_rotation: keys::last_rotation(),
            ..Activity::default()
        }));
        Self {
            tunnel: Tunnel::new(endpoint),
            activity,
            auto_rotate: Arc::new(AtomicBool::new(true)),
            running,
            tray: None,
            window_visible: true,
            tray_created: false,
        }
    }

    /// A panel with no client but a preset link, for rendering the window's
    /// looks headless. The keys are read from disk if present.
    pub fn demo(link: Link) -> Self {
        let (client, server) = keys::identities();
        let activity = Arc::new(Mutex::new(Activity {
            client,
            server,
            last_rotation: keys::last_rotation(),
            ..Activity::default()
        }));
        Self {
            tunnel: Tunnel::demo(Endpoint::default(), link),
            activity,
            auto_rotate: Arc::new(AtomicBool::new(true)),
            running: Arc::new(AtomicBool::new(true)),
            tray: None,
            window_visible: true,
            tray_created: false,
        }
    }

    /// A handle to the auto-rotation flag, for the weekly rotation thread.
    pub fn auto_rotate_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.auto_rotate)
    }

    /// A handle to the shared activity, for background actions to report into.
    pub fn activity_handle(&self) -> Arc<Mutex<Activity>> {
        Arc::clone(&self.activity)
    }

    /// Reads the activity for the current frame.
    fn activity(&self) -> std::sync::MutexGuard<'_, Activity> {
        match self.activity.lock() {
            Ok(activity) => activity,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Create and store the system tray icon.
    /// This runs on the main thread when the pump loop is active.
    pub fn create_tray(&mut self) -> Result<(), String> {
        eprintln!("DEBUG: create_tray() called");
        let icon_data = include_bytes!("../assets/tray-icon.png");
        eprintln!("DEBUG: About to call Tray::new()");
        let tray = Tray::new(icon_data, "SelfHost VPN")
            .map_err(|e| {
                eprintln!("DEBUG: Tray::new() failed: {:?}", e);
                format!("Tray creation failed: {:?}", e)
            })?;
        eprintln!("DEBUG: Tray::new() succeeded");
        // Set the actual icon image (Tray::new creates with a blank placeholder)
        let _ = tray.set_icon(icon_data);
        eprintln!("DEBUG: Tray icon set, storing tray");
        self.tray = Some(tray);
        self.update_tray_menu();
        eprintln!("DEBUG: Tray menu updated, create_tray() returning Ok");
        Ok(())
    }

    /// Drain and dispatch tray events each frame.
    /// Called from on_frame callback, integrated into the UI frame loop.
    /// Creates the tray on the first call (when the pump loop is active).
    pub fn drain_tray_events(&mut self) {
        // Create the tray on the first frame after the pump loop starts.
        if !self.tray_created {
            eprintln!("DEBUG: drain_tray_events() - first call, attempting tray creation");
            match self.create_tray() {
                Ok(()) => eprintln!("DEBUG: Tray creation succeeded"),
                Err(e) => eprintln!("DEBUG: Tray creation failed: {}", e),
            }
            self.tray_created = true;
        }

        if let Some(ref tray) = self.tray {
            for event in tray.drain_events() {
                self.handle_tray_event(event);
            }
        }
    }

    /// Handle a single tray event, dispatching to the same handlers as UI buttons.
    fn handle_tray_event(&mut self, event: TrayEvent) {
        match event {
            TrayEvent::IconActivated => {
                eprintln!("DEBUG: Tray icon activated");
                // Toggle window visibility on tray icon click
                self.window_visible = !self.window_visible;
                // TODO: Wire up actual window show/hide via rui window API
            }
            TrayEvent::MenuItemClicked(id) => {
                eprintln!("DEBUG: Tray menu item clicked: {}", id);
                match id {
                    1 => self.tunnel.connect(),
                    2 => self.tunnel.disconnect(),
                    3 => actions::open_console(self.activity_handle()),
                    4 => actions::open_sara(self.activity_handle()),
                    5 => actions::open_ai_studio(self.activity_handle()),
                    6 => self.running.store(false, Ordering::Relaxed),  // Quit
                    _ => {}
                }
            }
        }
    }

    /// Update the tray menu based on current tunnel state.
    /// This mirrors the window's own button states.
    fn update_tray_menu(&self) {
        if let Some(ref tray) = self.tray {
            let link = self.tunnel.link();
            let up = link.phase.is_up();
            let reaching = link.phase.is_reaching();

            let menu = vec![
                TrayMenuItem {
                    id: 1,
                    label: "Connect".into(),
                    enabled: !up && !reaching,
                    selected: false,
                },
                TrayMenuItem {
                    id: 2,
                    label: if up { "Disconnect".into() } else { "Cancel".into() },
                    enabled: up || reaching,
                    selected: false,
                },
                TrayMenuItem {
                    id: 3,
                    label: "Open Console".into(),
                    enabled: up,
                    selected: false,
                },
                TrayMenuItem {
                    id: 4,
                    label: "Open SARA".into(),
                    enabled: up,
                    selected: false,
                },
                TrayMenuItem {
                    id: 5,
                    label: "Open AI Studio".into(),
                    enabled: up,
                    selected: false,
                },
                TrayMenuItem {
                    id: 6,
                    label: "Quit".into(),
                    enabled: true,
                    selected: false,
                },
            ];
            let _ = tray.set_menu(menu);
        }
    }

    /// Opens the window and runs it until it is closed.
    pub fn run(self, title: String) -> Result<(), rui::Error> {
        let running = Arc::clone(&self.running);

        // on_frame callback: drain and dispatch tray events each frame before rendering.
        // The tray is created on the first frame when the pump loop is active.
        let on_frame = |panel: &mut Panel| {
            panel.drain_tray_events();
            panel.update_tray_menu();
        };

        application(title, self)
            .size(430.0, 620.0)
            .min_size(380.0, 560.0)
            .idle_timeout(std::time::Duration::from_millis(200))
            .while_running(move |_| running.load(Ordering::Relaxed))
            .on_frame(on_frame)
            .run()
    }
}

/// The panel as an application, in its own theme and ground.
pub fn application(title: impl Into<String>, panel: Panel) -> App<Panel> {
    App::new(title, panel, view).theme(style::theme).ground(style::ground)
}

/// The whole window, as one description.
pub fn view(ui: &Panel) -> El<Panel> {
    let link = ui.tunnel.link();
    let activity = ui.activity();
    let auto = ui.auto_rotate.load(Ordering::Relaxed);
    col((
        masthead(&link),
        hud::glass_panel(hero::tunnel_hero(&link)).align(rui::Align::Stretch),
        link_readout(&link),
        controls(&link),
        keys_panel(&activity, auto),
        footer(&activity),
    ))
    .pad(16.0)
    .gap(14.0)
}

/// The bar across the top: the mark, the wordmark, and the state at a glance.
fn masthead(link: &Link) -> El<Panel> {
    row((
        hud::mark(),
        title("SELFHOST").bold().tracking(1.0),
        caption("VPN").color(Tone::Exact(style::CYAN)).tracking(2.0),
        spacer().grow(),
        dot(status_of(link), 4.0),
        micro(state_word(link)).color(word_tone(link)).tracking(1.5),
    ))
    .gap(8.0)
    .h(26.0)
    .align(rui::Align::Center)
}

/// The link readout: where it goes, how it is, how long, how much.
///
/// Every state draws the same four rows — a reading that is not there yet shows
/// a dash, and a failure's reason folds into the STATUS row — so the panel
/// holds its geometry and the controls below it never move.
fn link_readout(link: &Link) -> El<Panel> {
    let reason = match &link.phase {
        Phase::Failed(reason) => Some(caption(reason.clone()).color(Tone::ink(Status::Bad))),
        _ => None,
    };
    let up = match link.since {
        Some(since) => caption(duration(since.elapsed())).color(Tone::Text),
        None => caption("—").color(Tone::Muted),
    };
    let traffic = format!("up {}   down {}", bytes(link.tx), bytes(link.rx));
    let rows = col((
        field_row("ENDPOINT", code("rockywearsahat.com:8443").color(Tone::Text)),
        field_row(
            "STATUS",
            row((tag(status_of(link), state_word(link).to_lowercase()), reason, spacer().grow()))
                .gap(8.0)
                .align(rui::Align::Center),
        ),
        field_row("UP", up),
        field_row("TRAFFIC", code(traffic).color(Tone::Muted)),
    ))
    .gap(6.0);
    hud::glass_panel(col((section("LINK", None), rows)).gap(10.0)).align(rui::Align::Stretch)
}

/// The connect control and the console button.
///
/// Disconnecting a healthy tunnel is routine, so Disconnect is a quiet button —
/// red belongs to Failed alone. The console button explains its own disablement
/// with a micro hint on a line the row reserves in every state.
fn controls(link: &Link) -> El<Panel> {
    let up = link.phase.is_up();
    let reaching = link.phase.is_reaching();

    let primary = if up {
        button("Disconnect").on_click(|panel: &mut Panel| panel.tunnel.disconnect())
    } else if reaching {
        button("Cancel").on_click(|panel: &mut Panel| panel.tunnel.disconnect())
    } else {
        button("Connect").primary().on_click(|panel: &mut Panel| panel.tunnel.connect())
    };
    let hint = if up { String::new() } else { "connect first".into() };

    col((
        row((
            primary.grow().h(30.0),
            button("Open Console")
                .disabled(!up)
                .on_click(|panel: &mut Panel| actions::open_console(panel.activity_handle()))
                .h(30.0),
            button("Open SARA")
                .disabled(!up)
                .on_click(|panel: &mut Panel| actions::open_sara(panel.activity_handle()))
                .h(30.0),
            button("Open AI Studio")
                .disabled(!up)
                .on_click(|panel: &mut Panel| actions::open_ai_studio(panel.activity_handle()))
                .h(30.0),
        ))
        .gap(8.0),
        row((spacer().grow(), micro(hint).color(Tone::Muted).tracking(1.0))).h(12.0),
    ))
    .gap(4.0)
}

/// The keys panel: which identities are live, when they last rotated, the
/// rotate control, and the automatic-rotation switch.
fn keys_panel(activity: &Activity, auto: bool) -> El<Panel> {
    let client = activity.client.as_ref().map(|id| id.fingerprint.clone()).unwrap_or_else(|| "—".into());
    let server = activity.server.as_ref().map(|id| id.fingerprint.clone()).unwrap_or_else(|| "—".into());
    let busy = activity.busy.is_some();

    hud::glass_panel(col((
        section("KEYS", Some("ed25519".into())),
        field_row("CLIENT", code(client).color(Tone::Text)),
        field_row("SERVER", code(server).color(Tone::Text)),
        field_row("ROTATED", rotated_reading(activity.last_rotation.as_deref())),
        row((
            button("Rotate now")
                .disabled(busy)
                .on_click(|panel: &mut Panel| {
                    actions::rotate(panel.activity_handle());
                })
                .h(28.0),
            spacer().grow(),
            micro("AUTO").color(Tone::Muted).tracking(1.5),
            switch(auto),
        ))
        .gap(6.0)
        .align(rui::Align::Center),
        micro("Session keys rotate every connection; the identity key weekly.").color(Tone::Muted),
    ))
    .gap(10.0))
    .align(rui::Align::Stretch)
}

/// The ROTATED reading: the age up front in human units, amber once the weekly
/// deadline nears, with the raw record demoted to a dim line beside it.
fn rotated_reading(raw: Option<&str>) -> El<Panel> {
    let Some(raw) = raw else {
        return caption("not yet").color(Tone::Muted);
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or(0);
    match keys::parse_epoch(raw) {
        Some(then) => {
            let tone =
                if keys::rotation_stale(then, now) { Tone::ink(Status::Warn) } else { Tone::Text };
            row((
                caption(keys::rotation_age(then, now)).color(tone),
                micro(raw.to_string()).color(Tone::Idle),
                spacer().grow(),
            ))
            .gap(8.0)
            .align(rui::Align::Center)
        }
        None => caption(raw.to_string()).color(Tone::Muted),
    }
}

/// A small two-state switch bound to the auto-rotation flag.
///
/// `on` is read by the view and captured here, because a custom-drawn element
/// cannot reach the application state itself; the click flips the real flag.
fn switch(on: bool) -> El<Panel> {
    rui::draw(Size::new(38.0, 18.0), move |painter, rect| hud::paint_switch(painter, rect, on))
        .w(38.0)
        .h(18.0)
        .role(rui::Role::Button)
        .selected(on)
        .label("Automatic key rotation")
    .on_click(|panel: &mut Panel| {
        let now = !panel.auto_rotate.load(Ordering::Relaxed);
        panel.auto_rotate.store(now, Ordering::Relaxed);
    })
}

/// The footer: what an action is doing, or what it last said. Blank when idle —
/// the console button carries its own "connect first" hint.
fn footer(activity: &Activity) -> El<Panel> {
    let line = if let Some(busy) = &activity.busy {
        micro(format!("• {busy}")).color(Tone::ink(Status::Warn))
    } else if let Some((ok, message)) = &activity.notice {
        let status = if *ok { Status::Ok } else { Status::Bad };
        micro(message.clone()).color(Tone::ink(status))
    } else {
        micro(String::new()).color(Tone::Muted)
    };
    row((line, spacer().grow())).h(16.0)
}

// ----- small formatting helpers -------------------------------------------

/// The status colour a link is in.
fn status_of(link: &Link) -> Status {
    match link.phase {
        Phase::Off => Status::Idle,
        Phase::Dialling | Phase::Authenticated => Status::Warn,
        Phase::Up => Status::Ok,
        Phase::Failed(_) => Status::Bad,
    }
}

/// The state word shown in the masthead and the status tag.
fn state_word(link: &Link) -> &'static str {
    match link.phase {
        Phase::Off => "OFFLINE",
        Phase::Dialling => "DIALLING",
        Phase::Authenticated => "AUTHENTICATED",
        Phase::Up => "CONNECTED",
        Phase::Failed(_) => "FAILED",
    }
}

/// The masthead word's own colour: quiet unless it wants attention.
fn word_tone(link: &Link) -> Tone {
    match link.phase {
        Phase::Up | Phase::Off => Tone::Muted,
        _ => Tone::ink(status_of(link)),
    }
}

/// A short human duration, "6m 04s" or "2h 09m".
fn duration(elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h {:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Bytes in the largest unit that keeps the number small.
fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_scale_to_readable_units() {
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(2048), "2.0 KB");
        assert_eq!(bytes(5 * 1024 * 1024), "5.0 MB");
    }

    #[test]
    fn duration_reads_in_the_right_grain() {
        assert_eq!(duration(std::time::Duration::from_secs(9)), "9s");
        assert_eq!(duration(std::time::Duration::from_secs(125)), "2m 05s");
        assert_eq!(duration(std::time::Duration::from_secs(7800)), "2h 10m");
    }
}
